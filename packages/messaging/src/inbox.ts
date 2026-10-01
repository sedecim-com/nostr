/**
 * FR009-03: a persona's DM inbox. Contacts send their DMs, and their receipts for our DMs, to the DM relays we
 * publish (kind 10050), so that is where the inbox reads: once (`sync`) or in the background (`start`, a live
 * subscription the pool renews after each reconnection). Every gift wrap for us is opened here:
 * - a receipt from the recipient of one of our DMs advances that operation (RECIPIENT_ACKED, READ; FR009-02);
 * - a message is kept and answered with the receipts the profile allows (ADR 0005), at most one of each type per
 *   message, sent to the sender's DM relays, where the sender's own inbox reads them. IR-2026-10-09: only to
 *   contacts (someone the persona wrote to): a stranger who writes first learns nothing about when the device is
 *   online, and cannot make it connect (and authenticate) to relays of its choosing.
 * PANEL-06: a message whose NIP-40 expiration passed is never shown, answered or kept, even if a relay still serves
 * it; one that expires while held is dropped (purgeExpired). A deletion (kind 5, NIP-17) removes a message only when
 * its authenticated sender wrote that message, in whichever order the two arrive.
 */
import type { Filter, NostrEvent, Signer } from '@sedecim/nostr-core';
import { resolveDmRelays, type DmRelayCache, type RelayQuery } from './dm-relays';
import { deletedMessageIds, DM_DELETION_KIND, isUnwrappedExpired, rumorTombstone, unwrappedExpiration, wrapTombstone, type TombstoneStore } from './expiration';
import { DirectMessenger, type DmOutbox } from './messenger';
import { directMessageFrom, dmInboxFilter, DM_KIND, FILE_MESSAGE_KIND, type DirectMessage } from './nip17';
import { unwrap, type Unwrapped, type WrapOptions } from './nip59';
import { APP_RECEIPT_KIND, parseReceipt, type Receipt, type ReceiptType } from './receipts';

/** The part of RelayPool the inbox uses (structural: messaging has no pool dependency). */
export interface InboxPool extends RelayQuery {
  subscribe(urls: string[], filters: Filter[], opts: { onevent: (evt: NostrEvent, relay: string) => void; oneose?: () => void }): { close(): void };
}

/** The outbox (a DeliveryEngine): receipts advance our operations, and our receipts are queued in it. */
export interface InboxOutbox<R> extends DmOutbox<R> {
  applyReceipt(receipt: Receipt): Promise<R | undefined>;
}

export interface DmInboxOptions<R> {
  pool: InboxPool;
  outbox: InboxOutbox<R>;
  /** The persona's relays: always read, and the fallback for senders without DM relays. */
  ownRelays: string[];
  /** Where our own and the senders' relay lists are looked up (default: ownRelays). */
  discoveryRelays?: string[];
  /** Which receipts may be sent (profiles.receiptPolicy). Asked for each message, so a panel change applies at once. */
  policy: () => { delivered: boolean; read: boolean };
  /**
   * IR-2026-10-09: whether the sender is a contact of this persona (e.g. outboxContacts: someone it wrote to). Receipts
   * only go to contacts; without it, none go.
   */
  isContact?: (pubkey: string) => Promise<boolean>;
  /** Receipts already sent, by `<type>:<rumor id>`, so that each goes at most once, across sessions. */
  sent: { get(key: string): Promise<boolean | undefined>; put(key: string, value: boolean): Promise<void> };
  wrapOptions?: WrapOptions;
  cache?: DmRelayCache;
  timeoutMs?: number;
  /** A message read for the first time. `live`: it arrived through the subscription after the stored ones. */
  onMessage?: (m: DirectMessage, live: boolean) => void;
  /** A receipt for one of our DMs, with that operation as the receipt leaves it (states never move backwards). */
  onReceipt?: (r: Receipt, record: R) => void;
  /**
   * PANEL-06: the messages deleted by their author, remembered across sessions (in the persona's encrypted store), so
   * that one never comes back from a relay that still serves it. Without it, only for as long as this inbox lives.
   */
  tombstones?: TombstoneStore;
  /** PANEL-06: the clock (ms) against which NIP-40 expirations are read. */
  now?: () => number;
  /** PANEL-06: messages that were shown and are gone: `expired` (NIP-40) or `deleted` by their author. */
  onRemoved?: (messages: DirectMessage[], reason: 'expired' | 'deleted') => void;
}

export class DmInbox<R> {
  private readonly seen = new Set<string>();
  private readonly messages = new Map<string, DirectMessage>();
  /** PANEL-06: deletions read by this inbox (`rumor:<id>:<author>`), besides those in `tombstones`. */
  private readonly deletions = new Set<string>();
  private queue: Promise<void> = Promise.resolve();
  private sub?: { close(): void };
  private me?: string;
  private inboxRelays?: string[];
  private eose = false;
  private closed = false;

  constructor(private readonly signer: Signer, private readonly opts: DmInboxOptions<R>) {}

  /**
   * Where our DMs arrive: the persona's relays plus those of its own kind 10050 (else its NIP-65 read relays),
   * which may have been published by another client with the same key.
   */
  async relays(): Promise<string[]> {
    if (this.inboxRelays) return this.inboxRelays;
    const own = await resolveDmRelays(this.opts.pool, await this.pubkey(), { discoveryRelays: this.discovery(), fallback: this.opts.ownRelays, timeoutMs: this.opts.timeoutMs, cache: this.opts.cache });
    const relays = [...new Set([...this.opts.ownRelays, ...own.relays])];
    // Finding nothing is not remembered: offline it looks like a persona without a list (FR010-03).
    if (own.source !== 'fallback') this.inboxRelays = relays;
    return relays;
  }

  /** Reads every gift wrap for us on our DM relays once. */
  async sync(timeoutMs = 8000): Promise<DirectMessage[]> {
    const wraps = await this.opts.pool.query(await this.relays(), [dmInboxFilter(await this.pubkey())], timeoutMs);
    for (const w of wraps) await this.enqueue(w, false);
    return this.list();
  }

  /** Keeps reading in the background: stored wraps first, then each new one as it arrives. */
  async start(): Promise<void> {
    if (this.sub || this.closed) return;
    const relays = await this.relays();
    const filter = dmInboxFilter(await this.pubkey());
    if (this.sub || this.closed) return;
    this.sub = this.opts.pool.subscribe(relays, [filter], {
      onevent: (e) => void this.enqueue(e, this.eose),
      oneose: () => (this.eose = true),
    });
  }

  /** The messages read so far, oldest first, without those that expired (NIP-40). */
  list(): DirectMessage[] {
    const now = this.nowSeconds();
    return [...this.messages.values()].filter((m) => !isUnwrappedExpired(m, now)).sort((a, b) => a.rumor.created_at - b.rumor.created_at);
  }

  /** The user saw a message: a read receipt, only if the profile allows it (opt-in, ADR 0005). */
  markRead(m: DirectMessage): Promise<void> {
    return this.serial(() => this.receipt(m, 'read'));
  }

  /** PANEL-06: drops the messages whose expiration passed while they were held, and returns them (and to onRemoved). */
  purgeExpired(): DirectMessage[] {
    const now = this.nowSeconds();
    const gone = [...this.messages.values()].filter((m) => isUnwrappedExpired(m, now));
    for (const m of gone) this.messages.delete(m.rumor.id);
    if (gone.length) this.opts.onRemoved?.(gone, 'expired');
    return gone;
  }

  /** PANEL-06: the soonest expiration (unix seconds) of the messages held, to call purgeExpired then. */
  nextExpiration(): number | undefined {
    const at = [...this.messages.values()].map(unwrappedExpiration).filter((x): x is number => x !== undefined);
    return at.length ? Math.min(...at) : undefined;
  }

  /**
   * PANEL-06: the persona deleted one of its own messages here: it leaves this inbox at once, before its deletion comes
   * back from the relays, and it is not shown again while the inbox lives. Returns it if it was held.
   */
  forget(rumorId: string, author: string): DirectMessage | undefined {
    const held = this.messages.get(rumorId);
    if (held?.sender === author) this.messages.delete(rumorId);
    this.deletions.add(rumorTombstone(rumorId, author));
    return held?.sender === author ? held : undefined;
  }

  close(): void {
    this.closed = true;
    this.sub?.close();
    this.sub = undefined;
  }

  private async pubkey(): Promise<string> {
    return (this.me ??= await this.signer.getPublicKey());
  }

  private nowSeconds(): number {
    return Math.floor((this.opts.now ?? Date.now)() / 1000);
  }

  private discovery(): string[] {
    return this.opts.discoveryRelays ?? this.opts.ownRelays;
  }

  /** PANEL-06: whether the author of `m` deleted it (read here, or remembered from an earlier session). */
  private async deleted(m: DirectMessage): Promise<boolean> {
    const key = rumorTombstone(m.rumor.id, m.sender);
    return this.deletions.has(key) || !!(await this.opts.tombstones?.get(key));
  }

  /**
   * PANEL-06 (NIP-17): a kind 5 from the authenticated sender `u.sender` deletes the messages it names that this same
   * sender wrote, now or when they arrive; a message by anyone else stays. Deleted messages are remembered with their
   * wrap, so that a later vault push leaves the wrap out.
   */
  private async applyDeletion(u: Unwrapped): Promise<void> {
    const gone: DirectMessage[] = [];
    for (const id of deletedMessageIds(u.rumor)) {
      const key = rumorTombstone(id, u.sender);
      this.deletions.add(key);
      await this.opts.tombstones?.put(key, true);
      const held = this.messages.get(id);
      if (held?.sender !== u.sender) continue;
      this.messages.delete(id);
      await this.opts.tombstones?.put(wrapTombstone(held.wrap.id), true);
      gone.push(held);
    }
    if (gone.length) this.opts.onRemoved?.(gone, 'deleted');
  }

  /** One wrap at a time: a remote signer is never asked to decrypt a burst in parallel. */
  private serial(fn: () => Promise<void>): Promise<void> {
    this.queue = this.queue.then(fn).catch(() => undefined);
    return this.queue;
  }

  private enqueue(wrap: NostrEvent, live: boolean): Promise<void> {
    return this.serial(() => this.handle(wrap, live));
  }

  private async handle(wrap: NostrEvent, live: boolean): Promise<void> {
    if (this.closed || this.seen.has(wrap.id)) return;
    let u: Unwrapped;
    try {
      u = await unwrap(this.signer, wrap);
    } catch {
      return; // not for us, not a valid gift wrap, or the signer could not decrypt it now (a later sync retries)
    }
    this.seen.add(wrap.id);
    const me = await this.pubkey();
    if (u.rumor.kind === APP_RECEIPT_KIND) {
      // FR009-02: the engine only counts it when its authenticated sender is the recipient of that DM.
      const r = parseReceipt(u);
      if (!r || r.from === me) return;
      const rec = await this.opts.outbox.applyReceipt(r);
      if (rec) this.opts.onReceipt?.(r, rec);
      return;
    }
    if (u.rumor.kind === DM_DELETION_KIND) return this.applyDeletion(u);
    if (u.rumor.kind !== DM_KIND && u.rumor.kind !== FILE_MESSAGE_KIND) return;
    const m = directMessageFrom(u);
    if (this.messages.has(m.rumor.id)) return;
    // PANEL-06: NIP-40 asks clients to ignore what expired, which a relay may still serve.
    if (isUnwrappedExpired(m, this.nowSeconds())) return;
    if (await this.deleted(m)) {
      await this.opts.tombstones?.put(wrapTombstone(m.wrap.id), true);
      return;
    }
    this.messages.set(m.rumor.id, m);
    this.opts.onMessage?.(m, live);
    await this.receipt(m, 'delivered');
  }

  private async receipt(m: DirectMessage, type: ReceiptType): Promise<void> {
    const policy = this.opts.policy();
    if (!policy[type] || this.closed || m.sender === (await this.pubkey())) return;
    // PANEL-06: an expired or deleted message is no longer shown, so nothing tells its sender it was read.
    if (isUnwrappedExpired(m, this.nowSeconds()) || !this.messages.has(m.rumor.id)) return;
    const key = `${type}:${m.rumor.id}`;
    if (await this.opts.sent.get(key)) return;
    // Not remembered as sent: once the persona writes to them, a later receipt for this message may go.
    if (!(await this.opts.isContact?.(m.sender))) return;
    const messenger = new DirectMessenger(this.signer, { nip17: true, readReceipts: policy.read }, this.opts.wrapOptions);
    const route = { pool: this.opts.pool, outbox: this.opts.outbox, ownRelays: this.opts.ownRelays, discoveryRelays: this.discovery(), cache: this.opts.cache, timeoutMs: this.opts.timeoutMs, quorum: 1 };
    // PANEL-06: the receipt of a disappearing message asks to expire with it.
    await messenger.receipt(m.sender, m.rumor.id, type, route, unwrappedExpiration(m));
    await this.opts.sent.put(key, true);
  }
}

/** What outboxContacts reads: the outbox records (a DeliveryEngine) and, when it has them, its changes. */
export interface ContactSource {
  list(): Promise<Array<{ meta?: Record<string, string> }>>;
  onChange?(fn: (r: { meta?: Record<string, string> }) => void): () => void;
}

/**
 * IR-2026-10-09: the persona's contacts, for receipts: whoever it wrote a DM to, as its outbox records it (a DM wrap
 * whose `meta.recipient` is someone else; the receipts it sent do not count). The outbox is read once; later sends are
 * picked up from its changes, so a contact written to a moment ago counts at once.
 */
export function outboxContacts(outbox: ContactSource, self: string): (pubkey: string) => Promise<boolean> {
  const known = new Set<string>();
  const add = (r: { meta?: Record<string, string> }) => {
    const to = r.meta?.recipient;
    if (to && to !== self && r.meta?.receipt === undefined) known.add(to);
  };
  outbox.onChange?.(add);
  let loaded: Promise<void> | undefined;
  return async (pubkey) => {
    loaded ??= outbox.list().then(
      (records) => records.forEach(add),
      (err: unknown) => {
        loaded = undefined; // read again next time: an unreadable outbox sends no receipt, it does not stop them for good
        throw err;
      },
    );
    await loaded;
    return known.has(pubkey);
  };
}
