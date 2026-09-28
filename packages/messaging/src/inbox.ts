/**
 * FR009-03: a persona's DM inbox. Contacts send their DMs, and their receipts for our DMs, to the DM relays we
 * publish (kind 10050), so that is where the inbox reads: once (`sync`) or in the background (`start`, a live
 * subscription the pool renews after each reconnection). Every gift wrap for us is opened here:
 * - a receipt from the recipient of one of our DMs advances that operation (RECIPIENT_ACKED, READ; FR009-02);
 * - a message is kept and answered with the receipts the profile allows (ADR 0005), at most one of each type per
 *   message, sent to the sender's DM relays, where the sender's own inbox reads them.
 */
import type { Filter, NostrEvent, Signer } from '@sedecim/nostr-core';
import { resolveDmRelays, type DmRelayCache, type RelayQuery } from './dm-relays';
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
  /** Receipts already sent, by `<type>:<rumor id>`, so that each goes at most once, across sessions. */
  sent: { get(key: string): Promise<boolean | undefined>; put(key: string, value: boolean): Promise<void> };
  wrapOptions?: WrapOptions;
  cache?: DmRelayCache;
  timeoutMs?: number;
  /** A message read for the first time. `live`: it arrived through the subscription after the stored ones. */
  onMessage?: (m: DirectMessage, live: boolean) => void;
  /** A receipt for one of our DMs, with that operation as the receipt leaves it (states never move backwards). */
  onReceipt?: (r: Receipt, record: R) => void;
}

export class DmInbox<R> {
  private readonly seen = new Set<string>();
  private readonly messages = new Map<string, DirectMessage>();
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

  /** The messages read so far, oldest first. */
  list(): DirectMessage[] {
    return [...this.messages.values()].sort((a, b) => a.rumor.created_at - b.rumor.created_at);
  }

  /** The user saw a message: a read receipt, only if the profile allows it (opt-in, ADR 0005). */
  markRead(m: DirectMessage): Promise<void> {
    return this.serial(() => this.receipt(m, 'read'));
  }

  close(): void {
    this.closed = true;
    this.sub?.close();
    this.sub = undefined;
  }

  private async pubkey(): Promise<string> {
    return (this.me ??= await this.signer.getPublicKey());
  }

  private discovery(): string[] {
    return this.opts.discoveryRelays ?? this.opts.ownRelays;
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
    if (u.rumor.kind !== DM_KIND && u.rumor.kind !== FILE_MESSAGE_KIND) return;
    const m = directMessageFrom(u);
    if (this.messages.has(m.rumor.id)) return;
    this.messages.set(m.rumor.id, m);
    this.opts.onMessage?.(m, live);
    await this.receipt(m, 'delivered');
  }

  private async receipt(m: DirectMessage, type: ReceiptType): Promise<void> {
    const policy = this.opts.policy();
    if (!policy[type] || this.closed || m.sender === (await this.pubkey())) return;
    const key = `${type}:${m.rumor.id}`;
    if (await this.opts.sent.get(key)) return;
    const messenger = new DirectMessenger(this.signer, { nip17: true, readReceipts: policy.read }, this.opts.wrapOptions);
    await messenger.receipt(m.sender, m.rumor.id, type, { pool: this.opts.pool, outbox: this.opts.outbox, ownRelays: this.opts.ownRelays, discoveryRelays: this.discovery(), cache: this.opts.cache, timeoutMs: this.opts.timeoutMs, quorum: 1 });
    await this.opts.sent.put(key, true);
  }
}
