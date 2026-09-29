import { getTagValues, type NostrEvent, type Rumor, type Signer } from '@sedecim/nostr-core';
import { createDirectMessage, directMessageRumor, DM_KIND, fileMessageRumor, openDirectMessage, type DirectMessageInput, type FileMessageInput, type WrappedMessage, type DirectMessage } from './nip17';
import { wrapRumor, type WrapOptions } from './nip59';
import { resolveDmRelays, type DmRelayCache, type DmRelaySource, type RelayQuery } from './dm-relays';
import { OperationMismatchError, wrapOpId, type DmOperation, type DmOperationStore } from './operations';
import { createReceipt, type ReceiptType } from './receipts';

export interface MessagingFlags {
  /** NIP-17 DMs: disabled until the E2E interop suite passes against the pinned relay (FR-017). */
  nip17: boolean;
  /** Read receipts are opt-in. */
  readReceipts: boolean;
}

export const DEFAULT_FLAGS: MessagingFlags = { nip17: false, readReceipts: false };

export class FeatureDisabledError extends Error {
  constructor(readonly feature: string) {
    super(`feature disabled: ${feature}`);
  }
}

/** The part of DeliveryEngine used to queue wraps (structural: messaging has no engine dependency). */
export interface DmOutbox<R> {
  submit(input: { event: NostrEvent }, opts: { relays: string[]; groupId?: string; meta?: Record<string, string>; quorum?: number; wait?: boolean; opId?: string }): Promise<R>;
}

/** FR011-05: an outbox that also finds and re-drives what an operation already queued (a DeliveryEngine). */
export interface OperationOutbox<R> extends DmOutbox<R> {
  get(opId: string): Promise<R | undefined>;
  process(opId: string): Promise<R>;
}

/** What the messenger reads back from a wrap already queued: where it went. */
export interface QueuedWrap {
  relays: string[];
  meta?: Record<string, string>;
}

export interface DmSendOptions<R> {
  /** Looks up the recipients' relay lists (a RelayPool). */
  pool: RelayQuery;
  /** Where the wraps are queued (a DeliveryEngine). */
  outbox: DmOutbox<R>;
  /** Sender's relays: receive the sender's own copy; also the default discovery and fallback relays. */
  ownRelays: string[];
  discoveryRelays?: string[];
  /** Used for recipients without kind 10050 / 10002 (default: ownRelays). */
  fallback?: string[];
  timeoutMs?: number;
  cache?: DmRelayCache;
  quorum?: number;
  wait?: boolean;
}

/** FR011-05: sending as a client operation (DmOperation): the outbox re-drives, and the operation store is kept. */
export interface DmOperationOptions<R> extends Omit<DmSendOptions<R>, 'outbox'> {
  outbox: OperationOutbox<R>;
  operations: DmOperationStore;
}

type RouteOptions = Pick<DmSendOptions<unknown>, 'pool' | 'ownRelays' | 'discoveryRelays' | 'fallback' | 'timeoutMs' | 'cache'>;

/** A stored DM is the retry of `input` only if it says the same to the same people. */
function sameMessage(rumor: Rumor, input: DirectMessageInput): boolean {
  const to = new Set(getTagValues(rumor, 'p'));
  return rumor.kind === DM_KIND && rumor.content === input.content && to.size === new Set(input.recipients).size && input.recipients.every((r) => to.has(r));
}

export interface DmDelivery<R> {
  recipient: string;
  relays: string[];
  /** 'self' for the sender's own copy. Anything but 'dm-relays' means "destinatario sin relays de DM". */
  source: DmRelaySource | 'self';
  record: R;
}

/** Thin façade that enforces feature flags around NIP-17 building/opening. */
export class DirectMessenger {
  constructor(private readonly signer: Signer, private readonly flags: MessagingFlags = DEFAULT_FLAGS, private readonly wrapOptions: WrapOptions = {}) {}

  compose(input: DirectMessageInput): Promise<WrappedMessage> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    return createDirectMessage(this.signer, input, this.wrapOptions);
  }

  /**
   * Composes and queues a DM: each recipient's wrap goes to that recipient's resolved DM relays
   * (FR-010), the sender's copy to `ownRelays`. The routing source is stored in the outbox record meta
   * (`recipient`, `dmRelaySource`) so the outbox/UI can flag recipients without DM relays.
   */
  async send<R>(input: DirectMessageInput, opts: DmSendOptions<R>): Promise<{ message: WrappedMessage; deliveries: Array<DmDelivery<R>> }> {
    return this.deliver(await this.compose(input), opts);
  }

  /**
   * FR011-05 (scope §11.1, §11.2): send() as the client operation `opId` (see DmOperation). The rumor is stored
   * before any wrap is made; called again with the same id (the user retries), it reuses that rumor, re-drives the
   * wraps already queued and makes only the missing ones. No other rumor, no other event. Another text or recipient
   * under the same id is refused (OperationMismatchError): that is a new message, not a retry.
   */
  sendDmOnce<R extends QueuedWrap>(opId: string, input: DirectMessageInput, opts: DmOperationOptions<R>): Promise<{ rumor: Rumor; deliveries: Array<DmDelivery<R>> }> {
    return this.sendOperation(opId, () => directMessageRumor(this.signer, input), opts, (rumor) => sameMessage(rumor, input));
  }

  /** FR011-05: a file message (kind 15) as a client operation. `input` runs only on the first try: it uploads the file. */
  sendFileOnce<R extends QueuedWrap>(opId: string, input: () => Promise<FileMessageInput>, opts: DmOperationOptions<R>): Promise<{ rumor: Rumor; deliveries: Array<DmDelivery<R>> }> {
    return this.sendOperation(opId, async () => fileMessageRumor(this.signer, await input()), opts);
  }

  private async sendOperation<R extends QueuedWrap>(opId: string, makeRumor: () => Promise<Rumor>, opts: DmOperationOptions<R>, matches?: (rumor: Rumor) => boolean): Promise<{ rumor: Rumor; deliveries: Array<DmDelivery<R>> }> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    const me = await this.signer.getPublicKey();
    let op = await opts.operations.get(opId);
    if (op && matches && !matches(op.rumor)) throw new OperationMismatchError(opId);
    if (!op) {
      const rumor = await makeRumor();
      op = { opId, rumor, targets: [...new Set([...getTagValues(rumor, 'p'), me])], createdAt: Date.now() } satisfies DmOperation;
      // Stored before any seal or wrap exists: a failed signer or a closed tab leaves this, never half a message.
      await opts.operations.put(opId, op);
    }
    const deliveries: Array<DmDelivery<R>> = [];
    for (const target of op.targets) {
      const id = wrapOpId(opId, target);
      const queued = await opts.outbox.get(id);
      if (queued) {
        // Queued by an earlier try: sent again now, the retry the user asked for, and never wrapped again.
        let record = queued;
        if (opts.wait) record = await opts.outbox.process(id);
        else void opts.outbox.process(id).catch(() => undefined);
        const source = target === me ? 'self' : ((queued.meta?.dmRelaySource as DmRelaySource | undefined) ?? 'fallback');
        deliveries.push({ recipient: target, relays: queued.relays, source, record });
        continue;
      }
      const route = target === me ? { relays: opts.ownRelays, source: 'self' as const } : await this.route(target, opts);
      const event = await wrapRumor(this.signer, op.rumor, target, this.wrapOptions);
      const record = await opts.outbox.submit({ event }, { opId: id, relays: route.relays, groupId: op.rumor.id, meta: { recipient: target, dmRelaySource: route.source }, quorum: opts.quorum, wait: opts.wait });
      deliveries.push({ recipient: target, relays: route.relays, source: route.source, record });
    }
    if (op.queuedAt === undefined) await opts.operations.put(opId, { ...op, queuedAt: Date.now() });
    return { rumor: op.rumor, deliveries };
  }

  /** Routes an already wrapped message (e.g. a kind 15 file message) exactly like send(). */
  async deliver<R>(message: WrappedMessage, opts: DmSendOptions<R>): Promise<{ message: WrappedMessage; deliveries: Array<DmDelivery<R>> }> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    const me = await this.signer.getPublicKey();
    const deliveries: Array<DmDelivery<R>> = [];
    for (const w of message.wraps) {
      const route = w.recipient === me ? { relays: opts.ownRelays, source: 'self' as const } : await this.route(w.recipient, opts);
      const record = await opts.outbox.submit(
        { event: w.event },
        { relays: route.relays, groupId: message.rumor.id, meta: { recipient: w.recipient, dmRelaySource: route.source }, quorum: opts.quorum, wait: opts.wait },
      );
      deliveries.push({ recipient: w.recipient, relays: route.relays, source: route.source, record });
    }
    return { message, deliveries };
  }

  /**
   * FR009-03: a receipt goes where the message's sender reads, like a DM: to the sender's DM relays (kind 10050,
   * else NIP-65 read relays, else `fallback`), never only to ours. The record keeps `meta.recipient` and
   * `meta.dmRelaySource`, so a retry resolves the route again (FR010-03), and `meta.receipt`. Read receipts also
   * need the `readReceipts` flag (opt-in, ADR 0005).
   */
  async receipt<R>(to: string, rumorId: string, type: ReceiptType, opts: DmSendOptions<R>): Promise<DmDelivery<R>> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    if (type === 'read' && !this.flags.readReceipts) throw new FeatureDisabledError('readReceipts');
    const { rumor, event } = await createReceipt(this.signer, to, rumorId, type, this.wrapOptions);
    const route = await this.route(to, opts);
    const record = await opts.outbox.submit(
      { event },
      { relays: route.relays, groupId: rumor.id, meta: { recipient: to, dmRelaySource: route.source, receipt: type }, quorum: opts.quorum, wait: opts.wait },
    );
    return { recipient: to, relays: route.relays, source: route.source, record };
  }

  private route(recipient: string, opts: RouteOptions) {
    return resolveDmRelays(opts.pool, recipient, {
      discoveryRelays: opts.discoveryRelays ?? opts.ownRelays,
      fallback: opts.fallback ?? opts.ownRelays,
      timeoutMs: opts.timeoutMs,
      cache: opts.cache,
    });
  }

  open(wrap: NostrEvent): Promise<DirectMessage> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    return openDirectMessage(this.signer, wrap);
  }
}
