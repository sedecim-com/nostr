import type { NostrEvent, Signer } from '@sedecim/nostr-core';
import { createDirectMessage, openDirectMessage, type DirectMessageInput, type WrappedMessage, type DirectMessage } from './nip17';
import type { WrapOptions } from './nip59';
import { resolveDmRelays, type DmRelayCache, type DmRelaySource, type RelayQuery } from './dm-relays';

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
  submit(input: { event: NostrEvent }, opts: { relays: string[]; groupId?: string; meta?: Record<string, string>; quorum?: number; wait?: boolean }): Promise<R>;
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

  /** Routes an already wrapped message (e.g. a kind 15 file message) exactly like send(). */
  async deliver<R>(message: WrappedMessage, opts: DmSendOptions<R>): Promise<{ message: WrappedMessage; deliveries: Array<DmDelivery<R>> }> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    const me = await this.signer.getPublicKey();
    const deliveries: Array<DmDelivery<R>> = [];
    for (const w of message.wraps) {
      const route =
        w.recipient === me
          ? { relays: opts.ownRelays, source: 'self' as const }
          : await resolveDmRelays(opts.pool, w.recipient, {
              discoveryRelays: opts.discoveryRelays ?? opts.ownRelays,
              fallback: opts.fallback ?? opts.ownRelays,
              timeoutMs: opts.timeoutMs,
              cache: opts.cache,
            });
      const record = await opts.outbox.submit(
        { event: w.event },
        { relays: route.relays, groupId: message.rumor.id, meta: { recipient: w.recipient, dmRelaySource: route.source }, quorum: opts.quorum, wait: opts.wait },
      );
      deliveries.push({ recipient: w.recipient, relays: route.relays, source: route.source, record });
    }
    return { message, deliveries };
  }

  open(wrap: NostrEvent): Promise<DirectMessage> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    return openDirectMessage(this.signer, wrap);
  }
}
