import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import { getTagValues } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';
import type { Logger } from '@sedecim/telemetry-policy';
import type { EventRepository } from './repository';

/**
 * Default mirrored kinds: public + NIP-29 channel traffic. p-gated kinds (1059 gift wraps, 44100/44101)
 * are NOT requested: relays such as Buzz only serve them to their authenticated recipient, so the mirror
 * receives a user's gift wraps only through that user's own authenticated session (ciphertext-first).
 */
export const DEFAULT_MIRROR_KINDS = [0, 1, 3, 5, 6, 7, 9, 10, 11, 12, 16, 1111, 9000, 9001, 9002, 9005, 9007, 9008, 9009, 9021, 9022, 10002, 10050, 10063, 30023, 39000, 39001, 39002, 40002, 40003];

/** NIP-29 channel traffic mirrored per channel (Buzz only fans out channel events to `#h` subscriptions). */
export const CHANNEL_KINDS = [5, 7, 9, 10, 11, 12, 16, 1111, 40002, 40003];

export interface IndexerOptions {
  relays: string[];
  filters: Filter[];
  communityId?: string;
  logger?: Logger;
  /**
   * Discover visible channels (kind 39000) and keep a live `#h` subscription for them, refreshed every
   * intervalMs (39000 updates are channel-scoped too, so they are polled). 0 disables it.
   */
  channelRefreshMs?: number;
}

/**
 * Mirror that follows the same relays as Buzz Desktop/Mobile (spec §15). It never decrypts content
 * and never alters the canonical event: derived views are rebuilt from the signed events.
 */
export class Indexer {
  private sub?: { close(): void };
  ingested = 0;

  constructor(private readonly pool: RelayPool, private readonly repo: EventRepository, private readonly opts: IndexerOptions) {}

  async ingest(evt: NostrEvent, relay: string): Promise<boolean> {
    const isNew = await this.repo.upsert(evt, relay, this.opts.communityId);
    if (isNew) this.ingested++;
    if (isNew && evt.kind === 5) await this.repo.tombstone(getTagValues(evt, 'e'), evt.pubkey);
    return isNew;
  }

  private channelSub?: { close(): void };
  private channelTimer?: ReturnType<typeof setInterval>;
  readonly channels = new Set<string>();

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.sub = this.pool.subscribe(this.opts.relays, this.opts.filters, {
        onevent: (evt, relay) => {
          this.ingest(evt, relay).catch((err: Error) => this.opts.logger?.error('ingest failed', { error: err.message, event_id: evt.id }));
        },
        oneose: () => {
          void this.refreshChannels().finally(() => resolve());
          const every = this.opts.channelRefreshMs ?? 30_000;
          if (every > 0 && !this.channelTimer) {
            this.channelTimer = setInterval(() => void this.refreshChannels(), every);
            (this.channelTimer as { unref?: () => void }).unref?.();
          }
        },
        onclosed: (relay, reason) => this.opts.logger?.warn('subscription closed', { relay, reason }),
        dedupe: false,
      });
    });
  }

  /** Re-discover channels; (re)open one live `#h` subscription covering all of them when the set grows. */
  async refreshChannels(): Promise<string[]> {
    if ((this.opts.channelRefreshMs ?? 30_000) === 0) return [];
    const metas = await this.pool.query(this.opts.relays, [{ kinds: [39000], limit: 1000 }], 8000);
    for (const m of metas) await this.ingest(m, this.opts.relays[0]!).catch(() => false);
    const found = metas.map((m) => getTagValues(m, 'd')[0]).filter((d): d is string => !!d);
    const before = this.channels.size;
    found.forEach((id) => this.channels.add(id));
    if (this.channels.size !== before || (!this.channelSub && this.channels.size > 0)) {
      this.channelSub?.close();
      const ids = [...this.channels];
      this.channelSub = this.pool.subscribe(this.opts.relays, [{ kinds: CHANNEL_KINDS, '#h': ids }], {
        onevent: (evt, relay) => {
          this.ingest(evt, relay).catch((err: Error) => this.opts.logger?.error('ingest failed', { error: err.message, event_id: evt.id }));
        },
        onclosed: (relay, reason) => this.opts.logger?.warn('channel subscription closed', { relay, reason }),
        dedupe: false,
      });
      this.opts.logger?.info('mirroring channels', { count: ids.length });
    }
    return [...this.channels];
  }

  stop(): void {
    if (this.channelTimer) clearInterval(this.channelTimer);
    this.channelSub?.close();
    this.sub?.close();
  }
}
