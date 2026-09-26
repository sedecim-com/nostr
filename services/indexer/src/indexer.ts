import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import { getTagValues } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';
import type { Logger } from '@sedecim/telemetry-policy';
import type { EventRepository } from './repository';

export interface IndexerOptions {
  relays: string[];
  filters: Filter[];
  communityId?: string;
  logger?: Logger;
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

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.sub = this.pool.subscribe(this.opts.relays, this.opts.filters, {
        onevent: (evt, relay) => {
          this.ingest(evt, relay).catch((err: Error) => this.opts.logger?.error('ingest failed', { error: err.message, event_id: evt.id }));
        },
        oneose: () => resolve(),
        onclosed: (relay, reason) => this.opts.logger?.warn('subscription closed', { relay, reason }),
        dedupe: false,
      });
    });
  }

  stop(): void {
    this.sub?.close();
  }
}
