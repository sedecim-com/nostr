/**
 * History reconstruction after reinstall/reconnect (FR-013). NIP-77 (Negentropy) is draft/optional:
 * strategies are tried in order and the REQ/time-window fallback always exists.
 */
import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';

export interface SyncStrategy {
  readonly name: string;
  /** Resolve false if the strategy cannot be used with this relay (e.g. no NIP-77 support). */
  supported(relay: string): Promise<boolean>;
  run(relay: string, filter: Filter, onEvent: (e: NostrEvent) => void): Promise<void>;
}

export interface WindowSyncOptions {
  since: number;
  until?: number;
  /** size of each time window (seconds) */
  windowSeconds?: number;
  /** page size inside a window; windows that return `pageLimit` events are paginated with `until` */
  pageLimit?: number;
  timeoutMs?: number;
}

/** Fallback strategy: walk backwards in time windows with paginated REQs until `since`. */
export class FilterWindowSync implements SyncStrategy {
  readonly name = 'req-window';
  constructor(private readonly pool: RelayPool, private readonly opts: WindowSyncOptions) {}

  async supported(): Promise<boolean> {
    return true;
  }

  async run(relay: string, filter: Filter, onEvent: (e: NostrEvent) => void): Promise<void> {
    const window = this.opts.windowSeconds ?? 7 * 24 * 3600;
    const limit = this.opts.pageLimit ?? 500;
    let upper = this.opts.until ?? Math.floor(Date.now() / 1000);
    while (upper >= this.opts.since) {
      const lower = Math.max(this.opts.since, upper - window + 1);
      let pageUntil = upper;
      for (;;) {
        const page = await this.pool.query([relay], [{ ...filter, since: lower, until: pageUntil, limit }], this.opts.timeoutMs ?? 10_000);
        page.forEach(onEvent);
        if (page.length < limit) break;
        const oldest = Math.min(...page.map((e) => e.created_at));
        if (oldest <= lower || oldest > pageUntil) break;
        pageUntil = oldest; // inclusive: duplicates are removed by id
      }
      if (lower === this.opts.since) break;
      upper = lower - 1;
    }
  }
}

/**
 * Placeholder for NIP-77. It declares itself unsupported until a Negentropy implementation is wired in,
 * which keeps the orchestration and tests honest about what runs today.
 */
export class NegentropySync implements SyncStrategy {
  readonly name = 'nip77-negentropy';
  async supported(): Promise<boolean> {
    return false;
  }
  async run(): Promise<void> {
    throw new Error('NIP-77 not implemented');
  }
}

export interface SyncReport {
  events: NostrEvent[];
  perRelay: Record<string, { strategy: string; count: number; error?: string }>;
}

export async function syncHistory(relays: string[], filter: Filter, strategies: SyncStrategy[]): Promise<SyncReport> {
  const byId = new Map<string, NostrEvent>();
  const perRelay: SyncReport['perRelay'] = {};
  await Promise.all(
    relays.map(async (relay) => {
      for (const s of strategies) {
        if (!(await s.supported(relay).catch(() => false))) continue;
        let count = 0;
        try {
          await s.run(relay, filter, (e) => {
            count++;
            byId.set(e.id, e);
          });
          perRelay[relay] = { strategy: s.name, count };
        } catch (err) {
          perRelay[relay] = { strategy: s.name, count, error: (err as Error).message };
        }
        return;
      }
      perRelay[relay] = { strategy: 'none', count: 0, error: 'no supported strategy' };
    }),
  );
  return { events: [...byId.values()].sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : 1)), perRelay };
}
