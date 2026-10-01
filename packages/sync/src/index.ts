/**
 * History reconstruction after reinstall/reconnect (FR-013). NIP-77 (Negentropy) is optional:
 * strategies are tried in order per relay, and if one is unsupported or fails mid-session the next one
 * (ultimately the REQ/time-window fallback) takes over.
 */
import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';
import { queryUntilEose } from './eose';

export interface SyncStrategy {
  readonly name: string;
  /** Resolve false if the strategy cannot be used with this relay (e.g. no NIP-77 support). */
  supported(relay: string): Promise<boolean>;
  run(relay: string, filter: Filter, onEvent: (e: NostrEvent) => void): Promise<void>;
}

export interface WindowSyncOptions {
  /** Lower bound; a `since` in the filter that is older (e.g. the 2-day gift-wrap widening) wins. */
  since: number;
  /** Upper bound; defaults to the filter's `until`, else now. */
  until?: number;
  /** size of each time window (seconds) */
  windowSeconds?: number;
  /** page size inside a window; windows that return `pageLimit` events are paginated with `until` */
  pageLimit?: number;
  timeoutMs?: number;
  /**
   * FR013-05: fail (so the next strategy runs, or the relay counts as not synced) unless every page ends with the
   * relay's EOSE. Off by default: a page cut by the timeout or a CLOSED then counts as complete, as before.
   */
  requireEose?: boolean;
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
    // FR013-04: honour an older `since` carried by the filter (dmInboxFilter widens it by 2 days for
    // NIP-59 backdated wraps); otherwise the window walk would silently drop those wraps.
    const since = Math.min(this.opts.since, filter.since ?? this.opts.since);
    let upper = this.opts.until ?? filter.until ?? Math.floor(Date.now() / 1000);
    const timeoutMs = this.opts.timeoutMs ?? 10_000;
    // Strict pages hand over each event as it arrives, so what came before a cut is kept even though the page fails.
    const fetchPage = (f: Filter): Promise<NostrEvent[]> =>
      this.opts.requireEose ? queryUntilEose(this.pool, relay, [f], timeoutMs, onEvent) : this.pool.query([relay], [f], timeoutMs).then((events) => (events.forEach(onEvent), events));
    while (upper >= since) {
      const lower = Math.max(since, upper - window + 1);
      let pageUntil = upper;
      for (;;) {
        const page = await fetchPage({ ...filter, since: lower, until: pageUntil, limit });
        if (page.length < limit) break;
        const oldest = Math.min(...page.map((e) => e.created_at));
        if (oldest <= lower || oldest > pageUntil) break;
        pageUntil = oldest; // inclusive: duplicates are removed by id
      }
      if (lower === since) break;
      upper = lower - 1;
    }
  }
}

export interface StrategyAttempt {
  strategy: string;
  /** false when `supported()` said no (the strategy never ran) */
  supported: boolean;
  count: number;
  error?: string;
}

export interface RelaySyncResult {
  /** strategy that completed ('none' if every strategy was unsupported or failed) */
  strategy: string;
  /** events received from this relay across all attempts (duplicates included) */
  count: number;
  error?: string;
  /** every strategy considered, in order: shows the automatic fallback */
  attempts: StrategyAttempt[];
}

export interface SyncReport {
  /** deduplicated by id, sorted by created_at then id */
  events: NostrEvent[];
  perRelay: Record<string, RelaySyncResult>;
  /** relays on which each event id was seen (e.g. to reconcile outbox acks) */
  seenOn: Map<string, Set<string>>;
}

/**
 * Syncs `filter` from every relay (in parallel). Per relay, strategies are tried in order: unsupported
 * ones are skipped and a strategy that fails mid-session falls back to the next one. Events already
 * received are kept; duplicates across strategies/relays are removed by id.
 */
export async function syncHistory(relays: string[], filter: Filter, strategies: SyncStrategy[]): Promise<SyncReport> {
  const byId = new Map<string, NostrEvent>();
  const seenOn = new Map<string, Set<string>>();
  const perRelay: SyncReport['perRelay'] = {};
  await Promise.all(
    relays.map(async (relay) => {
      const attempts: StrategyAttempt[] = [];
      let total = 0;
      for (const s of strategies) {
        if (!(await s.supported(relay).catch(() => false))) {
          attempts.push({ strategy: s.name, supported: false, count: 0 });
          continue;
        }
        const attempt: StrategyAttempt = { strategy: s.name, supported: true, count: 0 };
        attempts.push(attempt);
        try {
          await s.run(relay, filter, (e) => {
            attempt.count++;
            total++;
            byId.set(e.id, e);
            const where = seenOn.get(e.id) ?? new Set<string>();
            where.add(relay);
            seenOn.set(e.id, where);
          });
          perRelay[relay] = { strategy: s.name, count: total, attempts };
          return;
        } catch (err) {
          attempt.error = (err as Error).message;
        }
      }
      const lastError = attempts.filter((a) => a.error).at(-1)?.error;
      perRelay[relay] = { strategy: 'none', count: total, error: lastError ?? 'no supported strategy', attempts };
    }),
  );
  return { events: sortEvents([...byId.values()]), perRelay, seenOn };
}

/** Canonical order used across the package: created_at ascending, then id. */
export function sortEvents<T extends { created_at: number; id: string }>(events: T[]): T[] {
  return events.sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export * from './eose';
export * from './negentropy';
export * from './jsonl';
export * from './cache';
export * from './resume';
export * from './rebuild';
