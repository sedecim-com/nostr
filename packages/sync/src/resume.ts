/**
 * FR013-05: resumed sync over the event cache. Each relay has its own cursor per filter: the moment its last complete
 * sync started. The next sync asks that relay only from `cursor - overlap` (the filter helper may widen it further, as
 * dmInboxFilter does by the 2 days of NIP-59 for gift wraps, FR013-04), and the cursor moves only when a strategy
 * finished against that relay: NIP-77 reconciled and fetched every missing event, or every REQ page ended with EOSE.
 * A failure, a timeout or a cut connection leaves the cursor where it was; what did arrive is kept in the cache.
 */
import { matchFilter, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import type { EventCache } from './cache';
import { sortEvents, syncHistory, type RelaySyncResult, type SyncReport, type SyncStrategy } from './index';

/** Covers clock skew between clients and relays and the time an event takes to reach a relay. */
export const DEFAULT_RESUME_OVERLAP_SECONDS = 600;

export interface CachedSyncOptions {
  cache: EventCache;
  relays: string[];
  /**
   * The filter for a lower bound, e.g. `(since) => dmInboxFilter(pubkey, since)` (which widens `since` by 2 days for
   * gift wraps) or `(since) => channelFilter(id, since)`. Called without `since` for the filter's identity.
   */
  filter: (since?: number) => Filter;
  /** Strategies for one relay starting at `since` (undefined: from the beginning), tried in order. */
  strategies: (since: number | undefined) => SyncStrategy[];
  /**
   * 'resume' (default): each relay continues from its cursor, and never below the cache's floor. 'full': everything the
   * relays hold. Both move the cursors of the relays that complete.
   */
  mode?: 'resume' | 'full';
  /** Explicit lower bound: replaces the cursors, which then stay as they are (the window may leave a gap behind them). */
  since?: number;
  overlapSeconds?: number;
  /** Answer from the cache only: no strategy runs, so nothing touches the network and nothing waits for it. */
  offline?: boolean;
  /** Clock in seconds (tests). */
  now?: () => number;
}

export interface CachedRelayResult extends RelaySyncResult {
  /** lower bound asked of this relay (absent: everything it holds) */
  since?: number;
  /** its cursor after this sync */
  cursor?: number;
  /** whether this sync moved the cursor: only after a complete sync */
  advanced: boolean;
}

export interface CachedSyncReport extends SyncReport {
  /** what the cache holds for the filter plus what arrived now and its rules admit, whatever the limits kept */
  events: NostrEvent[];
  perRelay: Record<string, CachedRelayResult>;
  /** events that arrived from the relays in this run */
  received: number;
}

export async function syncWithCache(o: CachedSyncOptions): Promise<CachedSyncReport> {
  const now = o.now ?? (() => Math.floor(Date.now() / 1000));
  const identity = o.filter();
  const view = o.since !== undefined ? o.filter(o.since) : identity;
  const received = new Map<string, NostrEvent>();
  const seenOn = new Map<string, Set<string>>();
  const perRelay: Record<string, CachedRelayResult> = {};
  if (!o.offline) {
    const overlap = o.overlapSeconds ?? DEFAULT_RESUME_OVERLAP_SECONDS;
    const resume = o.mode !== 'full' && o.since === undefined;
    await Promise.all(
      o.relays.map(async (relay) => {
        const started = now();
        const stored = o.cache.cursor(relay, identity);
        // A cursor ahead of now (the clock was ahead when it was written) would skip everything until then: not used,
        // and replaced once this sync completes.
        const ahead = stored !== undefined && stored > started + overlap;
        const cursor = resume && !ahead ? stored : undefined;
        let filter = o.filter(o.since ?? (cursor !== undefined ? cursor - overlap : undefined));
        // Below the floor the limits drop events anyway: asking for them again would only churn the cache.
        if (resume && o.cache.floor > (filter.since ?? 0)) filter = { ...filter, since: o.cache.floor };
        const report = await syncHistory([relay], filter, o.strategies(filter.since));
        for (const e of report.events) received.set(e.id, e);
        for (const [id, where] of report.seenOn) seenOn.set(id, new Set([...(seenOn.get(id) ?? []), ...where]));
        // Kept even when the relay did not finish: the next sync (NIP-77 from this set) only fetches the rest.
        await o.cache.put(report.events, { relay });
        const result = report.perRelay[relay]!;
        const complete = result.strategy !== 'none';
        const after = complete && o.since === undefined ? await o.cache.advanceCursor(relay, identity, started, { reset: ahead }) : o.cache.cursor(relay, identity);
        perRelay[relay] = { ...result, ...(filter.since !== undefined ? { since: filter.since } : {}), ...(after !== undefined ? { cursor: after } : {}), advanced: complete && o.since === undefined };
      }),
    );
  }
  const events = new Map(o.cache.query(view).map((e) => [e.id, e]));
  for (const e of received.values()) if (!events.has(e.id) && o.cache.admits(e) && matchFilter(view, e)) events.set(e.id, e);
  return { events: sortEvents([...events.values()]), perRelay, seenOn, received: received.size };
}
