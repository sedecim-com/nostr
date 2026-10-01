/**
 * FR013-03: rebuild a persona's history on a clean device (after restoring its backup): NIP-29 channels
 * (known + discovered from our own events and the NIP-51 kind 10009 list), NIP-17 DMs (gift wraps,
 * with the 2-day NIP-59 widening) and the relay evidence needed to reconcile the restored outbox.
 * FR013-05: with an event cache, each filter resumes per relay from its cursor and the result is what the cache holds.
 */
import { getTagValues, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { normalizeRelayUrl } from '@sedecim/relay-pool';
import { NIP29, channelFilter, dmInboxFilter, openDirectMessage, type DirectMessage } from '@sedecim/messaging';
import type { EventCache } from './cache';
import { sortEvents, syncHistory, type SyncReport, type SyncStrategy } from './index';
import { syncWithCache } from './resume';

/** NIP-51 "simple groups" list (NIP-29 memberships). */
export const GROUP_LIST_KIND = 10009;

/** Our own events that reveal which channels we are in. Kinds are explicit: relays p-gate unscoped REQs. */
export function ownActivityFilter(pubkey: string, since?: number): Filter {
  return {
    authors: [pubkey],
    kinds: [NIP29.ChatMessage, NIP29.Reaction, NIP29.Deletion, NIP29.CreateGroup, NIP29.JoinRequest, NIP29.LeaveRequest, GROUP_LIST_KIND],
    ...(since !== undefined ? { since } : {}),
  };
}

/** Channel ids referenced by our events: `h` tags, and `group` tags of the kind 10009 list. Left channels are dropped. */
export function discoverChannels(own: NostrEvent[]): string[] {
  const joined = new Set<string>();
  const lastLeave = new Map<string, number>();
  const lastActivity = new Map<string, number>();
  for (const e of own) {
    const ids = e.kind === GROUP_LIST_KIND ? getTagValues(e, 'group') : getTagValues(e, 'h');
    for (const id of ids) {
      joined.add(id);
      const map = e.kind === NIP29.LeaveRequest ? lastLeave : lastActivity;
      map.set(id, Math.max(map.get(id) ?? 0, e.created_at));
    }
  }
  return [...joined].filter((id) => (lastLeave.get(id) ?? -1) < (lastActivity.get(id) ?? 0)).sort();
}

export interface RebuildCacheOptions {
  store: EventCache;
  /** 'resume' (default): channels and DMs continue per relay from their cursors; 'full': everything the relays hold. */
  mode?: 'resume' | 'full';
  overlapSeconds?: number;
}

export interface RebuildOptions {
  relays: string[];
  pubkey: string;
  /**
   * Tried in order per relay (e.g. [NegentropySync, FilterWindowSync]). As a function it gets the lower bound the sync
   * starts from (with a cache, each relay's own), for strategies that need it such as FilterWindowSync.
   */
  strategies: SyncStrategy[] | ((since?: number) => SyncStrategy[]);
  /** Channels known from elsewhere (e.g. local config); merged with the discovered ones. */
  channels?: string[];
  /** Last successful sync (seconds). Undefined rebuilds the full history (with a cache: resumes from its cursors). */
  since?: number;
  /** Persona signer: when given, gift wraps are opened into DMs. */
  signer?: Signer;
  /**
   * FR013-05: sync through this event cache. Channels and DMs resume per relay from its cursors; what arrives is kept
   * there, and each result is what the cache holds for the filter plus what arrived now (docs/event-cache.md).
   */
  cache?: RebuildCacheOptions;
}

export interface RebuiltHistory {
  channels: Record<string, NostrEvent[]>;
  /** gift wraps addressed to us (including our own copies of sent DMs) */
  wraps: NostrEvent[];
  /** opened DMs, deduplicated by rumor id, ordered by rumor created_at */
  dms: DirectMessage[];
  /** wraps that could not be opened (not for us / malformed) */
  undecryptable: number;
  /** our own channel activity and group list */
  own: NostrEvent[];
  seenOn: Map<string, Set<string>>;
  reports: { own: SyncReport; dms: SyncReport; channels: Record<string, SyncReport> };
}

function mergeSeen(into: Map<string, Set<string>>, from: Map<string, Set<string>>) {
  for (const [id, relays] of from) {
    const s = into.get(id) ?? new Set<string>();
    for (const r of relays) s.add(normalizeRelayUrl(r));
    into.set(id, s);
  }
}

export async function rebuildHistory(opts: RebuildOptions): Promise<RebuiltHistory> {
  const given = opts.strategies;
  const strategies = typeof given === 'function' ? given : () => given;
  const cache = opts.cache;
  /** One filter from every relay: directly, or through the cache, resuming from its cursors when `resumable`. */
  const sync = (filter: (since?: number) => Filter, resumable: boolean, since = opts.since): Promise<SyncReport> =>
    cache
      ? syncWithCache({
          cache: cache.store,
          relays: opts.relays,
          filter,
          strategies,
          mode: resumable ? (cache.mode ?? 'resume') : 'full',
          ...(since !== undefined ? { since } : {}),
          ...(cache.overlapSeconds !== undefined ? { overlapSeconds: cache.overlapSeconds } : {}),
        })
      : syncHistory(opts.relays, filter(since), strategies(since));
  const own = (since?: number) => ownActivityFilter(opts.pubkey, since);
  const seenOn = new Map<string, Set<string>>();
  // Channel discovery looks at our whole activity, not just the window: joining is older than `since`. With a cache that
  // whole activity is a single sync (NIP-77 only fetches what the cache lacks) and the window is cut from it afterwards.
  const [ownReport, dmReport] = await Promise.all([sync(own, false, cache ? undefined : opts.since), sync((since) => dmInboxFilter(opts.pubkey, since), true)]);
  mergeSeen(seenOn, ownReport.seenOn);
  mergeSeen(seenOn, dmReport.seenOn);

  const ownAll = opts.since === undefined || cache ? ownReport : await sync(own, false, undefined);
  const ownEvents = cache && opts.since !== undefined ? ownReport.events.filter((e) => e.created_at >= opts.since!) : ownReport.events;
  const channelIds = [...new Set([...(opts.channels ?? []), ...discoverChannels(ownAll.events)])].sort();
  const channels: RebuiltHistory['channels'] = {};
  const channelReports: Record<string, SyncReport> = {};
  for (const id of channelIds) {
    const r = await sync((since) => channelFilter(id, since), true);
    channels[id] = r.events;
    channelReports[id] = r;
    mergeSeen(seenOn, r.seenOn);
  }

  const dms = new Map<string, DirectMessage>();
  let undecryptable = 0;
  if (opts.signer) {
    for (const w of dmReport.events) {
      try {
        const m = await openDirectMessage(opts.signer, w);
        if (!dms.has(m.rumor.id)) dms.set(m.rumor.id, m);
      } catch {
        undecryptable++;
      }
    }
  }
  return {
    channels,
    wraps: dmReport.events,
    dms: [...dms.values()].sort((a, b) => a.rumor.created_at - b.rumor.created_at || (a.rumor.id < b.rumor.id ? -1 : 1)),
    undecryptable,
    own: sortEvents([...ownEvents]),
    seenOn,
    reports: { own: ownReport, dms: dmReport, channels: channelReports },
  };
}

/**
 * Relay evidence from a sync as a delivery-engine `EventLookup`: `engine.reconcile()` then marks restored
 * outbox operations as accepted where the relay demonstrably stores the event (no republish).
 */
export function seenLookup(seenOn: Map<string, Set<string>>): { has(relay: string, eventId: string): Promise<boolean> } {
  return { has: async (relay, eventId) => seenOn.get(eventId)?.has(normalizeRelayUrl(relay)) ?? false };
}
