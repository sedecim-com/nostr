/**
 * FR013-03: rebuild a persona's history on a clean device (after restoring its backup): NIP-29 channels
 * (known + discovered from our own events and the NIP-51 kind 10009 list), NIP-17 DMs (gift wraps,
 * with the 2-day NIP-59 widening) and the relay evidence needed to reconcile the restored outbox.
 * PANEL-06: what expired (NIP-40) is left out, even when a relay still serves it: each event by its own tag and, once
 * opened with the signer, a gift wrap also by its seal's; so the history export and the vault push do not carry it.
 */
import { getTagValues, isExpired, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { normalizeRelayUrl } from '@sedecim/relay-pool';
import { NIP29, channelFilter, dmInboxFilter, isUnwrappedExpired, openDirectMessage, type DirectMessage } from '@sedecim/messaging';
import { sortEvents, syncHistory, type SyncReport, type SyncStrategy } from './index';

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

export interface RebuildOptions {
  relays: string[];
  pubkey: string;
  /** Tried in order per relay (e.g. [NegentropySync, FilterWindowSync]). */
  strategies: SyncStrategy[];
  /** Channels known from elsewhere (e.g. local config); merged with the discovered ones. */
  channels?: string[];
  /** Last successful sync (seconds). Undefined rebuilds the full history. */
  since?: number;
  /** Persona signer: when given, gift wraps are opened into DMs. */
  signer?: Signer;
  /** PANEL-06: the clock (ms) against which NIP-40 expirations are read. */
  now?: () => number;
}

export interface RebuiltHistory {
  channels: Record<string, NostrEvent[]>;
  /** gift wraps addressed to us (including our own copies of sent DMs) */
  wraps: NostrEvent[];
  /** opened DMs, deduplicated by rumor id, ordered by rumor created_at */
  dms: DirectMessage[];
  /** wraps that could not be opened (not for us / malformed) */
  undecryptable: number;
  /** PANEL-06: events a relay still served after their NIP-40 expiration, left out of everything above */
  expired: number;
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
  const seenOn = new Map<string, Set<string>>();
  const [ownReport, dmReport] = await Promise.all([
    syncHistory(opts.relays, ownActivityFilter(opts.pubkey, opts.since), opts.strategies),
    syncHistory(opts.relays, dmInboxFilter(opts.pubkey, opts.since), opts.strategies),
  ]);
  mergeSeen(seenOn, ownReport.seenOn);
  mergeSeen(seenOn, dmReport.seenOn);

  // Channel discovery looks at our whole activity, not just the window: joining is older than `since`.
  const ownAll = opts.since === undefined ? ownReport : await syncHistory(opts.relays, ownActivityFilter(opts.pubkey), opts.strategies);
  const channelIds = [...new Set([...(opts.channels ?? []), ...discoverChannels(ownAll.events)])].sort();
  // PANEL-06: NIP-40 asks clients to ignore what expired, which a relay that does not honour it keeps serving.
  const nowSeconds = Math.floor((opts.now ?? Date.now)() / 1000);
  // Each expired event counts once, though it may come in more than one list (e.g. a channel and our own activity).
  const expired = new Set<string>();
  const current = (events: NostrEvent[]) =>
    events.filter((e) => {
      if (!isExpired(e, nowSeconds)) return true;
      expired.add(e.id);
      return false;
    });
  const channels: RebuiltHistory['channels'] = {};
  const channelReports: Record<string, SyncReport> = {};
  for (const id of channelIds) {
    const r = await syncHistory(opts.relays, channelFilter(id, opts.since), opts.strategies);
    channels[id] = current(r.events);
    channelReports[id] = r;
    mergeSeen(seenOn, r.seenOn);
  }

  const wraps = current(dmReport.events);
  const dms = new Map<string, DirectMessage>();
  // The seal may carry an expiration the wrap does not show: such a wrap leaves `wraps` too.
  const sealExpired = new Set<string>();
  let undecryptable = 0;
  if (opts.signer) {
    for (const w of wraps) {
      try {
        const m = await openDirectMessage(opts.signer, w);
        if (isUnwrappedExpired(m, nowSeconds)) sealExpired.add(w.id);
        else if (!dms.has(m.rumor.id)) dms.set(m.rumor.id, m);
      } catch {
        undecryptable++;
      }
    }
  }
  for (const id of sealExpired) expired.add(id);
  const own = sortEvents(current([...ownReport.events]));
  return {
    channels,
    wraps: sealExpired.size ? wraps.filter((w) => !sealExpired.has(w.id)) : wraps,
    dms: [...dms.values()].sort((a, b) => a.rumor.created_at - b.rumor.created_at || (a.rumor.id < b.rumor.id ? -1 : 1)),
    undecryptable,
    expired: expired.size,
    own,
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
