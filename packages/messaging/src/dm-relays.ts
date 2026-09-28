/**
 * DM relay routing (FR-010, FR-017): NIP-17 kind 10050 ("DM relays") with the NIP-65 kind 10002 read
 * relays as fallback. Relay lists are public, replaceable events; the sender resolves the recipient's list
 * on its discovery relays and publishes the gift wrap there.
 */
import type { Filter, NostrEvent, Signer } from '@sedecim/nostr-core';

export const DM_RELAY_LIST_KIND = 10_050;
export const RELAY_LIST_KIND = 10_002;

/** Where the recipient's relays came from. Anything but 'dm-relays' is a guess the UI must disclose. */
export type DmRelaySource = 'dm-relays' | 'nip65-read' | 'fallback';

export interface ResolvedDmRelays {
  relays: string[];
  source: DmRelaySource;
}

/** The part of RelayPool needed to look relay lists up (kept structural: messaging has no pool dependency). */
export interface RelayQuery {
  query(urls: string[], filters: Filter[], timeoutMs?: number): Promise<NostrEvent[]>;
}

export interface ResolveDmRelaysOptions {
  /** Used when the recipient publishes neither list (e.g. the sender's own relays). */
  fallback: string[];
  /** Relays where relay lists are looked up. */
  discoveryRelays: string[];
  timeoutMs?: number;
  cache?: DmRelayCache;
}

function relayUrls(urls: Iterable<string | undefined>): string[] {
  const out = new Set<string>();
  for (const raw of urls) {
    if (!raw) continue;
    try {
      const u = new URL(raw.trim());
      if (u.protocol === 'ws:' || u.protocol === 'wss:') out.add(u.pathname === '/' && !u.search ? u.origin : u.toString());
    } catch {
      /* ignore malformed entries in someone else's list */
    }
  }
  return [...out];
}

/** Builds and signs the kind 10050 list the recipient's contacts use to route DMs to us (FR017-04). */
export async function publishDmRelayList(signer: Signer, relays: string[]): Promise<NostrEvent> {
  const urls = relayUrls(relays);
  if (urls.length === 0) throw new Error('at least one ws:// or wss:// relay is required');
  return signer.signEvent({ kind: DM_RELAY_LIST_KIND, content: '', tags: urls.map((u) => ['relay', u]) });
}

/** Relays from a kind 10050 event. */
export function parseDmRelayList(evt: NostrEvent): string[] {
  return evt.kind === DM_RELAY_LIST_KIND ? relayUrls(evt.tags.filter((t) => t[0] === 'relay').map((t) => t[1])) : [];
}

/** NIP-65 read relays: `r` tags marked 'read' or without a marker (read + write). */
export function parseNip65ReadRelays(evt: NostrEvent): string[] {
  if (evt.kind !== RELAY_LIST_KIND) return [];
  return relayUrls(evt.tags.filter((t) => t[0] === 'r' && (t[2] === undefined || t[2] === '' || t[2] === 'read')).map((t) => t[1]));
}

/**
 * Short-lived per-recipient cache of the relay lists discovery found. Finding nothing is never cached (FR010-03):
 * offline it looks just like a recipient without lists, and caching it would send their DMs to the fallback.
 */
export class DmRelayCache {
  private readonly entries = new Map<string, { at: number; value: ResolvedDmRelays }>();
  constructor(readonly ttlMs = 5 * 60_000, private readonly now: () => number = Date.now) {}

  get(key: string): ResolvedDmRelays | undefined {
    const e = this.entries.get(key);
    if (!e) return undefined;
    if (this.now() - e.at > this.ttlMs) {
      this.entries.delete(key);
      return undefined;
    }
    return e.value;
  }

  set(key: string, value: ResolvedDmRelays): void {
    this.entries.set(key, { at: this.now(), value });
  }

  /** Forget a recipient, e.g. after they publish a new list. */
  delete(pubkey: string): void {
    for (const k of this.entries.keys()) if (k.startsWith(`${pubkey}|`)) this.entries.delete(k);
  }
}

export const defaultDmRelayCache = new DmRelayCache();

function newest(events: NostrEvent[], kind: number, pubkey: string): NostrEvent | undefined {
  // Relays are not trusted to honour `authors`: only the recipient's own signed lists count.
  return events
    .filter((e) => e.kind === kind && e.pubkey === pubkey)
    .sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0];
}

/**
 * Recipient DM relays: newest kind 10050 → its relays; else newest kind 10002 → read relays; else
 * `fallback`. An empty list counts as absent.
 */
export async function resolveDmRelays(pool: RelayQuery, recipientPubkey: string, opts: ResolveDmRelaysOptions): Promise<ResolvedDmRelays> {
  const cache = opts.cache ?? defaultDmRelayCache;
  const key = `${recipientPubkey}|${[...opts.discoveryRelays].sort().join(',')}`;
  let found = cache.get(key);
  if (!found) {
    try {
      const events = await pool.query(opts.discoveryRelays, [{ kinds: [DM_RELAY_LIST_KIND, RELAY_LIST_KIND], authors: [recipientPubkey] }], opts.timeoutMs ?? 5000);
      const dm = newest(events, DM_RELAY_LIST_KIND, recipientPubkey);
      const nip65 = newest(events, RELAY_LIST_KIND, recipientPubkey);
      const dmRelays = dm ? parseDmRelayList(dm) : [];
      const readRelays = nip65 ? parseNip65ReadRelays(nip65) : [];
      found = dmRelays.length ? { relays: dmRelays, source: 'dm-relays' } : readRelays.length ? { relays: readRelays, source: 'nip65-read' } : undefined;
      if (found) cache.set(key, found);
    } catch {
      /* discovery failed: fall back, and ask again next time */
    }
  }
  return found ?? { relays: relayUrls(opts.fallback), source: 'fallback' };
}

/** New relays for an outbox record, from the delivery engine's router (FR010-03). */
export interface DmRoute {
  relays: string[];
  meta: Record<string, string>;
}

/**
 * FR010-03: resolves a DM wrap's relays when it is published, not only when it was written. The delivery engine
 * asks before each retry of a wrap for a recipient (`meta.recipient` with a `meta.dmRelaySource` other than
 * 'self', as DirectMessenger queues them) until a relay accepts it. A wrap written offline, when discovery found
 * nothing and it was queued for the fallback, goes to the recipient's DM relays as soon as they can be found.
 */
export function dmRouter(pool: RelayQuery, opts: ResolveDmRelaysOptions): (rec: { meta?: Record<string, string> }) => Promise<DmRoute | undefined> {
  return async (rec) => {
    const recipient = rec.meta?.recipient;
    const source = rec.meta?.dmRelaySource;
    if (!recipient || !source || source === 'self') return undefined;
    const route = await resolveDmRelays(pool, recipient, opts);
    return { relays: route.relays, meta: { dmRelaySource: route.source } };
  };
}
