/**
 * FR013-05 (spec §7, §12): a persona's local encrypted cache of Nostr events. It keeps the signed events exactly as the
 * relays serve them: channel messages, the persona's own activity and the gift wraps addressed to it, which stay
 * NIP-44 encrypted. An opened DM is never written here. The cache answers filters without the network (offline
 * reading), keeps a cursor per relay and filter (resuming by `since`) and remembers which relay served each event, so
 * that NIP-77 describes to a relay only what that relay already sent (docs/event-cache.md).
 *
 * Storage is an encrypted-store Collection: XChaCha20-Poly1305 values and HMAC'd entry names. Events go into 64 buckets
 * by the first byte of their id, so the backend holds at most 64 sealed entries of varying size plus one of metadata.
 * It does not see how many events there are, nor their ids, authors or channels.
 */
import { eventAddress, getTagValue, getTagValues, isAddressableKind, isEphemeralKind, isReplaceableKind, matchFilter, supersedes, validateEventShape, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import { normalizeRelayUrl } from '@sedecim/relay-pool';

const BUCKETS = 64;
const META_ID = 'meta';
const META_VERSION = 1;
/** Targets honoured per deletion event: a deletion naming thousands of ids cannot inflate the metadata record. */
const MAX_DELETION_TARGETS = 256;

export const DEFAULT_CACHE_MAX_EVENTS = 5000;
export const DEFAULT_CACHE_MAX_BYTES = 16 * 1024 * 1024;

/** What the cache needs from its storage; an encrypted-store `Collection` fits (values sealed at rest). */
export interface CacheCollection<T> {
  get(id: string): Promise<T | undefined>;
  put(id: string, value: T): Promise<void>;
  delete(id: string): Promise<void>;
  all(): Promise<Array<{ id: string; value: T }>>;
  clear(): Promise<void>;
}

/** Where the cache's collections come from: an encrypted-store `EncryptedStore` (or a `Vault`'s store) fits. */
export interface CacheStore {
  collection<T>(name: string): CacheCollection<T>;
}

export interface EventCacheOptions {
  /** Collection name (default `evcache`, plus `<name>-meta`). A store shared by personas (the web's vault) needs one each. */
  name?: string;
  /** Most events kept (default 5000). */
  maxEvents?: number;
  /** Most bytes of events kept, as serialised JSON (default 16 MiB). */
  maxBytes?: number;
  /** Events whose created_at is older than this many seconds are not kept (default: no age limit). */
  maxAgeSeconds?: number;
  /** Clock in seconds (tests). */
  now?: () => number;
}

export interface CachePutResult {
  /** events stored now (already held ones only gain the relay that served them) */
  added: number;
  /** refused by rule: malformed, ephemeral, expired (NIP-40), deleted (NIP-09 or NIP-29 9005) or an older replaceable version */
  refused: number;
  /** dropped by the limits (count, bytes, age), oldest first */
  evicted: number;
}

export interface CacheStats {
  events: number;
  bytes: number;
  oldest?: number;
  newest?: number;
  /** created_at below which the limits may have dropped events */
  floor: number;
  cursors: number;
}

export interface CacheCursor {
  relay: string;
  /** the filter it belongs to, without since/until/limit (see `filterKey`) */
  filter: string;
  at: number;
}

interface StoredEvent {
  e: NostrEvent;
  /** indexes into CacheMeta.relays of the relays that served it */
  r?: number[];
}

interface CacheMeta {
  v: number;
  relays: string[];
  /** `<relay index> <filter key>` → cursor (seconds) */
  cursors: Record<string, number>;
  floor: number;
  /** deleted id → [id of the deletion event, whom it applies to: an author pubkey or `h:<channel>`] */
  tombstones: Record<string, Array<[string, string]>>;
}

interface Entry {
  event: NostrEvent;
  relays: Set<number>;
  size: number;
  expiration?: number;
}

const emptyMeta = (): CacheMeta => ({ v: META_VERSION, relays: [], cursors: {}, floor: 0, tombstones: {} });
const bucketOf = (id: string) => (parseInt(id.slice(0, 2), 16) % BUCKETS).toString(16).padStart(2, '0');
const byTime = (a: Entry, b: Entry) => a.event.created_at - b.event.created_at || (a.event.id < b.event.id ? -1 : a.event.id > b.event.id ? 1 : 0);
const encoder = new TextEncoder();

/** NIP-40 `expiration` (unix seconds); a malformed value counts as none. */
function expirationOf(e: NostrEvent): number | undefined {
  const v = getTagValue(e, 'expiration');
  return v !== undefined && /^\d{1,12}$/.test(v) ? Number(v) : undefined;
}

const addressOf = (e: NostrEvent) => (isReplaceableKind(e.kind) || isAddressableKind(e.kind) ? eventAddress(e) : undefined);

/** Whom a deletion applies to: NIP-09 kind 5 only to its own author's events, NIP-29 9005 to events of its channel. */
const appliesTo = (scope: string, e: NostrEvent) => (scope.startsWith('h:') ? getTagValue(e, 'h') === scope.slice(2) : e.pubkey === scope);

/**
 * Identity of a filter for cursors: its fields without since/until/limit, keys and array values sorted, so the same
 * subscription always finds its cursor whatever its lower bound.
 */
export function filterKey(filter: Filter): string {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(filter).sort()) {
    const v = (filter as Record<string, unknown>)[k];
    if (k === 'since' || k === 'until' || k === 'limit' || v === undefined) continue;
    out[k] = Array.isArray(v) ? [...new Set(v)].sort((a, b) => (typeof a === 'number' && typeof b === 'number' ? a - b : String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0)) : v;
  }
  return JSON.stringify(out);
}

export class EventCache {
  private readonly entries = new Map<string, Entry>();
  private readonly byKind = new Map<number, Set<string>>();
  private readonly byAuthor = new Map<string, Set<string>>();
  private readonly byBucket = new Map<string, Set<string>>();
  /** replaceable/addressable address → id of the version kept */
  private readonly heads = new Map<string, string>();
  private ordered?: Entry[];
  private bytes = 0;
  private meta: CacheMeta = emptyMeta();
  private readonly dirty = new Set<string>();
  private metaDirty = false;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly maxEvents: number;
  private readonly maxBytes: number;
  private readonly maxAgeSeconds?: number;
  private readonly now: () => number;

  private constructor(
    private readonly buckets: CacheCollection<StoredEvent[]>,
    private readonly metaStore: CacheCollection<CacheMeta>,
    opts: EventCacheOptions,
  ) {
    this.maxEvents = Math.max(0, opts.maxEvents ?? DEFAULT_CACHE_MAX_EVENTS);
    this.maxBytes = Math.max(0, opts.maxBytes ?? DEFAULT_CACHE_MAX_BYTES);
    if (opts.maxAgeSeconds !== undefined) this.maxAgeSeconds = Math.max(0, opts.maxAgeSeconds);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Opens (reads and decrypts) the cache. Fails, and deletes nothing, if an entry does not decrypt (e.g. another key). */
  static async open(store: CacheStore, opts: EventCacheOptions = {}): Promise<EventCache> {
    const name = opts.name ?? 'evcache';
    const cache = new EventCache(store.collection<StoredEvent[]>(name), store.collection<CacheMeta>(`${name}-meta`), opts);
    await cache.load();
    return cache;
  }

  private async load(): Promise<void> {
    const meta = await this.metaStore.get(META_ID);
    if (meta && meta.v !== META_VERSION) throw new Error(`event cache format ${meta.v} is not supported: clear the cache`);
    if (meta) this.meta = meta;
    for (const { id: bucket, value } of await this.buckets.all()) {
      for (const stored of value) {
        const e = stored.e;
        if (!validateEventShape(e)) {
          this.dirty.add(bucket);
          continue;
        }
        // Rewritten where it belongs on the next write (a bucket layout change, or a copy left in the wrong entry).
        if (bucketOf(e.id) !== bucket) this.dirty.add(bucket).add(bucketOf(e.id));
        const held = this.entries.get(e.id);
        if (held) for (const r of stored.r ?? []) held.relays.add(r);
        else this.insert(e, new Set(stored.r ?? []));
      }
    }
    // Limits lowered since the last write, or events expired meanwhile: applied in memory, written with the next change.
    this.applyLimits(this.now());
  }

  get size(): number {
    return this.entries.size;
  }

  /** Events older than this (created_at) may have been dropped by the limits: a resumed sync does not ask below it. */
  get floor(): number {
    return this.meta.floor;
  }

  has(id: string): boolean {
    return this.entries.has(id);
  }

  get(id: string): NostrEvent | undefined {
    return this.entries.get(id)?.event;
  }

  /**
   * Whether the cache's rules would keep this event: not ephemeral, not expired (NIP-40), not deleted (a NIP-09 kind 5
   * of its author, or a NIP-29 9005 of its channel) and not an older version of a replaceable one it holds. The limits
   * (count, bytes, age) are not rules: an event they would drop is still admitted.
   */
  admits(e: NostrEvent): boolean {
    return validateEventShape(e) && (this.entries.has(e.id) || this.admitsAt(e, this.now()));
  }

  private admitsAt(e: NostrEvent, now: number): boolean {
    if (isEphemeralKind(e.kind)) return false;
    const exp = expirationOf(e);
    if (exp !== undefined && exp <= now) return false;
    if (this.meta.tombstones[e.id]?.some(([, scope]) => appliesTo(scope, e))) return false;
    const addr = addressOf(e);
    const head = addr ? this.entries.get(this.heads.get(addr) ?? '') : undefined;
    return !head || supersedes(e, head.event);
  }

  /**
   * Stores events (duplicates by id are ignored; the relay that served them is remembered) and then applies deletions,
   * expiration and the limits. Everything is written before it resolves.
   */
  put(events: Iterable<NostrEvent>, opts: { relay?: string } = {}): Promise<CachePutResult> {
    const list = [...events];
    return this.serial(async () => {
      const relay = opts.relay !== undefined ? this.relayIndex(opts.relay) : undefined;
      const now = this.now();
      const result: CachePutResult = { added: 0, refused: 0, evicted: 0 };
      for (const raw of list) {
        if (!validateEventShape(raw)) {
          result.refused++;
          continue;
        }
        const held = this.entries.get(raw.id);
        if (held) {
          if (relay !== undefined && !held.relays.has(relay)) {
            held.relays.add(relay);
            this.dirty.add(bucketOf(raw.id));
          }
          continue;
        }
        if (!this.admitsAt(raw, now)) {
          result.refused++;
          continue;
        }
        if (this.maxAgeSeconds !== undefined && raw.created_at < now - this.maxAgeSeconds) {
          result.evicted++;
          continue;
        }
        const e: NostrEvent = { id: raw.id, pubkey: raw.pubkey, created_at: raw.created_at, kind: raw.kind, tags: raw.tags.map((t) => [...t]), content: raw.content, sig: raw.sig };
        const addr = addressOf(e);
        const previous = addr ? this.heads.get(addr) : undefined;
        if (previous) this.remove(previous);
        this.insert(e, new Set(relay !== undefined ? [relay] : []));
        this.dirty.add(bucketOf(e.id));
        result.added++;
        if (e.kind === 5 || e.kind === 9005) this.applyDeletion(e);
      }
      result.evicted += this.applyLimits(now);
      await this.flush();
      return result;
    });
  }

  /**
   * Events matching any filter (NIP-01 semantics: each filter's `limit` keeps its newest events), expired ones left
   * out, in the package's canonical order (created_at, then id). Never touches the network.
   */
  query(filters: Filter | Filter[]): NostrEvent[] {
    const now = this.now();
    const out = new Map<string, NostrEvent>();
    for (const f of Array.isArray(filters) ? filters : [filters]) {
      let matched = this.candidates(f).filter((x) => !(x.expiration !== undefined && x.expiration <= now) && matchFilter(f, x.event));
      if (f.limit !== undefined) matched = matched.sort((a, b) => byTime(b, a)).slice(0, Math.max(0, f.limit));
      for (const x of matched) out.set(x.event.id, x.event);
    }
    return [...out.values()].sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  /**
   * The ids and created_at of the cached events matching `filter` (its `limit` ignored) for NIP-77. With `relay`, only
   * those that relay served: a relay is never told about events that reached this device through another one.
   */
  localSet(filter: Filter, relay?: string): Array<{ id: string; created_at: number }> {
    const { limit: _limit, ...f } = filter;
    const index = relay === undefined ? undefined : this.meta.relays.indexOf(normalizeRelayUrl(relay));
    if (index === -1) return [];
    const now = this.now();
    return this.candidates(f)
      .filter((x) => (index === undefined || x.relays.has(index)) && !(x.expiration !== undefined && x.expiration <= now) && matchFilter(f, x.event))
      .map((x) => ({ id: x.event.id, created_at: x.event.created_at }));
  }

  /** Last complete sync of `filter` (without since/until/limit) from `relay`, in seconds. */
  cursor(relay: string, filter: Filter): number | undefined {
    const index = this.meta.relays.indexOf(normalizeRelayUrl(relay));
    return index < 0 ? undefined : this.meta.cursors[`${index} ${filterKey(filter)}`];
  }

  /**
   * Moves the cursor of `filter` on `relay` to `at` (never backwards). The events already put are written first, so a
   * cursor never runs ahead of what it covers.
   */
  advanceCursor(relay: string, filter: Filter, at: number): Promise<number> {
    return this.serial(async () => {
      const key = `${this.relayIndex(relay)} ${filterKey(filter)}`;
      const next = Math.max(this.meta.cursors[key] ?? Number.NEGATIVE_INFINITY, Math.floor(at));
      if (this.meta.cursors[key] !== next) {
        this.meta.cursors[key] = next;
        this.metaDirty = true;
      }
      await this.flush();
      return next;
    });
  }

  cursors(): CacheCursor[] {
    return Object.entries(this.meta.cursors).map(([key, at]) => {
      const space = key.indexOf(' ');
      return { relay: this.meta.relays[Number(key.slice(0, space))] ?? '?', filter: key.slice(space + 1), at };
    });
  }

  stats(): CacheStats {
    const order = this.sorted();
    return {
      events: this.entries.size,
      bytes: this.bytes,
      ...(order.length ? { oldest: order[0]!.event.created_at, newest: order[order.length - 1]!.event.created_at } : {}),
      floor: this.meta.floor,
      cursors: Object.keys(this.meta.cursors).length,
    };
  }

  /** Deletes every event, cursor and deletion record of this cache from the storage, whatever the index says. */
  clear(): Promise<void> {
    return this.serial(async () => {
      await this.buckets.clear();
      await this.metaStore.clear();
      for (const m of [this.entries, this.byKind, this.byAuthor, this.byBucket, this.heads]) m.clear();
      this.dirty.clear();
      this.ordered = undefined;
      this.bytes = 0;
      this.meta = emptyMeta();
      this.metaDirty = false;
    });
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private relayIndex(url: string): number {
    const relay = normalizeRelayUrl(url);
    let index = this.meta.relays.indexOf(relay);
    if (index < 0) {
      index = this.meta.relays.push(relay) - 1;
      this.metaDirty = true;
    }
    return index;
  }

  private candidates(f: Filter): Entry[] {
    if (f.ids) return [...new Set(f.ids)].flatMap((id) => this.entries.get(id) ?? []);
    const sets: Array<Set<string>> = [];
    const union = <K>(index: Map<K, Set<string>>, keys: K[]) => new Set(keys.flatMap((k) => [...(index.get(k) ?? [])]));
    if (f.kinds) sets.push(union(this.byKind, f.kinds));
    if (f.authors) sets.push(union(this.byAuthor, f.authors));
    if (sets.length === 0) return [...this.entries.values()];
    sets.sort((a, b) => a.size - b.size);
    const [smallest, ...rest] = sets;
    return [...smallest!].filter((id) => rest.every((s) => s.has(id))).map((id) => this.entries.get(id)!);
  }

  private sorted(): Entry[] {
    this.ordered ??= [...this.entries.values()].sort(byTime);
    return this.ordered;
  }

  private insert(e: NostrEvent, relays: Set<number>): void {
    const entry: Entry = { event: e, relays, size: encoder.encode(JSON.stringify(e)).length };
    const exp = expirationOf(e);
    if (exp !== undefined) entry.expiration = exp;
    this.entries.set(e.id, entry);
    const add = <K>(index: Map<K, Set<string>>, key: K) => {
      let s = index.get(key);
      if (!s) index.set(key, (s = new Set()));
      s.add(e.id);
    };
    add(this.byKind, e.kind);
    add(this.byAuthor, e.pubkey);
    add(this.byBucket, bucketOf(e.id));
    const addr = addressOf(e);
    if (addr) this.heads.set(addr, e.id);
    this.bytes += entry.size;
    this.ordered = undefined;
  }

  private remove(id: string): void {
    const entry = this.entries.get(id);
    if (!entry) return;
    const e = entry.event;
    this.entries.delete(id);
    const drop = <K>(index: Map<K, Set<string>>, key: K) => {
      const s = index.get(key);
      s?.delete(id);
      if (s?.size === 0) index.delete(key);
    };
    drop(this.byKind, e.kind);
    drop(this.byAuthor, e.pubkey);
    drop(this.byBucket, bucketOf(id));
    const addr = addressOf(e);
    if (addr && this.heads.get(addr) === id) this.heads.delete(addr);
    this.bytes -= entry.size;
    this.ordered = undefined;
    this.dirty.add(bucketOf(id));
    // A deletion that leaves the cache takes its records along.
    if (e.kind === 5 || e.kind === 9005) {
      for (const [target, list] of Object.entries(this.meta.tombstones)) {
        const kept = list.filter(([by]) => by !== id);
        if (kept.length === list.length) continue;
        if (kept.length) this.meta.tombstones[target] = kept;
        else delete this.meta.tombstones[target];
        this.metaDirty = true;
      }
    }
  }

  /** NIP-09 (kind 5: its author's own events) and NIP-29 (9005: events of its channel, as the group's relay decides). */
  private applyDeletion(d: NostrEvent): void {
    const channel = d.kind === 9005 ? getTagValue(d, 'h') : undefined;
    const scope = d.kind === 5 ? d.pubkey : channel ? `h:${channel}` : undefined;
    if (!scope) return;
    for (const target of getTagValues(d, 'e').slice(0, MAX_DELETION_TARGETS)) {
      if (!/^[0-9a-f]{64}$/.test(target) || target === d.id) continue;
      const list = this.meta.tombstones[target] ?? [];
      if (!list.some(([by]) => by === d.id)) {
        this.meta.tombstones[target] = [...list, [d.id, scope]];
        this.metaDirty = true;
      }
      const held = this.entries.get(target);
      if (held && appliesTo(scope, held.event)) this.remove(target);
    }
  }

  /** Expired events go by rule; then the age, count and byte limits drop the oldest (created_at, then id) and raise the floor. */
  private applyLimits(now: number): number {
    for (const entry of [...this.entries.values()]) if (entry.expiration !== undefined && entry.expiration <= now) this.remove(entry.event.id);
    let evicted = 0;
    const raiseFloor = (t: number) => {
      if (t > this.meta.floor) {
        this.meta.floor = t;
        this.metaDirty = true;
      }
    };
    if (this.maxAgeSeconds !== undefined) {
      const limit = now - this.maxAgeSeconds;
      for (const entry of [...this.entries.values()]) {
        if (entry.event.created_at >= limit) continue;
        this.remove(entry.event.id);
        evicted++;
      }
      raiseFloor(limit);
    }
    if (this.entries.size > this.maxEvents || this.bytes > this.maxBytes) {
      for (const entry of this.sorted()) {
        if (this.entries.size <= this.maxEvents && this.bytes <= this.maxBytes) break;
        this.remove(entry.event.id);
        evicted++;
        raiseFloor(entry.event.created_at + 1);
      }
    }
    return evicted;
  }

  /** Writes the changed buckets, then the metadata (cursors last: they never cover events that are not on disk yet). */
  private async flush(): Promise<void> {
    for (const bucket of [...this.dirty].sort()) {
      const ids = this.byBucket.get(bucket);
      if (ids?.size) {
        const content: StoredEvent[] = [...ids].map((id) => {
          const entry = this.entries.get(id)!;
          return entry.relays.size ? { e: entry.event, r: [...entry.relays].sort((a, b) => a - b) } : { e: entry.event };
        });
        await this.buckets.put(bucket, content);
      } else await this.buckets.delete(bucket);
      this.dirty.delete(bucket);
    }
    if (this.metaDirty) {
      await this.metaStore.put(META_ID, this.meta);
      this.metaDirty = false;
    }
  }
}
