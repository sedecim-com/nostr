import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { createDirectMessage, dmInboxFilter } from '@sedecim/messaging';
import { finalizeEvent, generateSecretKey, getPublicKey, randomBytes, toUnsigned, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { DEFAULT_RESUME_OVERLAP_SECONDS, EventCache, FilterWindowSync, NegentropySync, syncWithCache, type SyncStrategy } from '../src/index';
import { decodeMessage } from './negentropy-spec';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const nowSec = () => Math.floor(Date.now() / 1000);
const OVERLAP = DEFAULT_RESUME_OVERLAP_SECONDS;
const newCache = () => EventCache.open(EncryptedStore.withKey(new MemoryBackend(), randomBytes(32)));

/** A fresh author with `n` notes spread over the last `span` seconds (the newest ones inside the overlap). */
function author(n: number, span = 3 * 24 * 3600) {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  const t = nowSec();
  const note = (created_at: number, i: number) => finalizeEvent(toUnsigned({ kind: 1, content: `n${i}`, created_at }, pk), sk);
  const events = Array.from({ length: n }, (_, i) => note(t - Math.floor((span * (n - 1 - i)) / Math.max(1, n - 1)), i));
  const filter = (since?: number): Filter => ({ kinds: [1], authors: [pk], ...(since !== undefined ? { since } : {}) });
  return { sk, pk, events, filter, note };
}

describe('resumed sync over the encrypted cache (FR013-05)', () => {
  const neg = new TestRelay({ supportsNegentropy: true });
  const plain = new TestRelay();
  const locked = new TestRelay({ requireAuth: true });
  let pool: RelayPool;

  const negentropy = (cache: EventCache, timeoutMs = 2_000) => new NegentropySync(pool, { local: (relay, f) => cache.localSet(f, relay), known: (id) => cache.get(id), requireEose: true, timeoutMs });
  const window = (since: number | undefined, timeoutMs = 2_000) => new FilterWindowSync(pool, { since: since ?? 0, windowSeconds: since === undefined ? nowSec() + 1 : 24 * 3600, pageLimit: 50, requireEose: true, timeoutMs });
  const both = (n: NegentropySync, timeoutMs?: number) => (since?: number): SyncStrategy[] => [n, window(since, timeoutMs)];

  beforeAll(async () => {
    await Promise.all([neg.start(), plain.start(), locked.start()]);
    pool = new RelayPool({ webSocketFactory: factory });
  });
  afterAll(async () => {
    pool.close();
    await Promise.all([neg.stop(), plain.stop(), locked.stop()]);
  });

  it('NIP-77 starts from what the cache holds: only the missing events come down, and a second sync brings nothing (FR013-05)', async () => {
    const { events, filter } = author(60);
    events.forEach((e) => neg.inject(e));
    const cache = await newCache();
    await cache.put(events.filter((_, i) => i % 3 !== 0), { relay: neg.url });
    const n = negentropy(cache);

    const before = neg.sentEvents;
    const first = await syncWithCache({ cache, relays: [neg.url], filter, strategies: both(n) });
    expect(first.perRelay[neg.url]).toMatchObject({ strategy: 'nip77-negentropy', advanced: true });
    expect(neg.sentEvents - before).toBe(20);
    expect(n.stats.get(neg.url)).toMatchObject({ need: 20, fetched: 20, reused: 0, have: 0 });
    expect(first.events.map((e) => e.id).sort()).toEqual(events.map((e) => e.id).sort());
    expect(cache.size).toBe(60);

    const mid = neg.sentEvents;
    const second = await syncWithCache({ cache, relays: [neg.url], filter, strategies: both(n) });
    expect(neg.sentEvents - mid).toBe(0);
    expect(n.stats.get(neg.url)).toMatchObject({ need: 0, fetched: 0 });
    expect(second.received).toBe(0);
    expect(second.events).toHaveLength(60);
    expect(second.perRelay[neg.url]!.since).toBe(first.perRelay[neg.url]!.cursor! - OVERLAP);
  });

  it('tells each relay only what that relay served, and does not download again what another relay sent (FR013-05)', async () => {
    const { events, filter } = author(50);
    const [shared, onlyPlain, onlyNeg] = [events.slice(0, 30), events.slice(30, 40), events.slice(40)];
    [...shared, ...onlyPlain].forEach((e) => plain.inject(e));
    [...shared, ...onlyNeg].forEach((e) => neg.inject(e));
    const cache = await newCache();
    await syncWithCache({ cache, relays: [plain.url], filter, strategies: both(negentropy(cache)) });
    expect(cache.size).toBe(40);

    const n = negentropy(cache);
    const log = neg.negLog.length;
    const before = neg.sentEvents;
    await syncWithCache({ cache, relays: [neg.url], filter, strategies: both(n) });
    const sent = neg.negLog.slice(log);
    // The cache holds 40 matching events, all from the other relay: this relay is told of none of them.
    expect(sent.find((m) => m.type === 'NEG-OPEN')?.message).toBe('6100000200');
    const described = sent.flatMap((m) => (m.message ? decodeMessage(m.message).ranges.flatMap((r) => r.ids ?? []) : []));
    expect(described.filter((id) => events.some((e) => e.id === id))).toEqual([]);
    // It had 40: the 30 shared ones are taken from the cache, only its own 10 are downloaded.
    expect(n.stats.get(neg.url)).toMatchObject({ need: 40, reused: 30, fetched: 10 });
    expect(neg.sentEvents - before).toBe(10);
    expect(cache.localSet(filter(), neg.url).map((x) => x.id).sort()).toEqual([...shared, ...onlyNeg].map((e) => e.id).sort());
    expect(cache.size).toBe(50);
  });

  it('each relay resumes from its own cursor minus the overlap, by REQ where there is no NIP-77 (FR013-05)', async () => {
    const { events, filter, note } = author(30);
    events.forEach((e) => (plain.inject(e), neg.inject(e)));
    const cache = await newCache();
    const n = negentropy(cache);
    const first = await syncWithCache({ cache, relays: [plain.url, neg.url], filter, strategies: both(n) });
    expect(first.perRelay[plain.url]).toMatchObject({ strategy: 'req-window', advanced: true });
    expect(first.perRelay[plain.url]!.since).toBeUndefined();
    const cursorPlain = first.perRelay[plain.url]!.cursor!;
    const cursorNeg = first.perRelay[neg.url]!.cursor!;
    expect(cache.cursor(plain.url, filter())).toBe(cursorPlain);

    const fresh = note(nowSec(), 99);
    plain.inject(fresh);
    neg.inject(fresh);
    const reqs = plain.reqFilters.length;
    const before = plain.sentEvents;
    const second = await syncWithCache({ cache, relays: [plain.url, neg.url], filter, strategies: both(n) });
    expect(second.perRelay[plain.url]).toMatchObject({ strategy: 'req-window', since: cursorPlain - OVERLAP, advanced: true });
    expect(second.perRelay[neg.url]).toMatchObject({ strategy: 'nip77-negentropy', since: cursorNeg - OVERLAP });
    const asked = plain.reqFilters.slice(reqs).flat();
    expect(Math.min(...asked.map((f) => f.since ?? 0))).toBe(cursorPlain - OVERLAP);
    // Only what falls inside the overlap comes down again from the relay without NIP-77.
    const inWindow = [...events, fresh].filter((e) => e.created_at >= cursorPlain - OVERLAP).length;
    expect(plain.sentEvents - before).toBe(inWindow);
    expect(inWindow).toBeLessThan(events.length);
    expect(second.events.map((e) => e.id).sort()).toEqual([...events, fresh].map((e) => e.id).sort());
  });

  it('an event that reaches the relay later than the overlap is left out of a resumed sync and comes with a full one (FR013-05)', async () => {
    const { events, filter, note } = author(5);
    events.forEach((e) => plain.inject(e));
    const cache = await newCache();
    const n = negentropy(cache);
    const first = await syncWithCache({ cache, relays: [plain.url], filter, strategies: both(n) });
    const cursor = first.perRelay[plain.url]!.cursor!;
    // Signed long ago (e.g. offline) and published only now.
    const late = note(cursor - OVERLAP - 60, 77);
    plain.inject(late);
    const resumed = await syncWithCache({ cache, relays: [plain.url], filter, strategies: both(n) });
    expect(resumed.events.map((e) => e.id)).not.toContain(late.id);
    const full = await syncWithCache({ cache, relays: [plain.url], filter, strategies: both(n), mode: 'full' });
    expect(full.perRelay[plain.url]!.since).toBeUndefined();
    expect(full.events.map((e) => e.id)).toContain(late.id);
    expect(cache.has(late.id)).toBe(true);
  });

  it('gift wraps resume two more days back, so a wrap backdated by NIP-59 after the last sync is not lost (FR013-05)', async () => {
    const buzzLike = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
    await buzzLike.start();
    const bobKey = generateSecretKey();
    const bob = getPublicKey(bobKey);
    const dmPool = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(bobKey) });
    try {
      const alice = new LocalSigner(generateSecretKey());
      const early = await createDirectMessage(alice, { recipients: [bob], content: 'antes' }, { now: nowSec() - 3600, timestampJitterSeconds: 0 });
      early.wraps.forEach((w) => buzzLike.inject(w.event));
      const cache = await newCache();
      const strategies = (since?: number) => [new FilterWindowSync(dmPool, { since: since ?? 0, windowSeconds: since === undefined ? nowSec() + 1 : 24 * 3600, requireEose: true, timeoutMs: 3_000 })];
      const inbox = (since?: number) => dmInboxFilter(bob, since);
      const first = await syncWithCache({ cache, relays: [buzzLike.url], filter: inbox, strategies });
      const cursor = first.perRelay[buzzLike.url]!.cursor!;
      expect(first.events).toHaveLength(1);

      // Published after that sync, dated almost two days before it (NIP-59 randomises created_at up to 2 days back).
      const late = await createDirectMessage(alice, { recipients: [bob], content: 'antedatado' }, { now: cursor - 2 * 24 * 3600 + 60, timestampJitterSeconds: 0 });
      late.wraps.forEach((w) => buzzLike.inject(w.event));
      const reqs = buzzLike.reqFilters.length;
      const second = await syncWithCache({ cache, relays: [buzzLike.url], filter: inbox, strategies });
      expect(second.perRelay[buzzLike.url]!.since).toBe(cursor - OVERLAP - 2 * 24 * 3600);
      expect(Math.min(...buzzLike.reqFilters.slice(reqs).flat().map((f) => f.since ?? 0))).toBe(cursor - OVERLAP - 2 * 24 * 3600);
      const bobsWrap = late.wraps.find((w) => w.recipient === bob)!.event.id;
      expect(second.events.map((e) => e.id)).toContain(bobsWrap);
      expect(cache.has(bobsWrap)).toBe(true);
    } finally {
      dmPool.close();
      await buzzLike.stop();
    }
  });

  it('a cursor moves only after a complete sync: not when the relay is down, refuses the REQ or never answers (FR013-05)', async () => {
    const { events, filter } = author(10);
    events.forEach((e) => (plain.inject(e), locked.inject(e)));
    const cache = await newCache();
    const reqOnly = (since?: number): SyncStrategy[] => [window(since, 1_000)];

    const down = new TestRelay();
    await down.start();
    const downUrl = down.url;
    await down.stop();
    const r1 = await syncWithCache({ cache, relays: [plain.url, downUrl, locked.url], filter, strategies: reqOnly });
    expect(r1.perRelay[plain.url]).toMatchObject({ strategy: 'req-window', advanced: true });
    for (const url of [downUrl, locked.url]) {
      expect(r1.perRelay[url]).toMatchObject({ strategy: 'none', advanced: false });
      expect(cache.cursor(url, filter())).toBeUndefined();
    }
    expect(r1.perRelay[locked.url]!.error).toMatch(/closed: auth-required/);

    const cursor = cache.cursor(plain.url, filter())!;
    plain.faults.silentReqs = true;
    try {
      const r2 = await syncWithCache({ cache, relays: [plain.url], filter, strategies: reqOnly });
      expect(r2.perRelay[plain.url]).toMatchObject({ strategy: 'none', advanced: false, cursor });
      expect(r2.perRelay[plain.url]!.error).toMatch(/timeout/);
    } finally {
      plain.faults.silentReqs = false;
    }
    expect(cache.cursor(plain.url, filter())).toBe(cursor);
  });

  it('a relay cut in the middle keeps what arrived, leaves the cursor, and the next sync fetches only the rest (FR013-05)', async () => {
    const { events, filter } = author(50);
    events.forEach((e) => neg.inject(e));
    const cache = await newCache();
    const n = negentropy(cache, 1_000);
    neg.faults.cutAfterEvents = 20;
    try {
      const cut = await syncWithCache({ cache, relays: [neg.url], filter, strategies: both(n, 1_000) });
      const r = cut.perRelay[neg.url]!;
      expect(r).toMatchObject({ strategy: 'none', advanced: false });
      expect(r.attempts.map((a) => [a.strategy, a.count])).toEqual([
        ['nip77-negentropy', 20],
        ['req-window', 0],
      ]);
      expect(cache.size).toBe(20);
      expect(cache.cursor(neg.url, filter())).toBeUndefined();
    } finally {
      neg.faults.cutAfterEvents = null;
      neg.faults.offline = false;
    }
    const before = neg.sentEvents;
    const again = await syncWithCache({ cache, relays: [neg.url], filter, strategies: both(n) });
    expect(again.perRelay[neg.url]).toMatchObject({ strategy: 'nip77-negentropy', advanced: true });
    expect(n.stats.get(neg.url)).toMatchObject({ need: 30, fetched: 30 });
    expect(neg.sentEvents - before).toBe(30);
    expect(cache.size).toBe(50);
  });

  it('a relay that aborts NIP-77 half way falls back to REQ windows, which complete the sync (FR013-05)', async () => {
    // Enough events for the relay to answer with fingerprints, so the session needs a second round to be aborted in.
    const { events, filter } = author(600);
    events.forEach((e) => neg.inject(e));
    const cache = await newCache();
    await cache.put(events.filter((_, i) => i % 4 !== 0), { relay: neg.url });
    neg.faults.negErrorAfterMessages = 1;
    try {
      const r = await syncWithCache({ cache, relays: [neg.url], filter, strategies: both(negentropy(cache)) });
      expect(r.perRelay[neg.url]).toMatchObject({ strategy: 'req-window', advanced: true });
      expect(r.perRelay[neg.url]!.attempts[0]!.error).toMatch(/aborted/);
      expect(cache.size).toBe(600);
    } finally {
      neg.faults.negErrorAfterMessages = null;
    }
  });

  it('offline answers from the cache without building a strategy or touching a pool (FR013-05)', async () => {
    const { events, filter } = author(12);
    const cache = await newCache();
    await cache.put(events);
    const trap = new Proxy({}, { get: () => { throw new Error('the network was touched'); } }) as unknown as RelayPool;
    const connections = plain.connectionAttempts + neg.connectionAttempts;
    const started = Date.now();
    const r = await syncWithCache({
      cache,
      relays: [plain.url, neg.url],
      filter,
      offline: true,
      strategies: () => [new NegentropySync(trap, { fetch: () => Promise.reject(new Error('the network was touched')) }), new FilterWindowSync(trap, { since: 0 })].map((s) => {
        throw new Error(`strategy ${s.name} was built`);
      }),
    });
    expect(Date.now() - started).toBeLessThan(200);
    expect(r.events.map((e) => e.id)).toEqual(events.map((e: NostrEvent) => e.id));
    expect(r.perRelay).toEqual({});
    expect(plain.connectionAttempts + neg.connectionAttempts).toBe(connections);
  });
});
