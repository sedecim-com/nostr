import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, toUnsigned, type EventTemplate } from '@sedecim/nostr-core';
import { createPgPool, MemoryReplayStore, migrateReplayStore, PgReplayStore, ReplayStoreFullError, Service, type ReplayStore } from '../src/index';

const sk = generateSecretKey();
const sign = (t: EventTemplate) => nip98.encodeAuthHeader(finalizeEvent(toUnsigned(t, getPublicKey(sk)), sk));
const header = (url: string, method = 'GET', body?: string) => sign(nip98.buildHttpAuthTemplate(url, method, body));

function makeService(name: string, replayStore: ReplayStore, publicBaseUrl?: string) {
  const svc = new Service({ name, replayStore, ...(publicBaseUrl ? { publicBaseUrl } : {}) });
  svc.get('/v1/me', (req) => ({ pubkey: req.pubkey }), 'nip98');
  svc.post('/v1/things', (req) => ({ status: 201, body: { got: req.json() } }), 'nip98');
  return svc;
}

describe('MemoryReplayStore', () => {
  it('accepts an id once until it expires, and refuses to evict live ids when full', async () => {
    let now = 1_000_000;
    const store = new MemoryReplayStore({ maxEntries: 2, now: () => now });
    expect(await store.use('a', 1060)).toBe(true);
    expect(await store.use('a', 1060)).toBe(false);
    expect(await store.use('b', 1060)).toBe(true);
    await expect(store.use('c', 1060)).rejects.toBeInstanceOf(ReplayStoreFullError);
    now = 1_061_000; // both expired: swept, room again
    expect(await store.use('c', 1120)).toBe(true);
    expect(await store.use('a', 1120)).toBe(true);
    expect(store.size).toBe(2);
  });
});

/** Replay protection through the HTTP layer, for any store (IR-2026-09-04). */
function replaySuite(name: string, shared: boolean, stores: () => Promise<[ReplayStore, ReplayStore]>) {
  describe(name, () => {
    const PUBLIC = 'https://api.example';
    let a: Service;
    let b: Service;
    let urlA: string;
    let urlB: string;
    beforeAll(async () => {
      const [sa, sb] = await stores();
      // Two replicas behind the same public URL.
      a = makeService('replay-a', sa, PUBLIC);
      b = makeService('replay-b', sb, PUBLIC);
      urlA = await a.listen();
      urlB = await b.listen();
    });
    afterAll(async () => {
      await a.close();
      await b.close();
    });
    const get = (base: string, authorization: string) => fetch(`${base}/v1/me`, { headers: { authorization } });

    it('rejects a replayed event (401) and accepts distinct events', async () => {
      const h = header(`${PUBLIC}/v1/me`);
      expect((await get(urlA, h)).status).toBe(200);
      const again = await get(urlA, h);
      expect(again.status).toBe(401);
      expect(((await again.json()) as { error: string }).error).toMatch(/already used/);
      // A fresh signature for the same request (the nonce makes a new id) is fine.
      expect((await get(urlA, header(`${PUBLIC}/v1/me`))).status).toBe(200);
      expect((await get(urlA, header(`${PUBLIC}/v1/me`))).status).toBe(200);
    });

    it('rejects the replay on another replica sharing the store', async () => {
      const h = header(`${PUBLIC}/v1/me`);
      expect((await get(urlA, h)).status).toBe(200);
      expect((await get(urlB, h)).status).toBe(shared ? 401 : 200);
    });

    it('of N parallel requests with the same event exactly one succeeds', async () => {
      const body = JSON.stringify({ n: 1 });
      const h = header(`${PUBLIC}/v1/things`, 'POST', body);
      const statuses = await Promise.all(
        Array.from({ length: 16 }, (_, i) => fetch(`${i % 2 && shared ? urlB : urlA}/v1/things`, { method: 'POST', headers: { authorization: h }, body }).then((r) => r.status)),
      );
      expect(statuses.filter((s) => s === 201)).toHaveLength(1);
      expect(statuses.filter((s) => s === 401)).toHaveLength(15);
    });

    it('rejects expired events and events outside the window', async () => {
      const t = nip98.buildHttpAuthTemplate(`${PUBLIC}/v1/me`, 'GET');
      const old = finalizeEvent({ ...toUnsigned(t, getPublicKey(sk)), created_at: Math.floor(Date.now() / 1000) - 61 }, sk);
      const future = finalizeEvent({ ...toUnsigned(t, getPublicKey(sk)), created_at: Math.floor(Date.now() / 1000) + 120 }, sk);
      expect((await get(urlA, nip98.encodeAuthHeader(old))).status).toBe(401);
      expect((await get(urlA, nip98.encodeAuthHeader(future))).status).toBe(401);
    });
  });
}

replaySuite('NIP-98 replay (memory store per replica)', false, async () => [new MemoryReplayStore(), new MemoryReplayStore()]);

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  replaySuite('NIP-98 replay (postgres store shared by replicas)', true, async () => {
    const poolA = createPgPool(PG);
    const poolB = createPgPool(PG);
    await migrateReplayStore(poolA);
    await migrateReplayStore(poolB); // idempotent
    return [new PgReplayStore(poolA), new PgReplayStore(poolB)];
  });

  describe('PgReplayStore', () => {
    it('is atomic, and cleanup only removes rows expired past the grace period', async () => {
      const pool = createPgPool(PG);
      await migrateReplayStore(pool);
      const store = new PgReplayStore(pool, { cleanupIntervalMs: 0 });
      const id = (s: string) => `${s}-${Math.random().toString(16).slice(2)}`;
      const now = Math.floor(Date.now() / 1000);
      const fresh = id('fresh');
      const results = await Promise.all(Array.from({ length: 10 }, () => store.use(fresh, now + 60)));
      expect(results.filter(Boolean)).toHaveLength(1);
      const stale = id('stale');
      const recent = id('recent');
      expect(await store.use(stale, now - 3600)).toBe(true);
      expect(await store.use(recent, now - 10)).toBe(true);
      expect(await store.cleanup()).toBeGreaterThanOrEqual(1);
      const { rows } = await pool.query<{ event_id: string }>('SELECT event_id FROM nip98_replay WHERE event_id = ANY($1)', [[stale, recent, fresh]]);
      expect(rows.map((r) => r.event_id).sort()).toEqual([fresh, recent].sort());
      await pool.end();
    });
  });
} else {
  describe.skip('NIP-98 replay (postgres) — set TEST_DATABASE_URL', () => {
    it('skipped', () => {});
  });
}

describe('NIP-98 strict binding', () => {
  const svc = makeService('binding', new MemoryReplayStore(), 'https://api.example/');
  let base: string;
  beforeAll(async () => (base = await svc.listen()));
  afterAll(() => svc.close());

  it('binds the exact URL (query included, trailing slash of the base ignored), method and payload', async () => {
    const ok = await fetch(`${base}/v1/me?x=1`, { headers: { authorization: header('https://api.example/v1/me?x=1') } });
    expect(ok.status).toBe(200);
    expect((await fetch(`${base}/v1/me?x=2`, { headers: { authorization: header('https://api.example/v1/me?x=1') } })).status).toBe(401);
    expect((await fetch(`${base}/v1/me`, { headers: { authorization: header('http://api.example/v1/me') } })).status).toBe(401);
    expect((await fetch(`${base}/v1/me`, { headers: { authorization: header('https://api.example/v1/me', 'POST') } })).status).toBe(401);
    const body = JSON.stringify({ a: 1 });
    // No payload tag for a body, or a payload tag for a body that was not sent.
    const noPayload = sign({ kind: nip98.HTTP_AUTH_KIND, content: '', tags: [['u', 'https://api.example/v1/things'], ['method', 'POST']] });
    expect((await fetch(`${base}/v1/things`, { method: 'POST', headers: { authorization: noPayload }, body })).status).toBe(401);
    const phantom = header('https://api.example/v1/me', 'GET', 'unsent body');
    expect((await fetch(`${base}/v1/me`, { headers: { authorization: phantom } })).status).toBe(401);
    expect((await fetch(`${base}/v1/things`, { method: 'POST', headers: { authorization: header('https://api.example/v1/things', 'POST', body) }, body })).status).toBe(201);
  });
});
