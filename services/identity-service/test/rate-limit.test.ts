import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, toUnsigned } from '@sedecim/nostr-core';
import { createPgPool, migrateReplayStore, nip98Fetch, PgReplayStore } from '@sedecim/service-kit';
import { createIdentityApi, MemoryIdentityRepository } from '../src/index';

/** IR-2026-09-05 (account creation is in the strict `auth` class) and IR-2026-09-04 (replay). */
describe('identity-service rate limits and NIP-98 replay', () => {
  let now = 0;
  const api = createIdentityApi(new MemoryIdentityRepository(), {
    name: 'identity-rl',
    rateLimit: { rules: { auth: { perMinute: 60, burst: 2 }, read: { perMinute: 60, burst: 3 } }, now: () => now },
  });
  let base: string;
  beforeAll(async () => (base = await api.listen()));
  afterAll(() => api.close());

  it('limits account creation per address with 429 + Retry-After and recovers after the refill', async () => {
    const create = () => nip98Fetch(generateSecretKey(), `${base}/v1/accounts`, 'POST', {});
    expect((await create()).status).toBe(201);
    expect((await create()).status).toBe(201);
    const res = await fetch(`${base}/v1/accounts`, { method: 'POST', body: '{}' });
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('1');
    now += 1000;
    expect((await create()).status).toBe(201);
    expect((await create()).status).toBe(429);
  });

  it('health is never limited; reads have their own bucket', async () => {
    for (let i = 0; i < 10; i++) expect((await fetch(`${base}/health`)).status).toBe(200);
    const pk = getPublicKey(generateSecretKey());
    const reads = await Promise.all(Array.from({ length: 4 }, () => fetch(`${base}/v1/links/public/${pk}`).then((r) => r.status)));
    expect(reads.sort()).toEqual([200, 200, 200, 429]);
  });

  it('refuses a replayed NIP-98 header', async () => {
    now += 600_000;
    const sk = generateSecretKey();
    expect((await nip98Fetch(sk, `${base}/v1/accounts`, 'POST', {})).status).toBe(201);
    const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(`${base}/v1/accounts/me`, 'GET'), getPublicKey(sk)), sk);
    const h = { authorization: nip98.encodeAuthHeader(evt) };
    expect((await fetch(`${base}/v1/accounts/me`, { headers: h })).status).toBe(200);
    expect((await fetch(`${base}/v1/accounts/me`, { headers: h })).status).toBe(401);
  });
});

describe('identity-service free-text limits (IR-2026-09-19)', () => {
  const api = createIdentityApi(new MemoryIdentityRepository(), { name: 'identity-text' });
  let base: string;
  beforeAll(async () => (base = await api.listen()));
  afterAll(() => api.close());

  it('refuses oversized labels and key-metadata values with 400', async () => {
    const sk = generateSecretKey();
    expect((await nip98Fetch(sk, `${base}/v1/accounts`, 'POST', { label: 'x'.repeat(201) })).status).toBe(400);
    expect((await nip98Fetch(sk, `${base}/v1/accounts`, 'POST', { label: 'x'.repeat(200) })).status).toBe(201);
    const meta = (body: Record<string, unknown>) => nip98Fetch(sk, `${base}/v1/personas/${getPublicKey(sk)}/key-metadata`, 'PUT', { key_id: 'k1', provider: 'local', ...body });
    expect((await meta({ provider: 'p'.repeat(201) })).status).toBe(400);
    expect((await meta({ recovery_state: 'r'.repeat(201) })).status).toBe(400);
    expect((await meta({ key_id: 'k'.repeat(201) })).status).toBe(400);
    expect((await meta({ version: 1.5 })).status).toBe(400);
    expect((await meta({ version: 2, recovery_state: 'backup-exported' })).status).toBe(200);
  });
});

const PG = process.env.TEST_DATABASE_URL;
describe.runIf(PG)('identity-service replicas sharing the Postgres replay store', () => {
  const PUBLIC = 'https://id.example';
  const repo = new MemoryIdentityRepository();
  let a: ReturnType<typeof createIdentityApi>;
  let b: ReturnType<typeof createIdentityApi>;
  let urlA: string;
  let urlB: string;
  beforeAll(async () => {
    const pool = createPgPool(PG!);
    await migrateReplayStore(pool);
    a = createIdentityApi(repo, { name: 'identity-a', publicBaseUrl: PUBLIC, replayStore: new PgReplayStore(pool) });
    b = createIdentityApi(repo, { name: 'identity-b', publicBaseUrl: PUBLIC, replayStore: new PgReplayStore(pool) });
    urlA = await a.listen();
    urlB = await b.listen();
  });
  afterAll(async () => {
    await a.close();
    await b.close();
  });

  it('a header accepted by one replica is refused by the other', async () => {
    const sk = generateSecretKey();
    const sign = (url: string, method: string, body?: string) => nip98.encodeAuthHeader(finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, method, body), getPublicKey(sk)), sk));
    const created = await fetch(`${urlA}/v1/accounts`, { method: 'POST', body: '{}', headers: { authorization: sign(`${PUBLIC}/v1/accounts`, 'POST', '{}') } });
    expect(created.status).toBe(201);
    const h = { authorization: sign(`${PUBLIC}/v1/accounts/me`, 'GET') };
    expect((await fetch(`${urlA}/v1/accounts/me`, { headers: h })).status).toBe(200);
    expect((await fetch(`${urlB}/v1/accounts/me`, { headers: h })).status).toBe(401);
  });
});
