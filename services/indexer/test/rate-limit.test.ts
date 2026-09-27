import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, toUnsigned } from '@sedecim/nostr-core';
import { nip98Fetch } from '@sedecim/service-kit';
import { createIndexerApi, MemoryEventRepository } from '../src/index';

/** IR-2026-09-05: mirror reads per address and per authenticated reader. */
describe('indexer rate limits', () => {
  let now = 0;
  const api = createIndexerApi(new MemoryEventRepository(), {
    name: 'indexer-rl',
    requireAuth: true,
    rateLimit: { rules: { read: { perMinute: 60, burst: 3 } }, trustProxyHops: 1, now: () => now },
  });
  let base: string;
  beforeAll(async () => (base = await api.listen()));
  afterAll(() => api.close());

  it('answers 429 + Retry-After after the burst and recovers after the refill', async () => {
    const sk = generateSecretKey();
    const read = () => nip98Fetch(sk, `${base}/v1/events?kinds=1&limit=5`).then((r) => r.status);
    expect([await read(), await read(), await read()]).toEqual([200, 200, 200]);
    const res = await fetch(`${base}/v1/events?kinds=1`);
    expect(res.status).toBe(429);
    expect(Number(res.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    now += 60_000;
    expect(await read()).toBe(200);
  });

  it('limits a reader across addresses once authenticated', async () => {
    now += 600_000;
    const sk = generateSecretKey();
    const p = getPublicKey(sk);
    const read = async (ip: string) => {
      const url = `${base}/v1/events?kinds=1059&p=${p}`;
      const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, 'GET'), p), sk);
      return (await fetch(url, { headers: { authorization: nip98.encodeAuthHeader(evt), 'x-forwarded-for': ip } })).status;
    };
    expect([await read('7.7.7.1'), await read('7.7.7.2'), await read('7.7.7.3'), await read('7.7.7.4')]).toEqual([200, 200, 200, 429]);
  });
});
