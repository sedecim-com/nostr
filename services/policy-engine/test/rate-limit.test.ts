import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { nip98Fetch } from '@sedecim/service-kit';
import { createPolicyApi, MemoryPolicyRepository, PolicyEngine } from '../src/index';

/** IR-2026-09-05: admin reads by IP and pubkey; service bearer calls by principal only. */
describe('policy-engine rate limits', () => {
  let now = 0;
  const adminSk = generateSecretKey();
  const api = createPolicyApi(new PolicyEngine(new MemoryPolicyRepository(), Date.now, { rpId: 'localhost', rpName: 'Test', origins: ['http://localhost:8080'] }), {
    name: 'policy-rl',
    adminPubkeys: [getPublicKey(adminSk)],
    bearerTokens: { 'relay-token-1234': 'relay' },
    serviceScopes: { relay: ['evaluate'] },
    rateLimit: { rules: { read: { perMinute: 60, burst: 2 }, service: { perMinute: 60, burst: 3 } }, now: () => now },
  });
  let base: string;
  beforeAll(async () => (base = await api.listen()));
  afterAll(() => api.close());

  it('answers 429 + Retry-After after the read burst and recovers after the refill', async () => {
    const list = () => nip98Fetch(adminSk, `${base}/v1/subjects`);
    expect((await list()).status).toBe(200);
    expect((await list()).status).toBe(200);
    const res = await fetch(`${base}/v1/subjects`);
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('1');
    now += 2000;
    expect((await list()).status).toBe(200);
  });

  it('limits a service principal on its own bucket (not by the relay address)', async () => {
    const evaluate = () =>
      fetch(`${base}/v1/evaluate`, { method: 'POST', headers: { authorization: 'Bearer relay-token-1234' }, body: JSON.stringify({ pubkey: getPublicKey(generateSecretKey()), resourceId: 'r', action: 'read' }) }).then((r) => r.status);
    expect([await evaluate(), await evaluate(), await evaluate(), await evaluate()]).toEqual([200, 200, 200, 429]);
    now += 1000;
    expect(await evaluate()).toBe(200);
  });
});
