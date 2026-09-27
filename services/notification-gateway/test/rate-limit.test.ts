import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, toUnsigned } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';
import { createLogger } from '@sedecim/telemetry-policy';
import { createNotificationApi, generateVapidKeys, NotificationGateway } from '../src/index';

const pool = { subscribe: () => ({ close() {}, seenOn: () => [] }) } as unknown as RelayPool;

/** IR-2026-09-05 (429 + Retry-After) and IR-2026-09-04 (per-process replay cache, no database). */
describe('notification-gateway rate limits and NIP-98 replay', () => {
  let now = 0;
  const gw = new NotificationGateway({ pool, sender: { send: async () => 201 }, relays: [{ public: 'wss://relay.example.org', dial: 'ws://relay:3000' }], logger: createLogger({ write: () => {} }) });
  const api = createNotificationApi(gw, { name: 'gateway-rl', vapid: generateVapidKeys(), rateLimit: { rules: { read: { perMinute: 60, burst: 2 }, mutating: { perMinute: 60, burst: 5 } }, now: () => now } });
  let base: string;
  beforeAll(async () => (base = await api.listen()));
  afterAll(() => api.close());

  it('answers 429 + Retry-After after the burst and recovers after the refill', async () => {
    const vapid = () => fetch(`${base}/v1/vapid`);
    expect((await vapid()).status).toBe(200);
    expect((await vapid()).status).toBe(200);
    const res = await vapid();
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('1');
    now += 1000;
    expect((await vapid()).status).toBe(200);
  });

  it('refuses a replayed registration header', async () => {
    const sk = generateSecretKey();
    const url = `${base}/v1/subscriptions`;
    const body = JSON.stringify({});
    const h = { authorization: nip98.encodeAuthHeader(finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, 'DELETE', body), getPublicKey(sk)), sk)) };
    expect((await fetch(url, { method: 'DELETE', headers: h, body })).status).toBe(200);
    expect((await fetch(url, { method: 'DELETE', headers: h, body })).status).toBe(401);
  });
});
