import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, toUnsigned } from '@sedecim/nostr-core';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import { clientIp, HttpRateLimiter, rateLimitFromEnv, Service, TokenBucketLimiter } from '../src/index';

const peer = (remoteAddress: string, xff?: string) => ({ socket: { remoteAddress }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } }) as Parameters<typeof clientIp>[0];

describe('TokenBucketLimiter', () => {
  it('spends the burst, then refills at perMinute', () => {
    let now = 0;
    const l = new TokenBucketLimiter({ now: () => now });
    const rule = { perMinute: 60, burst: 3 };
    expect([1, 2, 3].map(() => l.take('k', rule).ok)).toEqual([true, true, true]);
    expect(l.take('k', rule)).toEqual({ ok: false, retryAfterMs: 1000 });
    now = 500;
    expect(l.take('k', rule)).toEqual({ ok: false, retryAfterMs: 500 });
    now = 1000;
    expect(l.take('k', rule).ok).toBe(true);
    expect(l.take('k', rule).ok).toBe(false);
    now = 1000 + 60_000; // full again, never above the burst
    expect([1, 2, 3, 4].map(() => l.take('k', rule).ok)).toEqual([true, true, true, false]);
    // Default burst = perMinute; keys are independent.
    expect(l.take('other', { perMinute: 1 }).ok).toBe(true);
    expect(l.take('other', { perMinute: 1 }).ok).toBe(false);
  });

  it('keeps memory bounded by evicting the least recently used bucket', () => {
    const l = new TokenBucketLimiter({ maxKeys: 2, now: () => 0 });
    const rule = { perMinute: 1 };
    l.take('a', rule);
    l.take('b', rule);
    expect(l.take('a', rule).ok).toBe(false); // touches a: b is now the oldest
    l.take('c', rule); // evicts b
    expect(l.size).toBe(2);
    expect(l.take('a', rule).ok).toBe(false);
    expect(l.take('b', rule).ok).toBe(true); // forgotten, so fresh (evicts c)
    expect(l.take('c', rule).ok).toBe(true);
  });
});

describe('clientIp', () => {
  it('ignores X-Forwarded-For unless proxies are trusted', () => {
    expect(clientIp(peer('10.0.0.5', '1.2.3.4'))).toBe('10.0.0.5');
    expect(clientIp(peer('10.0.0.5', '1.2.3.4'), 0)).toBe('10.0.0.5');
  });

  it('takes the address the trusted hops saw, right to left', () => {
    expect(clientIp(peer('10.0.0.5', 'spoofed, 1.2.3.4'), 1)).toBe('1.2.3.4');
    expect(clientIp(peer('10.0.0.5', 'spoofed, 1.2.3.4, 10.0.0.9'), 2)).toBe('1.2.3.4');
    expect(clientIp(peer('10.0.0.5'), 1)).toBe('10.0.0.5');
    expect(clientIp(peer('10.0.0.5', '1.2.3.4'), 5)).toBe('1.2.3.4');
  });
});

describe('rateLimitFromEnv', () => {
  it('parses the knobs and rejects nonsense', () => {
    expect(rateLimitFromEnv({ RATE_LIMIT: 'off' })).toBe(false);
    expect(rateLimitFromEnv({})).toEqual({ rules: {}, trustProxyHops: 0, maxKeys: 100_000 });
    expect(rateLimitFromEnv({ RATE_LIMIT_AUTH: '5', RATE_LIMIT_READ: '100:20', RATE_LIMIT_TRUST_PROXY_HOPS: '1' })).toEqual({
      rules: { auth: { perMinute: 5 }, read: { perMinute: 100, burst: 20 } },
      trustProxyHops: 1,
      maxKeys: 100_000,
    });
    expect(() => rateLimitFromEnv({ RATE_LIMIT_MUTATING: '0' })).toThrow(/RATE_LIMIT_MUTATING/);
    expect(() => rateLimitFromEnv({ RATE_LIMIT_READ: 'x:1' })).toThrow();
    expect(() => rateLimitFromEnv({ RATE_LIMIT_TRUST_PROXY_HOPS: '-1' })).toThrow();
  });
});

describe('Service rate limiting', () => {
  let now = 0;
  const logs: LogRecord[] = [];
  const limiter = new HttpRateLimiter({
    rules: { read: { perMinute: 60, burst: 2 }, mutating: { perMinute: 60, burst: 3 }, auth: { perMinute: 60, burst: 2 }, service: { perMinute: 60, burst: 1 } },
    trustProxyHops: 1,
    now: () => now,
  });
  const svc = new Service({ name: 'rl-test', rateLimit: limiter, bearerTokens: { tok: 'svc' }, logger: createLogger({ write: (r) => logs.push(r) }) });
  svc.get('/health', () => ({ ok: true }), 'none', { rateClass: 'none' });
  svc.get('/items', () => ({ items: [] }));
  svc.post('/items', () => ({ ok: true }), 'nip98');
  svc.get('/svc', () => ({ ok: true }), 'bearer');
  const sk = generateSecretKey();
  let base: string;
  beforeAll(async () => (base = await svc.listen()));
  afterAll(() => svc.close());
  const from = (ip: string, extra: Record<string, string> = {}) => ({ headers: { 'x-forwarded-for': ip, ...extra } });
  const signed = (ip: string) => {
    const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(`${base}/items`, 'POST', '{}'), getPublicKey(sk)), sk);
    return fetch(`${base}/items`, { method: 'POST', body: '{}', headers: { 'x-forwarded-for': ip, authorization: nip98.encodeAuthHeader(evt) } });
  };

  it('answers 429 with Retry-After once the IP bucket is empty, and recovers after the refill', async () => {
    expect((await fetch(`${base}/items`, from('1.1.1.1'))).status).toBe(200);
    expect((await fetch(`${base}/items`, from('1.1.1.1'))).status).toBe(200);
    const limited = await fetch(`${base}/items`, from('1.1.1.1'));
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBe('1');
    expect((await fetch(`${base}/items`, from('2.2.2.2'))).status).toBe(200); // another client
    now += 1000;
    expect((await fetch(`${base}/items`, from('1.1.1.1'))).status).toBe(200);
    expect((await fetch(`${base}/items`, from('1.1.1.1'))).status).toBe(429);
    // Routes of class 'none' are never limited.
    for (let i = 0; i < 5; i++) expect((await fetch(`${base}/health`, from('1.1.1.1'))).status).toBe(200);
  });

  it('limits an authenticated pubkey across addresses', async () => {
    now += 600_000;
    expect((await signed('3.3.3.1')).status).toBe(200);
    expect((await signed('3.3.3.2')).status).toBe(200);
    expect((await signed('3.3.3.3')).status).toBe(200);
    expect((await signed('3.3.3.4')).status).toBe(429);
  });

  it('turns repeated authentication failures into 429 (auth bucket)', async () => {
    now += 600_000;
    const bad = () => fetch(`${base}/items`, { method: 'POST', body: '{}', headers: { 'x-forwarded-for': '4.4.4.4', authorization: 'Nostr bm9wZQ==' } }).then((r) => r.status);
    expect([await bad(), await bad(), await bad()]).toEqual([401, 401, 429]);
    const svcBad = () => fetch(`${base}/svc`, { headers: { 'x-forwarded-for': '5.5.5.5', authorization: 'Bearer wrong' } }).then((r) => r.status);
    expect([await svcBad(), await svcBad(), await svcBad()]).toEqual([401, 401, 429]);
  });

  it('limits bearer principals per principal only', async () => {
    now += 600_000;
    expect((await fetch(`${base}/svc`, from('6.6.6.1', { authorization: 'Bearer tok' }))).status).toBe(200);
    expect((await fetch(`${base}/svc`, from('6.6.6.2', { authorization: 'Bearer tok' }))).status).toBe(429);
  });

  it('counts 429s by class and scope only, and logs no address or key', async () => {
    const text = await limiter.render();
    expect(text).toMatch(/http_rate_limited_total\{class="read",scope="ip"\} [1-9]/);
    expect(text).toMatch(/http_rate_limited_total\{class="mutating",scope="principal"\} 1/);
    expect(text).toMatch(/http_rate_limited_total\{class="auth",scope="ip"\} 2/);
    expect(text).not.toMatch(/1\.1\.1\.1|3\.3\.3|svc|[0-9a-f]{64}/);
    const lines = logs.filter((l) => l.msg === 'rate limited');
    expect(lines.length).toBeGreaterThan(0);
    const dump = JSON.stringify(lines);
    expect(dump).not.toMatch(/1\.1\.1\.1|4\.4\.4\.4|Bearer|Nostr |[0-9a-f]{64}/);
    expect(lines[0]).toMatchObject({ class: 'read', scope: 'ip', retry_after_s: 1 });
  });

  it('without a limiter nothing is limited', async () => {
    const plain = new Service({ name: 'rl-off' });
    plain.get('/x', () => ({ ok: true }));
    const url = await plain.listen();
    const statuses = await Promise.all(Array.from({ length: 50 }, () => fetch(`${url}/x`).then((r) => r.status)));
    expect(new Set(statuses)).toEqual(new Set([200]));
    await plain.close();
  });
});
