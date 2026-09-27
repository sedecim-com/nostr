import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { verifyEvent } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import {
  createManagedSignerApi,
  ManagedSigner,
  MemoryDeviceStore,
  MemoryKeyRegistry,
  MemoryVault,
  parseKindLimits,
  SigningRateLimiter,
  type ManagedSignerApiOptions,
  type ManagedSignerOptions,
} from '../src/index';

const acceso = createTestCognito();
const silent = createLogger({ write: () => {} });
const REVOKE = 'revocation-token-0123456789';

async function start(opts: ManagedSignerOptions = {}, api: Partial<ManagedSignerApiOptions> = {}) {
  const registry = new MemoryKeyRegistry();
  const core = new ManagedSigner(new MemoryVault(), { registry, ...opts });
  const svc = createManagedSignerApi(core, { name: 'ms-test', cognito: acceso.verifier(), logger: silent, revocationTokens: { [REVOKE]: 'policy-engine' }, ...api });
  const base = await svc.listen();
  const call = (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) =>
    fetch(`${base}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({
      status: r.status,
      headers: r.headers,
      json: await r.json(),
    }));
  return { core, registry, svc, base, call };
}

describe('managed-signer device binding and revocation (FR024-03)', () => {
  let t: Awaited<ReturnType<typeof start>>;
  const user = () => acceso.token({ sub: 'device-user' });
  const auth = (token: string) => ({ authorization: `Bearer ${token}` });
  beforeAll(async () => {
    t = await start();
  });
  afterAll(() => t.svc.close());

  it('binds sessions to a device and rejects everything from it once it is revoked', async () => {
    const key = await ManagedSignerClient.createKey({ baseUrl: t.base, token: async () => user() });
    const phone = await t.call('/v1/device-sessions', 'POST', { device_id: 'dev-phone' }, auth(user()));
    const laptop = await t.call('/v1/device-sessions', 'POST', { device_id: 'dev-laptop', ttl_seconds: 3600 }, auth(user()));
    expect(phone.status).toBe(201);
    expect(phone.json).toMatchObject({ device_id: 'dev-phone', token: expect.stringMatching(/^sds_[0-9a-f]{64}$/) });
    // Only the hash of the token is stored.
    expect(JSON.stringify([...(t.core.devices as MemoryDeviceStore).sessions.values()])).not.toContain(phone.json.token);

    const onPhone = new ManagedSignerClient({ baseUrl: t.base, keyId: key.keyId, token: async () => phone.json.token });
    const onLaptop = new ManagedSignerClient({ baseUrl: t.base, keyId: key.keyId, token: async () => laptop.json.token });
    expect(verifyEvent(await onPhone.signEvent({ kind: 1, content: 'desde el móvil' }))).toBe(true);
    // A session cannot mint more sessions.
    expect((await t.call('/v1/device-sessions', 'POST', { device_id: 'dev-x' }, auth(phone.json.token))).status).toBe(403);

    const revoked: string[] = [];
    t.core.onDeviceRevoked((r) => void revoked.push(r.deviceId));
    // Only revocation tokens may revoke: not users, not sessions.
    expect((await t.call('/v1/devices/dev-phone/revoke', 'POST', {}, auth(user()))).status).toBe(401);
    expect((await t.call('/v1/devices/dev-phone/revoke', 'POST', {}, auth(phone.json.token))).status).toBe(401);
    const rev = await t.call('/v1/devices/dev-phone/revoke', 'POST', { reason: 'lost phone' }, auth(REVOKE));
    expect(rev.json).toEqual({ revoked: true, already_revoked: false, sessions_dropped: 1 });
    expect(revoked).toEqual(['dev-phone']);

    await expect(onPhone.signEvent({ kind: 1, content: 'robado' })).rejects.toThrow(/401/);
    await expect(onPhone.nip44Encrypt(key.pubkey, 'x')).rejects.toThrow(/401/);
    expect((await t.call('/v1/device-sessions', 'POST', { device_id: 'dev-phone' }, auth(user()))).status).toBe(403);
    // Naming the revoked device with a plain Acceso token fails too.
    expect((await t.call(`/v1/keys/${key.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } }, { ...auth(user()), 'x-device-id': 'dev-phone' })).status).toBe(403);
    // Other devices keep working; the audit says which device signed.
    const evt = await onLaptop.signEvent({ kind: 1, content: 'desde el portátil' });
    const usage = await t.registry.usageOf(key.keyId);
    expect(usage.filter((u) => u.action === 'sign').map((u) => u.deviceId)).toEqual(['dev-phone', 'dev-laptop']);
    expect(usage.at(-1)).toMatchObject({ eventId: evt.id, deviceId: 'dev-laptop' });

    // Idempotent.
    expect((await t.call('/v1/devices/dev-phone/revoke', 'POST', {}, auth(REVOKE))).json).toEqual({ revoked: true, already_revoked: true, sessions_dropped: 0 });
    expect(await t.core.metrics.render()).toMatch(/managed_signer_device_revocations_total\{result="new"\} 1/);
  });

  it('a revocation that races with opening a session still applies to it', async () => {
    // The revocation lands between openDeviceSession's check and its insert: the session row survives.
    const token = `sds_${'1'.repeat(64)}`;
    await t.core.devices.revoke({ deviceId: 'dev-race', revokedAt: Date.now(), revokedBy: 'test' });
    await t.core.devices.insertSession({ tokenHash: createHash('sha256').update(token).digest('hex'), deviceId: 'dev-race', owner: 'o', principal: 'o', createdAt: Date.now(), expiresAt: Date.now() + 1e6 });
    await expect(t.core.resolveDeviceSession(token)).rejects.toThrow(/device revoked/);
  });

  it('can require device sessions for every key operation', async () => {
    const strict = await start({}, { requireDeviceSession: true });
    try {
      const token = acceso.token({ sub: 'strict-user' });
      expect((await strict.call('/v1/keys', 'POST', {}, auth(token))).status).toBe(403);
      const s = await strict.call('/v1/device-sessions', 'POST', { device_id: 'dev-1' }, auth(token));
      expect(s.status).toBe(201);
      const created = await strict.call('/v1/keys', 'POST', {}, auth(s.json.token));
      expect(created.status).toBe(201);
      expect((await strict.call(`/v1/keys/${created.json.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } }, auth(token))).status).toBe(403);
      expect((await strict.call(`/v1/keys/${created.json.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } }, auth(s.json.token))).status).toBe(200);
    } finally {
      await strict.svc.close();
    }
  });

  it('expired sessions stop working and are purged by the retention job', async () => {
    let now = Date.UTC(2026, 5, 1);
    const core = new ManagedSigner(new MemoryVault(), { now: () => now, deviceSessionTtlMs: 60_000 });
    const s = await core.openDeviceSession('o', 'o', 'dev-ttl');
    expect(await core.resolveDeviceSession(s.token)).toMatchObject({ deviceId: 'dev-ttl' });
    now += 60_001;
    await expect(core.resolveDeviceSession(s.token)).rejects.toThrow(/expired/);
    expect((await core.runRetention()).sessionsPurged).toBe(1);
  });
});

describe('managed-signer rate limits and anomalous use (FR005-06)', () => {
  it('limits per kind and per key with 429 + Retry-After, audits once and exports metrics', async () => {
    let now = Date.UTC(2026, 5, 1, 12);
    const t = await start({ now: () => now, rateLimits: { perKey: { perMinute: 5 }, perKind: { perMinute: 3 }, kinds: { 22242: { perMinute: 4 } } } });
    try {
      const token = acceso.token({ sub: 'busy-user' });
      const key = await ManagedSignerClient.createKey({ baseUrl: t.base, token: async () => token });
      const client = new ManagedSignerClient({ baseUrl: t.base, token: async () => token, keyId: key.keyId });
      const sign = (kind: number) => t.call(`/v1/keys/${key.keyId}/sign`, 'POST', { template: { kind, content: 'x' } }, { authorization: `Bearer ${token}` });
      for (let i = 0; i < 3; i++) expect((await sign(1)).status).toBe(200);
      const limited = await sign(1);
      expect(limited.status).toBe(429);
      expect(limited.headers.get('retry-after')).toBe('20');
      expect(limited.json.error).toMatch(/rate limit exceeded \(kind\)/);
      // Another kind has its own bucket, until the key-wide limit (5/min) is reached.
      expect((await sign(22242)).status).toBe(200);
      expect((await sign(22242)).status).toBe(200);
      const keyLimited = await sign(22242);
      expect(keyLimited.status).toBe(429);
      expect(keyLimited.json.error).toMatch(/\(key\)/);
      await expect(client.nip44Encrypt(key.pubkey, 'x')).rejects.toThrow(/429/);

      // One audit row for the burst, not one per rejected call.
      const usage = await t.registry.usageOf(key.keyId);
      expect(usage.filter((u) => u.action === 'rate-limited')).toEqual([expect.objectContaining({ kind: 1, principal: `${acceso.issuer}#busy-user` })]);
      const metrics = await t.core.metrics.render();
      expect(metrics).toContain('managed_signer_rate_limited_total{op="sign",scope="kind"} 1');
      expect(metrics).toContain('managed_signer_rate_limited_total{op="sign",scope="key"} 1');
      expect(metrics).toContain('managed_signer_operations_total{op="sign",result="ok"} 5');
      expect(metrics).not.toMatch(/busy-user|[0-9a-f]{32}/);

      // Tokens come back with time.
      now += 20_000;
      expect((await sign(1)).status).toBe(200);
      now += 61_000;
      expect((await sign(1)).status).toBe(200);
      expect((await t.registry.usageOf(key.keyId)).filter((u) => u.action === 'rate-limited')).toHaveLength(1);
    } finally {
      await t.svc.close();
    }
  });

  it('token buckets refill continuously and a rejection consumes nothing', () => {
    const l = new SigningRateLimiter({ perKey: { perMinute: 60, burst: 2 }, perKind: { perMinute: 60, burst: 2 } });
    expect(l.take('k', 1, 0).ok).toBe(true);
    expect(l.take('k', 1, 0).ok).toBe(true);
    expect(l.take('k', 1, 0)).toEqual({ ok: false, scope: 'key', retryAfterMs: 1000 });
    expect(l.take('k', 1, 500)).toEqual({ ok: false, scope: 'key', retryAfterMs: 500 });
    expect(l.take('k', 1, 1000).ok).toBe(true);
    expect(l.take('other', 1, 1000).ok).toBe(true);
    expect(parseKindLimits('22242:300, 1:30:5')).toEqual({ 22242: { perMinute: 300 }, 1: { perMinute: 30, burst: 5 } });
    expect(() => parseKindLimits('1:0')).toThrow(/invalid/);
  });
});
