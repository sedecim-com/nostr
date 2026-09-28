import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateSecretKey, nip49 } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, ManagedSigner, MemoryVault, RateLimitedError, ScryptGate } from '../src/index';

const PASSWORD = 'contraseña larga 123';
const ncryptsec = () => nip49.encryptKey(generateSecretKey(), PASSWORD, 4);
const rejection = (p: Promise<unknown>) => p.then(() => undefined, (e: unknown) => e);

/** IR-2026-09-20: import/export (scrypt) limited per owner, one at a time per owner, bounded per process. */
describe('managed-signer import/export limits', () => {
  it('per-owner bucket: wrong passwords count, other owners are unaffected, tokens come back', async () => {
    let now = 0;
    const core = new ManagedSigner(new MemoryVault(), { now: () => now, scryptLimits: { perOwner: { perMinute: 60, burst: 2 }, maxConcurrent: 2, maxQueue: 4 } });
    expect(((await rejection(core.importEncrypted('o', 'p', ncryptsec(), 'wrong password'))) as { status: number }).status).toBe(400);
    const k = await core.importEncrypted('o', 'p', ncryptsec(), PASSWORD);
    const err = await rejection(core.export(k.keyId, 'o', 'p', PASSWORD, 4));
    expect(err).toBeInstanceOf(RateLimitedError);
    expect(err).toMatchObject({ status: 429, scope: 'owner', retryAfterSeconds: 1 });
    expect((await core.importEncrypted('other', 'p', ncryptsec(), PASSWORD)).state).toBe('active');
    now += 1000;
    expect((await core.export(k.keyId, 'o', 'p', PASSWORD, 4)).ncryptsec).toMatch(/^ncryptsec1/);
    expect(core.metrics.rateLimited.get({ op: 'export', scope: 'owner' })).toBe(1);
  });

  it('one scrypt operation at a time per owner', async () => {
    const core = new ManagedSigner(new MemoryVault(), { scryptLimits: { perOwner: { perMinute: 60, burst: 10 }, maxConcurrent: 4, maxQueue: 4 } });
    const results = await Promise.allSettled([core.importEncrypted('o', 'p', ncryptsec(), PASSWORD), core.importEncrypted('o', 'p', ncryptsec(), PASSWORD)]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const failed = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
    expect(failed.reason).toMatchObject({ status: 429, scope: 'owner' });
  });

  it('bounds concurrent scrypt runs per process and rejects beyond the queue', async () => {
    const gate = new ScryptGate({ perOwner: { perMinute: 60 }, maxConcurrent: 1, maxQueue: 1 });
    let running = 0;
    let peak = 0;
    const releases: Array<() => void> = [];
    const job = () =>
      new Promise<void>((resolve) => {
        running++;
        peak = Math.max(peak, running);
        releases.push(() => (running--, resolve()));
      });
    const a = gate.run('a', job);
    const b = gate.run('b', job); // queued
    expect(await gate.run('c', job)).toEqual({ ok: false, scope: 'busy', retryAfterMs: 1000 });
    releases.shift()!();
    expect(await a).toEqual({ ok: true, value: undefined });
    await new Promise((r) => setTimeout(r, 0));
    releases.shift()!();
    expect(await b).toEqual({ ok: true, value: undefined });
    expect(peak).toBe(1);
  });

  describe('over HTTP', () => {
    const acceso = createTestCognito();
    let base: string;
    const core = new ManagedSigner(new MemoryVault(), { scryptLimits: { perOwner: { perMinute: 1, burst: 1 }, maxConcurrent: 2, maxQueue: 4 } });
    const api = createManagedSignerApi(core, { name: 'signer-scrypt', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
    beforeAll(async () => (base = await api.listen()));
    afterAll(() => api.close());

    it('answers 429 with Retry-After', async () => {
      const imp = () => fetch(`${base}/v1/keys/import`, { method: 'POST', headers: { authorization: `Bearer ${acceso.token({ sub: 'u1' })}` }, body: JSON.stringify({ ncryptsec: ncryptsec(), password: PASSWORD, consent_version: 'textos test' }) });
      expect((await imp()).status).toBe(201);
      const res = await imp();
      expect(res.status).toBe(429);
      expect(Number(res.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    });
  });
});
