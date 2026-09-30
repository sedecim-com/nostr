import { afterAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, finalizeEvent, generateSecretKey, nip19, nip49, toUnsigned, verifyEvent } from '@sedecim/nostr-core';
import { createPgPool, createTestCognito, migrate, resetScope, type Pool } from '@sedecim/service-kit';
import { ManagedSignerClient } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, LocalEnvelopeVault, ManagedSigner, MemoryDeviceStore, MemoryKeyRegistry, PgDeviceStore, PgKeyRegistry, type DeviceStore, type KeyRegistry } from '../src/index';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
const OPS = fileURLToPath(new URL('../src/ops.ts', import.meta.url));
/** Runs an operator command (src/ops.ts) as the operator would, with only the given configuration. */
const ops = (args: string[], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, ['--import', 'tsx', OPS, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', ...env }, timeout: 60_000 });
const acceso = createTestCognito();
const silent = createLogger({ write: () => {} });

/** `open()` simulates a (re)start of the service: a fresh registry over the same storage. */
function suite(name: string, open: () => Promise<KeyRegistry>) {
  describe(name, () => {
    it('keeps keys and the usage log across restarts: create, restart, sign', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vault-'));
      const kek = new Uint8Array(32).fill(7);
      const start = async () => {
        const api = createManagedSignerApi(new ManagedSigner(new LocalEnvelopeVault(dir, kek), { registry: await open(), retentionDays: 30 }), { name: 'ms', cognito: acceso.verifier(), logger: silent });
        return { api, base: await api.listen() };
      };
      const token = async () => acceso.token({ sub: 'restart-user' });

      const first = await start();
      const created = await ManagedSignerClient.createKey({ baseUrl: first.base, token }, { allowedKinds: [1, 7], consentVersion: 'textos test' });
      const before = await new ManagedSignerClient({ baseUrl: first.base, token, keyId: created.keyId }).signEvent({ kind: 1, content: 'antes' });
      await first.api.close();

      const second = await start();
      try {
        const client = new ManagedSignerClient({ baseUrl: second.base, token, keyId: created.keyId });
        const info = await client.describe();
        expect(info).toMatchObject({ keyId: created.keyId, pubkey: created.pubkey, owner: `${acceso.issuer}#restart-user`, state: 'active', allowedKinds: [1, 7], retentionDays: 30, consentVersion: 'textos test' });
        expect(info.consentAt).toBe(created.consentAt); // FR005-08: the recorded consent survives a restart
        expect(info.lastUsed).toBeGreaterThanOrEqual(info.createdAt);
        const after = await client.signEvent({ kind: 1, content: 'después' });
        expect(verifyEvent(after) && after.pubkey === before.pubkey).toBe(true);
        await expect(client.signEvent({ kind: 4, content: 'no' })).rejects.toThrow(/403/);
        expect((await ManagedSignerClient.listKeys({ baseUrl: second.base, token })).map((k) => k.keyId)).toEqual([created.keyId]);
      } finally {
        await second.api.close();
      }
      const usage = await (await open()).usageOf(created.keyId);
      expect(usage.map((u) => u.action)).toEqual(['created', 'sign', 'sign']);
      expect(usage[1]).toMatchObject({ kind: 1, eventId: before.id });
    });

    it('refuses to manage the same pubkey twice and finalizes deletions after the retention window', async () => {
      const registry = await open();
      let now = Date.UTC(2026, 10, 1);
      const core = new ManagedSigner(new LocalEnvelopeVault(await mkdtemp(join(tmpdir(), 'vault-')), new Uint8Array(32).fill(9)), { registry, retentionDays: 30, now: () => now });
      const sk = generateSecretKey();
      const ncryptsec = nip49.encryptKey(sk, 'contraseña de importación', 4);
      const k = await core.importEncrypted('owner-x', 'owner-x', ncryptsec, 'contraseña de importación');
      await expect(core.importEncrypted('owner-y', 'owner-y', ncryptsec, 'contraseña de importación')).rejects.toThrow(/already managed/);

      const exp = await core.export(k.keyId, 'owner-x', 'owner-x', 'contraseña suficientemente larga', 4);
      await core.confirmMigration(k.keyId, 'owner-x', 'owner-x', finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', exp.challenge]] }, k.pubkey), sk));
      await core.delete(k.keyId, 'owner-x', 'owner-x');
      expect((await registry.get(k.keyId))!).toMatchObject({ state: 'deleted', deletedAt: now });
      // Once deleted the pubkey can be managed again (e.g. the user opts back in).
      const again = await core.importEncrypted('owner-x', 'owner-x', ncryptsec, 'contraseña de importación');
      expect(again.keyId).not.toBe(k.keyId);

      now += 31 * 86_400_000;
      expect((await registry.pendingDestruction(now)).map((r) => r.keyId)).toEqual([k.keyId]);
      expect((await core.runRetention()).keysDestroyed).toBe(1);
      expect((await registry.get(k.keyId))!.destroyedAt).toBe(now);
      expect(await registry.pendingDestruction(now)).toEqual([]);

      now = Date.UTC(2027, 11, 15);
      const { usagePurged } = await core.runRetention();
      expect(usagePurged).toBeGreaterThanOrEqual(5);
      expect(await registry.usageOf(k.keyId)).toEqual([]);
    });

    it('records how a key left and clears its owner and consent once destroyed (FR026-04)', async () => {
      const registry = await open();
      let now = Date.UTC(2026, 10, 2);
      const core = new ManagedSigner(new LocalEnvelopeVault(await mkdtemp(join(tmpdir(), 'vault-')), new Uint8Array(32).fill(3)), { registry, retentionDays: 30, now: () => now });
      const owner = 'owner-exit';
      const k = await core.create(owner, owner, { consentVersion: 'textos test' });
      await core.cancel(k.keyId, owner, owner, nip19.npubEncode(k.pubkey));
      expect((await registry.get(k.keyId))!).toMatchObject({ state: 'deleted', exit: 'cancelled', deletedAt: now, consentVersion: 'textos test' });
      expect((await registry.listClosedByOwner(owner)).map((r) => r.keyId)).toEqual([k.keyId]);

      now += 31 * 86_400_000;
      expect((await core.runRetention()).keysScrubbed).toBeGreaterThanOrEqual(1);
      const rec = (await registry.get(k.keyId))!;
      expect(rec).toMatchObject({ owner: '', exit: 'cancelled', destroyedAt: now, scrubbedAt: now });
      expect(rec.consentVersion).toBeUndefined();
      expect(rec.consentAt).toBeUndefined();
      expect(await registry.listClosedByOwner(owner)).toEqual([]);
      expect(await registry.pendingScrub()).toEqual([]);
    });
  });
}

function deviceStoreSuite(name: string, open: () => Promise<DeviceStore>) {
  describe(name, () => {
    it('keeps revocations, drops the sessions of the device and purges expired ones', async () => {
      const store = await open();
      const at = Date.UTC(2026, 5, 1);
      const sess = (h: string, deviceId: string, expiresAt = at + 1000) => ({ tokenHash: h.repeat(64), deviceId, owner: 'o', principal: 'o', createdAt: at, expiresAt });
      await store.insertSession(sess('a', 'd1'));
      await store.insertSession(sess('b', 'd1'));
      await store.insertSession(sess('c', 'd2', at));
      expect(await store.session('a'.repeat(64))).toMatchObject({ deviceId: 'd1', expiresAt: at + 1000 });
      expect(await store.revoke({ deviceId: 'd1', revokedAt: at, revokedBy: 'policy', reason: 'lost' })).toEqual({ alreadyRevoked: false, sessionsDropped: 2 });
      expect(await store.revoke({ deviceId: 'd1', revokedAt: at + 5, revokedBy: 'other' })).toEqual({ alreadyRevoked: true, sessionsDropped: 0 });
      expect(await store.revocation('d1')).toEqual({ deviceId: 'd1', revokedAt: at, revokedBy: 'policy', reason: 'lost' });
      expect(await store.revocation('d2')).toBeUndefined();
      expect(await store.session('a'.repeat(64))).toBeUndefined();
      expect(await store.purgeExpiredSessions(at)).toBe(1);
      expect(await store.session('c'.repeat(64))).toBeUndefined();
    });

    it("lists and closes an owner's own live sessions only (FR005-11)", async () => {
      const store = await open();
      const at = Date.UTC(2026, 6, 1);
      const sess = (h: string, owner: string, createdAt: number, expiresAt = at + 1000) => ({ tokenHash: h.repeat(64), deviceId: `dev-${h}`, owner, principal: owner, createdAt, expiresAt });
      await store.insertSession(sess('e', 'ana', at + 2));
      await store.insertSession(sess('f', 'ana', at + 1));
      await store.insertSession(sess('0', 'ana', at, at)); // expired
      await store.insertSession(sess('1', 'bea', at));
      expect((await store.sessionsOf('ana', at)).map((x) => x.deviceId)).toEqual(['dev-f', 'dev-e']);
      // Another owner's session is not closed through this owner.
      expect(await store.dropSessions('ana', ['1'.repeat(64), 'e'.repeat(64)])).toBe(1);
      expect(await store.session('1'.repeat(64))).toMatchObject({ owner: 'bea' });
      expect((await store.sessionsOf('ana', at)).map((x) => x.deviceId)).toEqual(['dev-f']);
      expect(await store.dropSessions('ana', [])).toBe(0);
    });
  });
}

describe('managed-signer operator commands (FR026-04)', () => {
  it('validates their arguments and never act on a fresh in-memory registry', async () => {
    expect(ops([]).stderr).toMatch(/usage: ops.ts close-owner/);
    const noOwner = ops(['close-owner', 'sin-emisor', 'ARCO-1']);
    expect(noOwner.status).toBe(2);
    expect(noOwner.stderr).toMatch(/'<issuer>#<sub>'/);
    expect(ops(['close-owner', 'https://idp.example#sub', 'ticket con espacios']).stderr).toMatch(/name the request/);
    const noDb = ops(['close-owner', 'https://idp.example#sub', 'ARCO-1'], { MANAGED_SIGNER_KEK: '00'.repeat(32), MANAGED_SIGNER_VAULT_DIR: await mkdtemp(join(tmpdir(), 'vault-')) });
    expect(noDb.status).toBe(2);
    expect(noDb.stderr).toMatch(/DATABASE_URL is not set/);
  });
});

const memory = new MemoryKeyRegistry();
suite('managed-signer registry (memory)', async () => memory);
deviceStoreSuite('managed-signer device store (memory)', async () => new MemoryDeviceStore());

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  const pools: Pool[] = [];
  let reset = false;
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end()));
  });
  const openPool = async () => {
    const pool = createPgPool(PG);
    pools.push(pool);
    if (!reset) {
      await resetScope(pool, 'managed-signer', ['managed_key_usage', 'managed_keys', 'managed_signer_device_sessions', 'managed_signer_revoked_devices']);
      reset = true;
    }
    await migrate(pool, MIGRATIONS, 'managed-signer');
    return pool;
  };
  suite('managed-signer registry (postgres)', async () => new PgKeyRegistry(await openPool()));
  describe('managed-signer operator commands (postgres)', () => {
    it("close-owner takes every live key of the owner out of managed custody, in the service's registry (FR026-04)", async () => {
      const registry = new PgKeyRegistry(await openPool());
      const dir = await mkdtemp(join(tmpdir(), 'vault-'));
      const kek = new Uint8Array(32).fill(4);
      const core = new ManagedSigner(new LocalEnvelopeVault(dir, kek), { registry, retentionDays: 30 });
      const owner = 'https://idp.example#arco-user';
      const k = await core.create(owner, owner, { consentVersion: 'textos test' });
      const other = await core.create('https://idp.example#otra', 'x');
      const run = ops(['close-owner', owner, 'ARCO-2026-001'], { DATABASE_URL: PG, MANAGED_SIGNER_KEK: bytesToHex(kek), MANAGED_SIGNER_VAULT_DIR: dir });
      expect(run.status, run.stderr).toBe(0);
      const out = JSON.parse(run.stdout) as { owner: string; closed: Array<{ key_id: string; destroy_after: string }> };
      expect(out.owner).toBe(owner);
      expect(out.closed.map((c) => c.key_id)).toEqual([k.keyId]);
      expect(Date.parse(out.closed[0]!.destroy_after)).toBeGreaterThan(Date.now() + 29 * 86_400_000);
      expect(await registry.get(k.keyId)).toMatchObject({ state: 'deleted', exit: 'cancelled' });
      expect((await registry.usageOf(k.keyId)).at(-1)).toMatchObject({ action: 'cancelled', principal: 'operator:ARCO-2026-001' });
      expect((await registry.get(other.keyId))!.state).toBe('active');
    });
  });
  deviceStoreSuite('managed-signer device store (postgres)', async () => new PgDeviceStore(await openPool()));
}
