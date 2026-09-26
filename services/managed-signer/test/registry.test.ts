import { afterAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { finalizeEvent, generateSecretKey, nip49, toUnsigned, verifyEvent } from '@sedecim/nostr-core';
import { createPgPool, createTestCognito, migrate, resetScope, type Pool } from '@sedecim/service-kit';
import { ManagedSignerClient } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, LocalEnvelopeVault, ManagedSigner, MemoryKeyRegistry, PgKeyRegistry, type KeyRegistry } from '../src/index';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
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
      const created = await ManagedSignerClient.createKey({ baseUrl: first.base, token }, { allowedKinds: [1, 7] });
      const before = await new ManagedSignerClient({ baseUrl: first.base, token, keyId: created.keyId }).signEvent({ kind: 1, content: 'antes' });
      await first.api.close();

      const second = await start();
      try {
        const client = new ManagedSignerClient({ baseUrl: second.base, token, keyId: created.keyId });
        const info = await client.describe();
        expect(info).toMatchObject({ keyId: created.keyId, pubkey: created.pubkey, owner: `${acceso.issuer}#restart-user`, state: 'active', allowedKinds: [1, 7], retentionDays: 30 });
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
  });
}

const memory = new MemoryKeyRegistry();
suite('managed-signer registry (memory)', async () => memory);

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  const pools: Pool[] = [];
  let reset = false;
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end()));
  });
  suite('managed-signer registry (postgres)', async () => {
    const pool = createPgPool(PG);
    pools.push(pool);
    if (!reset) {
      await resetScope(pool, 'managed-signer', ['managed_key_usage', 'managed_keys']);
      reset = true;
    }
    await migrate(pool, MIGRATIONS, 'managed-signer');
    return new PgKeyRegistry(pool);
  });
}
