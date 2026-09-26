import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { generateSecretKey, getPublicKey, nip19, nip49, nip98, bytesToHex, npubEncode } from '@sedecim/nostr-core';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { LocalSigner } from '@sedecim/signer';
import { IdentityManager } from '@sedecim/identity';
import { BackupVaultClient, BackupVaultError, BackupEnvelopeError } from '@sedecim/identity/backup-vault';
import { createPgPool, migrate, nip98Fetch, resetScope } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import { createIdentityApi, MemoryIdentityRepository, PgIdentityRepository, type IdentityRepository } from '../src/index';
import { iss, token, verifier } from './cognito-fixture';

const LOGN = 4;
const webBackup = (sk: Uint8Array, pass = 'backup-pw') => ({ format: 'acceso-nostr-key-backup', version: 1, npub: npubEncode(getPublicKey(sk)), ncryptsec: nip49.encryptKey(sk, pass, LOGN, 0x01) });

function manager() {
  const account = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(3));
  const backends = new Map<string, MemoryBackend>();
  const open = async (id: string) => {
    if (!backends.has(id)) backends.set(id, new MemoryBackend());
    return EncryptedStore.withKey(backends.get(id)!, new Uint8Array(32).fill(id.length));
  };
  return new IdentityManager(account, open);
}

function suite(name: string, makeRepo: () => Promise<IdentityRepository>) {
  describe(name, () => {
    let base: string;
    let api: ReturnType<typeof createIdentityApi>;
    let repo: IdentityRepository;
    const logs: string[] = [];
    const a = generateSecretKey();
    const b = generateSecretKey();

    beforeAll(async () => {
      repo = await makeRepo();
      const logger = createLogger({ base: { service: 'identity-test' }, minimizeIp: true, write: (r) => logs.push(JSON.stringify(r)), level: 'debug' });
      api = createIdentityApi(repo, { name: 'identity-test', cognito: verifier(), backupVault: { maxBytes: 64 * 1024, keep: 3 }, logger });
      base = await api.listen();
      await nip98Fetch(a, `${base}/v1/accounts`, 'POST', {});
      await nip98Fetch(b, `${base}/v1/accounts`, 'POST', {});
    });
    afterAll(() => api.close());

    it('stores only well-formed encrypted envelopes and rejects plaintext keys (FR027-03)', async () => {
      const url = `${base}/v1/backups`;
      const nsec = nip19.nsecEncode(a);
      const hex = bytesToHex(a);
      const env = webBackup(a);
      const bad: unknown[] = [
        { ...env, ncryptsec: undefined, nsec },
        { ...env, note: nsec },
        { ...env, secretHex: hex },
        { ...env, ncryptsec: nsec },
        { ...env, ncryptsec: 'ncryptsec1notreally' },
        { format: 'sedecim-identity-backup', version: 1, persona: { id: 'p', pubkey: getPublicKey(a), relays: [] }, createdAt: 1 },
        { format: 'sedecim-identity-backup', version: 2, contentKey: env.ncryptsec, sealed: 'plain text', createdAt: 1 },
        { format: 'plain', version: 1, secret: hex },
        [env],
        { ...env, extra: 'x' },
      ];
      for (const body of bad) expect((await nip98Fetch(a, url, 'POST', body)).status, JSON.stringify(body).slice(0, 80)).toBe(400);
      expect((await nip98Fetch(a, url, 'POST', nsec)).status).toBe(400);
      expect((await nip98Fetch(a, url, 'POST', { ...env, npub: env.npub.slice(0, -1) + (env.npub.endsWith('q') ? 'p' : 'q') })).status).toBe(400);
      const big = { format: 'sedecim-identity-backup', version: 2, contentKey: env.ncryptsec, sealed: Buffer.alloc(70 * 1024, 7).toString('base64'), createdAt: 1 };
      expect((await nip98Fetch(a, url, 'POST', big)).status).toBe(413);
      expect((await fetch(url, { method: 'POST', body: JSON.stringify(env) })).status).toBe(401);
      expect(await repo.backupsOf((await repo.personaByPubkey(getPublicKey(a)))!.accountId)).toEqual([]);

      const ok = await nip98Fetch(a, url, 'POST', env);
      expect(ok.status).toBe(201);
      expect(ok.json.backup).toMatchObject({ format: 'acceso-nostr-key-backup', format_version: 1, npub: env.npub, sha256: nip98.payloadHash(JSON.stringify(env)) });
      // Contents are never logged, even at debug level, and the audit keeps metadata only.
      expect(logs.join('\n')).not.toContain(env.ncryptsec.slice(12, 40));
      const audit = (await nip98Fetch(a, `${base}/v1/accounts/me/audit`)).json.audit;
      expect(JSON.stringify(audit)).not.toContain('ncryptsec1');
      expect(audit.at(-1)).toMatchObject({ action: 'backup.stored', details: { format: 'acceso-nostr-key-backup' } });
    });

    it('isolates owners, keeps the last N versions and deletes on request', async () => {
      const ca = new BackupVaultClient({ baseUrl: base, auth: { signer: new LocalSigner(a) } });
      const cb = new BackupVaultClient({ baseUrl: base, auth: { signer: new LocalSigner(b) } });
      const mine = await ca.upload(webBackup(a, 'second'));
      await expect(cb.download(mine.id)).rejects.toMatchObject({ status: 404 });
      await expect(cb.download()).rejects.toMatchObject({ status: 404 });
      expect(await cb.list()).toEqual([]);
      expect(await cb.remove(mine.id).catch((e: BackupVaultError) => e.status)).toBe(404);
      await cb.upload(webBackup(b));
      expect((await cb.list()).map((x) => x.npub)).toEqual([npubEncode(getPublicKey(b))]);
      // An unregistered key has no vault.
      await expect(new BackupVaultClient({ baseUrl: base, auth: { signer: new LocalSigner(generateSecretKey()) } }).list()).rejects.toMatchObject({ status: 404 });

      for (let i = 0; i < 3; i++) await ca.upload(webBackup(a, `v${i}`));
      const list = await ca.list();
      expect(list).toHaveLength(3);
      expect(list.map((x) => x.id)).not.toContain(mine.id);
      const latest = await ca.download();
      expect(latest.meta.id).toBe(list[0]!.id);
      expect((await nip49.decryptKeyAsync(JSON.parse(latest.envelope).ncryptsec, 'v2')).secretKey).toEqual(a);
      expect(await ca.remove(list[2]!.id)).toBe(1);
      expect(await ca.remove()).toBe(2);
      expect(await ca.list()).toEqual([]);
      expect(await cb.list()).toHaveLength(1);
    });

    it('client refuses to upload plaintext before anything leaves the device', async () => {
      let calls = 0;
      const c = new BackupVaultClient({ baseUrl: base, auth: { signer: new LocalSigner(a) }, fetch: (async () => (calls++, new Response('{}'))) as typeof fetch });
      await expect(c.upload({ format: 'acceso-nostr-key-backup', version: 1, npub: npubEncode(getPublicKey(a)), ncryptsec: nip19.nsecEncode(a) })).rejects.toBeInstanceOf(BackupEnvelopeError);
      await expect(c.upload(bytesToHex(a))).rejects.toBeInstanceOf(BackupEnvelopeError);
      expect(calls).toBe(0);
    });

    it('round-trips a full v2 backup and restores it on a new device with the Acceso login', async () => {
      const one = manager();
      const p = await one.createPersona({ label: 'Grupos', relays: ['wss://a.example'], keyPassphrase: 'pp', scryptLogN: LOGN });
      const signer = await one.unlock(p.id, 'pp');
      // The persona creates its own account and links the Acceso login.
      const reg = await new BackupVaultClient({ baseUrl: base, auth: { signer } }).list().catch((e: BackupVaultError) => e.status);
      expect(reg).toBe(404);
      const signed = async (path: string, method: string, body?: unknown) => {
        const raw = body === undefined ? undefined : JSON.stringify(body);
        const evt = await signer.signEvent(nip98.buildHttpAuthTemplate(`${base}${path}`, method, raw));
        return fetch(`${base}${path}`, { method, headers: { authorization: nip98.encodeAuthHeader(evt), 'content-type': 'application/json' }, ...(raw ? { body: raw } : {}) });
      };
      expect((await signed('/v1/accounts', 'POST', {})).status).toBe(201);
      expect((await signed('/v1/accounts/me/external-logins', 'POST', { provider: 'cognito', token: token({ sub: 'vault-user' }) })).status).toBe(201);

      const pkg = await one.exportBackup(p.id, 'backup-pw', { keyPassphrase: 'pp', scryptLogN: LOGN });
      const meta = await new BackupVaultClient({ baseUrl: base, auth: { signer } }).upload(pkg);
      expect(meta).toMatchObject({ format: 'sedecim-identity-backup', format_version: 2 });
      expect(meta.npub).toBeUndefined();

      // New device: only the Acceso token (SaaS) and the backup password.
      const viaAcceso = new BackupVaultClient({ baseUrl: base, auth: { token: async () => token({ sub: 'vault-user' }) } });
      const { envelope } = await viaAcceso.download();
      const two = manager();
      const restored = await two.restoreBackup(JSON.parse(envelope), 'backup-pw', 'new-pp', { scryptLogN: LOGN });
      expect(restored).toEqual(p);
      expect(await (await two.unlock(p.id, 'new-pp')).getPublicKey()).toBe(p.pubkey);

      // Acceso tokens: invalid, unlinked or from another user never reach this vault.
      await expect(new BackupVaultClient({ baseUrl: base, auth: { token: async () => token({ sub: 'vault-user', exp: 1 }) } }).list()).rejects.toMatchObject({ status: 401 });
      await expect(new BackupVaultClient({ baseUrl: base, auth: { token: async () => token({ sub: 'someone-else' }) } }).list()).rejects.toMatchObject({ status: 404 });
      await expect(new BackupVaultClient({ baseUrl: base, auth: { token: async () => token({ sub: 'vault-user', iss: `${iss}x` }) } }).list()).rejects.toMatchObject({ status: 401 });
      expect(await new BackupVaultClient({ baseUrl: base, auth: { signer: new LocalSigner(a) } }).list()).toEqual([]);
    });

    it('detects a tampered download', async () => {
      const c = new BackupVaultClient({
        baseUrl: base,
        auth: { signer: new LocalSigner(a) },
        fetch: (async () => new Response(JSON.stringify({ backup: { id: 'x', sha256: '00'.repeat(32) }, envelope: JSON.stringify(webBackup(a)) }))) as typeof fetch,
      });
      await expect(c.download()).rejects.toThrow(/sha256/);
    });
  });
}

suite('backup vault (memory)', async () => new MemoryIdentityRepository());
const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  suite('backup vault (postgres)', async () => {
    const pool = createPgPool(PG);
    await resetScope(pool, 'identity-service', ['backup_vault', 'identity_audit', 'external_logins', 'key_metadata', 'identity_links', 'identity_personas', 'accounts']);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'identity-service');
    return new PgIdentityRepository(pool);
  });
}
