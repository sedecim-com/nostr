import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64 } from '@scure/base';
import { finalizeEvent, generateSecretKey, getPublicKey, nip19, nip98, randomBytes, toUnsigned, utf8ToBytes } from '@sedecim/nostr-core';
import { ArchiveVaultClient, ArchiveVaultError, archiveAuthKey, archiveId, archiveKeyId, archiveOwnerPubkey, generateArchiveKey, openArchiveText, sealArchive } from '@sedecim/continuity';
import { createPgPool, createTestCognito, migrate, resetScope, type Pool } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import { CreateBucketCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { createContinuityVaultApi, FileObjectStore, MemoryArchiveRepository, MemoryObjectStore, PgArchiveRepository, S3ObjectStore, VaultSweeper, type ArchiveRepository, type ContinuityVaultOptions, type ObjectStore } from '../src/index';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
const acceso = createTestCognito();
const silent = createLogger({ write: () => {} });

/** A request signed with NIP-98 by the key the client derives from its archive key. */
async function call(key: Uint8Array, base: string, method: string, path: string, body?: string) {
  const url = base + path;
  const sk = archiveAuthKey(key);
  const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, method, body), getPublicKey(sk)), sk);
  const res = await fetch(url, { method, headers: { authorization: nip98.encodeAuthHeader(evt), 'content-type': 'application/json' }, ...(body !== undefined ? { body } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : undefined };
}

async function bearer(token: string, base: string, method: string, path: string, body?: string) {
  const res = await fetch(base + path, { method, headers: { authorization: `Bearer ${token}` }, ...(body !== undefined ? { body } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : undefined };
}

async function keysOf(objects: ObjectStore): Promise<string[]> {
  const out: string[] = [];
  for await (const k of objects.list()) out.push(k);
  return out;
}

interface Backend {
  repo: ArchiveRepository;
  objects: ObjectStore;
  /** Every stored metadata row, as text (what an operator could read from the database). */
  dump(): Promise<string>;
}

function suite(name: string, open: () => Promise<Backend>) {
  describe(name, () => {
    let backend: Backend;
    let logs: string[];
    const apis: Array<{ close(): Promise<void> }> = [];
    const start = async (opts: Partial<ContinuityVaultOptions> = {}, b: Backend = backend) => {
      const api = createContinuityVaultApi(b.repo, b.objects, {
        name: 'vault-test',
        cognito: acceso.verifier(),
        logger: createLogger({ base: { service: 'vault-test' }, level: 'debug', write: (r) => logs.push(JSON.stringify(r)) }),
        ...opts,
      });
      apis.push(api);
      return api.listen();
    };

    beforeAll(async () => {
      backend = await open();
      logs = [];
    });
    afterAll(async () => {
      await Promise.all(apis.map((a) => a.close()));
    });

    it('stores, replaces, lists, returns and deletes sealed envelopes (VAULT-01)', async () => {
      const base = await start();
      const key = generateArchiveKey();
      const vault = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });
      const ledger = archiveId(key, 'ledger');
      const first = await vault.put(ledger, sealArchive(key, ledger, '{"v":1}'));
      expect(first.created).toBe(true);
      expect(first.archive).toMatchObject({ id: ledger, key_id: archiveKeyId(key) });
      const objectsAfterFirst = await keysOf(backend.objects);

      // Retrying or updating the same id replaces it: no duplicate, and the old object is gone.
      const second = await vault.put(ledger, sealArchive(key, ledger, '{"v":2}'));
      expect(second.created).toBe(false);
      expect(second.archive.created_at).toBe(first.archive.created_at);
      expect(second.archive.sha256).not.toBe(first.archive.sha256);
      const objectsAfterSecond = await keysOf(backend.objects);
      expect(objectsAfterSecond.length).toBe(objectsAfterFirst.length);
      expect(objectsAfterSecond).not.toEqual(objectsAfterFirst);

      const got = await vault.get(ledger);
      expect(openArchiveText(key, ledger, got.envelope)).toBe('{"v":2}');
      expect(await vault.listAll()).toEqual([second.archive]);
      expect(await vault.usage()).toMatchObject({ archives: 1, bytes: second.archive.size, limits: { max_archives: 100_000 } });

      expect(await vault.remove(ledger)).toBe(1);
      await expect(vault.get(ledger)).rejects.toMatchObject({ status: 404 });
      await expect(vault.remove(ledger)).rejects.toMatchObject({ status: 404 });
      expect(await vault.listAll()).toEqual([]);
      expect(await keysOf(backend.objects)).not.toContain(objectsAfterSecond.find((k) => !objectsAfterFirst.includes(k)));
    });

    it('rejects plaintext and anything that is not a sealed envelope, whatever the client', async () => {
      const base = await start({ limits: { maxEnvelopeBytes: 16 * 1024 } });
      const key = generateArchiveKey();
      const id = archiveId(key, 'x');
      const sk = generateSecretKey();
      const event = finalizeEvent(toUnsigned({ kind: 14, content: 'nos vemos a las 9', tags: [] }, getPublicKey(sk)), sk);
      const good = sealArchive(key, id, 'hola');
      const readable = base64.encode(new Uint8Array([...randomBytes(24), ...utf8ToBytes(JSON.stringify(event).padEnd(276, ' ').slice(0, 276))]));
      const before = (await keysOf(backend.objects)).length;
      for (const [body, status] of [
        [JSON.stringify(event), 400],
        [JSON.stringify({ messages: ['hola'] }), 400],
        [JSON.stringify({ ...good, note: nip19.nsecEncode(sk) }), 400],
        [JSON.stringify({ ...good, label: 'dm con ana' }), 400],
        [JSON.stringify({ ...good, sealed: readable }), 400],
        [JSON.stringify({ ...good, sealed: base64.encode(randomBytes(24 + 4 + 300 + 16)) }), 400],
        ['hola', 400],
        ['', 400],
        [JSON.stringify(sealArchive(key, id, new Uint8Array(20_000))), 413],
      ] as const) {
        const r = await call(key, base, 'PUT', `/v1/archives/${id}`, body);
        expect(r.status, body.slice(0, 60)).toBe(status);
      }
      expect((await keysOf(backend.objects)).length).toBe(before);
      expect((await call(key, base, 'PUT', '/v1/archives/ledger', JSON.stringify(good))).status).toBe(400);
      expect((await call(key, base, 'GET', '/v1/archives?after=zz')).status).toBe(400);
      expect((await call(key, base, 'GET', '/v1/archives?limit=0')).status).toBe(400);
      expect((await call(key, base, 'GET', '/v1/archives?limit=1001')).status).toBe(400);
      // Unauthenticated or replayed requests never reach the handler.
      expect((await fetch(`${base}/v1/archives`)).status).toBe(401);
      // Nothing about the rejected content ends up in the logs.
      expect(logs.join('\n')).not.toContain('nos vemos');
    });

    it('keeps accounts apart: one archive key cannot see, read or delete another', async () => {
      const base = await start();
      const a = generateArchiveKey();
      const b = generateArchiveKey();
      const va = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: a } });
      const vb = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: b } });
      const id = archiveId(a, 'ledger');
      await va.put(id, sealArchive(a, id, 'de a'));
      expect(await vb.listAll()).toEqual([]);
      await expect(vb.get(id)).rejects.toMatchObject({ status: 404 });
      await expect(vb.remove(id)).rejects.toMatchObject({ status: 404 });
      expect(await vb.remove()).toBe(0);
      // Even with the same id, b's upload is b's archive.
      await vb.put(id, sealArchive(b, id, 'de b'));
      expect(openArchiveText(a, id, (await va.get(id)).envelope)).toBe('de a');
      expect(openArchiveText(b, id, (await vb.get(id)).envelope)).toBe('de b');
      await va.remove();
      await vb.remove();
    });

    it('accepts Acceso logins as their own accounts and applies the NIP-98 policy', async () => {
      const base = await start();
      const token = acceso.token({ sub: 'vault-user' });
      const vault = new ArchiveVaultClient({ baseUrl: base, auth: { token: async () => token } });
      const key = generateArchiveKey();
      const id = archiveId(key, 'ledger');
      await vault.put(id, sealArchive(key, id, 'con acceso'));
      expect((await vault.listAll()).map((m) => m.id)).toEqual([id]);
      // The same archive key over NIP-98 is a different account.
      expect(await new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } }).listAll()).toEqual([]);
      expect((await bearer('not-a-token', base, 'GET', '/v1/archives')).status).toBe(401);
      expect((await bearer(acceso.token({ exp: 1 }), base, 'GET', '/v1/archives')).status).toBe(401);
      expect(await vault.remove()).toBe(1);

      const noAcceso = await start({ cognito: undefined });
      expect((await bearer(token, noAcceso, 'GET', '/v1/archives')).status).toBe(401);

      const onlyAcceso = await start({ nip98: 'off' });
      expect((await call(key, onlyAcceso, 'GET', '/v1/archives')).status).toBe(403);
      expect((await bearer(token, onlyAcceso, 'GET', '/v1/archives')).status).toBe(200);

      const allowedKey = generateArchiveKey();
      const allowlist = await start({ nip98: 'allowlist', allowedPubkeys: [archiveOwnerPubkey(allowedKey)] });
      expect((await call(key, allowlist, 'GET', '/v1/archives')).status).toBe(403);
      expect((await call(allowedKey, allowlist, 'GET', '/v1/archives')).status).toBe(200);

      expect(() => createContinuityVaultApi(backend.repo, backend.objects, { name: 'x', nip98: 'allowlist' })).toThrow(/allowed pubkey/);
      expect(() => createContinuityVaultApi(backend.repo, backend.objects, { name: 'x', nip98: 'off' })).toThrow(/Acceso/);
      expect(() => createContinuityVaultApi(backend.repo, backend.objects, { name: 'x', limits: { maxArchives: 0 } })).toThrow(/positive/);
    });

    it('enforces the quotas per account without leaving objects behind', async () => {
      const key = generateArchiveKey();
      const sample = JSON.stringify(sealArchive(key, archiveId(key, 's'), 'x')).length;
      const base = await start({ limits: { maxArchives: 2, maxBytes: sample * 3 } });
      const vault = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });
      const ids = ['a', 'b', 'c'].map((l) => archiveId(key, l));
      await vault.put(ids[0]!, sealArchive(key, ids[0]!, 'x'));
      await vault.put(ids[1]!, sealArchive(key, ids[1]!, 'x'));
      const before = (await keysOf(backend.objects)).length;
      await expect(vault.put(ids[2]!, sealArchive(key, ids[2]!, 'x'))).rejects.toMatchObject({ status: 507 });
      expect((await keysOf(backend.objects)).length).toBe(before);
      // Replacing does not count as a new archive.
      expect((await vault.put(ids[1]!, sealArchive(key, ids[1]!, 'y'))).created).toBe(false);
      // A bigger version that would pass the byte quota is refused, and the old one is kept.
      await expect(vault.put(ids[1]!, sealArchive(key, ids[1]!, new Uint8Array(sample * 2)))).rejects.toMatchObject({ status: 507 });
      expect(openArchiveText(key, ids[1]!, (await vault.get(ids[1]!)).envelope)).toBe('y');
      expect(await vault.usage()).toMatchObject({ archives: 2, limits: { max_archives: 2, max_bytes: sample * 3 } });
      await vault.remove(ids[0]);
      await vault.put(ids[2]!, sealArchive(key, ids[2]!, 'x'));
      expect(await vault.remove()).toBe(2);
      expect(await vault.usage()).toMatchObject({ archives: 0, bytes: 0 });
    });

    it('pages through the archives in id order', async () => {
      const base = await start();
      const key = generateArchiveKey();
      const vault = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });
      const ids = Array.from({ length: 5 }, (_, i) => archiveId(key, `event:${i}`));
      for (const id of ids) await vault.put(id, sealArchive(key, id, id));
      const sorted = [...ids].sort();
      const p1 = await vault.list({ limit: 2 });
      expect(p1.archives.map((m) => m.id)).toEqual(sorted.slice(0, 2));
      const p2 = await vault.list({ limit: 2, after: p1.next! });
      expect(p2.archives.map((m) => m.id)).toEqual(sorted.slice(2, 4));
      const p3 = await vault.list({ limit: 2, after: p2.next! });
      expect(p3.archives.map((m) => m.id)).toEqual(sorted.slice(4));
      expect(p3.next).toBeUndefined();
      expect((await vault.list({ limit: 5 })).next).toBeUndefined();
      expect((await vault.listAll()).map((m) => m.id)).toEqual(sorted);
      expect(await vault.remove()).toBe(5);
    });

    it('VAULT-05: an account chooses how long its archives are kept, within the operator maximum', async () => {
      const unlimited = new ArchiveVaultClient({ baseUrl: await start(), auth: { archiveKey: generateArchiveKey() } });
      expect((await unlimited.usage()).retention).toEqual({ days: null, max_days: null, effective_days: null });
      expect(await unlimited.setRetention(30)).toEqual({ days: 30, max_days: null, effective_days: 30 });
      expect(await unlimited.setRetention(null)).toEqual({ days: null, max_days: null, effective_days: null });

      const base = await start({ retentionDays: 90 });
      const key = generateArchiveKey();
      const vault = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });
      expect((await vault.usage()).retention).toEqual({ days: null, max_days: 90, effective_days: 90 });
      expect(await vault.setRetention(30)).toEqual({ days: 30, max_days: 90, effective_days: 30 });
      await expect(vault.setRetention(91)).rejects.toMatchObject({ status: 400 });
      for (const body of ['{"days":0}', '{"days":1.5}', '{"days":"30"}', '{}', 'nope']) expect((await call(key, base, 'PUT', '/v1/retention', body)).status, body).toBe(400);
      // The choice survives an archive coming and going, and goes with the account when everything is deleted.
      const id = archiveId(key, 'ledger');
      await vault.put(id, sealArchive(key, id, 'x'));
      await vault.remove(id);
      expect((await vault.usage()).retention!.days).toBe(30);
      await vault.put(id, sealArchive(key, id, 'x'));
      expect(await vault.remove()).toBe(1);
      expect((await vault.usage()).retention).toEqual({ days: null, max_days: 90, effective_days: 90 });
    });

    it('VAULT-05: the sweep deletes what outlived its retention, row and object, and objects no row points to', async () => {
      const base = await start({ retentionDays: 365 });
      const later = (days: number) => () => new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      const shortKey = generateArchiveKey();
      const short = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: shortKey } });
      const longKey = generateArchiveKey();
      const long = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: longKey } });
      await short.setRetention(30);
      for (const label of ['a', 'b']) {
        const id = archiveId(shortKey, label);
        await short.put(id, sealArchive(shortKey, id, label));
      }
      const kept = archiveId(longKey, 'a');
      await long.put(kept, sealArchive(longKey, kept, 'a'));
      const before = await keysOf(backend.objects);

      // Day 10: nothing is old enough. Day 31: the 30-day account loses its archives, the other keeps them.
      expect(await new VaultSweeper(backend.repo, backend.objects, { retentionDays: 365, now: later(10) }).sweep()).toMatchObject({ expired: 0 });
      const sweeper = new VaultSweeper(backend.repo, backend.objects, { retentionDays: 365, now: later(31) });
      expect((await sweeper.sweep()).expired).toBe(2);
      expect(await short.listAll()).toEqual([]);
      expect(await short.usage()).toMatchObject({ archives: 0, bytes: 0, retention: { days: 30 } });
      expect((await long.listAll()).map((a) => a.id)).toEqual([kept]);
      const after = await keysOf(backend.objects);
      expect(before.length - after.length).toBe(2);
      // Past the operator's maximum everything goes, whatever the account chose.
      await long.setRetention(null);
      expect((await new VaultSweeper(backend.repo, backend.objects, { retentionDays: 365, now: later(366) }).sweep()).expired).toBe(1);
      expect(await long.listAll()).toEqual([]);

      // An object no row points to (a crash between object and row) goes on the second sweep that finds it, never the first.
      const orphan = 'ab'.repeat(16);
      await backend.objects.put(orphan, utf8ToBytes('huérfano'));
      const orphans = new VaultSweeper(backend.repo, backend.objects);
      expect((await orphans.sweep()).orphans).toBe(0);
      expect(await keysOf(backend.objects)).toContain(orphan);
      // An upload that completes between two sweeps is not an orphan.
      const late = archiveId(shortKey, 'late');
      await short.put(late, sealArchive(shortKey, late, 'late'));
      expect((await orphans.sweep()).orphans).toBe(1);
      expect(await keysOf(backend.objects)).not.toContain(orphan);
      expect(openArchiveText(shortKey, late, (await short.get(late)).envelope)).toBe('late');
      expect((await orphans.sweep()).orphans).toBe(0);
      await short.remove();
    });

    it('VAULT-02: neither the database nor the object store holds readable text, events or keys', async () => {
      const logStart = logs.length;
      const base = await start();
      const persona = generateSecretKey();
      const personaPk = getPublicKey(persona);
      const key = generateArchiveKey();
      const vault = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });
      const secret = 'La reunión se mueve al jueves en el local de siempre';
      const event = finalizeEvent(toUnsigned({ kind: 14, content: secret, tags: [['p', getPublicKey(generateSecretKey())]] }, personaPk), persona);
      const stored = [
        [`event:${event.id}`, JSON.stringify(event)],
        ['ledger', JSON.stringify({ outbox: [{ id: event.id, state: 'REPLICATED', relays: ['wss://relay.example'] }] })],
        ['dm:ana', secret],
      ] as const;
      for (const [label, text] of stored) {
        const id = archiveId(key, label);
        await vault.put(id, sealArchive(key, id, text));
      }
      const objectTexts: string[] = [];
      for (const k of await keysOf(backend.objects)) objectTexts.push(new TextDecoder().decode((await backend.objects.get(k))!));
      const everything = [await backend.dump(), ...objectTexts, ...logs.slice(logStart)].join('\n');
      for (const needle of [secret, 'reunión', event.id, event.sig, personaPk, nip19.npubEncode(personaPk), nip19.nsecEncode(persona), '"kind"', '"content"', 'REPLICATED', 'relay.example', 'ledger', 'event:', 'dm:ana']) {
        expect(everything, needle).not.toContain(needle);
      }
      // The account is the key derived from the archive key, not the persona.
      expect(everything).toContain(`nostr:${archiveOwnerPubkey(key)}`);
      // And the owner can still read everything back.
      for (const [label, text] of stored) expect(openArchiveText(key, archiveId(key, label), (await vault.get(archiveId(key, label))).envelope)).toBe(text);
      await vault.remove();
    });
  });
}

suite('continuity-vault (memory)', async () => {
  const repo = new MemoryArchiveRepository();
  return { repo, objects: new MemoryObjectStore(), dump: async () => JSON.stringify(repo.rows()) };
});
suite('continuity-vault (memory metadata, file objects)', async () => {
  const repo = new MemoryArchiveRepository();
  return { repo, objects: new FileObjectStore(await mkdtemp(join(tmpdir(), 'vault-objects-'))), dump: async () => JSON.stringify(repo.rows()) };
});

describe('FileObjectStore', () => {
  it('writes files the vault can list, reads back and deletes; rejects keys that are not object keys', async () => {
    const store = new FileObjectStore(await mkdtemp(join(tmpdir(), 'vault-objects-')));
    const k = 'ab'.repeat(16);
    await store.put(k, new Uint8Array([1, 2, 3]));
    expect(await store.get(k)).toEqual(new Uint8Array([1, 2, 3]));
    expect(await keysOf(store)).toEqual([k]);
    await store.delete(k);
    await store.delete(k);
    expect(await store.get(k)).toBeUndefined();
    expect(await keysOf(store)).toEqual([]);
    await expect(store.put('../../etc/passwd', new Uint8Array(1))).rejects.toThrow(/invalid object key/);
    expect(await keysOf(new FileObjectStore(join(tmpdir(), 'no-such-vault-dir-' + Date.now())))).toEqual([]);
  });
});

/**
 * VAULT-06: the S3-compatible backend, against moto in CI (MOTO_ENDPOINT) or any S3 store (TEST_S3_ENDPOINT with
 * TEST_S3_ACCESS_KEY / TEST_S3_SECRET_KEY, e.g. the compose SeaweedFS). Each run uses a bucket of its own.
 */
const S3_ENDPOINT = process.env.TEST_S3_ENDPOINT || process.env.MOTO_ENDPOINT;
const s3Credentials = { accessKeyId: process.env.TEST_S3_ACCESS_KEY || 'test', secretAccessKey: process.env.TEST_S3_SECRET_KEY || 'test' };
const s3Bucket = `vault-test-${Date.now().toString(36)}`;
let s3BucketReady: Promise<void> | undefined;
const s3Store = async (opts: { prefix?: string; pageSize?: number; bucket?: string } = {}) => {
  s3BucketReady ??= (async () => {
    const admin = new S3Client({ region: 'us-east-1', endpoint: S3_ENDPOINT, forcePathStyle: true, credentials: s3Credentials });
    await admin.send(new CreateBucketCommand({ Bucket: s3Bucket }));
    admin.destroy();
  })();
  await s3BucketReady;
  return new S3ObjectStore({ bucket: opts.bucket ?? s3Bucket, endpoint: S3_ENDPOINT, credentials: s3Credentials, prefix: opts.prefix ?? `${randomHex()}/`, ...(opts.pageSize ? { pageSize: opts.pageSize } : {}) });
};
const randomHex = () => Buffer.from(randomBytes(6)).toString('hex');

if (S3_ENDPOINT) {
  describe('S3ObjectStore (VAULT-06)', () => {
    it('stores, lists page by page, reads back and deletes, only under its prefix', async () => {
      const prefix = `${randomHex()}/`;
      const store = await s3Store({ prefix, pageSize: 3 });
      await store.check();
      const keys = Array.from({ length: 7 }, () => randomHex().padEnd(32, '0').slice(0, 32)).sort();
      for (const [i, k] of keys.entries()) await store.put(k, new Uint8Array([i, 1, 2]));
      expect(await store.get(keys[3]!)).toEqual(new Uint8Array([3, 1, 2]));
      // Seven keys in pages of three, and nothing that is not an object key of this prefix.
      const other = await s3Store({ prefix: `${randomHex()}/` });
      await other.put('cd'.repeat(16), new Uint8Array([9]));
      const raw = new S3Client({ region: 'us-east-1', endpoint: S3_ENDPOINT, forcePathStyle: true, credentials: s3Credentials });
      await raw.send(new PutObjectCommand({ Bucket: s3Bucket, Key: `${prefix}not-an-object-key`, Body: 'x' }));
      raw.destroy();
      expect((await keysOf(store)).sort()).toEqual(keys);
      expect(await keysOf(other)).toEqual(['cd'.repeat(16)]);
      await store.delete(keys[0]!);
      await store.delete(keys[0]!);
      expect(await store.get(keys[0]!)).toBeUndefined();
      expect(await keysOf(store)).toHaveLength(6);
      await expect(store.put('../x', new Uint8Array(1))).rejects.toThrow(/invalid object key/);
      store.close();
      other.close();
    });

    it('refuses to start against a bucket that does not exist', async () => {
      const missing = await s3Store({ bucket: `${s3Bucket}-missing` });
      await expect(missing.check()).rejects.toThrow();
      missing.close();
    });
  });

  suite('continuity-vault (memory metadata, S3 objects)', async () => {
    const repo = new MemoryArchiveRepository();
    return { repo, objects: await s3Store(), dump: async () => JSON.stringify(repo.rows()) };
  });
}

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  const pools: Pool[] = [];
  let reset = false;
  const openPool = async () => {
    const pool = createPgPool(PG);
    pools.push(pool);
    if (!reset) {
      await resetScope(pool, 'continuity-vault', ['vault_archives', 'vault_owners']);
      reset = true;
    }
    await migrate(pool, MIGRATIONS, 'continuity-vault');
    return pool;
  };
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end()));
  });
  const pgBackend = async (dir?: string): Promise<Backend> => {
    const pool = await openPool();
    return {
      repo: new PgArchiveRepository(pool),
      objects: new FileObjectStore(dir ?? (await mkdtemp(join(tmpdir(), 'vault-objects-')))),
      dump: async () => JSON.stringify([(await pool.query('SELECT * FROM vault_owners')).rows, (await pool.query('SELECT * FROM vault_archives')).rows]),
    };
  };
  suite('continuity-vault (postgres, file objects)', () => pgBackend());
  if (S3_ENDPOINT) {
    suite('continuity-vault (postgres, S3 objects)', async () => {
      const b = await pgBackend();
      return { ...b, objects: await s3Store() };
    });
  }

  describe('continuity-vault (postgres) restarts and concurrency', () => {
    it('keeps the archives across a restart', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vault-objects-'));
      const key = generateArchiveKey();
      const id = archiveId(key, 'ledger');
      const b1 = await pgBackend(dir);
      const api1 = createContinuityVaultApi(b1.repo, b1.objects, { name: 'vault-restart', logger: silent });
      await new ArchiveVaultClient({ baseUrl: await api1.listen(), auth: { archiveKey: key } }).put(id, sealArchive(key, id, 'sobrevive'));
      await api1.close();
      const b2 = await pgBackend(dir);
      const api2 = createContinuityVaultApi(b2.repo, b2.objects, { name: 'vault-restart', logger: silent });
      try {
        const vault = new ArchiveVaultClient({ baseUrl: await api2.listen(), auth: { archiveKey: key } });
        expect(openArchiveText(key, id, (await vault.get(id)).envelope)).toBe('sobrevive');
        expect(await vault.remove()).toBe(1);
      } finally {
        await api2.close();
      }
    });

    it('serializes concurrent uploads of one account: the quota and the counters stay exact', async () => {
      const b = await pgBackend();
      const api = createContinuityVaultApi(b.repo, b.objects, { name: 'vault-race', limits: { maxArchives: 5 }, logger: silent });
      try {
        const base = await api.listen();
        const key = generateArchiveKey();
        const vault = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });
        const ids = Array.from({ length: 12 }, (_, i) => archiveId(key, `race:${i}`));
        const results = await Promise.allSettled(ids.map((id) => vault.put(id, sealArchive(key, id, id))));
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(5);
        for (const r of results) if (r.status === 'rejected') expect(r.reason).toBeInstanceOf(ArchiveVaultError);
        const same = archiveId(key, 'race:0');
        await vault.remove();
        // Twelve simultaneous uploads of one new id: one archive, one object, exact byte count.
        const puts = await Promise.all(Array.from({ length: 12 }, () => vault.put(same, sealArchive(key, same, 'mismo'))));
        expect(puts.filter((p) => p.created)).toHaveLength(1);
        const usage = await vault.usage();
        expect(usage.archives).toBe(1);
        expect(usage.bytes).toBe((await vault.listAll())[0]!.size);
        expect(await keysOf(b.objects)).toHaveLength(1);
        await vault.remove();
      } finally {
        await api.close();
      }
    });
  });
}
