/**
 * SEC-06 (IR-2026-09-15): a sealed mirror payload names its event id. Moved to another row it no longer
 * authenticates. Payloads sealed before (without AAD) are still read, but only in their own row, and an
 * existing mirror re-seals them.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes, finalizeEvent, generateSecretKey, getPublicKey, randomBytes, toUnsigned, utf8ToBytes, type NostrEvent } from '@sedecim/nostr-core';
import { createPgPool, migrate, resetScope, type Pool } from '@sedecim/service-kit';
import { PgEventRepository, plainCodec, SEAL_VERSION, sealedCodec } from '../src/index';

const key = new Uint8Array(32).fill(7);
const codec = sealedCodec(key);
const sk = generateSecretKey();
const note = (content: string) => finalizeEvent(toUnsigned({ kind: 9, content, tags: [['h', 'general']], created_at: Math.floor(Date.now() / 1000) }, getPublicKey(sk)), sk);
/** The format written before SEC-06: nonce || XChaCha20-Poly1305 without AAD. */
const legacySeal = (evt: NostrEvent) => {
  const nonce = randomBytes(24);
  return concatBytes(nonce, xchacha20poly1305(key, nonce).encrypt(utf8ToBytes(JSON.stringify(evt))));
};

describe('sealed mirror payloads (SEC-06)', () => {
  const [a, b] = [note('alpha'), note('beta')];

  it('name their event id: in another row they do not authenticate', () => {
    const sealed = codec.encode(a);
    expect(sealed.sealVersion).toBe(SEAL_VERSION);
    expect(codec.decode(sealed, a.id)).toEqual(a);
    expect(() => codec.decode(sealed, b.id)).toThrow(/invalid tag/);
  });

  it('cannot be read as the format without AAD, nor under a version this code does not know', () => {
    const sealed = codec.encode(a);
    expect(() => codec.decode({ encrypted: sealed.encrypted }, a.id)).toThrow(/invalid tag/);
    expect(() => codec.decode({ ...sealed, sealVersion: 3 }, a.id)).toThrow(/unknown seal version 3/);
  });

  it('sealed before SEC-06 are read in their own row and refused in any other', () => {
    const legacy = { encrypted: legacySeal(a) };
    expect(codec.decode(legacy, a.id)).toEqual(a);
    expect(() => codec.decode(legacy, b.id)).toThrow(/holds another event/);
  });

  it('plain rows follow the same rule', () => {
    expect(plainCodec.decode({ raw: a }, a.id)).toEqual(a);
    expect(() => plainCodec.decode({ raw: a }, b.id)).toThrow(/holds another event/);
    expect(() => codec.decode({ raw: a }, b.id)).toThrow(/holds another event/);
  });
});

const PG = process.env.TEST_DATABASE_URL;
(PG ? describe : describe.skip)('sealed mirror in Postgres (SEC-06)', () => {
  const migrations = fileURLToPath(new URL('../migrations', import.meta.url));
  const pools: Pool[] = [];
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end()));
  });
  /** A pool on its own schema, so this file does not share the events table with the other suites. */
  const schemaPool = async (schema: string) => {
    const admin = createPgPool(PG!);
    await admin.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
    await admin.end();
    const pool = createPgPool(`${PG}${PG!.includes('?') ? '&' : '?'}options=${encodeURIComponent(`-c search_path=${schema}`)}`);
    pools.push(pool);
    await resetScope(pool, 'indexer', ['read_cursors', 'event_sources', 'events', 'events_superseded', 'indexer_checkpoints', 'indexer_jobs', 'indexer_replicas', 'moderation_deletions']);
    return pool;
  };
  const payloadOf = async (pool: Pool, id: string) => (await pool.query<{ encrypted_payload: Buffer }>('SELECT encrypted_payload FROM events WHERE event_id = $1', [id])).rows[0]!.encrypted_payload;
  const setPayload = (pool: Pool, id: string, payload: Buffer) => pool.query('UPDATE events SET encrypted_payload = $2 WHERE event_id = $1', [id, payload]);

  it('a payload moved to another row fails to authenticate, and reads again once put back', async () => {
    const pool = await schemaPool('sec06_swap');
    await migrate(pool, migrations, 'indexer');
    const repo = new PgEventRepository(pool, codec);
    const [a, b] = [note('uno'), note('dos')];
    await repo.upsert(a, 'ws://relay');
    await repo.upsert(b, 'ws://relay');
    const [pa, pb] = [await payloadOf(pool, a.id), await payloadOf(pool, b.id)];
    await setPayload(pool, b.id, pa);
    await expect(repo.get(b.id)).rejects.toThrow(/invalid tag/);
    await setPayload(pool, b.id, pb);
    expect((await repo.get(b.id))!.event).toEqual(b);
  });

  it('an existing mirror upgrades: rows sealed before read as they were and are re-sealed bound to their id', async () => {
    // A mirror on migrations 001-004, with rows in the format written before SEC-06.
    const pool = await schemaPool('sec06_upgrade');
    const before = mkdtempSync(join(tmpdir(), 'indexer-migrations-'));
    for (const f of ['001_events.sql', '002_read_cursors.sql', '003_sharding.sql', '004_moderation.sql']) copyFileSync(join(migrations, f), join(before, f));
    await migrate(pool, before, 'indexer');
    const insert = (e: NostrEvent, payload: Uint8Array) =>
      pool.query(`INSERT INTO events (event_id, pubkey, kind, created_at, encrypted_payload, h_tag, sensitivity_class) VALUES ($1, $2, $3, $4, $5, 'general', 'channel')`, [e.id, e.pubkey, e.kind, e.created_at, Buffer.from(payload)]);
    const rows = [note('uno'), note('dos'), note('tres')];
    for (const e of rows) await insert(e, legacySeal(e));
    // Someone with write access to the database moved a payload into another row.
    const tampered = note('cuatro');
    await insert(tampered, legacySeal(rows[0]!));

    expect(await migrate(pool, migrations, 'indexer')).toEqual(['005_seal_version.sql', '006_superseded.sql']);
    const repo = new PgEventRepository(pool, codec);
    for (const e of rows) expect((await repo.get(e.id))!.event).toEqual(e);
    await expect(repo.get(tampered.id)).rejects.toThrow(/holds another event/);

    // Batches of two: the paging goes past the row it cannot re-seal.
    expect(await repo.resealLegacy(2)).toEqual({ resealed: 3, failed: 1 });
    const { rows: versions } = await pool.query<{ event_id: string; seal_version: number | null }>('SELECT event_id, seal_version FROM events');
    expect(versions.filter((v) => v.seal_version === SEAL_VERSION).map((v) => v.event_id).sort()).toEqual(rows.map((e) => e.id).sort());
    expect(versions.find((v) => v.event_id === tampered.id)!.seal_version).toBeNull();
    for (const e of rows) expect((await repo.get(e.id))!.event).toEqual(e);
    await expect(repo.get(tampered.id)).rejects.toThrow(/holds another event/);
    // Nothing left for another replica, or for the next start; the tampered row is reported again.
    expect(await repo.resealLegacy()).toEqual({ resealed: 0, failed: 1 });

    // Once re-sealed, a moved payload no longer authenticates.
    const [r0, r1] = rows as [NostrEvent, NostrEvent];
    await setPayload(pool, r1.id, await payloadOf(pool, r0.id));
    await expect(repo.get(r1.id)).rejects.toThrow(/invalid tag/);
  });

  it('a plain mirror has nothing to re-seal', async () => {
    const pool = await schemaPool('sec06_plain');
    await migrate(pool, migrations, 'indexer');
    const repo = new PgEventRepository(pool, plainCodec);
    await repo.upsert(note('uno'), 'ws://relay');
    expect(await repo.resealLegacy()).toEqual({ resealed: 0, failed: 0 });
  });
});
