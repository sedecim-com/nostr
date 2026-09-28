import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes, finalizeEvent, generateSecretKey, getPublicKey, randomBytes, toUnsigned, utf8ToBytes, type NostrEvent } from '@sedecim/nostr-core';
import { createPgPool, migrate, resetScope } from '@sedecim/service-kit';
import { PgEventRepository, plainCodec, sealedCodec, SEAL_VERSION } from '../src/index';

// IR-2026-09-15: a sealed payload is bound to the row (event id) it was written for.
const key = new Uint8Array(32).fill(7);
const note = (content: string): NostrEvent => {
  const sk = generateSecretKey();
  return finalizeEvent(toUnsigned({ kind: 1, content, created_at: Math.floor(Date.now() / 1000) }, getPublicKey(sk)), sk);
};
/** Payload as written before IR-2026-09-15: nonce || XChaCha20-Poly1305 without AAD. */
const legacySeal = (evt: NostrEvent) => {
  const nonce = randomBytes(24);
  return concatBytes(nonce, xchacha20poly1305(key, nonce).encrypt(utf8ToBytes(JSON.stringify(evt))));
};

describe('sealed codec', () => {
  const codec = sealedCodec(key);

  it('round-trips and binds the event id as AAD', () => {
    const a = note('a');
    const stored = codec.encode(a);
    expect(stored.sealVersion).toBe(SEAL_VERSION);
    expect(codec.decode(stored, a.id)).toEqual(a);
    expect(() => codec.decode(stored, note('b').id)).toThrow();
  });

  it('rejects a legacy payload moved to another row and accepts it in its own', () => {
    const a = note('a');
    const legacy = { encrypted: legacySeal(a), sealVersion: null };
    expect(codec.decode(legacy, a.id)).toEqual(a);
    expect(() => codec.decode(legacy, note('b').id)).toThrow('does not match its row');
    // A legacy payload relabelled as v1 fails authentication.
    expect(() => codec.decode({ ...legacy, sealVersion: SEAL_VERSION }, a.id)).toThrow();
  });

  it('checks the id of plain rows too', () => {
    const a = note('a');
    expect(plainCodec.decode({ raw: a }, a.id)).toEqual(a);
    expect(() => plainCodec.decode({ raw: a }, note('b').id)).toThrow('does not match its row');
  });
});

const PG = process.env.TEST_DATABASE_URL;
(PG ? describe : describe.skip)('legacy sealed rows (postgres)', () => {
  it('reseals legacy rows and leaves swapped payloads unreadable', async () => {
    const pool = createPgPool(PG!);
    await resetScope(pool, 'indexer', ['read_cursors', 'event_sources', 'events', 'indexer_checkpoints', 'indexer_jobs', 'indexer_replicas']);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
    const repo = new PgEventRepository(pool, sealedCodec(key));
    const [a, b, c] = [note('a'), note('b'), note('c')];
    for (const e of [a, b, c]) await repo.upsert(e, 'ws://r');
    // Rewrite them as pre-IR-2026-09-15 rows, then swap the payloads of a and b.
    for (const e of [a, b, c]) await pool.query('UPDATE events SET encrypted_payload = $2, seal_version = NULL WHERE event_id = $1', [e.id, Buffer.from(legacySeal(e))]);
    const pa = legacySeal(a);
    const pb = legacySeal(b);
    await pool.query('UPDATE events SET encrypted_payload = $2 WHERE event_id = $1', [a.id, Buffer.from(pb)]);
    await pool.query('UPDATE events SET encrypted_payload = $2 WHERE event_id = $1', [b.id, Buffer.from(pa)]);
    await expect(repo.get(a.id)).rejects.toThrow('does not match its row');

    let res = await repo.resealLegacy('', 2);
    let upgraded = res.upgraded;
    let failed = res.failed;
    while (res.last) {
      res = await repo.resealLegacy(res.last, 2);
      upgraded += res.upgraded;
      failed += res.failed;
    }
    expect({ upgraded, failed }).toEqual({ upgraded: 1, failed: 2 });
    expect((await repo.get(c.id))?.event).toEqual(c);
    const { rows } = await pool.query<{ event_id: string; seal_version: number | null }>('SELECT event_id, seal_version FROM events ORDER BY event_id');
    expect(Object.fromEntries(rows.map((r) => [r.event_id, r.seal_version]))).toEqual({ [a.id]: null, [b.id]: null, [c.id]: SEAL_VERSION });
    await expect(repo.get(b.id)).rejects.toThrow();
    await pool.end();
  });
});
