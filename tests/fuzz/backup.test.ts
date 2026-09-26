/**
 * SEC-03: key backup parsers — parseKeyBackup (FR002-03 files) and the cloud vault's envelope validator
 * (FR027-03) on random and near-valid JSON: they return or throw their own error type, and the
 * validator never accepts a text that carries a plaintext key.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { bytesToHex, getPublicKey, nip19, nip49, npubEncode } from '@sedecim/nostr-core';
import { BackupEnvelopeError, KeyBackupError, parseKeyBackup, validateBackupEnvelope } from '@sedecim/identity';
import { runs, secretKey } from './arbitraries';

const NCRYPTSEC = nip49.encryptKey(new Uint8Array(32).fill(9), 'pw', 1);
const field = <T>(a: fc.Arbitrary<T>) => fc.oneof(a, fc.jsonValue());
/** JSON objects close to the accepted formats, with fields swapped for arbitrary JSON. */
const nearBackup = fc.record(
  {
    format: field(fc.constantFrom('sedecim-offline-key', 'acceso-nostr-key-backup', 'sedecim-identity-backup')),
    version: field(fc.constantFrom(1, 2)),
    npub: field(fc.constantFrom(npubEncode('a'.repeat(64)), 'npub1', nip19.noteEncode('b'.repeat(64)))),
    ncryptsec: field(fc.constantFrom(NCRYPTSEC, NCRYPTSEC.slice(0, -1), 'ncryptsec1')),
    contentKey: field(fc.constant(NCRYPTSEC)),
    sealed: field(fc.base64String({ minLength: 56, maxLength: 120 })),
    createdAt: field(fc.integer({ min: 0 })),
    kdf: fc.jsonValue(),
  },
  { requiredKeys: [] },
);
const input = fc.oneof(nearBackup, fc.jsonValue(), fc.string({ maxLength: 200 }), nearBackup.map((o) => JSON.stringify(o)));

describe('backup parsers (fuzz)', () => {
  it('parseKeyBackup returns or throws KeyBackupError on any input', () => {
    fc.assert(
      fc.property(input, (v) => {
        try {
          const r = parseKeyBackup(v);
          expect(r.npub).toBe(npubEncode(r.pubkey));
        } catch (e) {
          expect(e).toBeInstanceOf(KeyBackupError);
        }
      }),
      runs(500),
    );
  });

  it('regression: objects that break String() still yield KeyBackupError', () => {
    for (const v of [{ format: 'sedecim-offline-key', version: { toString: 0 } }, { format: { toString: 0 } }, { format: 'acceso-nostr-key-backup', version: Object.create(null) }]) expect(() => parseKeyBackup(v)).toThrow(KeyBackupError);
  });

  it('validateBackupEnvelope returns or throws BackupEnvelopeError on any JSON text', () => {
    fc.assert(
      fc.property(input, (v) => {
        const t = typeof v === 'string' ? v : JSON.stringify(v) ?? 'null';
        try {
          const r = validateBackupEnvelope(t);
          expect(['sedecim-identity-backup', 'acceso-nostr-key-backup']).toContain(r.format);
        } catch (e) {
          expect(e).toBeInstanceOf(BackupEnvelopeError);
        }
      }),
      runs(500),
    );
  });

  it('never accepts an envelope that carries a plaintext key anywhere', () => {
    const envelope = (sk: Uint8Array) =>
      fc.constantFrom<Record<string, unknown>>(
        { format: 'acceso-nostr-key-backup', version: 1, npub: npubEncode(getPublicKey(sk)), ncryptsec: NCRYPTSEC },
        { format: 'sedecim-identity-backup', version: 2, contentKey: NCRYPTSEC, sealed: Buffer.alloc(64, 1).toString('base64'), createdAt: 1 },
      );
    fc.assert(
      fc.property(
        secretKey().chain((sk) => fc.tuple(fc.constant(sk), envelope(sk), fc.constantFrom('nsec', 'hex', 'HEX'), fc.string({ maxLength: 10 }), fc.constantFrom('field', 'value', 'suffix'))),
        ([sk, env, enc, junk, where]) => {
          const secret = enc === 'nsec' ? nip19.nsecEncode(sk) : enc === 'hex' ? bytesToHex(sk) : bytesToHex(sk).toUpperCase();
          const o = { ...env };
          if (where === 'field') o[`x${junk}`] = secret;
          else if (where === 'value') o[Object.keys(o).find((k) => typeof o[k] === 'string' && k !== 'format')!] = `${junk}${secret}`;
          const text = where === 'suffix' ? `${JSON.stringify(o)} ${secret}` : JSON.stringify(o);
          // Rejected by the plaintext scan itself, not by a later structural check.
          expect(() => validateBackupEnvelope(text)).toThrow(/plaintext|hex value/);
        },
      ),
      runs(200),
    );
  });
});
