import { describe, expect, it } from 'vitest';
import { base64 } from '@scure/base';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, isValidSecretKey, nip19, randomBytes, toUnsigned, utf8ToBytes } from '@sedecim/nostr-core';
import {
  ARCHIVE_MIN_PADDED,
  ArchiveEnvelopeError,
  ArchiveKeyMismatchError,
  archiveAuthKey,
  archiveId,
  archiveKeyId,
  archiveOwnerPubkey,
  assertDistinctFromNsec,
  generateArchiveKey,
  openArchive,
  openArchiveText,
  paddedLength,
  parseArchiveEnvelope,
  sealArchive,
  validateArchiveEnvelope,
} from '../src/index';

const key = generateArchiveKey();
const id = archiveId(key, 'ledger');

describe('archive keys (VAULT-02)', () => {
  it('derives independent, stable values from one random key', () => {
    expect(key).toHaveLength(32);
    expect(archiveKeyId(key)).toMatch(/^[0-9a-f]{16}$/);
    expect(archiveKeyId(key)).toBe(archiveKeyId(new Uint8Array(key)));
    expect(archiveId(key, 'ledger')).toMatch(/^[0-9a-f]{64}$/);
    expect(archiveId(key, 'ledger')).toBe(id);
    expect(archiveId(key, 'event:1')).not.toBe(id);
    expect(archiveId(generateArchiveKey(), 'ledger')).not.toBe(id);
    const auth = archiveAuthKey(key);
    expect(isValidSecretKey(auth)).toBe(true);
    expect(bytesToHex(auth)).not.toBe(bytesToHex(key));
    expect(archiveOwnerPubkey(key)).toBe(getPublicKey(auth));
    expect(archiveOwnerPubkey(generateArchiveKey())).not.toBe(archiveOwnerPubkey(key));
  });

  it('never accepts the nsec as the archive key', () => {
    const sk = generateSecretKey();
    expect(() => assertDistinctFromNsec(new Uint8Array(sk), sk)).toThrow(/must not be the nsec/);
    expect(() => assertDistinctFromNsec(key, sk)).not.toThrow();
    expect(() => archiveKeyId(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe('padding', () => {
  it('pads to a 256-byte floor, then with at most 12.5 % overhead, and is a fixed point', () => {
    let prev = 0;
    for (const n of [0, 1, 255, 256, 257, 300, 320, 321, 511, 512, 513, 1000, 4096, 70_000, 1_000_000]) {
      const p = paddedLength(n);
      expect(p).toBeGreaterThanOrEqual(Math.max(n, ARCHIVE_MIN_PADDED));
      expect(p).toBeGreaterThanOrEqual(prev);
      if (n > ARCHIVE_MIN_PADDED) expect(p / n).toBeLessThanOrEqual(1.25);
      expect(paddedLength(p)).toBe(p);
      prev = p;
    }
    expect(paddedLength(257)).toBe(320);
    expect(paddedLength(576)).toBe(640);
    expect(() => paddedLength(-1)).toThrow();
  });
});

describe('seal and open', () => {
  it('round-trips any size, with a random nonce each time and a padded length', () => {
    for (const n of [0, 1, 255, 256, 257, 1000, 70_000]) {
      // getRandomValues gives at most 64 KiB per call.
      const data = new Uint8Array(n);
      for (let i = 0; i < n; i += 65_536) data.set(randomBytes(Math.min(65_536, n - i)), i);
      const env = sealArchive(key, id, data);
      expect(env).toMatchObject({ format: 'sedecim-archive-envelope', version: 1, key_id: archiveKeyId(key) });
      const { sealed } = parseArchiveEnvelope(JSON.stringify(env));
      expect(paddedLength(sealed.length - 24 - 16 - 4)).toBe(sealed.length - 24 - 16 - 4);
      expect(openArchive(key, id, env)).toEqual(data);
    }
    const a = sealArchive(key, id, 'hola');
    const b = sealArchive(key, id, 'hola');
    expect(a.sealed).not.toBe(b.sealed);
    expect(openArchiveText(key, id, JSON.stringify(b))).toBe('hola');
    // Short texts of different lengths look the same size.
    expect(sealArchive(key, id, 'sí').sealed.length).toBe(sealArchive(key, id, 'x'.repeat(250)).sealed.length);
  });

  it('refuses another key, another id and any altered byte', () => {
    const env = sealArchive(key, id, 'mensaje');
    expect(() => openArchive(generateArchiveKey(), id, env)).toThrow(ArchiveKeyMismatchError);
    // The vault serving one archive in place of another is detected (the id is in the AAD).
    expect(() => openArchive(key, archiveId(key, 'event:otro'), env)).toThrow(/does not authenticate/);
    const raw = base64.decode(env.sealed);
    for (const at of [0, 23, 24, 40, raw.length - 1]) {
      const bad = new Uint8Array(raw);
      bad[at]! ^= 0x01;
      expect(() => openArchive(key, id, { ...env, sealed: base64.encode(bad) })).toThrow(ArchiveEnvelopeError);
    }
    // A key_id rewritten to the other key's does not help an attacker either.
    const other = generateArchiveKey();
    expect(() => openArchive(other, id, { ...env, key_id: archiveKeyId(other) })).toThrow(/does not authenticate/);
    expect(() => sealArchive(key, 'ledger', 'x')).toThrow(/64 hex/);
  });
});

describe('validateArchiveEnvelope: only sealed envelopes (VAULT-01)', () => {
  const sk = generateSecretKey();
  const event = finalizeEvent(toUnsigned({ kind: 14, content: 'nos vemos a las 9 en la plaza', tags: [['p', getPublicKey(generateSecretKey())]] }, getPublicKey(sk)), sk);
  const good = sealArchive(key, id, JSON.stringify(event));
  const b64 = (text: string) => base64.encode(utf8ToBytes(text));
  // Plaintext shaped so the only thing wrong is that it is readable: a nonce and exactly a valid v1 length.
  const encodedPlaintext = (text: string) => {
    const body = new Uint8Array(4 + ARCHIVE_MIN_PADDED + 16).fill(0x20);
    body.set(utf8ToBytes(text).subarray(0, body.length));
    return base64.encode(new Uint8Array([...randomBytes(24), ...body]));
  };

  it('accepts what sealArchive produces (2 000 random seals)', () => {
    expect(validateArchiveEnvelope(JSON.stringify(good))).toEqual({ keyId: archiveKeyId(key), size: JSON.stringify(good).length });
    for (let i = 0; i < 2000; i++) validateArchiveEnvelope(JSON.stringify(sealArchive(key, id, randomBytes(i % 700))));
  });

  it.each([
    ['a signed event in clear', JSON.stringify(event), /32-byte hex/],
    ['a signed event without hex fields', JSON.stringify({ kind: event.kind, content: event.content }), /format/],
    ['JSON that is not an envelope', JSON.stringify({ messages: ['hola'] }), /format/],
    ['an array', JSON.stringify([good]), /JSON object/],
    ['not JSON', 'hola', /not valid JSON/],
    ['an extra field', JSON.stringify({ ...good, label: 'dm-con-ana' }), /not allowed/],
    ['another version', JSON.stringify({ ...good, version: 2 }), /version/],
    ['a bad key_id', JSON.stringify({ ...good, key_id: 'ana' }), /key_id/],
    ['sealed that is not base64', JSON.stringify({ ...good, sealed: 'hola mundo' }), /base64/],
    ['sealed too short', JSON.stringify({ ...good, sealed: base64.encode(randomBytes(120)) }), /too short/],
    ['an unpadded ciphertext', JSON.stringify({ ...good, sealed: base64.encode(randomBytes(24 + 4 + 300 + 16)) }), /not padded/],
    ['base64 of an ASCII text', JSON.stringify({ ...good, sealed: encodedPlaintext(JSON.stringify(event)) }), /plaintext/],
    ['base64 of a UTF-8 text', JSON.stringify({ ...good, sealed: encodedPlaintext('我们九点在广场见面。'.repeat(12)) }), /plaintext/],
    ['base64 of a short text', JSON.stringify({ ...good, sealed: b64('hola') }), /too short/],
    ['a plaintext nsec', JSON.stringify({ ...good, sealed: good.sealed, note: nip19.nsecEncode(sk) }), /nsec/],
    ['an event id or hex key', JSON.stringify({ ...good, id: event.id }), /hex/],
  ])('rejects %s', (_name, text, reason) => {
    expect(() => validateArchiveEnvelope(text)).toThrow(reason);
  });

  it('enforces the size limit and never echoes the content', () => {
    const text = JSON.stringify(sealArchive(key, id, randomBytes(4000)));
    expect(() => validateArchiveEnvelope(text, 1000)).toThrow(/too large/);
    let message = '';
    try {
      validateArchiveEnvelope(JSON.stringify({ ...good, sealed: encodedPlaintext('secreto-muy-visible') }));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/plaintext/);
    expect(message).not.toContain('secreto');
  });
});
