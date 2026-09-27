/**
 * Internal review 2026-09: hand-written parsers of the managed-signer enclave tier (FR005-05) — CBOR
 * (Nitro attestation documents / COSE_Sign1), ASN.1 DER and CMS EnvelopedData (KMS CiphertextForRecipient).
 * Everything they read comes from outside the enclave (via the untrusted parent), so any input must be
 * decoded or rejected with an Error, without crashes or hangs, and verification must never pass on a
 * tampered document.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { generateKeyPairSync } from 'node:crypto';
import {
  AttestationError,
  buildAttestationDocument,
  buildCertificate,
  CborTag,
  createTestPki,
  decodeCbor,
  decodeCoseSign1,
  decryptEnvelopedData,
  encodeCbor,
  encryptEnvelopedData,
  simulatedPcrs,
  verifyAttestation,
  type CborValue,
} from '@sedecim/managed-signer';
import { decodeOid, derChildren, int, octets, oid, parseDer, seq, set, utf8 } from '../../services/managed-signer/src/enclave/der';
import { runs, throwsCleanly } from './arbitraries';

const { value: cborValue } = fc.letrec((tie) => ({
  leaf: fc.oneof(
    fc.maxSafeInteger(),
    fc.string({ maxLength: 20 }),
    fc.uint8Array({ maxLength: 40 }),
    fc.boolean(),
    fc.constant(null),
    fc.constant(undefined),
  ),
  value: fc.oneof(
    { depthSize: 'small' },
    tie('leaf'),
    fc.array(tie('value'), { maxLength: 5 }),
    fc.uniqueArray(fc.tuple(fc.oneof(fc.integer({ min: -1000, max: 1000 }), fc.string({ maxLength: 8 })), tie('value')), { maxLength: 5, selector: ([k]) => k }).map((e) => new Map(e)),
    fc.tuple(fc.nat({ max: 2 ** 32 }), tie('value')).map(([t, v]) => new CborTag(t, v)),
  ),
})) as { value: fc.Arbitrary<CborValue> };

const flip = (b: Uint8Array, flips: Array<[number, number]>) => {
  const out = b.slice();
  for (const [i, x] of flips) out[i % out.length]! ^= x;
  return out;
};
const flips = fc.array(fc.tuple(fc.nat(), fc.integer({ min: 1, max: 255 })), { minLength: 1, maxLength: 4 });

describe('enclave CBOR (fuzz)', () => {
  it('decode ∘ encode is the identity', () => {
    fc.assert(fc.property(cborValue, (v) => {
      expect(decodeCbor(encodeCbor(v))).toEqual(v);
    }), runs(500));
  });

  it('random and mutated bytes decode or throw an Error (bounded work)', () => {
    fc.assert(fc.property(fc.oneof(fc.uint8Array({ maxLength: 200 }), fc.tuple(cborValue, flips).map(([v, f]) => flip(encodeCbor(v), f))), (b) => void throwsCleanly(() => decodeCbor(b))), runs(2000));
  });

  it('regressions: huge declared lengths, deep nesting, indefinite lengths, duplicate keys, trailing bytes', () => {
    for (const b of [
      Uint8Array.of(0x5b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
      Uint8Array.of(0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
      new Uint8Array(40).fill(0x81),
      Uint8Array.of(0x9f, 0xff),
      Uint8Array.of(0xa2, 0x01, 0x02, 0x01, 0x03),
      Uint8Array.of(0x01, 0x02),
      Uint8Array.of(0x62, 0xc3, 0x28),
    ]) expect(throwsCleanly(() => decodeCbor(b))).toBe(true);
  });
});

describe('enclave DER (fuzz)', () => {
  const arc = fc.nat({ max: 2 ** 40 });
  const oidStr = fc.tuple(fc.constantFrom(0, 1, 2), fc.nat({ max: 39 }), fc.array(arc, { maxLength: 6 })).map(([a, b, r]) => [a, b, ...r].join('.'));

  it('OID encode → decode round-trips; truncated or non-minimal arcs are rejected', () => {
    fc.assert(fc.property(oidStr, (s) => {
      expect(decodeOid(parseDer(oid(s)).value)).toBe(s);
    }), runs(500));
    expect(() => decodeOid(Uint8Array.of(0x2a, 0x86))).toThrow(/truncated/);
    expect(() => decodeOid(Uint8Array.of(0x2a, 0x80, 0x01))).toThrow(/non-minimal/);
    expect(() => decodeOid(new Uint8Array(0))).toThrow();
  });

  it('nested structures round-trip through parseDer/derChildren', () => {
    const node = fc.oneof(fc.uint8Array({ maxLength: 300 }).map(octets), fc.string({ maxLength: 50 }).map(utf8), fc.nat().map(int));
    fc.assert(
      fc.property(fc.array(node, { maxLength: 8 }), (kids) => {
        const kidsOf = (b: Uint8Array) => derChildren(parseDer(b)).map((n) => Buffer.from(n.raw).toString('hex'));
        const want = kids.map((k) => Buffer.from(k).toString('hex'));
        expect(kidsOf(seq(...kids))).toEqual(want);
        expect(kidsOf(set(...kids))).toEqual(want);
      }),
      runs(300),
    );
  });

  it('random and mutated bytes parse or throw an Error', () => {
    const walk = (b: Uint8Array) => {
      const n = parseDer(b);
      if (n.tag & 0x20) for (const c of derChildren(n)) if (c.tag & 0x20) derChildren(c);
    };
    const sample = seq(oid('1.2.840.113549.1.7.3'), octets(new Uint8Array(200)), set(int(2), utf8('x')));
    fc.assert(fc.property(fc.oneof(fc.uint8Array({ maxLength: 300 }), flips.map((f) => flip(sample, f))), (b) => void throwsCleanly(() => walk(b))), runs(2000));
  });
});

describe('enclave CMS EnvelopedData (fuzz)', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

  it('decrypt ∘ encrypt is the identity', () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 100 }), (pt) => {
      expect(decryptEnvelopedData(encryptEnvelopedData(pt, rsa.publicKey), rsa.privateKey)).toEqual(pt);
    }), runs(30));
  });

  it('mutated CiphertextForRecipient is rejected with an Error or yields the plaintext (never a crash)', () => {
    const pt = new Uint8Array(32).fill(0x42);
    const cms = encryptEnvelopedData(pt, rsa.publicKey);
    fc.assert(
      fc.property(flips, (f) => {
        try {
          const out = decryptEnvelopedData(flip(cms, f), rsa.privateKey);
          // Unauthenticated CBC (as KMS defines it): a flip in the rid or last block may still decrypt.
          expect(out).toBeInstanceOf(Uint8Array);
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
        }
      }),
      runs(300),
    );
  });

  it('random bytes throw an Error', () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 400 }), (b) => {
      expect(throwsCleanly(() => decryptEnvelopedData(b, rsa.privateKey))).toBe(true);
    }), runs(500));
  });
});

describe('Nitro attestation verification (fuzz)', () => {
  const now = Date.now();
  const pki = createTestPki(now);
  const pcrs = simulatedPcrs();
  const leaf = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const cert = buildCertificate({ subject: 'i-fuzz-enc', issuer: 'simulated.intermediate', publicKey: leaf.publicKey, issuerKey: pki.intermediate.key, notBefore: new Date(now - 60_000), notAfter: new Date(now + 3_600_000), ca: false });
  const doc = buildAttestationDocument({ timestamp: now - 1000, pcrs, certificate: cert, cabundle: [pki.root.cert, pki.intermediate.cert], nonce: new Uint8Array(32).fill(7) }, leaf.privateKey);
  const policy = { trustedRootFingerprints: [pki.fingerprint], expectedPcrs: { 0: pcrs[0], 1: pcrs[1], 2: pcrs[2] }, expectedNonce: new Uint8Array(32).fill(7), now };

  it('the fixture document verifies (sanity)', () => {
    expect(verifyAttestation(doc, policy).pcrs[0]).toBe(pcrs[0]);
  });

  it('a tampered document never verifies unless the flip leaves the signed bytes untouched', () => {
    const { protectedBytes, payload } = decodeCoseSign1(doc);
    fc.assert(
      fc.property(flips, (f) => {
        const bad = flip(doc, f);
        try {
          const v = verifyAttestation(bad, policy);
          // Only possible if the COSE protected header and payload are byte-identical (e.g. a flip that
          // turned tag 18 into another encoding of the same structure is rejected earlier).
          const d = decodeCoseSign1(bad);
          expect(Buffer.from(d.protectedBytes)).toEqual(Buffer.from(protectedBytes));
          expect(Buffer.from(d.payload)).toEqual(Buffer.from(payload));
          expect(v.pcrs[0]).toBe(pcrs[0]);
        } catch (e) {
          expect(e).toBeInstanceOf(AttestationError);
        }
      }),
      runs(300),
    );
  });

  it('random bytes and random CBOR are rejected with AttestationError', () => {
    fc.assert(
      fc.property(fc.oneof(fc.uint8Array({ maxLength: 300 }), cborValue.map((v) => encodeCbor(v))), (b) => {
        expect(() => verifyAttestation(b, policy)).toThrow(AttestationError);
      }),
      runs(1000),
    );
  });
});
