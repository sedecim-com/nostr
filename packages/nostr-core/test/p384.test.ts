import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { sha384, verifyEcdsaP384 } from '../src/index';

/** Order of the P-384 group: s and n - s are both valid ECDSA signatures (OpenSSL signs either). */
const N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n;
const toBytes = (v: bigint, len = 48) => Uint8Array.from(Buffer.from(v.toString(16).padStart(len * 2, '0'), 'hex'));
const toBig = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString('hex')}`);

describe('verifyEcdsaP384', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const point = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })).subarray(-97);
  const msg = new TextEncoder().encode('documento de attestation');

  it('FR005-10: verifies what node:crypto signs with P-384 / SHA-384, in the X.509 (DER) and the COSE (r || s) forms', () => {
    const der = new Uint8Array(sign('sha384', msg, privateKey));
    const compact = new Uint8Array(sign('sha384', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
    expect(verifyEcdsaP384(der, msg, point, 'der')).toBe(true);
    expect(verifyEcdsaP384(compact, msg, point, 'compact')).toBe(true);
    expect(sha384(msg)).toHaveLength(48);
    // One form is not the other.
    expect(verifyEcdsaP384(der, msg, point, 'compact')).toBe(false);
    expect(verifyEcdsaP384(compact, msg, point, 'der')).toBe(false);
  });

  it('FR005-10: accepts high-S signatures, as OpenSSL does', () => {
    const compact = new Uint8Array(sign('sha384', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
    const flipped = new Uint8Array(96);
    flipped.set(compact.subarray(0, 48));
    flipped.set(toBytes(N - toBig(compact.subarray(48))), 48);
    expect(verifyEcdsaP384(flipped, msg, point, 'compact')).toBe(true);
  });

  it('FR005-10: another message, another key or a malformed input is false, never an exception', () => {
    const der = new Uint8Array(sign('sha384', msg, privateKey));
    const other = new Uint8Array(generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ type: 'spki', format: 'der' })).subarray(-97);
    expect(verifyEcdsaP384(der, new TextEncoder().encode('otro'), point, 'der')).toBe(false);
    expect(verifyEcdsaP384(der, msg, other, 'der')).toBe(false);
    const bent = der.slice();
    bent[bent.length - 1]! ^= 1;
    expect(verifyEcdsaP384(bent, msg, point, 'der')).toBe(false);
    for (const junk of [new Uint8Array(0), Uint8Array.of(0x30, 0x00), der.subarray(0, 20), new Uint8Array(200).fill(0x30)]) expect(verifyEcdsaP384(junk, msg, point, 'der')).toBe(false);
    expect(verifyEcdsaP384(new Uint8Array(95), msg, point, 'compact')).toBe(false);
    expect(verifyEcdsaP384(new Uint8Array(96), msg, point, 'compact')).toBe(false);
    expect(verifyEcdsaP384(der, msg, new Uint8Array(97).fill(4), 'der')).toBe(false);
    expect(verifyEcdsaP384(der, msg, new Uint8Array(0), 'der')).toBe(false);
  });
});
