import { describe, expect, it } from 'vitest';
import { constants, createDecipheriv, createHash, generateKeyPairSync, privateDecrypt, randomBytes } from 'node:crypto';
import { accesoOwner, checkEnclaveTrust, envelopeAad, EnvelopeError, fromBase64Url, MAX_ENVELOPE_CHARS, ownerTag, sealToEnclave, toBase64Url } from '../src/index';

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = new Uint8Array(rsa.publicKey.export({ type: 'spki', format: 'der' }));
const TAG = ownerTag('https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST#ana');
const PUBKEY = 'a'.repeat(64);
const pcr = (c: string) => c.repeat(96);
const jwt = (claims: Record<string, unknown>) => `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.c2ln`;

describe('sealing a secret to the enclave, in the client', () => {
  it('FR005-10: the envelope is what the format says: RSA-OAEP-SHA256 of an AES-256-GCM key, the purpose, owner and key in the AAD', async () => {
    const at = Date.now();
    const envelope = await sealToEnclave(spki, { purpose: 'export', ownerTag: TAG, pubkey: PUBKEY, at, password: 'una contraseña larga' });
    const [version, ek, iv, ct] = envelope.split('.') as [string, string, string, string];
    expect(version).toBe('ae1');
    // Opened with node:crypto and nothing of this package but the AAD text, spelled out here.
    const key = privateDecrypt({ key: rsa.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(ek, 'base64url'));
    expect(key).toHaveLength(32);
    const body = Buffer.from(ct, 'base64url');
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'), { authTagLength: 16 });
    d.setAAD(Buffer.from(`acceso-nostr/enclave-envelope/v1|export|${TAG}|${PUBKEY}`));
    d.setAuthTag(body.subarray(body.length - 16));
    expect(JSON.parse(Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]).toString('utf8'))).toEqual({ password: 'una contraseña larga', at });
    expect(Buffer.from(envelopeAad('import', TAG)).toString()).toBe(`acceso-nostr/enclave-envelope/v1|import|${TAG}|`);
    // Every envelope has its own AES key and IV.
    const again = await sealToEnclave(spki, { purpose: 'export', ownerTag: TAG, pubkey: PUBKEY, at, password: 'una contraseña larga' });
    expect(again.split('.')[2]).not.toBe(iv);
  });

  it('FR005-10: the owner tag is the SHA-256 the enclave seals keys with', () => {
    const owner = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST#ana';
    expect(ownerTag(owner)).toBe(createHash('sha256').update(`acceso-nostr/owner/v1|${owner}`).digest('hex'));
  });

  it('FR005-10: refuses what it cannot seal properly: a secret too large, no attestation time, a short RSA key, a bad owner tag or pubkey', async () => {
    await expect(sealToEnclave(spki, { purpose: 'import', ownerTag: TAG, at: Date.now(), ncryptsec: 'ncryptsec1x', password: 'x'.repeat(MAX_ENVELOPE_CHARS) })).rejects.toThrow(/too large/);
    for (const at of [0, -1, 1.5, Number.NaN]) await expect(sealToEnclave(spki, { purpose: 'import', ownerTag: TAG, at, ncryptsec: 'n', password: 'p' })).rejects.toThrow(EnvelopeError);
    const short = new Uint8Array(generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'der' }));
    await expect(sealToEnclave(short, { purpose: 'import', ownerTag: TAG, at: Date.now(), ncryptsec: 'n', password: 'p' })).rejects.toThrow(/2048 bits/);
    await expect(sealToEnclave(spki, { purpose: 'import', ownerTag: 'ana', at: Date.now(), ncryptsec: 'n', password: 'p' })).rejects.toThrow(/owner tag/);
    await expect(sealToEnclave(spki, { purpose: 'export', ownerTag: TAG, pubkey: 'npub1x', at: Date.now(), password: 'p' })).rejects.toThrow(/pubkey/);
  });

  it('FR005-10: base64url as Node writes it, read back strictly (no padding, no other alphabet, canonical only)', () => {
    for (let n = 0; n < 70; n++) {
      const b = randomBytes(n);
      expect(toBase64Url(b)).toBe(b.toString('base64url'));
      expect(Buffer.from(fromBase64Url(b.toString('base64url'))).equals(b)).toBe(true);
    }
    for (const bad of ['AAA=', 'AA+A', 'AA/A', 'A', 'AAAAA', 'AB', 'AAB']) expect(() => fromBase64Url(bad)).toThrow(EnvelopeError);
    expect(fromBase64Url('AA')).toEqual(new Uint8Array([0]));
  });

  it('FR005-10: trusts an enclave only by PCR0, PCR1 and PCR2 (PCR8 optional), 96 hex characters each', () => {
    const ok = { pcrs: { 0: pcr('a'), 1: pcr('b'), 2: pcr('C') } };
    expect(checkEnclaveTrust(ok)).toBe(ok);
    expect(checkEnclaveTrust({ pcrs: { ...ok.pcrs, 8: pcr('d') }, rootFingerprints: ['ab'.repeat(32)] }).pcrs[8]).toBe(pcr('d'));
    for (const bad of [{ pcrs: { 0: pcr('a'), 1: pcr('b') } }, { pcrs: { ...ok.pcrs, 2: '' } }, { pcrs: { ...ok.pcrs, 0: pcr('z') } }, { pcrs: { ...ok.pcrs, 1: 'ab'.repeat(47) } }, { pcrs: { ...ok.pcrs, 8: 'x' } }, { ...ok, rootFingerprints: [] }, {}]) {
      expect(() => checkEnclaveTrust(bad as never)).toThrow(/enclave trust/);
    }
  });

  it('FR005-10: names the owner as the managed-signer does, from the Acceso token, and refuses a device session', () => {
    expect(accesoOwner(jwt({ iss: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST', sub: 'ana', token_use: 'access' }))).toBe('https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST#ana');
    for (const t of [`sds_${'0'.repeat(64)}`, jwt({ sub: 'ana' }), jwt({ iss: 'x', sub: '' }), 'a.b.c', '']) expect(() => accesoOwner(t)).toThrow(/Acceso token/);
  });
});
