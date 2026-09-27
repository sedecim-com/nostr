import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import {
  AttestationError,
  buildAttestationDocument,
  buildCertificate,
  CborTag,
  createTestPki,
  decodeCbor,
  decryptEnvelopedData,
  encodeCbor,
  encryptEnvelopedData,
  NITRO_ROOT_G1_PEM,
  NITRO_ROOT_G1_SHA256,
  simulatedPcrs,
  verifyAttestation,
  type AttestationPolicy,
  type DocumentFields,
} from '../src/index';

const now = Date.now();
const pki = createTestPki(now);
const pcrs = simulatedPcrs();
const leaf = generateKeyPairSync('ec', { namedCurve: 'P-384' });
const leafCert = (o: { notAfter?: Date; issuerKey?: typeof pki.intermediate.key; issuer?: string } = {}) =>
  buildCertificate({
    subject: 'i-test-enc',
    issuer: o.issuer ?? 'simulated.intermediate',
    publicKey: leaf.publicKey,
    issuerKey: o.issuerKey ?? pki.intermediate.key,
    notBefore: new Date(now - 60_000),
    notAfter: o.notAfter ?? new Date(now + 3_600_000),
    ca: false,
  });
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = new Uint8Array(rsa.publicKey.export({ type: 'spki', format: 'der' }));
const nonce = new Uint8Array(32).fill(7);

const fields = (over: Partial<DocumentFields> = {}): DocumentFields => ({
  timestamp: now - 1000,
  pcrs,
  certificate: leafCert(),
  cabundle: [pki.root.cert, pki.intermediate.cert],
  publicKey: spki,
  nonce,
  ...over,
});
const policy = (over: Partial<AttestationPolicy> = {}): AttestationPolicy => ({
  trustedRootFingerprints: [pki.fingerprint],
  expectedPcrs: { 0: pcrs[0], 1: pcrs[1], 2: pcrs[2] },
  expectedNonce: nonce,
  requirePublicKey: true,
  now,
  ...over,
});
const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (err) {
    if (err instanceof AttestationError) return err.code;
    throw err;
  }
  return 'ok';
};

describe('CBOR codec', () => {
  it('round-trips the types used by COSE and attestation documents', () => {
    const v = new Map<unknown, unknown>([
      [1, -35],
      ['pcrs', new Map([[0, new Uint8Array(48)]])],
      ['big', 1_727_400_000_000],
      ['arr', [new Uint8Array([1, 2]), 'x', null, true, false]],
    ]);
    expect(decodeCbor(encodeCbor(v))).toEqual(v);
    const tagged = decodeCbor(encodeCbor(new CborTag(18, [1, 2])));
    expect(tagged).toBeInstanceOf(CborTag);
    expect((tagged as CborTag).value).toEqual([1, 2]);
  });

  it('rejects truncated input, trailing bytes and indefinite lengths', () => {
    expect(() => decodeCbor(Uint8Array.of(0x58, 10, 1))).toThrow(/truncated/);
    expect(() => decodeCbor(Uint8Array.of(0x01, 0x02))).toThrow(/trailing/);
    expect(() => decodeCbor(Uint8Array.of(0x9f, 0xff))).toThrow(/indefinite/);
  });
});

describe('AWS Nitro root pin', () => {
  it('the bundled root PEM matches the published SHA-256 fingerprint', () => {
    const root = new X509Certificate(NITRO_ROOT_G1_PEM);
    expect(createHash('sha256').update(root.raw).digest('hex')).toBe(NITRO_ROOT_G1_SHA256);
    expect(root.subject).toContain('CN=aws.nitro-enclaves');
    expect(root.ca).toBe(true);
    expect(root.verify(root.publicKey)).toBe(true);
  });

  it('documents chained to another root are rejected by default (no test root trusted)', () => {
    const doc = buildAttestationDocument(fields(), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, { now }))).toBe('untrusted-root');
  });
});

describe('verifyAttestation', () => {
  it('accepts a valid document and returns PCRs, public key and nonce', () => {
    const doc = buildAttestationDocument(fields({ userData: new Uint8Array([9]) }), leaf.privateKey);
    const att = verifyAttestation(doc, policy({ expectedPcrs: { 0: pcrs[0], 1: pcrs[1], 2: pcrs[2], 8: pcrs[8] } }));
    expect(att.pcrs[0]).toBe(pcrs[0]);
    expect(Buffer.from(att.publicKey!).equals(Buffer.from(spki))).toBe(true);
    expect(Buffer.from(att.nonce!).equals(Buffer.from(nonce))).toBe(true);
    expect(att.userData).toEqual(new Uint8Array([9]));
    expect(att.moduleId).toMatch(/^i-/);
  });

  it('accepts the COSE tag 18 form', () => {
    const doc = buildAttestationDocument(fields(), leaf.privateKey);
    const tagged = encodeCbor(new CborTag(18, decodeCbor(doc)));
    expect(code(() => verifyAttestation(tagged, policy()))).toBe('ok');
  });

  it('rejects a bad signature', () => {
    const doc = buildAttestationDocument(fields(), leaf.privateKey);
    const bad = new Uint8Array(doc);
    bad[bad.length - 5]! ^= 0x01; // inside the 96-byte signature (last member)
    expect(code(() => verifyAttestation(bad, policy()))).toBe('bad-signature');
  });

  it('rejects a payload signed by a key other than the leaf certificate', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    expect(code(() => verifyAttestation(buildAttestationDocument(fields(), other.privateKey), policy()))).toBe('bad-signature');
  });

  it('rejects a wrong PCR', () => {
    const doc = buildAttestationDocument(fields(), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy({ expectedPcrs: { 0: simulatedPcrs('other-image')[0] } })))).toBe('pcr-mismatch');
    expect(code(() => verifyAttestation(doc, policy({ expectedPcrs: { 8: 'ab'.repeat(48) } })))).toBe('pcr-mismatch');
  });

  it('rejects debug-mode enclaves (PCR0-2 zero) unless allowed', () => {
    const zero = '00'.repeat(48);
    const doc = buildAttestationDocument(fields({ pcrs: { 0: zero, 1: zero, 2: zero } }), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy({ expectedPcrs: {} })))).toBe('debug-enclave');
    expect(code(() => verifyAttestation(doc, policy({ expectedPcrs: {}, allowDebug: true })))).toBe('ok');
  });

  it('rejects an expired leaf certificate', () => {
    const doc = buildAttestationDocument(fields({ certificate: leafCert({ notAfter: new Date(now - 1000) }) }), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy()))).toBe('expired-certificate');
  });

  it('rejects stale and future documents', () => {
    expect(code(() => verifyAttestation(buildAttestationDocument(fields({ timestamp: now - 6 * 60_000 }), leaf.privateKey), policy()))).toBe('stale');
    expect(code(() => verifyAttestation(buildAttestationDocument(fields({ timestamp: now + 5 * 60_000 }), leaf.privateKey), policy()))).toBe('stale');
  });

  it('rejects a wrong or missing nonce', () => {
    const doc = buildAttestationDocument(fields(), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy({ expectedNonce: new Uint8Array(32).fill(8) })))).toBe('nonce-mismatch');
    const noNonce = buildAttestationDocument(fields({ nonce: undefined }), leaf.privateKey);
    expect(code(() => verifyAttestation(noNonce, policy()))).toBe('nonce-mismatch');
  });

  it('rejects an untrusted root', () => {
    const rogue = createTestPki(now);
    const cert = buildCertificate({ subject: 'i-test-enc', issuer: 'simulated.intermediate', publicKey: leaf.publicKey, issuerKey: rogue.intermediate.key, notBefore: new Date(now - 60_000), notAfter: new Date(now + 3_600_000), ca: false });
    const doc = buildAttestationDocument(fields({ certificate: cert, cabundle: [rogue.root.cert, rogue.intermediate.cert] }), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy()))).toBe('untrusted-root');
  });

  it('rejects a broken chain (leaf not issued by the bundled intermediate)', () => {
    const rogue = createTestPki(now);
    const doc = buildAttestationDocument(fields({ certificate: leafCert({ issuerKey: rogue.intermediate.key }) }), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy()))).toBe('bad-chain');
  });

  it('rejects a non-CA intermediate', () => {
    const k = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const notCa = buildCertificate({ subject: 'simulated.intermediate', issuer: 'simulated.nitro-enclaves', publicKey: k.publicKey, issuerKey: pki.root.key, notBefore: new Date(now - 60_000), notAfter: new Date(now + 3_600_000), ca: false });
    const doc = buildAttestationDocument(fields({ certificate: leafCert({ issuerKey: k.privateKey }), cabundle: [pki.root.cert, notCa] }), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy()))).toBe('bad-chain');
  });

  it('rejects other algorithms, digests and malformed input', () => {
    expect(code(() => verifyAttestation(buildAttestationDocument(fields(), leaf.privateKey, -7), policy()))).toBe('unsupported-algorithm');
    expect(code(() => verifyAttestation(buildAttestationDocument(fields({ digest: 'SHA256' }), leaf.privateKey), policy()))).toBe('unsupported-algorithm');
    expect(code(() => verifyAttestation(Uint8Array.of(0x01), policy()))).toBe('malformed');
    expect(code(() => verifyAttestation(encodeCbor([1, 2, 3]), policy()))).toBe('malformed');
  });

  it('requires the public key when asked (KMS Recipient flow)', () => {
    const doc = buildAttestationDocument(fields({ publicKey: undefined }), leaf.privateKey);
    expect(code(() => verifyAttestation(doc, policy()))).toBe('missing-public-key');
  });
});

describe('CMS EnvelopedData (CiphertextForRecipient)', () => {
  it('decrypts what is encrypted to the enclave RSA key, and nothing else', () => {
    const dk = new Uint8Array(32).fill(3);
    const cms = encryptEnvelopedData(dk, rsa.publicKey);
    expect(decryptEnvelopedData(cms, rsa.privateKey)).toEqual(dk);
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(() => decryptEnvelopedData(cms, other.privateKey)).toThrow();
    expect(() => decryptEnvelopedData(Uint8Array.of(0x30, 0x00), rsa.privateKey)).toThrow(/cms/);
  });
});
