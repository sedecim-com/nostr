/**
 * FR005-10: the browser checks the enclave's attestation itself, with the portable verifier of @sedecim/signer (no
 * node:*), before it seals a secret to the key in it. It must accept and reject what the backend's verifier
 * (node:crypto, X509Certificate) accepts and rejects, with the same error code: a matrix of documents and mutations
 * built with node:crypto (P-384, as the Nitro PKI) goes through both. Where the portable one is deliberately stricter,
 * the difference is spelled out below.
 */
import { describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject, X509Certificate } from 'node:crypto';
import { NITRO_ROOT_G1_SHA256 as PORTABLE_ROOT_SHA256, NitroAttestationError, verifyNitroAttestation, type NitroAttestationPolicy } from '@sedecim/signer';
import {
  AttestationError,
  buildAttestationDocument,
  buildCertificate,
  CborTag,
  coseSigStructure,
  createTestPki,
  decodeCbor,
  encodeCbor,
  NITRO_ROOT_G1_PEM,
  NITRO_ROOT_G1_SHA256,
  simulatedPcrs,
  verifyAttestation,
  type AttestationPolicy,
  type DocumentFields,
} from '../src/index';
import { bitString, bool, ctx, der, derChildren, int, octets, oid, parseDer, seq, set, TAG, time, utf8 } from '../src/enclave/der';

const now = Date.now();
const pki = createTestPki(now);
const pcrs = simulatedPcrs();
const ec = () => generateKeyPairSync('ec', { namedCurve: 'P-384' });
const leafKey = ec();
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = new Uint8Array(rsa.publicKey.export({ type: 'spki', format: 'der' }));
const nonce = new Uint8Array(32).fill(7);
const DAY = 86_400_000;

// --- certificates with every knob the chain rules look at

const ECDSA_SHA384 = seq(oid('1.2.840.10045.4.3.3'));
const name = (cn: string, printable = false) => seq(set(seq(oid('2.5.4.3'), printable ? der(0x13, new TextEncoder().encode(cn)) : utf8(cn))));
const ext = (id: string, critical: boolean, value: Uint8Array) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value));
const basicConstraints = (ca: boolean) => ext('2.5.29.19', true, ca ? seq(bool(true)) : seq());
/** keyUsage with the given bits (0 digitalSignature … 5 keyCertSign, 6 cRLSign). */
const keyUsage = (...bits: number[]) => ext('2.5.29.15', true, der(TAG.BIT_STRING, Uint8Array.of(1, bits.reduce((v, b) => v | (0x80 >> b), 0))));
const skid = (id: Uint8Array) => ext('2.5.29.14', false, octets(id));
const akid = (id: Uint8Array) => ext('2.5.29.35', false, seq(der(0x80, id)));

interface Cert {
  subject: string;
  issuer: string;
  publicKey: KeyObject;
  issuerKey: KeyObject;
  exts?: Uint8Array[];
  notBefore?: Date;
  notAfter?: Date;
  alg?: Uint8Array;
  tbsAlg?: Uint8Array;
  printableIssuer?: boolean;
  /** Issuer Name as DER, instead of a CN built from `issuer`. */
  issuerName?: Uint8Array;
}
function cert(o: Cert): Uint8Array {
  const alg = o.alg ?? ECDSA_SHA384;
  const serial = randomBytes(8);
  serial[0] = serial[0]! & 0x7f;
  const exts = o.exts ?? [];
  const tbs = seq(
    ctx(0, true, int(2)),
    int(serial),
    o.tbsAlg ?? alg,
    o.issuerName ?? name(o.issuer, o.printableIssuer),
    seq(time(o.notBefore ?? new Date(now - DAY)), time(o.notAfter ?? new Date(now + DAY))),
    name(o.subject),
    new Uint8Array(o.publicKey.export({ type: 'spki', format: 'der' })),
    ...(exts.length ? [ctx(3, true, seq(...exts))] : []),
  );
  return seq(tbs, alg, bitString(new Uint8Array(sign('sha384', tbs, o.issuerKey))));
}
const leafCert = (o: Partial<Cert> = {}) => cert({ subject: 'i-test-enc', issuer: 'simulated.intermediate', publicKey: leafKey.publicKey, issuerKey: pki.intermediate.key, exts: [basicConstraints(false)], ...o });
/** An intermediate under the test root and a leaf under it. */
const underRoot = (inter: Partial<Cert>, leaf: Partial<Cert> = {}) => {
  const k = ec();
  const interCert = cert({ subject: 'other.intermediate', issuer: 'simulated.nitro-enclaves', publicKey: k.publicKey, issuerKey: pki.root.key, exts: [basicConstraints(true)], ...inter });
  return { cabundle: [pki.root.cert, interCert], certificate: leafCert({ issuer: 'other.intermediate', issuerKey: k.privateKey, ...leaf }) };
};

const fields = (over: Partial<DocumentFields> = {}): DocumentFields => ({ timestamp: now - 1000, pcrs, certificate: leafCert(), cabundle: [pki.root.cert, pki.intermediate.cert], publicKey: spki, nonce, ...over });
const doc = (over: Partial<DocumentFields> = {}, key: KeyObject = leafKey.privateKey, alg?: number) => buildAttestationDocument(fields(over), key, alg);
const policy = (over: Partial<AttestationPolicy> = {}): AttestationPolicy => ({ trustedRootFingerprints: [pki.fingerprint], expectedPcrs: { 0: pcrs[0], 1: pcrs[1], 2: pcrs[2] }, expectedNonce: nonce, requirePublicKey: true, now, ...over });
/** Rebuilds a document from its COSE members, after changing some of them (the signature is kept unless given). */
const recose = (d: Uint8Array, change: (m: [Uint8Array, unknown, Uint8Array, Uint8Array]) => unknown[]) => encodeCbor(change(decodeCbor(d) as [Uint8Array, unknown, Uint8Array, Uint8Array]));
const withPayload = (d: Uint8Array, edit: (m: Map<unknown, unknown>) => void) =>
  recose(d, ([p, u, payload, s]) => {
    const m = decodeCbor(payload) as Map<unknown, unknown>;
    edit(m);
    return [p, u, encodeCbor(m), s];
  });
/** The same, signed again by the leaf: what an enclave whose NSM wrote such a payload would send. */
const resigned = (d: Uint8Array, edit: (m: Map<unknown, unknown>) => void) =>
  recose(d, ([p, u, payload]) => {
    const m = decodeCbor(payload) as Map<unknown, unknown>;
    edit(m);
    const body = encodeCbor(m);
    return [p, u, body, new Uint8Array(sign('sha384', coseSigStructure(p, body), { key: leafKey.privateKey, dsaEncoding: 'ieee-p1363' }))];
  });

type Outcome = { ok: true; value: Record<string, unknown> } | { ok: false; code: string; message: string };
const outcome = (fn: () => unknown): Outcome => {
  try {
    return { ok: true, value: fn() as Record<string, unknown> };
  } catch (err) {
    if (err instanceof AttestationError || err instanceof NitroAttestationError) return { ok: false, code: err.code, message: err.message };
    throw err;
  }
};
const hex = (b: unknown) => (b instanceof Uint8Array ? Buffer.from(b).toString('hex') : b);

/** Runs both verifiers; they must agree on the verdict, the code and, when they accept, on everything they return. */
function both(d: Uint8Array, p: AttestationPolicy = policy()) {
  const node = outcome(() => verifyAttestation(d, p));
  const portable = outcome(() => verifyNitroAttestation(d, p as NitroAttestationPolicy));
  if (node.ok && portable.ok) {
    const n = node.value;
    const q = portable.value;
    for (const k of ['moduleId', 'timestamp', 'digest', 'pcrs']) expect(q[k]).toEqual(n[k]);
    for (const k of ['publicKey', 'userData', 'nonce']) expect(hex(q[k])).toEqual(hex(n[k]));
    expect(hex(q.certificate)).toBe(hex(new Uint8Array((n.certificate as X509Certificate).raw)));
  }
  return { node: node.ok ? 'ok' : node.code, portable: portable.ok ? 'ok' : portable.code, message: portable.ok ? '' : portable.message };
}

const zero = '00'.repeat(48);
const other = simulatedPcrs('other-image');
const rogue = createTestPki(now);
const expiredRoot = (() => {
  const k = ec();
  const rootCert = cert({ subject: 'old.root', issuer: 'old.root', publicKey: k.publicKey, issuerKey: k.privateKey, exts: [basicConstraints(true)], notBefore: new Date(now - 30 * DAY), notAfter: new Date(now - DAY) });
  return { rootCert, key: k, fingerprint: createHash('sha256').update(rootCert).digest('hex') };
})();
const notSelfSigned = (() => {
  const k = ec();
  const rootCert = cert({ subject: 'fake.root', issuer: 'fake.root', publicKey: k.publicKey, issuerKey: ec().privateKey, exts: [basicConstraints(true)] });
  return { rootCert, key: k, fingerprint: createHash('sha256').update(rootCert).digest('hex') };
})();
const longChain = (() => {
  const [a, b, c] = [ec(), ec(), ec()];
  const regional = cert({ subject: 'us-east-1.aws.nitro-enclaves', issuer: 'simulated.nitro-enclaves', publicKey: a.publicKey, issuerKey: pki.root.key, exts: [basicConstraints(true), keyUsage(0, 5, 6)] });
  const zonal = cert({ subject: 'use1-az4.us-east-1.aws.nitro-enclaves', issuer: 'us-east-1.aws.nitro-enclaves', publicKey: b.publicKey, issuerKey: a.privateKey, exts: [basicConstraints(true), keyUsage(0, 5, 6)] });
  const instance = cert({ subject: 'i-0123.use1-az4.us-east-1.aws.nitro-enclaves', issuer: 'use1-az4.us-east-1.aws.nitro-enclaves', publicKey: c.publicKey, issuerKey: b.privateKey, exts: [basicConstraints(true), keyUsage(0, 5, 6), skid(Uint8Array.of(1, 2, 3))] });
  const leaf = cert({ subject: 'i-0123-enc0123', issuer: 'i-0123.use1-az4.us-east-1.aws.nitro-enclaves', publicKey: leafKey.publicKey, issuerKey: c.privateKey, exts: [basicConstraints(false), keyUsage(0), akid(Uint8Array.of(1, 2, 3))] });
  return { cabundle: [pki.root.cert, regional, zonal, instance], certificate: leaf };
})();
const flipLast = (b: Uint8Array) => {
  const out = b.slice();
  out[out.length - 1]! ^= 0x01;
  return out;
};
const withSkid = (() => {
  const k = ec();
  const interCert = cert({ subject: 'kid.intermediate', issuer: 'simulated.nitro-enclaves', publicKey: k.publicKey, issuerKey: pki.root.key, exts: [basicConstraints(true), skid(Uint8Array.of(9, 9, 9))] });
  const leaf = (id: Uint8Array) => leafCert({ issuer: 'kid.intermediate', issuerKey: k.privateKey, exts: [basicConstraints(false), akid(id)] });
  return { interCert, leaf };
})();

/** [what, document, policy, the code both must give]. */
const MATRIX: Array<[string, () => Uint8Array, AttestationPolicy, string]> = [
  ['a valid document', () => doc(), policy(), 'ok'],
  ['a valid document with user data, PCR8 expected', () => doc({ userData: new Uint8Array([9]) }), policy({ expectedPcrs: { 0: pcrs[0], 1: pcrs[1], 2: pcrs[2], 8: pcrs[8] } }), 'ok'],
  ['the COSE tag 18 form', () => encodeCbor(new CborTag(18, decodeCbor(doc()))), policy(), 'ok'],
  ['PCRs expected in upper case', () => doc(), policy({ expectedPcrs: { 0: pcrs[0]!.toUpperCase() } }), 'ok'],
  ['a chain of four certificates, like Nitro, with keyUsage and key identifiers', () => doc(longChain), policy(), 'ok'],
  ['a leaf issued by the root itself', () => doc({ cabundle: [pki.root.cert], certificate: leafCert({ issuer: 'simulated.nitro-enclaves', issuerKey: pki.root.key }) }), policy(), 'ok'],
  ['a leaf that is itself a CA', () => doc({ certificate: leafCert({ exts: [basicConstraints(true)] }) }), policy(), 'ok'],
  ['an intermediate CA whose keyUsage allows keyCertSign', () => doc(underRoot({ exts: [basicConstraints(true), keyUsage(0, 5, 6)] })), policy(), 'ok'],
  ['a leaf whose authority key id matches the intermediate', () => doc({ cabundle: [pki.root.cert, withSkid.interCert], certificate: withSkid.leaf(Uint8Array.of(9, 9, 9)) }), policy(), 'ok'],
  ['no public key when it is not required', () => doc({ publicKey: undefined }), policy({ requirePublicKey: false }), 'ok'],
  ['a debug-mode enclave where debug is allowed', () => doc({ pcrs: { 0: zero, 1: zero, 2: zero } }), policy({ expectedPcrs: {}, allowDebug: true }), 'ok'],
  ['a document exactly 5 minutes old', () => doc({ timestamp: now - 5 * 60_000 }), policy(), 'ok'],
  ['a document exactly 60 s ahead', () => doc({ timestamp: now + 60_000 }), policy(), 'ok'],
  // roots
  ['a chain to the AWS root by default (a test root is not it)', () => doc(), policy({ trustedRootFingerprints: undefined }), 'untrusted-root'],
  ['a chain to a rogue root', () => doc({ cabundle: [rogue.root.cert, rogue.intermediate.cert], certificate: leafCert({ issuerKey: rogue.intermediate.key }) }), policy(), 'untrusted-root'],
  ['the cabundle in the wrong order', () => doc({ cabundle: [pki.intermediate.cert, pki.root.cert] }), policy(), 'untrusted-root'],
  ['a pinned root that is not self-signed', () => doc({ cabundle: [notSelfSigned.rootCert], certificate: leafCert({ issuer: 'fake.root', issuerKey: notSelfSigned.key.privateKey }) }), policy({ trustedRootFingerprints: [notSelfSigned.fingerprint] }), 'bad-chain'],
  // chain
  ['a leaf issued by another intermediate key', () => doc({ certificate: leafCert({ issuerKey: rogue.intermediate.key }) }), policy(), 'bad-chain'],
  ['a leaf certificate as the intermediate (not a CA)', () => doc(underRoot({ exts: [basicConstraints(false)] })), policy(), 'bad-chain'],
  ['an intermediate without extensions', () => doc(underRoot({ exts: [] })), policy(), 'bad-chain'],
  ['an intermediate CA whose keyUsage lacks keyCertSign', () => doc(underRoot({ exts: [basicConstraints(true), keyUsage(0)] })), policy(), 'bad-chain'],
  ['an intermediate with basicConstraints twice', () => doc(underRoot({ exts: [basicConstraints(true), basicConstraints(true)] })), policy(), 'bad-chain'],
  ['an intermediate with a malformed basicConstraints', () => doc(underRoot({ exts: [ext('2.5.29.19', true, octets(Uint8Array.of(1)))] })), policy(), 'bad-chain'],
  ['an intermediate with a malformed keyUsage', () => doc(underRoot({ exts: [basicConstraints(true), ext('2.5.29.15', true, octets(Uint8Array.of(1)))] })), policy(), 'bad-chain'],
  ['a leaf with a malformed basicConstraints', () => doc(underRoot({}, { exts: [ext('2.5.29.19', true, octets(Uint8Array.of(1)))] })), policy(), 'bad-chain'],
  ['a leaf that names another issuer', () => doc({ certificate: leafCert({ issuer: 'someone.else' }) }), policy(), 'bad-chain'],
  ['a leaf whose authority key id is not the intermediate\'s', () => doc({ cabundle: [pki.root.cert, withSkid.interCert], certificate: withSkid.leaf(Uint8Array.of(1, 1, 1)) }), policy(), 'bad-chain'],
  ['a certificate whose two signature algorithms differ', () => doc({ certificate: leafCert({ tbsAlg: seq(oid('1.2.840.10045.4.3.2')) }) }), policy(), 'bad-chain'],
  ['a certificate signed with SHA-384 but labelled SHA-256', () => doc({ certificate: leafCert({ alg: seq(oid('1.2.840.10045.4.3.2')) }) }), policy(), 'bad-chain'],
  ['a certificate whose signature was altered', () => doc({ certificate: flipLast(leafCert()) }), policy(), 'bad-chain'],
  ['an intermediate whose signature was altered', () => doc({ cabundle: [pki.root.cert, flipLast(pki.intermediate.cert)] }), policy(), 'bad-chain'],
  // validity
  ['an expired leaf', () => doc({ certificate: leafCert({ notAfter: new Date(now - 1000) }) }), policy(), 'expired-certificate'],
  ['a leaf not valid yet', () => doc({ certificate: leafCert({ notBefore: new Date(now + 60_000) }) }), policy(), 'expired-certificate'],
  ['an expired intermediate', () => doc(underRoot({ notAfter: new Date(now - 1000) })), policy(), 'expired-certificate'],
  ['an expired root', () => doc({ cabundle: [expiredRoot.rootCert], certificate: leafCert({ issuer: 'old.root', issuerKey: expiredRoot.key.privateKey }) }), policy({ trustedRootFingerprints: [expiredRoot.fingerprint] }), 'expired-certificate'],
  // leaf key and COSE signature
  ['a P-256 leaf key', () => doc({ certificate: leafCert({ publicKey: generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey }) }), policy(), 'unsupported-algorithm'],
  ['an RSA leaf key', () => doc({ certificate: leafCert({ publicKey: rsa.publicKey }) }), policy(), 'unsupported-algorithm'],
  ['a COSE signature altered', () => flipLast(doc()), policy(), 'bad-signature'],
  ['a document signed by a key other than the leaf\'s', () => doc({}, ec().privateKey), policy(), 'bad-signature'],
  ['a COSE signature of 95 bytes', () => recose(doc(), ([p, u, pl, s]) => [p, u, pl, s.subarray(0, 95)]), policy(), 'bad-signature'],
  ['a payload changed after signing', () => withPayload(doc(), (m) => m.set('module_id', 'i-attacker-enc')), policy(), 'bad-signature'],
  ['a public key swapped after signing', () => withPayload(doc(), (m) => m.set('public_key', new Uint8Array(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' })))), policy(), 'bad-signature'],
  ['a protected header that declares ES256', () => doc({}, leafKey.privateKey, -7), policy(), 'unsupported-algorithm'],
  ['a protected header that was changed after signing', () => recose(doc(), ([, u, pl, s]) => [encodeCbor(new Map<number, unknown>([[1, -35], [4, new Uint8Array(1)]])), u, pl, s]), policy(), 'bad-signature'],
  ['a SHA256 digest', () => doc({ digest: 'SHA256' }), policy(), 'unsupported-algorithm'],
  // freshness, nonce, PCRs
  ['a document 6 minutes old', () => doc({ timestamp: now - 6 * 60_000 }), policy(), 'stale'],
  ['a document 5 minutes and 1 ms old', () => doc({ timestamp: now - 5 * 60_000 - 1 }), policy(), 'stale'],
  ['a document 60 s and 1 ms ahead', () => doc({ timestamp: now + 60_001 }), policy(), 'stale'],
  ['a document 5 minutes ahead', () => doc({ timestamp: now + 5 * 60_000 }), policy(), 'stale'],
  ['another nonce', () => doc({ nonce: new Uint8Array(32).fill(8) }), policy(), 'nonce-mismatch'],
  ['no nonce', () => doc({ nonce: undefined }), policy(), 'nonce-mismatch'],
  ['a nonce of another length', () => doc({ nonce: new Uint8Array(31).fill(7) }), policy(), 'nonce-mismatch'],
  ['a debug-mode enclave', () => doc({ pcrs: { 0: zero, 1: zero, 2: zero } }), policy({ expectedPcrs: {} }), 'debug-enclave'],
  ['another PCR0', () => doc({ pcrs: { ...pcrs, 0: other[0]! } }), policy(), 'pcr-mismatch'],
  ['another PCR1', () => doc({ pcrs: { ...pcrs, 1: other[1]! } }), policy(), 'pcr-mismatch'],
  ['another PCR2', () => doc({ pcrs: { ...pcrs, 2: other[2]! } }), policy(), 'pcr-mismatch'],
  ['another PCR8', () => doc(), policy({ expectedPcrs: { 8: other[8] } }), 'pcr-mismatch'],
  ['no PCR8 where one is expected', () => doc({ pcrs: { 0: pcrs[0]!, 1: pcrs[1]!, 2: pcrs[2]! } }), policy({ expectedPcrs: { 8: pcrs[8] } }), 'pcr-mismatch'],
  ['an expected PCR that is not hex', () => doc(), policy({ expectedPcrs: { 0: 'zz'.repeat(48) } }), 'pcr-mismatch'],
  ['no public key when it is required', () => doc({ publicKey: undefined }), policy(), 'missing-public-key'],
  // structure
  ['an empty cabundle', () => doc({ cabundle: [] }), policy(), 'malformed'],
  ['a cabundle entry that is not bytes', () => withPayload(doc(), (m) => m.set('cabundle', [pki.root.cert, 'x'])), policy(), 'malformed'],
  ['a cabundle entry that is not a certificate', () => doc({ cabundle: [pki.root.cert, new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])] }), policy(), 'malformed'],
  ['a leaf that is not a certificate', () => doc({ certificate: new Uint8Array(40).fill(0x42) }), policy(), 'malformed'],
  ['no certificate', () => withPayload(doc(), (m) => m.delete('certificate')), policy(), 'malformed'],
  ['no module_id', () => withPayload(doc(), (m) => m.delete('module_id')), policy(), 'malformed'],
  ['no timestamp', () => withPayload(doc(), (m) => m.delete('timestamp')), policy(), 'malformed'],
  ['a timestamp of zero', () => doc({ timestamp: 0 }), policy(), 'malformed'],
  ['no PCRs', () => doc({ pcrs: {} }), policy(), 'malformed'],
  ['a PCR of 47 bytes', () => withPayload(doc(), (m) => m.set('pcrs', new Map([[0, new Uint8Array(47)]]))), policy(), 'malformed'],
  ['a nonce that is not bytes, signed as such', () => resigned(doc(), (m) => m.set('nonce', 'nonce')), policy(), 'malformed'],
  ['a public key that is not bytes, signed as such', () => resigned(doc(), (m) => m.set('public_key', 42)), policy(), 'malformed'],
  ['user data that is not bytes, signed as such', () => resigned(doc(), (m) => m.set('user_data', [1])), policy(), 'malformed'],
  ['a payload re-signed by the leaf after a change (the leaf key is what vouches for it)', () => resigned(doc(), (m) => m.set('module_id', 'i-other-enc')), policy(), 'ok'],
  ['a payload that is not a map', () => recose(doc(), ([p, u, , s]) => [p, u, encodeCbor([1, 2]), s]), policy(), 'malformed'],
  ['a COSE structure of three members', () => recose(doc(), ([p, u, pl]) => [p, u, pl]), policy(), 'malformed'],
  ['a CBOR tag other than 18', () => encodeCbor(new CborTag(98, decodeCbor(doc()))), policy(), 'malformed'],
  ['random bytes', () => new Uint8Array(randomBytes(64)), policy(), 'malformed'],
  ['nothing', () => new Uint8Array(0), policy(), 'malformed'],
];

describe('portable Nitro attestation verifier against the node:crypto one', () => {
  it('FR005-10: pins the same AWS Nitro G1 root', () => {
    expect(PORTABLE_ROOT_SHA256).toBe(NITRO_ROOT_G1_SHA256);
  });

  it.each(MATRIX)('FR005-10: %s', (_what, make, p, code) => {
    const r = both(make(), p);
    expect(r.portable).toBe(r.node);
    expect(r.node).toBe(code);
  });

  it('FR005-10: verifies the self-signature of the real AWS Nitro root with its own X.509 and P-384 code', () => {
    const root = new Uint8Array(Buffer.from(NITRO_ROOT_G1_PEM.replace(/-----[^-]+-----|\s/g, ''), 'base64'));
    expect(new X509Certificate(root).subject).toContain('CN=aws.nitro-enclaves');
    // The real root is pinned by default. A leaf that names it as its issuer, byte for byte, but that AWS never signed,
    // gets past the pin and the root's own signature (ECDSA P-384 by AWS) and is refused at the next link, by both.
    const subjectOfRoot = derChildren(derChildren(parseDer(root))[0]!)[5]!.raw;
    const forged = cert({ subject: 'i-forged-enc', issuer: '', issuerName: subjectOfRoot, publicKey: leafKey.publicKey, issuerKey: ec().privateKey, exts: [basicConstraints(false)] });
    const r = both(doc({ cabundle: [root], certificate: forged }), policy({ trustedRootFingerprints: undefined }));
    expect(r).toEqual({ node: 'bad-chain', portable: 'bad-chain', message: 'attestation: certificate 1 is not issued by its predecessor' });
  });

  describe('where the portable verifier is stricter than OpenSSL (it refuses what the node:crypto one takes)', () => {
    it('FR005-10: a critical extension it does not know, in an intermediate or in the leaf (RFC 5280 §4.2)', () => {
      const unknown = ext('1.3.6.1.4.1.99999.1', true, octets(Uint8Array.of(1)));
      expect(both(doc(underRoot({ exts: [basicConstraints(true), unknown] })))).toMatchObject({ node: 'ok', portable: 'bad-chain' });
      expect(both(doc(underRoot({}, { exts: [basicConstraints(false), unknown] })))).toMatchObject({ node: 'ok', portable: 'bad-chain' });
      // The same extension, not critical, is ignored by both.
      expect(both(doc(underRoot({ exts: [basicConstraints(true), ext('1.3.6.1.4.1.99999.1', false, octets(Uint8Array.of(1)))] })))).toMatchObject({ node: 'ok', portable: 'ok' });
    });

    it('FR005-10: bytes after the DER of a certificate', () => {
      expect(both(doc({ certificate: new Uint8Array([...leafCert(), 0, 0]) }))).toMatchObject({ node: 'ok', portable: 'malformed' });
    });

    it('FR005-10: an issuer name equal to the subject of its issuer only once both are normalised (DER compared, not text)', () => {
      expect(both(doc({ certificate: leafCert({ printableIssuer: true }) }))).toMatchObject({ node: 'ok', portable: 'bad-chain' });
    });

    it('FR005-10: an intermediate key that is not P-384 (the Nitro PKI is P-384 / SHA-384 throughout)', () => {
      const k = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const interCert = cert({ subject: 'p256.intermediate', issuer: 'simulated.nitro-enclaves', publicKey: k.publicKey, issuerKey: pki.root.key, exts: [basicConstraints(true)] });
      const leaf = leafCert({ issuer: 'p256.intermediate', issuerKey: k.privateKey });
      expect(both(doc({ cabundle: [pki.root.cert, interCert], certificate: leaf }))).toMatchObject({ node: 'ok', portable: 'bad-chain' });
    });
  });
});
