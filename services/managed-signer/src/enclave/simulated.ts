/**
 * SIMULATED enclave for tests and development. NOT SECURE: the "NSM" signs attestation documents with a
 * locally generated CA, the "KMS" is an in-memory AES key and everything runs in the backend process, so
 * the backend can read every secret. It exists to exercise the real protocol, attestation verification and
 * the attestation-conditioned KMS flow end to end without AWS (docs/managed-enclave.md).
 */
import { createCipheriv, createDecipheriv, createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, type KeyObject, X509Certificate } from 'node:crypto';
import { encodeCbor } from './cbor';
import { coseSigStructure, pemFingerprint, verifyAttestation, type AttestationPolicy } from './attestation';
import { encryptEnvelopedData } from './cms';
import { bitString, bool, ctx, int, octets, oid, seq, set, time, utf8 } from './der';
import { EnclaveSigner } from './enclave';
import type { Nsm } from './enclave';
import type { EnclaveKms } from './kms';
import type { UserProofVerifier } from './proof';

export const SIMULATION_WARNING = 'managed-signer: SIMULATED enclave (NOT SECURE, tests/dev only): the backend process holds every key';

const ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const name = (cn: string) => seq(set(seq(oid('2.5.4.3'), utf8(cn))));

export interface CertOptions {
  subject: string;
  issuer: string;
  publicKey: KeyObject;
  issuerKey: KeyObject;
  notBefore: Date;
  notAfter: Date;
  ca: boolean;
}

/** Minimal X.509 v3 certificate signed with ECDSA P-384 / SHA-384 (basicConstraints only). */
export function buildCertificate(o: CertOptions): Uint8Array {
  const alg = seq(oid(ECDSA_SHA384));
  const basicConstraints = seq(oid('2.5.29.19'), bool(true), octets(o.ca ? seq(bool(true)) : seq()));
  const serial = randomBytes(8);
  serial[0] = serial[0]! & 0x7f;
  const tbs = seq(
    ctx(0, true, int(2)),
    int(serial),
    alg,
    name(o.issuer),
    seq(time(o.notBefore), time(o.notAfter)),
    name(o.subject),
    new Uint8Array(o.publicKey.export({ type: 'spki', format: 'der' })),
    ctx(3, true, seq(basicConstraints)),
  );
  return seq(tbs, alg, bitString(sign('sha384', tbs, o.issuerKey)));
}

const p384 = () => generateKeyPairSync('ec', { namedCurve: 'P-384' });

export interface TestPki {
  root: { cert: Uint8Array; key: KeyObject };
  intermediate: { cert: Uint8Array; key: KeyObject };
  /** SHA-256 of the root, to pin in AttestationPolicy.trustedRootFingerprints. */
  fingerprint: string;
}

/** Root + intermediate CA, both P-384 like the Nitro PKI. */
export function createTestPki(now = Date.now(), days = 3650): TestPki {
  const root = p384();
  const inter = p384();
  const nb = new Date(now - 86_400_000);
  const na = new Date(now + days * 86_400_000);
  const rootCert = buildCertificate({ subject: 'simulated.nitro-enclaves', issuer: 'simulated.nitro-enclaves', publicKey: root.publicKey, issuerKey: root.privateKey, notBefore: nb, notAfter: na, ca: true });
  const interCert = buildCertificate({ subject: 'simulated.intermediate', issuer: 'simulated.nitro-enclaves', publicKey: inter.publicKey, issuerKey: root.privateKey, notBefore: nb, notAfter: na, ca: true });
  return { root: { cert: rootCert, key: root.privateKey }, intermediate: { cert: interCert, key: inter.privateKey }, fingerprint: pemFingerprint(new X509Certificate(rootCert)) };
}

/** Deterministic fake measurements (hex, 48 bytes). */
export function simulatedPcrs(label = 'acceso-nostr-enclave'): Record<number, string> {
  const pcr = (i: number) => createHash('sha384').update(`${label}/pcr${i}`).digest('hex');
  return { 0: pcr(0), 1: pcr(1), 2: pcr(2), 3: pcr(3), 4: pcr(4), 8: pcr(8) };
}

export interface DocumentFields {
  moduleId?: string;
  timestamp: number;
  pcrs: Record<number, string>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
  digest?: string;
}

/** COSE_Sign1 attestation document in the Nitro layout, signed by `leafKey` (ES384). */
export function buildAttestationDocument(f: DocumentFields, leafKey: KeyObject, alg = -35): Uint8Array {
  const payload = encodeCbor(
    new Map<string, unknown>([
      ['module_id', f.moduleId ?? 'i-simulated-enc0123456789'],
      ['digest', f.digest ?? 'SHA384'],
      ['timestamp', f.timestamp],
      ['pcrs', new Map(Object.entries(f.pcrs).map(([k, v]) => [Number(k), new Uint8Array(Buffer.from(v, 'hex'))]))],
      ['certificate', f.certificate],
      ['cabundle', f.cabundle],
      ['public_key', f.publicKey ?? null],
      ['user_data', f.userData ?? null],
      ['nonce', f.nonce ?? null],
    ]),
  );
  const protectedBytes = encodeCbor(new Map([[1, alg]]));
  const signature = sign('sha384', coseSigStructure(protectedBytes, payload), { key: leafKey, dsaEncoding: 'ieee-p1363' });
  return encodeCbor([protectedBytes, new Map(), payload, new Uint8Array(signature)]);
}

/** Stand-in for /dev/nsm: a per-instance leaf certificate under the test PKI. */
export class SimulatedNsm implements Nsm {
  private readonly leaf = p384();
  private readonly leafCert: Uint8Array;

  constructor(private readonly opts: { pki: TestPki; pcrs: Record<number, string>; now?: () => number }) {
    const now = this.now();
    this.leafCert = buildCertificate({
      subject: 'i-simulated-enc0123456789',
      issuer: 'simulated.intermediate',
      publicKey: this.leaf.publicKey,
      issuerKey: opts.pki.intermediate.key,
      notBefore: new Date(now - 60_000),
      notAfter: new Date(now + 3 * 3_600_000),
      ca: false,
    });
  }

  private now() {
    return (this.opts.now ?? Date.now)();
  }

  async attest(req: { publicKey?: Uint8Array; nonce?: Uint8Array; userData?: Uint8Array }) {
    return buildAttestationDocument(
      {
        timestamp: this.now(),
        pcrs: this.opts.pcrs,
        certificate: this.leafCert,
        cabundle: [this.opts.pki.root.cert, this.opts.pki.intermediate.cert],
        ...(req.publicKey ? { publicKey: req.publicKey } : {}),
        ...(req.nonce ? { nonce: req.nonce } : {}),
        ...(req.userData ? { userData: req.userData } : {}),
      },
      this.leaf.privateKey,
    );
  }
}

export class KmsAccessDenied extends Error {
  override readonly name = 'AccessDeniedException';
}

/**
 * Stand-in for KMS with a key policy that requires Recipient attestation: every call verifies the document
 * (chain, signature, freshness, PCRs) and answers only with CiphertextForRecipient. Calls without an
 * attestation document (what the parent could do with its own credentials) are denied.
 */
export class SimulatedKms implements EnclaveKms {
  private readonly master = randomBytes(32);
  readonly calls: Array<{ op: 'generateDataKey' | 'decrypt'; ok: boolean }> = [];

  constructor(private readonly policy: AttestationPolicy & { keyId?: string }) {}

  private recipientKey(doc: Uint8Array | undefined, op: 'generateDataKey' | 'decrypt') {
    try {
      if (!doc?.length) throw new KmsAccessDenied('key policy requires kms:RecipientAttestation');
      const att = verifyAttestation(doc, { ...this.policy, requirePublicKey: true });
      this.calls.push({ op, ok: true });
      return createPublicKey({ key: Buffer.from(att.publicKey!), format: 'der', type: 'spki' });
    } catch (err) {
      this.calls.push({ op, ok: false });
      throw err instanceof KmsAccessDenied ? err : new KmsAccessDenied((err as Error).message);
    }
  }

  private aad(keyId: string, context: Record<string, string>) {
    if (this.policy.keyId && keyId !== this.policy.keyId) throw new KmsAccessDenied('unknown key');
    return Buffer.from(JSON.stringify([keyId, Object.entries(context).sort(([a], [b]) => a.localeCompare(b))]));
  }

  async generateDataKey(req: { keyId: string; context: Record<string, string>; attestationDocument: Uint8Array }) {
    const pub = this.recipientKey(req.attestationDocument, 'generateDataKey');
    const dk = randomBytes(32);
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.master, iv);
    c.setAAD(this.aad(req.keyId, req.context));
    const ciphertextBlob = Buffer.concat([iv, c.update(dk), c.final(), c.getAuthTag()]);
    const ciphertextForRecipient = encryptEnvelopedData(dk, pub);
    dk.fill(0);
    return { ciphertextBlob: new Uint8Array(ciphertextBlob), ciphertextForRecipient };
  }

  async decrypt(req: { keyId: string; ciphertextBlob: Uint8Array; context: Record<string, string>; attestationDocument: Uint8Array }) {
    const pub = this.recipientKey(req.attestationDocument, 'decrypt');
    const b = Buffer.from(req.ciphertextBlob);
    const d = createDecipheriv('aes-256-gcm', this.master, b.subarray(0, 12), { authTagLength: 16 });
    d.setAAD(this.aad(req.keyId, req.context));
    d.setAuthTag(b.subarray(b.length - 16));
    let dk: Buffer;
    try {
      dk = Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
    } catch {
      throw new Error('InvalidCiphertextException');
    }
    const ciphertextForRecipient = encryptEnvelopedData(dk, pub);
    dk.fill(0);
    return { ciphertextForRecipient };
  }
}

export interface SimulatedEnclave {
  enclave: EnclaveSigner;
  kms: SimulatedKms;
  nsm: SimulatedNsm;
  pki: TestPki;
  pcrs: Record<number, string>;
  /** Policy a parent/KMS should apply to this enclave's documents. */
  policy: Required<Pick<AttestationPolicy, 'trustedRootFingerprints' | 'expectedPcrs'>>;
}

/** Wires a simulated NSM + KMS to a real EnclaveSigner. */
export function createSimulatedEnclave(opts: { pcrs?: Record<number, string>; kmsPcrs?: Record<number, string>; now?: () => number; allowExport?: boolean; proof?: UserProofVerifier; maxRememberedProofs?: number } = {}): SimulatedEnclave {
  const pki = createTestPki();
  const pcrs = opts.pcrs ?? simulatedPcrs();
  const expected = opts.kmsPcrs ?? simulatedPcrs();
  const policy = { trustedRootFingerprints: [pki.fingerprint], expectedPcrs: { 0: expected[0], 1: expected[1], 2: expected[2] } };
  const nsm = new SimulatedNsm({ pki, pcrs, ...(opts.now ? { now: opts.now } : {}) });
  const kms = new SimulatedKms({ ...policy, keyId: 'alias/simulated-enclave' });
  // Export stays on in the (already insecure) simulation so dev/tests can exercise FR-026, but like the real enclave it
  // only opens a key for a proof of its owner: without `proof` every export is refused (FR005-09).
  const enclave = new EnclaveSigner({ nsm, kms, kmsKeyId: 'alias/simulated-enclave', allowExport: opts.allowExport ?? true, ...(opts.proof ? { proof: opts.proof } : {}), ...(opts.maxRememberedProofs !== undefined ? { maxRememberedProofs: opts.maxRememberedProofs } : {}) });
  return { enclave, kms, nsm, pki, pcrs, policy };
}
