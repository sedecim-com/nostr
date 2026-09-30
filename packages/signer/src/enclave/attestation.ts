import { bytesToHex, equalBytes, sha256, verifyEcdsaP384 } from '@sedecim/nostr-core';
import { CborTag, decodeCbor, encodeCbor, type CborValue } from './cbor';
import { decodeOid, derChildren, parseDer, TAG, type DerNode } from './der';

/**
 * FR005-10: the AWS Nitro attestation check without node:*, so that a browser checks the enclave's document itself
 * before sealing a secret to the key in it (the parent relays the document and must not be able to swap in a key of its
 * own). Same rules and error codes as the backend's verifier (services/managed-signer/src/enclave/attestation.ts, on
 * node:crypto), which a differential test holds it to: COSE_Sign1 ES384 by the leaf certificate, X.509 chain from the
 * cabundle up to a root pinned by its SHA-256, validity, freshness, nonce and PCRs. On the chain it is stricter than
 * OpenSSL's per-certificate checks: only ECDSA P-384 / SHA-384 (what the Nitro PKI uses), names compared as DER, and
 * an unknown critical extension (RFC 5280 §4.2) is refused.
 */

/** SHA-256 of the DER AWS Nitro Enclaves root certificate (G1), as AWS publishes it; the backend pins the same. */
export const NITRO_ROOT_G1_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';

export type NitroAttestationErrorCode =
  | 'malformed'
  | 'unsupported-algorithm'
  | 'untrusted-root'
  | 'bad-chain'
  | 'expired-certificate'
  | 'bad-signature'
  | 'stale'
  | 'nonce-mismatch'
  | 'pcr-mismatch'
  | 'debug-enclave'
  | 'missing-public-key';

export class NitroAttestationError extends Error {
  constructor(readonly code: NitroAttestationErrorCode, message: string) {
    super(`attestation: ${message}`);
  }
}

export interface NitroAttestationPolicy {
  /** SHA-256 fingerprints (hex) of acceptable roots. Default: the AWS Nitro G1 root only. */
  trustedRootFingerprints?: string[];
  /** Expected PCR values (hex, 48 bytes) by index: 0 image, 1 kernel/bootstrap, 2 application, 8 signing cert. */
  expectedPcrs?: Partial<Record<number, string>>;
  /** Nonce the verifier sent; when set the document must carry exactly this nonce. */
  expectedNonce?: Uint8Array;
  /** Maximum age of the document (default 5 minutes). */
  maxAgeMs?: number;
  /** Tolerated clock skew for documents from the future (default 60 s). */
  maxSkewMs?: number;
  /** Require the `public_key` field (the enclave's RSA key). */
  requirePublicKey?: boolean;
  /** Accept enclaves started with --debug-mode (PCR0-2 all zeros). Never in production. */
  allowDebug?: boolean;
  now?: number;
}

export interface VerifiedNitroAttestation {
  moduleId: string;
  timestamp: number;
  digest: 'SHA384';
  /** Lowercase hex by PCR index. */
  pcrs: Record<number, string>;
  /** SPKI (DER) of the enclave's RSA key. */
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
  /** Leaf (enclave) certificate, DER. */
  certificate: Uint8Array;
}

const COSE_ALG_ES384 = -35;
const OID = {
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
  ecPublicKey: '1.2.840.10045.2.1',
  secp384r1: '1.3.132.0.34',
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  basicConstraints: '2.5.29.19',
  authorityKeyIdentifier: '2.5.29.35',
} as const;

const fail = (code: NitroAttestationErrorCode, msg: string): never => {
  throw new NitroAttestationError(code, msg);
};

const bytesField = (m: Map<CborValue, CborValue>, k: string, optional = false): Uint8Array | undefined => {
  const v = m.get(k);
  if ((v === undefined || v === null) && optional) return undefined;
  if (!(v instanceof Uint8Array)) return fail('malformed', `${k} must be a byte string`);
  return v;
};

/** Splits a COSE_Sign1 (tag 18 optional) into its four members. */
function decodeCoseSign1(doc: Uint8Array) {
  let top: CborValue;
  try {
    top = decodeCbor(doc);
  } catch (err) {
    return fail('malformed', (err as Error).message);
  }
  if (top instanceof CborTag) {
    if (top.tag !== 18) fail('malformed', `unexpected CBOR tag ${top.tag}`);
    top = top.value as CborValue;
  }
  if (!Array.isArray(top) || top.length !== 4) return fail('malformed', 'not a COSE_Sign1 structure');
  const [protectedBytes, , payload, signature] = top;
  if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) return fail('malformed', 'COSE_Sign1 members have the wrong types');
  return { protectedBytes, payload, signature };
}

/** COSE Sig_structure for Signature1 with empty external AAD (RFC 9052 §4.4). */
const coseSigStructure = (protectedBytes: Uint8Array, payload: Uint8Array) => encodeCbor(['Signature1', protectedBytes, new Uint8Array(0), payload]);

// --- X.509, as much of RFC 5280 as the chain check needs

interface Extensions {
  /** No extension twice, and the ones read here (basicConstraints, keyUsage, key identifiers) well formed. */
  valid: boolean;
  /** A critical extension this code does not process. */
  unknownCritical: boolean;
  /** basicConstraints present: its cA. */
  ca?: boolean;
  /** keyUsage present: whether it allows keyCertSign. */
  keyCertSign?: boolean;
  skid?: Uint8Array;
  akid?: { keyId?: Uint8Array; serial?: Uint8Array };
}

interface Certificate {
  der: Uint8Array;
  /** TBSCertificate, exactly as signed. */
  tbs: Uint8Array;
  /** AlgorithmIdentifier outside and inside the TBS (DER): X.509 wants them identical. */
  signatureAlgorithm: Uint8Array;
  tbsSignatureAlgorithm: Uint8Array;
  signature: Uint8Array;
  serial: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: number;
  notAfter: number;
  key: { algorithm: string; curve?: string; point: Uint8Array };
  ext: Extensions;
}

function expectTag(node: DerNode | undefined, tag: number): DerNode {
  if (!node || node.tag !== tag) throw new Error('unexpected ASN.1 structure');
  return node;
}

/** UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ), the only forms RFC 5280 allows, in ms. */
function parseTime(node: DerNode | undefined): number {
  const s = new TextDecoder().decode(node?.value ?? new Uint8Array(0));
  const m = node?.tag === TAG.UTC_TIME ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : node?.tag === TAG.GENERALIZED_TIME ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : null;
  if (!m) throw new Error('bad time');
  const [y, mo, d, h, mi, se] = m.slice(1).map(Number) as [number, number, number, number, number, number];
  const year = node!.tag === TAG.UTC_TIME ? (y < 50 ? 2000 + y : 1900 + y) : y;
  const t = Date.UTC(year, mo - 1, d, h, mi, se);
  const back = new Date(t);
  if (back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59 || se > 59) throw new Error('bad time');
  return t;
}

const isTrue = (node: DerNode) => {
  if (node.value.length !== 1) throw new Error('bad boolean');
  return node.value[0] !== 0;
};

/** Mirrors what OpenSSL caches from the extensions: a duplicated or malformed one leaves the certificate unusable in a chain. */
function parseExtensions(node: DerNode | undefined): Extensions {
  const ext: Extensions = { valid: true, unknownCritical: false };
  if (!node) return ext;
  const [list, ...rest] = derChildren(node);
  if (rest.length) throw new Error('extensions');
  const seen = new Set<string>();
  for (const e of derChildren(expectTag(list, TAG.SEQUENCE))) {
    const f = derChildren(expectTag(e, TAG.SEQUENCE));
    const id = decodeOid(expectTag(f[0], TAG.OID).value);
    let k = 1;
    let critical = false;
    if (f[k]?.tag === TAG.BOOLEAN) critical = isTrue(f[k++]!);
    const value = expectTag(f[k++], TAG.OCTET_STRING).value;
    if (k !== f.length) throw new Error('extension');
    if (seen.has(id)) ext.valid = false;
    seen.add(id);
    try {
      switch (id) {
        case OID.basicConstraints: {
          const bc = derChildren(expectTag(parseDer(value), TAG.SEQUENCE));
          let j = 0;
          const ca = bc[j]?.tag === TAG.BOOLEAN ? isTrue(bc[j++]!) : false;
          if (bc[j]?.tag === TAG.INTEGER) j++;
          if (j !== bc.length) throw new Error('basicConstraints');
          ext.ca = ca;
          break;
        }
        case OID.keyUsage: {
          const bits = expectTag(parseDer(value), TAG.BIT_STRING).value;
          if (bits.length < 1 || bits[0]! > 7) throw new Error('keyUsage');
          ext.keyCertSign = bits.length > 1 && (bits[1]! & 0x04) !== 0;
          break;
        }
        case OID.subjectKeyIdentifier:
          ext.skid = expectTag(parseDer(value), TAG.OCTET_STRING).value;
          break;
        case OID.authorityKeyIdentifier: {
          const akid: NonNullable<Extensions['akid']> = {};
          for (const n of derChildren(expectTag(parseDer(value), TAG.SEQUENCE))) {
            if (n.tag === 0x80) akid.keyId = n.value;
            else if (n.tag === 0x82) akid.serial = n.value;
            else if (n.tag !== 0xa1) throw new Error('authorityKeyIdentifier');
          }
          ext.akid = akid;
          break;
        }
        default:
          if (critical) ext.unknownCritical = true;
      }
    } catch {
      ext.valid = false;
    }
  }
  return ext;
}

function parseCertificate(bytes: Uint8Array, what: string): Certificate {
  try {
    const top = derChildren(expectTag(parseDer(bytes), TAG.SEQUENCE));
    if (top.length !== 3) throw new Error('certificate');
    const [tbsNode, algNode, sigNode] = top as [DerNode, DerNode, DerNode];
    expectTag(tbsNode, TAG.SEQUENCE);
    expectTag(algNode, TAG.SEQUENCE);
    const sig = expectTag(sigNode, TAG.BIT_STRING).value;
    if (sig.length < 1 || sig[0] !== 0) throw new Error('signature');
    const f = derChildren(tbsNode);
    let i = 0;
    if (f[i]?.tag === 0xa0) i++; // version
    const serial = expectTag(f[i++], TAG.INTEGER).value;
    const tbsAlg = expectTag(f[i++], TAG.SEQUENCE);
    const issuer = expectTag(f[i++], TAG.SEQUENCE);
    const validity = derChildren(expectTag(f[i++], TAG.SEQUENCE));
    const subject = expectTag(f[i++], TAG.SEQUENCE);
    const spki = derChildren(expectTag(f[i++], TAG.SEQUENCE));
    while (f[i] && [0x81, 0xa1, 0x82, 0xa2].includes(f[i]!.tag)) i++; // issuer/subject unique ids
    const extensions = f[i]?.tag === 0xa3 ? f[i++] : undefined;
    if (i !== f.length || validity.length !== 2 || spki.length !== 2) throw new Error('tbs');
    const keyAlg = derChildren(expectTag(spki[0], TAG.SEQUENCE));
    const algorithm = decodeOid(expectTag(keyAlg[0], TAG.OID).value);
    const curve = keyAlg[1]?.tag === TAG.OID ? decodeOid(keyAlg[1].value) : undefined;
    const point = expectTag(spki[1], TAG.BIT_STRING).value;
    if (point.length < 1) throw new Error('key');
    return {
      der: bytes,
      tbs: tbsNode.raw,
      signatureAlgorithm: algNode.raw,
      tbsSignatureAlgorithm: tbsAlg.raw,
      signature: sig.subarray(1),
      serial,
      issuer: issuer.raw,
      subject: subject.raw,
      notBefore: parseTime(validity[0]),
      notAfter: parseTime(validity[1]),
      key: { algorithm, ...(curve ? { curve } : {}), point: point[0] === 0 ? point.subarray(1) : new Uint8Array(0) },
      ext: parseExtensions(extensions),
    };
  } catch {
    return fail('malformed', `${what} is not an X.509 certificate`);
  }
}

function isP384(c: Certificate): boolean {
  const { algorithm, curve } = c.key;
  return algorithm === OID.ecPublicKey && curve === OID.secp384r1;
}

/** ecdsa-with-SHA384, parameters absent (RFC 5758) or NULL (tolerated by OpenSSL). */
function isEcdsaSha384(alg: Uint8Array): boolean {
  try {
    const f = derChildren(parseDer(alg));
    return decodeOid(expectTag(f[0], TAG.OID).value) === OID.ecdsaWithSha384 && (f.length === 1 || (f.length === 2 && f[1]!.tag === TAG.NULL && f[1]!.value.length === 0));
  } catch {
    return false;
  }
}

/** X509_verify: the signature over the TBS, by `issuer`'s key, under the algorithm the certificate names twice. */
function signedBy(c: Certificate, issuer: Certificate): boolean {
  if (!equalBytes(c.signatureAlgorithm, c.tbsSignatureAlgorithm) || !isEcdsaSha384(c.signatureAlgorithm) || !isP384(issuer)) return false;
  return verifyEcdsaP384(c.signature, c.tbs, issuer.key.point, 'der');
}

/** X509_check_ca() == 1, what X509Certificate#ca reports: basicConstraints cA, keyUsage (if any) with keyCertSign. */
const isCa = (c: Certificate) => c.ext.valid && !c.ext.unknownCritical && c.ext.ca === true && c.ext.keyCertSign !== false;

/** X509_check_issued: names chained, key identifiers consistent, issuer allowed to sign certificates. */
function issuedBy(c: Certificate, issuer: Certificate): boolean {
  if (!equalBytes(c.issuer, issuer.subject) || !c.ext.valid || !issuer.ext.valid || c.ext.unknownCritical || issuer.ext.keyCertSign === false) return false;
  const { akid } = c.ext;
  if (akid?.keyId && issuer.ext.skid && !equalBytes(akid.keyId, issuer.ext.skid)) return false;
  if (akid?.serial && !equalBytes(akid.serial, issuer.serial)) return false;
  return true;
}

function checkValidity(c: Certificate, now: number, what: string) {
  if (now < c.notBefore || now > c.notAfter) fail('expired-certificate', `${what} is outside its validity period`);
}

/** Constant-time comparison of a document PCR with an expected hex value (a malformed one simply does not match). */
function samePcr(got: Uint8Array | undefined, want: string): boolean {
  const w = want.toLowerCase();
  if (!got || w.length !== got.length * 2 || !/^[0-9a-f]*$/.test(w)) return false;
  const bytes = new Uint8Array(got.length);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(w.slice(2 * i, 2 * i + 2), 16);
  return equalBytes(got, bytes);
}

/**
 * Verifies a Nitro attestation document: COSE_Sign1 ES384 signature by the leaf certificate, certificate chain
 * (cabundle) up to a pinned root, validity periods, freshness, nonce and expected PCRs. Throws NitroAttestationError.
 */
export function verifyNitroAttestation(doc: Uint8Array, policy: NitroAttestationPolicy = {}): VerifiedNitroAttestation {
  const now = policy.now ?? Date.now();
  const { protectedBytes, payload, signature } = decodeCoseSign1(doc);

  let header: CborValue;
  let body: CborValue;
  try {
    header = protectedBytes.length ? decodeCbor(protectedBytes) : new Map();
    body = decodeCbor(payload);
  } catch (err) {
    return fail('malformed', (err as Error).message);
  }
  if (!(header instanceof Map) || header.get(1) !== COSE_ALG_ES384) fail('unsupported-algorithm', 'protected header must declare ES384');
  if (!(body instanceof Map)) return fail('malformed', 'payload is not a map');

  const moduleId = body.get('module_id');
  const digest = body.get('digest');
  const timestamp = body.get('timestamp');
  const pcrMap = body.get('pcrs');
  const cabundle = body.get('cabundle');
  if (typeof moduleId !== 'string' || !moduleId) fail('malformed', 'module_id missing');
  if (digest !== 'SHA384') fail('unsupported-algorithm', `digest ${String(digest)} is not SHA384`);
  if (typeof timestamp !== 'number' || timestamp <= 0) return fail('malformed', 'timestamp missing');
  if (!(pcrMap instanceof Map) || pcrMap.size === 0 || pcrMap.size > 32) return fail('malformed', 'pcrs missing');
  if (!Array.isArray(cabundle) || cabundle.length === 0) return fail('malformed', 'cabundle missing');
  const leafDer = bytesField(body, 'certificate')!;

  const pcrs: Record<number, string> = {};
  const pcrBytes = new Map<number, Uint8Array>();
  for (const [k, v] of pcrMap) {
    if (typeof k !== 'number' || k < 0 || k > 31 || !(v instanceof Uint8Array) || ![32, 48, 64].includes(v.length)) fail('malformed', 'invalid PCR entry');
    pcrs[k as number] = bytesToHex(v as Uint8Array);
    pcrBytes.set(k as number, v as Uint8Array);
  }

  // Chain: cabundle[0] is the root, then intermediates, then the leaf certificate.
  const chain = cabundle.map((c, i) => (c instanceof Uint8Array ? parseCertificate(c, `cabundle[${i}]`) : fail('malformed', 'cabundle entries must be byte strings')));
  const leaf = parseCertificate(leafDer, 'certificate');
  const root = chain[0]!;
  const trusted = (policy.trustedRootFingerprints ?? [NITRO_ROOT_G1_SHA256]).map((f) => f.replace(/:/g, '').toLowerCase());
  if (!trusted.includes(bytesToHex(sha256(root.der)))) fail('untrusted-root', 'root certificate is not pinned');
  if (!signedBy(root, root)) fail('bad-chain', 'root is not self-signed');
  const all = [...chain, leaf];
  for (let i = 0; i < all.length; i++) {
    const cert = all[i]!;
    checkValidity(cert, now, i === all.length - 1 ? 'leaf certificate' : `cabundle[${i}]`);
    if (i === 0) continue;
    const issuer = all[i - 1]!;
    if (!isCa(issuer)) fail('bad-chain', `cabundle[${i - 1}] is not a CA`);
    if (!issuedBy(cert, issuer) || !signedBy(cert, issuer)) fail('bad-chain', `certificate ${i} is not issued by its predecessor`);
  }

  if (!isP384(leaf)) fail('unsupported-algorithm', 'leaf key must be EC P-384');
  if (signature.length !== 96) fail('bad-signature', 'ES384 signature must be 96 bytes');
  if (!verifyEcdsaP384(signature, coseSigStructure(protectedBytes, payload), leaf.key.point, 'compact')) fail('bad-signature', 'COSE signature does not verify');

  const maxAge = policy.maxAgeMs ?? 5 * 60_000;
  if (timestamp > now + (policy.maxSkewMs ?? 60_000)) fail('stale', 'timestamp is in the future');
  if (now - timestamp > maxAge) fail('stale', `document older than ${maxAge} ms`);

  const nonce = bytesField(body, 'nonce', true);
  if (policy.expectedNonce) {
    if (!nonce || !equalBytes(nonce, policy.expectedNonce)) fail('nonce-mismatch', 'nonce does not match');
  }

  if (!policy.allowDebug && [0, 1, 2].every((i) => pcrs[i] !== undefined && /^0+$/.test(pcrs[i]!))) fail('debug-enclave', 'PCR0-2 are zero (debug-mode enclave)');
  for (const [idx, want] of Object.entries(policy.expectedPcrs ?? {})) {
    if (want === undefined || want === '') continue;
    if (!samePcr(pcrBytes.get(Number(idx)), want)) fail('pcr-mismatch', `PCR${idx} does not match`);
  }

  const publicKey = bytesField(body, 'public_key', true);
  if (policy.requirePublicKey && !publicKey) fail('missing-public-key', 'public_key missing');
  const userData = bytesField(body, 'user_data', true);
  return {
    moduleId: moduleId as string,
    timestamp,
    digest: 'SHA384',
    pcrs,
    certificate: leaf.der,
    ...(publicKey ? { publicKey } : {}),
    ...(userData ? { userData } : {}),
    ...(nonce ? { nonce } : {}),
  };
}
