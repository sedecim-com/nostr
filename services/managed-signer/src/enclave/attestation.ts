import { createHash, timingSafeEqual, verify as verifySignature, X509Certificate } from 'node:crypto';
import { CborTag, decodeCbor, encodeCbor, type CborValue } from './cbor';

/**
 * AWS Nitro Enclaves root certificate (G1).
 * Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip (root.pem), documented in
 * https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html. Valid until 2049-10-28.
 */
export const NITRO_ROOT_G1_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`;

/** SHA-256 of the DER root certificate, as published by AWS (pinned: the bundled PEM must match it). */
export const NITRO_ROOT_G1_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';

export type AttestationErrorCode =
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

export class AttestationError extends Error {
  constructor(readonly code: AttestationErrorCode, message: string) {
    super(`attestation: ${message}`);
  }
}

export interface AttestationPolicy {
  /** SHA-256 fingerprints (hex) of acceptable roots. Default: the AWS Nitro G1 root only. */
  trustedRootFingerprints?: string[];
  /** Expected PCR values (hex, 48 bytes) by index: 0 image, 1 kernel/bootstrap, 2 application, 8 signing cert. */
  expectedPcrs?: Partial<Record<number, string>>;
  /** Nonce the verifier sent; when set the document must carry exactly this nonce. */
  expectedNonce?: Uint8Array;
  /** Maximum age of the document (default 5 minutes, the window KMS applies). */
  maxAgeMs?: number;
  /** Tolerated clock skew for documents from the future (default 60 s). */
  maxSkewMs?: number;
  /** Require the `public_key` field (the RSA key KMS encrypts to). */
  requirePublicKey?: boolean;
  /** Accept enclaves started with --debug-mode (PCR0-2 all zeros). Never in production. */
  allowDebug?: boolean;
  now?: number;
}

export interface VerifiedAttestation {
  moduleId: string;
  timestamp: number;
  digest: string;
  /** Lowercase hex by PCR index. */
  pcrs: Record<number, string>;
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
  /** Leaf (enclave) certificate. */
  certificate: X509Certificate;
}

const COSE_ALG_ES384 = -35;

export const pemFingerprint = (cert: X509Certificate) => createHash('sha256').update(cert.raw).digest('hex');

const fail = (code: AttestationErrorCode, msg: string): never => {
  throw new AttestationError(code, msg);
};

const bytesField = (m: Map<CborValue, CborValue>, k: string, optional = false): Uint8Array | undefined => {
  const v = m.get(k);
  if ((v === undefined || v === null) && optional) return undefined;
  if (!(v instanceof Uint8Array)) return fail('malformed', `${k} must be a byte string`);
  return v;
};

function parseCert(der: Uint8Array, what: string): X509Certificate {
  try {
    return new X509Certificate(der);
  } catch {
    return fail('malformed', `${what} is not an X.509 certificate`);
  }
}

function checkValidity(cert: X509Certificate, now: number, what: string) {
  const from = new Date(cert.validFrom).getTime();
  const to = new Date(cert.validTo).getTime();
  // A validity date that does not parse is NaN, and every comparison against NaN is false: fail closed on it, not open.
  if (!Number.isFinite(from) || !Number.isFinite(to) || now < from || now > to) fail('expired-certificate', `${what} is outside its validity period`);
}

/** Splits a COSE_Sign1 (tag 18 optional) into its four members. */
export function decodeCoseSign1(doc: Uint8Array) {
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
export const coseSigStructure = (protectedBytes: Uint8Array, payload: Uint8Array) => encodeCbor(['Signature1', protectedBytes, new Uint8Array(0), payload]);

/**
 * Verifies a Nitro attestation document: COSE_Sign1 ES384 signature by the leaf certificate, certificate
 * chain (cabundle) up to a pinned root, validity periods, freshness, nonce and expected PCRs.
 */
export function verifyAttestation(doc: Uint8Array, policy: AttestationPolicy = {}): VerifiedAttestation {
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
  for (const [k, v] of pcrMap) {
    if (typeof k !== 'number' || k < 0 || k > 31 || !(v instanceof Uint8Array) || ![32, 48, 64].includes(v.length)) fail('malformed', 'invalid PCR entry');
    pcrs[k as number] = Buffer.from(v as Uint8Array).toString('hex');
  }

  // Chain: cabundle[0] is the root, then intermediates, then the leaf certificate.
  const chain = cabundle.map((c, i) => (c instanceof Uint8Array ? parseCert(c, `cabundle[${i}]`) : fail('malformed', 'cabundle entries must be byte strings')));
  const leaf = parseCert(leafDer, 'certificate');
  const root = chain[0]!;
  const trusted = (policy.trustedRootFingerprints ?? [NITRO_ROOT_G1_SHA256]).map((f) => f.replace(/:/g, '').toLowerCase());
  if (!trusted.includes(pemFingerprint(root))) fail('untrusted-root', 'root certificate is not pinned');
  if (!root.verify(root.publicKey)) fail('bad-chain', 'root is not self-signed');
  const all = [...chain, leaf];
  for (let i = 0; i < all.length; i++) {
    const cert = all[i]!;
    checkValidity(cert, now, i === all.length - 1 ? 'leaf certificate' : `cabundle[${i}]`);
    if (i === 0) continue;
    const issuer = all[i - 1]!;
    if (!issuer.ca) fail('bad-chain', `cabundle[${i - 1}] is not a CA`);
    if (!cert.checkIssued(issuer) || !cert.verify(issuer.publicKey)) fail('bad-chain', `certificate ${i} is not issued by its predecessor`);
  }

  const key = leaf.publicKey;
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'secp384r1') fail('unsupported-algorithm', 'leaf key must be EC P-384');
  if (signature.length !== 96) fail('bad-signature', 'ES384 signature must be 96 bytes');
  if (!verifySignature('sha384', coseSigStructure(protectedBytes, payload), { key, dsaEncoding: 'ieee-p1363' }, signature)) fail('bad-signature', 'COSE signature does not verify');

  const maxAge = policy.maxAgeMs ?? 5 * 60_000;
  if (timestamp > now + (policy.maxSkewMs ?? 60_000)) fail('stale', 'timestamp is in the future');
  if (now - timestamp > maxAge) fail('stale', `document older than ${maxAge} ms`);

  const nonce = bytesField(body, 'nonce', true);
  if (policy.expectedNonce) {
    if (!nonce || nonce.length !== policy.expectedNonce.length || !timingSafeEqual(nonce, policy.expectedNonce)) fail('nonce-mismatch', 'nonce does not match');
  }

  if (!policy.allowDebug && [0, 1, 2].every((i) => pcrs[i] !== undefined && /^0+$/.test(pcrs[i]!))) fail('debug-enclave', 'PCR0-2 are zero (debug-mode enclave)');
  for (const [idx, want] of Object.entries(policy.expectedPcrs ?? {})) {
    if (want === undefined || want === '') continue;
    const got = pcrs[Number(idx)];
    if (!got || got !== want.toLowerCase()) fail('pcr-mismatch', `PCR${idx} does not match`);
  }

  const publicKey = bytesField(body, 'public_key', true);
  if (policy.requirePublicKey && !publicKey) fail('missing-public-key', 'public_key missing');
  const userData = bytesField(body, 'user_data', true);
  return {
    moduleId: moduleId as string,
    timestamp,
    digest: 'SHA384',
    pcrs,
    certificate: leaf,
    ...(publicKey ? { publicKey } : {}),
    ...(userData ? { userData } : {}),
    ...(nonce ? { nonce } : {}),
  };
}
