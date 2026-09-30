import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify, X509Certificate, type JsonWebKey } from 'node:crypto';

/**
 * Minimal WebAuthn verification with node:crypto only: registration (FR023-07) of ES256 credentials, attestation
 * formats `packed` (self or x5c) and `none`, and assertions (FR023-11) signed by a registered credential. The x5c
 * chain is not validated against vendor roots (no FIDO MDS): the signature proves the authenticator produced this
 * credential.
 */

/** Strips base64 '=' padding in linear time (a /=+$/ regex backtracks on long runs of '='). */
function unpad(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 61) end--;
  return s.slice(0, end);
}

export const b64u = {
  encode: (b: Uint8Array) => Buffer.from(b).toString('base64url'),
  decode: (s: string) => {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*={0,2}$/.test(s)) throw new WebAuthnError('invalid base64url');
    return new Uint8Array(Buffer.from(s, 'base64url'));
  },
};

export class WebAuthnError extends Error {}

type Cbor = number | bigint | boolean | null | undefined | string | Uint8Array | Cbor[] | Map<Cbor, Cbor>;

/** Decodes one CBOR item (RFC 8949 subset used by WebAuthn); returns it and the offset after it. */
export function cborDecode(buf: Uint8Array, offset = 0, depth = 0): { value: Cbor; offset: number } {
  if (depth > 16) throw new WebAuthnError('CBOR too deep');
  const need = (n: number) => {
    if (offset + n > buf.length) throw new WebAuthnError('truncated CBOR');
  };
  need(1);
  const ib = buf[offset++]!;
  const major = ib >> 5;
  const info = ib & 31;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let len: number;
  if (info < 24) len = info;
  else if (info === 24) (need(1), (len = buf[offset]!), (offset += 1));
  else if (info === 25) (need(2), (len = dv.getUint16(offset)), (offset += 2));
  else if (info === 26) (need(4), (len = dv.getUint32(offset)), (offset += 4));
  else if (info === 27) {
    need(8);
    const big = dv.getBigUint64(offset);
    offset += 8;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new WebAuthnError('CBOR integer too large');
    len = Number(big);
  } else throw new WebAuthnError('unsupported CBOR encoding');
  switch (major) {
    case 0:
      return { value: len, offset };
    case 1:
      return { value: -1 - len, offset };
    case 2:
    case 3: {
      need(len);
      const bytes = buf.slice(offset, offset + len);
      if (major === 2) return { value: bytes, offset: offset + len };
      try {
        return { value: new TextDecoder('utf-8', { fatal: true }).decode(bytes), offset: offset + len };
      } catch {
        throw new WebAuthnError('invalid UTF-8 in CBOR text string');
      }
    }
    case 4: {
      const arr: Cbor[] = [];
      for (let i = 0; i < len; i++) {
        const r = cborDecode(buf, offset, depth + 1);
        arr.push(r.value);
        offset = r.offset;
      }
      return { value: arr, offset };
    }
    case 5: {
      const map = new Map<Cbor, Cbor>();
      for (let i = 0; i < len; i++) {
        const k = cborDecode(buf, offset, depth + 1);
        const v = cborDecode(buf, k.offset, depth + 1);
        // CTAP2 canonical CBOR has unique keys; a duplicate could shadow a checked field.
        if (map.has(k.value)) throw new WebAuthnError('duplicate CBOR map key');
        map.set(k.value, v.value);
        offset = v.offset;
      }
      return { value: map, offset };
    }
    case 7:
      if (info === 20) return { value: false, offset };
      if (info === 21) return { value: true, offset };
      if (info === 22) return { value: null, offset };
      throw new WebAuthnError('unsupported CBOR simple value');
    default:
      throw new WebAuthnError('unsupported CBOR major type');
  }
}

const sha256 = (b: Uint8Array | string) => new Uint8Array(createHash('sha256').update(b).digest());
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && timingSafeEqual(a, b);

type ClientData = { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };

/**
 * Parses clientDataJSON and checks what registration and assertion share: the ceremony type, the challenge (constant
 * time), an allowed origin and no cross-origin iframe. Anything but a JSON object is a WebAuthnError, never a TypeError.
 */
function checkClientData(raw: Uint8Array, expected: { type: 'webauthn.create' | 'webauthn.get'; challenge: string; origins: string[] }): void {
  let clientData: ClientData;
  try {
    clientData = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)) as ClientData;
  } catch {
    throw new WebAuthnError('invalid clientDataJSON');
  }
  if (!clientData || typeof clientData !== 'object' || Array.isArray(clientData)) throw new WebAuthnError('invalid clientDataJSON');
  if (clientData.type !== expected.type) throw new WebAuthnError(`clientData.type must be ${expected.type}`);
  if (typeof clientData.challenge !== 'string' || !eq(Buffer.from(clientData.challenge), Buffer.from(expected.challenge))) throw new WebAuthnError('challenge mismatch');
  if (typeof clientData.origin !== 'string' || !expected.origins.includes(clientData.origin)) throw new WebAuthnError('origin not allowed');
  if (clientData.crossOrigin) throw new WebAuthnError('cross-origin ceremony not allowed');
}

/** The credential id of a PublicKeyCredential JSON (`id`, and `rawId` when present), unpadded; WebAuthnError otherwise. */
function credentialIdOf(cred: { id: unknown; rawId?: unknown }): string {
  if (typeof cred.id !== 'string' || (cred.rawId !== undefined && typeof cred.rawId !== 'string')) throw new WebAuthnError('invalid credential id');
  const id = unpad(cred.id);
  if (cred.rawId !== undefined && unpad(cred.rawId as string) !== id) throw new WebAuthnError('credential id mismatch');
  return id;
}

/** COSE EC2 P-256 key (alg -7) → JWK. */
export function coseToJwk(cose: Cbor): JsonWebKey {
  if (!(cose instanceof Map)) throw new WebAuthnError('invalid COSE key');
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
    throw new WebAuthnError('only ES256 (EC2 P-256) credentials are supported');
  }
  return { kty: 'EC', crv: 'P-256', x: b64u.encode(x), y: b64u.encode(y) };
}

/** 'required' when WEBAUTHN_REQUIRE_UV asks for a PIN or biometrics, not only presence (FR023-11). */
export type UserVerification = 'required' | 'preferred';

export interface RegistrationOptionsInput {
  rpId: string;
  rpName: string;
  userId: Uint8Array;
  userName: string;
  challenge: string;
  excludeCredentials?: string[];
  timeoutMs?: number;
  userVerification?: UserVerification;
}

/** PublicKeyCredentialCreationOptions as JSON (binary fields base64url, as in `PublicKeyCredential.parseCreationOptionsFromJSON`). */
export function creationOptions(i: RegistrationOptionsInput) {
  return {
    challenge: i.challenge,
    rp: { id: i.rpId, name: i.rpName },
    user: { id: b64u.encode(i.userId), name: i.userName, displayName: i.userName },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: i.timeoutMs ?? 300_000,
    attestation: 'direct',
    authenticatorSelection: { residentKey: 'discouraged', userVerification: i.userVerification ?? 'preferred' },
    excludeCredentials: (i.excludeCredentials ?? []).map((id) => ({ type: 'public-key', id })),
  };
}

export interface AssertionOptionsInput {
  rpId: string;
  challenge: string;
  /** The credentials that may answer: the one of the device the session is opened on. */
  allowCredentials: string[];
  timeoutMs?: number;
  userVerification?: UserVerification;
}

/** PublicKeyCredentialRequestOptions as JSON (binary fields base64url, as in `PublicKeyCredential.parseRequestOptionsFromJSON`). */
export function requestOptions(i: AssertionOptionsInput) {
  return {
    challenge: i.challenge,
    rpId: i.rpId,
    allowCredentials: i.allowCredentials.map((id) => ({ type: 'public-key', id })),
    timeout: i.timeoutMs ?? 300_000,
    userVerification: i.userVerification ?? 'preferred',
  };
}

export const newChallenge = () => b64u.encode(randomBytes(32));

export interface RegistrationCredentialJSON {
  id: string;
  rawId?: string;
  type: string;
  response: { clientDataJSON: string; attestationObject: string };
}

export interface VerifiedRegistration {
  credentialId: string;
  publicKey: JsonWebKey;
  signCount: number;
  fmt: 'packed' | 'none';
  userVerified: boolean;
}

/** Verifies a `navigator.credentials.create()` result against the expected challenge, origin and RP id. */
export function verifyRegistration(
  cred: RegistrationCredentialJSON,
  expected: { challenge: string; origins: string[]; rpId: string; allowNone?: boolean },
): VerifiedRegistration {
  if (!cred || typeof cred !== 'object' || cred.type !== 'public-key' || !cred.response || typeof cred.response !== 'object') throw new WebAuthnError('not a public-key credential');
  const claimedId = credentialIdOf(cred);
  const clientDataRaw = b64u.decode(cred.response.clientDataJSON);
  checkClientData(clientDataRaw, { type: 'webauthn.create', challenge: expected.challenge, origins: expected.origins });

  const attRaw = b64u.decode(cred.response.attestationObject);
  const attDecoded = cborDecode(attRaw);
  if (attDecoded.offset !== attRaw.length) throw new WebAuthnError('trailing bytes after attestationObject');
  const att = attDecoded.value;
  if (!(att instanceof Map)) throw new WebAuthnError('invalid attestationObject');
  const fmt = att.get('fmt');
  const attStmt = att.get('attStmt');
  const authData = att.get('authData');
  if (!(authData instanceof Uint8Array) || authData.length < 37 || !(attStmt instanceof Map)) throw new WebAuthnError('invalid attestationObject');

  if (!eq(authData.slice(0, 32), sha256(expected.rpId))) throw new WebAuthnError('rpIdHash mismatch');
  const flags = authData[32]!;
  if (!(flags & 0x01)) throw new WebAuthnError('user presence required');
  if (!(flags & 0x40)) throw new WebAuthnError('no attested credential data');
  const signCount = new DataView(authData.buffer, authData.byteOffset).getUint32(33);
  if (authData.length < 55) throw new WebAuthnError('truncated authenticator data');
  const credLen = (authData[53]! << 8) | authData[54]!;
  const credentialId = authData.slice(55, 55 + credLen);
  if (credentialId.length !== credLen || credLen === 0) throw new WebAuthnError('truncated credential id');
  const credentialIdB64 = b64u.encode(credentialId);
  if (credentialIdB64 !== claimedId) throw new WebAuthnError('credential id mismatch');
  const cose = cborDecode(authData, 55 + credLen);
  if (cose.offset !== authData.length && !(flags & 0x80)) throw new WebAuthnError('trailing authenticator data');
  const publicKey = coseToJwk(cose.value);
  let credKey;
  try {
    credKey = createPublicKey({ key: publicKey, format: 'jwk' }); // also rejects points off the curve
  } catch {
    throw new WebAuthnError('credential public key is not a valid P-256 point');
  }

  const signed = Buffer.concat([authData, sha256(clientDataRaw)]);
  if (fmt === 'none') {
    if (!expected.allowNone) throw new WebAuthnError('attestation required (fmt none not accepted)');
    if (attStmt.size !== 0) throw new WebAuthnError('fmt none must have an empty attStmt');
  } else if (fmt === 'packed') {
    const sig = attStmt.get('sig');
    if (attStmt.get('alg') !== -7 || !(sig instanceof Uint8Array)) throw new WebAuthnError('packed: only alg -7 is supported');
    const x5c = attStmt.get('x5c');
    let key;
    if (x5c !== undefined) {
      if (!Array.isArray(x5c) || !(x5c[0] instanceof Uint8Array)) throw new WebAuthnError('packed: invalid x5c');
      let cert: X509Certificate;
      try {
        cert = new X509Certificate(x5c[0]);
      } catch {
        throw new WebAuthnError('packed: x5c[0] is not an X.509 certificate');
      }
      if (!/OU=Authenticator Attestation/.test(cert.subject)) throw new WebAuthnError('packed: attestation certificate OU must be "Authenticator Attestation"');
      key = cert.publicKey;
    } else {
      key = credKey;
    }
    let ok = false;
    try {
      ok = verify('sha256', signed, key, sig);
    } catch {
      ok = false;
    }
    if (!ok) throw new WebAuthnError('attestation signature invalid');
  } else {
    throw new WebAuthnError(`unsupported attestation format: ${String(fmt)}`);
  }
  return { credentialId: credentialIdB64, publicKey, signCount, fmt, userVerified: !!(flags & 0x04) };
}

export interface AssertionCredentialJSON {
  id: string;
  rawId?: string;
  type: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string | null };
}

export interface VerifiedAssertion {
  signCount: number;
  userVerified: boolean;
}

/**
 * FR023-11: verifies a `navigator.credentials.get()` result against the credential registered on the device: ceremony
 * `webauthn.get`, challenge, origin, RP id hash, user presence (and verification when required), the credential id and
 * user handle, and the ES256 signature over `authenticatorData || SHA-256(clientDataJSON)` with the stored public key.
 * The signature counter is returned, not judged: whether it went up is the repository's atomic check.
 */
export function verifyAssertion(
  cred: AssertionCredentialJSON,
  expected: { challenge: string; origins: string[]; rpId: string; credentialId: string; publicKey: JsonWebKey; userHandle?: Uint8Array; requireUserVerification?: boolean },
): VerifiedAssertion {
  if (!cred || typeof cred !== 'object' || cred.type !== 'public-key' || !cred.response || typeof cred.response !== 'object') throw new WebAuthnError('not a public-key credential');
  if (credentialIdOf(cred) !== expected.credentialId) throw new WebAuthnError('credential not allowed');
  const { userHandle } = cred.response;
  if (userHandle !== undefined && userHandle !== null && expected.userHandle && !eq(b64u.decode(userHandle), expected.userHandle)) throw new WebAuthnError('user handle mismatch');
  const clientDataRaw = b64u.decode(cred.response.clientDataJSON);
  checkClientData(clientDataRaw, { type: 'webauthn.get', challenge: expected.challenge, origins: expected.origins });

  const authData = b64u.decode(cred.response.authenticatorData);
  if (authData.length < 37) throw new WebAuthnError('truncated authenticator data');
  if (!eq(authData.subarray(0, 32), sha256(expected.rpId))) throw new WebAuthnError('rpIdHash mismatch');
  const flags = authData[32]!;
  if (!(flags & 0x01)) throw new WebAuthnError('user presence required');
  if (expected.requireUserVerification && !(flags & 0x04)) throw new WebAuthnError('user verification required');
  if (!(flags & 0x08) && flags & 0x10) throw new WebAuthnError('backup state without backup eligibility');
  // An assertion never carries attested credential data; extensions, when flagged, are one CBOR map up to the end.
  if (flags & 0x40) throw new WebAuthnError('unexpected attested credential data');
  if (flags & 0x80) {
    const ext = cborDecode(authData, 37);
    if (!(ext.value instanceof Map) || ext.offset !== authData.length) throw new WebAuthnError('invalid authenticator extensions');
  } else if (authData.length !== 37) throw new WebAuthnError('trailing authenticator data');
  const signCount = new DataView(authData.buffer, authData.byteOffset, authData.byteLength).getUint32(33);

  const sig = b64u.decode(cred.response.signature);
  const jwk = expected.publicKey;
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new WebAuthnError('stored credential key is not ES256');
  let key;
  try {
    key = createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    throw new WebAuthnError('stored credential key is invalid');
  }
  let ok = false;
  try {
    // DER-encoded ECDSA; OpenSSL rejects non-canonical encodings and trailing bytes.
    ok = verify('sha256', Buffer.concat([authData, sha256(clientDataRaw)]), key, sig);
  } catch {
    ok = false;
  }
  if (!ok) throw new WebAuthnError('assertion signature invalid');
  return { signCount, userVerified: !!(flags & 0x04) };
}
