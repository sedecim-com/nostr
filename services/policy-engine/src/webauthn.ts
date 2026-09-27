import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify, X509Certificate, type JsonWebKey } from 'node:crypto';

/**
 * Minimal WebAuthn registration verification (FR023-07) with node:crypto only: ES256 credentials,
 * attestation formats `packed` (self or x5c) and `none`. The x5c chain is not validated against
 * vendor roots (no FIDO MDS): the signature proves the authenticator produced this credential.
 */

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
      return { value: major === 2 ? bytes : new TextDecoder('utf-8', { fatal: true }).decode(bytes), offset: offset + len };
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

export interface RegistrationOptionsInput {
  rpId: string;
  rpName: string;
  userId: Uint8Array;
  userName: string;
  challenge: string;
  excludeCredentials?: string[];
  timeoutMs?: number;
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
    authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
    excludeCredentials: (i.excludeCredentials ?? []).map((id) => ({ type: 'public-key', id })),
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
  if (!cred || cred.type !== 'public-key' || typeof cred.id !== 'string' || !cred.response) throw new WebAuthnError('not a public-key credential');
  const clientDataRaw = b64u.decode(cred.response.clientDataJSON);
  let clientData: { type?: string; challenge?: string; origin?: string; crossOrigin?: boolean };
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataRaw));
  } catch {
    throw new WebAuthnError('invalid clientDataJSON');
  }
  if (clientData.type !== 'webauthn.create') throw new WebAuthnError('clientData.type must be webauthn.create');
  if (typeof clientData.challenge !== 'string' || !eq(Buffer.from(clientData.challenge), Buffer.from(expected.challenge))) throw new WebAuthnError('challenge mismatch');
  if (!clientData.origin || !expected.origins.includes(clientData.origin)) throw new WebAuthnError('origin not allowed');
  if (clientData.crossOrigin) throw new WebAuthnError('cross-origin registration not allowed');

  const att = cborDecode(b64u.decode(cred.response.attestationObject)).value;
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
  if (credentialIdB64 !== cred.id.replace(/=+$/, '') || (cred.rawId !== undefined && cred.rawId.replace(/=+$/, '') !== credentialIdB64)) throw new WebAuthnError('credential id mismatch');
  const cose = cborDecode(authData, 55 + credLen);
  if (cose.offset !== authData.length && !(flags & 0x80)) throw new WebAuthnError('trailing authenticator data');
  const publicKey = coseToJwk(cose.value);

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
      const cert = new X509Certificate(x5c[0]);
      if (!/OU=Authenticator Attestation/.test(cert.subject)) throw new WebAuthnError('packed: attestation certificate OU must be "Authenticator Attestation"');
      key = cert.publicKey;
    } else {
      key = createPublicKey({ key: publicKey, format: 'jwk' });
    }
    if (!verify('sha256', signed, key, sig)) throw new WebAuthnError('attestation signature invalid');
  } else {
    throw new WebAuthnError(`unsupported attestation format: ${String(fmt)}`);
  }
  return { credentialId: credentialIdB64, publicKey, signCount, fmt, userVerified: !!(flags & 0x04) };
}
