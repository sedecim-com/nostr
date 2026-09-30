import { createHash, generateKeyPairSync, randomBytes, sign, type KeyPairKeyObjectResult } from 'node:crypto';

/**
 * Test authenticator: builds `navigator.credentials.create()` results (ES256, fmt packed-self or none) and
 * `navigator.credentials.get()` assertions of the same credential.
 */

export type C = number | string | Uint8Array | C[] | Map<C, C>;

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
  return [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export function cborEncode(v: C): Uint8Array {
  if (typeof v === 'number') return new Uint8Array(v >= 0 ? head(0, v) : head(1, -1 - v));
  if (typeof v === 'string') {
    const b = Buffer.from(v);
    return new Uint8Array([...head(3, b.length), ...b]);
  }
  if (v instanceof Uint8Array) return new Uint8Array([...head(2, v.length), ...v]);
  if (Array.isArray(v)) return new Uint8Array([...head(4, v.length), ...v.flatMap((x) => [...cborEncode(x)])]);
  return new Uint8Array([...head(5, v.size), ...[...v].flatMap(([k, x]) => [...cborEncode(k), ...cborEncode(x)])]);
}

const sha256 = (b: Uint8Array | string) => new Uint8Array(createHash('sha256').update(b).digest());
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

export interface AssertionInput {
  challenge: string;
  origin: string;
  rpId: string;
  /** Signature counter in authenticatorData (default 0: an authenticator without one). */
  counter?: number;
  /** Default 0x05 (UP | UV), plus 0x80 (ED) with `extensions`. */
  flags?: number;
  type?: string;
  crossOrigin?: boolean;
  /** CBOR map appended as authenticator extensions. */
  extensions?: Map<C, C>;
  /** Default null (a credential that is not discoverable). */
  userHandle?: Uint8Array | null;
  /** Claimed credential id (default: this one). */
  id?: string;
  tamperSig?: boolean;
}

export class TestAuthenticator {
  readonly credentialId: Uint8Array;
  private readonly keys: KeyPairKeyObjectResult;
  /** `new TestAuthenticator(other)`: a clone, with the same credential id and key. */
  constructor(from?: TestAuthenticator) {
    this.credentialId = from ? from.credentialId : new Uint8Array(randomBytes(16));
    this.keys = from ? from.keys : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  }

  get id() {
    return b64u(this.credentialId);
  }

  cose(): Map<C, C> {
    const jwk = this.keys.publicKey.export({ format: 'jwk' });
    return new Map<C, C>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
      [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
    ]);
  }

  create(o: { challenge: string; origin: string; rpId: string; fmt?: 'packed' | 'none'; type?: string; flags?: number; tamperSig?: boolean }) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: o.type ?? 'webauthn.create', challenge: o.challenge, origin: o.origin, crossOrigin: false }));
    const cose = cborEncode(this.cose());
    const authData = new Uint8Array([
      ...sha256(o.rpId),
      o.flags ?? 0x45, // UP | UV | AT
      0, 0, 0, 0,
      ...new Uint8Array(16), // aaguid
      this.credentialId.length >> 8, this.credentialId.length & 255,
      ...this.credentialId,
      ...cose,
    ]);
    const fmt = o.fmt ?? 'packed';
    let attStmt = new Map<C, C>();
    if (fmt === 'packed') {
      const sig = new Uint8Array(sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.keys.privateKey));
      if (o.tamperSig) sig[10] = sig[10]! ^ 1; // inside r: still valid DER, wrong signature
      attStmt = new Map<C, C>([['alg', -7], ['sig', sig]]);
    }
    const attestationObject = cborEncode(new Map<C, C>([['fmt', fmt], ['attStmt', attStmt], ['authData', authData]]));
    return { id: b64u(this.credentialId), rawId: b64u(this.credentialId), type: 'public-key', response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) } };
  }

  /** An assertion (`navigator.credentials.get()` as JSON) signed over `authenticatorData || SHA-256(clientDataJSON)`. */
  get(o: AssertionInput) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: o.type ?? 'webauthn.get', challenge: o.challenge, origin: o.origin, crossOrigin: o.crossOrigin ?? false }));
    const n = o.counter ?? 0;
    const authData = new Uint8Array([
      ...sha256(o.rpId),
      o.flags ?? (0x05 | (o.extensions ? 0x80 : 0)),
      (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255,
      ...(o.extensions ? cborEncode(o.extensions) : []),
    ]);
    const signature = new Uint8Array(sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.keys.privateKey));
    if (o.tamperSig) signature[10] = signature[10]! ^ 1; // inside r: still valid DER, wrong signature
    const id = o.id ?? this.id;
    return {
      id,
      rawId: id,
      type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: o.userHandle ? b64u(o.userHandle) : null },
    };
  }
}
