import { readFileSync } from 'node:fs';
import { createPublicKey, createVerify, type JsonWebKey, type KeyObject } from 'node:crypto';

/**
 * FR005-09: the user's own say-so, checked inside the enclave. What lets a key out of the enclave (FR-026 export) is an
 * Acceso (AWS Cognito) token that this code verifies against the user pool's signing keys *pinned in the enclave image*
 * (PCR-measured): the parent can relay a token, never mint one, and cannot swap the keys it is checked against.
 *
 * Rules mirror packages/service-kit/src/cognito.ts (RS256, issuer, token_use, audience or client, expiry), plus what a
 * proof needs and a login does not: a recent password sign-in (`auth_time`, IR-2026-10-03) judged by the caller's clock
 * (inside the enclave: the Nitro NSM, not the parent's), and a `jti`, so that the enclave can refuse to accept one token
 * twice. Nothing here does I/O.
 */

export interface UserProofPolicy {
  /** `iss` of the Acceso user pool: `https://cognito-idp.<region>.amazonaws.com/<userPoolId>`. */
  issuer: string;
  /** App client id of the Acceso web client: `aud` of id tokens, `client_id` of access tokens. */
  clientId: string;
  /** The pool's JWKS as published at `<issuer>/.well-known/jwks.json`, copied into the image. */
  jwks: { keys: Array<JsonWebKey & { kid?: string }> };
  /** How recent the password sign-in must be, in seconds (default 300, the backend's IR-2026-10-03 limit). */
  maxAgeSeconds?: number;
  /** Tolerated clock skew between Cognito and the NSM, in seconds (default 60). */
  skewSeconds?: number;
}

export interface VerifiedProof {
  /** `${issuer}#${sub}`: the key owner as the managed-signer names it. */
  owner: string;
  /** Unique id of this token: the enclave accepts it once. */
  jti: string;
  /** When the password sign-in happened (seconds). */
  authTime: number;
  /** When the token stops being valid (seconds). */
  expiresAt: number;
}

export class UserProofError extends Error {}

/** What the enclave asks of a proof verifier: the real one is PinnedJwksProofVerifier; tests and the simulation may swap it. */
export interface UserProofVerifier {
  /** Verifies `token` as of `nowMs` (the enclave's trusted clock). Throws UserProofError. */
  verify(token: string, nowMs: number): VerifiedProof;
}

export const DEFAULT_PROOF_MAX_AGE_S = 300;
const DEFAULT_SKEW_S = 60;
const MAX_TOKEN_BYTES = 8192;
const MIN_RSA_BITS = 2048;
const b64url = (s: string) => Buffer.from(s, 'base64url');
const fail = (msg: string): never => {
  throw new UserProofError(`proof: ${msg}`);
};

export class PinnedJwksProofVerifier implements UserProofVerifier {
  private readonly keys = new Map<string, KeyObject>();
  private readonly maxAge: number;
  private readonly skew: number;

  constructor(private readonly policy: UserProofPolicy) {
    if (!/^https:\/\/[^\s#]+$/.test(policy.issuer)) throw new Error('proof issuer must be the https issuer URL of the user pool');
    if (typeof policy.clientId !== 'string' || !policy.clientId) throw new Error('proof clientId is required');
    this.maxAge = policy.maxAgeSeconds ?? DEFAULT_PROOF_MAX_AGE_S;
    this.skew = policy.skewSeconds ?? DEFAULT_SKEW_S;
    if (!(Number.isInteger(this.maxAge) && this.maxAge > 0 && this.maxAge <= 3600)) throw new Error('proof maxAgeSeconds must be a whole number of seconds between 1 and 3600');
    if (!(Number.isInteger(this.skew) && this.skew >= 0 && this.skew <= 300)) throw new Error('proof skewSeconds must be a whole number of seconds between 0 and 300');
    for (const jwk of policy.jwks?.keys ?? []) {
      if (jwk.kty !== 'RSA' || typeof jwk.kid !== 'string' || !jwk.kid) continue; // the pool also publishes nothing else; ignore what cannot sign RS256
      if ((jwk.use ?? 'sig') !== 'sig') continue;
      const key = createPublicKey({ key: jwk, format: 'jwk' });
      if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) throw new Error(`proof key ${jwk.kid} is shorter than ${MIN_RSA_BITS} bits`);
      if (this.keys.has(jwk.kid)) throw new Error(`proof key ${jwk.kid} is listed twice`);
      this.keys.set(jwk.kid, key);
    }
    if (this.keys.size === 0) throw new Error('proof jwks holds no RSA signing key');
  }

  verify(token: string, nowMs: number): VerifiedProof {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_BYTES) return fail('malformed token');
    const parts = token.split('.');
    if (parts.length !== 3) return fail('malformed token');
    const [h, p, sig] = parts as [string, string, string];
    let header: { alg?: unknown; kid?: unknown };
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(b64url(h).toString('utf8'));
      claims = JSON.parse(b64url(p).toString('utf8'));
    } catch {
      return fail('malformed token');
    }
    if (!header || typeof header !== 'object' || !claims || typeof claims !== 'object') return fail('malformed token');
    // The algorithm is fixed by us, never read from the token (no `none`, no HS256 with the public key as secret).
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') return fail('unsupported token algorithm');
    const key = this.keys.get(header.kid);
    if (!key) return fail('unknown signing key');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${h}.${p}`);
    if (!verifier.verify(key, b64url(sig))) return fail('bad signature');

    if (claims.iss !== this.policy.issuer) return fail('wrong issuer');
    const use = claims.token_use;
    if (use === 'id') {
      if (claims.aud !== this.policy.clientId) return fail('wrong audience');
    } else if (use === 'access') {
      if (claims.client_id !== this.policy.clientId) return fail('wrong client');
    } else return fail('unexpected token_use');
    const sub = claims.sub;
    if (typeof sub !== 'string' || sub.length === 0 || sub.length > 256) return fail('missing subject');
    const jti = claims.jti;
    if (typeof jti !== 'string' || jti.length === 0 || jti.length > 128) return fail('missing token id');

    const now = Math.floor(nowMs / 1000);
    const { exp, iat, auth_time: authTime } = claims;
    if (typeof exp !== 'number' || !Number.isFinite(exp) || exp <= now) return fail('token expired');
    if (typeof iat !== 'number' || !Number.isFinite(iat) || iat > now + this.skew) return fail('token issued in the future');
    // A sign-in older than the limit is a stolen browser that keeps refreshing its tokens, not the owner typing the password.
    if (typeof authTime !== 'number' || !Number.isFinite(authTime)) return fail('token carries no sign-in time');
    if (authTime > now + this.skew) return fail('sign-in time is in the future');
    if (now - authTime > this.maxAge) return fail(`the password sign-in is older than ${this.maxAge} seconds`);
    return { owner: `${this.policy.issuer}#${sub}`, jti, authTime, expiresAt: exp };
  }
}

/**
 * The pinned user pool from the environment: `<prefix>_ISSUER`, `_CLIENT_ID`, `_JWKS` (path of the pool's jwks.json) and
 * optionally `_MAX_AGE_S`. All of them or none; `undefined` means no verifier, and then the enclave refuses every export.
 */
export function proofVerifierFromEnv(env: NodeJS.ProcessEnv, prefix: string): PinnedJwksProofVerifier | undefined {
  const issuer = env[`${prefix}_ISSUER`];
  const clientId = env[`${prefix}_CLIENT_ID`];
  const jwksPath = env[`${prefix}_JWKS`];
  if (!issuer && !clientId && !jwksPath) return undefined;
  if (!issuer || !clientId || !jwksPath) throw new Error(`${prefix}_ISSUER, ${prefix}_CLIENT_ID and ${prefix}_JWKS go together`);
  const maxAgeSeconds = Number(env[`${prefix}_MAX_AGE_S`] ?? DEFAULT_PROOF_MAX_AGE_S);
  return new PinnedJwksProofVerifier({ issuer, clientId, jwks: JSON.parse(readFileSync(jwksPath, 'utf8')) as UserProofPolicy['jwks'], maxAgeSeconds });
}

/**
 * What the enclave image starts with (ENCLAVE_ALLOW_EXPORT and ENCLAVE_PROOF_*). Export without the pinned user pool is a
 * configuration error, refused at boot: an export the parent could ask for alone is the hole FR005-09 closes.
 */
export function exportConfigFromEnv(env: NodeJS.ProcessEnv): { allowExport: boolean; proof?: PinnedJwksProofVerifier } {
  const allowExport = env.ENCLAVE_ALLOW_EXPORT === '1';
  const proof = proofVerifierFromEnv(env, 'ENCLAVE_PROOF');
  if (allowExport && !proof) throw new Error('ENCLAVE_ALLOW_EXPORT=1 needs ENCLAVE_PROOF_ISSUER, ENCLAVE_PROOF_CLIENT_ID and ENCLAVE_PROOF_JWKS (the user pool keys pinned in the image)');
  return { allowExport, ...(proof ? { proof } : {}) };
}
