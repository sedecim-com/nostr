import { createSign, generateKeyPairSync, randomUUID, type KeyObject } from 'node:crypto';
import { CognitoVerifier } from '@sedecim/service-kit';

export interface AccesoPool {
  issuer: string;
  clientId: string;
  /** The pool's JWKS document, what the enclave pins in its image. */
  jwks: { keys: Array<Record<string, unknown>> };
  /** The backend's verifier of the same pool (JWKS fetched from this stand-in). */
  verifier(): CognitoVerifier;
  /** A Cognito-like token as a valid id token of `sub` signed in just now; `claims` override any default. */
  token(claims?: Record<string, unknown>, header?: Record<string, unknown>, key?: KeyObject): string;
}

/** An in-process Acceso (Cognito) user pool with its own RSA key: tokens carry `iat` and a `jti` of their own, like Cognito's. */
export function createAccesoPool(cfg = { region: 'us-east-1', userPoolId: 'us-east-1_TEST', clientId: 'acceso-web' }): AccesoPool {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
  const issuer = `https://cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
  const jwks = { keys: [jwk] };
  const fetchJwks = (async () => new Response(JSON.stringify(jwks))) as typeof fetch;
  return {
    issuer,
    clientId: cfg.clientId,
    jwks,
    verifier: () => new CognitoVerifier({ ...cfg, fetch: fetchJwks }),
    token(claims = {}, header = { alg: 'RS256', kid: 'k1' }, key = privateKey) {
      const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      const body = `${enc(header)}.${enc({ iss: issuer, token_use: 'id', aud: cfg.clientId, sub: 'user-1', 'cognito:username': 'ana', exp: now + 600, iat: now, auth_time: now, jti: randomUUID(), origin_jti: 'test-login', ...claims })}`;
      return `${body}.${createSign('RSA-SHA256').update(body).sign(key).toString('base64url')}`;
    },
  };
}
