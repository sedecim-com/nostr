import { createSign, generateKeyPairSync } from 'node:crypto';
import { CognitoVerifier } from '../src/index';

export const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
export const cfg = { region: 'us-east-1', userPoolId: 'us-east-1_TEST', clientId: 'acceso-web' };
export const iss = `https://cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
export const jwksFetch = (async () => new Response(JSON.stringify({ keys: [jwk] }))) as typeof fetch;
export const verifier = () => new CognitoVerifier({ ...cfg, fetch: jwksFetch });

/** Signs a Cognito-like token; claims override the defaults of a valid id token. */
export function token(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'RS256', kid: 'k1' }, key = privateKey) {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const body = `${enc(header)}.${enc({ iss, token_use: 'id', aud: cfg.clientId, sub: 'user-1', 'cognito:username': 'ana', exp: Math.floor(Date.now() / 1000) + 600, ...claims })}`;
  return `${body}.${createSign('RSA-SHA256').update(body).sign(key).toString('base64url')}`;
}
