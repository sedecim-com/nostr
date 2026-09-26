import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { CognitoVerifier, type CognitoConfig } from './cognito';

export interface TestCognito {
  cfg: Pick<CognitoConfig, 'region' | 'userPoolId' | 'clientId'>;
  issuer: string;
  /** JWKS endpoint stand-in to pass as `CognitoConfig.fetch`. */
  jwksFetch: typeof fetch;
  verifier(): CognitoVerifier;
  /** Signs a Cognito-like token; claims override the defaults of a valid id token for `user-1`. */
  token(claims?: Record<string, unknown>, header?: Record<string, unknown>, key?: KeyObject): string;
}

/**
 * Test helper: an in-process Acceso (Cognito) user pool with its own RSA key and JWKS, so services can
 * exercise CognitoVerifier end to end without AWS.
 */
export function createTestCognito(cfg = { region: 'us-east-1', userPoolId: 'us-east-1_TEST', clientId: 'acceso-web' }): TestCognito {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
  const issuer = `https://cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
  const jwksFetch = (async () => new Response(JSON.stringify({ keys: [jwk] }))) as typeof fetch;
  return {
    cfg,
    issuer,
    jwksFetch,
    verifier: () => new CognitoVerifier({ ...cfg, fetch: jwksFetch }),
    token(claims = {}, header = { alg: 'RS256', kid: 'k1' }, key = privateKey) {
      const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const body = `${enc(header)}.${enc({ iss: issuer, token_use: 'id', aud: cfg.clientId, sub: 'user-1', 'cognito:username': 'ana', exp: Math.floor(Date.now() / 1000) + 600, ...claims })}`;
      return `${body}.${createSign('RSA-SHA256').update(body).sign(key).toString('base64url')}`;
    },
  };
}
