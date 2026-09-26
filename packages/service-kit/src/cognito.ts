import { createPublicKey, createVerify, type JsonWebKey } from 'node:crypto';

export interface CognitoConfig {
  region: string;
  userPoolId: string;
  /** App client id of the Acceso web client: `aud` of id tokens, `client_id` of access tokens. */
  clientId: string;
  /** Override for tests; defaults to the pool's well-known JWKS. */
  jwksUrl?: string;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface CognitoIdentity {
  issuer: string;
  subject: string;
  username?: string;
  tokenUse: 'id' | 'access';
}

export class CognitoTokenError extends Error {}

const b64url = (s: string) => Buffer.from(s, 'base64url');

/**
 * Verifies Acceso (AWS Cognito) tokens the same way authentication-server-api does: RS256 against the
 * user pool JWKS, plus issuer, token_use, audience/client and expiry checks (SaaS login, ADR 0008).
 */
export class CognitoVerifier {
  readonly issuer: string;
  private jwks?: { at: number; keys: Map<string, JsonWebKey> };

  constructor(private readonly cfg: CognitoConfig) {
    this.issuer = `https://cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
  }

  private async key(kid: string): Promise<JsonWebKey> {
    const now = (this.cfg.now ?? Date.now)();
    if (!this.jwks || now - this.jwks.at > 3_600_000 || !this.jwks.keys.has(kid)) {
      const res = await (this.cfg.fetch ?? fetch)(this.cfg.jwksUrl ?? `${this.issuer}/.well-known/jwks.json`);
      if (!res.ok) throw new CognitoTokenError(`jwks fetch failed: ${res.status}`);
      const body = (await res.json()) as { keys: Array<JsonWebKey & { kid: string }> };
      this.jwks = { at: now, keys: new Map(body.keys.map((k) => [k.kid, k])) };
    }
    const k = this.jwks.keys.get(kid);
    if (!k) throw new CognitoTokenError('unknown signing key');
    return k;
  }

  async verify(token: string): Promise<CognitoIdentity> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new CognitoTokenError('malformed token');
    const [h, p, sig] = parts as [string, string, string];
    let header: { alg?: string; kid?: string };
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(b64url(h).toString('utf8'));
      claims = JSON.parse(b64url(p).toString('utf8'));
    } catch {
      throw new CognitoTokenError('malformed token');
    }
    if (header.alg !== 'RS256' || !header.kid) throw new CognitoTokenError('unsupported token algorithm');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${h}.${p}`);
    if (!verifier.verify(createPublicKey({ key: await this.key(header.kid), format: 'jwk' }), b64url(sig))) throw new CognitoTokenError('bad signature');
    if (claims.iss !== this.issuer) throw new CognitoTokenError('wrong issuer');
    const nowS = Math.floor((this.cfg.now ?? Date.now)() / 1000);
    if (typeof claims.exp !== 'number' || claims.exp <= nowS) throw new CognitoTokenError('token expired');
    const use = claims.token_use;
    if (use === 'id') {
      if (claims.aud !== this.cfg.clientId) throw new CognitoTokenError('wrong audience');
    } else if (use === 'access') {
      if (claims.client_id !== this.cfg.clientId) throw new CognitoTokenError('wrong client');
    } else throw new CognitoTokenError('unexpected token_use');
    if (typeof claims.sub !== 'string') throw new CognitoTokenError('missing subject');
    const username = (claims['cognito:username'] ?? claims.username) as string | undefined;
    return { issuer: this.issuer, subject: claims.sub, tokenUse: use, ...(username ? { username } : {}) };
  }
}
