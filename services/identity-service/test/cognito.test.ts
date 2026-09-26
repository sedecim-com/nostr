import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { cfg, iss, token, verifier } from './cognito-fixture';

describe('CognitoVerifier (Acceso login, ADR 0008)', () => {
  const v = verifier();

  it('accepts id and access tokens of the configured pool and client', async () => {
    expect(await v.verify(token({}))).toEqual({ issuer: iss, subject: 'user-1', username: 'ana', tokenUse: 'id' });
    expect((await v.verify(token({ token_use: 'access', aud: undefined, client_id: cfg.clientId }))).tokenUse).toBe('access');
  });

  it('rejects forged, foreign, expired or mis-addressed tokens', async () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    await expect(v.verify(token({}, undefined, other))).rejects.toThrow(/signature/);
    await expect(v.verify(token({ iss: 'https://evil.example' }))).rejects.toThrow(/issuer/);
    await expect(v.verify(token({ aud: 'other-client' }))).rejects.toThrow(/audience/);
    await expect(v.verify(token({ token_use: 'access', client_id: 'other' }))).rejects.toThrow(/client/);
    await expect(v.verify(token({ exp: Math.floor(Date.now() / 1000) - 1 }))).rejects.toThrow(/expired/);
    await expect(v.verify(token({}, { alg: 'HS256', kid: 'k1' }))).rejects.toThrow(/algorithm/);
    await expect(v.verify(token({}, { alg: 'RS256', kid: 'nope' }))).rejects.toThrow(/unknown signing key/);
    await expect(v.verify('not-a-jwt')).rejects.toThrow(/malformed/);
  });
});
