import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { CognitoVerifier, createTestCognito, JWKS_MIN_REFETCH_MS } from '../src/index';

const { cfg, issuer: iss, token, verifier } = createTestCognito();

describe('CognitoVerifier (Acceso login, ADR 0008)', () => {
  const v = verifier();

  it('accepts id and access tokens of the configured pool and client', async () => {
    const authTime = Math.floor(Date.now() / 1000) - 30;
    expect(await v.verify(token({ auth_time: authTime }))).toEqual({ issuer: iss, subject: 'user-1', username: 'ana', tokenUse: 'id', authTime, loginId: 'test-login' });
    expect((await v.verify(token({ token_use: 'access', aud: undefined, client_id: cfg.clientId }))).tokenUse).toBe('access');
  });

  it('reports when the user last signed in and which sign-in the token comes from (IR-2026-10-03, IR-2026-10-11)', async () => {
    // A refreshed token keeps auth_time and origin_jti; event_id stands in when the pool does not revoke tokens.
    expect(await v.verify(token({ auth_time: 1_790_000_000, origin_jti: 'ojti-1', event_id: 'ev-1' }))).toMatchObject({ authTime: 1_790_000_000, loginId: 'ojti-1' });
    expect((await v.verify(token({ origin_jti: undefined, event_id: 'ev-1' }))).loginId).toBe('ev-1');
    const bare = await v.verify(token({ auth_time: '1790000000', origin_jti: 'x'.repeat(129), event_id: undefined }));
    expect(bare.authTime).toBeUndefined();
    expect(bare.loginId).toBeUndefined();
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

  it('unknown kids trigger at most one JWKS refetch per window (no request amplification)', async () => {
    const { cfg: c, jwksFetch, token: t } = createTestCognito();
    let fetches = 0;
    let now = 1_000_000;
    const counting = (async (...a: Parameters<typeof fetch>) => (fetches++, jwksFetch(...a))) as typeof fetch;
    const v2 = new CognitoVerifier({ ...c, fetch: counting, now: () => now });
    await v2.verify(t({ exp: Math.floor(now / 1000) + 600 }));
    expect(fetches).toBe(1);
    for (let i = 0; i < 20; i++) await expect(v2.verify(t({}, { alg: 'RS256', kid: `forged-${i}` }))).rejects.toThrow(/unknown signing key/);
    expect(fetches).toBe(1);
    now += JWKS_MIN_REFETCH_MS;
    for (let i = 0; i < 5; i++) await expect(v2.verify(t({}, { alg: 'RS256', kid: 'forged-x' }))).rejects.toThrow(/unknown signing key/);
    expect(fetches).toBe(2);
  });
});
