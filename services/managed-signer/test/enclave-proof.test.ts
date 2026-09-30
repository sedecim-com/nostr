import { afterAll, describe, expect, it } from 'vitest';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey, getPublicKey, nip49 } from '@sedecim/nostr-core';
import { createLogger } from '@sedecim/telemetry-policy';
import { createAccesoPool } from './acceso-pool';
import {
  createManagedSignerApi,
  createSimulatedEnclave,
  EnclaveClient,
  EnclaveError,
  enclaveBackendFromEnv,
  exportConfigFromEnv,
  inProcessTransport,
  ManagedSigner,
  MemoryVault,
  ownerTag,
  PinnedJwksProofVerifier,
  proofVerifierFromEnv,
  UserProofError,
} from '../src/index';

/** FR005-09: what lets a key out of the enclave is the owner's own Acceso token, checked inside it. */

const pool = createAccesoPool();
const policy = { issuer: pool.issuer, clientId: pool.clientId, jwks: pool.jwks };
const verifier = () => new PinnedJwksProofVerifier(policy);
const nowS = () => Math.floor(Date.now() / 1000);
const ownerOf = (sub: string) => `${pool.issuer}#${sub}`;
const PASSWORD = 'una contraseña larga de exportación';
const refuses = async (p: Promise<unknown>) => {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(EnclaveError);
  return err as EnclaveError;
};

describe('PinnedJwksProofVerifier (FR005-09): the user pool keys pinned in the image', () => {
  const v = verifier();
  /** A token as issued and signed in at `at`, which is also when a test verifies it: no second of drift between them. */
  const tokenAt = (at: number, claims: Record<string, unknown> = {}, header?: Record<string, unknown>, key?: Parameters<typeof pool.token>[2]) => {
    const s = Math.floor(at / 1000);
    return pool.token({ iat: s, auth_time: s, exp: s + 600, ...claims }, header, key);
  };

  it('FR005-09: accepts an id token and an access token of the pool and names the owner as the managed-signer does', () => {
    const at = Date.now();
    const id = v.verify(tokenAt(at, { sub: 'ana', jti: 'j-1' }), at);
    expect(id).toMatchObject({ owner: ownerOf('ana'), jti: 'j-1' });
    expect(id.expiresAt).toBe(Math.floor(at / 1000) + 600);
    const access = v.verify(tokenAt(at, { sub: 'ana', token_use: 'access', client_id: pool.clientId, aud: undefined }), at);
    expect(access.owner).toBe(ownerOf('ana'));
  });

  it('FR005-09: refuses another issuer, another app client or an unknown token_use', () => {
    const at = Date.now();
    expect(() => v.verify(tokenAt(at, { iss: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OTHER' }), at)).toThrow(/wrong issuer/);
    expect(() => v.verify(tokenAt(at, { aud: 'another-client' }), at)).toThrow(/wrong audience/);
    expect(() => v.verify(tokenAt(at, { token_use: 'access', client_id: 'another-client' }), at)).toThrow(/wrong client/);
    expect(() => v.verify(tokenAt(at, { token_use: 'refresh' }), at)).toThrow(/token_use/);
  });

  it('FR005-09: refuses forged tokens: another key with the same kid, an unknown kid, alg none, HS256 keyed with the public key', () => {
    const at = Date.now();
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    expect(() => v.verify(tokenAt(at, {}, { alg: 'RS256', kid: 'k1' }, other), at)).toThrow(/bad signature/);
    expect(() => v.verify(tokenAt(at, {}, { alg: 'RS256', kid: 'k9' }), at)).toThrow(/unknown signing key/);
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const s = Math.floor(at / 1000);
    const claims = enc({ iss: pool.issuer, token_use: 'id', aud: pool.clientId, sub: 'ana', jti: 'j', exp: s + 600, iat: s, auth_time: s });
    expect(() => v.verify(`${enc({ alg: 'none', kid: 'k1' })}.${claims}.`, at)).toThrow(/unsupported token algorithm/);
    // The classic confusion: HS256 with the pool's public key as the secret.
    const secret = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
    const head = `${enc({ alg: 'HS256', kid: 'k1' })}.${claims}`;
    expect(() => v.verify(`${head}.${createHmac('sha256', secret).update(head).digest('base64url')}`, at)).toThrow(/unsupported token algorithm/);
  });

  it('FR005-09: refuses a payload changed after signing, and tokens that are not tokens', () => {
    const at = Date.now();
    const [h, p, s] = tokenAt(at, { sub: 'ana' }).split('.') as [string, string, string];
    const tampered = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString('utf8')), sub: 'root' })).toString('base64url');
    expect(() => v.verify(`${h}.${tampered}.${s}`, at)).toThrow(/bad signature/);
    for (const junk of ['', 'a.b', 'a.b.c.d', '!!.!!.!!', 'x'.repeat(9000)]) expect(() => v.verify(junk, at)).toThrow(UserProofError);
  });

  it('FR005-09: needs exp, iat, sub and a token id, all sane', () => {
    const at = Date.now();
    const s = Math.floor(at / 1000);
    expect(() => v.verify(tokenAt(at, { exp: s - 1 }), at)).toThrow(/expired/);
    expect(() => v.verify(tokenAt(at, { exp: undefined }), at)).toThrow(/expired/);
    expect(() => v.verify(tokenAt(at, { iat: s + 3600 }), at)).toThrow(/future/);
    expect(() => v.verify(tokenAt(at, { iat: undefined }), at)).toThrow(/future/);
    expect(() => v.verify(tokenAt(at, { sub: '' }), at)).toThrow(/subject/);
    expect(() => v.verify(tokenAt(at, { jti: undefined }), at)).toThrow(/token id/);
    expect(() => v.verify(tokenAt(at, { jti: 'j'.repeat(129) }), at)).toThrow(/token id/);
  });

  it('FR005-09: needs a password sign-in from the last 300 seconds, as the caller\'s clock sees it', () => {
    const at = Date.now();
    const s = Math.floor(at / 1000);
    expect(v.verify(tokenAt(at, { auth_time: s - 300 }), at).authTime).toBe(s - 300);
    expect(() => v.verify(tokenAt(at, { auth_time: s - 301 }), at)).toThrow(/older than 300 seconds/);
    expect(() => v.verify(tokenAt(at, { auth_time: undefined }), at)).toThrow(/sign-in time/);
    expect(() => v.verify(tokenAt(at, { auth_time: s + 3600 }), at)).toThrow(/future/);
    // A token fresh by this machine's clock is stale by the enclave's (the NSM) when that one is 10 minutes on.
    expect(() => v.verify(tokenAt(at, { exp: s + 3600 }), at + 10 * 60_000)).toThrow(/older than 300 seconds/);
    // The age limit is the pinned policy's.
    expect(() => new PinnedJwksProofVerifier({ ...policy, maxAgeSeconds: 60 }).verify(tokenAt(at, { auth_time: s - 61 }), at)).toThrow(/older than 60 seconds/);
  });

  it('FR005-09: refuses a policy that pins nothing usable', () => {
    expect(() => new PinnedJwksProofVerifier({ ...policy, jwks: { keys: [] } })).toThrow(/no RSA signing key/);
    expect(() => new PinnedJwksProofVerifier({ ...policy, jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'e1' }] } })).toThrow(/no RSA signing key/);
    const small = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey;
    expect(() => new PinnedJwksProofVerifier({ ...policy, jwks: { keys: [{ ...small.export({ format: 'jwk' }), kid: 's1' }] } })).toThrow(/shorter than 2048 bits/);
    expect(() => new PinnedJwksProofVerifier({ ...policy, jwks: { keys: [pool.jwks.keys[0]!, pool.jwks.keys[0]!] } })).toThrow(/listed twice/);
    expect(() => new PinnedJwksProofVerifier({ ...policy, issuer: 'http://insecure.example/pool' })).toThrow(/https/);
    expect(() => new PinnedJwksProofVerifier({ ...policy, clientId: '' })).toThrow(/clientId/);
    expect(() => new PinnedJwksProofVerifier({ ...policy, maxAgeSeconds: 0 })).toThrow(/maxAgeSeconds/);
  });
});

describe('export from the enclave (FR005-09)', () => {
  const setup = (opts: Parameters<typeof createSimulatedEnclave>[0] = {}) => {
    const sim = createSimulatedEnclave({ proof: verifier(), ...opts });
    return { sim, client: new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: sim.policy }) };
  };

  it('FR005-09: lets the owner\'s key out for the owner\'s fresh token, and the ncryptsec opens only with the export password', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const ncryptsec = await client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, pool.token({ sub: 'ana' }));
    expect(getPublicKey(nip49.decryptKey(ncryptsec, PASSWORD).secretKey)).toBe(pubkey);
    expect(() => nip49.decryptKey(ncryptsec, 'otra contraseña distinta')).toThrow();
  });

  it('FR005-09: without a proof the enclave refuses, whatever password the parent chooses', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    for (const proof of ['', undefined as unknown as string, 'not-a-token']) expect((await refuses(client.exportNcryptsec(sealed, pubkey, 'contraseña del atacante', 4, proof))).status).toBe(401);
  });

  it('FR005-09: an enclave with no verifier configured refuses every export, even with a valid token', async () => {
    const sim = createSimulatedEnclave({});
    const client = new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: sim.policy });
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const err = await refuses(client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, pool.token({ sub: 'ana' })));
    expect(err.status).toBe(403);
    expect(err.message).toMatch(/no verifier configured/);
  });

  it('FR005-09: a valid token of another user does not open this key', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const err = await refuses(client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, pool.token({ sub: 'beto' })));
    expect(err.status).toBe(403);
    expect(err.message).toMatch(/not from the owner/);
  });

  it('FR005-09: refuses forged, expired and stale-sign-in tokens', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const s = nowS();
    for (const token of [pool.token({ sub: 'ana' }, { alg: 'RS256', kid: 'k1' }, other), pool.token({ sub: 'ana', exp: s - 5 }), pool.token({ sub: 'ana', auth_time: s - 3600 })]) {
      expect((await refuses(client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, token))).status).toBe(401);
    }
  });

  it('FR005-09: judges freshness by the enclave\'s own clock (the NSM), not by anything the parent says', async () => {
    let clock = Date.now();
    const { client } = setup({ now: () => clock });
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    // Fresh by this machine's clock...
    const token = pool.token({ sub: 'ana', auth_time: nowS() - 100 });
    // ...and 250 seconds later by the enclave's: the sign-in is 350 seconds old there.
    clock += 250_000;
    const err = await refuses(client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, token));
    expect(err.status).toBe(401);
    expect(err.message).toMatch(/older than 300 seconds/);
  });

  it('FR005-09: accepts a token once: a replay is refused, a fresh sign-in works', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const token = pool.token({ sub: 'ana' });
    await client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, token);
    const err = await refuses(client.exportNcryptsec(sealed, pubkey, 'la contraseña del atacante', 4, token));
    expect(err.status).toBe(401);
    expect(err.message).toMatch(/already used/);
    await client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, pool.token({ sub: 'ana' }));
  });

  it('FR005-09: a token refused for not being the owner\'s is not spent', async () => {
    const { client } = setup();
    const ana = await client.generate(ownerOf('ana'));
    const beto = await client.generate(ownerOf('beto'));
    const betoToken = pool.token({ sub: 'beto' });
    await refuses(client.exportNcryptsec(ana.sealed, ana.pubkey, PASSWORD, 4, betoToken));
    await client.exportNcryptsec(beto.sealed, beto.pubkey, PASSWORD, 4, betoToken);
  });

  it('FR005-09: remembers the tokens it accepted up to a limit, refuses when full, and forgets the ones that expired', async () => {
    let clock = Date.now();
    const { client } = setup({ now: () => clock, maxRememberedProofs: 2 });
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const fresh = () => {
      const s = Math.floor(clock / 1000);
      return pool.token({ sub: 'ana', iat: s, auth_time: s, exp: s + 400 });
    };
    await client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, fresh());
    await client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, fresh());
    const full = await refuses(client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, fresh()));
    expect(full.status).toBe(403);
    expect(full.message).toMatch(/too many proofs/);
    // Once the first two have expired they are forgotten: the proof check passes and the export goes on to KMS, which
    // (simulated, on the real clock) refuses a document stamped this far ahead. Not "too many proofs" any more.
    clock += 401_000;
    const later = await refuses(client.exportNcryptsec(sealed, pubkey, PASSWORD, 4, fresh()));
    expect(later.status).toBeUndefined();
    expect(later.message).toMatch(/timestamp is in the future/);
  });

  it('FR005-09: a key sealed without an owner binding cannot be exported', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const blob = JSON.parse(Buffer.from(Buffer.from(sealed).toString('utf8'), 'base64').toString('utf8')) as Record<string, unknown>;
    const v1: Record<string, unknown> = { ...blob, v: 1 };
    delete v1.ot;
    const legacy = new Uint8Array(Buffer.from(Buffer.from(JSON.stringify(v1)).toString('base64')));
    const err = await refuses(client.exportNcryptsec(legacy, pubkey, PASSWORD, 4, pool.token({ sub: 'ana' })));
    expect(err.status).toBe(403);
    expect(err.message).toMatch(/no owner binding/);
  });

  it('FR005-09: rewriting the owner tag of a sealed key to match a token in hand does not open it', async () => {
    const { client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const blob = JSON.parse(Buffer.from(Buffer.from(sealed).toString('utf8'), 'base64').toString('utf8')) as Record<string, unknown>;
    const rebound = new Uint8Array(Buffer.from(Buffer.from(JSON.stringify({ ...blob, ot: ownerTag(ownerOf('beto')) })).toString('base64')));
    // Beto's token is valid and matches the rewritten tag, but the tag is inside the KMS context and the GCM AAD.
    const err = await refuses(client.exportNcryptsec(rebound, pubkey, PASSWORD, 4, pool.token({ sub: 'beto' })));
    expect(err.status).toBeUndefined();
    expect(err.message).toMatch(/enclave: /);
  });

  it('FR005-09: seals the owner as a hash: the KMS encryption context (written to CloudTrail) never names the Acceso account', async () => {
    const { sim, client } = setup();
    const seen: Array<Record<string, string>> = [];
    const generateDataKey = sim.kms.generateDataKey.bind(sim.kms);
    sim.kms.generateDataKey = async (req) => (seen.push(req.context), generateDataKey(req));
    const { pubkey } = await client.generate(ownerOf('ana'));
    expect(seen).toEqual([{ app: 'acceso-nostr', purpose: 'enclave-key', pubkey, owner_tag: ownerTag(ownerOf('ana')) }]);
    expect(JSON.stringify(seen)).not.toContain('ana');
    expect(JSON.stringify(seen)).not.toContain(pool.issuer);
  });

  it('FR005-09: creating or importing a key needs an owner', async () => {
    const { sim } = setup();
    expect(await sim.enclave.handle({ op: 'generate' } as never)).toMatchObject({ ok: false, status: 400 });
    const ncryptsec = nip49.encryptKey(generateSecretKey(), 'contraseña larga 123', 4);
    expect(await sim.enclave.handle({ op: 'import', ncryptsec, password: 'contraseña larga 123' } as never)).toMatchObject({ ok: false, status: 400 });
  });

  it('FR005-09: a wrong import password is the caller\'s error (400), not an enclave failure', async () => {
    const { client } = setup();
    const ncryptsec = nip49.encryptKey(generateSecretKey(), 'contraseña larga 123', 4);
    const err = await refuses(client.importNcryptsec(ownerOf('ana'), ncryptsec, 'otra contraseña larga'));
    expect(err.status).toBe(400);
  });
});

describe('the managed-signer API with the enclave tier (FR005-09)', () => {
  const acceso = createAccesoPool();
  const apiVerifier = new PinnedJwksProofVerifier({ issuer: acceso.issuer, clientId: acceso.clientId, jwks: acceso.jwks });
  const backend = enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SIMULATED: '1' }, () => {}, { proof: apiVerifier });
  const api = createManagedSignerApi(new ManagedSigner(new MemoryVault(), { sealedKeys: backend!.client, retentionDays: 0 }), { name: 'managed-signer-proof-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
  let base: string;
  const call = (token: string, path: string, method = 'GET', body?: unknown) =>
    fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: (await r.json()) as Record<string, string> }));
  afterAll(() => api.close());

  it('FR005-09: the token that authenticated the export travels to the enclave as its proof; the same token cannot export twice', async () => {
    base = await api.listen();
    const created = await call(acceso.token({ sub: 'ana' }), '/v1/keys', 'POST', { consent_version: 'textos test' });
    expect(created.status).toBe(201);
    const token = acceso.token({ sub: 'ana' });
    const first = await call(token, `/v1/keys/${created.json.keyId}/export`, 'POST', { password: PASSWORD });
    expect(first.status).toBe(200);
    expect(getPublicKey(nip49.decryptKey(first.json.ncryptsec!, PASSWORD).secretKey)).toBe(created.json.pubkey);
    const replay = await call(token, `/v1/keys/${created.json.keyId}/export`, 'POST', { password: 'la contraseña de quien lo repite' });
    expect(replay.status).toBe(401);
    expect(replay.json.error).toMatch(/already used/);
  });
});

describe('configuration of the pinned user pool (FR005-09)', () => {
  let dir: string | undefined;
  afterAll(async () => dir && rm(dir, { recursive: true, force: true }));
  const writeJwks = async () => {
    dir ??= await mkdtemp(join(tmpdir(), 'enclave-proof-'));
    const jwksPath = join(dir, 'jwks.json');
    await writeFile(jwksPath, JSON.stringify(pool.jwks));
    return jwksPath;
  };

  it('FR005-09: an enclave image asked to export without the user pool pinned does not start', async () => {
    const jwks = await writeJwks();
    const pinned = { ENCLAVE_PROOF_ISSUER: pool.issuer, ENCLAVE_PROOF_CLIENT_ID: pool.clientId, ENCLAVE_PROOF_JWKS: jwks };
    expect(() => exportConfigFromEnv({ ENCLAVE_ALLOW_EXPORT: '1' })).toThrow(/needs ENCLAVE_PROOF_ISSUER/);
    expect(() => exportConfigFromEnv({ ENCLAVE_ALLOW_EXPORT: '1', ENCLAVE_PROOF_ISSUER: pool.issuer })).toThrow(/go together/);
    expect(exportConfigFromEnv({ ENCLAVE_ALLOW_EXPORT: '1', ...pinned })).toMatchObject({ allowExport: true, proof: expect.any(PinnedJwksProofVerifier) });
    expect(exportConfigFromEnv({})).toEqual({ allowExport: false });
    expect(exportConfigFromEnv(pinned).allowExport).toBe(false);
    const now = Date.now();
    const s = Math.floor(now / 1000);
    const strict = proofVerifierFromEnv({ ...pinned, ENCLAVE_PROOF_MAX_AGE_S: '60' }, 'ENCLAVE_PROOF')!;
    expect(() => strict.verify(pool.token({ iat: s, auth_time: s - 61 }), now)).toThrow(/older than 60 seconds/);
  });

  it('FR005-09: the simulated enclave of a development backend takes the pool from MANAGED_SIGNER_ENCLAVE_PROOF_*, or refuses to export', async () => {
    const jwks = await writeJwks();
    const env = { MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SIMULATED: '1' };
    const pinned = { ...env, MANAGED_SIGNER_ENCLAVE_PROOF_ISSUER: pool.issuer, MANAGED_SIGNER_ENCLAVE_PROOF_CLIENT_ID: pool.clientId, MANAGED_SIGNER_ENCLAVE_PROOF_JWKS: jwks };
    const { client } = enclaveBackendFromEnv(pinned, () => {})!;
    const k = await client.generate(ownerOf('ana'));
    const ncryptsec = await client.exportNcryptsec(k.sealed, k.pubkey, PASSWORD, 4, pool.token({ sub: 'ana' }));
    expect(getPublicKey(nip49.decryptKey(ncryptsec, PASSWORD).secretKey)).toBe(k.pubkey);
    const bare = enclaveBackendFromEnv(env, () => {})!.client;
    const b = await bare.generate(ownerOf('ana'));
    await expect(bare.exportNcryptsec(b.sealed, b.pubkey, PASSWORD, 4, pool.token({ sub: 'ana' }))).rejects.toThrow(/no verifier configured/);
  });
});
