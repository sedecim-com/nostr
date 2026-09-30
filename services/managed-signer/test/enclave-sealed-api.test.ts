/**
 * FR005-10: the managed-signer API with secrets sealed to the enclave. The client asks for an attestation with a nonce
 * of its own (GET /v1/enclave/attestation), verifies it, seals, and sends `sealed_secrets` (import) or
 * `sealed_password` (export) instead of the secrets; the service relays them as they are.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey, nip49 } from '@sedecim/nostr-core';
import { ManagedSignerClient, ManagedSignerHttpError, sealToEnclave, verifyNitroAttestation } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { createAccesoPool } from './acceso-pool';
import { createManagedSignerApi, createSimulatedEnclave, EnclaveClient, inProcessTransport, ManagedSigner, MemoryVault, ownerTag, PinnedJwksProofVerifier, type EnclaveRequest, type EnclaveTransport } from '../src/index';

const acceso = createAccesoPool();
const verifier = new PinnedJwksProofVerifier({ issuer: acceso.issuer, clientId: acceso.clientId, jwks: acceso.jwks });
const OWNER = `${acceso.issuer}#ana`;
const IMPORT_PASSWORD = 'contraseña de importación';
const EXPORT_PASSWORD = 'contraseña de exportación larga';
const token = (claims: Record<string, unknown> = {}) => acceso.token({ sub: 'ana', ...claims });

/** An API over the simulated enclave; `frames` is every request that reached the enclave. */
function stack(opts: { requireSealedSecrets?: boolean } = {}) {
  const sim = createSimulatedEnclave({ proof: verifier });
  const frames: EnclaveRequest[] = [];
  const inner = inProcessTransport(sim.enclave);
  const transport: EnclaveTransport = { request: (req) => (frames.push(req), inner.request(req)) };
  const vault = new MemoryVault();
  const core = new ManagedSigner(vault, { sealedKeys: new EnclaveClient({ transport, attestation: sim.policy, provider: 'simulated-enclave' }), retentionDays: 0, ...(opts.requireSealedSecrets ? { requireSealedSecrets: true } : {}) });
  const api = createManagedSignerApi(core, { name: 'managed-signer-sealed-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
  const ops = () => frames.filter((f) => f.op === 'import' || f.op === 'export').length;
  return { sim, frames, ops, vault, core, api, base: '' };
}
type Stack = ReturnType<typeof stack>;

// One connection per request: an export's scrypt keeps this single process busy for seconds, and a pooled socket the
// test server closes meanwhile (Node's 5 s keep-alive) would reset the next request.
const call = (s: Stack, path: string, method = 'GET', body?: unknown, bearer = token()) =>
  fetch(`${s.base}${path}`, { method, headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json', connection: 'close' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: (await r.json()) as Record<string, string> }));

/** What the client does: its own nonce, and the document checked against the enclave it trusts. */
async function attested(s: Stack) {
  const nonce = randomBytes(32);
  const r = await call(s, `/v1/enclave/attestation?nonce=${nonce.toString('base64url')}`);
  expect(r.status).toBe(200);
  const att = verifyNitroAttestation(new Uint8Array(Buffer.from(r.json.document!, 'base64')), { trustedRootFingerprints: s.sim.policy.trustedRootFingerprints, expectedPcrs: s.sim.policy.expectedPcrs, expectedNonce: nonce, requirePublicKey: true });
  return { spki: att.publicKey!, at: att.timestamp };
}
const sealedImport = async (s: Stack, ncryptsec: string, password = IMPORT_PASSWORD, owner = OWNER) => {
  const { spki, at } = await attested(s);
  return sealToEnclave(spki, { purpose: 'import', ownerTag: ownerTag(owner), at, ncryptsec, password });
};
const sealedExport = async (s: Stack, pubkey: string, password = EXPORT_PASSWORD) => {
  const { spki, at } = await attested(s);
  return sealToEnclave(spki, { purpose: 'export', ownerTag: ownerTag(OWNER), pubkey, at, password });
};

describe('managed-signer API with secrets sealed to the enclave', () => {
  const s = stack();
  beforeAll(async () => {
    s.base = await s.api.listen();
  });
  afterAll(() => s.api.close());

  it('FR005-10: GET /v1/enclave/attestation answers the enclave\'s document for the caller\'s own nonce', async () => {
    const nonce = randomBytes(24);
    const r = await call(s, `/v1/enclave/attestation?nonce=${nonce.toString('base64url')}`);
    expect(r.status).toBe(200);
    const att = verifyNitroAttestation(new Uint8Array(Buffer.from(r.json.document!, 'base64')), { trustedRootFingerprints: s.sim.policy.trustedRootFingerprints, expectedPcrs: s.sim.policy.expectedPcrs, expectedNonce: nonce, requirePublicKey: true });
    expect(att.publicKey!.length).toBeGreaterThan(200);
    for (const bad of ['', 'nonce=', `nonce=${randomBytes(15).toString('base64url')}`, `nonce=${randomBytes(65).toString('base64url')}`, `nonce=${randomBytes(32).toString('base64')}==`, 'nonce=%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F']) {
      expect((await call(s, `/v1/enclave/attestation?${bad}`)).status).toBe(400);
    }
    const anonymous = await fetch(`${s.base}/v1/enclave/attestation?nonce=${nonce.toString('base64url')}`);
    expect(anonymous.status).toBe(401);
  });

  it('FR005-10: POST /v1/keys/import with sealed_secrets: the key is imported for the caller, sealed for the owner of the envelope', async () => {
    const sk = generateSecretKey();
    const envelope = await sealedImport(s, nip49.encryptKey(sk, IMPORT_PASSWORD, 4));
    const r = await call(s, '/v1/keys/import', 'POST', { sealed_secrets: envelope, consent_version: 'textos test' });
    expect(r.status).toBe(201);
    // The same envelope sent again (within its minutes) gives the same key, and the registry already has it.
    expect((await call(s, '/v1/keys/import', 'POST', { sealed_secrets: envelope, consent_version: 'textos test' })).status).toBe(409);
    expect(r.json.pubkey).toBe(getPublicKey(sk));
    expect(r.json.owner).toBe(OWNER);
    expect(r.json.custody).toBe('managed-enclave');
    const blob = JSON.parse(Buffer.from(Buffer.from((await s.vault.get(r.json.keyId!))!).toString('utf8'), 'base64').toString('utf8')) as { ot: string };
    expect(blob.ot).toBe(ownerTag(OWNER));
    // Sealed for another owner, it does not open for this caller: the owner is in the AAD.
    const other = await call(s, '/v1/keys/import', 'POST', { sealed_secrets: await sealedImport(s, nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4), IMPORT_PASSWORD, `${acceso.issuer}#beto`), consent_version: 'textos test' });
    expect(other.status).toBe(400);
    expect(other.json.error).toMatch(/does not open/);
  });

  it('FR005-10: POST /v1/keys/:id/export with sealed_password: the ncryptsec opens with that password', async () => {
    const created = await call(s, '/v1/keys', 'POST', { consent_version: 'textos test' });
    const r = await call(s, `/v1/keys/${created.json.keyId}/export`, 'POST', { sealed_password: await sealedExport(s, created.json.pubkey!) });
    expect(r.status).toBe(200);
    expect(getPublicKey(nip49.decryptKey(r.json.ncryptsec!, EXPORT_PASSWORD).secretKey)).toBe(created.json.pubkey);
    expect(r.json.challenge).toMatch(/^[0-9a-f]{32}$/);
  });

  it('FR005-10: in clear or sealed, never both nor neither (400)', async () => {
    const ncryptsec = nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4);
    const both = await call(s, '/v1/keys/import', 'POST', { ncryptsec, password: IMPORT_PASSWORD, sealed_secrets: await sealedImport(s, ncryptsec), consent_version: 'textos test' });
    expect(both.status).toBe(400);
    expect(both.json.error).toMatch(/not both/);
    expect((await call(s, '/v1/keys/import', 'POST', { consent_version: 'textos test' })).status).toBe(400);
    expect((await call(s, '/v1/keys/import', 'POST', { sealed_secrets: 42, consent_version: 'textos test' })).status).toBe(400);
    expect((await call(s, '/v1/keys/import', 'POST', { sealed_secrets: 'x'.repeat(5000), consent_version: 'textos test' })).status).toBe(400);
    const created = await call(s, '/v1/keys', 'POST', { consent_version: 'textos test' });
    const bothExport = await call(s, `/v1/keys/${created.json.keyId}/export`, 'POST', { password: EXPORT_PASSWORD, sealed_password: await sealedExport(s, created.json.pubkey!) });
    expect(bothExport.status).toBe(400);
    expect(bothExport.json.error).toMatch(/not both/);
    expect((await call(s, `/v1/keys/${created.json.keyId}/export`, 'POST', {})).status).toBe(400);
  });

  it('FR005-10: the rules of both modes are the same: consent to import, a recent Acceso sign-in and never a device session to export', async () => {
    const ncryptsec = nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4);
    const noConsent = await call(s, '/v1/keys/import', 'POST', { sealed_secrets: await sealedImport(s, ncryptsec) });
    expect(noConsent.status).toBe(400);
    expect(noConsent.json.error).toMatch(/consent_version/);
    const created = await call(s, '/v1/keys', 'POST', { consent_version: 'textos test' });
    const envelope = await sealedExport(s, created.json.pubkey!);
    const stale = await call(s, `/v1/keys/${created.json.keyId}/export`, 'POST', { sealed_password: envelope }, token({ auth_time: Math.floor(Date.now() / 1000) - 3600 }));
    expect(stale.status).toBe(401);
    expect(stale.json.error_code).toBe('insufficient_user_authentication');
    const session = await call(s, '/v1/device-sessions', 'POST', { device_id: 'navegador-1' });
    const viaSession = await call(s, `/v1/keys/${created.json.keyId}/export`, 'POST', { sealed_password: envelope }, session.json.token);
    expect(viaSession.status).toBe(401);
  });
});

describe('managed-signer with MANAGED_SIGNER_REQUIRE_SEALED_SECRETS', () => {
  const s = stack({ requireSealedSecrets: true });
  beforeAll(async () => {
    s.base = await s.api.listen();
  });
  afterAll(() => s.api.close());

  it('FR005-10: secrets in clear are refused (400) before anything reaches the enclave; sealed ones go through', async () => {
    const sk = generateSecretKey();
    const ncryptsec = nip49.encryptKey(sk, IMPORT_PASSWORD, 4);
    const before = s.ops();
    const clearImport = await call(s, '/v1/keys/import', 'POST', { ncryptsec, password: IMPORT_PASSWORD, consent_version: 'textos test' });
    expect(clearImport.status).toBe(400);
    expect(clearImport.json.error).toMatch(/MANAGED_SIGNER_REQUIRE_SEALED_SECRETS/);
    const imported = await call(s, '/v1/keys/import', 'POST', { sealed_secrets: await sealedImport(s, ncryptsec), consent_version: 'textos test' });
    expect(imported.status).toBe(201);
    const clearExport = await call(s, `/v1/keys/${imported.json.keyId}/export`, 'POST', { password: EXPORT_PASSWORD });
    expect(clearExport.status).toBe(400);
    // Only the sealed import reached the enclave.
    expect(s.ops()).toBe(before + 1);
    const exported = await call(s, `/v1/keys/${imported.json.keyId}/export`, 'POST', { sealed_password: await sealedExport(s, getPublicKey(sk)) });
    expect(exported.status).toBe(200);
    expect(exported.json.ncryptsec).toMatch(/^ncryptsec1/);
  });

  it('FR005-10: the switch needs the enclave tier: with the vault one it would refuse every import and export', () => {
    expect(() => new ManagedSigner(new MemoryVault(), { requireSealedSecrets: true })).toThrow(/enclave tier/);
  });
});

describe('managed-signer on the vault tier (no enclave)', () => {
  const core = new ManagedSigner(new MemoryVault(), { retentionDays: 0 });
  const api = createManagedSignerApi(core, { name: 'managed-signer-vault-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
  const s = { base: '' } as Stack;
  beforeAll(async () => {
    s.base = await api.listen();
  });
  afterAll(() => api.close());

  it('FR005-10: has no attestation (404) and refuses sealed secrets with 400: it decrypts in its own process, where sealing protects nothing', async () => {
    expect((await call(s, `/v1/enclave/attestation?nonce=${randomBytes(32).toString('base64url')}`)).status).toBe(404);
    const imp = await call(s, '/v1/keys/import', 'POST', { sealed_secrets: 'ae1.AAAA.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAA', consent_version: 'textos test' });
    expect(imp.status).toBe(400);
    expect(imp.json.error).toMatch(/need the enclave tier/);
    const created = await call(s, '/v1/keys', 'POST', { consent_version: 'textos test' });
    const exp = await call(s, `/v1/keys/${created.json.keyId}/export`, 'POST', { sealed_password: 'ae1.AAAA.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAA' });
    expect(exp.status).toBe(400);
    expect(exp.json.error).toMatch(/need the enclave tier/);
    // Secrets in clear work there as before.
    const sk = generateSecretKey();
    const clear = await call(s, '/v1/keys/import', 'POST', { ncryptsec: nip49.encryptKey(sk, IMPORT_PASSWORD, 4), password: IMPORT_PASSWORD, consent_version: 'textos test' });
    expect(clear.status).toBe(201);
    expect(clear.json.pubkey).toBe(getPublicKey(sk));
  });

  it('FR005-10: without enclave, the client imports as the API always took it: ncryptsec and password in the request', async () => {
    const posted: string[] = [];
    const f: typeof fetch = (input, init) => (typeof init?.body === 'string' && posted.push(init.body), fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), connection: 'close' } }));
    const sk = generateSecretKey();
    const ncryptsec = nip49.encryptKey(sk, IMPORT_PASSWORD, 4);
    const key = await ManagedSignerClient.importEncrypted({ baseUrl: s.base, token: async () => token(), fetch: f }, ncryptsec, IMPORT_PASSWORD, { consentVersion: 'textos test' });
    expect(key.pubkey).toBe(getPublicKey(sk));
    expect(posted).toEqual([JSON.stringify({ ncryptsec, password: IMPORT_PASSWORD, consent_version: 'textos test' })]);
  });

  it('FR005-10: a client told to seal to an enclave stops at the 404 and does not fall back to sending the password in clear', async () => {
    const created = await call(s, '/v1/keys', 'POST', { consent_version: 'textos test' });
    const posted: string[] = [];
    const f: typeof fetch = (input, init) => (typeof init?.body === 'string' && posted.push(init.body), fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), connection: 'close' } }));
    const client = new ManagedSignerClient({ baseUrl: s.base, token: async () => token(), fetch: f, keyId: created.json.keyId! });
    const err = await client.exportForMigration(EXPORT_PASSWORD, { enclave: { pcrs: { 0: 'a'.repeat(96), 1: 'b'.repeat(96), 2: 'c'.repeat(96) } } }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ManagedSignerHttpError);
    expect((err as ManagedSignerHttpError).status).toBe(404);
    expect(posted).toEqual([]);
  });
});
