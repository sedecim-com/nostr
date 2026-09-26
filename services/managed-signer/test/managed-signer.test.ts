import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, generateSecretKey, getPublicKey, nip19, nip49, verifyEvent, finalizeEvent, toUnsigned } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient, LocalSigner } from '@sedecim/signer';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, LocalEnvelopeVault, ManagedSigner, MemoryKeyRegistry, MemoryVault } from '../src/index';

const acceso = createTestCognito();
const WEB = 'https://nostr.acce.so';
const tokenA = () => acceso.token({ sub: 'user-a' });
const tokenB = () => acceso.token({ sub: 'user-b', 'cognito:username': 'beto' });
const ownerA = `${acceso.issuer}#user-a`;

describe('managed-signer (FR-005, FR-026)', () => {
  const logs: LogRecord[] = [];
  let base: string;
  let dir: string;
  let vault: LocalEnvelopeVault;
  let registry: MemoryKeyRegistry;
  let api: ReturnType<typeof createManagedSignerApi>;
  const call = (path: string, method = 'GET', body?: unknown, token = tokenA(), extra: Record<string, string> = {}) =>
    fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...extra }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({
      status: r.status,
      headers: r.headers,
      json: await r.json(),
    }));
  const proofFor = (secretKey: Uint8Array, challenge: string) => finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', challenge]] }, getPublicKey(secretKey)), secretKey);

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vault-'));
    vault = new LocalEnvelopeVault(dir, new Uint8Array(32).fill(5));
    registry = new MemoryKeyRegistry();
    const core = new ManagedSigner(vault, { registry, retentionDays: 0 });
    api = createManagedSignerApi(core, { name: 'managed-signer-test', cognito: acceso.verifier(), corsOrigins: [WEB], logger: createLogger({ write: (r) => logs.push(r), level: 'debug' }) });
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('lets an Acceso user create a custodial key and sign through the SDK client without leaking the secret', async () => {
    const created = await call('/v1/keys', 'POST', {});
    expect(created.status).toBe(201);
    expect(created.json.custodial).toBe(true);
    expect(created.json.owner).toBe(ownerA);
    expect(created.json.disclosure).toMatch(/capacidad técnica de firmar/);
    const keyId = created.json.keyId as string;
    let tokenCalls = 0;
    const client = new ManagedSignerClient({ baseUrl: base, keyId, token: async () => (tokenCalls++, tokenA()) });
    const evt = await client.signEvent({ kind: 1, content: 'firmado por managed' });
    expect(verifyEvent(evt)).toBe(true);
    expect(tokenCalls).toBeGreaterThanOrEqual(2);
    const peer = new LocalSigner(generateSecretKey());
    const ct = await client.nip44Encrypt(await peer.getPublicKey(), 'hola');
    expect(await peer.nip44Decrypt(evt.pubkey, ct)).toBe('hola');
    expect((await ManagedSignerClient.listKeys({ baseUrl: base, token: async () => tokenA() })).map((k) => k.keyId)).toContain(keyId);

    const usage = (await call(`/v1/keys/${keyId}/usage`)).json.usage as Array<{ action: string; principal: string }>;
    expect(usage.map((u) => u.action)).toEqual(['created', 'sign', 'nip44_encrypt']);
    expect(usage.every((u) => u.principal === ownerA)).toBe(true);

    const secret = (await vault.get(keyId))!;
    const secretHex = bytesToHex(secret);
    const nsec = nip19.nsecEncode(secret);
    const everything = JSON.stringify(logs) + JSON.stringify(registry.usage) + JSON.stringify([...registry.keys.values()]);
    expect(everything).not.toContain(secretHex);
    expect(everything).not.toContain(nsec);
    for (const f of await readdir(dir)) expect(await readFile(join(dir, f), 'utf8')).not.toContain(secretHex);
  });

  it('rejects impersonation: other users, forged or expired tokens and x-account-id from end users', async () => {
    const { json: k } = await call('/v1/keys', 'POST', {});
    const tpl = { template: { kind: 1, content: 'x' } };
    const peer = getPublicKey(generateSecretKey());
    // Another Acceso user can neither use, describe, export nor delete it.
    for (const [path, method, body] of [
      [`/v1/keys/${k.keyId}`, 'GET', undefined],
      [`/v1/keys/${k.keyId}/sign`, 'POST', tpl],
      [`/v1/keys/${k.keyId}/nip44/encrypt`, 'POST', { peer, plaintext: 'x' }],
      [`/v1/keys/${k.keyId}/export`, 'POST', { password: 'una contraseña larga' }],
      [`/v1/keys/${k.keyId}/confirm-migration`, 'POST', { proof: {} }],
      [`/v1/keys/${k.keyId}`, 'DELETE', undefined],
      [`/v1/keys/${k.keyId}/usage`, 'GET', undefined],
    ] as const) {
      expect((await call(path, method, body, tokenB())).status, `${method} ${path}`).toBe(403);
    }
    expect((await call('/v1/keys', 'GET', undefined, tokenB())).json.keys).toEqual([]);
    // Naming the victim as account is refused outright for end users.
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, tokenB(), { 'x-account-id': ownerA })).status).toBe(403);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, tokenA(), { 'x-account-id': ownerA })).status).toBe(403);
    // Tokens that are not valid Acceso tokens for this pool/client.
    const forged = acceso.token({ sub: 'user-a' }, undefined, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, forged)).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, acceso.token({ sub: 'user-a', exp: Math.floor(Date.now() / 1000) - 5 }))).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, acceso.token({ sub: 'user-a', aud: 'other-client' }))).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, 'service-token-0123456789', { 'x-account-id': ownerA })).status).toBe(401);
    expect((await fetch(`${base}/v1/keys/${k.keyId}`)).status).toBe(401);
    // The owner still can.
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl)).status).toBe(200);
  });

  it('answers CORS preflights only for the configured web origin', async () => {
    const pre = await fetch(`${base}/v1/keys`, { method: 'OPTIONS', headers: { origin: WEB, 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization, content-type' } });
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-origin')).toBe(WEB);
    expect(pre.headers.get('access-control-allow-headers')).toMatch(/authorization/);
    expect((await fetch(`${base}/v1/keys`, { method: 'OPTIONS', headers: { origin: 'https://evil.example' } })).status).toBe(403);
    const r = await call('/v1/keys', 'GET', undefined, tokenA(), { origin: WEB });
    expect(r.headers.get('access-control-allow-origin')).toBe(WEB);
  });

  it('migrates managed → local with verification before deleting the managed copy', async () => {
    const { json: k } = await call('/v1/keys', 'POST', {});
    expect((await call(`/v1/keys/${k.keyId}`, 'DELETE')).status).toBe(409);
    expect((await call(`/v1/keys/${k.keyId}/export`, 'POST', { password: 'short' })).status).toBe(400);
    const exp = await call(`/v1/keys/${k.keyId}/export`, 'POST', { password: 'una contraseña larga' });
    expect(exp.status).toBe(200);
    const { secretKey } = nip49.decryptKey(exp.json.ncryptsec, 'una contraseña larga');
    expect(getPublicKey(secretKey)).toBe(k.pubkey);
    expect((await call(`/v1/keys/${k.keyId}/confirm-migration`, 'POST', { proof: proofFor(generateSecretKey(), exp.json.challenge) })).status).toBe(400);
    expect((await call(`/v1/keys/${k.keyId}/confirm-migration`, 'POST', { proof: proofFor(secretKey, exp.json.challenge) })).json.state).toBe('migrated');
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } })).status).toBe(409);
    const del = await call(`/v1/keys/${k.keyId}`, 'DELETE');
    expect(del.json.deleted).toBe(true);
    expect(Date.parse(del.json.destroy_after)).toBeGreaterThan(0);
    expect((await call(`/v1/keys/${k.keyId}`)).status).toBe(404);
  });

  it('keeps the legacy service-token mode only when enabled, with x-account-id', async () => {
    const SERVICE = 'service-token-0123456789';
    const svcApi = createManagedSignerApi(new ManagedSigner(new MemoryVault()), { name: 'managed-signer-legacy', logger: createLogger({ write: () => {} }), serviceTokens: { [SERVICE]: 'saas-backend' }, cognito: acceso.verifier() });
    const svcBase = await svcApi.listen();
    try {
      const req = (path: string, method: string, headers: Record<string, string>, body?: unknown) =>
        fetch(`${svcBase}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));
      const created = await req('/v1/keys', 'POST', { authorization: `Bearer ${SERVICE}`, 'x-account-id': 'acct-1' }, {});
      expect(created.status).toBe(201);
      expect(created.json.owner).toBe('acct-1');
      expect((await req('/v1/keys', 'POST', { authorization: `Bearer ${SERVICE}` }, {})).status).toBe(400);
      expect((await req(`/v1/keys/${created.json.keyId}`, 'GET', { authorization: `Bearer ${SERVICE}`, 'x-account-id': 'acct-2' })).status).toBe(403);
      // An Acceso user whose sub equals the account id still cannot reach it: owners are issuer-scoped.
      expect((await req(`/v1/keys/${created.json.keyId}`, 'GET', { authorization: `Bearer ${acceso.token({ sub: 'acct-1' })}` })).status).toBe(403);
    } finally {
      await svcApi.close();
    }
  });
});

describe('managed-signer retention (DEC-09)', () => {
  it('keeps the material for the retention window after deletion, then destroys it; purges usage after 12 months', async () => {
    let now = Date.UTC(2026, 0, 15);
    const vault = new MemoryVault();
    const registry = new MemoryKeyRegistry();
    const c = new ManagedSigner(vault, { registry, retentionDays: 30, now: () => now });
    const k = await c.create('o', 'p');
    const { ncryptsec, challenge } = await c.export(k.keyId, 'o', 'p', 'contraseña suficientemente larga', 4);
    const sk = nip49.decryptKey(ncryptsec, 'contraseña suficientemente larga').secretKey;
    await c.confirmMigration(k.keyId, 'o', 'p', finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', challenge]] }, k.pubkey), sk));
    const { destroyAfter } = await c.delete(k.keyId, 'o', 'p');
    expect(destroyAfter).toBe(now + 30 * 86_400_000);
    await expect(c.describe(k.keyId, 'o')).rejects.toThrow(/unknown key/);

    now += 29 * 86_400_000;
    expect(await c.runRetention()).toEqual({ usagePurged: 0, keysDestroyed: 0 });
    expect(await vault.get(k.keyId)).toBeDefined();

    now += 2 * 86_400_000;
    expect((await c.runRetention()).keysDestroyed).toBe(1);
    expect(await vault.get(k.keyId)).toBeUndefined();
    expect((await registry.get(k.keyId))!.destroyedAt).toBe(now);
    expect((await c.runRetention()).keysDestroyed).toBe(0);

    const actions = (await registry.usageOf(k.keyId)).map((u) => u.action);
    expect(actions).toEqual(['created', 'export', 'migration-confirmed', 'deleted', 'destroyed']);
    now = Date.UTC(2027, 0, 20);
    expect((await c.runRetention()).usagePurged).toBe(4);
    expect((await registry.usageOf(k.keyId)).map((u) => u.action)).toEqual(['destroyed']);
  });
});
