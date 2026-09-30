import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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

  it('creates or imports a managed key only with the recorded consent of its owner (FR005-08)', async () => {
    const refused = await call('/v1/keys', 'POST', {});
    expect(refused.status).toBe(400);
    expect(refused.json.error).toMatch(/consent_version required/);
    expect((await call('/v1/keys', 'POST', { consent_version: '<script>' })).status).toBe(400);
    const password = 'contraseña larga 123';
    expect((await call('/v1/keys/import', 'POST', { ncryptsec: nip49.encryptKey(generateSecretKey(), password, 4), password })).status).toBe(400);
    const created = await call('/v1/keys', 'POST', { consent_version: 'textos 1.3.0; términos 2026-10' });
    expect(created.status).toBe(201);
    expect(created.json.consentVersion).toBe('textos 1.3.0; términos 2026-10');
    expect(created.json.consentAt).toBeTypeOf('number');
    expect(created.json.disclosure).toMatch(/descifra en el servidor sus mensajes directos \(NIP-44\)/);
  });

  it('lets an Acceso user create a custodial key and sign through the SDK client without leaking the secret', async () => {
    const created = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
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
    const { json: k } = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
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
    // Naming the victim as account is refused outright (FR005-12: for everyone).
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, tokenB(), { 'x-account-id': ownerA })).status).toBe(403);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, tokenA(), { 'x-account-id': ownerA })).status).toBe(403);
    // Tokens that are not valid Acceso tokens for this pool/client.
    const forged = acceso.token({ sub: 'user-a' }, undefined, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, forged)).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, acceso.token({ sub: 'user-a', exp: Math.floor(Date.now() / 1000) - 5 }))).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, acceso.token({ sub: 'user-a', aud: 'other-client' }))).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, 'service-token-0123456789')).status).toBe(401);
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
    const { json: k } = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
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

  it('cancels managed custody without migrating, confirmed with the npub, and lists the key until destruction (FR026-04)', async () => {
    const conn = { baseUrl: base, token: async () => tokenA() };
    const { json: k } = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
    const npub = nip19.npubEncode(k.pubkey);
    expect((await call(`/v1/keys/${k.keyId}/cancel`, 'POST', {})).status).toBe(400);
    expect((await call(`/v1/keys/${k.keyId}/cancel`, 'POST', { confirm: nip19.npubEncode(getPublicKey(generateSecretKey())) })).status).toBe(400);
    // Knowing the npub is not enough for another user.
    expect((await call(`/v1/keys/${k.keyId}/cancel`, 'POST', { confirm: npub }, tokenB())).status).toBe(403);

    const { destroyAfter } = await new ManagedSignerClient({ ...conn, keyId: k.keyId }).cancelCustody(npub);
    // Unusable at once, gone from the live keys, listed as closed (with when it is destroyed) for its owner only.
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } })).status).toBe(404);
    expect((await ManagedSignerClient.listKeys(conn)).map((x) => x.keyId)).not.toContain(k.keyId);
    const closed = (await ManagedSignerClient.closedKeys(conn)).find((x) => x.keyId === k.keyId);
    expect(closed).toEqual({ keyId: k.keyId, pubkey: k.pubkey, exit: 'cancelled', deletedAt: expect.any(Number), destroyAfter: Date.parse(destroyAfter) });
    expect((await call('/v1/keys/closed', 'GET', undefined, tokenB())).json.keys.map((x: { keyId: string }) => x.keyId)).not.toContain(k.keyId);
    expect((await call(`/v1/keys/${k.keyId}/cancel`, 'POST', { confirm: npub })).status).toBe(404);

    // A migrated key is not cancelled: its managed copy is deleted (FR026-03).
    const { json: m } = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
    const exp = await call(`/v1/keys/${m.keyId}/export`, 'POST', { password: 'una contraseña larga' });
    await call(`/v1/keys/${m.keyId}/confirm-migration`, 'POST', { proof: proofFor(nip49.decryptKey(exp.json.ncryptsec, 'una contraseña larga').secretKey, exp.json.challenge) });
    expect((await call(`/v1/keys/${m.keyId}/cancel`, 'POST', { confirm: nip19.npubEncode(m.pubkey) })).status).toBe(409);
    expect((await call(`/v1/keys/${m.keyId}`, 'DELETE')).status).toBe(200);
    expect((await ManagedSignerClient.closedKeys(conn)).find((x) => x.keyId === m.keyId)?.exit).toBe('migrated');
    expect(logs.some((r) => r.msg === 'managed key cancelled' && r.key_id === k.keyId)).toBe(true);
  });

  it('refuses the retired service-token mode: no x-account-id, and a service token is not a credential (FR005-12)', async () => {
    const tpl = { template: { kind: 1, content: 'hola' } };
    const k = (await call('/v1/keys', 'POST', { consent_version: 'textos test' }, tokenA())).json;
    // x-account-id is refused before anything else, whatever the credential.
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, 'service-token-0123456789', { 'x-account-id': ownerA })).status).toBe(403);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, tokenA(), { 'x-account-id': ownerA })).status).toBe(403);
    const session = (await call('/v1/device-sessions', 'POST', { device_id: 'phone-legacy' }, tokenA())).json.token as string;
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, session, { 'x-account-id': ownerA })).status).toBe(403);
    // Without it, a would-be service token is just an invalid bearer; the user's own credentials still sign.
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, 'service-token-0123456789')).status).toBe(401);
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', tpl, session)).status).toBe(200);
    // The service does not start with the old configuration instead of silently ignoring it.
    const run = spawnSync(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('../src/main.ts', import.meta.url))], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH, MANAGED_SIGNER_SERVICE_TOKENS: 'service-token-0123456789:saas-backend' },
      timeout: 60_000,
    });
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain('MANAGED_SIGNER_SERVICE_TOKENS: the legacy service mode was removed (FR005-12)');
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
    expect(await c.runRetention()).toEqual({ usagePurged: 0, keysDestroyed: 0, keysScrubbed: 0, sessionsPurged: 0 });
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

  it('destroys a cancelled key after the window, then clears its owner and consent (FR026-04)', async () => {
    let now = Date.UTC(2026, 0, 15);
    const vault = new MemoryVault();
    const registry = new MemoryKeyRegistry();
    const c = new ManagedSigner(vault, { registry, retentionDays: 30, now: () => now });
    const k = await c.create('o', 'p', { consentVersion: 'textos test' });
    await expect(c.cancel(k.keyId, 'o', 'p', 'npub1nada')).rejects.toThrow(/confirm must be the npub/);
    const { destroyAfter } = await c.cancel(k.keyId, 'o', 'p', nip19.npubEncode(k.pubkey));
    expect(destroyAfter).toBe(now + 30 * 86_400_000);
    expect(await c.closed('o')).toEqual([{ keyId: k.keyId, pubkey: k.pubkey, exit: 'cancelled', deletedAt: now, destroyAfter }]);

    now += 31 * 86_400_000;
    expect(await c.runRetention()).toMatchObject({ keysDestroyed: 1, keysScrubbed: 1 });
    expect(await vault.get(k.keyId)).toBeUndefined();
    const rec = (await registry.get(k.keyId))!;
    expect(rec).toMatchObject({ owner: '', exit: 'cancelled', destroyedAt: now, scrubbedAt: now });
    expect(rec.consentVersion).toBeUndefined();
    expect(rec.consentAt).toBeUndefined();
    expect(await c.closed('o')).toEqual([]);
    expect((await registry.usageOf(k.keyId)).map((u) => u.action)).toEqual(['created', 'cancelled', 'destroyed']);
    expect((await c.runRetention()).keysScrubbed).toBe(0);
  });

  it('lets the operator close every live key of an owner, as an ARCO cancellation (FR026-04)', async () => {
    const now = Date.UTC(2026, 0, 15);
    const registry = new MemoryKeyRegistry();
    const c = new ManagedSigner(new MemoryVault(), { registry, retentionDays: 30, now: () => now });
    const a = await c.create('o', 'p');
    const b = await c.create('o', 'p');
    await c.export(b.keyId, 'o', 'p', 'contraseña suficientemente larga', 4);
    const other = await c.create('otra', 'x');
    const closed = await c.closeOwner('o', 'operator:ARCO-7');
    expect(closed.map((x) => x.keyId).sort()).toEqual([a.keyId, b.keyId].sort());
    expect(closed.every((x) => x.destroyAfter === now + 30 * 86_400_000)).toBe(true);
    expect(await c.list('o')).toEqual([]);
    expect((await c.closed('o')).map((x) => x.exit)).toEqual(['cancelled', 'cancelled']);
    expect((await registry.usageOf(a.keyId)).at(-1)).toMatchObject({ action: 'cancelled', principal: 'operator:ARCO-7' });
    expect((await c.list('otra')).map((x) => x.keyId)).toEqual([other.keyId]);
    expect(await c.closeOwner('o', 'operator:ARCO-7')).toEqual([]);
  });
});
