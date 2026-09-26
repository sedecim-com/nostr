import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, generateSecretKey, getPublicKey, nip19, nip49, verifyEvent, finalizeEvent, toUnsigned } from '@sedecim/nostr-core';
import { ManagedSignerClient, LocalSigner } from '@sedecim/signer';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, LocalEnvelopeVault, ManagedSigner, MemoryVault } from '../src/index';

describe('managed-signer (FR-005, FR-026)', () => {
  const logs: LogRecord[] = [];
  let base: string;
  let dir: string;
  let vault: LocalEnvelopeVault;
  let core: ManagedSigner;
  let api: ReturnType<typeof createManagedSignerApi>;
  const TOKEN = 'test-token-0123456789';
  const call = (path: string, method = 'GET', body?: unknown, account = 'acct-1') =>
    fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${TOKEN}`, 'x-account-id': account, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vault-'));
    vault = new LocalEnvelopeVault(dir, new Uint8Array(32).fill(5));
    core = new ManagedSigner(vault, { retentionDays: 0 });
    api = createManagedSignerApi(core, { name: 'managed-signer-test', bearerTokens: { [TOKEN]: 'saas-backend' }, logger: createLogger({ write: (r) => logs.push(r), level: 'debug' }) });
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('creates custodial keys, signs through the SDK client and never leaks the secret', async () => {
    const created = await call('/v1/keys', 'POST', {});
    expect(created.status).toBe(201);
    expect(created.json.custodial).toBe(true);
    expect(created.json.disclosure).toMatch(/capacidad técnica de firmar/);
    const keyId = created.json.keyId as string;
    const client = new ManagedSignerClient({ baseUrl: base, keyId, authorization: () => `Bearer ${TOKEN}`, fetch: (u, i) => fetch(u, { ...i, headers: { ...(i?.headers as Record<string, string>), 'x-account-id': 'acct-1' } }) });
    const evt = await client.signEvent({ kind: 1, content: 'firmado por managed' });
    expect(verifyEvent(evt)).toBe(true);
    const peer = new LocalSigner(generateSecretKey());
    const ct = await client.nip44Encrypt(await peer.getPublicKey(), 'hola');
    expect(await peer.nip44Decrypt(evt.pubkey, ct)).toBe('hola');

    const secret = (await vault.get(keyId))!;
    const secretHex = bytesToHex(secret);
    const nsec = nip19.nsecEncode(secret);
    const everything = JSON.stringify(logs) + JSON.stringify(core.usage) + JSON.stringify([...core.keys.values()]);
    expect(everything).not.toContain(secretHex);
    expect(everything).not.toContain(nsec);
    for (const f of await readdir(dir)) expect(await readFile(join(dir, f), 'utf8')).not.toContain(secretHex);
    expect(core.usage.filter((u) => u.action === 'sign')).toHaveLength(1);
    expect((await call(`/v1/keys/${keyId}`, 'GET', undefined, 'other-account')).status).toBe(403);
    expect((await fetch(`${base}/v1/keys/${keyId}`)).status).toBe(401);
  });

  it('migrates managed → local with verification before deleting the managed copy', async () => {
    const { json: k } = await call('/v1/keys', 'POST', {});
    expect((await call(`/v1/keys/${k.keyId}`, 'DELETE')).status).toBe(409);
    expect((await call(`/v1/keys/${k.keyId}/export`, 'POST', { password: 'short' })).status).toBe(400);
    const exp = await call(`/v1/keys/${k.keyId}/export`, 'POST', { password: 'una contraseña larga' });
    expect(exp.status).toBe(200);
    const { secretKey } = nip49.decryptKey(exp.json.ncryptsec, 'una contraseña larga');
    expect(getPublicKey(secretKey)).toBe(k.pubkey);
    const wrongProof = finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', exp.json.challenge]] }, getPublicKey(generateSecretKey())), generateSecretKey());
    expect((await call(`/v1/keys/${k.keyId}/confirm-migration`, 'POST', { proof: wrongProof })).status).toBe(400);
    const proof = finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', exp.json.challenge]] }, k.pubkey), secretKey);
    expect((await call(`/v1/keys/${k.keyId}/confirm-migration`, 'POST', { proof })).json.state).toBe('migrated');
    expect((await call(`/v1/keys/${k.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } })).status).toBe(409);
    expect((await call(`/v1/keys/${k.keyId}`, 'DELETE')).json.deleted).toBe(true);
    expect(await vault.get(k.keyId)).toBeUndefined();
  });

  it('enforces the retention policy before deletion', async () => {
    let now = 1_000_000;
    const c = new ManagedSigner(new MemoryVault(), { retentionDays: 30, now: () => now });
    const k = await c.create('o', 'p');
    const { ncryptsec, challenge } = await c.export(k.keyId, 'o', 'p', 'contraseña suficientemente larga', 4);
    const sk = nip49.decryptKey(ncryptsec, 'contraseña suficientemente larga').secretKey;
    c.confirmMigration(k.keyId, 'o', 'p', finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', challenge]] }, k.pubkey), sk));
    await expect(c.delete(k.keyId, 'o', 'p')).rejects.toThrow(/retention/);
    now += 31 * 86_400_000;
    await c.delete(k.keyId, 'o', 'p');
  });
});
