import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { archiveOwnerPubkey } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { CONTINUITY_VAULT_TEXTS } from '@sedecim/profiles';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const RELAY_ONION = 'vaultrelay' + 'a'.repeat(46) + '.onion';
const VAULT_ONION = 'continuityvault' + 'b'.repeat(41) + '.onion';
const silent = createLogger({ write: () => {} });
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

/** A real CLI process, without blocking this process (the vault under test runs here). */
function run(args: string[], env: NodeJS.ProcessEnv): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

async function objectsText(objects: MemoryObjectStore): Promise<string> {
  const out: string[] = [];
  for await (const k of objects.list()) out.push(new TextDecoder().decode((await objects.get(k))!));
  return out.join('\n');
}

describe('sovereign client and the Continuity Vault (VAULT-02)', () => {
  const relay = new TestRelay({ requireAuth: true });
  const onionRelay = new TestRelay({ publicUrl: `ws://${RELAY_ONION}` });
  const repo = new MemoryArchiveRepository();
  const objects = new MemoryObjectStore();
  const vault = createContinuityVaultApi(repo, objects, { name: 'vault-cli', logger: silent });
  const onionRepo = new MemoryArchiveRepository();
  const onionVault = createContinuityVaultApi(onionRepo, new MemoryObjectStore(), { name: 'vault-onion', publicBaseUrl: `http://${VAULT_ONION}`, logger: silent });
  let vaultUrl: string;
  let socks: TestSocksServer;
  const clients: SovereignClient[] = [];
  const newClient = async (socksPort = socks.port) => {
    const c = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-vault-')), passphrase: 'pass', scryptLogN: 4, socksPort, retry: { baseMs: 20, maxMs: 50 } });
    clients.push(c);
    return c;
  };

  beforeAll(async () => {
    await relay.start();
    await onionRelay.start();
    vaultUrl = await vault.listen();
    const onionPort = Number(new URL(await onionVault.listen()).port);
    socks = new TestSocksServer({ [RELAY_ONION]: { host: '127.0.0.1', port: onionRelay.port }, [VAULT_ONION]: { host: '127.0.0.1', port: onionPort } });
    await socks.start();
  });
  afterAll(async () => {
    for (const c of clients) c.close();
    await vault.close();
    await onionVault.close();
    await socks.stop();
    await relay.stop();
    await onionRelay.stop();
  });

  it('seals the delivery ledger on the device; the vault holds neither text nor keys, and a restored device opens it', async () => {
    const a = await newClient();
    const alice = await a.createPersona({ label: 'Alice', relays: [relay.url] });
    expect((await a.sendChannel(alice.id, 'general', 'la clave del portal es 4471')).state).toBe('REPLICATED');

    const pushed = await a.vaultPush(alice.id, vaultUrl);
    expect(pushed.operations).toBeGreaterThanOrEqual(1);
    expect((await a.vaultPush(alice.id, vaultUrl)).archive.id).toBe(pushed.archive.id);
    expect(await a.vaultList(alice.id, vaultUrl)).toHaveLength(1);
    expect(await a.vaultVerify(alice.id, vaultUrl)).toEqual({ archives: 1, opened: 1 });

    // The vault account is the key derived from the archive key, not the persona; nothing readable is stored.
    const key = await (await a.identities()).archiveKey(alice.id);
    const rows = repo.rows();
    expect(rows.map((r) => r.owner)).toEqual([`nostr:${archiveOwnerPubkey(key)}`]);
    const stored = JSON.stringify(rows) + (await objectsText(objects));
    for (const needle of ['4471', 'portal', alice.pubkey, relay.url, 'REPLICATED', '"outbox"', '"kind"']) expect(stored, needle).not.toContain(needle);

    // The archive key travels in the identity backup: a clean device restores it and opens the vault.
    const pkg = await a.exportBackup(alice.id, 'contraseña del backup', { scryptLogN: 4 });
    const b = await newClient();
    await b.restoreBackup(pkg, 'contraseña del backup');
    expect(await b.vaultVerify(alice.id, vaultUrl)).toEqual({ archives: 1, opened: 1 });
    expect((await b.vaultList(alice.id, vaultUrl)).map((m) => m.id)).toEqual([pushed.archive.id]);
  });

  it('the CLI tells what the operator sees before it uploads, and verifies with this device key (VAULT-07)', async () => {
    const env = { ...process.env, SOVEREIGN_DATA_DIR: await mkdtemp(join(tmpdir(), 'sovereign-vault-cli-')), SOVEREIGN_PASSPHRASE: 'cli-vault', SOVEREIGN_VAULT_URL: vaultUrl };
    const created = await run(['persona', 'create', '--label', 'Cli', '--relay', relay.url], env);
    expect(created.status, created.stderr).toBe(0);
    const id = (JSON.parse(created.stdout) as { id: string }).id;
    const push = await run(['vault', 'push', '--persona', id], env);
    expect(push.status, push.stderr).toBe(0);
    expect(push.stderr).toContain(`aviso: ${CONTINUITY_VAULT_TEXTS.sealed}`);
    expect(push.stderr).toContain(`aviso: ${CONTINUITY_VAULT_TEXTS.metadata}`);
    expect(push.stdout).toMatch(/sellado y guardado en el vault: 0 operaciones/);
    const verify = await run(['vault', 'verify', '--persona', id], env);
    expect(verify.stdout, verify.stderr).toContain('1 de 1 archivos se abren');
    const noUrl = await run(['vault', 'list', '--persona', id], { ...env, SOVEREIGN_VAULT_URL: '' });
    expect(noUrl.status).not.toBe(0);
    expect(noUrl.stderr).toMatch(/--vault URL or SOVEREIGN_VAULT_URL required/);
  }, 90_000);

  it('a Tor persona reaches the vault only through Tor and fails closed without it', async () => {
    const c = await newClient();
    const anon = await c.createPersona({ label: 'Fuente', relays: [`ws://${RELAY_ONION}`], highRisk: true });
    const before = socks.requests.length;
    await c.vaultPush(anon.id, `http://${VAULT_ONION}`);
    expect(socks.requests.slice(before).some((r) => r.addressType === 'domain' && r.host === VAULT_ONION)).toBe(true);
    expect(onionRepo.rows()).toHaveLength(1);

    const offline = await newClient(1);
    const restored = await offline.restoreBackup(await c.exportBackup(anon.id, 'contraseña del backup', { scryptLogN: 4 }), 'contraseña del backup');
    await expect(offline.vaultPush(restored.id, `http://${VAULT_ONION}`)).rejects.toThrow();
    // Nor does it fall back to a clearnet vault.
    const clearnetRows = repo.rows().length;
    await expect(offline.vaultPush(restored.id, vaultUrl)).rejects.toThrow();
    expect(onionRepo.rows()).toHaveLength(1);
    expect(repo.rows()).toHaveLength(clearnetRows);
  });
});
