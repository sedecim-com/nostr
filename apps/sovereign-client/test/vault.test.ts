import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { verifyEvent as ntVerifyEvent } from 'nostr-tools';
import { spawn } from 'node:child_process';
import { closeSync, fstatSync, openSync, readFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { archiveOwnerPubkey, type VaultExport } from '@sedecim/continuity';
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

  it('seals the history on the device; the vault holds neither text nor keys, and a restored device opens it', async () => {
    const a = await newClient();
    const alice = await a.createPersona({ label: 'Alice', relays: [relay.url] });
    expect((await a.sendChannel(alice.id, 'general', 'la clave del portal es 4471')).state).toBe('REPLICATED');
    await a.publishDmRelays(alice.id);

    // VAULT-03: its channel message and its DM relay list (kind 10050), one archive each, plus the ledger.
    const pushed = await a.vaultPush(alice.id, vaultUrl);
    expect(pushed.operations).toBeGreaterThanOrEqual(1);
    expect(pushed.events.uploaded).toBeGreaterThanOrEqual(2);
    expect(pushed.snapshots).toEqual(['ledger']);
    // A second push writes no event again, only the ledger.
    const again = await a.vaultPush(alice.id, vaultUrl);
    expect(again.events).toEqual({ uploaded: 0, kept: pushed.events.uploaded, invalid: 0 });
    const archives = pushed.events.uploaded + 1;
    expect(await a.vaultList(alice.id, vaultUrl)).toHaveLength(archives);
    expect(await a.vaultVerify(alice.id, vaultUrl)).toEqual({ archives, opened: archives });

    // The vault account is the key derived from the archive key, not the persona; nothing readable is stored.
    const key = await (await a.identities()).archiveKey(alice.id);
    const rows = repo.rows();
    expect(new Set(rows.map((r) => r.owner))).toEqual(new Set([`nostr:${archiveOwnerPubkey(key)}`]));
    const stored = JSON.stringify(rows) + (await objectsText(objects));
    for (const needle of ['4471', 'portal', alice.pubkey, relay.url, 'REPLICATED', '"outbox"', '"kind"']) expect(stored, needle).not.toContain(needle);

    // The archive key travels in the identity backup: a clean device restores it and opens the vault.
    const pkg = await a.exportBackup(alice.id, 'contraseña del backup', { scryptLogN: 4 });
    const b = await newClient();
    await b.restoreBackup(pkg, 'contraseña del backup');
    expect(await b.vaultVerify(alice.id, vaultUrl)).toEqual({ archives, opened: archives });
    expect((await b.vaultList(alice.id, vaultUrl)).map((m) => m.id)).toEqual((await a.vaultList(alice.id, vaultUrl)).map((m) => m.id));
  });

  it('the CLI tells what the operator sees before it uploads, and verifies with this device key (VAULT-07)', async () => {
    const env = { ...process.env, SOVEREIGN_DATA_DIR: await mkdtemp(join(tmpdir(), 'sovereign-vault-cli-')), SOVEREIGN_PASSPHRASE: 'cli-vault', SOVEREIGN_VAULT_URL: vaultUrl };
    const created = await run(['persona', 'create', '--label', 'Cli', '--relay', relay.url], env);
    expect(created.status, created.stderr).toBe(0);
    // FR017-06: creating a persona publishes its DM relay list, the one operation of its ledger so far.
    expect(created.stderr).toMatch(/relays de DM \(kind 10050\): REPLICATED/);
    const id = (JSON.parse(created.stdout) as { id: string }).id;
    const push = await run(['vault', 'push', '--persona', id], env);
    expect(push.status, push.stderr).toBe(0);
    expect(push.stderr).toContain(`aviso: ${CONTINUITY_VAULT_TEXTS.sealed}`);
    expect(push.stderr).toContain(`aviso: ${CONTINUITY_VAULT_TEXTS.metadata}`);
    expect(push.stdout).toMatch(/historial sellado y guardado en el vault: 1 eventos nuevos \(0 ya estaban\), 0 mensajes de grupo nuevos, ledger de 1 operaciones/);
    const verify = await run(['vault', 'verify', '--persona', id], env);
    expect(verify.stdout, verify.stderr).toContain('2 de 2 archivos se abren');
    const noUrl = await run(['vault', 'list', '--persona', id], { ...env, SOVEREIGN_VAULT_URL: '' });
    expect(noUrl.status).not.toBe(0);
    expect(noUrl.stderr).toMatch(/--vault URL or SOVEREIGN_VAULT_URL required/);
  }, 90_000);

  it('VAULT-05: the CLI sets the retention, exports the vault to an open file that `history import` takes back, and deletes it', async () => {
    // An operator that keeps nothing more than 90 days, and relays of this persona alone.
    const cappedRepo = new MemoryArchiveRepository();
    const capped = createContinuityVaultApi(cappedRepo, new MemoryObjectStore(), { name: 'vault-cli-05', logger: silent, retentionDays: 90 });
    const cappedUrl = await capped.listen();
    const own = new TestRelay({ requireAuth: true });
    await own.start();
    try {
      const dir = await mkdtemp(join(tmpdir(), 'sovereign-vault-05-'));
      const env = { ...process.env, SOVEREIGN_DATA_DIR: dir, SOVEREIGN_PASSPHRASE: 'cli-vault-05', SOVEREIGN_VAULT_URL: cappedUrl };
      const created = await run(['persona', 'create', '--label', 'Portable', '--relay', own.url], env);
      expect(created.status, created.stderr).toBe(0);
      const id = (JSON.parse(created.stdout) as { id: string }).id;

      const shown = await run(['vault', 'retention', '--persona', id], env);
      expect(shown.stdout, shown.stderr).toContain('retención: 90 días desde la última vez que se guarda cada archivo; máximo del operador: 90 días');
      const chosen = await run(['vault', 'retention', '--persona', id, '--days', '30'], env);
      expect(chosen.stdout, chosen.stderr).toContain('retención: 30 días desde la última vez que se guarda cada archivo (elegida: 30 días); máximo del operador: 90 días');
      const tooLong = await run(['vault', 'retention', '--persona', id, '--days', '400'], env);
      expect(tooLong.status).not.toBe(0);
      expect(tooLong.stderr).toMatch(/from 1 to 90/);

      expect((await run(['channel', 'send', '--persona', id, '--group', 'general', 'para llevar 9914'], env)).status).toBe(0);
      expect((await run(['vault', 'push', '--persona', id], env)).status).toBe(0);
      const file = join(dir, 'vault.json');
      const exported = await run(['vault', 'export', '--persona', id, '--out', file], env);
      expect(exported.status, exported.stderr).toBe(0);
      expect(exported.stdout).toMatch(/\(sedecim-vault-export v1\): 2 eventos firmados, 0 mensajes de grupo, 2 operaciones del ledger/);
      expect(exported.stderr).toContain(`aviso: ${CONTINUITY_VAULT_TEXTS.export}`);
      // One descriptor for the mode and the content: both read from the same file.
      const fd = openSync(file, 'r');
      let data: VaultExport;
      try {
        expect(fstatSync(fd).mode & 0o777).toBe(0o600);
        data = JSON.parse(readFileSync(fd, 'utf8')) as VaultExport;
      } finally {
        closeSync(fd);
      }
      expect(data).toMatchObject({ format: 'sedecim-vault-export', version: 1 });
      const note = data.events.find((e) => e.content === 'para llevar 9914')!;
      expect(note).toBeTruthy();
      // Signed events as they were: another Nostr implementation verifies them.
      for (const e of data.events) expect(ntVerifyEvent({ ...e })).toBe(true);
      expect((await run(['vault', 'export', '--persona', id, '--out', file], env)).status, 'an export never overwrites a file').not.toBe(0);

      // The relays lose everything: `history import` takes the export and puts its events back.
      own.events.clear();
      const imported = await run(['history', 'import', '--persona', id, file], env);
      expect(imported.status, imported.stderr).toBe(0);
      expect(imported.stdout).toContain('válidos=2 inválidos=0 duplicados=0 publicados=2 rechazados=0 (exportación del vault; 0 cifrados para otras personas no se publican)');
      expect(new Set(own.events.keys())).toEqual(new Set(data.events.map((e) => e.id)));
      // Another persona's export is not taken.
      const other = await run(['persona', 'create', '--label', 'Otra', '--relay', own.url], env);
      const otherId = (JSON.parse(other.stdout) as { id: string }).id;
      const wrong = await run(['history', 'import', '--persona', otherId, file], env);
      expect(wrong.status).not.toBe(0);
      expect(wrong.stderr).toContain('esta exportación del vault es de otra persona');

      // Delete asks for --yes, and then removes every archive and the account (its retention choice included).
      const unconfirmed = await run(['vault', 'delete', '--persona', id], env);
      expect(unconfirmed.status).not.toBe(0);
      expect(unconfirmed.stderr).toContain('repite con --yes');
      expect(cappedRepo.rows().length).toBe(3);
      const deleted = await run(['vault', 'delete', '--persona', id, '--yes'], env);
      expect(deleted.status, deleted.stderr).toBe(0);
      expect(deleted.stdout).toContain('vault: 3 archivos borrados y cuenta eliminada');
      expect(deleted.stderr).toContain(`aviso: ${CONTINUITY_VAULT_TEXTS.deletion}`);
      expect(deleted.stderr).not.toContain('copia automática');
      expect(cappedRepo.rows()).toEqual([]);
      expect((await run(['vault', 'retention', '--persona', id], env)).stdout).toContain('retención: 90 días desde la última vez que se guarda cada archivo; máximo del operador: 90 días');
    } finally {
      await capped.close();
      await own.stop();
    }
  }, 240_000);

  it('a Tor persona reaches the vault only through Tor and fails closed without it', async () => {
    const c = await newClient();
    const anon = await c.createPersona({ label: 'Fuente', relays: [`ws://${RELAY_ONION}`], highRisk: true });
    const before = socks.requests.length;
    const pushed = await c.vaultPush(anon.id, `http://${VAULT_ONION}`);
    expect(socks.requests.slice(before).some((r) => r.addressType === 'domain' && r.host === VAULT_ONION)).toBe(true);
    const onionRows = pushed.events.uploaded + 1;
    expect(onionRepo.rows()).toHaveLength(onionRows);

    const offline = await newClient(1);
    const restored = await offline.restoreBackup(await c.exportBackup(anon.id, 'contraseña del backup', { scryptLogN: 4 }), 'contraseña del backup');
    await expect(offline.vaultPush(restored.id, `http://${VAULT_ONION}`)).rejects.toThrow();
    // Nor does it fall back to a clearnet vault.
    const clearnetRows = repo.rows().length;
    await expect(offline.vaultPush(restored.id, vaultUrl)).rejects.toThrow();
    expect(onionRepo.rows()).toHaveLength(onionRows);
    expect(repo.rows()).toHaveLength(clearnetRows);
  });
});
