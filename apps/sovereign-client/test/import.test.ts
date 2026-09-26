import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey, getPublicKey, nip19, nip49 } from '@sedecim/nostr-core';
import { backupFile, generateKey } from '../../key-generator/src/generate';
import { SovereignClient } from '../src/index';

const cli = new URL('../src/cli.ts', import.meta.url).pathname;
const tsx = new URL('../../../node_modules/.bin/tsx', import.meta.url).pathname;

describe('import of key backups (FR002-03)', () => {
  it('sovereign persona import --backup accepts the offline generator JSON and rejects a mismatched one', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sovereign-import-'));
    const k = generateKey({ password: 'contraseña del backup', logN: 4 });
    const file = join(dir, 'backup.json');
    await writeFile(file, JSON.stringify(backupFile(k, 4)));
    const pw = join(dir, 'pw');
    await writeFile(pw, 'contraseña del backup\n');
    const env = { ...process.env, SOVEREIGN_DATA_DIR: join(dir, 'data'), SOVEREIGN_PASSPHRASE: 'local-pass' };
    const ok = spawnSync(tsx, [cli, 'persona', 'import', '--backup', file, '--label', 'Offline', '--relay', 'wss://relay.example', '--password-file', pw], { encoding: 'utf8', env });
    expect(ok.status, ok.stderr).toBe(0);
    expect(JSON.parse(ok.stdout)).toMatchObject({ pubkey: k.pubkeyHex, custody: 'local', label: 'Offline', relays: ['wss://relay.example'] });
    const list = spawnSync(tsx, [cli, 'persona', 'list'], { encoding: 'utf8', env });
    expect(list.stdout).toContain('Offline');

    const other = generateSecretKey();
    const mismatched = join(dir, 'bad.json');
    await writeFile(mismatched, JSON.stringify({ format: 'acceso-nostr-key-backup', version: 1, npub: nip19.npubEncode(getPublicKey(generateSecretKey())), ncryptsec: nip49.encryptKey(other, 'x', 4) }));
    const bad = spawnSync(tsx, [cli, 'persona', 'import', '--backup', mismatched, '--label', 'Mal'], { encoding: 'utf8', env: { ...env, SOVEREIGN_BACKUP_PASSWORD: 'x' } });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/does not match its npub/);
    const noPw = spawnSync(tsx, [cli, 'persona', 'import', '--backup', file], { encoding: 'utf8', env });
    expect(noPw.stderr).toMatch(/backup password required/);
  }, 90_000);

  it('imports the web key backup format through the client and stores the panel config', async () => {
    const client = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-import-web-')), passphrase: 'pass', scryptLogN: 4 });
    try {
      const sk = generateSecretKey();
      const web = { format: 'acceso-nostr-key-backup', version: 1, npub: nip19.npubEncode(getPublicKey(sk)), ncryptsec: nip49.encryptKey(sk, 'web-pw', 4) };
      await expect(client.importBackup(web, 'mal', { label: 'Web', relays: ['wss://r.example'] })).rejects.toThrow(/wrong passphrase/);
      const p = await client.importBackup(JSON.stringify(web), 'web-pw', { label: 'Web', relays: ['wss://r.example', 'wss://s.example'] });
      expect(p.pubkey).toBe(getPublicKey(sk));
      expect(await (await client.identities()).getConfig(p.id)).toMatchObject({ network: 'multi-relay', telemetry: 'none' });
      const signer = await (await client.identities()).unlock(p.id, 'pass');
      expect(await signer.getPublicKey()).toBe(p.pubkey);
    } finally {
      client.close();
    }
  });
});
