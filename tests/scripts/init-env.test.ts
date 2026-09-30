import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getPublicKey, hexToBytes, nip19 } from '@sedecim/nostr-core';
import { verifyBackup, type BackupFile } from '../../apps/key-generator/src/generate';

const root = new URL('../..', import.meta.url).pathname;

function initEnv(env: Record<string, string>) {
  // stdin is not a terminal here: the owner is only generated with OWNER_PASSWORD_FILE.
  const res = spawnSync('sh', [join(root, 'scripts/init-env.sh')], { cwd: root, env: { ...process.env, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  expect(res.status, res.stderr + res.stdout).toBe(0);
  return res.stdout;
}

const parse = (file: string) => Object.fromEntries(readFileSync(file, 'utf8').split('\n').filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));

describe('scripts/init-env.sh (OPS-03)', () => {
  it('generates service keys and the relay owner with the offline key generator', () => {
    const dir = mkdtempSync(join(tmpdir(), 'init-env-'));
    const envFile = join(dir, '.env');
    const backup = join(dir, 'owner.json');
    writeFileSync(join(dir, 'pw'), 'una contraseña de owner larga\n');
    initEnv({ ENV_FILE: envFile, OWNER_BACKUP: backup, OWNER_PASSWORD_FILE: join(dir, 'pw') });

    const env = parse(envFile);
    expect(statSync(envFile).mode & 0o777).toBe(0o600);
    expect(Object.entries(env).filter(([, v]) => v === 'CHANGE_ME')).toEqual([]);
    // FR023-10: BUZZ_MEMBERSHIP_NSEC keeps the NIP-29 membership of the registered channels.
    const identities = ['BUZZ_RELAY_PRIVATE_KEY', 'INDEXER_NSEC', 'ROTATION_WORKER_NSEC', 'BUZZ_MEMBERSHIP_NSEC'];
    for (const k of identities) expect(getPublicKey(hexToBytes(env[k]!))).toMatch(/^[0-9a-f]{64}$/);
    expect(new Set(identities.map((k) => env[k])).size).toBe(identities.length);
    // FR024-05: the key that encrypts the rotation worker's MLS state.
    expect(env.ROTATION_STATE_KEY).toMatch(/^[0-9a-f]{64}$/);
    // the owner's secret is only in the encrypted backup; .env gets the matching pubkey
    const file = JSON.parse(readFileSync(backup, 'utf8')) as BackupFile;
    expect(nip19.decode(file.npub).data).toBe(env.RELAY_OWNER_PUBKEY);
    expect(verifyBackup(file, 'una contraseña de owner larga').ok).toBe(true);
    expect(readFileSync(envFile, 'utf8')).not.toContain(file.ncryptsec);
  }, 60_000);

  it('is idempotent and never overwrites an existing value', () => {
    const dir = mkdtempSync(join(tmpdir(), 'init-env-'));
    const envFile = join(dir, '.env');
    const example = readFileSync(join(root, '.env.example'), 'utf8');
    writeFileSync(envFile, example.replace(/^POSTGRES_PASSWORD=.*$/m, 'POSTGRES_PASSWORD=mia').replace(/^INDEXER_NSEC=.*$/m, `INDEXER_NSEC=${'ab'.repeat(32)}`));
    const out = initEnv({ ENV_FILE: envFile, OWNER_BACKUP: join(dir, 'owner.json') });
    const first = readFileSync(envFile, 'utf8');
    const env = parse(envFile);
    expect(env.POSTGRES_PASSWORD).toBe('mia');
    expect(env.INDEXER_NSEC).toBe('ab'.repeat(32));
    expect(env.REDIS_PASSWORD).toMatch(/^[0-9a-f]{48}$/);
    // non-interactive without a password file: the owner is skipped, not invented
    expect(env.RELAY_OWNER_PUBKEY).toBe('');
    expect(out).toContain('RELAY_OWNER_PUBKEY left empty');
    initEnv({ ENV_FILE: envFile, OWNER_BACKUP: join(dir, 'owner.json') });
    expect(readFileSync(envFile, 'utf8')).toBe(first);
  }, 60_000);
});
