/**
 * PANEL-05: `persona create --high-risk` prints the residual risks of the profile (stderr, so stdout stays the
 * persona JSON). A real CLI process.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

describe('sovereign CLI: high-risk warnings (PANEL-05)', () => {
  it('persona create --high-risk warns about what Tor and this client do not cover', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sovereign-warnings-'));
    const r = spawnSync(process.execPath, ['--import', 'tsx', CLI, 'persona', 'create', '--label', 'Fuente', '--relay', 'ws://sovereignrelayabcdefghijklmnopqrstuvwxyz234567abcdefghijk.onion', '--high-risk'], {
      env: { ...process.env, SOVEREIGN_DATA_DIR: dir, SOVEREIGN_PASSPHRASE: 'warnings-test' },
      encoding: 'utf8',
    });
    expect(r.status, r.stderr).toBe(0);
    expect((JSON.parse(r.stdout) as { network: string }).network).toBe('tor-only');
    const warnings = r.stderr.split('\n').filter((l) => l.startsWith('aviso: '));
    expect(warnings.join('\n')).toMatch(/auditoría independiente/);
    expect(warnings.join('\n')).toMatch(/correlacionar horarios/);
    expect(warnings.join('\n')).toMatch(/perder el dispositivo/);
  }, 60_000);
});
