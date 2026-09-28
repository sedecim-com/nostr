/**
 * FR011-04 (D2): a message a CLI run could not deliver goes out the next time any command opens the persona,
 * without anyone running `sovereign resume`. Real CLI processes over the same data dir.
 */
import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestRelay } from '@sedecim/test-relay';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

/** Runs the CLI in its own process (async: the relays of this test live in this process's event loop). */
function cli(dataDir: string, ...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, SOVEREIGN_DATA_DIR: dataDir, SOVEREIGN_PASSPHRASE: 'resume-test' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('sovereign CLI: pending messages are retried when the persona opens (FR011-04)', () => {
  it('a message sent while the relay was down goes out with the next command of another process', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sovereign-resume-'));
    const relay = new TestRelay({ host: '127.0.0.1' });
    await relay.start();
    const port = relay.port;
    const created = await cli(dir, 'persona', 'create', '--label', 'Resume', '--relay', relay.url);
    expect(created.status, created.stderr).toBe(0);
    const id = (JSON.parse(created.stdout) as { id: string }).id;
    await relay.stop();

    const sent = await cli(dir, 'channel', 'send', '--persona', id, '--group', 'general', 'escrito sin red');
    expect(sent.status, sent.stderr).toBe(0);
    expect(sent.stdout).toMatch(/^QUEUED/);

    const back = new TestRelay({ host: '127.0.0.1', port });
    await back.start();
    try {
      // Any command that opens the persona delivers it (here, listing the outbox); nobody runs `resume`.
      const listed = await cli(dir, 'outbox', '--persona', id);
      expect(listed.status, listed.stderr).toBe(0);
      expect(back.received.filter((e) => e.content === 'escrito sin red')).toHaveLength(1);
      expect((await cli(dir, 'outbox', '--persona', id)).stdout).toMatch(/REPLICATED/);
      expect(back.received.filter((e) => e.content === 'escrito sin red')).toHaveLength(1);
    } finally {
      await back.stop();
    }
  }, 180_000);
});
