/**
 * FR011-05 (scope §11.2): a send the user retries from the CLI with the same operation id (--op) makes no other
 * rumor and no other event; the DM's rumor is stored before its wraps are made. Real CLI processes over one data dir.
 */
import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { TestRelay } from '@sedecim/test-relay';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function cli(dataDir: string, ...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, SOVEREIGN_DATA_DIR: dataDir, SOVEREIGN_PASSPHRASE: 'operation-test' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('sovereign CLI: a retried send is the same operation (FR011-05)', () => {
  it('dm send and channel send with --op retry the message sent without network instead of making another', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sovereign-op-'));
    const relay = new TestRelay({ host: '127.0.0.1' });
    await relay.start();
    const port = relay.port;
    const created = await cli(dir, 'persona', 'create', '--label', 'Op', '--relay', relay.url);
    expect(created.status, created.stderr).toBe(0);
    const id = (JSON.parse(created.stdout) as { id: string }).id;
    const bob = getPublicKey(generateSecretKey());
    await relay.stop();

    // Without network: the DM is stored and queued, and the CLI says which operation it is.
    const first = await cli(dir, 'dm', 'send', '--persona', id, '--to', bob, 'escrito sin red');
    expect(first.status, first.stderr).toBe(0);
    const op = /^operación ([0-9a-f]{32}) \(para reintentar este envío sin duplicarlo: --op \1\)$/m.exec(first.stderr)?.[1];
    expect(op).toBeDefined();
    const channel = await cli(dir, 'channel', 'send', '--persona', id, '--group', 'general', '--op', 'canal-1', 'también sin red');
    expect(channel.status, channel.stderr).toBe(0);
    expect(channel.stdout).toMatch(/^QUEUED .*\(op canal-1\)$/m);

    const back = new TestRelay({ host: '127.0.0.1', port });
    await back.start();
    try {
      // The user retries both sends with their ids: they go out, once.
      const retried = await cli(dir, 'dm', 'send', '--persona', id, '--to', bob, '--op', op!, 'escrito sin red');
      expect(retried.status, retried.stderr).toBe(0);
      expect(retried.stdout.trim().split('\n')).toEqual([`${bob.slice(0, 8)} REPLICATED`, expect.stringMatching(/ REPLICATED$/)]);
      expect((await cli(dir, 'channel', 'send', '--persona', id, '--group', 'general', '--op', 'canal-1', 'también sin red')).stdout).toMatch(/^REPLICATED .*\(op canal-1\)$/m);
      const wraps = back.received.filter((e) => e.kind === 1059);
      expect(new Set(wraps.map((e) => e.id)).size).toBe(2); // Bob's wrap and the sender's own copy, never a second pair
      expect(new Set(back.received.filter((e) => e.content === 'también sin red').map((e) => e.id)).size).toBe(1);

      // Another text under the same id is a new message, not a retry: refused, and nothing is sent.
      const other = await cli(dir, 'dm', 'send', '--persona', id, '--to', bob, '--op', op!, 'otro texto');
      expect(other.status).toBe(1);
      expect(other.stderr).toMatch(/ya guarda otro mensaje/);
      expect(new Set(back.received.filter((e) => e.kind === 1059).map((e) => e.id)).size).toBe(2);

      // Without --op the same text is a new message: a new rumor and new wraps.
      expect((await cli(dir, 'dm', 'send', '--persona', id, '--to', bob, 'escrito sin red')).status).toBe(0);
      expect(new Set(back.received.filter((e) => e.kind === 1059).map((e) => e.id)).size).toBe(4);
    } finally {
      await back.stop();
    }
  }, 180_000);
});
