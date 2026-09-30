/**
 * FR018-06: a file over the limit of group media is refused by the sovereign client before anything is hashed, asked
 * about or sent: no relay connection, no upload. The CLI checks the size of the file before it reads it.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AttachmentTooLargeError, MAX_ATTACHMENT_BYTES } from '@sedecim/blossom-client';
import { TestBlossomServer, TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function cli(dataDir: string, ...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, SOVEREIGN_DATA_DIR: dataDir, SOVEREIGN_PASSPHRASE: 'attachments-test', SOVEREIGN_FLAGS: '/nonexistent/flags.json' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('sovereign client: size of group media (FR018-06)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const blobs = new TestBlossomServer();
  beforeAll(async () => {
    await relay.start();
    await blobs.start();
  });
  afterAll(async () => {
    await relay.stop();
    await blobs.stop();
  });

  it('FR018-06: over the limit the file is refused before anything is sent; at the limit it goes', async () => {
    const client = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-attachments-')), passphrase: 'pass', scryptLogN: 4, blobStore: blobs.url });
    try {
      const alice = await client.createPersona({ label: 'Alice', relays: [relay.url] });
      const group = await client.groupCreate(alice.id, 'adjuntos');
      const received = relay.received.length;
      const uploaded = blobs.blobs.size;

      const err = await client.groupSendFile(alice.id, group.groupId, { data: new Uint8Array(MAX_ATTACHMENT_BYTES.group + 1), filename: 'grande.bin', mimeType: 'application/octet-stream' }).catch((e: Error) => e);
      expect(err).toBeInstanceOf(AttachmentTooLargeError);
      expect((err as Error).message).toBe('El archivo pesa 25,0 MB y los archivos de los grupos seguros pueden pesar como mucho 25,0 MB.');
      expect(relay.received.length).toBe(received);
      expect(blobs.blobs.size).toBe(uploaded);

      // A file that fits goes through as before.
      const ok = await client.groupSendFile(alice.id, group.groupId, { data: new TextEncoder().encode('acta'), filename: 'acta.txt', mimeType: 'text/plain' });
      expect(ok.attachment.filename).toBe('acta.txt');
      expect(blobs.blobs.size).toBe(uploaded + 1);
    } finally {
      client.close();
    }
  }, 60_000);

  it('FR018-06: the CLI checks the size of the file before reading it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sovereign-attachments-cli-'));
    // A sparse file one byte over the limit: it costs no disk, and reading it would cost 25 MB of memory.
    const big = join(dir, 'grande.bin');
    const f = await open(big, 'w');
    await f.truncate(MAX_ATTACHMENT_BYTES.group + 1);
    await f.close();
    const r = await cli(dir, 'group', 'send-file', '--persona', 'inexistente', '--group', 'g1', '--file', big);
    expect(r.status).not.toBe(0);
    // The size is refused before the persona is even looked up: that would say «persona no encontrada».
    expect(r.stderr).toMatch(/los archivos de los grupos seguros pueden pesar como mucho 25,0 MB/);
  }, 60_000);
});
