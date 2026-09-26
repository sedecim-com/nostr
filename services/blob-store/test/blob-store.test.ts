import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { BlossomClient, prepareBlob } from '@sedecim/blossom-client';
import { BlobStore } from '../src/index';

describe('blob-store (content-agnostic Blossom)', () => {
  let store: BlobStore;
  let dir: string;
  const owner = new LocalSigner(generateSecretKey());
  const stranger = new LocalSigner(generateSecretKey());
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'blobs-'));
    store = new BlobStore({ dir, allowedPubkeys: [await owner.getPublicKey()], maxBytes: 1024 * 1024 });
    await store.listen();
  });
  afterAll(() => store.close());

  it('stores client-encrypted blobs it cannot read and serves them by hash', async () => {
    const client = new BlossomClient(store.url, owner);
    const plaintext = new TextEncoder().encode('documento confidencial');
    const blob = prepareBlob(plaintext, { sanitize: false, encrypt: true });
    const d = await client.upload(blob);
    const onDisk = await Promise.all((await readdir(dir, { recursive: true })).filter((f) => String(f).endsWith('.bin')).map((f) => readFile(join(dir, String(f)))));
    expect(onDisk.some((b) => b.includes(Buffer.from('confidencial')))).toBe(false);
    expect(new TextDecoder().decode(await client.download(d.sha256, { decrypt: blob.encryption! }))).toBe('documento confidencial');
  });

  it('rejects uploads from pubkeys outside the allowlist', async () => {
    const client = new BlossomClient(store.url, stranger);
    await expect(client.upload(prepareBlob(new Uint8Array([9, 9]), { sanitize: false }))).rejects.toThrow(/401.*not allowed/);
  });
});
