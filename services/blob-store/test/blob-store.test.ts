import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { BlossomClient, prepareBlob } from '@sedecim/blossom-client';
import { BLOB_SAFETY_HEADERS, BlobStore } from '../src/index';

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

describe('blob-store ownership and serving (internal review 2026-09)', () => {
  let store: BlobStore;
  const alice = new LocalSigner(generateSecretKey());
  const mallory = new LocalSigner(generateSecretKey());
  const auth = async (s: LocalSigner, verb: 'upload' | 'delete', hash: string) => {
    const evt = await s.signEvent({ kind: 24242, content: verb, created_at: Math.floor(Date.now() / 1000), tags: [['t', verb], ['x', hash], ['expiration', String(Math.floor(Date.now() / 1000) + 60)]] });
    return `Nostr ${Buffer.from(JSON.stringify(evt)).toString('base64')}`;
  };
  beforeAll(async () => {
    store = new BlobStore({ dir: await mkdtemp(join(tmpdir(), 'blobs-')), maxBytes: 1024 * 1024 });
    await store.listen();
  });
  afterAll(() => store.close());

  it('re-uploading public bytes does not transfer ownership (no takeover-then-delete)', async () => {
    const data = new TextEncoder().encode('<html><script>alert(1)</script></html>');
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', data)).toString('hex');
    const put = (s: LocalSigner) => auth(s, 'upload', hash).then((a) => fetch(`${store.url}/upload`, { method: 'PUT', body: data, headers: { authorization: a, 'content-type': 'text/html' } }));
    expect((await put(alice)).status).toBe(200);
    expect((await put(mallory)).status).toBe(200); // idempotent for the second uploader
    const del = (s: LocalSigner) => auth(s, 'delete', hash).then((a) => fetch(`${store.url}/${hash}`, { method: 'DELETE', headers: { authorization: a } }));
    expect((await del(mallory)).status).toBe(403);
    const get = await fetch(`${store.url}/${hash}`);
    expect(get.status).toBe(200);
    for (const [k, v] of Object.entries(BLOB_SAFETY_HEADERS)) expect(get.headers.get(k)).toBe(v);
    expect((await del(alice)).status).toBe(200);
    expect((await fetch(`${store.url}/${hash}`)).status).toBe(404);
  });
});
