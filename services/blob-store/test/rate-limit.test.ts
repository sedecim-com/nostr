import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { request } from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { BlobStore } from '../src/index';

/** IR-2026-09-05: uploads limited per address (before the body is read) and per pubkey, plus concurrency. */
describe('blob-store rate limits', () => {
  let now = 0;
  let store: BlobStore;
  const signer = new LocalSigner(generateSecretKey());
  const token = async (data: Uint8Array) => {
    const evt = await signer.signEvent({ kind: 24242, content: 'upload', tags: [['t', 'upload'], ['x', bytesToHex(sha256(data))], ['expiration', String(Math.floor(Date.now() / 1000) + 300)]] });
    return `Nostr ${Buffer.from(JSON.stringify(evt)).toString('base64')}`;
  };
  const upload = async (n: number) => {
    const data = new TextEncoder().encode(`blob ${n} ${Math.random()}`);
    return fetch(`${store.url}/upload`, { method: 'PUT', headers: { authorization: await token(data) }, body: data });
  };

  beforeAll(async () => {
    store = new BlobStore({
      dir: await mkdtemp(join(tmpdir(), 'blobs-rl-')),
      rateLimit: { rules: { mutating: { perMinute: 60, burst: 2 }, auth: { perMinute: 1, burst: 2 } }, now: () => now },
      maxConcurrentUploadsPerIp: 1,
    });
    await store.listen();
  });
  afterAll(() => store.close());

  it('answers 429 + Retry-After after the burst and recovers after the refill', async () => {
    expect((await upload(1)).status).toBe(200);
    expect((await upload(2)).status).toBe(200);
    const res = await upload(3);
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('1');
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    now += 1000;
    expect((await upload(4)).status).toBe(200);
    // Downloads are a different class.
    expect((await fetch(`${store.url}/${'0'.repeat(64)}`)).status).toBe(404);
  });

  it('turns repeated invalid authorizations into 429', async () => {
    now += 600_000;
    const bad = () => fetch(`${store.url}/upload`, { method: 'PUT', headers: { authorization: 'Nostr bm9wZQ==' }, body: 'x' }).then((r) => r.status);
    expect([await bad(), await bad()]).toEqual([401, 401]);
    now += 1000; // one mutating token back, the auth bucket is still empty
    expect(await bad()).toBe(429);
  });

  it('caps concurrent uploads per address', async () => {
    now += 600_000;
    const data = new TextEncoder().encode('slow upload body');
    const auth = await token(data);
    let finish!: (status: number) => void;
    const slow = new Promise<number>((r) => (finish = r));
    const req = request(`${store.url}/upload`, { method: 'PUT', headers: { authorization: auth, 'content-length': String(data.length) } }, (res) => (res.resume(), finish(res.statusCode!)));
    req.write(data.slice(0, 4));
    await new Promise((r) => setTimeout(r, 100));
    const second = await upload(5);
    expect(second.status).toBe(429);
    expect(second.headers.get('x-reason')).toMatch(/concurrent/);
    req.end(data.slice(4));
    expect(await slow).toBe(200);
  });
});
