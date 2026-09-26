import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestBlossomServer, TestRelay } from '@sedecim/test-relay';
import { BUZZ_PINNED_ADAPTER } from '@sedecim/messaging';
import { USER_SERVER_LIST_KIND, buildServerList, downloadFromServers, fetchServerList, latestServerList, normalizeServerUrl, parseServerList, prepareBlob, publishServerList, selectUploadServers, uploadToServers } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const signer = new LocalSigner(generateSecretKey());

describe('BUD-03 user server list (kind 10063, FR018-05)', () => {
  it('builds and parses `server` tags in order, normalized and deduplicated', () => {
    const t = buildServerList(['https://a.example/', 'https://b.example/media/', 'https://a.example']);
    expect(t).toEqual({ kind: USER_SERVER_LIST_KIND, content: '', tags: [['server', 'https://a.example'], ['server', 'https://b.example/media']] });
    expect(() => buildServerList(['ftp://x.example'])).toThrow(/http/);
    expect(() => buildServerList(['https://u:p@x.example'])).toThrow(/credentials/);
    expect(parseServerList({ kind: 10063, tags: [['server', 'https://z.example/'], ['server', 'javascript:alert(1)'], ['r', 'https://no.example'], ['server', 'https://z.example']] })).toEqual(['https://z.example']);
    expect(() => parseServerList({ kind: 10050, tags: [] })).toThrow(/kind/);
    expect(normalizeServerUrl(' https://a.example/x/?q=1#f ')).toBe('https://a.example/x');
  });

  it('keeps only the newest valid list of the author', async () => {
    const other = new LocalSigner(generateSecretKey());
    const pk = await signer.getPublicKey();
    const old = await signer.signEvent({ ...buildServerList(['https://old.example']), created_at: 100 });
    const cur = await signer.signEvent({ ...buildServerList(['https://new.example']), created_at: 200 });
    const forged = { ...(await other.signEvent({ ...buildServerList(['https://evil.example']), created_at: 300 })), pubkey: pk };
    expect(latestServerList([old, forged, cur], pk)?.id).toBe(cur.id);
  });

  it('routes ciphertext away from image-only servers and falls back to the deployment server', () => {
    const buzzMedia = 'https://relay.example/media';
    const blobStore = 'https://blobs.example';
    // BUZZ_PINNED_ADAPTER: Buzz /media rejects encrypted blobs, so ciphertext must go to a content-agnostic server.
    expect(BUZZ_PINNED_ADAPTER.encryptedAttachments).toBe('blob-store');
    const user = [buzzMedia + '/', 'https://mine.example'];
    expect(selectUploadServers({ userServers: user, encrypted: true, contentRestricted: [buzzMedia], fallback: blobStore })).toEqual(['https://mine.example', blobStore]);
    expect(selectUploadServers({ userServers: [buzzMedia], encrypted: true, contentRestricted: [buzzMedia], fallback: blobStore })).toEqual([blobStore]);
    expect(selectUploadServers({ userServers: user, encrypted: false, contentRestricted: [buzzMedia], fallback: buzzMedia })).toEqual([buzzMedia, 'https://mine.example']);
    expect(selectUploadServers({ userServers: [], encrypted: true, contentRestricted: [buzzMedia], fallback: buzzMedia })).toEqual([]);
    expect(selectUploadServers({ userServers: [], encrypted: false, fallback: buzzMedia })).toEqual([buzzMedia]);
  });

  describe('against a test relay and in-process Blossom servers', () => {
    const relay = new TestRelay();
    const primary = new TestBlossomServer();
    const secondary = new TestBlossomServer();
    let pool: RelayPool;
    beforeAll(async () => {
      await Promise.all([relay.start(), primary.start(), secondary.start()]);
      pool = new RelayPool({ webSocketFactory: factory, signer });
    });
    afterAll(async () => {
      pool.close();
      await Promise.all([relay.stop(), primary.stop(), secondary.stop()]);
    });

    it('publishes the list, fetches the latest one and uploads to the primary server (mirroring optional)', async () => {
      const pk = await signer.getPublicKey();
      expect(await fetchServerList(pool, [relay.url], pk, 2000)).toEqual([]);
      expect((await pool.publishTo(await publishServerList(signer, ['http://127.0.0.1:1']), relay.url)).ok).toBe(true);
      await new Promise((r) => setTimeout(r, 1100)); // replaceable: the newer list needs a later created_at
      expect((await pool.publishTo(await publishServerList(signer, [primary.url, secondary.url]), relay.url)).ok).toBe(true);
      const servers = await fetchServerList(pool, [relay.url], pk, 2000);
      expect(servers).toEqual([primary.url, secondary.url]);

      const blob = prepareBlob(new TextEncoder().encode('adjunto'), { sanitize: false, encrypt: true });
      const up = await uploadToServers(blob, servers, signer);
      expect(up.server).toBe(primary.url);
      expect(primary.blobs.has(blob.sha256)).toBe(true);
      expect(secondary.blobs.has(blob.sha256)).toBe(false);

      const blob2 = prepareBlob(new TextEncoder().encode('espejo'), { sanitize: false });
      const mirrored = await uploadToServers(blob2, servers, signer, { mirror: true });
      expect(mirrored.mirrored).toEqual([secondary.url]);
      expect(secondary.blobs.has(blob2.sha256)).toBe(true);
    });

    it('falls through to the next server when the primary is down', async () => {
      const blob = prepareBlob(new TextEncoder().encode('failover'), { sanitize: false });
      const up = await uploadToServers(blob, ['http://127.0.0.1:1', secondary.url], signer);
      expect(up.server).toBe(secondary.url);
      expect(up.failed).toHaveLength(1);
      await expect(uploadToServers(blob, [], signer)).rejects.toThrow(/every server/);
    });

    it('downloads from the shared URL, else from the author servers in order, skipping corrupt copies', async () => {
      const blob = prepareBlob(new TextEncoder().encode('secreto'), { sanitize: false, encrypt: true });
      await uploadToServers(blob, [primary.url, secondary.url], signer, { mirror: true });
      primary.corruptDownloads = true;
      try {
        const got = await downloadFromServers(blob.sha256, { url: `http://127.0.0.1:1/${blob.sha256}`, servers: [primary.url, secondary.url] }, signer, { decrypt: blob.encryption! });
        expect(new TextDecoder().decode(got.data)).toBe('secreto');
        expect(got.from).toBe(`${secondary.url}/${blob.sha256}`);
        await expect(downloadFromServers(blob.sha256, { servers: [primary.url] }, signer)).rejects.toThrow(/hash mismatch/);
      } finally {
        primary.corruptDownloads = false;
      }
    });
  });
});
