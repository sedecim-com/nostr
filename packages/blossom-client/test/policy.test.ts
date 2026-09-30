import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { bytesToHex, generateSecretKey } from '@sedecim/nostr-core';
import { sha256 } from '@noble/hashes/sha2.js';
import { LocalSigner } from '@sedecim/signer';
import { AttachmentTooLargeError, BlossomClient, checkAttachmentSize, fetchHttpClient, MAX_ATTACHMENT_BYTES, MAX_DOWNLOAD_BYTES, prepareBlob, type HttpClient } from '../src/index';

/** FR018-06: what one attachment may weigh is checked in the client, before it is read and when it is downloaded. */

const MiB = 1024 * 1024;
const MB = 1_000_000;

describe('attachment size policy (FR018-06)', () => {
  it('FR018-06: every flow has a limit, and the ones the servers cap are lower than the servers\' caps', () => {
    expect(MAX_ATTACHMENT_BYTES).toEqual({ dm: 25 * MB, group: 25 * MB, channelImage: 10 * MB, avatar: MB });
    // blob-store takes 50 MiB by default (BLOB_MAX_BYTES): an upload the client accepts fits, with what encryption adds.
    expect(Math.max(...Object.values(MAX_ATTACHMENT_BYTES))).toBeLessThan(50 * MiB);
    expect(MAX_DOWNLOAD_BYTES).toBeGreaterThan(MAX_ATTACHMENT_BYTES.dm);
  });

  it('FR018-06: a file at the limit passes and one byte more is refused, with what the user is shown', () => {
    for (const flow of Object.keys(MAX_ATTACHMENT_BYTES) as Array<keyof typeof MAX_ATTACHMENT_BYTES>) {
      const limit = MAX_ATTACHMENT_BYTES[flow];
      expect(() => checkAttachmentSize(flow, limit)).not.toThrow();
      expect(() => checkAttachmentSize(flow, 0)).not.toThrow();
      const err = (() => {
        try {
          checkAttachmentSize(flow, limit + 1);
        } catch (e) {
          return e as AttachmentTooLargeError;
        }
      })();
      expect(err).toBeInstanceOf(AttachmentTooLargeError);
      expect(err).toMatchObject({ flow, size: limit + 1, limit });
    }
    expect(() => checkAttachmentSize('dm', 31.2 * MB)).toThrow('El archivo pesa 31,2 MB y los adjuntos de mensajes directos pueden pesar como mucho 25,0 MB.');
    // One byte over reads as over, not as equal.
    expect(() => checkAttachmentSize('avatar', MB + 1)).toThrow('El archivo pesa 1,1 MB y los avatares de los perfiles pueden pesar como mucho 1,0 MB.');
    expect(() => checkAttachmentSize('channelImage', 11 * MB)).toThrow(/las imágenes de los canales pueden pesar como mucho 10,0 MB/);
  });

  it('FR018-06: prepareBlob refuses an oversize file before sanitizing, hashing or encrypting it (25 MB by default, 10 MB for a channel image)', () => {
    const at = (n: number) => new Uint8Array(n);
    expect(prepareBlob(at(MAX_ATTACHMENT_BYTES.dm), { sanitize: false }).data.length).toBe(MAX_ATTACHMENT_BYTES.dm);
    expect(() => prepareBlob(at(MAX_ATTACHMENT_BYTES.dm + 1), { sanitize: false })).toThrow(AttachmentTooLargeError);
    expect(() => prepareBlob(at(MAX_ATTACHMENT_BYTES.dm + 1), { encrypt: true })).toThrow(AttachmentTooLargeError);
    expect(prepareBlob(at(MAX_ATTACHMENT_BYTES.channelImage), { sanitize: false, flow: 'channelImage' }).data.length).toBe(MAX_ATTACHMENT_BYTES.channelImage);
    expect(() => prepareBlob(at(MAX_ATTACHMENT_BYTES.channelImage + 1), { sanitize: false, flow: 'channelImage' })).toThrow(/las imágenes de los canales/);
    // The same size goes where the limit is higher.
    expect(prepareBlob(at(MAX_ATTACHMENT_BYTES.channelImage + 1), { sanitize: false, flow: 'dm' }).data.length).toBe(MAX_ATTACHMENT_BYTES.channelImage + 1);
    expect(() => prepareBlob(at(MAX_ATTACHMENT_BYTES.avatar + 1), { flow: 'avatar' })).toThrow(/los avatares de los perfiles/);
  });

  describe('downloads', () => {
    const signer = new LocalSigner(generateSecretKey());
    const respond =
      (body: Uint8Array, seen: Array<number | undefined> = []): HttpClient =>
      async (_url, init) => {
        seen.push(init.maxBytes);
        return { status: 200, headers: {}, body };
      };

    it('FR018-06: BlossomClient.download asks the transport for at most MAX_DOWNLOAD_BYTES and refuses more before hashing', async () => {
      const seen: Array<number | undefined> = [];
      const small = new TextEncoder().encode('hola');
      const ok = await new BlossomClient('https://blobs.example', signer, respond(small, seen)).download(bytesToHex(sha256(small)));
      expect(new TextDecoder().decode(ok)).toBe('hola');
      expect(seen).toEqual([MAX_DOWNLOAD_BYTES]);

      // A transport that cannot stop early hands the whole body over: the size is checked anyway, and not hashed.
      const big = new Uint8Array(MAX_DOWNLOAD_BYTES + 1);
      await expect(new BlossomClient('https://blobs.example', signer, respond(big)).download(bytesToHex(sha256(big)))).rejects.toMatchObject({ name: 'AttachmentTooLargeError', flow: 'download', size: MAX_DOWNLOAD_BYTES + 1, limit: MAX_DOWNLOAD_BYTES });
      // The limit is the caller's when it says so.
      await expect(new BlossomClient('https://blobs.example', signer, respond(small)).download(bytesToHex(sha256(small)), { maxBytes: 3 })).rejects.toBeInstanceOf(AttachmentTooLargeError);
      expect(new TextDecoder().decode(await new BlossomClient('https://blobs.example', signer, respond(small)).download(bytesToHex(sha256(small)), { maxBytes: 4 }))).toBe('hola');
    });

    describe('fetchHttpClient stops at the limit instead of buffering the whole body', () => {
      let server: Server;
      let base = '';
      const sent = { declared: 0, streamed: 0 };
      beforeAll(async () => {
        server = createServer((req, res) => {
          if (req.url === '/declared') {
            // A declared length over the limit: not one byte of the body is sent.
            res.writeHead(200, { 'content-length': String(3 * MiB) });
            res.flushHeaders();
            sent.declared += 1;
            res.end(Buffer.alloc(3 * MiB));
          } else if (req.url === '/streamed') {
            // No declared length: 4 MiB in chunks; the client hangs up after the first MiB it is allowed.
            res.writeHead(200);
            const chunk = Buffer.alloc(64 * 1024);
            let n = 0;
            const push = () => {
              while (n < 64) {
                n += 1;
                sent.streamed = n;
                if (!res.write(chunk)) return void res.once('drain', push);
              }
              res.end();
            };
            push();
          } else {
            res.writeHead(200, { 'content-length': '5' });
            res.end('hello');
          }
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      });
      afterAll(async () => {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
      });

      it('FR018-06: over the declared length, it refuses from the headers', async () => {
        await expect(fetchHttpClient(`${base}/declared`, { method: 'GET', maxBytes: MiB })).rejects.toMatchObject({ name: 'AttachmentTooLargeError', flow: 'download', size: 3 * MiB, limit: MiB });
      });

      it('FR018-06: with no declared length, it hangs up once the limit is passed', async () => {
        await expect(fetchHttpClient(`${base}/streamed`, { method: 'GET', maxBytes: MiB })).rejects.toMatchObject({ name: 'AttachmentTooLargeError', size: undefined, limit: MiB });
        // The server wrote a part of the 4 MiB, not (much more than) all of it.
        expect(sent.streamed).toBeLessThan(64);
      });

      it('FR018-06: under the limit, or with no limit, the body comes whole', async () => {
        expect(new TextDecoder().decode((await fetchHttpClient(`${base}/small`, { method: 'GET', maxBytes: MiB })).body)).toBe('hello');
        expect(new TextDecoder().decode((await fetchHttpClient(`${base}/small`, { method: 'GET' })).body)).toBe('hello');
        expect(new TextDecoder().decode((await fetchHttpClient(`${base}/small`, { method: 'GET', maxBytes: 5 })).body)).toBe('hello');
        await expect(fetchHttpClient(`${base}/small`, { method: 'GET', maxBytes: 4 })).rejects.toBeInstanceOf(AttachmentTooLargeError);
      });
    });
  });
});
