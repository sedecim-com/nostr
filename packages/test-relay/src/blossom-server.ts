import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, getTagValue, getTagValues, verifyEvent, type NostrEvent } from '@sedecim/nostr-core';

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, x-sha-256', 'access-control-allow-methods': 'GET, HEAD, PUT' };

/** Minimal in-memory Blossom server (BUD-01 GET/HEAD, BUD-02 PUT /upload) for tests. */
export class TestBlossomServer {
  readonly blobs = new Map<string, { data: Uint8Array; type: string; uploader: string }>();
  private server?: Server;
  url = '';
  /** URL the descriptors name instead of `url` (e.g. an onion reached through a SOCKS stub, FR020-05). */
  publicUrl?: string;
  /** Corrupt served bytes (to test hash verification). */
  corruptDownloads = false;
  /** Require a BUD-01 `get` authorization for downloads (Buzz /media behaviour). */
  requireGetAuth = false;
  /** Answer CORS like Buzz /media and the blob-store do, for browser tests. */
  cors = false;

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      void this.handle(req).then(
        ({ status, body, headers }) => {
          res.writeHead(status, this.cors ? { ...CORS, ...headers } : headers);
          res.end(body);
        },
        (err: Error) => {
          res.writeHead(500, { 'content-type': 'text/plain' });
          res.end(err.message);
        },
      );
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', () => r()));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this.url;
  }

  async stop(): Promise<void> {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }

  private async readBody(req: IncomingMessage): Promise<Uint8Array> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    return new Uint8Array(Buffer.concat(chunks));
  }

  private async handle(req: IncomingMessage): Promise<{ status: number; body?: string | Uint8Array; headers?: Record<string, string> }> {
    const url = new URL(req.url ?? '/', this.url);
    if (req.method === 'OPTIONS' && this.cors) return { status: 204 };
    if (req.method === 'PUT' && url.pathname === '/upload') {
      const body = await this.readBody(req);
      const hash = bytesToHex(sha256(body));
      const auth = this.checkAuth(req.headers.authorization, 'upload');
      if (typeof auth === 'string') return { status: 401, body: auth, headers: { 'x-reason': auth } };
      if (!getTagValues(auth, 'x').includes(hash)) return { status: 403, body: 'hash not authorized', headers: { 'x-reason': 'hash not authorized' } };
      const type = (req.headers['content-type'] as string | undefined) ?? 'application/octet-stream';
      this.blobs.set(hash, { data: body, type, uploader: auth.pubkey });
      const descriptor = { url: `${this.publicUrl ?? this.url}/${hash}`, sha256: hash, size: body.length, type, uploaded: Math.floor(Date.now() / 1000) };
      return { status: 200, body: JSON.stringify(descriptor), headers: { 'content-type': 'application/json' } };
    }
    const m = /^\/([0-9a-f]{64})(\.[a-z0-9]+)?$/.exec(url.pathname);
    if ((req.method === 'GET' || req.method === 'HEAD') && m) {
      if (this.requireGetAuth) {
        const auth = this.checkAuth(req.headers.authorization, 'get');
        if (typeof auth === 'string') return { status: 401, body: auth };
        if (!getTagValues(auth, 'x').includes(m[1]!)) return { status: 403, body: 'hash not authorized' };
      }
      const blob = this.blobs.get(m[1]!);
      if (!blob) return { status: 404, body: 'not found' };
      let data = blob.data;
      if (this.corruptDownloads) {
        data = new Uint8Array(blob.data);
        data[0] = data[0]! ^ 0xff;
      }
      return { status: 200, body: req.method === 'HEAD' ? undefined : data, headers: { 'content-type': blob.type, 'content-length': String(data.length) } };
    }
    return { status: 404, body: 'not found' };
  }

  private checkAuth(header: string | undefined, verb: string): NostrEvent | string {
    if (!header?.startsWith('Nostr ')) return 'missing auth';
    let evt: unknown;
    try {
      evt = JSON.parse(Buffer.from(header.slice(6), 'base64').toString('utf8'));
    } catch {
      return 'malformed auth';
    }
    if (!verifyEvent(evt) || evt.kind !== 24242) return 'invalid auth event';
    if (getTagValue(evt, 't') !== verb) return 'wrong verb';
    const exp = Number(getTagValue(evt, 'expiration'));
    if (!exp || exp < Date.now() / 1000) return 'expired auth';
    return evt;
  }
}
