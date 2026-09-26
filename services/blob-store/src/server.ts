import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdir, readFile, rm, writeFile, rename, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, getTagValue, getTagValues, verifyEvent, type NostrEvent } from '@sedecim/nostr-core';
import { createLogger, type Logger } from '@sedecim/telemetry-policy';

export interface BlobStoreOptions {
  dir: string;
  publicUrl?: string;
  /** Only these pubkeys may upload (empty = any authenticated pubkey). */
  allowedPubkeys?: string[];
  maxBytes?: number;
  logger?: Logger;
}

interface Meta {
  sha256: string;
  size: number;
  type: string;
  uploader: string;
  uploaded: number;
}

/**
 * Content-agnostic Blossom server. Unlike Buzz /media (which only accepts sniffed images/video),
 * it never inspects bytes, so client-side encrypted attachments can be stored (spec §13).
 * Access is authorised with BUD kind 24242 events; downloads are by hash.
 */
export class BlobStore {
  private server?: Server;
  url = '';
  private readonly log: Logger;

  constructor(private readonly opts: BlobStoreOptions) {
    this.log = opts.logger ?? createLogger({ base: { service: 'blob-store' }, minimizeIp: true });
  }

  private path(hash: string, ext: 'bin' | 'json') {
    return join(this.opts.dir, hash.slice(0, 2), `${hash}.${ext}`);
  }

  private auth(header: string | undefined, verb: 'upload' | 'delete' | 'get'): NostrEvent | string {
    if (!header?.startsWith('Nostr ')) return 'missing authorization';
    let evt: unknown;
    try {
      evt = JSON.parse(Buffer.from(header.slice(6).trim(), 'base64').toString('utf8'));
    } catch {
      return 'malformed authorization';
    }
    if (!verifyEvent(evt) || evt.kind !== 24242) return 'invalid authorization event';
    if (getTagValue(evt, 't') !== verb) return 'wrong verb';
    const exp = Number(getTagValue(evt, 'expiration'));
    if (!exp || exp < Date.now() / 1000) return 'authorization expired';
    if (evt.created_at > Date.now() / 1000 + 60) return 'authorization from the future';
    if (verb === 'upload' && this.opts.allowedPubkeys?.length && !this.opts.allowedPubkeys.includes(evt.pubkey)) return 'pubkey not allowed';
    return evt;
  }

  private async body(req: IncomingMessage): Promise<Uint8Array> {
    const max = this.opts.maxBytes ?? 50 * 1024 * 1024;
    const chunks: Buffer[] = [];
    let n = 0;
    for await (const c of req) {
      n += (c as Buffer).length;
      if (n > max) throw Object.assign(new Error('blob too large'), { status: 413 });
      chunks.push(c as Buffer);
    }
    return new Uint8Array(Buffer.concat(chunks));
  }

  async handle(req: IncomingMessage): Promise<{ status: number; body?: Uint8Array | string; headers?: Record<string, string> }> {
    const url = new URL(req.url ?? '/', 'http://x');
    const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, x-sha-256', 'access-control-allow-methods': 'GET, HEAD, PUT, DELETE' };
    const reason = (status: number, r: string) => ({ status, body: JSON.stringify({ error: r }), headers: { ...cors, 'content-type': 'application/json', 'x-reason': r } });
    if (req.method === 'OPTIONS') return { status: 204, headers: cors };
    if (req.method === 'PUT' && url.pathname === '/upload') {
      const a = this.auth(req.headers.authorization, 'upload');
      if (typeof a === 'string') return reason(401, a);
      const data = await this.body(req);
      const hash = bytesToHex(sha256(data));
      if (!getTagValues(a, 'x').includes(hash)) return reason(403, 'authorization does not cover this hash');
      const meta: Meta = { sha256: hash, size: data.length, type: String(req.headers['content-type'] ?? 'application/octet-stream').slice(0, 100), uploader: a.pubkey, uploaded: Math.floor(Date.now() / 1000) };
      await mkdir(join(this.opts.dir, hash.slice(0, 2)), { recursive: true, mode: 0o700 });
      await writeFile(this.path(hash, 'bin') + '.tmp', data, { mode: 0o600 });
      await rename(this.path(hash, 'bin') + '.tmp', this.path(hash, 'bin'));
      await writeFile(this.path(hash, 'json'), JSON.stringify(meta), { mode: 0o600 });
      this.log.info('blob stored', { sha256: hash, size: data.length });
      const base = this.opts.publicUrl ?? this.url;
      return { status: 200, body: JSON.stringify({ url: `${base}/${hash}`, sha256: hash, size: meta.size, type: meta.type, uploaded: meta.uploaded }), headers: { ...cors, 'content-type': 'application/json' } };
    }
    const m = /^\/([0-9a-f]{64})(\.[a-z0-9]{1,8})?$/.exec(url.pathname);
    if (m) {
      const hash = m[1]!;
      let meta: Meta;
      try {
        meta = JSON.parse(await readFile(this.path(hash, 'json'), 'utf8')) as Meta;
      } catch {
        return reason(404, 'not found');
      }
      if (req.method === 'DELETE') {
        const a = this.auth(req.headers.authorization, 'delete');
        if (typeof a === 'string') return reason(401, a);
        if (a.pubkey !== meta.uploader || !getTagValues(a, 'x').includes(hash)) return reason(403, 'only the uploader can delete');
        await rm(this.path(hash, 'bin'), { force: true });
        await rm(this.path(hash, 'json'), { force: true });
        return { status: 200, body: '{"deleted":true}', headers: { ...cors, 'content-type': 'application/json' } };
      }
      if (req.method === 'GET' || req.method === 'HEAD') {
        const headers = { ...cors, 'content-type': meta.type, 'content-length': String((await stat(this.path(hash, 'bin'))).size), 'cache-control': 'public, max-age=31536000, immutable' };
        return { status: 200, headers, ...(req.method === 'GET' ? { body: new Uint8Array(await readFile(this.path(hash, 'bin'))) } : {}) };
      }
    }
    if (url.pathname === '/health') return { status: 200, body: '{"ok":true}', headers: { 'content-type': 'application/json' } };
    return reason(404, 'not found');
  }

  async listen(port = 0, host = '127.0.0.1'): Promise<string> {
    await mkdir(this.opts.dir, { recursive: true, mode: 0o700 });
    this.server = createServer((req, res) => {
      this.handle(req).then(
        (r) => {
          res.writeHead(r.status, r.headers);
          res.end(r.body);
        },
        (err: Error & { status?: number }) => {
          res.writeHead(err.status ?? 500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: err.status ? err.message : 'internal error' }));
        },
      );
    });
    await new Promise<void>((r) => this.server!.listen(port, host, () => r()));
    this.url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${(this.server.address() as AddressInfo).port}`;
    return this.url;
  }

  async close() {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }
}
