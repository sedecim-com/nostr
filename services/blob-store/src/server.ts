import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdir, readFile, rm, writeFile, rename, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, getTagValue, getTagValues, verifyEvent, type NostrEvent } from '@sedecim/nostr-core';
import { createLogger, type Logger, type Tracer } from '@sedecim/telemetry-policy';
import { createServiceTracer, HttpRateLimiter, isOnionHost, logRateLimited, retryAfterSeconds, type HttpRateLimitOptions, type RateClass, type RateScope, type ServiceTracingOptions } from '@sedecim/service-kit';

export interface BlobStoreOptions {
  dir: string;
  publicUrl?: string;
  /** Only these pubkeys may upload (empty = any authenticated pubkey). */
  allowedPubkeys?: string[];
  maxBytes?: number;
  logger?: Logger;
  /** IR-2026-09-05: token buckets by IP (before reading the body) and by pubkey. Off unless given. */
  rateLimit?: HttpRateLimitOptions | HttpRateLimiter | false;
  /** Uploads in flight per client IP (default 4); each one can hold up to `maxBytes` in memory. */
  maxConcurrentUploadsPerIp?: number;
  /** NFR007-02: a span per request, as in service-kit (tracingFromEnv). Off unless given, and at telemetry level 'none'. */
  tracing?: ServiceTracingOptions | Tracer;
}

/** The route of a request as a template (NFR007-02): a blob is `/:sha256`, never its hash. */
function routeOf(pathname: string): string | undefined {
  if (pathname === '/health' || pathname === '/upload') return pathname;
  return /^\/[0-9a-f]{64}(\.[a-z0-9]{1,8})?$/.test(pathname) ? '/:sha256' : undefined;
}

type Reply = { status: number; body?: Uint8Array | string; headers?: Record<string, string> };
/** Either the verified token or the reply to send instead; kept apart so request data never reaches a reply. */
type Authorized = { event: NostrEvent; reply?: undefined } | { event?: undefined; reply: Reply };

/** Served with every blob: no sniffing, no scripts, no plugins, even for `text/html` or SVG uploads. */
export const BLOB_SAFETY_HEADERS = { 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; sandbox" } as const;

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
  readonly rateLimiter?: HttpRateLimiter;
  readonly tracer: Tracer;
  private readonly uploadsByIp = new Map<string, number>();

  constructor(private readonly opts: BlobStoreOptions) {
    this.log = opts.logger ?? createLogger({ base: { service: 'blob-store' }, minimizeIp: true });
    if (opts.rateLimit) this.rateLimiter = opts.rateLimit instanceof HttpRateLimiter ? opts.rateLimit : new HttpRateLimiter(opts.rateLimit);
    this.tracer = createServiceTracer('blob-store', opts.tracing, this.log);
  }

  private path(hash: string, ext: 'bin' | 'json') {
    return join(this.opts.dir, hash.slice(0, 2), `${hash}.${ext}`);
  }

  private async meta(hash: string): Promise<Meta | undefined> {
    try {
      return JSON.parse(await readFile(this.path(hash, 'json'), 'utf8')) as Meta;
    } catch {
      return undefined;
    }
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

  async handle(req: IncomingMessage): Promise<Reply> {
    const url = new URL(req.url ?? '/', 'http://x');
    const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, x-sha-256', 'access-control-allow-methods': 'GET, HEAD, PUT, DELETE' };
    const reason = (status: number, r: string, retryAfter?: string): Reply => {
      const headers: Record<string, string> = { ...cors, 'content-type': 'application/json', 'x-reason': r };
      if (retryAfter !== undefined) headers['retry-after'] = retryAfter;
      return { status, body: JSON.stringify({ error: r }), headers };
    };
    if (req.method === 'OPTIONS') return { status: 204, headers: cors };
    if (url.pathname === '/health') return { status: 200, body: '{"ok":true}', headers: { 'content-type': 'application/json' } };
    const rl = this.rateLimiter;
    const ip = rl ? rl.ip(req) : '';
    /** 429 reply when the bucket is empty, undefined otherwise. */
    const limited = (cls: RateClass, scope: RateScope, id: string): Reply | undefined => {
      const d = rl?.check(cls, scope, id);
      if (!d || d.ok) return undefined;
      logRateLimited(this.log, cls, scope, d.retryAfterMs);
      return reason(429, 'too many requests', retryAfterSeconds(d.retryAfterMs));
    };
    /** Verifies a kind 24242 token; failures charge the strict `auth` bucket of the address. */
    const authorize = (verb: 'upload' | 'delete'): Authorized => {
      const a = this.auth(req.headers.authorization, verb);
      if (typeof a === 'string') return { reply: (ip && limited('auth', 'ip', ip)) || reason(401, a) };
      const reply = limited('mutating', 'principal', a.pubkey);
      return reply ? { reply } : { event: a };
    };
    const cls: RateClass = req.method === 'GET' || req.method === 'HEAD' ? 'read' : 'mutating';
    if (ip) {
      const r = limited(cls, 'ip', ip);
      if (r) return r;
    }
    if (req.method === 'PUT' && url.pathname === '/upload') {
      const { event: a, reply } = authorize('upload');
      if (!a) return reply!;
      // Checked before reading the body: each upload may buffer up to maxBytes.
      const inFlight = this.uploadsByIp.get(ip) ?? 0;
      if (rl && inFlight >= (this.opts.maxConcurrentUploadsPerIp ?? 4)) return reason(429, 'too many concurrent uploads', '1');
      this.uploadsByIp.set(ip, inFlight + 1);
      try {
        return await this.upload(req, a, cors, reason);
      } finally {
        const n = (this.uploadsByIp.get(ip) ?? 1) - 1;
        if (n > 0) this.uploadsByIp.set(ip, n);
        else this.uploadsByIp.delete(ip);
      }
    }
    return this.byHash(req, url, cors, reason, authorize);
  }

  private async upload(req: IncomingMessage, a: NostrEvent, cors: Record<string, string>, reason: (status: number, r: string) => Reply): Promise<Reply> {
    const data = await this.body(req);
    const hash = bytesToHex(sha256(data));
    if (!getTagValues(a, 'x').includes(hash)) return reason(403, 'authorization does not cover this hash');
    // Content is public by hash: re-uploading the same bytes must not transfer ownership (and with it
    // the right to delete another user's blob). The first uploader keeps it.
    const existing = await this.meta(hash);
    const meta: Meta = existing ?? { sha256: hash, size: data.length, type: String(req.headers['content-type'] ?? 'application/octet-stream').slice(0, 100), uploader: a.pubkey, uploaded: Math.floor(Date.now() / 1000) };
    if (!existing) {
      await mkdir(join(this.opts.dir, hash.slice(0, 2)), { recursive: true, mode: 0o700 });
      const tmp = `${this.path(hash, 'bin')}.${randomBytes(6).toString('hex')}.tmp`;
      await writeFile(tmp, data, { mode: 0o600 });
      await rename(tmp, this.path(hash, 'bin'));
      await writeFile(this.path(hash, 'json'), JSON.stringify(meta), { flag: 'wx', mode: 0o600 }).catch((err: NodeJS.ErrnoException) => {
        if (err.code !== 'EEXIST') throw err; // concurrent upload of the same bytes: first one wins
      });
      this.log.info('blob stored', { sha256: hash, size: data.length });
    }
    const base = this.opts.publicUrl ?? this.url;
    return { status: 200, body: JSON.stringify({ url: `${base}/${hash}`, sha256: hash, size: meta.size, type: meta.type, uploaded: meta.uploaded }), headers: { ...cors, 'content-type': 'application/json' } };
  }

  private async byHash(req: IncomingMessage, url: URL, cors: Record<string, string>, reason: (status: number, r: string) => Reply, authorize: (verb: 'delete') => Authorized): Promise<Reply> {
    const m = /^\/([0-9a-f]{64})(\.[a-z0-9]{1,8})?$/.exec(url.pathname);
    if (m) {
      const hash = m[1]!;
      const meta = await this.meta(hash);
      if (!meta) return reason(404, 'not found');
      if (req.method === 'DELETE') {
        const { event: a, reply } = authorize('delete');
        if (!a) return reply!;
        if (a.pubkey !== meta.uploader || !getTagValues(a, 'x').includes(hash)) return reason(403, 'only the uploader can delete');
        await rm(this.path(hash, 'bin'), { force: true });
        await rm(this.path(hash, 'json'), { force: true });
        return { status: 200, body: '{"deleted":true}', headers: { ...cors, 'content-type': 'application/json' } };
      }
      if (req.method === 'GET' || req.method === 'HEAD') {
        // The type is uploader-chosen: never let a stored blob run as a page on this origin.
        const headers = { ...cors, ...BLOB_SAFETY_HEADERS, 'content-type': meta.type, 'content-length': String((await stat(this.path(hash, 'bin'))).size), 'cache-control': 'public, max-age=31536000, immutable' };
        return { status: 200, headers, ...(req.method === 'GET' ? { body: new Uint8Array(await readFile(this.path(hash, 'bin'))) } : {}) };
      }
    }
    return reason(404, 'not found');
  }

  async listen(port = 0, host = '127.0.0.1'): Promise<string> {
    await mkdir(this.opts.dir, { recursive: true, mode: 0o700 });
    this.server = createServer((req, res) => {
      // NFR007-02: each request is the root of a trace (method, route template, status, duration); never for a .onion host.
      const route = routeOf((req.url ?? '/').split('?')[0]!);
      const opts = { kind: 'server' as const, attributes: { 'http.request.method': req.method, ...(route ? { 'http.route': route } : {}) }, untraced: isOnionHost(req.headers.host) };
      void this.tracer.withSpan(
        route ? `${req.method} ${route}` : (req.method ?? 'http.server'),
        (span) =>
          this.handle(req).then(
            (r) => {
              span.setAttribute('http.response.status_code', r.status);
              res.writeHead(r.status, r.headers);
              res.end(r.body);
            },
            (err: Error & { status?: number }) => {
              const status = err.status ?? 500;
              span.setAttribute('http.response.status_code', status);
              if (status >= 500) span.recordError(err);
              res.writeHead(status, { 'content-type': 'application/json' });
              res.end(JSON.stringify({ error: err.status ? err.message : 'internal error' }));
            },
          ),
        opts,
      );
    });
    await new Promise<void>((r) => this.server!.listen(port, host, () => r()));
    this.url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${(this.server.address() as AddressInfo).port}`;
    return this.url;
  }

  async close() {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
    await this.tracer.shutdown();
  }
}
