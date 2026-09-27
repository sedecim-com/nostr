import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { timingSafeEqual } from 'node:crypto';
import { nip98 } from '@sedecim/nostr-core';
import { createLogger, type Logger } from '@sedecim/telemetry-policy';

/** 'nip98-or-token': NIP-98, or an `Authorization: Bearer` token handed to the route as `req.token` to verify (e.g. Cognito). */
export type AuthMode = 'none' | 'nip98' | 'bearer' | 'nip98-optional' | 'nip98-or-token';

export interface Req {
  method: string;
  path: string;
  params: Record<string, string>;
  query: URLSearchParams;
  headers: IncomingMessage['headers'];
  rawBody: string;
  /** Authenticated Nostr pubkey (NIP-98). */
  pubkey?: string;
  /** Authenticated service principal (bearer). */
  principal?: string;
  /** Unverified bearer token ('nip98-or-token' routes): the handler must verify it. */
  token?: string;
  json<T = unknown>(): T;
}

export interface Res {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

/** Constant-time string comparison; compares byte lengths first so timingSafeEqual never throws. */
export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Principal of the first configured token that matches (constant time per comparison). */
export function lookupToken(tokens: Record<string, string> | undefined, token: string): string | undefined {
  return Object.entries(tokens ?? {}).find(([t]) => safeEqual(t, token))?.[1];
}

export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

type Handler = (req: Req) => Promise<Res | unknown> | Res | unknown;

interface Route {
  method: string;
  pattern: RegExp;
  keys: string[];
  handler: Handler;
  auth: AuthMode;
}

export interface ServiceOptions {
  name: string;
  /** Public base URL used to validate NIP-98 `u` tags (e.g. https://api.example.com). */
  publicBaseUrl?: string;
  /** Map of bearer token -> principal name, for service-to-service calls. */
  bearerTokens?: Record<string, string>;
  logger?: Logger;
  maxBodyBytes?: number;
  /** Browser origins allowed to call this service (exact match), e.g. the web app. Empty: no CORS. */
  corsOrigins?: string[];
}

export class Service {
  private readonly routes: Route[] = [];
  private server?: Server;
  readonly logger: Logger;
  baseUrl = '';

  constructor(readonly opts: ServiceOptions) {
    this.logger = opts.logger ?? createLogger({ base: { service: opts.name }, minimizeIp: true });
  }

  route(method: string, path: string, handler: Handler, auth: AuthMode = 'none'): this {
    const keys: string[] = [];
    const pattern = new RegExp('^' + path.replace(/:([a-zA-Z_]+)/g, (_m, k: string) => (keys.push(k), '([^/]+)')) + '/?$');
    this.routes.push({ method: method.toUpperCase(), pattern, keys, handler, auth });
    return this;
  }

  get = (p: string, h: Handler, a?: AuthMode) => this.route('GET', p, h, a);
  post = (p: string, h: Handler, a?: AuthMode) => this.route('POST', p, h, a);
  put = (p: string, h: Handler, a?: AuthMode) => this.route('PUT', p, h, a);
  delete = (p: string, h: Handler, a?: AuthMode) => this.route('DELETE', p, h, a);

  private async readBody(req: IncomingMessage): Promise<string> {
    const max = this.opts.maxBodyBytes ?? 1_000_000;
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > max) throw new HttpError(413, 'body too large');
      chunks.push(c as Buffer);
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  private authenticate(route: Route, req: Req, rawUrl: string) {
    if (route.auth === 'none') return;
    const header = req.headers.authorization;
    if (route.auth === 'bearer') {
      const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
      const principal = token ? lookupToken(this.opts.bearerTokens, token) : undefined;
      if (!principal) throw new HttpError(401, 'invalid bearer token');
      req.principal = principal;
      return;
    }
    if (route.auth === 'nip98-optional' && !header) return;
    if (route.auth === 'nip98-or-token' && header?.startsWith('Bearer ')) {
      req.token = header.slice(7).trim();
      if (!req.token) throw new HttpError(401, 'empty bearer token');
      return;
    }
    const base = this.opts.publicBaseUrl ?? this.baseUrl;
    try {
      const evt = nip98.verifyAuthHeader(header, { url: base + rawUrl, method: req.method, body: req.rawBody });
      req.pubkey = evt.pubkey;
    } catch (err) {
      throw new HttpError(401, `NIP-98: ${(err as Error).message}`);
    }
  }

  private corsHeaders(req: IncomingMessage): Record<string, string> {
    const origin = req.headers.origin;
    if (!origin || !this.opts.corsOrigins?.includes(origin)) return {};
    return { 'access-control-allow-origin': origin, vary: 'Origin' };
  }

  async handle(req: IncomingMessage, res: ServerResponse) {
    const started = Date.now();
    const url = new URL(req.url ?? '/', 'http://local');
    let status = 500;
    const cors = this.corsHeaders(req);
    if (req.method === 'OPTIONS') {
      status = cors['access-control-allow-origin'] ? 204 : 403;
      res.writeHead(status, { ...cors, 'access-control-allow-methods': 'GET, POST, PUT, DELETE', 'access-control-allow-headers': 'authorization, content-type', 'access-control-max-age': '600' });
      res.end();
      return;
    }
    try {
      const route = this.routes.find((r) => r.method === req.method && r.pattern.test(url.pathname));
      if (!route) throw new HttpError(404, 'not found');
      const m = route.pattern.exec(url.pathname)!;
      const rawBody = req.method === 'GET' || req.method === 'HEAD' ? '' : await this.readBody(req);
      const r: Req = {
        method: req.method!,
        path: url.pathname,
        params: Object.fromEntries(route.keys.map((k, i) => [k, decodeParam(m[i + 1]!)])),
        query: url.searchParams,
        headers: req.headers,
        rawBody,
        json<T>() {
          try {
            return JSON.parse(rawBody || '{}') as T;
          } catch {
            throw new HttpError(400, 'invalid JSON body');
          }
        },
      };
      this.authenticate(route, r, req.url ?? '/');
      const out = await route.handler(r);
      const resObj: Res = out && typeof out === 'object' && ('body' in out || 'status' in out) ? (out as Res) : { body: out };
      status = resObj.status ?? 200;
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...cors, ...resObj.headers });
      res.end(resObj.body === undefined ? '' : JSON.stringify(resObj.body));
    } catch (err) {
      status = err instanceof HttpError ? err.status : 500;
      if (status === 500) this.logger.error('unhandled error', { error: (err as Error).message });
      res.writeHead(status, { 'content-type': 'application/json', ...cors });
      res.end(JSON.stringify({ error: err instanceof HttpError ? err.message : 'internal error' }));
    } finally {
      this.logger.debug('request', { method: req.method, path: url.pathname, status, ms: Date.now() - started });
    }
  }

  async listen(port = 0, host = '127.0.0.1'): Promise<string> {
    this.server = createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server!.listen(port, host, () => r()));
    const addr = this.server.address() as AddressInfo;
    this.baseUrl = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${addr.port}`;
    this.logger.info('listening', { port: addr.port });
    return this.baseUrl;
  }

  async close(): Promise<void> {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }
}

function decodeParam(v: string): string {
  try {
    return decodeURIComponent(v);
  } catch {
    throw new HttpError(400, 'malformed path parameter');
  }
}

export function requireFields<T extends Record<string, unknown>>(body: T, fields: Array<keyof T>): void {
  for (const f of fields) if (body[f] === undefined || body[f] === null || body[f] === '') throw new HttpError(400, `missing field: ${String(f)}`);
}

export const isHex64 = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
