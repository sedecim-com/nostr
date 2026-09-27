import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Logger } from '@sedecim/telemetry-policy';

/**
 * IR-2026-09-05: in-process token buckets for the HTTP APIs. Limits are per replica: with N replicas the
 * effective limit is up to N times higher (the edge adds a global-ish layer per edge pod).
 */

/** Token bucket: `burst` tokens at most, refilled at `perMinute` tokens per minute. */
export interface RateRule {
  perMinute: number;
  /** Bucket size (default: perMinute). */
  burst?: number;
}

/**
 * Route classes. `auth`: account creation, token-authenticated reads of secrets (backups) and failed
 * authentications; `mutating`: other POST/PUT/DELETE; `read`: GET; `service`: bearer service-to-service.
 */
export type RateClass = 'auth' | 'mutating' | 'read' | 'service';
export const RATE_CLASSES: readonly RateClass[] = ['auth', 'mutating', 'read', 'service'];

export const DEFAULT_HTTP_RATE_LIMITS: Record<RateClass, RateRule> = {
  auth: { perMinute: 20, burst: 10 },
  mutating: { perMinute: 120, burst: 60 },
  read: { perMinute: 600, burst: 300 },
  service: { perMinute: 6000, burst: 1000 },
};

export type RateDecision = { ok: true } | { ok: false; retryAfterMs: number };

interface Bucket {
  tokens: number;
  at: number;
}

/** Token buckets keyed by string, bounded: the least recently used bucket is evicted (a reset only forgives). */
export class TokenBucketLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly opts: { maxKeys?: number; now?: () => number } = {}) {}

  get size() {
    return this.buckets.size;
  }

  take(key: string, rule: RateRule, cost = 1): RateDecision {
    const now = this.opts.now?.() ?? Date.now();
    const cap = rule.burst ?? rule.perMinute;
    const prev = this.buckets.get(key);
    const tokens = prev ? Math.min(cap, prev.tokens + ((now - prev.at) * rule.perMinute) / 60_000) : cap;
    // Re-insert so Map order is least-recently-used first.
    this.buckets.delete(key);
    if (tokens < cost) {
      this.buckets.set(key, { tokens, at: now });
      return { ok: false, retryAfterMs: Math.ceil(((cost - tokens) * 60_000) / rule.perMinute) };
    }
    this.buckets.set(key, { tokens: tokens - cost, at: now });
    const max = this.opts.maxKeys ?? 100_000;
    while (this.buckets.size > max) this.buckets.delete(this.buckets.keys().next().value!);
    return { ok: true };
  }
}

/**
 * Client address. `trustProxyHops` = number of reverse proxies in front of the service that append to
 * X-Forwarded-For (0: ignore the header, the default; spoofable otherwise).
 */
export function clientIp(req: Pick<IncomingMessage, 'headers' | 'socket'>, trustProxyHops = 0): string {
  const socket = req.socket.remoteAddress ?? 'unknown';
  if (trustProxyHops <= 0) return socket;
  const raw = req.headers['x-forwarded-for'];
  const chain = (Array.isArray(raw) ? raw.join(',') : (raw ?? '')).split(',').map((s) => s.trim()).filter(Boolean);
  // Right to left: socket peer, then each trusted hop's view of its client.
  const addrs = [socket, ...chain.reverse()];
  return addrs[Math.min(trustProxyHops, addrs.length - 1)]!;
}

export interface HttpRateLimitOptions {
  rules?: Partial<Record<RateClass, RateRule>>;
  trustProxyHops?: number;
  maxKeys?: number;
  now?: () => number;
}

export type RateScope = 'ip' | 'principal';

/** Per-class limiter by client IP (before auth) and by principal (after auth), with a 429-counter. */
export class HttpRateLimiter {
  readonly rules: Record<RateClass, RateRule>;
  private readonly buckets: TokenBucketLimiter;
  private readonly limited = new Map<string, number>();

  constructor(readonly opts: HttpRateLimitOptions = {}) {
    this.rules = { ...DEFAULT_HTTP_RATE_LIMITS, ...opts.rules };
    this.buckets = new TokenBucketLimiter({ maxKeys: opts.maxKeys, now: opts.now });
  }

  ip(req: Pick<IncomingMessage, 'headers' | 'socket'>): string {
    return clientIp(req, this.opts.trustProxyHops);
  }

  check(cls: RateClass, scope: RateScope, id: string): RateDecision {
    const d = this.buckets.take(`${cls}:${scope}:${id}`, this.rules[cls]);
    if (!d.ok) this.limited.set(`${cls}:${scope}`, (this.limited.get(`${cls}:${scope}`) ?? 0) + 1);
    return d;
  }

  get trackedKeys() {
    return this.buckets.size;
  }

  /** Prometheus text: counts by class and scope only (never IPs or principals). */
  async render(): Promise<string> {
    const lines = ['# HELP http_rate_limited_total Requests rejected with 429 by the in-process rate limiter.', '# TYPE http_rate_limited_total counter'];
    for (const cls of RATE_CLASSES) for (const scope of ['ip', 'principal'] as const) lines.push(`http_rate_limited_total{class="${cls}",scope="${scope}"} ${this.limited.get(`${cls}:${scope}`) ?? 0}`);
    return lines.join('\n') + '\n';
  }
}

/** Seconds for a Retry-After header (at least 1). */
export const retryAfterSeconds = (ms: number) => String(Math.max(1, Math.ceil(ms / 1000)));

/** Audit line of a 429: class and scope only, no address, pubkey or token. */
export function logRateLimited(logger: Logger, cls: RateClass, scope: RateScope, retryAfterMs: number) {
  logger.warn('rate limited', { class: cls, scope, retry_after_s: Number(retryAfterSeconds(retryAfterMs)) });
}

/** `perMinute[:burst]`. */
function parseRule(name: string, v: string): RateRule {
  const [perMinute, burst] = v.split(':').map(Number);
  if (!(perMinute! > 0) || (burst !== undefined && !(burst > 0))) throw new Error(`${name} must be perMinute[:burst] with positive numbers, got '${v}'`);
  return { perMinute: perMinute!, ...(burst !== undefined ? { burst } : {}) };
}

/**
 * Env knobs shared by every service: RATE_LIMIT=off disables; RATE_LIMIT_AUTH / _MUTATING / _READ / _SERVICE
 * = `perMinute[:burst]`; RATE_LIMIT_TRUST_PROXY_HOPS = proxies whose X-Forwarded-For is trusted (default 0);
 * RATE_LIMIT_MAX_KEYS = buckets kept in memory (default 100000).
 */
export function rateLimitFromEnv(env: Record<string, string | undefined>): HttpRateLimitOptions | false {
  if (env.RATE_LIMIT === 'off') return false;
  const rules: Partial<Record<RateClass, RateRule>> = {};
  for (const cls of RATE_CLASSES) {
    const v = env[`RATE_LIMIT_${cls.toUpperCase()}`];
    if (v) rules[cls] = parseRule(`RATE_LIMIT_${cls.toUpperCase()}`, v);
  }
  const hops = Number(env.RATE_LIMIT_TRUST_PROXY_HOPS ?? 0);
  if (!Number.isInteger(hops) || hops < 0) throw new Error('RATE_LIMIT_TRUST_PROXY_HOPS must be a non-negative integer');
  const maxKeys = Number(env.RATE_LIMIT_MAX_KEYS ?? 100_000);
  if (!(maxKeys > 0)) throw new Error('RATE_LIMIT_MAX_KEYS must be positive');
  return { rules, trustProxyHops: hops, maxKeys };
}

/** Serves `GET /metrics` from `render` on an internal port (never through the public API). */
export async function serveMetrics(render: () => Promise<string>, opts: { port: number; host?: string }): Promise<{ url: string; close(): Promise<void> }> {
  const server: Server = createServer((req, res) => {
    if (req.method !== 'GET' || (req.url ?? '/').split('?')[0] !== '/metrics') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    render().then(
      (body) => (res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store' }), res.end(body)),
      () => (res.writeHead(500, { 'content-type': 'text/plain' }), res.end('metrics unavailable')),
    );
  });
  const host = opts.host ?? '127.0.0.1';
  await new Promise<void>((r) => server.listen(opts.port, host, () => r()));
  const { port } = server.address() as AddressInfo;
  return { url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/metrics`, close: () => new Promise<void>((r) => server.close(() => r())) };
}
