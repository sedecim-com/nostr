import { randomUUID } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { BlockList, isIP, type LookupFunction } from 'node:net';
import { WEBHOOK_SIGNATURE_HEADER, webhookSecret, webhookSignatureHeader } from './events';
import type { ClaimedDelivery, PolicyRepository } from './repository';

/**
 * OPS-16: webhooks. The policy-engine POSTs each event to the subscriptions that want it, signed with the subscription's
 * secret, and retries with exponential backoff. A webhook is a request the server makes to a URL an admin typed, so the
 * destination is checked before every connection (SSRF): https only, no redirects, and every address the name resolves
 * to must be public; the connection then goes to that checked address, without resolving the name again (DNS rebinding).
 */

/** Why a destination is refused before connecting. */
export class DestinationError extends Error {
  constructor(
    readonly kind: 'invalid' | 'blocked' | 'dns',
    message: string,
  ) {
    super(message);
  }
}

export type Resolver = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

/**
 * The name as an absolute one (a trailing dot), so that the search domains of the pod or host
 * (`<name>.<namespace>.svc.cluster.local`…) never turn a short name into an internal service.
 */
export const absoluteName = (hostname: string) => (hostname.endsWith('.') ? hostname : `${hostname}.`);

/** The system resolver, asked for the absolute name. */
export const systemResolver: Resolver = (hostname) => dnsLookup(absoluteName(hostname), { all: true, verbatim: true });

export interface DestinationPolicy {
  /** POLICY_WEBHOOKS_ALLOW_PRIVATE (tests and development only): no address or name check, and `http:` allowed. */
  allowPrivate: boolean;
  resolve: Resolver;
  /**
   * Which resolved addresses count as public, instead of `isPublicAddress` (and checked even with allowPrivate): tests
   * narrow it to their own server.
   */
  isAllowed?: (address: string) => boolean;
}

/**
 * Addresses a webhook never reaches (IANA special-purpose registries): this host, private networks, shared CGNAT space
 * (Alibaba's metadata), link-local (169.254.169.254, the metadata service of AWS, GCP, Azure and OpenStack), IETF
 * assignments (Oracle's 192.0.0.192), documentation, benchmarking, multicast and reserved space; in IPv6 the same plus
 * ULA (AWS's fd00:ec2::254), and the forms that embed an IPv4 address (IPv4-compatible and -translated, NAT64, 6to4,
 * Teredo). An IPv4-mapped address (::ffff:a.b.c.d) is checked as its IPv4 address.
 */
const BLOCKED_V4: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];
const BLOCKED_V6: Array<[string, number]> = [
  ['::', 96],
  ['::ffff:0:0:0', 96],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['5f00::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
];
// Never add ::ffff:0:0/96 here: BlockList maps IPv4 onto it, and that rule would block every IPv4 address.
const BLOCKED = new BlockList();
for (const [net, prefix] of BLOCKED_V4) BLOCKED.addSubnet(net, prefix, 'ipv4');
for (const [net, prefix] of BLOCKED_V6) BLOCKED.addSubnet(net, prefix, 'ipv6');

/** Whether a webhook may connect to this address. A scoped IPv6 address (`%zone`) never is. */
export function isPublicAddress(address: string): boolean {
  if (address.includes('%')) return false;
  const v = isIP(address);
  return v !== 0 && !BLOCKED.check(address, v === 6 ? 'ipv6' : 'ipv4');
}

/** Names that only mean something inside a network: loopback, mDNS, cloud-internal DNS, Tor, home networks. */
const INTERNAL_NAME = /(^|\.)(localhost|local|localdomain|internal|intranet|lan|onion|home\.arpa)$/i;

const hostOf = (url: URL) => url.hostname.replace(/^\[(.*)\]$/, '$1');

export const WEBHOOK_URL_MAX = 2048;

/**
 * Parses and checks a webhook URL, when it is registered and before each delivery: https (http only with allowPrivate),
 * no credentials, no fragment, and a host that can be public: a public IP literal or a name with a dot outside the
 * internal suffixes. Where the name resolves is checked by `resolveDestination`, right before connecting.
 */
export function checkWebhookUrl(raw: unknown, allowPrivate: boolean): URL {
  if (typeof raw !== 'string' || !raw || raw.length > WEBHOOK_URL_MAX) throw new DestinationError('invalid', `url must be a string of up to ${WEBHOOK_URL_MAX} chars`);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new DestinationError('invalid', 'url is not a valid URL');
  }
  if (url.protocol !== 'https:' && !(allowPrivate && url.protocol === 'http:')) throw new DestinationError('invalid', 'url must be https');
  if (url.username || url.password) throw new DestinationError('invalid', 'url must not carry credentials');
  if (url.hash) throw new DestinationError('invalid', 'url must not have a fragment');
  const host = hostOf(url);
  if (!host || host.endsWith('.')) throw new DestinationError('invalid', 'url has no usable host');
  if (allowPrivate) return url;
  if (isIP(host)) {
    if (!isPublicAddress(host)) throw new DestinationError('blocked', 'destination is not a public address');
  } else if (!host.includes('.') || INTERNAL_NAME.test(host)) throw new DestinationError('blocked', 'destination is not a public host name');
  return url;
}

/**
 * Resolves the destination once and checks every address it answers (one internal answer refuses it all); returns the
 * address to connect to. The connection must use it, never the name, so that a second answer cannot differ.
 */
export async function resolveDestination(url: URL, policy: DestinationPolicy): Promise<{ address: string; family: 4 | 6 }> {
  const host = hostOf(url);
  const literal = isIP(host);
  if (literal) return { address: host, family: literal === 6 ? 6 : 4 };
  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await policy.resolve(host);
  } catch {
    throw new DestinationError('dns', 'destination does not resolve');
  }
  if (!answers.length) throw new DestinationError('dns', 'destination does not resolve');
  const allowed = policy.isAllowed ?? (policy.allowPrivate ? undefined : isPublicAddress);
  if (allowed && answers.some((a) => !allowed(a.address))) throw new DestinationError('blocked', 'destination resolves to an address that is not public');
  const [first] = answers;
  return { address: first!.address, family: first!.family === 6 ? 6 : 4 };
}

/** The lookup handed to the socket: always the checked address, whatever it is asked. */
const pinnedLookup = (dest: { address: string; family: 4 | 6 }): LookupFunction =>
  ((_hostname: string, options: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    if (options?.all) callback(null, [{ address: dest.address, family: dest.family }]);
    else callback(null, dest.address, dest.family);
  }) as LookupFunction;

/** Class of a failed delivery: what the delivery log keeps, never the destination's response. */
export type DeliveryErrorClass = 'invalid_destination' | 'blocked_destination' | 'dns' | 'connect' | 'tls' | 'timeout' | 'connection_closed' | 'redirect' | 'http_4xx' | 'http_5xx' | 'http_other' | 'payload_too_large' | 'network';

export interface DeliveryResult {
  ok: boolean;
  /** HTTP status, when the destination answered. */
  status?: number;
  error?: DeliveryErrorClass;
}

export interface WebhookRequest {
  url: string;
  body: string;
  headers: Record<string, string>;
}

/** Largest event a webhook sends (the event stays readable from GET /v1/events). */
export const WEBHOOK_MAX_BODY_BYTES = 64 * 1024;

class DeliveryTimeout extends Error {}

function errorClass(e: unknown): DeliveryErrorClass {
  if (e instanceof DeliveryTimeout) return 'timeout';
  const code = String((e as { code?: unknown })?.code ?? '');
  const message = String((e as Error)?.message ?? '');
  if (['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL'].includes(code)) return 'connect';
  if (['ECONNRESET', 'EPIPE', 'ECONNABORTED'].includes(code) || /socket hang up/i.test(message)) return 'connection_closed';
  if (/^ERR_(TLS|SSL)_/.test(code) || /CERT|SELF_SIGNED|UNABLE_TO_(GET|VERIFY)/.test(code)) return 'tls';
  if (['ENOTFOUND', 'EAI_AGAIN'].includes(code)) return 'dns';
  return 'network';
}

function statusResult(status: number): DeliveryResult {
  if (status >= 200 && status < 300) return { ok: true, status };
  if (status >= 300 && status < 400) return { ok: false, status, error: 'redirect' };
  if (status >= 400 && status < 500) return { ok: false, status, error: 'http_4xx' };
  if (status >= 500 && status < 600) return { ok: false, status, error: 'http_5xx' };
  return { ok: false, status, error: 'http_other' };
}

/**
 * One delivery: checks the URL, resolves and checks the destination, then POSTs to that address (TLS still verifies
 * the certificate for the host name). The whole request, name resolution included, has `timeoutMs`. A redirect is a
 * failure, never followed. Only the status line is read: the response body is discarded unread with its socket.
 */
export async function postWebhook(req: WebhookRequest, opts: { policy: DestinationPolicy; timeoutMs: number }): Promise<DeliveryResult> {
  let url: URL;
  try {
    url = checkWebhookUrl(req.url, opts.policy.allowPrivate);
  } catch (e) {
    return { ok: false, error: e instanceof DestinationError && e.kind === 'blocked' ? 'blocked_destination' : 'invalid_destination' };
  }
  const bytes = Buffer.byteLength(req.body, 'utf8');
  if (bytes > WEBHOOK_MAX_BODY_BYTES) return { ok: false, error: 'payload_too_large' };
  let timer: NodeJS.Timeout | undefined;
  const expired = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new DeliveryTimeout()), opts.timeoutMs)));
  expired.catch(() => {});
  try {
    let dest: { address: string; family: 4 | 6 };
    try {
      dest = await Promise.race([resolveDestination(url, opts.policy), expired]);
    } catch (e) {
      if (e instanceof DestinationError) return { ok: false, error: e.kind === 'blocked' ? 'blocked_destination' : 'dns' };
      return { ok: false, error: errorClass(e) };
    }
    return await new Promise<DeliveryResult>((resolve) => {
      const host = hostOf(url);
      const secure = url.protocol === 'https:';
      const request = (secure ? https : http).request({
        protocol: url.protocol,
        hostname: host,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method: 'POST',
        // A socket of its own, always to the checked address: no pool that could reuse another connection.
        agent: false,
        lookup: pinnedLookup(dest),
        ...(secure && !isIP(host) ? { servername: host } : {}),
        headers: { ...req.headers, 'content-length': String(bytes) },
      });
      let settled = false;
      const done = (r: DeliveryResult) => {
        if (settled) return;
        settled = true;
        resolve(r);
      };
      expired.catch((e: unknown) => {
        request.destroy(e as Error);
        done({ ok: false, error: 'timeout' });
      });
      request.on('response', (res) => {
        done(statusResult(res.statusCode ?? 0));
        res.destroy();
      });
      request.on('error', (e) => done({ ok: false, error: errorClass(e) }));
      request.end(req.body);
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Delay before the next attempt: exponential from `baseMs`, capped at `maxMs`, with jitter (between half and all of it). */
export function retryDelay(attempt: number, random: () => number, baseMs = 30_000, maxMs = 6 * 3_600_000): number {
  const ceiling = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt - 1));
  return Math.round(ceiling / 2 + Math.min(1, Math.max(0, random())) * (ceiling / 2));
}

export const WEBHOOK_USER_AGENT = 'acceso-nostr-policy-webhooks/1';

export interface WebhookDispatcherOptions {
  repo: PolicyRepository;
  /** POLICY_WEBHOOK_SECRETS_KEY: the subscriptions' secrets are derived from it. */
  secretsKey: Buffer;
  policy: DestinationPolicy;
  now?: () => number;
  random?: () => number;
  /** Attempts per delivery before it fails for good (POLICY_WEBHOOK_MAX_ATTEMPTS, 10). */
  maxAttempts?: number;
  /** Consecutive failed attempts that disable a subscription (POLICY_WEBHOOK_DISABLE_AFTER, 15). */
  disableAfter?: number;
  /** Limit of each request, name resolution included (POLICY_WEBHOOK_TIMEOUT_MS, 10 s). */
  timeoutMs?: number;
  /** Deliveries in flight at once in this process. */
  concurrency?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
  /** Replaces the HTTP request (tests). */
  send?: (req: WebhookRequest) => Promise<DeliveryResult>;
  /** A subscription was disabled by its failures (the engine audits it). */
  onDisabled?: (webhookId: string, failures: number) => Promise<void>;
  log?: (msg: string, fields: Record<string, unknown>) => void;
}

/** Extra time a claim lasts beyond the request limit before another replica may take the delivery over. */
export const LEASE_MARGIN_MS = 30_000;

/**
 * Sends the pending deliveries. Several replicas may run one each: a delivery is claimed with a lease (FOR UPDATE SKIP
 * LOCKED in Postgres), so two never send it at once, and a claim whose process died expires and is taken over. At least
 * once: a delivery is retried until the destination answers 2xx or its attempts run out, and a receiver may see an event
 * twice (same `Idempotency-Key`). A slow destination holds one slot until its limit, never the others.
 */
export class WebhookDispatcher {
  private readonly inflight = new Set<Promise<void>>();
  private timer?: NodeJS.Timeout;
  private ticking = false;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly maxAttempts: number;
  private readonly disableAfter: number;
  private readonly timeoutMs: number;
  private readonly concurrency: number;
  private readonly send: (req: WebhookRequest) => Promise<DeliveryResult>;

  constructor(private readonly opts: WebhookDispatcherOptions) {
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    this.maxAttempts = opts.maxAttempts ?? 10;
    this.disableAfter = opts.disableAfter ?? 15;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.concurrency = opts.concurrency ?? 8;
    this.send = opts.send ?? ((req) => postWebhook(req, { policy: opts.policy, timeoutMs: this.timeoutMs }));
  }

  /** Deliveries of this process still in flight. */
  get pending(): number {
    return this.inflight.size;
  }

  /** Claims the due deliveries there is room for and starts them; returns how many. It does not wait for them. */
  async tick(): Promise<number> {
    const room = this.concurrency - this.inflight.size;
    if (room <= 0) return 0;
    const leaseId = randomUUID();
    const claimed = await this.opts.repo.claimDeliveries({ now: this.now(), limit: room, leaseMs: this.timeoutMs + LEASE_MARGIN_MS, leaseId, maxAttempts: this.maxAttempts });
    for (const c of claimed) {
      const p: Promise<void> = this.deliver(c, leaseId)
        .catch((e: Error) => this.opts.log?.('webhook delivery not recorded', { webhook: c.webhookId, delivery: c.id, error: e.message }))
        .finally(() => this.inflight.delete(p));
      this.inflight.add(p);
    }
    return claimed.length;
  }

  /** Waits until this process has no delivery in flight. */
  async drain(): Promise<void> {
    while (this.inflight.size) await Promise.allSettled([...this.inflight]);
  }

  start(intervalMs: number): void {
    this.timer = setInterval(() => {
      if (this.ticking) return;
      this.ticking = true;
      this.tick()
        .catch((e: Error) => this.opts.log?.('webhook dispatch failed', { error: e.message }))
        .finally(() => (this.ticking = false));
    }, intervalMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    clearInterval(this.timer);
    await this.drain();
  }

  private async deliver(c: ClaimedDelivery, leaseId: string): Promise<void> {
    const secret = webhookSecret(this.opts.secretsKey, c.webhookId, c.salt);
    const headers = {
      'content-type': 'application/json',
      'user-agent': WEBHOOK_USER_AGENT,
      'idempotency-key': c.eventId,
      [WEBHOOK_SIGNATURE_HEADER]: webhookSignatureHeader(secret, c.envelope, Math.floor(this.now() / 1000)),
    };
    let result: DeliveryResult;
    try {
      result = await this.send({ url: c.url, body: c.envelope, headers });
    } catch {
      result = { ok: false, error: 'network' };
    }
    const now = this.now();
    // An event too large for a webhook will not shrink: no retries.
    const final = result.ok || result.error === 'payload_too_large' || c.attempts >= this.maxAttempts;
    const retryAt = final ? undefined : now + retryDelay(c.attempts, this.random, this.opts.retryBaseMs, this.opts.retryMaxMs);
    const outcome = await this.opts.repo.completeDelivery({
      id: c.id,
      leaseId,
      now,
      ok: result.ok,
      ...(result.status !== undefined ? { status: result.status } : {}),
      ...(result.error ? { error: result.error } : {}),
      ...(retryAt !== undefined ? { retryAt } : {}),
      disableAfter: this.disableAfter,
    });
    // Failures only, and never the URL, the body, the secret or anything the destination sent.
    if (!result.ok) this.opts.log?.('webhook delivery failed', { webhook: c.webhookId, delivery: c.id, attempt: c.attempts, status: result.status ?? null, error: result.error ?? null, retry: retryAt !== undefined });
    if (outcome.disabled) {
      this.opts.log?.('webhook subscription disabled', { webhook: c.webhookId, failures: outcome.failures });
      await this.opts.onDisabled?.(c.webhookId, outcome.failures);
    }
  }
}
