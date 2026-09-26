import { connect } from 'node:net';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import WebSocket from 'ws';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { NetworkBlockedError, type WebSocketFactory, type WebSocketLike } from '@sedecim/relay-pool';

export type NetworkMode = 'direct' | 'tor-only';

export interface NetworkPolicyConfig {
  mode: NetworkMode;
  socksHost?: string;
  socksPort?: number;
  /** Only allow .onion endpoints (strictest Sovereign Tor profile). */
  onionOnly?: boolean;
  /** Explicit endpoint allowlist (host names). When set, anything else is blocked. */
  allowedHosts?: string[];
  /**
   * Stream-isolation token (e.g. persona id). Sent as SOCKS username so Tor (IsolateSOCKSAuth)
   * builds separate circuits per compartment (spec §14.1).
   */
  isolationKey?: string;
  probeTimeoutMs?: number;
}

export interface EgressRecord {
  at: number;
  url: string;
  route: 'direct' | 'tor';
  allowed: boolean;
  reason?: string;
}

export const PRIVACY_NETWORK_UNAVAILABLE = 'No enviado: red de privacidad no disponible';

export function isOnionHost(host: string): boolean {
  return /^([a-z2-7]{56}|[a-z2-7]{16})\.onion$/i.test(host) || host.toLowerCase().endsWith('.onion');
}

/**
 * Enforces the network policy for every outbound connection. In `tor-only` mode it fails closed:
 * no route through Tor means no transmission, never a silent clearnet fallback (spec §14, FR-020).
 */
export class NetworkGuard {
  readonly egress: EgressRecord[] = [];
  private lastProbe?: { at: number; ok: boolean };

  constructor(readonly config: NetworkPolicyConfig) {}

  get torRequired(): boolean {
    return this.config.mode === 'tor-only';
  }

  private socksUrl(): string {
    const host = this.config.socksHost ?? '127.0.0.1';
    const port = this.config.socksPort ?? 9050;
    const auth = this.config.isolationKey ? `${encodeURIComponent(this.config.isolationKey)}:x@` : '';
    // socks5h: hostname resolution happens inside Tor, never through the local resolver.
    return `socks5h://${auth}${host}:${port}`;
  }

  private record(url: string, allowed: boolean, reason?: string) {
    this.egress.push({ at: Date.now(), url, route: this.torRequired ? 'tor' : 'direct', allowed, ...(reason ? { reason } : {}) });
    if (this.egress.length > 1000) this.egress.shift();
  }

  /** Synchronous policy check of a destination (scheme, onion rules, allowlist). */
  checkDestination(rawUrl: string): URL {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      this.record(rawUrl, false, 'invalid url');
      throw new NetworkBlockedError(`invalid url: ${rawUrl}`, rawUrl);
    }
    const host = url.hostname;
    const onion = isOnionHost(host);
    let reason: string | undefined;
    if (!['ws:', 'wss:', 'http:', 'https:'].includes(url.protocol)) reason = `scheme not allowed: ${url.protocol}`;
    else if (!this.torRequired && onion) reason = '.onion destinations require Tor mode';
    else if (this.torRequired && this.config.onionOnly && !onion) reason = 'onion-only policy: clearnet destination blocked';
    else if (this.config.allowedHosts && !this.config.allowedHosts.includes(host)) reason = `host not in allowlist: ${host}`;
    if (reason) {
      this.record(rawUrl, false, reason);
      throw new NetworkBlockedError(reason, rawUrl);
    }
    return url;
  }

  /** Verifies the Tor SOCKS port answers a SOCKS5 greeting. Cached for 5 seconds. */
  async probeTor(): Promise<boolean> {
    if (this.lastProbe && Date.now() - this.lastProbe.at < 5000) return this.lastProbe.ok;
    const ok = await new Promise<boolean>((resolve) => {
      const sock = connect(this.config.socksPort ?? 9050, this.config.socksHost ?? '127.0.0.1');
      const timer = setTimeout(() => {
        sock.destroy();
        resolve(false);
      }, this.config.probeTimeoutMs ?? 3000);
      sock.once('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
      sock.once('data', (d: Buffer) => {
        clearTimeout(timer);
        sock.destroy();
        resolve(d[0] === 0x05 && d[1] === 0x00);
      });
      sock.once('error', () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
    this.lastProbe = { at: Date.now(), ok };
    return ok;
  }

  invalidateProbe() {
    this.lastProbe = undefined;
  }

  /** Full pre-flight for a connection: policy + (in Tor mode) a live Tor route. Throws when blocked. */
  async assertRoute(rawUrl: string): Promise<URL> {
    const url = this.checkDestination(rawUrl);
    if (this.torRequired && !(await this.probeTor())) {
      this.record(rawUrl, false, 'tor unavailable');
      throw new NetworkBlockedError(PRIVACY_NETWORK_UNAVAILABLE, rawUrl);
    }
    this.record(rawUrl, true);
    return url;
  }

  private agent(): SocksProxyAgent | undefined {
    return this.torRequired ? new SocksProxyAgent(this.socksUrl()) : undefined;
  }

  /** WebSocket factory for RelayPool honouring this policy. */
  webSocketFactory(): WebSocketFactory {
    return async (rawUrl: string) => {
      await this.assertRoute(rawUrl);
      const agent = this.agent();
      return new WebSocket(rawUrl, agent ? { agent } : {}) as unknown as WebSocketLike;
    };
  }

  /** Minimal fetch-like HTTP client routed according to the policy (used for Blossom, NIP-11, APIs). */
  async fetch(rawUrl: string, init: { method?: string; headers?: Record<string, string>; body?: Uint8Array | string; signal?: AbortSignal } = {}): Promise<{ status: number; headers: Record<string, string>; body: Uint8Array }> {
    const url = await this.assertRoute(rawUrl);
    const agent = this.agent();
    const req = url.protocol === 'https:' ? httpsRequest : httpRequest;
    return new Promise((resolve, reject) => {
      const r = req(url, { method: init.method ?? 'GET', headers: init.headers, ...(agent ? { agent } : {}), ...(init.signal ? { signal: init.signal } : {}) }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : (v ?? '')])),
            body: new Uint8Array(Buffer.concat(chunks)),
          }),
        );
        res.on('error', reject);
      });
      r.on('error', reject);
      if (init.body !== undefined) r.write(init.body);
      r.end();
    });
  }

  /**
   * WHATWG `fetch` routed by this policy, for libraries that take a `fetch` option (e.g. NIP-11 lookups
   * in the history sync). Never hand those libraries the global fetch in Tor mode: it resolves names
   * with the local DNS and connects directly (found by the pcap leak tests, FR020-03).
   */
  fetchApi(): typeof fetch {
    return (async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const headers = Object.fromEntries(new Headers(init?.headers).entries());
      const body = typeof init?.body === 'string' || init?.body instanceof Uint8Array ? init.body : undefined;
      if (init?.body != null && body === undefined) throw new TypeError('NetworkGuard.fetchApi: only string or Uint8Array bodies');
      const res = await this.fetch(url, { method: init?.method, headers, ...(body !== undefined ? { body } : {}), ...(init?.signal ? { signal: init.signal } : {}) });
      const status = res.status >= 200 && res.status <= 599 ? res.status : 502;
      return new Response([204, 205, 304].includes(status) ? null : (res.body as Uint8Array<ArrayBuffer>), { status, headers: res.headers });
    }) as typeof fetch;
  }
}
