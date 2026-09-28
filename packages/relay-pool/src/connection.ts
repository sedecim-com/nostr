import { verifyEvent, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { NetworkBlockedError, WS_OPEN, type PublishResult, type RelayHealth, type RelayStatus, type WebSocketFactory, type WebSocketLike } from './types';

export interface SubscriptionHandlers {
  onevent?: (evt: NostrEvent) => void;
  oneose?: () => void;
  onclosed?: (reason: string) => void;
}

/**
 * Kinds that relays with NIP-42 DM protection serve only to the authenticated recipient: NIP-04 DMs (4), their
 * NIP-44 variant (44) and gift wraps (1059: NIP-17 DMs, Marmot Welcomes). nostr-rs-relay with `nip42_dms`
 * drops them silently for an unauthenticated connection, with no CLOSED or NOTICE to react to (FR025-11).
 */
export const RECIPIENT_ONLY_KINDS: readonly number[] = [4, 44, 1059];

const asksRecipientOnly = (filters: Filter[]) => filters.some((f) => f.kinds?.some((k) => RECIPIENT_ONLY_KINDS.includes(k)));

export interface RelayConnectionOptions {
  webSocketFactory?: WebSocketFactory;
  /** Signer used to answer NIP-42 challenges. */
  signer?: Signer;
  /**
   * 'auto': authenticate as soon as a challenge arrives. 'on-demand': only after auth-required, except that a
   * subscription asking for RECIPIENT_ONLY_KINDS authenticates first (no relay would say it is needed).
   */
  authMode?: 'auto' | 'on-demand' | 'never';
  /**
   * How long a subscription that must authenticate first waits for the relay's challenge after connecting
   * (default 500 ms for 'auto', 1500 ms for a recipient-only subscription). If none comes, the relay does not
   * do NIP-42 and later subscriptions on that connection no longer wait.
   */
  challengeWaitMs?: number;
  connectTimeoutMs?: number;
  publishTimeoutMs?: number;
  /** Wait for the OK to a NIP-42 AUTH. Some relays (nostr-rs-relay 0.9) never send it on success. */
  authTimeoutMs?: number;
  /**
   * URL to put in the NIP-42 `relay` tag when it differs from the dialled one (e.g. a service reaching
   * Buzz at ws://relay:3000 while the relay verifies against its public RELAY_URL).
   */
  authRelayUrl?: (connectUrl: string) => string;
  verifyEvents?: boolean;
  autoReconnect?: boolean;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
  /** Called when the socket opens again after a drop or a failed attempt (not on the first connect). */
  onReconnect?: (url: string) => void;
  /**
   * Called after every EVENT publish attempt with its outcome and publish→OK latency (NFR004-01), e.g. to
   * feed a metrics exporter. Listener errors are ignored: observing must never break a publish.
   */
  onPublishResult?: (result: PublishResult) => void;
}

interface PendingOk {
  resolve: (r: { ok: boolean; message: string }) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface SubState {
  filters: Filter[];
  handlers: SubscriptionHandlers;
  authRetried: boolean;
  eosed: boolean;
}

const defaultFactory: WebSocketFactory = (url) => {
  const WS = (globalThis as { WebSocket?: new (url: string) => WebSocketLike }).WebSocket;
  if (!WS) throw new Error('no WebSocket implementation available; pass webSocketFactory');
  return new WS(url);
};

let subCounter = 0;

/** Nearest-rank percentile of a sample (undefined when empty). */
export function percentile(values: readonly number[], q: number): number | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))];
}

export class RelayConnection {
  status: RelayStatus = 'idle';
  private ws?: WebSocketLike;
  private connecting?: Promise<void>;
  private challenge?: string;
  private authInFlight?: Promise<boolean>;
  private readonly authed = new Set<string>();
  private readonly pendingOks = new Map<string, PendingOk[]>();
  private readonly subs = new Map<string, SubState>();
  private readonly latencies: number[] = [];
  private readonly notices: string[] = [];
  private lastConnectedAt?: number;
  private lastError?: string;
  private consecutiveFailures = 0;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private closedByUser = false;
  /** Set when a connection dropped or an attempt failed; the next successful open is a reconnect. */
  private interrupted = false;
  private challengeWaiters: Array<() => void> = [];
  /** A subscription already waited for a challenge on this socket and none came: do not wait again. */
  private challengeWaitExpired = false;
  /** Resolves once the AUTH of the authentication in flight is on the wire (false if it could not be sent). */
  private authSent?: Promise<boolean>;
  private readonly rawListeners = new Set<(msg: unknown[]) => void>();
  private readonly opts: Required<Omit<RelayConnectionOptions, 'signer' | 'authRelayUrl' | 'onReconnect' | 'onPublishResult' | 'challengeWaitMs'>> &
    Pick<RelayConnectionOptions, 'signer' | 'authRelayUrl' | 'onReconnect' | 'onPublishResult' | 'challengeWaitMs'>;

  constructor(readonly url: string, opts: RelayConnectionOptions = {}) {
    this.opts = {
      webSocketFactory: opts.webSocketFactory ?? defaultFactory,
      signer: opts.signer,
      authRelayUrl: opts.authRelayUrl,
      onReconnect: opts.onReconnect,
      onPublishResult: opts.onPublishResult,
      challengeWaitMs: opts.challengeWaitMs,
      authMode: opts.authMode ?? 'on-demand',
      connectTimeoutMs: opts.connectTimeoutMs ?? 10_000,
      publishTimeoutMs: opts.publishTimeoutMs ?? 10_000,
      authTimeoutMs: opts.authTimeoutMs ?? 2_000,
      verifyEvents: opts.verifyEvents ?? true,
      autoReconnect: opts.autoReconnect ?? true,
      reconnectBaseMs: opts.reconnectBaseMs ?? 500,
      reconnectMaxMs: opts.reconnectMaxMs ?? 30_000,
    };
  }

  get connected(): boolean {
    return this.status === 'connected' && this.ws?.readyState === WS_OPEN;
  }

  health(): RelayHealth {
    const avg = this.latencies.length ? this.latencies.reduce((a, b) => a + b, 0) / this.latencies.length : undefined;
    const p95 = percentile(this.latencies, 0.95);
    return {
      url: this.url,
      status: this.status,
      authenticatedAs: [...this.authed],
      lastConnectedAt: this.lastConnectedAt,
      lastError: this.lastError,
      consecutiveFailures: this.consecutiveFailures,
      avgAckLatencyMs: avg,
      ...(p95 !== undefined ? { p95AckLatencyMs: p95, ackSamples: this.latencies.length } : {}),
      notices: [...this.notices],
    };
  }

  connect(): Promise<void> {
    if (this.connected) return Promise.resolve();
    if (this.connecting) return this.connecting;
    this.closedByUser = false;
    this.status = 'connecting';
    this.connecting = (async () => {
      let ws: WebSocketLike;
      try {
        ws = await this.opts.webSocketFactory(this.url);
      } catch (err) {
        this.status = err instanceof NetworkBlockedError ? 'blocked' : 'disconnected';
        this.lastError = (err as Error).message;
        this.interrupted = true;
        throw err;
      }
      this.ws = ws;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`connect timeout: ${this.url}`));
          try {
            ws.close();
          } catch {
            /* ignore */
          }
        }, this.opts.connectTimeoutMs);
        ws.onopen = () => {
          clearTimeout(timer);
          this.status = 'connected';
          this.lastConnectedAt = Date.now();
          this.consecutiveFailures = 0;
          resolve();
          if (this.interrupted) {
            this.interrupted = false;
            queueMicrotask(() => this.opts.onReconnect?.(this.url));
          }
        };
        ws.onerror = (ev) => {
          this.lastError = String((ev as { message?: string })?.message ?? 'websocket error');
        };
        ws.onclose = () => {
          clearTimeout(timer);
          const wasConnected = this.status === 'connected';
          this.onSocketClosed();
          if (!wasConnected) reject(new Error(`connection failed: ${this.url}${this.lastError ? ` (${this.lastError})` : ''}`));
        };
        ws.onmessage = (ev) => this.onMessage(ev.data);
      });
    })().finally(() => {
      this.connecting = undefined;
    });
    return this.connecting.catch((err) => {
      this.consecutiveFailures++;
      this.scheduleReconnect();
      throw err;
    });
  }

  private onSocketClosed() {
    this.ws = undefined;
    if (!this.closedByUser) this.interrupted = true;
    this.challenge = undefined;
    this.challengeWaitExpired = false;
    this.authed.clear();
    if (this.status !== 'blocked') this.status = 'disconnected';
    for (const [, waiters] of this.pendingOks) for (const w of waiters) {
      clearTimeout(w.timer);
      w.resolve({ ok: false, message: 'error: connection closed' });
    }
    this.pendingOks.clear();
    for (const s of this.subs.values()) s.eosed = false;
    this.scheduleReconnect();
  }

  private scheduleReconnect() {
    if (this.closedByUser || !this.opts.autoReconnect || this.subs.size === 0 || this.reconnectTimer) return;
    const exp = Math.min(this.opts.reconnectMaxMs, this.opts.reconnectBaseMs * 2 ** Math.min(this.consecutiveFailures, 10));
    const delay = exp / 2 + Math.random() * (exp / 2);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect().then(
        () => this.resubscribeAll(),
        () => undefined,
      );
    }, delay);
  }

  private resubscribeAll() {
    const send = () => {
      for (const [id, s] of this.subs) this.sendRaw(['REQ', id, ...s.filters]);
    };
    const wait = this.authFirstWait([...this.subs.values()].flatMap((s) => s.filters));
    if (wait !== undefined) void this.authenticateFirst(wait).then(send, send);
    else send();
  }

  /** How long to wait for a challenge before these filters' REQ, or undefined to send it right away. */
  private authFirstWait(filters: Filter[]): number | undefined {
    if (!this.canAuth() || this.authed.size > 0) return undefined;
    const wait = this.opts.authMode === 'auto' ? 500 : asksRecipientOnly(filters) ? 1500 : undefined;
    return wait === undefined ? undefined : (this.opts.challengeWaitMs ?? wait);
  }

  close() {
    this.closedByUser = true;
    this.interrupted = false;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    this.subs.clear();
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
    this.ws = undefined;
    this.status = 'idle';
  }

  private sendRaw(msg: unknown[]): boolean {
    if (!this.ws || this.ws.readyState !== WS_OPEN) return false;
    this.ws.send(JSON.stringify(msg));
    return true;
  }

  private onMessage(data: unknown) {
    let msg: unknown;
    try {
      msg = JSON.parse(typeof data === 'string' ? data : String(data));
    } catch {
      return;
    }
    if (!Array.isArray(msg)) return;
    for (const l of this.rawListeners) l(msg);
    const [type, a, b, c] = msg as [string, unknown, unknown, unknown];
    switch (type) {
      case 'EVENT': {
        const sub = this.subs.get(a as string);
        if (!sub) return;
        if (this.opts.verifyEvents && !verifyEvent(b)) return;
        sub.handlers.onevent?.(b as NostrEvent);
        return;
      }
      case 'EOSE': {
        const sub = this.subs.get(a as string);
        if (sub && !sub.eosed) {
          sub.eosed = true;
          sub.handlers.oneose?.();
        }
        return;
      }
      case 'OK': {
        const waiters = this.pendingOks.get(a as string);
        const w = waiters?.shift();
        if (!w) return;
        if (waiters!.length === 0) this.pendingOks.delete(a as string);
        clearTimeout(w.timer);
        w.resolve({ ok: b === true, message: typeof c === 'string' ? c : '' });
        return;
      }
      case 'CLOSED': {
        const id = a as string;
        const sub = this.subs.get(id);
        if (!sub) return;
        const reason = typeof b === 'string' ? b : '';
        // Relays such as Buzz answer `restricted:` (not `auth-required:`) to p-gated REQs from unauthenticated
        // connections, so an unauthenticated `restricted:` also triggers a single NIP-42 attempt.
        const needsAuth = reason.startsWith('auth-required:') || (reason.startsWith('restricted:') && this.authed.size === 0);
        if (needsAuth && !sub.authRetried && this.canAuth()) {
          sub.authRetried = true;
          void this.authenticate().then((ok) => {
            if (ok && this.subs.has(id)) this.sendRaw(['REQ', id, ...sub.filters]);
            else this.finishSub(id, reason);
          });
          return;
        }
        this.finishSub(id, reason);
        return;
      }
      case 'AUTH': {
        if (typeof a !== 'string') return;
        this.challenge = a;
        const waiters = this.challengeWaiters;
        this.challengeWaiters = [];
        waiters.forEach((w) => w());
        if (this.opts.authMode === 'auto' && this.canAuth()) void this.authenticate();
        return;
      }
      case 'NOTICE':
        if (typeof a === 'string') {
          this.notices.push(a);
          if (this.notices.length > 20) this.notices.shift();
          // Buzz answers an unauthenticated REQ with a NOTICE (not CLOSED): authenticate once and
          // replay the subscriptions that have not reached EOSE yet.
          if (a.startsWith('auth-required:') && this.canAuth() && this.authed.size === 0) {
            void this.authenticate().then((ok) => {
              if (!ok) return;
              for (const [id, sub] of this.subs) if (!sub.eosed && !sub.authRetried) {
                sub.authRetried = true;
                this.sendRaw(['REQ', id, ...sub.filters]);
              }
            });
          }
        }
        return;
      default:
        return;
    }
  }

  /**
   * Raw protocol hook for extensions the connection does not model (e.g. NIP-77 NEG-* messages).
   * The listener sees every parsed relay message; returns an unsubscribe function.
   */
  onRawMessage(fn: (msg: unknown[]) => void): () => void {
    this.rawListeners.add(fn);
    return () => this.rawListeners.delete(fn);
  }

  /** Connects if needed and sends a raw protocol message. Resolves false if the socket is not open. */
  async sendMessage(msg: unknown[]): Promise<boolean> {
    await this.connect();
    return this.sendRaw(msg);
  }

  /** true when a signer is configured and NIP-42 is allowed (used by extensions to retry after auth-required). */
  get canAuthenticate(): boolean {
    return this.canAuth();
  }

  private finishSub(id: string, reason: string) {
    const sub = this.subs.get(id);
    this.subs.delete(id);
    sub?.handlers.onclosed?.(reason);
  }

  private canAuth(): boolean {
    return !!this.opts.signer && this.opts.authMode !== 'never';
  }

  private waitForChallenge(timeoutMs: number): Promise<boolean> {
    if (this.challenge) return Promise.resolve(true);
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve(false), timeoutMs);
      this.challengeWaiters.push(() => {
        clearTimeout(t);
        resolve(true);
      });
    });
  }

  /** NIP-42: sign a kind 22242 event for the current challenge. Returns true on OK=true. */
  authenticate(): Promise<boolean> {
    if (!this.opts.signer) return Promise.resolve(false);
    if (this.authInFlight) return this.authInFlight;
    const signer = this.opts.signer;
    let markSent: (sent: boolean) => void = () => {};
    this.authSent = new Promise((resolve) => (markSent = resolve));
    this.authInFlight = (async () => {
      await this.connect();
      if (!(await this.waitForChallenge(this.opts.publishTimeoutMs))) return false;
      const evt = await signer.signEvent({
        kind: 22242,
        content: '',
        tags: [
          ['relay', this.opts.authRelayUrl?.(this.url) ?? this.url],
          ['challenge', this.challenge!],
        ],
      });
      const ok = this.sendAndAwaitOk(evt, 'AUTH', this.opts.authTimeoutMs);
      markSent(true);
      const res = await ok;
      // No answer at all (not a rejection): accept optimistically; a later auth-required will surface it.
      const silent = !res.ok && res.message === 'error: timeout waiting for OK';
      if (res.ok || silent) this.authed.add(evt.pubkey);
      else this.lastError = `auth failed: ${res.message}`;
      return res.ok || silent;
    })().finally(() => {
      markSent(false);
      this.authInFlight = undefined;
    });
    return this.authInFlight;
  }

  /**
   * Authenticates before a subscription that needs it and resolves once the AUTH is on the wire: relays
   * process a connection's messages in order, so a REQ sent next is already evaluated as authenticated,
   * without waiting for an OK that nostr-rs-relay 0.9 never sends on success. Resolves at once when there is
   * no challenge to answer (the relay does not do NIP-42).
   */
  private async authenticateFirst(waitMs: number): Promise<void> {
    if (this.challengeWaitExpired && !this.challenge) return;
    if (!(await this.waitForChallenge(waitMs))) {
      this.challengeWaitExpired = true;
      return;
    }
    const done = this.authenticate().catch(() => false);
    await Promise.race([this.authSent, done]);
  }

  private sendAndAwaitOk(evt: NostrEvent, verb: 'EVENT' | 'AUTH', timeoutMs = this.opts.publishTimeoutMs): Promise<{ ok: boolean; message: string }> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const list = this.pendingOks.get(evt.id);
        const idx = list?.findIndex((w) => w.timer === timer) ?? -1;
        if (list && idx >= 0) list.splice(idx, 1);
        resolve({ ok: false, message: 'error: timeout waiting for OK' });
      }, timeoutMs);
      const list = this.pendingOks.get(evt.id) ?? [];
      list.push({ resolve, timer });
      this.pendingOks.set(evt.id, list);
      if (!this.sendRaw([verb, evt])) {
        clearTimeout(timer);
        list.pop();
        resolve({ ok: false, message: 'error: not connected' });
      }
    });
  }

  /**
   * Publish a signed event. `OK=true` only means the relay accepted it (NIP-01); it does NOT mean the
   * recipient received or decrypted it (spec §11).
   */
  async publish(evt: NostrEvent): Promise<PublishResult> {
    const result = await this.publishOnce(evt);
    try {
      this.opts.onPublishResult?.(result);
    } catch {
      /* observers never break a publish */
    }
    return result;
  }

  private async publishOnce(evt: NostrEvent): Promise<PublishResult> {
    const started = Date.now();
    try {
      await this.connect();
    } catch (err) {
      return {
        relay: this.url,
        ok: false,
        message: `error: ${(err as Error).message}`,
        latencyMs: Date.now() - started,
        blocked: err instanceof NetworkBlockedError,
      };
    }
    let res = await this.sendAndAwaitOk(evt, 'EVENT');
    if (!res.ok && res.message.startsWith('auth-required:') && this.canAuth()) {
      if (await this.authenticate()) res = await this.sendAndAwaitOk(evt, 'EVENT');
    }
    const duplicate = res.message.startsWith('duplicate:');
    const latencyMs = Date.now() - started;
    if (res.ok || duplicate) {
      this.latencies.push(latencyMs);
      if (this.latencies.length > 50) this.latencies.shift();
    }
    return { relay: this.url, ok: res.ok || duplicate, message: res.message, latencyMs, ...(duplicate ? { duplicate } : {}) };
  }

  subscribe(filters: Filter[], handlers: SubscriptionHandlers, id = `s${++subCounter}`): { id: string; close: () => void } {
    this.subs.set(id, { filters, handlers, authRetried: false, eosed: false });
    const close = () => {
      if (this.subs.delete(id)) this.sendRaw(['CLOSE', id]);
    };
    this.connect().then(
      () => {
        if (!this.subs.has(id)) return;
        const doReq = () => {
          if (this.subs.has(id)) this.sendRaw(['REQ', id, ...filters]);
        };
        const wait = this.authFirstWait(filters);
        if (wait !== undefined) void this.authenticateFirst(wait).then(doReq, doReq);
        else doReq();
      },
      (err: Error) => {
        if (!this.opts.autoReconnect || err instanceof NetworkBlockedError) this.finishSub(id, `error: ${err.message}`);
      },
    );
    return { id, close };
  }
}
