import { verifyEvent, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { NetworkBlockedError, WS_OPEN, type PublishResult, type RelayHealth, type RelayStatus, type WebSocketFactory, type WebSocketLike } from './types';

export interface SubscriptionHandlers {
  onevent?: (evt: NostrEvent) => void;
  oneose?: () => void;
  onclosed?: (reason: string) => void;
}

export interface RelayConnectionOptions {
  webSocketFactory?: WebSocketFactory;
  /** Signer used to answer NIP-42 challenges. */
  signer?: Signer;
  /** 'auto': authenticate as soon as a challenge arrives; 'on-demand': only after auth-required. */
  authMode?: 'auto' | 'on-demand' | 'never';
  connectTimeoutMs?: number;
  publishTimeoutMs?: number;
  verifyEvents?: boolean;
  autoReconnect?: boolean;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
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
  private challengeWaiters: Array<() => void> = [];
  private readonly opts: Required<Omit<RelayConnectionOptions, 'signer'>> & { signer?: Signer };

  constructor(readonly url: string, opts: RelayConnectionOptions = {}) {
    this.opts = {
      webSocketFactory: opts.webSocketFactory ?? defaultFactory,
      signer: opts.signer,
      authMode: opts.authMode ?? 'on-demand',
      connectTimeoutMs: opts.connectTimeoutMs ?? 10_000,
      publishTimeoutMs: opts.publishTimeoutMs ?? 10_000,
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
    return {
      url: this.url,
      status: this.status,
      authenticatedAs: [...this.authed],
      lastConnectedAt: this.lastConnectedAt,
      lastError: this.lastError,
      consecutiveFailures: this.consecutiveFailures,
      avgAckLatencyMs: avg,
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
    this.challenge = undefined;
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
    for (const [id, s] of this.subs) this.sendRaw(['REQ', id, ...s.filters]);
  }

  close() {
    this.closedByUser = true;
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
        if (reason.startsWith('auth-required:') && !sub.authRetried && this.canAuth()) {
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
        }
        return;
      default:
        return;
    }
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
    this.authInFlight = (async () => {
      await this.connect();
      if (!(await this.waitForChallenge(this.opts.publishTimeoutMs))) return false;
      const evt = await signer.signEvent({
        kind: 22242,
        content: '',
        tags: [
          ['relay', this.url],
          ['challenge', this.challenge!],
        ],
      });
      const res = await this.sendAndAwaitOk(evt, 'AUTH');
      if (res.ok) this.authed.add(evt.pubkey);
      else this.lastError = `auth failed: ${res.message}`;
      return res.ok;
    })().finally(() => {
      this.authInFlight = undefined;
    });
    return this.authInFlight;
  }

  private sendAndAwaitOk(evt: NostrEvent, verb: 'EVENT' | 'AUTH'): Promise<{ ok: boolean; message: string }> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const list = this.pendingOks.get(evt.id);
        const idx = list?.findIndex((w) => w.timer === timer) ?? -1;
        if (list && idx >= 0) list.splice(idx, 1);
        resolve({ ok: false, message: 'error: timeout waiting for OK' });
      }, this.opts.publishTimeoutMs);
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
        const doReq = () => this.sendRaw(['REQ', id, ...filters]);
        if (this.opts.authMode === 'auto' && this.canAuth()) {
          void this.waitForChallenge(500).then((has) => (has ? this.authenticate().then(doReq) : doReq()));
        } else doReq();
      },
      (err: Error) => {
        if (!this.opts.autoReconnect || err instanceof NetworkBlockedError) this.finishSub(id, `error: ${err.message}`);
      },
    );
    return { id, close };
  }
}
