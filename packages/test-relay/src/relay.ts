import { WebSocketServer, type WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import {
  bytesToHex,
  eventAddress,
  getTagValue,
  isEphemeralKind,
  isAddressableKind,
  isReplaceableKind,
  matchFilters,
  randomBytes,
  supersedes,
  verifyEvent,
  type Filter,
  type NostrEvent,
} from '@sedecim/nostr-core';

export interface TestRelayOptions {
  port?: number;
  host?: string;
  /** Require NIP-42 authentication before EVENT/REQ. */
  requireAuth?: boolean;
  /** Optional pubkey allowlist enforced after NIP-42 (Buzz BUZZ_PUBKEY_ALLOWLIST emulation). */
  allowlist?: string[];
  /** Kinds whose REQs must be restricted to #p == authenticated pubkey (Buzz behaviour for 1059). */
  pGatedKinds?: number[];
  /** Emulates relays that reject NIP-59 randomized timestamps (Buzz issue #4192). */
  rejectCreatedAtSkewSeconds?: number;
  /** Public URL clients use (for NIP-42 relay tag checks). Defaults to the bound ws:// URL. */
  publicUrl?: string;
  /** Advertise NIP-77 support (answers NEG-OPEN with NEG-ERR "blocked" when false). */
  supportsNegentropy?: boolean;
}

export interface FaultInjection {
  /** Silently drop OK responses for the next N events (simulates lost acks). */
  dropOks: number;
  /** Reject every EVENT with this reason while set. */
  rejectReason: string | null;
  /** Delay before answering EVENT (ms). */
  okDelayMs: number;
  /** Refuse new connections (simulates a relay outage) */
  offline: boolean;
}

interface ClientState {
  ws: WebSocket;
  challenge: string;
  authed: Set<string>;
  subs: Map<string, Filter[]>;
}

const normalizeUrl = (u: string) => u.replace(/\/+$/, '').toLowerCase();

export class TestRelay {
  readonly events = new Map<string, NostrEvent>();
  readonly faults: FaultInjection = { dropOks: 0, rejectReason: null, okDelayMs: 0, offline: false };
  readonly received: NostrEvent[] = [];
  private readonly heads = new Map<string, string>();
  private readonly deleted = new Set<string>();
  private readonly clients = new Set<ClientState>();
  private wss?: WebSocketServer;
  url = '';

  constructor(private readonly opts: TestRelayOptions = {}) {}

  async start(): Promise<string> {
    this.wss = new WebSocketServer({ port: this.opts.port ?? 0, host: this.opts.host ?? '127.0.0.1' });
    await new Promise<void>((resolve) => this.wss!.once('listening', () => resolve()));
    const addr = this.wss.address() as AddressInfo;
    this.url = this.opts.publicUrl ?? `ws://127.0.0.1:${addr.port}`;
    this.wss.on('connection', (ws) => this.onConnection(ws));
    return this.url;
  }

  get port(): number {
    return (this.wss?.address() as AddressInfo).port;
  }

  get connectionCount(): number {
    return this.clients.size;
  }

  async stop(): Promise<void> {
    for (const c of this.clients) c.ws.terminate();
    this.clients.clear();
    await new Promise<void>((resolve) => (this.wss ? this.wss.close(() => resolve()) : resolve()));
  }

  /** Drop every open connection (simulates a network blip). */
  disconnectAll(): void {
    for (const c of this.clients) c.ws.terminate();
    this.clients.clear();
  }

  /** Insert an event directly (as if published by another client). */
  inject(evt: NostrEvent): void {
    this.store(evt);
  }

  query(filters: Filter[]): NostrEvent[] {
    const out = [...this.events.values()].filter((e) => !this.deleted.has(e.id) && matchFilters(filters, e));
    out.sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1));
    const limit = Math.min(...filters.map((f) => f.limit ?? Infinity));
    return Number.isFinite(limit) ? out.slice(0, limit) : out;
  }

  private onConnection(ws: WebSocket) {
    if (this.faults.offline) {
      ws.terminate();
      return;
    }
    const state: ClientState = { ws, challenge: bytesToHex(randomBytes(16)), authed: new Set(), subs: new Map() };
    this.clients.add(state);
    this.send(state, ['AUTH', state.challenge]);
    ws.on('message', (raw) => {
      let msg: unknown;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        this.send(state, ['NOTICE', 'invalid: malformed JSON']);
        return;
      }
      void this.onMessage(state, msg);
    });
    ws.on('close', () => this.clients.delete(state));
    ws.on('error', () => this.clients.delete(state));
  }

  private send(state: ClientState, msg: unknown[]) {
    if (state.ws.readyState === state.ws.OPEN) state.ws.send(JSON.stringify(msg));
  }

  private isAuthorized(state: ClientState): boolean {
    if (!this.opts.requireAuth) return true;
    return state.authed.size > 0;
  }

  private async onMessage(state: ClientState, msg: unknown) {
    if (!Array.isArray(msg) || typeof msg[0] !== 'string') {
      this.send(state, ['NOTICE', 'invalid: expected array']);
      return;
    }
    const [type, ...rest] = msg;
    switch (type) {
      case 'AUTH':
        return this.onAuth(state, rest[0]);
      case 'EVENT':
        return this.onEvent(state, rest[0]);
      case 'REQ':
        return this.onReq(state, rest[0] as string, rest.slice(1) as Filter[]);
      case 'CLOSE':
        state.subs.delete(rest[0] as string);
        return;
      case 'NEG-OPEN':
        this.send(state, ['NEG-ERR', rest[0], this.opts.supportsNegentropy ? 'blocked: not implemented in test relay' : 'unsupported: NIP-77 not supported']);
        return;
      default:
        this.send(state, ['NOTICE', `unsupported: ${type}`]);
    }
  }

  private onAuth(state: ClientState, evt: unknown) {
    const id = (evt as NostrEvent | undefined)?.id ?? '';
    if (!verifyEvent(evt) || evt.kind !== 22242) return this.send(state, ['OK', id, false, 'invalid: bad auth event']);
    if (getTagValue(evt, 'challenge') !== state.challenge) return this.send(state, ['OK', id, false, 'invalid: challenge mismatch']);
    const relayTag = getTagValue(evt, 'relay');
    if (!relayTag || normalizeUrl(relayTag) !== normalizeUrl(this.url)) return this.send(state, ['OK', id, false, 'invalid: relay mismatch']);
    if (Math.abs(Date.now() / 1000 - evt.created_at) > 600) return this.send(state, ['OK', id, false, 'invalid: stale auth']);
    if (this.opts.allowlist && !this.opts.allowlist.includes(evt.pubkey)) return this.send(state, ['OK', id, false, 'auth-required: verification failed']);
    state.authed.add(evt.pubkey);
    this.send(state, ['OK', id, true, '']);
  }

  private async onEvent(state: ClientState, evt: unknown) {
    const id = (evt as NostrEvent | undefined)?.id ?? '';
    const respond = async (ok: boolean, message: string) => {
      if (this.faults.okDelayMs) await new Promise((r) => setTimeout(r, this.faults.okDelayMs));
      if (this.faults.dropOks > 0) {
        this.faults.dropOks--;
        return;
      }
      this.send(state, ['OK', id, ok, message]);
    };
    if (!verifyEvent(evt)) return respond(false, 'invalid: bad signature or id');
    this.received.push(evt);
    if (!this.isAuthorized(state)) return respond(false, 'auth-required: authenticate first');
    if (this.faults.rejectReason) return respond(false, this.faults.rejectReason);
    const skew = this.opts.rejectCreatedAtSkewSeconds;
    if (skew !== undefined && Math.abs(Date.now() / 1000 - evt.created_at) > skew) return respond(false, 'invalid: created_at too far from now');
    if (this.events.has(evt.id)) return respond(true, 'duplicate: already have this event');
    this.store(evt);
    return respond(true, '');
  }

  private store(evt: NostrEvent) {
    if (evt.kind === 5) {
      for (const t of evt.tags) {
        if (t[0] === 'e' && t[1] && this.events.get(t[1])?.pubkey === evt.pubkey) this.deleted.add(t[1]);
      }
    }
    if (!isEphemeralKind(evt.kind)) {
      if (isReplaceableKind(evt.kind) || isAddressableKind(evt.kind)) {
        const addr = eventAddress(evt);
        const curId = this.heads.get(addr);
        const cur = curId ? this.events.get(curId) : undefined;
        if (cur && !supersedes(evt, cur)) return;
        if (cur) this.events.delete(cur.id);
        this.heads.set(addr, evt.id);
      }
      this.events.set(evt.id, evt);
    }
    for (const c of this.clients) {
      for (const [subId, filters] of c.subs) {
        if (matchFilters(filters, evt)) this.send(c, ['EVENT', subId, evt]);
      }
    }
  }

  private onReq(state: ClientState, subId: string, filters: Filter[]) {
    if (typeof subId !== 'string' || filters.length === 0) return this.send(state, ['NOTICE', 'invalid: bad REQ']);
    if (!this.isAuthorized(state)) return this.send(state, ['CLOSED', subId, 'auth-required: authenticate first']);
    const gated = this.opts.pGatedKinds ?? [];
    for (const f of filters) {
      const touchesGated = !f.kinds || f.kinds.some((k) => gated.includes(k));
      if (gated.length && touchesGated) {
        const ps = f['#p'];
        if (!ps || ps.length === 0 || !ps.every((p) => state.authed.has(p))) {
          return this.send(state, ['CLOSED', subId, 'restricted: p-gated events require #p matching your pubkey']);
        }
      }
    }
    state.subs.set(subId, filters);
    for (const evt of this.query(filters)) this.send(state, ['EVENT', subId, evt]);
    this.send(state, ['EOSE', subId]);
  }
}
