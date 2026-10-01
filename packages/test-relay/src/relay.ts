import { createServer, type Server } from 'node:http';
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
import { NegentropyResponder } from './negentropy';

export interface TestRelayOptions {
  port?: number;
  host?: string;
  /** Require NIP-42 authentication before EVENT/REQ. */
  requireAuth?: boolean;
  /**
   * OK message for an EVENT sent before AUTH. Default `auth-required: authenticate first`; nostr-rs-relay behind a
   * nauthz admission server says `blocked: auth-required: …` (FR023-13).
   */
  eventAuthRequiredMessage?: string;
  /** Optional pubkey allowlist enforced after NIP-42 (Buzz BUZZ_PUBKEY_ALLOWLIST emulation). */
  allowlist?: string[];
  /** Kinds whose REQs must be restricted to #p == authenticated pubkey (Buzz behaviour for 1059). */
  pGatedKinds?: number[];
  /** Emulates relays that reject NIP-59 randomized timestamps (Buzz issue #4192). */
  rejectCreatedAtSkewSeconds?: number;
  /** Public URL clients use (for NIP-42 relay tag checks). Defaults to the bound ws:// URL. */
  publicUrl?: string;
  /**
   * Enable NIP-77 (Negentropy) reconciliation and advertise 77 in NIP-11. Off by default: NEG-OPEN is
   * then answered like an unknown verb (NOTICE), as relays without NIP-77 do.
   */
  supportsNegentropy?: boolean;
  /** Do not send OK after a successful AUTH (nostr-rs-relay 0.9 behaviour). */
  silentAuthOk?: boolean;
  /**
   * nostr-rs-relay `nip42_dms`: events of these kinds reach only connections authenticated as their author or
   * a `p` recipient. Everyone else gets nothing, silently: no CLOSED, no NOTICE (e.g. [4, 44, 1059]).
   */
  silentDmKinds?: number[];
  /** Answer unauthenticated REQs with a NOTICE instead of CLOSED (Buzz behaviour). */
  authNoticeOnReq?: boolean;
  /** Buzz fan-out: live events carrying an `h` tag only reach subscriptions that filter by `#h`. */
  channelScopedFanout?: boolean;
  /** NIP-11 `self`: the relay's own signing key (hex), as Buzz advertises the key that signs NIP-29 group state. */
  self?: string;
  /**
   * Buzz ingest rules for channel collaboration (FR015-04): a reply (kind 9 with a NIP-10 `reply` marker) needs its
   * parent in the same channel and the parent's thread root as `root`; a reaction (7) needs a stored target; a
   * deletion (5 or 9005) names exactly one target; kind 5 only from the target's author; 9005 only in the target's
   * channel (`h`) and from its author or an admin of that channel's newest kind 39001 (signed by `self` when set). An
   * accepted 9005 hides its target from reads, as kind 5 already does.
   */
  groupModeration?: boolean;
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
  /** Abort NIP-77 sessions with NEG-ERR after answering this many client messages (null = never). */
  negErrorAfterMessages: number | null;
  /**
   * After sending this many more EVENT messages, drop every connection and go `offline` (a relay that dies in the
   * middle of a transfer); null = never. It resets itself once it fires.
   */
  cutAfterEvents: number | null;
  /** Never answer a REQ: no events, no EOSE, no CLOSED (a relay that hangs). */
  silentReqs: boolean;
}

/** A NIP-77 message a client sent (FR013-05: to check what a client tells the relay). */
export interface NegLogEntry {
  type: 'NEG-OPEN' | 'NEG-MSG' | 'NEG-CLOSE';
  subId: string;
  filter?: Filter;
  /** hex Negentropy message (NEG-OPEN, NEG-MSG) */
  message?: string;
}

interface ClientState {
  ws: WebSocket;
  challenge: string;
  authed: Set<string>;
  subs: Map<string, Filter[]>;
  neg: Map<string, { responder: NegentropyResponder; messages: number }>;
}

const normalizeUrl = (u: string) => u.replace(/\/+$/, '').toLowerCase();

/** NIP-10 `root` and `reply` markers with a valid id, the last of each winning (as Buzz parses them). */
function threadMarkers(evt: NostrEvent): { root?: string; reply?: string } {
  const out: { root?: string; reply?: string } = {};
  for (const t of evt.tags) if (t[0] === 'e' && /^[0-9a-f]{64}$/.test(t[1] ?? '') && (t[3] === 'root' || t[3] === 'reply')) out[t[3]] = t[1];
  return out;
}

export class TestRelay {
  readonly events = new Map<string, NostrEvent>();
  readonly faults: FaultInjection = { dropOks: 0, rejectReason: null, okDelayMs: 0, offline: false, negErrorAfterMessages: null, cutAfterEvents: null, silentReqs: false };
  readonly received: NostrEvent[] = [];
  /** Pubkeys of every NIP-42 AUTH it accepted, in order: who revealed themselves to this relay. */
  readonly authedPubkeys: string[] = [];
  /** Number of EVENT messages sent to clients (to measure how much a sync transferred). */
  sentEvents = 0;
  /** NIP-77 messages received from clients, by verb. */
  readonly negStats = { open: 0, msg: 0, close: 0 };
  /** Every NIP-77 message received from clients, in order. */
  readonly negLog: NegLogEntry[] = [];
  /** The filters of every REQ received, in order, served or refused: what clients asked this relay for. */
  readonly reqFilters: Filter[][] = [];
  /** Same list as `reqFilters` (FR015-05 reads it by this name). */
  get requests(): Filter[][] {
    return this.reqFilters;
  }
  /** WebSocket connection attempts (refused ones included) and NIP-11 (HTTP) requests since start: any network use shows here. */
  connectionAttempts = 0;
  infoRequests = 0;
  /** Set while `faults.cutAfterEvents` is cutting: nothing more goes out until the connections are closed. */
  private cutting = false;
  private readonly heads = new Map<string, string>();
  private readonly deleted = new Set<string>();
  private readonly clients = new Set<ClientState>();
  private wss?: WebSocketServer;
  private http?: Server;
  url = '';

  constructor(private readonly opts: TestRelayOptions = {}) {}

  async start(): Promise<string> {
    // Plain HTTP answers NIP-11 (relay information document); upgrades go to the WebSocket server.
    this.http = createServer((req, res) => {
      this.infoRequests++;
      const info = { name: 'sedecim test relay', software: '@sedecim/test-relay', supported_nips: [1, 9, 11, 42, 59, ...(this.opts.supportsNegentropy ? [77] : [])], ...(this.opts.self ? { self: this.opts.self } : {}) };
      res.writeHead(200, { 'content-type': 'application/nostr+json', 'access-control-allow-origin': '*' });
      res.end(JSON.stringify(info));
    });
    this.wss = new WebSocketServer({ server: this.http });
    await new Promise<void>((resolve) => this.http!.listen(this.opts.port ?? 0, this.opts.host ?? '127.0.0.1', () => resolve()));
    const addr = this.http.address() as AddressInfo;
    this.url = this.opts.publicUrl ?? `ws://127.0.0.1:${addr.port}`;
    this.wss.on('connection', (ws) => this.onConnection(ws));
    return this.url;
  }

  get port(): number {
    return (this.http?.address() as AddressInfo).port;
  }

  get connectionCount(): number {
    return this.clients.size;
  }

  async stop(): Promise<void> {
    for (const c of this.clients) c.ws.terminate();
    this.clients.clear();
    await new Promise<void>((resolve) => (this.wss ? this.wss.close(() => resolve()) : resolve()));
    await new Promise<void>((resolve) => (this.http?.listening ? this.http.close(() => resolve()) : resolve()));
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
    this.connectionAttempts++;
    if (this.faults.offline) {
      ws.terminate();
      return;
    }
    const state: ClientState = { ws, challenge: bytesToHex(randomBytes(16)), authed: new Set(), subs: new Map(), neg: new Map() };
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
    if (this.cutting || state.ws.readyState !== state.ws.OPEN) return;
    if (msg[0] === 'EVENT') this.sentEvents++;
    state.ws.send(JSON.stringify(msg));
    if (msg[0] === 'EVENT' && this.faults.cutAfterEvents !== null && --this.faults.cutAfterEvents <= 0) {
      // The relay dies right after this event: nothing else (no EOSE) goes out, and it refuses to come back until told.
      this.faults.cutAfterEvents = null;
      this.faults.offline = true;
      this.cutting = true;
      setImmediate(() => {
        for (const c of this.clients) c.ws.close(1011, 'cut');
        this.clients.clear();
        this.cutting = false;
      });
    }
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
      case 'NEG-MSG':
      case 'NEG-CLOSE':
        if (this.opts.supportsNegentropy) return this.onNegentropy(state, type, rest);
        this.send(state, ['NOTICE', `unsupported: ${type}`]);
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
    this.authedPubkeys.push(evt.pubkey);
    if (!this.opts.silentAuthOk) this.send(state, ['OK', id, true, '']);
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
    if (!this.isAuthorized(state)) return respond(false, this.opts.eventAuthRequiredMessage ?? 'auth-required: authenticate first');
    if (this.faults.rejectReason) return respond(false, this.faults.rejectReason);
    const skew = this.opts.rejectCreatedAtSkewSeconds;
    if (skew !== undefined && Math.abs(Date.now() / 1000 - evt.created_at) > skew) return respond(false, 'invalid: created_at too far from now');
    if (this.events.has(evt.id)) return respond(true, 'duplicate: already have this event');
    const refused = this.opts.groupModeration ? this.moderationRefusal(evt) : undefined;
    if (refused) return respond(false, refused);
    this.store(evt);
    return respond(true, '');
  }

  /** Admins of a channel: its newest kind 39001 (from `self` when set). */
  private groupAdmins(h: string): Set<string> {
    const lists = [...this.events.values()].filter((e) => e.kind === 39001 && getTagValue(e, 'd') === h && (!this.opts.self || e.pubkey === this.opts.self));
    const list = lists.sort((a, b) => b.created_at - a.created_at)[0];
    return new Set(list ? list.tags.filter((t) => t[0] === 'p' && t[1]).map((t) => t[1]!) : []);
  }

  /** Why Buzz would refuse a reply, a reaction or a deletion (groupModeration), with its messages; undefined when it accepts it. */
  private moderationRefusal(evt: NostrEvent): string | undefined {
    const live = (id: string | undefined) => (id && !this.deleted.has(id) ? this.events.get(id) : undefined);
    if (evt.kind === 9) {
      const markers = threadMarkers(evt);
      if (!markers.reply) return undefined;
      const parent = live(markers.reply);
      if (!parent) return 'invalid: reply parent not found';
      if (getTagValue(parent, 'h') !== getTagValue(evt, 'h')) return 'invalid: parent event belongs to a different channel';
      const parentMarkers = threadMarkers(parent);
      // The parent's thread root: its own root, its reply target when it only has that, or itself when top-level.
      const root = parentMarkers.reply ? (parentMarkers.root ?? parentMarkers.reply) : parent.id;
      return (markers.root ?? markers.reply) === root ? undefined : 'invalid: root tag does not match thread ancestry';
    }
    if (evt.kind === 7) {
      const target = [...evt.tags].reverse().find((t) => t[0] === 'e')?.[1];
      if (!target) return 'invalid: reaction must reference a target event via e tag';
      return live(target) ? undefined : 'invalid: reaction target event not found';
    }
    if (evt.kind !== 5 && evt.kind !== 9005) return undefined;
    const targets = evt.tags.filter((t) => t[0] === 'e' || t[0] === 'a');
    if (targets.length !== 1) return 'invalid: deletion events must reference exactly one target via e or a tag';
    const target = targets[0]![0] === 'e' ? this.events.get(targets[0]![1] ?? '') : undefined;
    if (evt.kind === 9005) return this.groupDeletionRefusal(evt, target);
    if (targets[0]![0] !== 'e') return undefined;
    if (!target) return 'invalid: target event not found';
    return target.pubkey === evt.pubkey ? undefined : 'invalid: must be event author';
  }

  private groupDeletionRefusal(evt: NostrEvent, target: NostrEvent | undefined): string | undefined {
    const h = getTagValue(evt, 'h');
    if (!h) return 'invalid: channel-scoped events must include an h tag';
    if (!target) return 'invalid: target event not found';
    if (getTagValue(target, 'h') !== h) return 'invalid: target event belongs to a different channel';
    if (target.pubkey !== evt.pubkey && !this.groupAdmins(h).has(evt.pubkey)) return 'invalid: must be event author or channel owner/admin';
    return undefined;
  }

  private store(evt: NostrEvent) {
    if (evt.kind === 5) {
      for (const t of evt.tags) {
        if (t[0] === 'e' && t[1] && this.events.get(t[1])?.pubkey === evt.pubkey) this.deleted.add(t[1]);
      }
    }
    if (evt.kind === 9005 && this.opts.groupModeration) {
      const target = this.events.get(getTagValue(evt, 'e') ?? '');
      if (target && !this.groupDeletionRefusal(evt, target)) this.deleted.add(target.id);
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
    const channelScoped = this.opts.channelScopedFanout && evt.tags.some((t) => t[0] === 'h' || (evt.kind >= 39000 && evt.kind <= 39002 && t[0] === 'd'));
    for (const c of this.clients) {
      for (const [subId, filters] of c.subs) {
        const live = channelScoped ? filters.filter((f) => f['#h'] !== undefined) : filters;
        if (matchFilters(live, evt) && this.dmVisible(c, evt)) this.send(c, ['EVENT', subId, evt]);
      }
    }
  }

  private dmVisible(state: ClientState, evt: NostrEvent): boolean {
    if (!this.opts.silentDmKinds?.includes(evt.kind)) return true;
    return state.authed.has(evt.pubkey) || evt.tags.some((t) => t[0] === 'p' && t[1] !== undefined && state.authed.has(t[1]));
  }

  /** Access check shared by REQ and NEG-OPEN: undefined when allowed, otherwise the machine-readable reason. */
  private readDenied(state: ClientState, filters: Filter[]): string | undefined {
    if (!this.isAuthorized(state)) return 'auth-required: authenticate first';
    const gated = this.opts.pGatedKinds ?? [];
    for (const f of filters) {
      const touchesGated = !f.kinds || f.kinds.some((k) => gated.includes(k));
      if (gated.length && touchesGated) {
        const ps = f['#p'];
        if (!ps || ps.length === 0 || !ps.every((p) => state.authed.has(p))) return 'restricted: p-gated events require #p matching your pubkey';
      }
    }
    return undefined;
  }

  /** NIP-77: NEG-OPEN / NEG-MSG / NEG-CLOSE, answered with NEG-MSG or NEG-ERR. */
  private onNegentropy(state: ClientState, type: string, rest: unknown[]) {
    const subId = rest[0];
    if (typeof subId !== 'string') return this.send(state, ['NOTICE', `invalid: bad ${type}`]);
    this.negLog.push({
      type: type as NegLogEntry['type'],
      subId,
      ...(type === 'NEG-OPEN' ? { filter: rest[1] as Filter } : {}),
      ...(type !== 'NEG-CLOSE' && typeof rest[type === 'NEG-OPEN' ? 2 : 1] === 'string' ? { message: rest[type === 'NEG-OPEN' ? 2 : 1] as string } : {}),
    });
    if (type === 'NEG-CLOSE') {
      this.negStats.close++;
      state.neg.delete(subId);
      return;
    }
    let session = state.neg.get(subId);
    let query: unknown;
    if (type === 'NEG-OPEN') {
      this.negStats.open++;
      const filter = rest[1] as Filter;
      query = rest[2];
      if (!filter || typeof filter !== 'object' || typeof query !== 'string') return this.send(state, ['NEG-ERR', subId, 'invalid: bad NEG-OPEN']);
      const denied = this.readDenied(state, [filter]);
      if (denied) return this.send(state, ['NEG-ERR', subId, denied]);
      const { limit: _limit, ...unlimited } = filter;
      session = { responder: new NegentropyResponder(this.query([unlimited]).filter((e) => this.dmVisible(state, e))), messages: 0 };
      state.neg.set(subId, session); // replaces a previous session with the same id (NIP-77)
    } else {
      this.negStats.msg++;
      query = rest[1];
      if (!session) return this.send(state, ['NEG-ERR', subId, 'closed: unknown subscription']);
      if (typeof query !== 'string') return this.send(state, ['NEG-ERR', subId, 'invalid: bad NEG-MSG']);
    }
    const limit = this.faults.negErrorAfterMessages;
    if (limit !== null && session.messages >= limit) {
      state.neg.delete(subId);
      return this.send(state, ['NEG-ERR', subId, 'error: negentropy session aborted']);
    }
    session.messages++;
    try {
      this.send(state, ['NEG-MSG', subId, session.responder.respond(query)]);
    } catch (err) {
      state.neg.delete(subId);
      this.send(state, ['NEG-ERR', subId, `invalid: ${(err as Error).message}`]);
    }
  }

  private onReq(state: ClientState, subId: string, filters: Filter[]) {
    if (typeof subId !== 'string' || filters.length === 0) return this.send(state, ['NOTICE', 'invalid: bad REQ']);
    this.reqFilters.push(filters);
    if (this.faults.silentReqs) return;
    if (!this.isAuthorized(state)) return this.send(state, this.opts.authNoticeOnReq ? ['NOTICE', 'auth-required: authenticate before subscribing'] : ['CLOSED', subId, 'auth-required: authenticate first']);
    const denied = this.readDenied(state, filters);
    if (denied) return this.send(state, ['CLOSED', subId, denied]);
    state.subs.set(subId, filters);
    for (const evt of this.query(filters)) if (this.dmVisible(state, evt)) this.send(state, ['EVENT', subId, evt]);
    this.send(state, ['EOSE', subId]);
  }
}
