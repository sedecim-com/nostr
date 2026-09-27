/**
 * NIP-46 remote signing ("Nostr Connect"). The client never holds the user's nsec: it holds an
 * ephemeral client keypair and sends NIP-44 encrypted JSON-RPC requests (kind 24133) through relays.
 */
import { bytesToHex, generateSecretKey, getPublicKey, randomBytes, verifyEvent, type EventTemplate, type NostrEvent, type Signer, type CustodyMode } from '@sedecim/nostr-core';
import { RelayPool } from '@sedecim/relay-pool';
import { LocalSigner } from './local';

export const NOSTR_CONNECT_KIND = 24133;

export type Nip46Method = 'connect' | 'get_public_key' | 'sign_event' | 'nip44_encrypt' | 'nip44_decrypt' | 'ping';

export interface BunkerPointer {
  remoteSignerPubkey: string;
  relays: string[];
  secret?: string;
}

export function parseBunkerUrl(url: string): BunkerPointer {
  const u = new URL(url);
  if (u.protocol !== 'bunker:') throw new Error('expected bunker:// url');
  const remoteSignerPubkey = (u.hostname || u.pathname.replace(/^\/+/, '')).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(remoteSignerPubkey)) throw new Error('invalid remote signer pubkey');
  const relays = u.searchParams.getAll('relay');
  if (relays.length === 0) throw new Error('bunker url needs at least one relay');
  const secret = u.searchParams.get('secret') ?? undefined;
  return { remoteSignerPubkey, relays, ...(secret ? { secret } : {}) };
}

export function formatBunkerUrl(p: BunkerPointer): string {
  const q = new URLSearchParams();
  p.relays.forEach((r) => q.append('relay', r));
  if (p.secret) q.set('secret', p.secret);
  return `bunker://${p.remoteSignerPubkey}?${q.toString()}`;
}

/** Kinds the Acceso Nostr web asks a remote signer to sign, with a human label (FR004-04). */
export const KIND_LABELS: Record<number, string> = {
  5: 'Borrar mensajes propios (NIP-09)',
  7: 'Reacciones',
  9: 'Mensajes de canal (NIP-29)',
  13: 'Sellos de mensajes directos (NIP-17)',
  9007: 'Crear canales',
  9021: 'Solicitar unirse a canales',
  10050: 'Lista de relays de mensajes directos',
  22242: 'Autenticación en relays (NIP-42)',
  24242: 'Autorizar subidas de archivos (Blossom)',
  27235: 'Autenticación HTTP en servicios (NIP-98)',
};

/** Minimal permissions for the web client: only the kinds it signs, plus NIP-44 for DMs (spec §8.3). */
export const WEB_NIP46_PERMISSIONS = ['get_public_key', 'nip44_encrypt', 'nip44_decrypt', ...Object.keys(KIND_LABELS).map((k) => `sign_event:${k}`)];

const METHOD_LABELS: Record<string, string> = {
  get_public_key: 'Conocer tu clave pública',
  nip44_encrypt: 'Cifrar mensajes directos (NIP-44)',
  nip44_decrypt: 'Descifrar mensajes directos (NIP-44)',
  sign_event: 'Firmar eventos',
};

/** Human-readable list of the permissions a client requests, shown before connecting. */
export function describePermissions(perms: string[]): Array<{ permission: string; method: string; kind?: number; label: string }> {
  return perms.map((permission) => {
    const [method, k] = permission.split(':') as [string, string | undefined];
    const kind = k !== undefined ? Number(k) : undefined;
    const label = kind !== undefined ? `Firmar: ${KIND_LABELS[kind] ?? `kind ${kind}`}` : (METHOD_LABELS[method] ?? method);
    return { permission, method, ...(kind !== undefined ? { kind } : {}), label };
  });
}

/** Client-initiated connection (FR004-03): the user scans or pastes this into their signer app. */
export interface NostrConnectOffer {
  uri: string;
  clientSecretKey: Uint8Array;
  secret: string;
  relays: string[];
  permissions: string[];
}

export function createNostrConnect(opts: { relays: string[]; permissions?: string[]; name?: string; url?: string; clientSecretKey?: Uint8Array }): NostrConnectOffer {
  if (opts.relays.length === 0) throw new Error('nostrconnect needs at least one relay');
  const clientSecretKey = opts.clientSecretKey ?? generateSecretKey();
  const secret = bytesToHex(randomBytes(16));
  const permissions = opts.permissions ?? WEB_NIP46_PERMISSIONS;
  const q = new URLSearchParams();
  opts.relays.forEach((r) => q.append('relay', r));
  q.set('secret', secret);
  q.set('perms', permissions.join(','));
  if (opts.name) q.set('name', opts.name);
  if (opts.url) q.set('url', opts.url);
  const clientPubkey = getPublicKey(clientSecretKey);
  return { uri: `nostrconnect://${clientPubkey}?${q.toString()}`, clientSecretKey, secret, relays: opts.relays, permissions };
}

export function parseNostrConnect(uri: string): { clientPubkey: string; relays: string[]; secret: string; permissions: string[]; name?: string } {
  const u = new URL(uri);
  if (u.protocol !== 'nostrconnect:') throw new Error('expected nostrconnect:// uri');
  const clientPubkey = (u.hostname || u.pathname.replace(/^\/+/, '')).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clientPubkey)) throw new Error('invalid client pubkey');
  const relays = u.searchParams.getAll('relay');
  const secret = u.searchParams.get('secret');
  if (relays.length === 0 || !secret) throw new Error('nostrconnect uri needs relay and secret');
  const name = u.searchParams.get('name') ?? undefined;
  return { clientPubkey, relays, secret, permissions: (u.searchParams.get('perms') ?? '').split(',').filter(Boolean), ...(name ? { name } : {}) };
}

export interface Nip46SignerOptions {
  pool: RelayPool;
  /** Ephemeral client key; generated if omitted. Persist it to keep a stable session with the bunker. */
  clientSecretKey?: Uint8Array;
  /** Minimal, visible permissions requested from the signer (spec §8.3). */
  permissions?: string[];
  timeoutMs?: number;
  /** The signer asks the user to approve in a web page (NIP-46 auth_url): open it; the request keeps waiting. */
  onAuthUrl?: (url: string) => void;
  /** How long to keep waiting after an auth_url challenge (default 5 min). */
  authTimeoutMs?: number;
}

interface Pending {
  resolve: (v: string) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class Nip46Signer implements Signer {
  readonly custody: CustodyMode = 'external';
  private readonly client: LocalSigner;
  private readonly pending = new Map<string, Pending>();
  private sub?: { close(): void };
  private userPubkey?: string;
  readonly permissions: string[];

  constructor(readonly bunker: BunkerPointer, private readonly opts: Nip46SignerOptions) {
    this.client = new LocalSigner(opts.clientSecretKey ?? generateSecretKey());
    this.permissions = opts.permissions ?? ['sign_event', 'nip44_encrypt', 'nip44_decrypt'];
  }

  async clientPubkey(): Promise<string> {
    return this.client.getPublicKey();
  }

  private async listen() {
    if (this.sub) return;
    const me = await this.client.getPublicKey();
    await new Promise<void>((resolve) => {
      this.sub = this.opts.pool.subscribe(this.bunker.relays, [{ kinds: [NOSTR_CONNECT_KIND], '#p': [me], since: Math.floor(Date.now() / 1000) - 10 }], {
        onevent: (evt) => void this.onResponse(evt),
        oneose: () => resolve(),
      });
    });
  }

  private async onResponse(evt: NostrEvent) {
    if (evt.pubkey !== this.bunker.remoteSignerPubkey) return;
    let msg: { id?: string; result?: string; error?: string };
    try {
      msg = JSON.parse(await this.client.nip44Decrypt(evt.pubkey, evt.content));
    } catch {
      return;
    }
    const p = msg.id ? this.pending.get(msg.id) : undefined;
    if (!p) return;
    if (msg.result === 'auth_url') {
      // Auth challenge (FR004-05): show the URL and keep waiting, longer, for the real response.
      if (msg.error && /^https:\/\//.test(msg.error)) this.opts.onAuthUrl?.(msg.error);
      clearTimeout(p.timer);
      p.timer = setTimeout(() => {
        this.pending.delete(msg.id!);
        p.reject(new Error('remote signer: auth_url not completed'));
      }, this.opts.authTimeoutMs ?? 300_000);
      return;
    }
    this.pending.delete(msg.id!);
    clearTimeout(p.timer);
    if (msg.error) p.reject(new Error(`remote signer: ${msg.error}`));
    else p.resolve(msg.result ?? '');
  }

  private async request(method: Nip46Method, params: string[]): Promise<string> {
    await this.listen();
    const id = bytesToHex(randomBytes(8));
    const content = await this.client.nip44Encrypt(this.bunker.remoteSignerPubkey, JSON.stringify({ id, method, params }));
    const evt = await this.client.signEvent({ kind: NOSTR_CONNECT_KIND, content, tags: [['p', this.bunker.remoteSignerPubkey]] });
    const result = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`remote signer timeout (${method})`));
      }, this.opts.timeoutMs ?? 30_000);
      this.pending.set(id, { resolve, reject, timer });
    });
    const acks = await this.opts.pool.publish(evt, this.bunker.relays);
    if (!acks.some((a) => a.ok)) {
      const p = this.pending.get(id);
      if (p) {
        clearTimeout(p.timer);
        this.pending.delete(id);
      }
      throw new Error(`could not reach remote signer relays: ${acks.map((a) => a.message).join('; ')}`);
    }
    return result;
  }

  /**
   * Waits for a signer to answer a nostrconnect:// offer: the response carries the offer secret and its
   * author is the remote signer. The returned signer is already connected (no bunker secret needed).
   */
  static async fromNostrConnect(offer: NostrConnectOffer, opts: Omit<Nip46SignerOptions, 'clientSecretKey'> & { signal?: AbortSignal; onReady?: () => void }): Promise<Nip46Signer> {
    const client = new LocalSigner(offer.clientSecretKey);
    const me = await client.getPublicKey();
    const remote = await new Promise<string>((resolve, reject) => {
      let sub: { close(): void } | undefined;
      const done = (fn: () => void) => {
        clearTimeout(timer);
        sub?.close();
        fn();
      };
      const timer = setTimeout(() => done(() => reject(new Error('nostrconnect: no signer answered'))), opts.timeoutMs ?? 300_000);
      opts.signal?.addEventListener('abort', () => done(() => reject(new Error('nostrconnect cancelled'))));
      // Responses are ephemeral (kind 24133, never stored): show the offer only once this subscription is live.
      sub = opts.pool.subscribe(offer.relays, [{ kinds: [NOSTR_CONNECT_KIND], '#p': [me], since: Math.floor(Date.now() / 1000) - 10 }], {
        oneose: () => opts.onReady?.(),
        onevent: (evt) =>
          void client
            .nip44Decrypt(evt.pubkey, evt.content)
            .then((raw) => {
              const msg = JSON.parse(raw) as { result?: string; error?: string };
              if (msg.result === offer.secret) done(() => resolve(evt.pubkey));
              else if (msg.result === 'auth_url' && msg.error && /^https:\/\//.test(msg.error)) opts.onAuthUrl?.(msg.error);
            })
            .catch(() => undefined),
      });
    });
    return new Nip46Signer({ remoteSignerPubkey: remote, relays: offer.relays }, { ...opts, clientSecretKey: offer.clientSecretKey, permissions: offer.permissions });
  }

  async connect(): Promise<void> {
    const res = await this.request('connect', [this.bunker.remoteSignerPubkey, this.bunker.secret ?? '', this.permissions.join(',')]);
    if (res !== 'ack' && res !== this.bunker.secret) throw new Error(`unexpected connect response: ${res}`);
  }

  async getPublicKey(): Promise<string> {
    if (!this.userPubkey) this.userPubkey = await this.request('get_public_key', []);
    return this.userPubkey;
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    const pubkey = await this.getPublicKey();
    const unsigned = { kind: template.kind, tags: template.tags ?? [], content: template.content, created_at: template.created_at ?? Math.floor(Date.now() / 1000), pubkey };
    const signed = JSON.parse(await this.request('sign_event', [JSON.stringify(unsigned)])) as NostrEvent;
    if (!verifyEvent(signed) || signed.pubkey !== pubkey) throw new Error('remote signer returned an invalid event');
    return signed;
  }

  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
    return this.request('nip44_encrypt', [peerPubkey, plaintext]);
  }

  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
    return this.request('nip44_decrypt', [peerPubkey, ciphertext]);
  }

  close(): void {
    this.sub?.close();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error('signer closed'));
    }
    this.pending.clear();
  }
}

export interface BunkerPolicy {
  /** Decide whether a client may call a method. Default: only after a successful `connect` with the secret. */
  authorize?: (clientPubkey: string, method: Nip46Method, params: string[]) => boolean | Promise<boolean>;
  /** Allowed event kinds for sign_event (undefined = any). */
  allowedKinds?: number[];
  onRequest?: (info: { clientPubkey: string; method: Nip46Method; kind?: number; allowed: boolean }) => void;
}

/**
 * NIP-46 remote-signer side ("bunker"). Wraps any Signer — a local key on a hardware-isolated
 * device, or the managed vault — and serves kind 24133 requests.
 */
export class Nip46Bunker {
  private sub?: { close(): void };
  /** Authorized client pubkeys -> device they are bound to (FR024-03), if any. */
  private readonly connected = new Map<string, string | undefined>();
  private readonly revokedClients = new Set<string>();
  private readonly revokedDevices = new Set<string>();
  private readonly transport: LocalSigner;
  private currentSecret: string;

  constructor(
    private readonly userSigner: Signer,
    private readonly pool: RelayPool,
    private readonly relays: string[],
    private readonly policy: BunkerPolicy = {},
    transportSecretKey: Uint8Array = generateSecretKey(),
    secret: string = bytesToHex(randomBytes(16)),
  ) {
    this.transport = new LocalSigner(transportSecretKey);
    this.currentSecret = secret;
  }

  /** Current connection secret (changes after `rotateSecret` / `revokeDevice`). */
  get secret(): string {
    return this.currentSecret;
  }

  /** New connection secret: bunker URLs handed out before stop working for new clients. */
  rotateSecret(): string {
    this.currentSecret = bytesToHex(randomBytes(16));
    return this.currentSecret;
  }

  /** Authorized client sessions and the device each one is bound to. */
  sessions(): Array<{ clientPubkey: string; deviceId?: string }> {
    return [...this.connected].map(([clientPubkey, deviceId]) => ({ clientPubkey, ...(deviceId ? { deviceId } : {}) }));
  }

  /** Bind an authorized client to a device (policy-engine device id) so that revoking the device drops it. */
  bindDevice(clientPubkey: string, deviceId: string): void {
    if (this.revokedDevices.has(deviceId)) throw new Error('device revoked');
    if (!this.connected.has(clientPubkey)) throw new Error('unknown client session');
    this.connected.set(clientPubkey, deviceId);
  }

  /** Drop one client session for good: it cannot reconnect, not even with the secret. */
  revokeClient(clientPubkey: string): void {
    this.connected.delete(clientPubkey);
    this.revokedClients.add(clientPubkey);
  }

  /**
   * FR024-03: drop every client session bound to a revoked device and block those client keys. The
   * connection secret is rotated too (the device may have kept a bunker URL with it). Returns the
   * dropped client pubkeys.
   */
  revokeDevice(deviceId: string, opts: { rotateSecret?: boolean } = {}): string[] {
    this.revokedDevices.add(deviceId);
    const dropped = [...this.connected].filter(([, d]) => d === deviceId).map(([c]) => c);
    dropped.forEach((c) => this.revokeClient(c));
    if (opts.rotateSecret ?? true) this.rotateSecret();
    return dropped;
  }

  /** Accept a client-initiated nostrconnect:// offer: answer with its secret and authorize that client. */
  async acceptNostrConnect(uri: string, opts: { deviceId?: string } = {}): Promise<void> {
    const offer = parseNostrConnect(uri);
    if (this.revokedClients.has(offer.clientPubkey)) throw new Error('client revoked');
    if (opts.deviceId && this.revokedDevices.has(opts.deviceId)) throw new Error('device revoked');
    const content = await this.transport.nip44Encrypt(offer.clientPubkey, JSON.stringify({ id: bytesToHex(randomBytes(8)), result: offer.secret }));
    const evt = await this.transport.signEvent({ kind: NOSTR_CONNECT_KIND, content, tags: [['p', offer.clientPubkey]] });
    this.connected.set(offer.clientPubkey, opts.deviceId);
    this.policy.onRequest?.({ clientPubkey: offer.clientPubkey, method: 'connect', allowed: true });
    await this.pool.publish(evt, offer.relays);
  }

  async pointer(): Promise<BunkerPointer> {
    return { remoteSignerPubkey: await this.transport.getPublicKey(), relays: this.relays, secret: this.secret };
  }

  async start(): Promise<string> {
    const me = await this.transport.getPublicKey();
    await new Promise<void>((resolve) => {
      this.sub = this.pool.subscribe(this.relays, [{ kinds: [NOSTR_CONNECT_KIND], '#p': [me], since: Math.floor(Date.now() / 1000) - 10 }], {
        onevent: (evt) => void this.handle(evt),
        oneose: () => resolve(),
      });
    });
    return formatBunkerUrl(await this.pointer());
  }

  stop(): void {
    this.sub?.close();
  }

  private async handle(evt: NostrEvent) {
    let req: { id: string; method: Nip46Method; params: string[] };
    try {
      req = JSON.parse(await this.transport.nip44Decrypt(evt.pubkey, evt.content));
    } catch {
      return;
    }
    const reply = async (body: { result?: string; error?: string }) => {
      const content = await this.transport.nip44Encrypt(evt.pubkey, JSON.stringify({ id: req.id, ...body }));
      const res = await this.transport.signEvent({ kind: NOSTR_CONNECT_KIND, content, tags: [['p', evt.pubkey]] });
      await this.pool.publish(res, this.relays);
    };
    const params = Array.isArray(req.params) ? req.params.map(String) : [];
    let kind: number | undefined;
    try {
      if (req.method === 'connect') {
        const revoked = this.revokedClients.has(evt.pubkey);
        const ok = !revoked && params[1] === this.currentSecret;
        this.policy.onRequest?.({ clientPubkey: evt.pubkey, method: req.method, allowed: ok });
        if (!ok) return reply({ error: revoked ? 'client revoked' : 'invalid secret' });
        if (!this.connected.has(evt.pubkey)) this.connected.set(evt.pubkey, undefined);
        return reply({ result: 'ack' });
      }
      if (req.method === 'ping') return reply({ result: 'pong' });
      let allowed = this.connected.has(evt.pubkey);
      if (allowed && this.policy.authorize) allowed = await this.policy.authorize(evt.pubkey, req.method, params);
      if (req.method === 'sign_event') {
        kind = (JSON.parse(params[0] ?? '{}') as { kind?: number }).kind;
        if (this.policy.allowedKinds && (kind === undefined || !this.policy.allowedKinds.includes(kind))) allowed = false;
      }
      this.policy.onRequest?.({ clientPubkey: evt.pubkey, method: req.method, kind, allowed });
      if (!allowed) return reply({ error: 'unauthorized' });
      switch (req.method) {
        case 'get_public_key':
          return reply({ result: await this.userSigner.getPublicKey() });
        case 'sign_event': {
          const t = JSON.parse(params[0]!) as EventTemplate;
          const signed = await this.userSigner.signEvent({ kind: t.kind, content: t.content, tags: t.tags ?? [], created_at: t.created_at });
          return reply({ result: JSON.stringify(signed) });
        }
        case 'nip44_encrypt':
          return reply({ result: await this.userSigner.nip44Encrypt(params[0]!, params[1]!) });
        case 'nip44_decrypt':
          return reply({ result: await this.userSigner.nip44Decrypt(params[0]!, params[1]!) });
        default:
          return reply({ error: `unsupported method ${String(req.method)}` });
      }
    } catch (err) {
      return reply({ error: (err as Error).message });
    }
  }
}

