/**
 * NIP-46 remote signing ("Nostr Connect"). The client never holds the user's nsec: it holds an
 * ephemeral client keypair and sends NIP-44 encrypted JSON-RPC requests (kind 24133) through relays.
 */
import { bytesToHex, generateSecretKey, randomBytes, verifyEvent, type EventTemplate, type NostrEvent, type Signer, type CustodyMode } from '@sedecim/nostr-core';
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

export interface Nip46SignerOptions {
  pool: RelayPool;
  /** Ephemeral client key; generated if omitted. Persist it to keep a stable session with the bunker. */
  clientSecretKey?: Uint8Array;
  /** Minimal, visible permissions requested from the signer (spec §8.3). */
  permissions?: string[];
  timeoutMs?: number;
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
    if (msg.result === 'auth_url') return; // auth challenge: keep waiting for the real response
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
  private readonly connected = new Set<string>();
  private readonly transport: LocalSigner;
  readonly secret: string;

  constructor(
    private readonly userSigner: Signer,
    private readonly pool: RelayPool,
    private readonly relays: string[],
    private readonly policy: BunkerPolicy = {},
    transportSecretKey: Uint8Array = generateSecretKey(),
    secret: string = bytesToHex(randomBytes(16)),
  ) {
    this.transport = new LocalSigner(transportSecretKey);
    this.secret = secret;
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
        const ok = params[1] === this.secret;
        this.policy.onRequest?.({ clientPubkey: evt.pubkey, method: req.method, allowed: ok });
        if (!ok) return reply({ error: 'invalid secret' });
        this.connected.add(evt.pubkey);
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

