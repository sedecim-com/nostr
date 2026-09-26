import { verifyEvent, type CustodyMode, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';

/** Returns the caller's current Acceso (Cognito) id or access token; called before every request. */
export type AccessTokenProvider = () => Promise<string>;

export interface ManagedSignerConnection {
  baseUrl: string;
  token: AccessTokenProvider;
  fetch?: typeof fetch;
}

export interface ManagedSignerClientOptions extends ManagedSignerConnection {
  keyId: string;
}

/** Key metadata as returned by the managed-signer service. Never contains key material. */
export interface ManagedKeyInfo {
  keyId: string;
  owner: string;
  pubkey: string;
  provider: string;
  version: number;
  state: 'active' | 'export-pending' | 'migrated';
  createdAt: number;
  lastUsed?: number;
  allowedKinds?: number[];
  migratedAt?: number;
  retentionDays: number;
  custody: 'managed';
  custodial: true;
  disclosure: string;
}

export class ManagedSignerHttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function request<T>(conn: ManagedSignerConnection, method: string, path: string, body?: unknown): Promise<T> {
  const token = await conn.token();
  if (!token) throw new ManagedSignerHttpError(401, 'managed signer: no Acceso session');
  const f = conn.fetch ?? fetch;
  const res = await f(`${conn.baseUrl.replace(/\/$/, '')}/v1/keys${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    let message = text;
    try {
      message = (JSON.parse(text) as { error?: string }).error ?? text;
    } catch {
      // not JSON
    }
    throw new ManagedSignerHttpError(res.status, `managed signer ${method} ${path || '/'}: ${res.status} ${message}`);
  }
  return (await res.json()) as T;
}

/**
 * Browser-safe client for the managed-signer service, authorized with the user's Acceso token (FR005-04).
 * CUSTODIAL: the operator has the technical capability to sign as the user. The UI must never present
 * this as non-custodial (spec §1, §8.4).
 */
export class ManagedSignerClient implements Signer {
  readonly custody: CustodyMode = 'managed';
  private pubkey?: string;

  constructor(private readonly opts: ManagedSignerClientOptions) {}

  /** The caller's live managed keys. */
  static async listKeys(conn: ManagedSignerConnection): Promise<ManagedKeyInfo[]> {
    return (await request<{ keys: ManagedKeyInfo[] }>(conn, 'GET', '')).keys;
  }

  /** Creates a managed key for the caller. Only after an explicit, informed opt-in (FR005-07). */
  static async createKey(conn: ManagedSignerConnection, opts: { allowedKinds?: number[] } = {}): Promise<ManagedKeyInfo> {
    return request<ManagedKeyInfo>(conn, 'POST', '', opts.allowedKinds ? { allowed_kinds: opts.allowedKinds } : {});
  }

  private call<T>(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST'): Promise<T> {
    return request<T>(this.opts, method, `/${encodeURIComponent(this.opts.keyId)}${path}`, body);
  }

  describe(): Promise<ManagedKeyInfo> {
    return this.call<ManagedKeyInfo>('');
  }

  async getPublicKey(): Promise<string> {
    if (!this.pubkey) this.pubkey = (await this.describe()).pubkey;
    return this.pubkey;
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    const { event } = await this.call<{ event: NostrEvent }>('/sign', { template });
    if (!verifyEvent(event) || event.pubkey !== (await this.getPublicKey())) throw new Error('managed signer returned invalid event');
    return event;
  }

  async nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
    return (await this.call<{ ciphertext: string }>('/nip44/encrypt', { peer: peerPubkey, plaintext })).ciphertext;
  }

  async nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
    return (await this.call<{ plaintext: string }>('/nip44/decrypt', { peer: peerPubkey, ciphertext })).plaintext;
  }

  /** FR-026 step 1: ncryptsec of the key plus the challenge to sign with it. */
  exportForMigration(password: string): Promise<{ ncryptsec: string; challenge: string }> {
    return this.call('/export', { password });
  }

  /** FR-026 step 2: proof = event signed with the exported key carrying the `challenge` tag. */
  async confirmMigration(proof: NostrEvent): Promise<'migrated'> {
    return (await this.call<{ state: 'migrated' }>('/confirm-migration', { proof })).state;
  }

  /** FR-026 step 3: deletes the managed copy; the material is destroyed after the retention window. */
  async deleteKey(): Promise<{ destroyAfter: string }> {
    return { destroyAfter: (await this.call<{ destroy_after: string }>('', undefined, 'DELETE')).destroy_after };
  }
}
