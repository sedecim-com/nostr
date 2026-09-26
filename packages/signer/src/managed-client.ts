import { verifyEvent, type CustodyMode, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';

export interface ManagedSignerClientOptions {
  baseUrl: string;
  keyId: string;
  /** Returns the Authorization header value for the SaaS session (bearer or NIP-98). */
  authorization: () => string | Promise<string>;
  fetch?: typeof fetch;
}

/**
 * Client for the managed-signer service. CUSTODIAL: the operator has the technical capability to sign
 * as the user. The UI must never present this as non-custodial (spec §1, §8.4).
 */
export class ManagedSignerClient implements Signer {
  readonly custody: CustodyMode = 'managed';
  private pubkey?: string;

  constructor(private readonly opts: ManagedSignerClientOptions) {}

  private async call<T>(path: string, body?: unknown): Promise<T> {
    const f = this.opts.fetch ?? fetch;
    const res = await f(`${this.opts.baseUrl}/v1/keys/${encodeURIComponent(this.opts.keyId)}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'content-type': 'application/json', authorization: await this.opts.authorization() },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`managed signer ${path}: ${res.status} ${await res.text()}`);
    return (await res.json()) as T;
  }

  async getPublicKey(): Promise<string> {
    if (!this.pubkey) this.pubkey = (await this.call<{ pubkey: string }>('')).pubkey;
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
}
