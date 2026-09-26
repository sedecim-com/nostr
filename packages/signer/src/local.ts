import { finalizeEvent, getPublicKey, nip44, toUnsigned, wipe, type CustodyMode, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';

/**
 * Signer holding the secret key in process memory. Used for 'local' and 'offline' custody on the
 * client, and inside the managed-signer service (where custody is 'managed').
 */
export class LocalSigner implements Signer {
  private secretKey: Uint8Array | null;
  private readonly pubkey: string;
  private readonly convKeys = new Map<string, Uint8Array>();

  constructor(secretKey: Uint8Array, readonly custody: CustodyMode = 'local') {
    this.secretKey = new Uint8Array(secretKey);
    this.pubkey = getPublicKey(this.secretKey);
  }

  private key(): Uint8Array {
    if (!this.secretKey) throw new Error('signer has been destroyed');
    return this.secretKey;
  }

  async getPublicKey(): Promise<string> {
    return this.pubkey;
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    return finalizeEvent(toUnsigned(template, this.pubkey), this.key());
  }

  private conversationKey(peer: string): Uint8Array {
    let ck = this.convKeys.get(peer);
    if (!ck) {
      ck = nip44.getConversationKey(this.key(), peer);
      this.convKeys.set(peer, ck);
    }
    return ck;
  }

  async nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
    return nip44.encrypt(plaintext, this.conversationKey(peerPubkey));
  }

  async nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
    return nip44.decrypt(ciphertext, this.conversationKey(peerPubkey));
  }

  /** Zeroize key material. The signer is unusable afterwards. */
  destroy(): void {
    if (this.secretKey) wipe(this.secretKey);
    for (const ck of this.convKeys.values()) wipe(ck);
    this.convKeys.clear();
    this.secretKey = null;
  }
}
