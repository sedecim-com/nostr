import type { CustodyMode, EventTemplate, NostrEvent, Signer } from '@sedecim/nostr-core';

interface Nip07Provider {
  getPublicKey(): Promise<string>;
  signEvent(evt: EventTemplate & { created_at: number }): Promise<NostrEvent>;
  nip44?: { encrypt(pk: string, pt: string): Promise<string>; decrypt(pk: string, ct: string): Promise<string> };
}

/** Browser extension signer (NIP-07). The web app never sees the nsec. */
export class Nip07Signer implements Signer {
  readonly custody: CustodyMode = 'external';
  constructor(private readonly provider: Nip07Provider = (globalThis as { nostr?: Nip07Provider }).nostr!) {
    if (!this.provider) throw new Error('no NIP-07 extension available');
  }
  getPublicKey() {
    return this.provider.getPublicKey();
  }
  signEvent(t: EventTemplate) {
    return this.provider.signEvent({ ...t, tags: t.tags ?? [], created_at: t.created_at ?? Math.floor(Date.now() / 1000) });
  }
  nip44Encrypt(pk: string, pt: string) {
    if (!this.provider.nip44) throw new Error('extension does not support NIP-44');
    return this.provider.nip44.encrypt(pk, pt);
  }
  nip44Decrypt(pk: string, ct: string) {
    if (!this.provider.nip44) throw new Error('extension does not support NIP-44');
    return this.provider.nip44.decrypt(pk, ct);
  }
}
