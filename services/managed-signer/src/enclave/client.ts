import { randomBytes } from 'node:crypto';
import { verifyEvent, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { verifyAttestation, type AttestationPolicy, type VerifiedAttestation } from './attestation';
import type { AwsCredentials, EnclaveRequest, EnclaveResult, EnclaveTransport } from './protocol';

/**
 * Key operations where the backend never holds plaintext (enclave tier, FR005-05). The backend stores only
 * `sealed` blobs (KMS ciphertext it cannot decrypt) and receives public keys, events and NIP-44 results.
 */
export interface SealedKeyOps {
  readonly provider: string;
  generate(): Promise<{ pubkey: string; sealed: Uint8Array }>;
  importNcryptsec(ncryptsec: string, password: string): Promise<{ pubkey: string; sealed: Uint8Array }>;
  /** Remote signer bound to one sealed key; `destroy()` is a no-op kept for symmetry with LocalSigner. */
  signer(sealed: Uint8Array, pubkey: string): Signer & { destroy(): void };
  /** FR-026: password-encrypted export produced inside the enclave. */
  exportNcryptsec(sealed: Uint8Array, pubkey: string, password: string, logN: number): Promise<string>;
}

export class EnclaveError extends Error {}

export interface EnclaveClientOptions {
  transport: EnclaveTransport;
  /**
   * Policy the enclave's attestation must satisfy before any key operation (root pin, PCRs). The nonce is
   * generated per check. KMS enforces the same PCRs independently through the key policy.
   */
  attestation: Omit<AttestationPolicy, 'expectedNonce'>;
  /** Credentials forwarded for the enclave's KMS calls (the parent's IAM principal). */
  credentials?: () => Promise<AwsCredentials | undefined>;
  /** Re-attest after this long (default 10 minutes). */
  reattestMs?: number;
  provider?: string;
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

/** Parent-side client of the enclave signer. */
export class EnclaveClient implements SealedKeyOps {
  readonly provider: string;
  private attested?: { at: number; result: Promise<VerifiedAttestation> };

  constructor(private readonly opts: EnclaveClientOptions) {
    this.provider = opts.provider ?? 'nitro-enclave';
  }

  /** Challenges the enclave with a fresh nonce and verifies its attestation document. */
  async verify(): Promise<VerifiedAttestation> {
    const nonce = randomBytes(32);
    const res = await this.opts.transport.request({ op: 'attest', nonce: b64(nonce) });
    if (!res.ok) throw new EnclaveError(`enclave: ${res.error}`);
    if (!('document' in res)) throw new EnclaveError('enclave: unexpected attest response');
    return verifyAttestation(new Uint8Array(Buffer.from(res.document, 'base64')), { ...this.opts.attestation, expectedNonce: nonce });
  }

  private ensureAttested() {
    const now = Date.now();
    if (!this.attested || now - this.attested.at > (this.opts.reattestMs ?? 600_000)) {
      const result = this.verify();
      this.attested = { at: now, result };
      result.catch(() => (this.attested = undefined));
    }
    return this.attested.result;
  }

  private async call(req: DistributiveOmit<EnclaveRequest, 'credentials'>, field: string): Promise<EnclaveResult> {
    await this.ensureAttested();
    const credentials = await this.opts.credentials?.();
    const res = await this.opts.transport.request({ ...req, ...(credentials ? { credentials } : {}) } as EnclaveRequest);
    if (!res.ok) throw new EnclaveError(`enclave: ${res.error}`);
    if (!(field in res)) throw new EnclaveError(`enclave: unexpected ${req.op} response`);
    return res;
  }

  private async sealedKey(req: { op: 'generate' } | { op: 'import'; ncryptsec: string; password: string }) {
    const res = (await this.call(req, 'sealed')) as { pubkey: string; sealed: string };
    return { pubkey: res.pubkey, sealed: new Uint8Array(Buffer.from(res.sealed, 'utf8')) };
  }

  generate() {
    return this.sealedKey({ op: 'generate' });
  }

  importNcryptsec(ncryptsec: string, password: string) {
    return this.sealedKey({ op: 'import', ncryptsec, password });
  }

  signer(sealedBytes: Uint8Array, pubkey: string): Signer & { destroy(): void } {
    const sealed = Buffer.from(sealedBytes).toString('utf8');
    const nip44 = async (mode: 'encrypt' | 'decrypt', peer: string, data: string) => ((await this.call({ op: 'nip44', sealed, pubkey, mode, peer, data }, 'result')) as { result: string }).result;
    return {
      custody: 'managed-enclave',
      getPublicKey: async () => pubkey,
      signEvent: async (template: EventTemplate): Promise<NostrEvent> => {
        const { event } = (await this.call({ op: 'sign', sealed, pubkey, template }, 'event')) as { event: NostrEvent };
        // Never trust the enclave blindly: the event must verify and belong to the expected key.
        if (!verifyEvent(event) || event.pubkey !== pubkey || event.kind !== template.kind || event.content !== template.content) throw new EnclaveError('enclave returned an invalid event');
        return event;
      },
      nip44Encrypt: (peer, plaintext) => nip44('encrypt', peer, plaintext),
      nip44Decrypt: (peer, ciphertext) => nip44('decrypt', peer, ciphertext),
      destroy: () => {},
    };
  }

  async exportNcryptsec(sealed: Uint8Array, pubkey: string, password: string, logN: number) {
    const res = (await this.call({ op: 'export', sealed: Buffer.from(sealed).toString('utf8'), pubkey, password, logN }, 'ncryptsec')) as { ncryptsec: string };
    return res.ncryptsec;
  }
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
