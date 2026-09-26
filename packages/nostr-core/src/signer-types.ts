import type { EventTemplate, NostrEvent } from './event';

/**
 * Signer abstraction (spec §7, §8). Every client and service signs through this interface, so
 * key custody (local, offline, NIP-46, managed, enclave) is swappable without changing callers.
 */
export interface Signer {
  /** Custody descriptor surfaced to the sovereignty panel. */
  readonly custody: CustodyMode;
  getPublicKey(): Promise<string>;
  signEvent(template: EventTemplate): Promise<NostrEvent>;
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
}

export type CustodyMode = 'local' | 'offline' | 'external' | 'encrypted-backup' | 'managed' | 'managed-enclave';

export interface CustodyFacts {
  mode: CustodyMode;
  /** Can the platform operator technically sign as the user? */
  operatorCanSign: boolean;
  /** Can the platform recover the key on the user's behalf? */
  operatorCanRecover: boolean;
  custodial: boolean;
}

export const CUSTODY_FACTS: Record<CustodyMode, CustodyFacts> = {
  local: { mode: 'local', operatorCanSign: false, operatorCanRecover: false, custodial: false },
  offline: { mode: 'offline', operatorCanSign: false, operatorCanRecover: false, custodial: false },
  external: { mode: 'external', operatorCanSign: false, operatorCanRecover: false, custodial: false },
  'encrypted-backup': { mode: 'encrypted-backup', operatorCanSign: false, operatorCanRecover: false, custodial: false },
  managed: { mode: 'managed', operatorCanSign: true, operatorCanRecover: true, custodial: true },
  'managed-enclave': { mode: 'managed-enclave', operatorCanSign: true, operatorCanRecover: true, custodial: true },
};
