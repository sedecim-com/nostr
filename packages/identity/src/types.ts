import type { CustodyMode } from '@sedecim/nostr-core';
import type { SovereigntyConfig } from '@sedecim/profiles';

export type Compartment = 'standard' | 'high-risk' | 'institutional';
export type LinkVisibility = 'private' | 'selective' | 'public';

export interface PersonaConfig {
  id: string;
  label: string;
  pubkey: string;
  custody: CustodyMode;
  compartment: Compartment;
  relays: string[];
  network: 'direct' | 'tor-only';
  /** bunker:// pointer when custody is external (no secret material) */
  bunker?: string;
  /** managed key id when custody is managed */
  managedKeyId?: string;
  createdAt: number;
}

export interface IdentityLink {
  id: string;
  from: string;
  to: string;
  visibility: LinkVisibility;
  /** pubkeys allowed to see a selective link */
  audience?: string[];
  createdAt: number;
  consent: 'explicit-user-action';
}

export interface AuditEntry {
  at: number;
  action: 'persona.created' | 'persona.imported' | 'persona.deleted' | 'link.created' | 'link.removed' | 'backup.exported' | 'backup.restored' | 'custody.migrated' | 'archive_key.created';
  subject: string;
  details?: Record<string, string>;
}

/** Legacy backup (v1): persona configuration in clear, only the key encrypted. Still restorable. */
export interface BackupPackageV1 {
  format: 'sedecim-identity-backup';
  version: 1;
  persona: Omit<PersonaConfig, 'id'> & { id: string };
  /** NIP-49 encrypted secret key (absent for external/managed custody) */
  ncryptsec?: string;
  createdAt: number;
}

/**
 * Full backup (v2, FR027-02): everything except the timestamp is encrypted with the backup password.
 * `ncryptsec` stays a standard NIP-49 string so the key alone can be imported in other clients.
 */
export interface BackupPackageV2 {
  format: 'sedecim-identity-backup';
  version: 2;
  /** NIP-49 encrypted secret key (absent for external/managed custody) */
  ncryptsec?: string;
  /** Random 32-byte content key wrapped with NIP-49 (scrypt + XChaCha20-Poly1305) under the backup password. */
  contentKey: string;
  /** base64(nonce[24] || XChaCha20-Poly1305(contentKey, JSON(BackupContents))) */
  sealed: string;
  createdAt: number;
}

export type BackupPackage = BackupPackageV1 | BackupPackageV2;

/** Sealed payload of a v2 backup. */
export interface BackupContents {
  persona: PersonaConfig;
  /** The persona's sovereignty/privacy panel configuration (PANEL-03). */
  config?: SovereigntyConfig;
  /** Encrypted-at-rest MLS group state (EncryptedGroupStorage `mls-*` collections), values as stored. */
  mls?: Record<string, Array<{ id: string; value: unknown }>>;
  /**
   * Delivery ledger (`outbox` collection of the delivery engine, FR013-03): pending operations keep their
   * signed event and per-relay state, so a restored device can resume or reconcile them instead of losing them.
   */
  outbox?: Array<{ id: string; value: unknown }>;
  /** VAULT-02: the persona's archive key for the Continuity Vault (hex), never the nsec (ADR 0011). */
  archiveKey?: string;
}
