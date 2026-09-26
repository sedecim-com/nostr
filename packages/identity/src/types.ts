import type { CustodyMode } from '@sedecim/nostr-core';

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
  action: 'persona.created' | 'persona.imported' | 'persona.deleted' | 'link.created' | 'link.removed' | 'backup.exported' | 'backup.restored' | 'custody.migrated';
  subject: string;
  details?: Record<string, string>;
}

export interface BackupPackage {
  format: 'sedecim-identity-backup';
  version: 1;
  persona: Omit<PersonaConfig, 'id'> & { id: string };
  /** NIP-49 encrypted secret key (absent for external/managed custody) */
  ncryptsec?: string;
  createdAt: number;
}
