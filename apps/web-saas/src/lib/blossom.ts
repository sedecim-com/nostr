import { fetchServerList, selectUploadServers } from '@sedecim/blossom-client';
import { BUZZ_PINNED_ADAPTER } from '@sedecim/messaging';
import type { DeploymentConfig } from './config';
import type { PersonaSession } from './session';

/** FR018-05: a user's Blossom server list (kind 10063) from the active persona's relays; empty when none or unreachable. */
export function blossomServersOf(s: PersonaSession, pubkey = s.pubkey): Promise<string[]> {
  return fetchServerList(s.pool, s.persona.relays, pubkey, 3000).catch(() => []);
}

/**
 * Upload targets: the user's list first (primary = first). Ciphertext never goes to the relay media
 * endpoint when the interop gate found it image-only (BUZZ_PINNED_ADAPTER: `encryptedAttachments:
 * 'blob-store'`); the deployment server is the fallback (blob-store for ciphertext, relay media for images).
 */
export function uploadTargets(cfg: DeploymentConfig, userServers: string[], encrypted: boolean): string[] {
  const restricted = BUZZ_PINNED_ADAPTER.encryptedAttachments === 'blob-store' && cfg.buzzMedia ? [cfg.buzzMedia] : [];
  return selectUploadServers({ userServers, encrypted, contentRestricted: restricted, fallback: encrypted ? cfg.blobStore : cfg.buzzMedia });
}
