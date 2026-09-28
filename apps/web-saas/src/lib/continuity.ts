import { ArchiveVaultClient, archiveId, openArchive, sealArchive, type ArchiveMeta, type ArchiveUsage } from '@sedecim/continuity';
import { hexToBytes, wipe } from '@sedecim/nostr-core';
import type { PersonaSession } from './session';
import type { PersonaRecord } from './vault';

/**
 * VAULT-02 (ADR 0011): the persona's Continuity Vault. Requests are signed (NIP-98) with a key derived from the
 * archive key, never with the persona key: the vault account is not the npub, and a NIP-46 or managed signer is
 * never asked to sign them. The archive key never leaves the browser.
 */
async function withVault<T>(url: string, persona: PersonaRecord, fn: (client: ArchiveVaultClient, key: Uint8Array) => Promise<T>): Promise<T> {
  if (!persona.archiveKeyHex) throw new Error('esta persona aún no tiene llave de archivo');
  const key = hexToBytes(persona.archiveKeyHex);
  try {
    return await fn(new ArchiveVaultClient({ baseUrl: url, auth: { archiveKey: key } }), key);
  } finally {
    wipe(key);
  }
}

/**
 * Seals the persona's delivery ledger (every outbox operation with its signed event and state per relay) in this
 * browser and stores it in the vault, replacing the previous copy. The vault only receives the sealed envelope.
 */
export function pushLedger(url: string, s: PersonaSession): Promise<{ archive: ArchiveMeta; operations: number }> {
  return withVault(url, s.persona, async (client, key) => {
    const outbox = await s.engine.list();
    const id = archiveId(key, 'ledger');
    const plaintext = JSON.stringify({ type: 'ledger', version: 1, pubkey: s.persona.pubkey, at: Date.now(), outbox });
    const { archive } = await client.put(id, sealArchive(key, id, plaintext));
    return { archive, operations: outbox.length };
  });
}

/** Downloads every archive and opens it here: shows that this browser's archive key opens what the vault keeps. */
export function verifyVault(url: string, persona: PersonaRecord): Promise<{ archives: number; opened: number }> {
  return withVault(url, persona, async (client, key) => {
    const all = await client.listAll();
    let opened = 0;
    for (const meta of all) {
      try {
        wipe(openArchive(key, meta.id, (await client.get(meta.id)).envelope));
        opened++;
      } catch {
        // Sealed with another archive key, or damaged: counted as not opened.
      }
    }
    return { archives: all.length, opened };
  });
}

export function vaultUsage(url: string, persona: PersonaRecord): Promise<ArchiveUsage> {
  return withVault(url, persona, (client) => client.usage());
}
