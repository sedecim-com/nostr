import { ArchiveVaultClient, archiveHistory, ledgerRecords, openArchive, restoreHistory, type ArchiveUsage, type HistoryArchiveResult } from '@sedecim/continuity';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { hexToBytes, wipe, type NostrEvent } from '@sedecim/nostr-core';
import { FilterWindowSync, rebuildHistory } from '@sedecim/sync';
import { GroupHistory, groupStateSnapshot, restoreGroupState } from './groups';
import type { PersonaSession } from './session';
import type { PersonaRecord } from './vault';

/** NIP-29 channel state (metadata, admins, members, roles), signed by the relay. */
const CHANNEL_STATE_KINDS = [39000, 39001, 39002, 39003];
/** The persona's own replaceable lists: profile, contacts, relays (NIP-65), DM relays (10050), Blossom servers (10063). */
const OWN_LIST_KINDS = [0, 3, 10002, 10050, 10063];

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

/** VAULT-03: every event the persona's relays hold for it: own activity and lists, its channels and their state, its gift wraps. */
async function canonicalHistory(s: PersonaSession): Promise<NostrEvent[]> {
  const now = Math.floor(Date.now() / 1000);
  const history = await rebuildHistory({ relays: s.persona.relays, pubkey: s.persona.pubkey, strategies: [new FilterWindowSync(s.pool, { since: 0, windowSeconds: now + 1, pageLimit: 500 })] });
  const channels = Object.keys(history.channels);
  const lists = await s.pool.query(s.persona.relays, [{ authors: [s.persona.pubkey], kinds: OWN_LIST_KINDS }, ...(channels.length ? [{ kinds: CHANNEL_STATE_KINDS, '#d': channels }] : [])], 10_000);
  return [...history.own, ...lists, ...Object.values(history.channels).flat(), ...history.wraps];
}

/**
 * VAULT-03 (ADR 0011): seals in this browser, and stores in the vault, what a clean device needs to rebuild the
 * persona's history with empty relays: every canonical event its relays hold for it (its channels with their state,
 * the gift wraps of its DMs in both directions), the group messages it read or sent, the delivery ledger and the MLS
 * group state. Events and messages are written once; the ledger and the MLS state replace their previous copy. The
 * vault only receives sealed envelopes.
 */
export function pushVault(url: string, s: PersonaSession, store: EncryptedStore): Promise<HistoryArchiveResult & { operations: number }> {
  return withVault(url, s.persona, async (client, key) => {
    const ledger = await s.engine.list();
    const mls = await groupStateSnapshot(store, s.persona.id);
    const result = await archiveHistory(client, key, {
      pubkey: s.persona.pubkey,
      events: await canonicalHistory(s),
      groupMessages: await new GroupHistory(store, s.persona.id).archived(),
      ledger,
      ...(Object.keys(mls).length ? { mls } : {}),
    });
    return { ...result, operations: ledger.length };
  });
}

export interface VaultRestore {
  archives: number;
  skipped: number;
  /** Verified events in the vault, and how many the persona's relays accepted again (or refused). */
  events: number;
  published: number;
  rejected: number;
  groupMessages: number;
  /** Ledger operations this browser did not have. */
  ledger: number;
  mls: 'restored' | 'kept' | 'none';
  /** When the restored ledger was sealed (ms), and archives it counted that the vault no longer lists. */
  savedAt?: number;
  missing: number;
}

/**
 * VAULT-03: rebuilds the persona's history in this browser from the vault, with nothing but its archive key (from the
 * persona's backup), even if every relay lost its events: the verified events go back to the persona's relays, so
 * channels and DMs read as before; the ledger operations this browser lacks join its outbox; the group messages join
 * its group history; the MLS state is written only if this browser has no groups of the persona.
 */
export async function restoreVault(url: string, s: PersonaSession, store: EncryptedStore): Promise<VaultRestore> {
  const restored = await withVault(url, s.persona, (client, key) => restoreHistory(client, key, { pubkey: s.persona.pubkey }));
  let published = 0;
  let rejected = 0;
  for (const e of restored.events) {
    if ((await s.pool.publish(e, s.persona.relays)).some((r) => r.ok)) published++;
    else rejected++;
  }
  const outbox = store.collection<OutboxRecord>(`outbox-${s.persona.id}`);
  let ledger = 0;
  for (const rec of ledgerRecords<OutboxRecord>(restored.ledger?.outbox ?? [])) {
    if (await outbox.get(rec.opId)) continue; // never overwrite newer local state
    await outbox.put(rec.opId, rec);
    ledger++;
  }
  const groupMessages = await new GroupHistory(store, s.persona.id).restore(restored.groupMessages);
  const mls = await restoreGroupState(s, store, restored.mls?.namespaces);
  return { archives: restored.archives, skipped: restored.skipped, events: restored.events.length, published, rejected, groupMessages, ledger, mls, ...(restored.ledger ? { savedAt: restored.ledger.at } : {}), missing: restored.missing };
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
