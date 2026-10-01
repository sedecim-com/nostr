import { ArchiveVaultClient, archiveHistory, belongsOnPersonaRelays, ledgerRecords, openArchive, restoreHistory, scheduleArchiveExpiry, vaultExport, type ArchiveRetention, type ArchiveUsage, type HistoryArchiveResult, type VaultExport } from '@sedecim/continuity';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { tombstonedWraps, wrapTombstone } from '@sedecim/messaging';
import { hexToBytes, isExpired, wipe, type NostrEvent } from '@sedecim/nostr-core';
import { FilterWindowSync, rebuildHistory } from '@sedecim/sync';
import { dmTombstones, vaultForgetQueue } from './expiration';
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
 * vault only receives sealed envelopes. PANEL-06: expired messages, and those their author deleted (dmTombstones), are
 * left out and their archives deleted; the expiring ones stored now are queued to leave the vault when they expire.
 */
export function pushVault(url: string, s: PersonaSession, store: EncryptedStore): Promise<HistoryArchiveResult & { operations: number }> {
  return withVault(url, s.persona, async (client, key) => {
    const ledger = await s.engine.list();
    const mls = await groupStateSnapshot(store, s.persona.id);
    const events = await canonicalHistory(s);
    const forget = tombstonedWraps(await dmTombstones(store, s.persona.id).all());
    const result = await archiveHistory(client, key, {
      pubkey: s.persona.pubkey,
      events,
      groupMessages: await new GroupHistory(store, s.persona.id).archived(),
      ledger,
      ...(Object.keys(mls).length ? { mls } : {}),
      forget,
    });
    const gone = new Set(forget);
    const now = Math.floor(Date.now() / 1000);
    await scheduleArchiveExpiry(vaultForgetQueue(store, s.persona.id), events.filter((e) => !gone.has(e.id) && !isExpired(e, now)));
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
  /** Gift wraps sent to other people (VAULT-04 copies each send): their place is those people's relays, not the persona's. */
  othersWraps: number;
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
 * persona's backup), even if every relay lost its events: the verified events go back to the persona's relays (gift
 * wraps sent to other people aside), so channels and DMs read as before; the ledger operations this browser lacks
 * join its outbox; the group messages join its group history; the MLS state is written only if this browser has no
 * groups of the persona. PANEL-06: expired messages stay out (restoreHistory), and so do the wraps of messages this
 * browser knows were deleted: neither published again nor put back in the outbox.
 */
export async function restoreVault(url: string, s: PersonaSession, store: EncryptedStore): Promise<VaultRestore> {
  const restored = await withVault(url, s.persona, (client, key) => restoreHistory(client, key, { pubkey: s.persona.pubkey }));
  const tombstones = dmTombstones(store, s.persona.id);
  const deleted = async (event?: NostrEvent) => !!event && !!(await tombstones.get(wrapTombstone(event.id)));
  let published = 0;
  let rejected = 0;
  let othersWraps = 0;
  for (const e of restored.events) {
    if (await deleted(e)) continue;
    if (!belongsOnPersonaRelays(e, s.persona.pubkey)) othersWraps++;
    else if ((await s.pool.publish(e, s.persona.relays)).some((r) => r.ok)) published++;
    else rejected++;
  }
  const outbox = store.collection<OutboxRecord>(`outbox-${s.persona.id}`);
  let ledger = 0;
  for (const rec of ledgerRecords<OutboxRecord>(restored.ledger?.outbox ?? [])) {
    if ((await outbox.get(rec.opId)) || (await deleted(rec.event))) continue; // never overwrite newer local state
    await outbox.put(rec.opId, rec);
    ledger++;
  }
  const groupMessages = await new GroupHistory(store, s.persona.id).restore(restored.groupMessages);
  const mls = await restoreGroupState(s, store, restored.mls?.namespaces);
  return { archives: restored.archives, skipped: restored.skipped, events: restored.events.length, published, rejected, othersWraps, groupMessages, ledger, mls, ...(restored.ledger ? { savedAt: restored.ledger.at } : {}), missing: restored.missing };
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

/** VAULT-05: keep this persona's archives `days` since their last write (null: the vault operator's maximum). */
export function setVaultRetention(url: string, persona: PersonaRecord, days: number | null): Promise<ArchiveRetention> {
  return withVault(url, persona, (client) => client.setRetention(days));
}

/**
 * VAULT-05: the persona's vault in an open, portable format, decrypted in this browser: signed NIP-01 events any
 * Nostr client can verify and publish, the group messages and the ledger. The MLS state stays out.
 */
export async function exportVault(url: string, persona: PersonaRecord): Promise<{ export: VaultExport; skipped: number }> {
  const restored = await withVault(url, persona, (client, key) => restoreHistory(client, key, { pubkey: persona.pubkey }));
  return { export: vaultExport(restored, persona.pubkey), skipped: restored.skipped };
}

/** VAULT-05: deletes every archive of the persona and its vault account (its retention choice included). */
export function deleteVault(url: string, persona: PersonaRecord): Promise<number> {
  return withVault(url, persona, (client) => client.remove());
}
