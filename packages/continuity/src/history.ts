/**
 * VAULT-03 (ADR 0011): what the Continuity Vault keeps of a persona's history, and how a clean device gets it back
 * with nothing but the archive key, even when every relay lost the persona's events.
 *
 * - One archive per canonical signed event (`event:<id>`): the persona's own activity, the events and state of
 *   its channels, and the gift wraps addressed to it (DMs it received, the copy of those it sent, receipts and
 *   group invitations). A signed event can be verified and published again exactly as it was.
 * - One archive per decrypted Marmot message (`group-message:<group>:<rumor>`): MLS deletes the keys of past
 *   epochs, so a group ciphertext read once cannot be read again; the vault keeps the rumor instead.
 * - Snapshots, replaced on every push: the delivery ledger (`ledger`) and the MLS group state (`mls`). Each one
 *   also seals the date and how many archives the account holds after that push, so a restore can tell when the
 *   copy is from and whether archives went missing since (deleted by the operator, or lost).
 *
 * Labels never reach the vault: `archiveId` turns them into opaque ids with the archive key.
 */
import { verifyEvent, type NostrEvent } from '@sedecim/nostr-core';
import type { ArchiveVaultClient } from './client';
import { archiveId, openArchiveText, sealArchive } from './seal';

export const LEDGER_LABEL = 'ledger';
export const MLS_LABEL = 'mls';
export const eventLabel = (eventId: string) => `event:${eventId}`;
export const groupMessageLabel = (groupId: string, rumorId: string) => `group-message:${groupId}:${rumorId}`;

/** A decrypted Marmot application message, as the persona read (or sent) it. */
export interface ArchivedGroupMessage {
  groupId: string;
  rumorId: string;
  sender: string;
  kind: number;
  content: string;
  createdAt: number;
  tags?: string[][];
  epoch?: number;
}

/**
 * MLS group state by logical `GroupStorage` namespace (without a client's own prefix), entries as stored. The
 * clients leave out private key packages: a restored copy never joins with the source device's.
 */
export type MlsSnapshot = Record<string, Array<{ id: string; value: unknown }>>;

export interface HistoryArchiveInput {
  /** The persona the history belongs to (checked again on restore). */
  pubkey: string;
  events: NostrEvent[];
  groupMessages?: ArchivedGroupMessage[];
  /** Delivery ledger: the outbox records. */
  ledger?: unknown[];
  mls?: MlsSnapshot;
}

export interface HistoryArchiveResult {
  /** `kept`: already in the vault (event archives never change). `invalid`: bad signature, not archived. */
  events: { uploaded: number; kept: number; invalid: number };
  groupMessages: { uploaded: number; kept: number };
  /** Snapshots written in this push (`ledger`, `mls`). */
  snapshots: string[];
}

export interface RestoredHistory {
  /** Verified signed events, oldest first. */
  events: NostrEvent[];
  groupMessages: ArchivedGroupMessage[];
  /** `at`: when the snapshot was sealed (ms). */
  ledger?: { at: number; outbox: unknown[] };
  mls?: { at: number; namespaces: MlsSnapshot };
  /** Archives in the vault account. */
  archives: number;
  /** Archives that do not open with this archive key, or do not hold a valid entry of this persona. */
  skipped: number;
  /** Archives the latest snapshot counted that the vault no longer lists: deleted by the operator, or lost. */
  missing: number;
}

type Snapshot = { pubkey: string; at: number; archives?: number };
type Payload =
  | { type: 'event'; version: 1; event: NostrEvent }
  | { type: 'group-message'; version: 1; pubkey: string; message: ArchivedGroupMessage }
  | ({ type: 'ledger'; version: 1; outbox: unknown[] } & Snapshot)
  | ({ type: 'mls'; version: 1; namespaces: MlsSnapshot } & Snapshot);

const NAMESPACE = /^[a-z0-9-]+$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** Ledger entries as outbox records keyed by `opId` (the CLI pushed `{ id, value }` store entries before VAULT-03). */
export function ledgerRecords<T extends { opId: string }>(outbox: unknown[]): T[] {
  return outbox
    .map((e) => (e && typeof e === 'object' && 'value' in e && typeof (e as { id?: unknown }).id === 'string' ? (e as { value: unknown }).value : e) as T)
    .filter((r) => !!r && typeof r === 'object' && typeof r.opId === 'string');
}

/** Runs `jobs` with at most `limit` in flight: enough to keep the vault busy without flooding it. */
async function runLimited(jobs: Array<() => Promise<void>>, limit: number): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) await jobs[next++]!();
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, jobs.length)) }, worker));
}

function isGroupMessage(m: unknown): m is ArchivedGroupMessage {
  const g = m as Partial<ArchivedGroupMessage> | null;
  return (
    !!g &&
    typeof g.groupId === 'string' &&
    g.groupId.length > 0 &&
    typeof g.rumorId === 'string' &&
    g.rumorId.length > 0 &&
    typeof g.sender === 'string' &&
    HEX64.test(g.sender) &&
    typeof g.content === 'string' &&
    Number.isSafeInteger(g.kind) &&
    Number.isSafeInteger(g.createdAt) &&
    (g.tags === undefined || (Array.isArray(g.tags) && g.tags.every((t) => Array.isArray(t) && t.every((x) => typeof x === 'string')))) &&
    (g.epoch === undefined || Number.isSafeInteger(g.epoch))
  );
}

function isMlsSnapshot(s: unknown): s is MlsSnapshot {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return false;
  return Object.entries(s).every(([ns, entries]) => NAMESPACE.test(ns) && Array.isArray(entries) && entries.every((e) => !!e && typeof (e as { id?: unknown }).id === 'string'));
}

/**
 * Seals and uploads the persona's history. Event and group-message archives are written once (a retry or the
 * next push skips what the vault already holds); the ledger and MLS snapshots replace their previous copy.
 */
export async function archiveHistory(client: ArchiveVaultClient, key: Uint8Array, input: HistoryArchiveInput, opts: { concurrency?: number; now?: () => number } = {}): Promise<HistoryArchiveResult> {
  const present = new Set((await client.listAll()).map((a) => a.id));
  const result: HistoryArchiveResult = { events: { uploaded: 0, kept: 0, invalid: 0 }, groupMessages: { uploaded: 0, kept: 0 }, snapshots: [] };
  const jobs: Array<() => Promise<void>> = [];
  const held = new Set(present);
  const put = (label: string, payload: Payload, done: () => void) => {
    const id = archiveId(key, label);
    jobs.push(async () => {
      await client.put(id, sealArchive(key, id, JSON.stringify(payload)));
      held.add(id);
      done();
    });
  };

  const seenEvents = new Set<string>();
  for (const event of input.events) {
    if (seenEvents.has(event.id)) continue;
    seenEvents.add(event.id);
    if (!verifyEvent(event)) {
      result.events.invalid++;
      continue;
    }
    if (present.has(archiveId(key, eventLabel(event.id)))) result.events.kept++;
    else put(eventLabel(event.id), { type: 'event', version: 1, event }, () => result.events.uploaded++);
  }

  const seenMessages = new Set<string>();
  for (const message of input.groupMessages ?? []) {
    const label = groupMessageLabel(message.groupId, message.rumorId);
    if (seenMessages.has(label) || !isGroupMessage(message)) continue;
    seenMessages.add(label);
    if (present.has(archiveId(key, label))) result.groupMessages.kept++;
    else put(label, { type: 'group-message', version: 1, pubkey: input.pubkey, message }, () => result.groupMessages.uploaded++);
  }
  await runLimited(jobs, opts.concurrency ?? 4);

  const at = (opts.now ?? Date.now)();
  // What the account holds once this push ends, snapshots included.
  if (input.ledger) held.add(archiveId(key, LEDGER_LABEL));
  if (input.mls) held.add(archiveId(key, MLS_LABEL));
  const snapshot: Snapshot = { pubkey: input.pubkey, at, archives: held.size };
  const snapshots: Array<[string, Payload]> = [];
  if (input.ledger) snapshots.push([LEDGER_LABEL, { type: 'ledger', version: 1, ...snapshot, outbox: input.ledger }]);
  if (input.mls) snapshots.push([MLS_LABEL, { type: 'mls', version: 1, ...snapshot, namespaces: input.mls }]);
  for (const [label, payload] of snapshots) {
    const id = archiveId(key, label);
    await client.put(id, sealArchive(key, id, JSON.stringify(payload)));
    result.snapshots.push(label);
  }
  return result;
}

/**
 * Downloads and opens every archive of the account. Only what opens with this archive key, is stored under the id
 * its own content implies, carries a valid signature (events) and belongs to `pubkey` (snapshots, group messages)
 * comes back; the rest is counted in `skipped`. A download that fails is an error: retry the restore.
 */
export async function restoreHistory(client: ArchiveVaultClient, key: Uint8Array, opts: { pubkey: string; concurrency?: number }): Promise<RestoredHistory> {
  const metas = await client.listAll();
  const events = new Map<string, NostrEvent>();
  const messages = new Map<string, ArchivedGroupMessage>();
  const out: RestoredHistory = { events: [], groupMessages: [], archives: metas.length, skipped: 0, missing: 0 };
  let counted = 0;
  const snapshotOk = (p: Snapshot) => p.pubkey === opts.pubkey && Number.isSafeInteger(p.at) && (p.archives === undefined || Number.isSafeInteger(p.archives));
  const accept = (p: Payload, id: string): boolean => {
    switch (p?.type) {
      case 'event':
        return verifyEvent(p.event) && archiveId(key, eventLabel(p.event.id)) === id;
      case 'group-message':
        return p.pubkey === opts.pubkey && isGroupMessage(p.message) && archiveId(key, groupMessageLabel(p.message.groupId, p.message.rumorId)) === id;
      case 'ledger':
        return snapshotOk(p) && Array.isArray(p.outbox) && archiveId(key, LEDGER_LABEL) === id;
      case 'mls':
        return snapshotOk(p) && isMlsSnapshot(p.namespaces) && archiveId(key, MLS_LABEL) === id;
      default:
        return false;
    }
  };
  await runLimited(
    metas.map((meta) => async () => {
      const { envelope } = await client.get(meta.id);
      let p: Payload;
      try {
        p = JSON.parse(openArchiveText(key, meta.id, envelope)) as Payload;
      } catch {
        out.skipped++;
        return;
      }
      if (!accept(p, meta.id)) {
        out.skipped++;
        return;
      }
      if (p.type === 'event') events.set(p.event.id, p.event);
      else if (p.type === 'group-message') messages.set(groupMessageLabel(p.message.groupId, p.message.rumorId), p.message);
      else {
        counted = Math.max(counted, p.archives ?? 0);
        if (p.type === 'ledger') out.ledger = { at: p.at, outbox: p.outbox };
        else out.mls = { at: p.at, namespaces: p.namespaces };
      }
    }),
    opts.concurrency ?? 4,
  );
  out.missing = Math.max(0, counted - metas.length);
  out.events = [...events.values()].sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  out.groupMessages = [...messages.values()].sort((a, b) => a.createdAt - b.createdAt || (a.rumorId < b.rumorId ? -1 : 1));
  return out;
}
