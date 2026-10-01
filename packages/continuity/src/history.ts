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
 *   copy is from and whether archives went missing since (expired by the retention, deleted, or lost).
 *
 * Labels never reach the vault: `archiveId` turns them into opaque ids with the archive key.
 *
 * PANEL-06: an event whose NIP-40 expiration passed is never archived nor restored, and a push deletes its archive
 * if the vault still holds it; so does a push for the events the caller names as deleted (`forget`). The format of the
 * archives does not change: they are deleted by id.
 */
import { eventExpiration, isExpired, verifyEvent, type NostrEvent } from '@sedecim/nostr-core';
import { ArchiveVaultError, type ArchiveVaultClient } from './client';
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
  /** PANEL-06: ids of events deleted by their author (e.g. the wraps of a deleted DM): never archived, and removed. */
  forget?: string[];
}

export interface HistoryArchiveResult {
  /**
   * `kept`: already in the vault (event archives never change). `invalid`: bad signature, not archived. PANEL-06:
   * `expired`: its NIP-40 expiration passed, not archived.
   */
  events: { uploaded: number; kept: number; invalid: number; expired: number };
  groupMessages: { uploaded: number; kept: number };
  /** Snapshots written in this push (`ledger`, `mls`). */
  snapshots: string[];
  /** PANEL-06: archives of expired or deleted events this push removed from the vault. */
  forgotten: number;
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
  /** Archives the latest snapshot counted that the vault no longer lists: expired (VAULT-05), deleted, or lost. */
  missing: number;
  /** PANEL-06: events (and ledger operations) left out because their NIP-40 expiration passed. */
  expired: number;
}

type Snapshot = { pubkey: string; at: number; archives?: number };
type Payload =
  | { type: 'event'; version: 1; event: NostrEvent }
  | { type: 'group-message'; version: 1; pubkey: string; message: ArchivedGroupMessage }
  | ({ type: 'ledger'; version: 1; outbox: unknown[] } & Snapshot)
  | ({ type: 'mls'; version: 1; namespaces: MlsSnapshot } & Snapshot);

const NAMESPACE = /^[a-z0-9-]+$/;
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * VAULT-04: seals one signed event as its `event:<id>` archive (the format `archiveHistory` writes and
 * `restoreHistory` reads) and stores it. Idempotent: the same event always lands on the same archive.
 */
export async function archiveEvent(client: ArchiveVaultClient, key: Uint8Array, event: NostrEvent): Promise<void> {
  if (!verifyEvent(event)) throw new Error('refusing to archive an event with an invalid signature');
  const id = archiveId(key, eventLabel(event.id));
  const payload: Payload = { type: 'event', version: 1, event };
  await client.put(id, sealArchive(key, id, JSON.stringify(payload)));
}

/**
 * PANEL-06: deletes the `event:<id>` archives of these events (e.g. the wraps of a message that expired or that its
 * author deleted), one request each. One the vault does not hold is skipped. Returns how many it deleted.
 */
export async function forgetArchivedEvents(client: ArchiveVaultClient, key: Uint8Array, eventIds: string[]): Promise<number> {
  let deleted = 0;
  for (const eventId of new Set(eventIds)) {
    try {
      const removed = await client.remove(archiveId(key, eventLabel(eventId)));
      deleted += removed;
    } catch (e) {
      if (!(e instanceof ArchiveVaultError && e.status === 404)) throw e;
    }
  }
  return deleted;
}

/**
 * PANEL-06: the archives this device still has to delete from the vault, in the persona's encrypted store (a
 * Collection): by event id, the unix second from which the deletion is due (the event's NIP-40 expiration; 0: now).
 */
export interface ArchiveForgetQueue {
  all(): Promise<Array<{ id: string; value: number }>>;
  put(eventId: string, due: number): Promise<void>;
  delete(eventId: string): Promise<void>;
}

/**
 * PANEL-06: remembers the expiring events this device stores in the vault (a push, or the copy of a send), so that
 * their archives are deleted when they expire, even if by then no relay serves them any more (and the next push
 * cannot see them).
 */
export async function scheduleArchiveExpiry(queue: ArchiveForgetQueue, events: NostrEvent[]): Promise<void> {
  for (const e of events) {
    const at = eventExpiration(e);
    if (at !== undefined) await queue.put(e.id, at);
  }
}

/**
 * PANEL-06: deletes from the vault the archives of `eventIds` and of every queued event due at `nowSeconds`. What the
 * vault confirms leaves the queue. What it cannot delete now (no vault at hand, `vault` undefined, or one that does not
 * answer) stays queued as due now, for a later run: the queued events, and `eventIds` too unless `remember` is false.
 * `remember: false` is for events that may never have reached the vault, as an expired message: whatever of it this
 * device stored there was queued then (scheduleArchiveExpiry), and the queue does not grow with every message that
 * expires. `next`: the soonest deletion still ahead.
 */
export async function forgetDueArchives(
  vault: { client: ArchiveVaultClient; key: Uint8Array } | undefined,
  queue: ArchiveForgetQueue,
  eventIds: string[],
  nowSeconds: number,
  opts: { remember?: boolean } = {},
): Promise<{ deleted: number; queued: number; next?: number; error?: string }> {
  const remember = opts.remember !== false;
  const entries = await queue.all();
  const inQueue = new Set(entries.map((e) => e.id));
  const due = new Set([...(vault || remember ? eventIds : []), ...entries.filter((e) => e.value <= nowSeconds).map((e) => e.id)]);
  const ahead = entries.filter((e) => e.value > nowSeconds && !due.has(e.id));
  const later = ahead.length ? { next: Math.min(...ahead.map((e) => e.value)) } : {};
  const pending = [...due].filter((id) => remember || inQueue.has(id));
  const requeue = async () => {
    for (const id of pending) await queue.put(id, 0);
  };
  if (!due.size) return { deleted: 0, queued: ahead.length, ...later };
  if (!vault) {
    await requeue();
    return { deleted: 0, queued: ahead.length + pending.length, ...later };
  }
  try {
    const deleted = await forgetArchivedEvents(vault.client, vault.key, [...due]);
    for (const id of due) if (inQueue.has(id)) await queue.delete(id);
    return { deleted, queued: ahead.length, ...later };
  } catch (e) {
    await requeue();
    return { deleted: 0, queued: ahead.length + pending.length, ...later, error: (e as Error).message };
  }
}

/**
 * Whether a restored event goes back to the persona's relays: every one does except a gift wrap addressed to
 * someone else (a DM or receipt sent to another person, archived with each send since VAULT-04), whose place is
 * that person's DM relays. It stays in the vault and in the ledger.
 */
export function belongsOnPersonaRelays(event: NostrEvent, pubkey: string): boolean {
  return event.kind !== 1059 || event.tags.some((t) => t[0] === 'p' && t[1] === pubkey);
}

/** VAULT-05: the portable export of a persona's vault (`vaultExport`), an open JSON format. */
export const VAULT_EXPORT_FORMAT = 'sedecim-vault-export';

export interface VaultExport {
  format: typeof VAULT_EXPORT_FORMAT;
  version: 1;
  /** Hex pubkey of the persona. */
  pubkey: string;
  exportedAt: string;
  /** Signed NIP-01 events (only their NIP-01 fields), oldest first: any Nostr client can verify and publish them. */
  events: NostrEvent[];
  /** Decrypted Marmot messages (rumors, unsigned): readable text. */
  groupMessages: ArchivedGroupMessage[];
  /** The delivery ledger (outbox records) of the latest snapshot. */
  ledger: unknown[];
}

/**
 * VAULT-05: what a persona takes out of the vault, in an open format that needs neither the vault nor its archive
 * key: the verified events, the group messages and the ledger. The MLS state is left out on purpose: it holds the
 * group secrets of a device and only works inside a client.
 */
export function vaultExport(restored: RestoredHistory, pubkey: string, now: () => number = Date.now): VaultExport {
  return {
    format: VAULT_EXPORT_FORMAT,
    version: 1,
    pubkey,
    exportedAt: new Date(now()).toISOString(),
    events: restored.events.map((e) => ({ id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig })),
    groupMessages: restored.groupMessages,
    ledger: restored.ledger?.outbox ?? [],
  };
}

/**
 * Reads a vault export back (e.g. to publish its events again). Only verified events and well-formed group messages
 * come out; the others are counted in `invalid`.
 */
export function parseVaultExport(text: string): { export: VaultExport; invalid: number } {
  let raw: Partial<VaultExport>;
  try {
    raw = JSON.parse(text) as Partial<VaultExport>;
  } catch {
    throw new Error('not a vault export: malformed JSON');
  }
  if (!raw || raw.format !== VAULT_EXPORT_FORMAT || raw.version !== 1 || typeof raw.pubkey !== 'string' || !HEX64.test(raw.pubkey)) throw new Error('not a vault export (format sedecim-vault-export, version 1)');
  const events = Array.isArray(raw.events) ? raw.events : [];
  const messages = Array.isArray(raw.groupMessages) ? raw.groupMessages : [];
  const okEvents = events.filter((e) => verifyEvent(e));
  const okMessages = messages.filter(isGroupMessage);
  return {
    export: { format: VAULT_EXPORT_FORMAT, version: 1, pubkey: raw.pubkey, exportedAt: String(raw.exportedAt ?? ''), events: okEvents, groupMessages: okMessages, ledger: Array.isArray(raw.ledger) ? raw.ledger : [] },
    invalid: events.length - okEvents.length + (messages.length - okMessages.length),
  };
}

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

/** PANEL-06: the signed event a ledger entry carries (an outbox record, or a `{ id, value }` store entry of the CLI). */
function ledgerEvent(entry: unknown): NostrEvent | undefined {
  const rec = entry && typeof entry === 'object' && 'value' in entry ? (entry as { value: unknown }).value : entry;
  const event = (rec as { event?: unknown } | null | undefined)?.event as NostrEvent | undefined;
  return event && typeof event === 'object' && Array.isArray(event.tags) ? event : undefined;
}

/**
 * Seals and uploads the persona's history. Event and group-message archives are written once (a retry or the
 * next push skips what the vault already holds); the ledger and MLS snapshots replace their previous copy.
 * PANEL-06: expired events (NIP-40) and those in `input.forget` are not uploaded, and their archives are deleted.
 */
export async function archiveHistory(client: ArchiveVaultClient, key: Uint8Array, input: HistoryArchiveInput, opts: { concurrency?: number; now?: () => number } = {}): Promise<HistoryArchiveResult> {
  const present = new Set((await client.listAll()).map((a) => a.id));
  const result: HistoryArchiveResult = { events: { uploaded: 0, kept: 0, invalid: 0, expired: 0 }, groupMessages: { uploaded: 0, kept: 0 }, snapshots: [], forgotten: 0 };
  const at = (opts.now ?? Date.now)();
  const nowSeconds = Math.floor(at / 1000);
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
  const forget = new Set(input.forget ?? []);
  const drop = new Set([...forget].map((eventId) => archiveId(key, eventLabel(eventId))).filter((id) => present.has(id)));

  const seenEvents = new Set<string>();
  for (const event of input.events) {
    if (seenEvents.has(event.id)) continue;
    seenEvents.add(event.id);
    if (!verifyEvent(event)) {
      result.events.invalid++;
      continue;
    }
    const id = archiveId(key, eventLabel(event.id));
    if (forget.has(event.id)) continue;
    if (isExpired(event, nowSeconds)) {
      result.events.expired++;
      if (present.has(id)) drop.add(id);
      continue;
    }
    if (present.has(id)) result.events.kept++;
    else put(eventLabel(event.id), { type: 'event', version: 1, event }, () => result.events.uploaded++);
  }
  for (const id of drop) {
    jobs.push(async () => {
      try {
        // Read after the await: jobs run concurrently, and `+= await` would add to a stale count.
        const removed = await client.remove(id);
        result.forgotten += removed;
      } catch (e) {
        if (!(e instanceof ArchiveVaultError && e.status === 404)) throw e;
      }
      held.delete(id);
    });
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

  // What the account holds once this push ends, snapshots included.
  if (input.ledger) held.add(archiveId(key, LEDGER_LABEL));
  if (input.mls) held.add(archiveId(key, MLS_LABEL));
  const snapshot: Snapshot = { pubkey: input.pubkey, at, archives: held.size };
  const snapshots: Array<[string, Payload]> = [];
  // PANEL-06: the operations of expired or deleted events stay out of the ledger too.
  const current = (entry: unknown) => {
    const event = ledgerEvent(entry);
    return !event || (!forget.has(event.id) && !isExpired(event, nowSeconds));
  };
  if (input.ledger) snapshots.push([LEDGER_LABEL, { type: 'ledger', version: 1, ...snapshot, outbox: input.ledger.filter(current) }]);
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
 * comes back; the rest is counted in `skipped`. `missing` compares the archives the last snapshot counted with the
 * listing, which listAll() only accepts without repeated entries (IR-2026-10-04): an operator that pads it to hide a
 * removed archive turns the gap into `skipped` archives, which the restore also reports. A download that fails is an
 * error: retry the restore. PANEL-06: an event, or a ledger operation, whose NIP-40 expiration passed stays out.
 */
export async function restoreHistory(client: ArchiveVaultClient, key: Uint8Array, opts: { pubkey: string; concurrency?: number; now?: () => number }): Promise<RestoredHistory> {
  const metas = await client.listAll();
  const events = new Map<string, NostrEvent>();
  const messages = new Map<string, ArchivedGroupMessage>();
  const out: RestoredHistory = { events: [], groupMessages: [], archives: metas.length, skipped: 0, missing: 0, expired: 0 };
  const nowSeconds = Math.floor((opts.now ?? Date.now)() / 1000);
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
      if (p.type === 'event') {
        if (isExpired(p.event, nowSeconds)) out.expired++;
        else events.set(p.event.id, p.event);
      } else if (p.type === 'group-message') messages.set(groupMessageLabel(p.message.groupId, p.message.rumorId), p.message);
      else {
        counted = Math.max(counted, p.archives ?? 0);
        if (p.type === 'ledger') {
          const outbox = p.outbox.filter((e) => {
            const event = ledgerEvent(e);
            return !event || !isExpired(event, nowSeconds);
          });
          out.expired += p.outbox.length - outbox.length;
          out.ledger = { at: p.at, outbox };
        } else out.mls = { at: p.at, namespaces: p.namespaces };
      }
    }),
    opts.concurrency ?? 4,
  );
  out.missing = Math.max(0, counted - metas.length);
  out.events = [...events.values()].sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  out.groupMessages = [...messages.values()].sort((a, b) => a.createdAt - b.createdAt || (a.rumorId < b.rumorId ? -1 : 1));
  return out;
}
