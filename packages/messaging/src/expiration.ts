/**
 * PANEL-06 (§12.2): disappearing direct messages (NIP-17 with an NIP-40 `expiration`) and the deletion of one's own
 * (NIP-17 with a gift-wrapped NIP-09 kind 5), as this client sends, reads and forgets them. Both are requests: a relay
 * that ignores NIP-40 keeps serving the wraps, and a contact's client that ignores the deletion keeps showing the
 * message. What this client controls is what it shows and what it keeps.
 */
import { createRumor, eventExpiration, getTagValues, type NostrEvent, type Rumor } from '@sedecim/nostr-core';
import type { Unwrapped } from './nip59';
import type { DmOperation } from './operations';

/** An expiration is rounded up to a UTC day. */
export const EXPIRATION_ROUNDING_SECONDS = 86_400;

/**
 * The `expiration` of a message sent at `nowSeconds` that asks to be kept `days`: the first UTC midnight at or after
 * `now + days`. The relay reads it on the gift wrap. An exact `now + days`, with `days` from a short list, would give
 * away the send time that NIP-59 hides by backdating `created_at`; rounded, it tells the day, the same for every
 * message of that length sent that day. A message may last up to a day longer than asked.
 */
export function roundedExpiration(days: number, nowSeconds: number): number {
  if (!Number.isSafeInteger(days) || days <= 0) throw new Error('days must be a positive integer');
  return Math.ceil((nowSeconds + days * 86_400) / EXPIRATION_ROUNDING_SECONDS) * EXPIRATION_ROUNDING_SECONDS;
}

/** A message's expiration as it arrived: the sooner of its gift wrap's and its seal's (NIP-17 sets it on both). */
export function unwrappedExpiration(u: Pick<Unwrapped, 'wrap' | 'seal'>): number | undefined {
  const at = [eventExpiration(u.wrap), eventExpiration(u.seal)].filter((x): x is number => x !== undefined);
  return at.length ? Math.min(...at) : undefined;
}

/** Whether a message had expired at `nowSeconds` (NIP-40: never shown, answered or kept from then on). */
export function isUnwrappedExpired(u: Pick<Unwrapped, 'wrap' | 'seal'>, nowSeconds: number): boolean {
  const at = unwrappedExpiration(u);
  return at !== undefined && at <= nowSeconds;
}

/** NIP-09 deletion, which NIP-17 gift-wraps to the conversation to delete one of its messages. */
export const DM_DELETION_KIND = 5;

const HEX64 = /^[0-9a-f]{64}$/;

/** The kind 5 rumor asking the recipients of `target`, a message of its author, to delete it (`e`, `k` and its `p`s). */
export function dmDeletionRumor(target: Rumor): Rumor {
  const tags = [['e', target.id], ['k', String(target.kind)], ...getTagValues(target, 'p').map((p) => ['p', p])];
  return createRumor({ kind: DM_DELETION_KIND, content: '', tags }, target.pubkey);
}

/** The message ids a deletion rumor names. */
export function deletedMessageIds(rumor: Rumor): string[] {
  return rumor.kind === DM_DELETION_KIND ? getTagValues(rumor, 'e').filter((id) => HEX64.test(id)) : [];
}

/** Deleting a message someone else wrote: refused before anything is signed or sent. */
export class NotYourMessageError extends Error {
  constructor(readonly rumorId: string) {
    super('solo puedes borrar los mensajes que escribiste tú: este lo escribió otra persona');
    this.name = 'NotYourMessageError';
  }
}

/**
 * What remembers the messages deleted by their author, in the persona's encrypted store: `rumor:<id>:<author>` for
 * the message, `wrap:<id>` for each gift wrap of it this device saw (so that a vault push leaves it out).
 */
export interface TombstoneStore {
  get(key: string): Promise<boolean | undefined>;
  put(key: string, value: boolean): Promise<void>;
}

export const rumorTombstone = (rumorId: string, author: string) => `rumor:${rumorId}:${author}`;
export const wrapTombstone = (wrapId: string) => `wrap:${wrapId}`;

/** The gift wraps a tombstone store remembers as deleted (from its entries, e.g. a Collection's `all()`). */
export function tombstonedWraps(entries: Array<{ id: string }>): string[] {
  return entries.filter((e) => e.id.startsWith('wrap:')).map((e) => e.id.slice('wrap:'.length));
}

/** Where this device keeps copies of the persona's DMs (structural: encrypted-store collections and a DeliveryEngine). */
export interface DmCopies {
  /** FR011-05: the sent operations (their rumor, in clear inside the encrypted store). */
  operations: { all(): Promise<Array<{ id: string; value: DmOperation }>>; delete(id: string): Promise<void> };
  /** The outbox: each wrap of a message is a record whose `groupId` is the message's rumor id. */
  outbox: { list(): Promise<Array<{ opId: string; groupId?: string; event?: NostrEvent }>>; forget(opId: string): Promise<void> };
  tombstones?: TombstoneStore;
}

export interface ForgottenCopies {
  /** Sent operations deleted (each held a message's rumor). */
  operations: number;
  /** Outbox records forgotten: wraps of the messages, and receipts or deletions that expired with them. */
  outbox: number;
  /** The gift wraps those records held: their Continuity Vault archives go next (continuity's forgetArchivedEvents). */
  wrapIds: string[];
}

/**
 * PANEL-06: forgets what this device keeps of the messages that expired at `nowSeconds`: their sent operation and
 * every outbox record whose event carries an expiration that passed (the wraps, and receipts or deletions that expired
 * with them), even if a relay never took it. `next`: the soonest expiration of what is left, to run it again then.
 */
export async function purgeExpiredCopies(copies: DmCopies, nowSeconds: number): Promise<ForgottenCopies & { next?: number }> {
  const out: ForgottenCopies & { next?: number } = { operations: 0, outbox: 0, wrapIds: [] };
  const later = (at: number) => (out.next = out.next === undefined ? at : Math.min(out.next, at));
  for (const { id, value } of await copies.operations.all()) {
    if (value.expiration === undefined) continue;
    if (value.expiration > nowSeconds) later(value.expiration);
    else {
      await copies.operations.delete(id);
      out.operations++;
    }
  }
  for (const rec of await copies.outbox.list()) {
    const at = rec.event ? eventExpiration(rec.event) : undefined;
    if (at === undefined) continue;
    if (at > nowSeconds) later(at);
    else {
      await copies.outbox.forget(rec.opId);
      out.outbox++;
      out.wrapIds.push(rec.event!.id);
    }
  }
  return out;
}

/**
 * PANEL-06: forgets what this device keeps of messages their author deleted (the persona's own, or a contact's whose
 * deletion arrived): their sent operation and the outbox records of their wraps. It remembers them as deleted
 * (tombstones), with the wraps it saw (`wrapIds`, e.g. the one the inbox opened) and those of the outbox.
 */
export async function forgetMessageCopies(copies: DmCopies, messages: Array<{ rumorId: string; author: string; wrapIds?: string[] }>): Promise<ForgottenCopies> {
  const ids = new Set(messages.map((m) => m.rumorId));
  const out: ForgottenCopies = { operations: 0, outbox: 0, wrapIds: messages.flatMap((m) => m.wrapIds ?? []) };
  for (const { id, value } of await copies.operations.all()) {
    if (!ids.has(value.rumor.id)) continue;
    await copies.operations.delete(id);
    out.operations++;
  }
  for (const rec of await copies.outbox.list()) {
    if (!rec.groupId || !ids.has(rec.groupId)) continue;
    await copies.outbox.forget(rec.opId);
    out.outbox++;
    if (rec.event) out.wrapIds.push(rec.event.id);
  }
  out.wrapIds = [...new Set(out.wrapIds)];
  for (const m of messages) await copies.tombstones?.put(rumorTombstone(m.rumorId, m.author), true);
  for (const w of out.wrapIds) await copies.tombstones?.put(wrapTombstone(w), true);
  return out;
}
