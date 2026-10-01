/**
 * FR015-05: NIP-38 user status (kind 30315, addressable): a short text in the `general` slot that expires (NIP-40).
 * What this client publishes is narrower than NIP-38 allows, because a status is public metadata signed with the
 * persona's npub:
 * - always a NIP-40 `expiration`, at most STATUS_MAX_TTL_SECONDS after it is published, so an old status goes away on
 *   its own;
 * - no `p`, `e`, `a` or `r` tags and no links or mentions in the text: they would tie it to other people or places;
 * - only what the user writes and confirms (buildStatus takes the text): nothing derived from activity, no "online",
 *   "typing" or "last seen".
 * Clearing publishes an empty status that expires STATUS_CLEAR_TTL_SECONDS later. The statuses of others are read
 * defensively (parseStatus, statusVisible): the `general` slot only, sanitized text, never past their expiration nor
 * longer than STATUS_MAX_TTL_SECONDS after they were published; their tags are ignored.
 */
import { getTagValue, nowSeconds, type EventTemplate, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import { cleanProfileText, type LookupCompanion } from './profile';

export const USER_STATUS_KIND = 30_315;
/** The only NIP-38 slot this client publishes and reads (never `music`). */
export const STATUS_SLOT = 'general';
/** Longest status text, in characters. */
export const STATUS_MAX_CHARS = 100;
/** Longest lifetime of a status this client publishes, and longest a status is shown after it was published. */
export const STATUS_MAX_TTL_SECONDS = 24 * 3600;
/** Shortest lifetime of a status this client publishes. */
export const STATUS_MIN_TTL_SECONDS = 60;
/** Lifetime of the empty status that clears the previous one. */
export const STATUS_CLEAR_TTL_SECONDS = 3600;
/** A status dated further ahead than this (clock skew) is not shown. */
const MAX_SKEW_SECONDS = 900;

// Links (scheme://, www., the URI schemes clients turn into links) and Nostr references (nostr: URIs, bech32 entities).
const LINK = /[a-z][a-z0-9+.-]*:\/\/|\bwww\.|\b(?:nostr|mailto|tel|geo|lightning|bitcoin|magnet):|\b(?:npub|nprofile|note|nevent|naddr|nrelay)1[02-9ac-hj-np-z]{6,}/i;

export type StatusTextProblem = 'empty' | 'too-long' | 'link';

/** A status text this client does not publish; the client says why in its own words. */
export class StatusTextError extends Error {
  constructor(readonly problem: StatusTextProblem) {
    super(`status text refused: ${problem}`);
  }
}

/**
 * The text a status is published with, as the user confirms it: control, zero-width and bidirectional characters and
 * line breaks become spaces and whitespace is collapsed. Refused (StatusTextError) when longer than STATUS_MAX_CHARS or
 * when it carries a link or a mention. An empty text is '' (only clearing publishes it).
 */
export function statusText(value: string): string {
  const text = cleanProfileText(value, Number.POSITIVE_INFINITY) ?? '';
  if ([...text].length > STATUS_MAX_CHARS) throw new StatusTextError('too-long');
  if (LINK.test(text)) throw new StatusTextError('link');
  return text;
}

/**
 * The kind 30315 template of a status the user wrote, dated `createdAt` and expiring `ttlSeconds` later (from
 * STATUS_MIN_TTL_SECONDS to STATUS_MAX_TTL_SECONDS). Its only tags are the `general` slot and the NIP-40 expiration.
 */
export function buildStatus(text: string, ttlSeconds: number, createdAt = nowSeconds()): EventTemplate {
  const content = statusText(text);
  if (!content) throw new StatusTextError('empty');
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < STATUS_MIN_TTL_SECONDS || ttlSeconds > STATUS_MAX_TTL_SECONDS) throw new RangeError(`a status expires ${STATUS_MIN_TTL_SECONDS} to ${STATUS_MAX_TTL_SECONDS} seconds after it is published`);
  return { kind: USER_STATUS_KIND, content, tags: [['d', STATUS_SLOT], ['expiration', String(createdAt + ttlSeconds)]], created_at: createdAt };
}

/** The empty status that replaces, and so clears, the previous one (NIP-38); it expires STATUS_CLEAR_TTL_SECONDS later. */
export function buildStatusClear(createdAt = nowSeconds()): EventTemplate {
  return { kind: USER_STATUS_KIND, content: '', tags: [['d', STATUS_SLOT], ['expiration', String(createdAt + STATUS_CLEAR_TTL_SECONDS)]], created_at: createdAt };
}

/**
 * Why a template or event is not a status this client publishes, or undefined when it is one: kind 30315, the `general`
 * slot and one NIP-40 expiration as its only tags (so no `p`, `e`, `a` or `r`), an expiration STATUS_MIN_TTL_SECONDS to
 * STATUS_MAX_TTL_SECONDS after created_at, and a text that statusText leaves as it is (empty only to clear).
 */
export function statusTemplateProblem(t: Pick<EventTemplate, 'kind' | 'content' | 'tags' | 'created_at'>): string | undefined {
  if (t.kind !== USER_STATUS_KIND) return `kind ${t.kind} is not a status`;
  const tags = t.tags ?? [];
  const slot = tags.filter((x) => x[0] === 'd');
  const expiration = tags.filter((x) => x[0] === 'expiration');
  if (tags.length !== 2 || slot.length !== 1 || expiration.length !== 1 || slot[0]!.length !== 2 || slot[0]![1] !== STATUS_SLOT || expiration[0]!.length !== 2 || !/^[1-9]\d{0,14}$/.test(expiration[0]![1]!)) {
    return 'its only tags must be the general slot and one NIP-40 expiration';
  }
  if (t.created_at === undefined) return 'it needs created_at to bound its expiration';
  const ttl = Number(expiration[0]![1]) - t.created_at;
  if (ttl < STATUS_MIN_TTL_SECONDS || ttl > STATUS_MAX_TTL_SECONDS) return `it must expire ${STATUS_MIN_TTL_SECONDS} to ${STATUS_MAX_TTL_SECONDS} seconds after created_at`;
  try {
    if (statusText(t.content) !== t.content) return 'its text is not sanitized';
  } catch (e) {
    if (e instanceof StatusTextError) return `its text is refused: ${e.problem}`;
    throw e;
  }
  return undefined;
}

export interface UserStatus {
  pubkey: string;
  /** Sanitized, at most STATUS_MAX_CHARS characters; '' when the status was cleared. */
  text: string;
  createdAt: number;
  /** NIP-40 expiration, when the event has one (another client may publish a status without it). */
  expiresAt?: number;
  eventId: string;
}

/** The `general` status in a kind 30315 event, read defensively (any client may have published it), or undefined. */
export function parseStatus(evt: NostrEvent): UserStatus | undefined {
  if (evt.kind !== USER_STATUS_KIND || getTagValue(evt, 'd') !== STATUS_SLOT) return undefined;
  const exp = getTagValue(evt, 'expiration');
  const expiresAt = exp !== undefined && /^\d{1,15}$/.test(exp) ? Number(exp) : undefined;
  return { pubkey: evt.pubkey, text: cleanProfileText(evt.content, STATUS_MAX_CHARS) ?? '', createdAt: evt.created_at, ...(expiresAt !== undefined ? { expiresAt } : {}), eventId: evt.id };
}

/** Until when a status is shown (seconds): its expiration, and never past STATUS_MAX_TTL_SECONDS after it was published. */
export function statusShownUntil(s: UserStatus): number {
  return Math.min(s.expiresAt ?? Number.POSITIVE_INFINITY, s.createdAt + STATUS_MAX_TTL_SECONDS);
}

/** Whether a status is shown at `now`: not empty, not dated ahead, and before statusShownUntil. */
export function statusVisible(s: UserStatus, now = nowSeconds()): boolean {
  return s.text !== '' && s.createdAt <= now + MAX_SKEW_SECONDS && now < statusShownUntil(s);
}

/** The filter for the `general` statuses of these keys. */
export function statusFilter(authors: string[]): Filter {
  return { kinds: [USER_STATUS_KIND], authors, '#d': [STATUS_SLOT] };
}

/**
 * The statuses one persona learned, in memory and only for that persona (spec §14.1), the newest of each key. It asks
 * nothing by itself: a ProfileCache with it as companion fills it from the same request as the profiles (FR015-05),
 * and the client adds the persona's own status.
 */
export class StatusCache implements LookupCompanion {
  private readonly entries = new Map<string, UserStatus>();
  private readonly listeners = new Set<() => void>();

  constructor(private readonly now: () => number = nowSeconds) {}

  /** The status of a key to show now (statusVisible), if any. */
  get(pubkey: string): UserStatus | undefined {
    const s = this.entries.get(pubkey);
    return s && statusVisible(s, this.now()) ? s : undefined;
  }

  /** The newest status known of a key, even a cleared or expired one (the next one is dated after it). */
  latest(pubkey: string): UserStatus | undefined {
    return this.entries.get(pubkey);
  }

  /** Every status to show now, newest first. */
  visible(): UserStatus[] {
    const now = this.now();
    return [...this.entries.values()].filter((s) => statusVisible(s, now)).sort((a, b) => b.createdAt - a.createdAt);
  }

  /** Called whenever a status is added, replaced or forgotten. Returns the unsubscribe function. */
  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Keeps the event if it is a newer status of its key (NIP-01: the newest created_at, then the lowest id). */
  put(evt: NostrEvent): void {
    const next = parseStatus(evt);
    if (!next) return;
    const cur = this.entries.get(next.pubkey);
    if (cur && !(next.createdAt > cur.createdAt || (next.createdAt === cur.createdAt && next.eventId < cur.eventId))) return;
    this.entries.set(next.pubkey, next);
    this.emit();
  }

  /** LookupCompanion: what a profile request also asks for these keys. */
  filter(authors: string[]): Filter {
    return statusFilter(authors);
  }

  /**
   * LookupCompanion: what the request returned for these keys. A key without a status there has none to show any more:
   * its relays dropped it when it expired, or it never had one.
   */
  receive(events: NostrEvent[], authors: string[]): void {
    const seen = new Set<string>();
    for (const e of events) {
      const status = parseStatus(e);
      if (!status || !authors.includes(status.pubkey)) continue;
      this.put(e);
      seen.add(status.pubkey);
    }
    let forgot = false;
    for (const pk of authors) if (!seen.has(pk) && this.entries.delete(pk)) forgot = true;
    if (forgot) this.emit();
  }

  private emit() {
    for (const l of this.listeners) l();
  }
}
