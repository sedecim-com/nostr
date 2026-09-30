import { getTagValue, nip98, verifyEvent, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { mirrorPolicy, type SovereigntyConfig } from '@sedecim/profiles';
import type { PersonaCustody } from './vault';

/**
 * FR014-04: unread counts and search of NIP-29 channels through the operator's mirror (services/indexer), each query
 * signed by the persona (NIP-98), only where the deployment has a mirror and the persona's profile allows it
 * (mirrorPolicy). Where each channel was read up to stays sealed in the vault, per persona, and is never sent: the
 * mirror returns when each channel's newest messages were written and the web counts here those after that cursor.
 */

export type MirrorAvailability = { state: 'hidden' } | { state: 'disabled'; reason: string } | { state: 'available' };

/** Whether the channels view asks the mirror for this persona, and why not when the deployment has one. */
export function mirrorAvailability(mirror: string | undefined, config: SovereigntyConfig | undefined): MirrorAvailability {
  if (!mirror || !config) return { state: 'hidden' };
  const policy = mirrorPolicy(config);
  return policy.use ? { state: 'available' } : { state: 'disabled', reason: policy.statement };
}

/**
 * Signers that sign a NIP-98 request without asking anyone (this browser's key, the managed-signer): the counts
 * refresh on their own. A NIP-07 extension or a NIP-46 signer may ask to approve every signature, so there they
 * refresh only when the user asks.
 */
export function refreshesInBackground(custody: PersonaCustody): boolean {
  return custody === 'local' || custody === 'managed';
}

/** How often the counts refresh on their own while the channels view is open. */
export const MIRROR_REFRESH_MS = 60_000;
/** Message times asked per channel: a channel with more unread messages than this shows `100+`. */
export const MIRROR_UNREAD_LIMIT = 100;
/** The indexer answers for at most this many channels per request, with ids of up to 256 characters. */
const CHANNELS_PER_REQUEST = 100;
const MAX_CHANNEL_ID = 256;

export class MirrorError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function errorMessage(status: number, error: unknown): string {
  if (status === 401) return 'El mirror rechazó la firma NIP-98 de esta persona: revisa la hora de este dispositivo.';
  if (status === 429) return 'El mirror pide esperar: demasiadas consultas seguidas.';
  return `El mirror respondió ${status}${typeof error === 'string' && error ? `: ${error}` : ''}.`;
}

export interface MirrorHit {
  event: NostrEvent;
  channel: string;
}

export class MirrorClient {
  private readonly base: string;

  constructor(
    base: string,
    private readonly signer: Signer,
    private readonly doFetch: typeof fetch = (input, init) => fetch(input, init),
  ) {
    this.base = base.replace(/\/+$/, '');
  }

  private async get(path: string, params: Record<string, string>): Promise<unknown> {
    const url = new URL(`${this.base}${path}`);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    // The indexer checks the signed `u` against its public base URL plus the path and query as received: sign the
    // serialized URL and send exactly that string.
    const u = url.toString();
    const auth = await this.signer.signEvent(nip98.buildHttpAuthTemplate(u, 'GET'));
    let res: Response;
    try {
      res = await this.doFetch(u, { headers: { authorization: nip98.encodeAuthHeader(auth) } });
    } catch {
      throw new MirrorError(0, 'No se pudo contactar con el mirror.');
    }
    const body = (await res.json().catch(() => undefined)) as { error?: unknown } | undefined;
    if (!res.ok) throw new MirrorError(res.status, errorMessage(res.status, body?.error));
    return body;
  }

  /**
   * When the newest messages (of `kinds`) of each channel were written, newest first, without the persona's own or
   * deleted ones. Only the channels the persona may read are in the answer: those the relay lists it in and, in an
   * organization, those its policy allows (FR014-05, FR023-05).
   */
  async recent(channels: string[], opts: { kinds?: number[]; limit?: number } = {}): Promise<Map<string, number[]>> {
    const out = new Map<string, number[]>();
    // An id the indexer would refuse (a relay can publish any `d`) would fail the whole request: it is not asked.
    const asked = new Set(channels.filter((h) => h && h.length <= MAX_CHANNEL_ID && !h.includes(',')));
    const unique = [...asked];
    for (let i = 0; i < unique.length; i += CHANNELS_PER_REQUEST) {
      const params: Record<string, string> = { h: unique.slice(i, i + CHANNELS_PER_REQUEST).join(','), limit: String(opts.limit ?? MIRROR_UNREAD_LIMIT) };
      if (opts.kinds) params.kinds = opts.kinds.join(',');
      const body = (await this.get('/v1/unread/recent', params)) as { recent?: Record<string, unknown> } | undefined;
      for (const [h, times] of Object.entries(body?.recent ?? {})) {
        if (asked.has(h) && Array.isArray(times) && times.every((t) => Number.isSafeInteger(t))) out.set(h, times as number[]);
      }
    }
    return out;
  }

  /**
   * Channel messages that contain `text`, newest first, of the channels the persona may read. The mirror is a copy of
   * signed events: whatever does not verify, or is not a channel message, is dropped.
   */
  async search(text: string, opts: { kinds?: number[]; limit?: number } = {}): Promise<MirrorHit[]> {
    const params: Record<string, string> = { q: text.trim(), limit: String(opts.limit ?? 50) };
    if (opts.kinds) params.kinds = opts.kinds.join(',');
    const body = (await this.get('/v1/search', params)) as { events?: unknown[] } | undefined;
    return (body?.events ?? []).flatMap((e) => {
      if (!verifyEvent(e)) return [];
      const channel = getTagValue(e, 'h');
      return channel && (!opts.kinds || opts.kinds.includes(e.kind)) ? [{ event: e, channel }] : [];
    });
  }
}

export interface UnreadCount {
  count: number;
  /** The mirror's list for the channel was all unread: there may be more than `count`. */
  more: boolean;
}

/** Unread messages of each channel in `recent`: the message times after its cursor. */
export function countUnread(recent: Map<string, number[]>, cursors: Map<string, number>, limit = MIRROR_UNREAD_LIMIT): Map<string, UnreadCount> {
  const out = new Map<string, UnreadCount>();
  for (const [h, times] of recent) {
    const cursor = cursors.get(h) ?? Infinity;
    const count = times.filter((t) => t > cursor).length;
    out.set(h, { count, more: count > 0 && count === times.length && times.length >= limit });
  }
  return out;
}

export function unreadLabel(u: UnreadCount): string {
  return u.more ? `${u.count}+` : String(u.count);
}

const nowSec = () => Math.floor(Date.now() / 1000);

/**
 * FR014-04: up to when the persona has read each channel (the created_at of the newest message it was shown), sealed in
 * the vault with the rest of the persona's state and never sent: the mirror does not keep, or see, this cursor.
 */
export class ChannelReadState {
  private readonly col;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(store: EncryptedStore, personaId: string) {
    this.col = store.collection<number>(`chanread-${personaId}`);
  }

  /** One read-modify-write at a time: a cursor never moves back because two updates interleaved. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  /**
   * The cursors of `channels`. A channel this browser has never counted starts read at `now`: only what arrives later
   * counts (the cursor is not synced between browsers).
   */
  cursors(channels: string[], now = nowSec()): Promise<Map<string, number>> {
    return this.serial(async () => {
      const stored = new Map((await this.col.all()).map((e) => [e.id, e.value]));
      const out = new Map<string, number>();
      for (const h of new Set(channels)) {
        let cursor = stored.get(h);
        if (cursor === undefined) {
          cursor = now;
          await this.col.put(h, cursor);
        }
        out.set(h, cursor);
      }
      return out;
    });
  }

  /**
   * Marks `channel` read up to `until`: never backwards, and never past `now`, so a message dated in the future cannot
   * mark as read what arrives before that date.
   */
  markRead(channel: string, until: number, now = nowSec()): Promise<number> {
    return this.serial(async () => {
      const next = Math.max((await this.col.get(channel)) ?? 0, Math.min(until, now));
      await this.col.put(channel, next);
      return next;
    });
  }
}
