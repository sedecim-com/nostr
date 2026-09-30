import { getTagValue, getTagValues, isAddressableKind, isReplaceableKind, eventAddress, supersedes, type NostrEvent } from '@sedecim/nostr-core';
import type { Pool } from '@sedecim/service-kit';
import { plainCodec, type EventCodec, type StoredEvent } from './codec';

export type SensitivityClass = 'ciphertext' | 'channel' | 'public' | 'protocol';

export function classify(evt: NostrEvent): SensitivityClass {
  if (evt.kind === 1059 || evt.kind === 13 || evt.kind === 445 || evt.kind === 444 || evt.kind === 24133) return 'ciphertext';
  if (getTagValue(evt, 'h')) return 'channel';
  if (evt.kind === 22242 || evt.kind === 27235 || evt.kind === 24242) return 'protocol';
  return 'public';
}

/**
 * Channel message kinds (NIP-29 chat, threads, replies, NIP-22 comments): the only kinds counted as
 * unread and the only ones searchable. Gift wraps, seals, MLS and anything classified 'ciphertext' never are.
 */
export const CHANNEL_MESSAGE_KINDS = [9, 10, 11, 12, 1111];

export interface SearchQuery {
  /** Case-insensitive substring over the plaintext `content`. */
  text: string;
  h?: string[];
  /** Narrows CHANNEL_MESSAGE_KINDS; other kinds are dropped. */
  kinds?: number[];
  limit?: number;
}

/** A sealed mirror cannot search in SQL: it decrypts and scans at most this many newest candidates. */
export const SEALED_SEARCH_SCAN = 5000;

function searchableKinds(kinds?: number[]): number[] {
  return kinds ? CHANNEL_MESSAGE_KINDS.filter((k) => kinds.includes(k)) : CHANNEL_MESSAGE_KINDS;
}

function contentMatches(evt: NostrEvent, text: string): boolean {
  return evt.content.toLocaleLowerCase().includes(text.toLocaleLowerCase());
}

export interface EventQuery {
  ids?: string[];
  kinds?: number[];
  authors?: string[];
  h?: string;
  p?: string;
  since?: number;
  until?: number;
  limit?: number;
  includeDeleted?: boolean;
}

export interface MirroredEvent {
  event: NostrEvent;
  firstSeenAt: number;
  lastSeenAt: number;
  relays: string[];
  sensitivity: SensitivityClass;
  deleted: boolean;
}

export interface EventRepository {
  /** Stores the canonical event unchanged; returns true if it was new. */
  upsert(evt: NostrEvent, relay: string, communityId?: string): Promise<boolean>;
  tombstone(ids: string[], byPubkey: string): Promise<number>;
  query(q: EventQuery): Promise<MirroredEvent[]>;
  get(id: string): Promise<MirroredEvent | undefined>;
  stats(): Promise<{ events: number; byClass: Record<string, number> }>;
  /** Per-reader read cursor for a channel: messages with created_at <= until are read. Never moves back. */
  setReadCursor(reader: string, h: string, until: number): Promise<number>;
  readCursors(reader: string, hs: string[]): Promise<Record<string, number>>;
  /** Channel messages newer than the reader's cursor, excluding the reader's own and deleted ones. */
  unreadCounts(reader: string, hs: string[]): Promise<Record<string, number>>;
  /**
   * FR014-04: per channel, the created_at of its newest `limit` channel messages (CHANNEL_MESSAGE_KINDS, narrowed by
   * `kinds`) that are neither the reader's own nor deleted, newest first. A client counts its unread messages against
   * a read cursor it keeps to itself. Index columns only (works on a sealed mirror).
   */
  recentMessageTimes(reader: string, hs: string[], opts: { kinds?: number[]; limit: number }): Promise<Record<string, number[]>>;
  /** Plaintext search over channel messages only (CHANNEL_MESSAGE_KINDS), newest first. */
  search(q: SearchQuery): Promise<MirroredEvent[]>;
  /** Retention (FR023-08): hard-deletes mirrored events older than `before`; returns how many. */
  purge(q: PurgeQuery): Promise<number>;
  /**
   * FR023-12: versions of replaceable/addressable events that a newer one superseded, kept (with `keepSuperseded`)
   * so that a legal hold covers them too. Never part of a canonical read.
   */
  superseded(): Promise<Array<{ event: NostrEvent; supersededBy: string }>>;
  /**
   * FR023-12: deletes the superseded versions no legal hold covers. `held` are resource ids, matched as a channel
   * (`h` tag, or the `d` of its NIP-29 state events 39000-39003) and as a workspace (community). Returns how many.
   */
  purgeSuperseded(held: string[]): Promise<number>;
  /**
   * FR014-05: channels whose NIP-29 access lists (39001 admins, 39002 members) signed by one of `authorities`
   * name `reader`. Only the head of each list is stored, so removing a member revokes the access.
   */
  memberChannels(reader: string, authorities: string[]): Promise<string[]>;
  /** FR014-05: remembers a NIP-29 deletion (kind 9005) until it can be applied. */
  recordModeration(d: ModerationDeletion): Promise<void>;
  /**
   * FR014-05: applies the pending deletions of channel `h` (only those of `targetId` when given) whose target is
   * already mirrored in the same channel and whose actor is its author or an admin in a 39001 signed by one of
   * `authorities`. Returns how many targets were hidden.
   */
  applyModeration(h: string, authorities: string[], targetId?: string): Promise<number>;
}

export interface ModerationDeletion {
  deletionId: string;
  targetId: string;
  h: string;
  actor: string;
}

const ACCESS_KINDS = [39001, 39002];

/** Events of one channel (`h`) or one community created before `before` (unix seconds), minus the exceptions. */
export type PurgeQuery = { before: number } & ({ h: string; exceptCommunities: string[] } | { community: string; exceptH: string[] });

/** FR023-12: repository options. */
export interface EventRepositoryOptions {
  /**
   * Keep what a newer version of a replaceable/addressable event supersedes (see `superseded`) instead of deleting it:
   * institutional mode, where a legal hold may cover it. `purgeSuperseded` then deletes what no hold covers.
   */
  keepSuperseded?: boolean;
}

/** NIP-29 group state events (metadata, admins, members, roles): their `d` names the channel. */
const GROUP_STATE_KINDS = [39000, 39001, 39002, 39003];

/** Whether a superseded version belongs to one of the `held` resources (FR023-12). */
function heldBy(held: string[], e: NostrEvent, communityId?: string): boolean {
  const h = getTagValue(e, 'h');
  return (!!h && held.includes(h)) || (!!communityId && held.includes(communityId)) || (GROUP_STATE_KINDS.includes(e.kind) && held.includes(getTagValue(e, 'd') ?? ''));
}

function matches(q: EventQuery, m: MirroredEvent): boolean {
  const e = m.event;
  if (!q.includeDeleted && m.deleted) return false;
  if (q.ids && !q.ids.includes(e.id)) return false;
  if (q.kinds && !q.kinds.includes(e.kind)) return false;
  if (q.authors && !q.authors.includes(e.pubkey)) return false;
  if (q.h && getTagValue(e, 'h') !== q.h) return false;
  if (q.p && !getTagValues(e, 'p').includes(q.p)) return false;
  if (q.since !== undefined && e.created_at < q.since) return false;
  if (q.until !== undefined && e.created_at > q.until) return false;
  return true;
}

export class MemoryEventRepository implements EventRepository {
  private readonly rows = new Map<string, MirroredEvent & { stored: StoredEvent; communityId?: string }>();
  private readonly cursors = new Map<string, number>();
  private readonly moderation = new Map<string, ModerationDeletion & { applied: boolean }>();
  private readonly archived = new Map<string, { stored: StoredEvent; event: NostrEvent; communityId?: string; supersededBy: string }>();
  constructor(
    private readonly codec: EventCodec = plainCodec,
    private readonly opts: EventRepositoryOptions = {},
  ) {}

  async upsert(evt: NostrEvent, relay: string, communityId?: string): Promise<boolean> {
    const now = Date.now();
    const cur = this.rows.get(evt.id);
    if (cur) {
      cur.lastSeenAt = now;
      if (!cur.relays.includes(relay)) cur.relays.push(relay);
      return false;
    }
    if (isReplaceableKind(evt.kind) || isAddressableKind(evt.kind)) {
      // Only the NIP-01 head of an address is kept (same outcome as the Postgres repository under races).
      const addr = eventAddress(evt);
      const older: string[] = [];
      for (const [id, r] of this.rows) {
        if (r.deleted) continue;
        const re = this.codec.decode(r.stored, id);
        if (eventAddress(re) !== addr) continue;
        if (!supersedes(evt, re)) {
          // FR023-12: a version older than the head that arrives after it is kept as superseded too.
          if (this.opts.keepSuperseded) this.archived.set(evt.id, { stored: this.codec.encode(evt), event: evt, supersededBy: id, ...(communityId ? { communityId } : {}) });
          return false;
        }
        older.push(id);
      }
      for (const id of older) {
        const r = this.rows.get(id)!;
        if (this.opts.keepSuperseded) this.archived.set(id, { stored: r.stored, event: r.event, supersededBy: evt.id, ...(r.communityId ? { communityId: r.communityId } : {}) });
        this.rows.delete(id);
      }
    }
    this.rows.set(evt.id, { event: evt, stored: this.codec.encode(evt), firstSeenAt: now, lastSeenAt: now, relays: [relay], sensitivity: classify(evt), deleted: false, ...(communityId ? { communityId } : {}) });
    return true;
  }

  async tombstone(ids: string[], byPubkey: string): Promise<number> {
    let n = 0;
    for (const id of ids) {
      const r = this.rows.get(id);
      if (r && r.event.pubkey === byPubkey && !r.deleted) {
        r.deleted = true;
        n++;
      }
    }
    return n;
  }

  async query(q: EventQuery): Promise<MirroredEvent[]> {
    const out = [...this.rows.values()].filter((m) => matches(q, m));
    out.sort((a, b) => b.event.created_at - a.event.created_at);
    return out.slice(0, q.limit ?? 500).map(({ stored: _s, communityId: _c, ...m }) => ({ ...m, event: this.codec.decode(_s, m.event.id) }));
  }

  async get(id: string) {
    return (await this.query({ ids: [id], includeDeleted: true }))[0];
  }

  async stats() {
    const byClass: Record<string, number> = {};
    for (const r of this.rows.values()) byClass[r.sensitivity] = (byClass[r.sensitivity] ?? 0) + 1;
    return { events: this.rows.size, byClass };
  }

  async setReadCursor(reader: string, h: string, until: number): Promise<number> {
    const key = `${reader}|${h}`;
    const v = Math.max(this.cursors.get(key) ?? 0, until);
    this.cursors.set(key, v);
    return v;
  }

  async readCursors(reader: string, hs: string[]): Promise<Record<string, number>> {
    return Object.fromEntries(hs.map((h) => [h, this.cursors.get(`${reader}|${h}`) ?? 0]));
  }

  async unreadCounts(reader: string, hs: string[]): Promise<Record<string, number>> {
    const cursors = await this.readCursors(reader, hs);
    const out: Record<string, number> = Object.fromEntries(hs.map((h) => [h, 0]));
    for (const r of this.rows.values()) {
      const h = getTagValue(r.event, 'h');
      if (r.deleted || !h || !(h in out) || !CHANNEL_MESSAGE_KINDS.includes(r.event.kind) || r.event.pubkey === reader) continue;
      if (r.event.created_at > cursors[h]!) out[h]!++;
    }
    return out;
  }

  async recentMessageTimes(reader: string, hs: string[], opts: { kinds?: number[]; limit: number }): Promise<Record<string, number[]>> {
    const kinds = searchableKinds(opts.kinds);
    const byH = new Map(hs.map((h) => [h, [] as number[]]));
    for (const r of this.rows.values()) {
      const times = byH.get(getTagValue(r.event, 'h') ?? '');
      if (!times || r.deleted || !kinds.includes(r.event.kind) || r.event.pubkey === reader) continue;
      times.push(r.event.created_at);
    }
    return Object.fromEntries([...byH].map(([h, times]) => [h, times.sort((a, b) => b - a).slice(0, opts.limit)]));
  }

  async search(q: SearchQuery): Promise<MirroredEvent[]> {
    const kinds = searchableKinds(q.kinds);
    const candidates = (await this.query({ kinds, limit: Number.MAX_SAFE_INTEGER })).filter(
      (m) => m.sensitivity === 'channel' && (!q.h?.length || q.h.includes(getTagValue(m.event, 'h')!)),
    );
    return candidates.filter((m) => contentMatches(m.event, q.text)).slice(0, q.limit ?? 50);
  }

  async memberChannels(reader: string, authorities: string[]): Promise<string[]> {
    const out = new Set<string>();
    for (const r of this.rows.values()) {
      const e = r.event;
      if (r.deleted || !ACCESS_KINDS.includes(e.kind) || !authorities.includes(e.pubkey) || !getTagValues(e, 'p').includes(reader)) continue;
      const d = getTagValue(e, 'd');
      if (d) out.add(d);
    }
    return [...out];
  }

  async recordModeration(d: ModerationDeletion): Promise<void> {
    const key = `${d.deletionId}|${d.targetId}`;
    if (!this.moderation.has(key)) this.moderation.set(key, { ...d, applied: false });
  }

  async applyModeration(h: string, authorities: string[], targetId?: string): Promise<number> {
    const admins = new Set<string>();
    for (const r of this.rows.values()) {
      if (!r.deleted && r.event.kind === 39001 && authorities.includes(r.event.pubkey) && getTagValue(r.event, 'd') === h) getTagValues(r.event, 'p').forEach((p) => admins.add(p));
    }
    let n = 0;
    for (const m of this.moderation.values()) {
      if (m.applied || m.h !== h || (targetId && m.targetId !== targetId)) continue;
      const t = this.rows.get(m.targetId);
      if (!t || getTagValue(t.event, 'h') !== h || (t.event.pubkey !== m.actor && !admins.has(m.actor))) continue;
      m.applied = true;
      if (!t.deleted) {
        t.deleted = true;
        n++;
      }
    }
    return n;
  }

  async purge(q: PurgeQuery): Promise<number> {
    let n = 0;
    for (const [id, r] of this.rows) {
      if (r.event.created_at >= q.before) continue;
      const h = getTagValue(r.event, 'h');
      const hit = 'h' in q ? h === q.h && !(r.communityId && q.exceptCommunities.includes(r.communityId)) : r.communityId === q.community && !(h && q.exceptH.includes(h));
      if (hit && this.rows.delete(id)) n++;
    }
    return n;
  }

  async superseded() {
    return [...this.archived.entries()].map(([id, a]) => ({ event: this.codec.decode(a.stored, id), supersededBy: a.supersededBy }));
  }

  async purgeSuperseded(held: string[]) {
    let n = 0;
    for (const [id, a] of this.archived) if (!heldBy(held, a.event, a.communityId) && this.archived.delete(id)) n++;
    return n;
  }
}

interface PgEventRow {
  event_id: string;
  raw_event_json: NostrEvent | null;
  encrypted_payload: Buffer | null;
  seal_version: number | null;
  first_seen_at: string;
  last_seen_at: string;
  relays: string[];
  sensitivity_class: SensitivityClass;
  deleted_tombstone: boolean;
}

export class PgEventRepository implements EventRepository {
  constructor(
    private readonly pool: Pool,
    private readonly codec: EventCodec = plainCodec,
    private readonly opts: EventRepositoryOptions = {},
  ) {}

  /**
   * Idempotent under concurrent replicas (NFR005-01): the event id is the primary key, writers of the same
   * replaceable/addressable address are serialized with a transaction-scoped advisory lock, and inserting a
   * new head deletes the versions it supersedes, so a race always ends with the NIP-01 head alone.
   */
  async upsert(evt: NostrEvent, relay: string, communityId?: string): Promise<boolean> {
    const addressable = isAddressableKind(evt.kind);
    const replaceable = addressable || isReplaceableKind(evt.kind);
    const d = addressable ? (getTagValue(evt, 'd') ?? '') : null;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const seen = await client.query('UPDATE events SET last_seen_at = now() WHERE event_id = $1', [evt.id]);
      let inserted = false;
      if (!seen.rowCount) {
        // The head that supersedes `evt`, if one is already stored.
        let supersededBy: string | undefined;
        if (replaceable) {
          await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [eventAddress(evt)]);
          const heads = await client.query<{ event_id: string; created_at: string }>(
            'SELECT event_id, created_at FROM events WHERE pubkey = $1 AND kind = $2 AND d_tag IS NOT DISTINCT FROM $3 AND NOT deleted_tombstone',
            [evt.pubkey, evt.kind, d],
          );
          supersededBy = heads.rows.find((h) => h.event_id !== evt.id && (Number(h.created_at) > evt.created_at || (Number(h.created_at) === evt.created_at && h.event_id < evt.id)))?.event_id;
        }
        if (supersededBy !== undefined) {
          // FR023-12: a version older than the head that arrives after it is kept as superseded too.
          if (this.opts.keepSuperseded) {
            const enc = this.codec.encode(evt);
            await client.query(
              `INSERT INTO events_superseded (event_id, pubkey, kind, created_at, raw_event_json, encrypted_payload, seal_version, community_id, h_tag, d_tag, superseded_by)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (event_id) DO NOTHING`,
              [evt.id, evt.pubkey, evt.kind, evt.created_at, enc.raw ? JSON.stringify(enc.raw) : null, enc.encrypted ? Buffer.from(enc.encrypted) : null, enc.sealVersion ?? null, communityId ?? null, getTagValue(evt, 'h') ?? null, d, supersededBy],
            );
          }
        } else {
          const enc = this.codec.encode(evt);
          const r = await client.query(
            `INSERT INTO events (event_id, pubkey, kind, created_at, raw_event_json, encrypted_payload, seal_version, community_id, h_tag, p_tags, sensitivity_class, d_tag)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (event_id) DO NOTHING RETURNING event_id`,
            [evt.id, evt.pubkey, evt.kind, evt.created_at, enc.raw ? JSON.stringify(enc.raw) : null, enc.encrypted ? Buffer.from(enc.encrypted) : null, enc.sealVersion ?? null, communityId ?? null, getTagValue(evt, 'h') ?? null, getTagValues(evt, 'p'), classify(evt), d],
          );
          inserted = r.rowCount === 1;
          if (inserted && replaceable) {
            // FR023-12: in institutional mode what the new head supersedes is archived first (a legal hold may cover it).
            if (this.opts.keepSuperseded) {
              await client.query(
                `INSERT INTO events_superseded (event_id, pubkey, kind, created_at, raw_event_json, encrypted_payload, seal_version, community_id, h_tag, d_tag, superseded_by)
                 SELECT event_id, pubkey, kind, created_at, raw_event_json, encrypted_payload, seal_version, community_id, h_tag, d_tag, $4 FROM events
                 WHERE pubkey = $1 AND kind = $2 AND d_tag IS NOT DISTINCT FROM $3 AND event_id <> $4 AND NOT deleted_tombstone
                 ON CONFLICT (event_id) DO NOTHING`,
                [evt.pubkey, evt.kind, d, evt.id],
              );
            }
            await client.query('DELETE FROM events WHERE pubkey = $1 AND kind = $2 AND d_tag IS NOT DISTINCT FROM $3 AND event_id <> $4 AND NOT deleted_tombstone', [evt.pubkey, evt.kind, d, evt.id]);
          }
        }
      }
      // Also when another replica inserted it concurrently (ON CONFLICT waited for its commit).
      await client.query('INSERT INTO event_sources (event_id, relay_url) SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM events WHERE event_id = $1) ON CONFLICT DO NOTHING', [evt.id, relay]);
      await client.query('COMMIT');
      return inserted;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async tombstone(ids: string[], byPubkey: string): Promise<number> {
    const r = await this.pool.query('UPDATE events SET deleted_tombstone = true WHERE event_id = ANY($1) AND pubkey = $2 AND NOT deleted_tombstone', [ids, byPubkey]);
    return r.rowCount ?? 0;
  }

  /**
   * SEC-06: re-seals the payloads sealed before the AAD existed (seal_version NULL), so every one names its
   * event id. Safe while serving and across replicas: reads accept both formats, and a row is only replaced
   * if it still holds the payload that was read. A row that does not decode (tampered or corrupted) is left
   * as it is and counted in `failed`; reads keep refusing it.
   */
  async resealLegacy(batch = 200): Promise<{ resealed: number; failed: number }> {
    const out = { resealed: 0, failed: 0 };
    if (!this.codec.sealed) return out;
    for (let after = ''; ; ) {
      const { rows } = await this.pool.query<{ event_id: string; encrypted_payload: Buffer }>(
        'SELECT event_id, encrypted_payload FROM events WHERE seal_version IS NULL AND encrypted_payload IS NOT NULL AND event_id > $1 ORDER BY event_id LIMIT $2',
        [after, batch],
      );
      for (const r of rows) {
        after = r.event_id;
        let enc: StoredEvent;
        try {
          enc = this.codec.encode(this.codec.decode({ encrypted: new Uint8Array(r.encrypted_payload) }, r.event_id));
        } catch {
          out.failed++;
          continue;
        }
        const u = await this.pool.query(
          'UPDATE events SET encrypted_payload = $2, seal_version = $3 WHERE event_id = $1 AND seal_version IS NULL AND encrypted_payload = $4',
          [r.event_id, Buffer.from(enc.encrypted!), enc.sealVersion, r.encrypted_payload],
        );
        out.resealed += u.rowCount ?? 0;
      }
      if (rows.length < batch) return out;
    }
  }

  async query(q: EventQuery): Promise<MirroredEvent[]> {
    const where: string[] = [];
    const args: unknown[] = [];
    const add = (sql: string, v: unknown) => {
      args.push(v);
      where.push(sql.replace('?', `$${args.length}`));
    };
    if (!q.includeDeleted) where.push('NOT e.deleted_tombstone');
    if (q.ids) add('e.event_id = ANY(?)', q.ids);
    if (q.kinds) add('e.kind = ANY(?)', q.kinds);
    if (q.authors) add('e.pubkey = ANY(?)', q.authors);
    if (q.h) add('e.h_tag = ?', q.h);
    if (q.p) add('? = ANY(e.p_tags)', q.p);
    if (q.since !== undefined) add('e.created_at >= ?', q.since);
    if (q.until !== undefined) add('e.created_at <= ?', q.until);
    args.push(Math.min(q.limit ?? 500, 5000));
    const sql = `SELECT e.*, COALESCE(array_agg(s.relay_url) FILTER (WHERE s.relay_url IS NOT NULL), '{}') AS relays
      FROM events e LEFT JOIN event_sources s ON s.event_id = e.event_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      GROUP BY e.event_id ORDER BY e.created_at DESC LIMIT $${args.length}`;
    const { rows } = await this.pool.query<PgEventRow>(sql, args);
    return rows.map((r) => this.toMirrored(r));
  }

  private toMirrored(r: PgEventRow): MirroredEvent {
    return {
      event: this.codec.decode({ raw: r.raw_event_json, encrypted: r.encrypted_payload ? new Uint8Array(r.encrypted_payload) : null, sealVersion: r.seal_version }, r.event_id),
      firstSeenAt: new Date(r.first_seen_at).getTime(),
      lastSeenAt: new Date(r.last_seen_at).getTime(),
      relays: r.relays,
      sensitivity: r.sensitivity_class,
      deleted: r.deleted_tombstone,
    };
  }

  async get(id: string) {
    return (await this.query({ ids: [id], includeDeleted: true }))[0];
  }

  async stats() {
    const { rows } = await this.pool.query<{ sensitivity_class: string; n: string }>('SELECT sensitivity_class, count(*) AS n FROM events GROUP BY 1');
    const byClass = Object.fromEntries(rows.map((r) => [r.sensitivity_class, Number(r.n)]));
    return { events: Object.values(byClass).reduce((a, b) => a + b, 0), byClass };
  }

  async setReadCursor(reader: string, h: string, until: number): Promise<number> {
    const { rows } = await this.pool.query<{ read_until: string }>(
      `INSERT INTO read_cursors (reader_pubkey, h_tag, read_until) VALUES ($1,$2,$3)
       ON CONFLICT (reader_pubkey, h_tag) DO UPDATE SET read_until = GREATEST(read_cursors.read_until, EXCLUDED.read_until), updated_at = now()
       RETURNING read_until`,
      [reader, h, until],
    );
    return Number(rows[0]!.read_until);
  }

  async readCursors(reader: string, hs: string[]): Promise<Record<string, number>> {
    const { rows } = await this.pool.query<{ h_tag: string; read_until: string }>('SELECT h_tag, read_until FROM read_cursors WHERE reader_pubkey = $1 AND h_tag = ANY($2)', [reader, hs]);
    const found = new Map(rows.map((r) => [r.h_tag, Number(r.read_until)]));
    return Object.fromEntries(hs.map((h) => [h, found.get(h) ?? 0]));
  }

  async unreadCounts(reader: string, hs: string[]): Promise<Record<string, number>> {
    // Only plaintext index columns are needed, so this also works on a sealed mirror.
    const { rows } = await this.pool.query<{ h_tag: string; n: string }>(
      `SELECT e.h_tag, count(*) AS n FROM events e
       LEFT JOIN read_cursors c ON c.reader_pubkey = $1 AND c.h_tag = e.h_tag
       WHERE e.h_tag = ANY($2) AND e.kind = ANY($3) AND NOT e.deleted_tombstone AND e.pubkey <> $1 AND e.created_at > COALESCE(c.read_until, 0)
       GROUP BY e.h_tag`,
      [reader, hs, CHANNEL_MESSAGE_KINDS],
    );
    const found = new Map(rows.map((r) => [r.h_tag, Number(r.n)]));
    return Object.fromEntries(hs.map((h) => [h, found.get(h) ?? 0]));
  }

  async recentMessageTimes(reader: string, hs: string[], opts: { kinds?: number[]; limit: number }): Promise<Record<string, number[]>> {
    // One index scan per channel (events_h_created_idx), plaintext index columns only.
    const { rows } = await this.pool.query<{ h_tag: string; created_at: string }>(
      `SELECT c.h_tag, t.created_at FROM unnest($2::text[]) AS c(h_tag)
       CROSS JOIN LATERAL (
         SELECT e.created_at FROM events e
         WHERE e.h_tag = c.h_tag AND e.kind = ANY($3) AND NOT e.deleted_tombstone AND e.pubkey <> $1
         ORDER BY e.created_at DESC LIMIT $4
       ) t`,
      [reader, hs, searchableKinds(opts.kinds), opts.limit],
    );
    const byH = new Map(hs.map((h) => [h, [] as number[]]));
    for (const r of rows) byH.get(r.h_tag)?.push(Number(r.created_at));
    return Object.fromEntries([...byH].map(([h, times]) => [h, times.sort((a, b) => b - a)]));
  }

  async search(q: SearchQuery): Promise<MirroredEvent[]> {
    const limit = Math.min(q.limit ?? 50, 500);
    const args: unknown[] = [searchableKinds(q.kinds)];
    const where = [`NOT e.deleted_tombstone`, `e.kind = ANY($1)`, `e.sensitivity_class = 'channel'`];
    if (q.h?.length) {
      args.push(q.h);
      where.push(`e.h_tag = ANY($${args.length})`);
    }
    if (!this.codec.sealed) {
      args.push(`%${q.text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
      where.push(`e.raw_event_json ->> 'content' ILIKE $${args.length}`);
    }
    // Sealed rows can only be matched after decrypting them through the codec, like any read.
    args.push(this.codec.sealed ? SEALED_SEARCH_SCAN : limit);
    const { rows } = await this.pool.query<PgEventRow>(
      `SELECT e.*, COALESCE(array_agg(s.relay_url) FILTER (WHERE s.relay_url IS NOT NULL), '{}') AS relays
       FROM events e LEFT JOIN event_sources s ON s.event_id = e.event_id
       WHERE ${where.join(' AND ')}
       GROUP BY e.event_id ORDER BY e.created_at DESC LIMIT $${args.length}`,
      args,
    );
    return rows.map((r) => this.toMirrored(r)).filter((m) => contentMatches(m.event, q.text)).slice(0, limit);
  }

  async memberChannels(reader: string, authorities: string[]): Promise<string[]> {
    if (!authorities.length) return [];
    // Index columns only (kind, pubkey, d_tag, p_tags): works on a sealed mirror.
    const { rows } = await this.pool.query<{ d_tag: string }>(
      'SELECT DISTINCT d_tag FROM events WHERE kind = ANY($1) AND pubkey = ANY($2) AND $3 = ANY(p_tags) AND NOT deleted_tombstone AND d_tag IS NOT NULL',
      [ACCESS_KINDS, authorities, reader],
    );
    return rows.map((r) => r.d_tag);
  }

  async recordModeration(d: ModerationDeletion): Promise<void> {
    await this.pool.query('INSERT INTO moderation_deletions (deletion_id, target_id, h_tag, actor) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [d.deletionId, d.targetId, d.h, d.actor]);
  }

  async applyModeration(h: string, authorities: string[], targetId?: string): Promise<number> {
    // One statement: the admin list, the authorized pending deletions, the tombstones and the applied marks.
    const { rows } = await this.pool.query<{ hidden: string }>(
      `WITH admins AS (
         SELECT DISTINCT unnest(p_tags) AS pk FROM events WHERE kind = 39001 AND d_tag = $1 AND pubkey = ANY($2) AND NOT deleted_tombstone
       ), ok AS (
         SELECT m.deletion_id, m.target_id FROM moderation_deletions m JOIN events t ON t.event_id = m.target_id
         WHERE m.h_tag = $1 AND NOT m.applied AND ($3::text IS NULL OR m.target_id = $3) AND t.h_tag = m.h_tag
           AND (t.pubkey = m.actor OR m.actor IN (SELECT pk FROM admins))
       ), hidden AS (
         UPDATE events SET deleted_tombstone = true WHERE event_id IN (SELECT target_id FROM ok) AND NOT deleted_tombstone RETURNING event_id
       ), marked AS (
         UPDATE moderation_deletions m SET applied = true FROM ok WHERE m.deletion_id = ok.deletion_id AND m.target_id = ok.target_id RETURNING m.target_id
       )
       SELECT (SELECT count(*) FROM hidden) AS hidden`,
      [h, authorities, targetId ?? null],
    );
    return Number(rows[0]?.hidden ?? 0);
  }

  async superseded() {
    const { rows } = await this.pool.query<{ event_id: string; raw_event_json: NostrEvent | null; encrypted_payload: Buffer | null; seal_version: number | null; superseded_by: string }>(
      'SELECT event_id, raw_event_json, encrypted_payload, seal_version, superseded_by FROM events_superseded ORDER BY created_at, event_id',
    );
    return rows.map((r) => ({
      event: this.codec.decode({ raw: r.raw_event_json, encrypted: r.encrypted_payload ? new Uint8Array(r.encrypted_payload) : null, sealVersion: r.seal_version }, r.event_id),
      supersededBy: r.superseded_by,
    }));
  }

  async purgeSuperseded(held: string[]) {
    // Index columns only (h, community, kind, d): works on a sealed mirror.
    const r = await this.pool.query(
      `DELETE FROM events_superseded WHERE NOT (coalesce(h_tag = ANY($1), false) OR coalesce(community_id = ANY($1), false) OR (kind = ANY($2) AND coalesce(d_tag = ANY($1), false)))`,
      [held, GROUP_STATE_KINDS],
    );
    return r.rowCount ?? 0;
  }

  async purge(q: PurgeQuery): Promise<number> {
    // event_sources rows go with their event (ON DELETE CASCADE). Index columns only: works on a sealed mirror.
    const r =
      'h' in q
        ? await this.pool.query('DELETE FROM events WHERE created_at < $1 AND h_tag = $2 AND (community_id IS NULL OR NOT community_id = ANY($3))', [q.before, q.h, q.exceptCommunities])
        : await this.pool.query('DELETE FROM events WHERE created_at < $1 AND community_id = $2 AND (h_tag IS NULL OR NOT h_tag = ANY($3))', [q.before, q.community, q.exceptH]);
    return r.rowCount ?? 0;
  }
}
