import { getTagValue, getTagValues, isAddressableKind, isReplaceableKind, eventAddress, supersedes, type NostrEvent } from '@sedecim/nostr-core';
import type { Pool } from '@sedecim/service-kit';
import { plainCodec, type EventCodec } from './codec';

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
  /** Plaintext search over channel messages only (CHANNEL_MESSAGE_KINDS), newest first. */
  search(q: SearchQuery): Promise<MirroredEvent[]>;
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
  private readonly rows = new Map<string, MirroredEvent & { stored: ReturnType<EventCodec['encode']> }>();
  private readonly cursors = new Map<string, number>();
  constructor(private readonly codec: EventCodec = plainCodec) {}

  async upsert(evt: NostrEvent, relay: string): Promise<boolean> {
    const now = Date.now();
    const cur = this.rows.get(evt.id);
    if (cur) {
      cur.lastSeenAt = now;
      if (!cur.relays.includes(relay)) cur.relays.push(relay);
      return false;
    }
    if (isReplaceableKind(evt.kind) || isAddressableKind(evt.kind)) {
      const addr = eventAddress(evt);
      for (const r of this.rows.values()) {
        const re = this.codec.decode(r.stored);
        if (eventAddress(re) === addr && !r.deleted && !supersedes(evt, re)) return false;
      }
    }
    this.rows.set(evt.id, { event: evt, stored: this.codec.encode(evt), firstSeenAt: now, lastSeenAt: now, relays: [relay], sensitivity: classify(evt), deleted: false });
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
    return out.slice(0, q.limit ?? 500).map(({ stored: _s, ...m }) => ({ ...m, event: this.codec.decode(_s) }));
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

  async search(q: SearchQuery): Promise<MirroredEvent[]> {
    const kinds = searchableKinds(q.kinds);
    const candidates = (await this.query({ kinds, limit: Number.MAX_SAFE_INTEGER })).filter(
      (m) => m.sensitivity === 'channel' && (!q.h?.length || q.h.includes(getTagValue(m.event, 'h')!)),
    );
    return candidates.filter((m) => contentMatches(m.event, q.text)).slice(0, q.limit ?? 50);
  }
}

interface PgEventRow {
  raw_event_json: NostrEvent | null;
  encrypted_payload: Buffer | null;
  first_seen_at: string;
  last_seen_at: string;
  relays: string[];
  sensitivity_class: SensitivityClass;
  deleted_tombstone: boolean;
}

export class PgEventRepository implements EventRepository {
  constructor(private readonly pool: Pool, private readonly codec: EventCodec = plainCodec) {}

  async upsert(evt: NostrEvent, relay: string, communityId?: string): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const exists = await client.query('SELECT 1 FROM events WHERE event_id = $1', [evt.id]);
      let inserted = false;
      if (exists.rowCount) {
        await client.query('UPDATE events SET last_seen_at = now() WHERE event_id = $1', [evt.id]);
      } else {
        let superseded = false;
        if (isReplaceableKind(evt.kind) || isAddressableKind(evt.kind)) {
          const d = isAddressableKind(evt.kind) ? (getTagValue(evt, 'd') ?? '') : null;
          const heads = await client.query<{ event_id: string; created_at: string }>(
            `SELECT event_id, created_at FROM events WHERE pubkey = $1 AND kind = $2 AND NOT deleted_tombstone ${d !== null ? `AND raw_event_json -> 'tags' @> $3::jsonb` : ''}`,
            d !== null ? [evt.pubkey, evt.kind, JSON.stringify([['d', d]])] : [evt.pubkey, evt.kind],
          );
          superseded = heads.rows.some((h) => Number(h.created_at) > evt.created_at || (Number(h.created_at) === evt.created_at && h.event_id < evt.id));
        }
        if (!superseded) {
          const enc = this.codec.encode(evt);
          await client.query(
            `INSERT INTO events (event_id, pubkey, kind, created_at, raw_event_json, encrypted_payload, community_id, h_tag, p_tags, sensitivity_class)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (event_id) DO NOTHING`,
            [evt.id, evt.pubkey, evt.kind, evt.created_at, enc.raw ? JSON.stringify(enc.raw) : null, enc.encrypted ? Buffer.from(enc.encrypted) : null, communityId ?? null, getTagValue(evt, 'h') ?? null, getTagValues(evt, 'p'), classify(evt)],
          );
          inserted = true;
        }
      }
      if (inserted || exists.rowCount) {
        await client.query('INSERT INTO event_sources (event_id, relay_url) VALUES ($1,$2) ON CONFLICT DO NOTHING', [evt.id, relay]);
      }
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
      event: this.codec.decode({ raw: r.raw_event_json, encrypted: r.encrypted_payload ? new Uint8Array(r.encrypted_payload) : null }),
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
}
