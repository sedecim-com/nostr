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
    const { rows } = await this.pool.query(sql, args);
    return rows.map((r) => ({
      event: this.codec.decode({ raw: r.raw_event_json, encrypted: r.encrypted_payload ? new Uint8Array(r.encrypted_payload) : null }),
      firstSeenAt: new Date(r.first_seen_at).getTime(),
      lastSeenAt: new Date(r.last_seen_at).getTime(),
      relays: r.relays,
      sensitivity: r.sensitivity_class,
      deleted: r.deleted_tombstone,
    }));
  }

  async get(id: string) {
    return (await this.query({ ids: [id], includeDeleted: true }))[0];
  }

  async stats() {
    const { rows } = await this.pool.query<{ sensitivity_class: string; n: string }>('SELECT sensitivity_class, count(*) AS n FROM events GROUP BY 1');
    const byClass = Object.fromEntries(rows.map((r) => [r.sensitivity_class, Number(r.n)]));
    return { events: Object.values(byClass).reduce((a, b) => a + b, 0), byClass };
  }
}
