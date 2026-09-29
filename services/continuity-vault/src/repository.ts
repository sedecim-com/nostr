import type { Pool } from '@sedecim/service-kit';

/**
 * Metadata of one stored envelope (ADR 0011): whose (the vault account), which opaque id, how big and when.
 * The content lives in the object store under `objectKey`.
 */
export interface ArchiveRow {
  /** Vault account: `nostr:<hex pubkey>` (NIP-98) or `acceso:<issuer>#<sub>` (Acceso login). */
  owner: string;
  archiveId: string;
  keyId: string;
  size: number;
  sha256: string;
  objectKey: string;
  createdAt: string;
  updatedAt: string;
}

export type NewArchive = Omit<ArchiveRow, 'createdAt' | 'updatedAt'>;

export interface VaultQuota {
  maxArchives: number;
  maxBytes: number;
}

export interface VaultUsage {
  archives: number;
  bytes: number;
}

export class QuotaExceededError extends Error {
  constructor() {
    super('vault quota exceeded');
    this.name = 'QuotaExceededError';
  }
}

export interface ArchiveRepository {
  /**
   * Inserts or replaces the archive (owner, archiveId) if the owner stays within `quota`; otherwise throws
   * QuotaExceededError and changes nothing. Returns the object key of the replaced version, if any.
   */
  upsert(a: NewArchive, quota: VaultQuota, at: string): Promise<{ row: ArchiveRow; created: boolean; replacedObject?: string }>;
  get(owner: string, archiveId: string): Promise<ArchiveRow | undefined>;
  /** Up to `limit` archives of the owner with an id greater than `after`, ordered by id. */
  list(owner: string, after: string | undefined, limit: number): Promise<ArchiveRow[]>;
  /** Deletes one archive, or every archive of the owner; returns the object keys to delete. */
  delete(owner: string, archiveId?: string): Promise<string[]>;
  usage(owner: string): Promise<VaultUsage>;
  /** VAULT-05: the days the owner keeps an archive since its last write (null: the operator's maximum). */
  retention(owner: string): Promise<number | null>;
  setRetention(owner: string, days: number | null): Promise<void>;
  /**
   * VAULT-05: deletes every archive not written for longer than its owner's retention (never more than `maxDays`,
   * the operator's), keeping the counters exact; returns the object keys to delete. Without either, nothing expires.
   */
  expire(now: Date, maxDays: number | undefined): Promise<string[]>;
  /** Every object key a row points to (the orphan sweep keeps these). */
  objectKeys(): Promise<Set<string>>;
}

/** The days an archive of an account is kept: the account's choice, never above the operator's maximum. */
export function effectiveRetention(accountDays: number | null | undefined, maxDays: number | undefined): number | undefined {
  if (accountDays == null) return maxDays;
  return maxDays === undefined ? accountDays : Math.min(accountDays, maxDays);
}

const DAY_MS = 24 * 60 * 60 * 1000;

export class MemoryArchiveRepository implements ArchiveRepository {
  private readonly owners = new Map<string, Map<string, ArchiveRow>>();
  private readonly retentions = new Map<string, number>();

  async upsert(a: NewArchive, quota: VaultQuota, at: string) {
    const mine = this.owners.get(a.owner) ?? new Map<string, ArchiveRow>();
    const prev = mine.get(a.archiveId);
    const used = sum(mine);
    if (used.archives + (prev ? 0 : 1) > quota.maxArchives || used.bytes - (prev?.size ?? 0) + a.size > quota.maxBytes) throw new QuotaExceededError();
    const row: ArchiveRow = { ...a, createdAt: prev?.createdAt ?? at, updatedAt: at };
    mine.set(a.archiveId, row);
    this.owners.set(a.owner, mine);
    return { row: { ...row }, created: !prev, ...(prev ? { replacedObject: prev.objectKey } : {}) };
  }

  async get(owner: string, archiveId: string) {
    const r = this.owners.get(owner)?.get(archiveId);
    return r ? { ...r } : undefined;
  }

  async list(owner: string, after: string | undefined, limit: number) {
    return [...(this.owners.get(owner)?.values() ?? [])]
      .filter((r) => after === undefined || r.archiveId > after)
      .sort((x, y) => (x.archiveId < y.archiveId ? -1 : 1))
      .slice(0, limit)
      .map((r) => ({ ...r }));
  }

  async delete(owner: string, archiveId?: string) {
    // Deleting everything deletes the account, its retention choice included.
    if (archiveId === undefined) this.retentions.delete(owner);
    const mine = this.owners.get(owner);
    if (!mine) return [];
    const gone = archiveId === undefined ? [...mine.values()] : mine.has(archiveId) ? [mine.get(archiveId)!] : [];
    for (const r of gone) mine.delete(r.archiveId);
    if (!mine.size) this.owners.delete(owner);
    return gone.map((r) => r.objectKey);
  }

  async usage(owner: string) {
    return sum(this.owners.get(owner) ?? new Map());
  }

  async retention(owner: string) {
    return this.retentions.get(owner) ?? null;
  }

  async setRetention(owner: string, days: number | null) {
    if (days === null) this.retentions.delete(owner);
    else this.retentions.set(owner, days);
  }

  async expire(now: Date, maxDays: number | undefined) {
    const gone: string[] = [];
    for (const [owner, mine] of this.owners) {
      const days = effectiveRetention(this.retentions.get(owner), maxDays);
      if (days === undefined) continue;
      const cutoff = now.getTime() - days * DAY_MS;
      for (const r of [...mine.values()]) {
        if (Date.parse(r.updatedAt) >= cutoff) continue;
        mine.delete(r.archiveId);
        gone.push(r.objectKey);
      }
      if (!mine.size) this.owners.delete(owner);
    }
    return gone;
  }

  async objectKeys() {
    return new Set([...this.owners.values()].flatMap((m) => [...m.values()].map((r) => r.objectKey)));
  }

  /** Every stored row: what an operator could read from this repository (audits and tests). */
  rows(): ArchiveRow[] {
    return [...this.owners.values()].flatMap((m) => [...m.values()].map((r) => ({ ...r })));
  }
}

function sum(rows: Map<string, ArchiveRow>): VaultUsage {
  let bytes = 0;
  for (const r of rows.values()) bytes += r.size;
  return { archives: rows.size, bytes };
}

/**
 * Postgres metadata. Every change to an owner's archives first locks the owner's row in `vault_owners`, so
 * concurrent uploads (from any replica) are serialized per account and the quota check cannot be raced.
 */
export class PgArchiveRepository implements ArchiveRepository {
  constructor(private readonly pool: Pool) {}

  private async tx<T>(fn: (q: (sql: string, params: unknown[]) => Promise<{ rows: any[]; rowCount: number | null }>) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      const out = await fn((sql, params) => c.query(sql, params));
      await c.query('COMMIT');
      return out;
    } catch (e) {
      await c.query('ROLLBACK');
      throw e;
    } finally {
      c.release();
    }
  }

  async upsert(a: NewArchive, quota: VaultQuota, at: string) {
    return this.tx(async (q) => {
      await q('INSERT INTO vault_owners (owner) VALUES ($1) ON CONFLICT (owner) DO NOTHING', [a.owner]);
      const used = (await q('SELECT archives, bytes FROM vault_owners WHERE owner = $1 FOR UPDATE', [a.owner])).rows[0];
      const prev = (await q('SELECT size, object_key, created_at FROM vault_archives WHERE owner = $1 AND archive_id = $2', [a.owner, a.archiveId])).rows[0];
      const archives = Number(used.archives) + (prev ? 0 : 1);
      const bytes = Number(used.bytes) - (prev ? Number(prev.size) : 0) + a.size;
      if (archives > quota.maxArchives || bytes > quota.maxBytes) throw new QuotaExceededError();
      await q('UPDATE vault_owners SET archives = $2, bytes = $3 WHERE owner = $1', [a.owner, archives, bytes]);
      const { rows } = await q(
        `INSERT INTO vault_archives (owner, archive_id, key_id, size, sha256, object_key, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
         ON CONFLICT (owner, archive_id) DO UPDATE
           SET key_id = EXCLUDED.key_id, size = EXCLUDED.size, sha256 = EXCLUDED.sha256, object_key = EXCLUDED.object_key, updated_at = EXCLUDED.updated_at
         RETURNING *`,
        [a.owner, a.archiveId, a.keyId, a.size, a.sha256, a.objectKey, at],
      );
      return { row: mapRow(rows[0]), created: !prev, ...(prev ? { replacedObject: prev.object_key as string } : {}) };
    });
  }

  async get(owner: string, archiveId: string) {
    const { rows } = await this.pool.query('SELECT * FROM vault_archives WHERE owner = $1 AND archive_id = $2', [owner, archiveId]);
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async list(owner: string, after: string | undefined, limit: number) {
    const { rows } =
      after === undefined
        ? await this.pool.query('SELECT * FROM vault_archives WHERE owner = $1 ORDER BY archive_id LIMIT $2', [owner, limit])
        : await this.pool.query('SELECT * FROM vault_archives WHERE owner = $1 AND archive_id > $2 ORDER BY archive_id LIMIT $3', [owner, after, limit]);
    return rows.map(mapRow);
  }

  async delete(owner: string, archiveId?: string) {
    return this.tx(async (q) => {
      if (!(await q('SELECT 1 FROM vault_owners WHERE owner = $1 FOR UPDATE', [owner])).rowCount) return [];
      if (archiveId === undefined) {
        const { rows } = await q('DELETE FROM vault_archives WHERE owner = $1 RETURNING object_key', [owner]);
        await q('DELETE FROM vault_owners WHERE owner = $1', [owner]);
        return rows.map((r) => r.object_key as string);
      }
      const { rows } = await q('DELETE FROM vault_archives WHERE owner = $1 AND archive_id = $2 RETURNING size, object_key', [owner, archiveId]);
      if (!rows.length) return [];
      await q('UPDATE vault_owners SET archives = archives - 1, bytes = bytes - $2 WHERE owner = $1', [owner, Number(rows[0].size)]);
      // An account with nothing stored leaves no row behind, unless it chose a retention (VAULT-05).
      await q('DELETE FROM vault_owners WHERE owner = $1 AND archives = 0 AND retention_days IS NULL', [owner]);
      return [rows[0].object_key as string];
    });
  }

  async usage(owner: string) {
    const { rows } = await this.pool.query('SELECT archives, bytes FROM vault_owners WHERE owner = $1', [owner]);
    return rows[0] ? { archives: Number(rows[0].archives), bytes: Number(rows[0].bytes) } : { archives: 0, bytes: 0 };
  }

  async retention(owner: string) {
    const { rows } = await this.pool.query('SELECT retention_days FROM vault_owners WHERE owner = $1', [owner]);
    return rows[0]?.retention_days == null ? null : Number(rows[0].retention_days);
  }

  async setRetention(owner: string, days: number | null) {
    await this.tx(async (q) => {
      await q('INSERT INTO vault_owners (owner, retention_days) VALUES ($1, $2) ON CONFLICT (owner) DO UPDATE SET retention_days = EXCLUDED.retention_days', [owner, days]);
      await q('DELETE FROM vault_owners WHERE owner = $1 AND archives = 0 AND retention_days IS NULL', [owner]);
    });
  }

  async expire(now: Date, maxDays: number | undefined) {
    const max = maxDays ?? null;
    // LEAST ignores NULLs: the account's days capped by the operator's, either alone, or neither (nothing expires).
    const { rows: owners } = await this.pool.query(
      `SELECT DISTINCT a.owner FROM vault_archives a JOIN vault_owners o ON o.owner = a.owner
       WHERE a.updated_at < $1::timestamptz - make_interval(days => LEAST(COALESCE(o.retention_days, $2::integer), $2::integer))`,
      [now.toISOString(), max],
    );
    const gone: string[] = [];
    for (const { owner } of owners) {
      // Per account, with its row locked like any other change: uploads and the counters cannot race the sweep.
      const keys = await this.tx(async (q) => {
        const o = (await q('SELECT retention_days FROM vault_owners WHERE owner = $1 FOR UPDATE', [owner])).rows[0];
        if (!o) return [];
        const days = effectiveRetention(o.retention_days == null ? null : Number(o.retention_days), maxDays);
        if (days === undefined) return [];
        const { rows } = await q("DELETE FROM vault_archives WHERE owner = $1 AND updated_at < $2::timestamptz - make_interval(days => $3::integer) RETURNING size, object_key", [owner, now.toISOString(), days]);
        if (!rows.length) return [];
        const bytes = rows.reduce((n: number, r: { size: unknown }) => n + Number(r.size), 0);
        await q('UPDATE vault_owners SET archives = archives - $2, bytes = bytes - $3 WHERE owner = $1', [owner, rows.length, bytes]);
        await q('DELETE FROM vault_owners WHERE owner = $1 AND archives = 0 AND retention_days IS NULL', [owner]);
        return rows.map((r: { object_key: unknown }) => r.object_key as string);
      });
      gone.push(...keys);
    }
    return gone;
  }

  async objectKeys() {
    const { rows } = await this.pool.query('SELECT object_key FROM vault_archives');
    return new Set(rows.map((r) => r.object_key as string));
  }
}

function mapRow(r: Record<string, unknown>): ArchiveRow {
  return {
    owner: r.owner as string,
    archiveId: r.archive_id as string,
    keyId: r.key_id as string,
    size: Number(r.size),
    sha256: r.sha256 as string,
    objectKey: r.object_key as string,
    createdAt: new Date(r.created_at as string).toISOString(),
    updatedAt: new Date(r.updated_at as string).toISOString(),
  };
}
