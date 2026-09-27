import type { Pool } from '@sedecim/service-kit';

export type KeyState = 'active' | 'export-pending' | 'migrated' | 'deleted';

export interface KeyRecord {
  keyId: string;
  owner: string;
  pubkey: string;
  provider: string;
  version: number;
  state: KeyState;
  createdAt: number;
  lastUsed?: number;
  allowedKinds?: number[];
  migrationChallenge?: string;
  migratedAt?: number;
  retentionDays: number;
  deletedAt?: number;
  /** Set once the vault material has been destroyed (or its scheduled deletion has elapsed). */
  destroyedAt?: number;
}

export interface UsageRecord {
  at: number;
  keyId: string;
  action: 'sign' | 'nip44_encrypt' | 'nip44_decrypt' | 'export' | 'migration-confirmed' | 'deleted' | 'destroyed' | 'created' | 'imported' | 'rate-limited';
  kind?: number;
  eventId?: string;
  principal: string;
  /** Device of the session that made the call (FR024-03), when it came through a device session. */
  deviceId?: string;
}

export class PubkeyAlreadyManagedError extends Error {
  constructor() {
    super('key already managed');
  }
}

/** Key registry and usage log (FR005-03). Metadata only: secrets never go through here. */
export interface KeyRegistry {
  /** Fails with PubkeyAlreadyManagedError if a live (not deleted) key has the same pubkey. */
  insert(rec: KeyRecord): Promise<void>;
  get(keyId: string): Promise<KeyRecord | undefined>;
  liveByPubkey(pubkey: string): Promise<KeyRecord | undefined>;
  /** Live keys of an owner, oldest first. */
  listByOwner(owner: string): Promise<KeyRecord[]>;
  save(rec: KeyRecord): Promise<void>;
  touch(keyId: string, at: number): Promise<void>;
  recordUsage(u: UsageRecord): Promise<void>;
  usageOf(keyId: string): Promise<UsageRecord[]>;
  /** Deletes usage rows older than `at`; returns how many. */
  purgeUsageBefore(at: number): Promise<number>;
  /** Deleted keys whose retention window is over at `now` and whose material is not destroyed yet. */
  pendingDestruction(now: number): Promise<KeyRecord[]>;
}

const retentionEnd = (k: KeyRecord) => (k.deletedAt ?? 0) + k.retentionDays * 86_400_000;

/** In-memory registry for tests and development (lost on restart). */
export class MemoryKeyRegistry implements KeyRegistry {
  readonly keys = new Map<string, KeyRecord>();
  readonly usage: UsageRecord[] = [];

  async insert(rec: KeyRecord) {
    if (await this.liveByPubkey(rec.pubkey)) throw new PubkeyAlreadyManagedError();
    this.keys.set(rec.keyId, structuredClone(rec));
  }
  async get(keyId: string) {
    const k = this.keys.get(keyId);
    return k ? structuredClone(k) : undefined;
  }
  async liveByPubkey(pubkey: string) {
    const k = [...this.keys.values()].find((r) => r.pubkey === pubkey && r.state !== 'deleted');
    return k ? structuredClone(k) : undefined;
  }
  async listByOwner(owner: string) {
    return [...this.keys.values()].filter((k) => k.owner === owner && k.state !== 'deleted').map((k) => structuredClone(k));
  }
  async save(rec: KeyRecord) {
    this.keys.set(rec.keyId, structuredClone(rec));
  }
  async touch(keyId: string, at: number) {
    const k = this.keys.get(keyId);
    if (k) k.lastUsed = at;
  }
  async recordUsage(u: UsageRecord) {
    this.usage.push({ ...u });
  }
  async usageOf(keyId: string) {
    return this.usage.filter((u) => u.keyId === keyId).map((u) => ({ ...u }));
  }
  async purgeUsageBefore(at: number) {
    const keep = this.usage.filter((u) => u.at >= at);
    const purged = this.usage.length - keep.length;
    this.usage.splice(0, this.usage.length, ...keep);
    return purged;
  }
  async pendingDestruction(now: number) {
    return [...this.keys.values()].filter((k) => k.state === 'deleted' && k.destroyedAt === undefined && retentionEnd(k) <= now).map((k) => structuredClone(k));
  }
}

type KeyRow = {
  key_id: string;
  owner: string;
  pubkey: string;
  provider: string;
  version: number;
  state: KeyState;
  allowed_kinds: number[] | null;
  migration_challenge: string | null;
  retention_days: number;
  created_at: Date;
  last_used_at: Date | null;
  migrated_at: Date | null;
  deleted_at: Date | null;
  destroyed_at: Date | null;
};

const ms = (d: Date | null) => d?.getTime();
const ts = (v: number | undefined) => (v === undefined ? null : new Date(v));

function fromRow(r: KeyRow): KeyRecord {
  const opt = <K extends keyof KeyRecord>(k: K, v: KeyRecord[K] | undefined) => (v === undefined ? {} : { [k]: v });
  return {
    keyId: r.key_id,
    owner: r.owner,
    pubkey: r.pubkey,
    provider: r.provider,
    version: r.version,
    state: r.state,
    createdAt: r.created_at.getTime(),
    retentionDays: r.retention_days,
    ...opt('lastUsed', ms(r.last_used_at)),
    ...opt('allowedKinds', r.allowed_kinds ?? undefined),
    ...opt('migrationChallenge', r.migration_challenge ?? undefined),
    ...opt('migratedAt', ms(r.migrated_at)),
    ...opt('deletedAt', ms(r.deleted_at)),
    ...opt('destroyedAt', ms(r.destroyed_at)),
  };
}

/** Postgres registry (migrations/): survives restarts and is shared by every replica. */
export class PgKeyRegistry implements KeyRegistry {
  constructor(private readonly pool: Pool) {}

  async insert(k: KeyRecord) {
    try {
      await this.pool.query(
        `INSERT INTO managed_keys (key_id, owner, pubkey, provider, version, state, allowed_kinds, migration_challenge, retention_days, created_at, last_used_at, migrated_at, deleted_at, destroyed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [k.keyId, k.owner, k.pubkey, k.provider, k.version, k.state, k.allowedKinds ?? null, k.migrationChallenge ?? null, k.retentionDays, ts(k.createdAt), ts(k.lastUsed), ts(k.migratedAt), ts(k.deletedAt), ts(k.destroyedAt)],
      );
    } catch (err) {
      if ((err as { code?: string }).code === '23505') throw new PubkeyAlreadyManagedError();
      throw err;
    }
  }
  async get(keyId: string) {
    const { rows } = await this.pool.query<KeyRow>('SELECT * FROM managed_keys WHERE key_id = $1', [keyId]);
    return rows[0] ? fromRow(rows[0]) : undefined;
  }
  async liveByPubkey(pubkey: string) {
    const { rows } = await this.pool.query<KeyRow>("SELECT * FROM managed_keys WHERE pubkey = $1 AND state <> 'deleted'", [pubkey]);
    return rows[0] ? fromRow(rows[0]) : undefined;
  }
  async listByOwner(owner: string) {
    const { rows } = await this.pool.query<KeyRow>("SELECT * FROM managed_keys WHERE owner = $1 AND state <> 'deleted' ORDER BY created_at, key_id", [owner]);
    return rows.map(fromRow);
  }
  async save(k: KeyRecord) {
    // Identity columns (owner, pubkey, provider, created_at) are immutable.
    await this.pool.query(
      `UPDATE managed_keys SET version = $2, state = $3, allowed_kinds = $4, migration_challenge = $5, retention_days = $6,
         last_used_at = $7, migrated_at = $8, deleted_at = $9, destroyed_at = $10 WHERE key_id = $1`,
      [k.keyId, k.version, k.state, k.allowedKinds ?? null, k.migrationChallenge ?? null, k.retentionDays, ts(k.lastUsed), ts(k.migratedAt), ts(k.deletedAt), ts(k.destroyedAt)],
    );
  }
  async touch(keyId: string, at: number) {
    await this.pool.query('UPDATE managed_keys SET last_used_at = $2 WHERE key_id = $1', [keyId, ts(at)]);
  }
  async recordUsage(u: UsageRecord) {
    await this.pool.query('INSERT INTO managed_key_usage (key_id, at, action, kind, event_id, principal, device_id) VALUES ($1,$2,$3,$4,$5,$6,$7)', [
      u.keyId,
      ts(u.at),
      u.action,
      u.kind ?? null,
      u.eventId ?? null,
      u.principal,
      u.deviceId ?? null,
    ]);
  }
  async usageOf(keyId: string) {
    const { rows } = await this.pool.query<{ at: Date; key_id: string; action: UsageRecord['action']; kind: number | null; event_id: string | null; principal: string; device_id: string | null }>(
      'SELECT at, key_id, action, kind, event_id, principal, device_id FROM managed_key_usage WHERE key_id = $1 ORDER BY at, id',
      [keyId],
    );
    return rows.map((r) => ({
      at: r.at.getTime(),
      keyId: r.key_id,
      action: r.action,
      principal: r.principal,
      ...(r.kind === null ? {} : { kind: r.kind }),
      ...(r.event_id === null ? {} : { eventId: r.event_id }),
      ...(r.device_id === null ? {} : { deviceId: r.device_id }),
    }));
  }
  async purgeUsageBefore(at: number) {
    const r = await this.pool.query('DELETE FROM managed_key_usage WHERE at < $1', [ts(at)]);
    return r.rowCount ?? 0;
  }
  async pendingDestruction(now: number) {
    const { rows } = await this.pool.query<KeyRow>(
      `SELECT * FROM managed_keys WHERE state = 'deleted' AND destroyed_at IS NULL
         AND deleted_at + make_interval(days => retention_days) <= $1 ORDER BY deleted_at`,
      [ts(now)],
    );
    return rows.map(fromRow);
  }
}
