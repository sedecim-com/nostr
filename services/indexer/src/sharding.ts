import { createHash } from 'node:crypto';
import type { Pool } from '@sedecim/service-kit';

/**
 * NFR005-01: coordination of N indexer replicas. Membership is a heartbeat table; each shard (a relay, or a
 * relay + channel) belongs to the replica chosen by rendezvous hashing over the live members, so every
 * replica computes the same assignment and only the shards of a replica that joins or leaves move.
 * Assignment views may briefly disagree during a change: two replicas then mirror the same shard (harmless,
 * writes are idempotent) or nobody does for up to one TTL (covered by the per-shard checkpoints).
 */
export interface ShardCoordinator {
  /** Records a heartbeat for `replicaId` and returns the live replicas (itself included), sorted. */
  heartbeat(replicaId: string, ttlMs: number): Promise<string[]>;
  /** Graceful exit: the replica's shards move on the others' next heartbeat instead of after the TTL. */
  leave(replicaId: string): Promise<void>;
  /** synced_until (unix seconds) of the given shards; missing keys were never synced. */
  checkpoints(keys: string[]): Promise<Map<string, number>>;
  /** Moves checkpoints forward (never back). */
  saveCheckpoints(entries: Map<string, number>, by: string): Promise<void>;
  /** Atomically claims a cluster-wide job; true for exactly one caller per interval. */
  claimJob(job: string, intervalMs: number, by: string): Promise<boolean>;
}

function score(member: string, key: string): string {
  return createHash('sha256').update(member).update('\n').update(key).digest('hex');
}

/** Rendezvous (highest random weight) owner of a shard key. */
export function shardOwner(key: string, members: readonly string[]): string | undefined {
  let best: string | undefined;
  let bestScore = '';
  for (const m of members) {
    const s = score(m, key);
    if (best === undefined || s > bestScore || (s === bestScore && m < best)) {
      best = m;
      bestScore = s;
    }
  }
  return best;
}

export const relayShard = (relay: string) => `relay:${relay}`;
export const channelShard = (relay: string, h: string) => `channel:${relay}#${h}`;

/** In-process coordinator: a single replica (no database), or several indexers sharing it in tests. */
export class MemoryShardCoordinator implements ShardCoordinator {
  private readonly beats = new Map<string, number>();
  private readonly cps = new Map<string, number>();
  private readonly jobs = new Map<string, number>();

  async heartbeat(replicaId: string, ttlMs: number): Promise<string[]> {
    const now = Date.now();
    this.beats.set(replicaId, now);
    return [...this.beats].filter(([, at]) => now - at < ttlMs).map(([id]) => id).sort();
  }

  async leave(replicaId: string): Promise<void> {
    this.beats.delete(replicaId);
  }

  async checkpoints(keys: string[]): Promise<Map<string, number>> {
    return new Map(keys.filter((k) => this.cps.has(k)).map((k) => [k, this.cps.get(k)!]));
  }

  async saveCheckpoints(entries: Map<string, number>): Promise<void> {
    for (const [k, v] of entries) this.cps.set(k, Math.max(this.cps.get(k) ?? 0, v));
  }

  async claimJob(job: string, intervalMs: number): Promise<boolean> {
    const now = Date.now();
    const last = this.jobs.get(job);
    if (last !== undefined && now - last < intervalMs) return false;
    this.jobs.set(job, now);
    return true;
  }
}

/** Coordinator over the mirror's Postgres (migration 003). Times use the database clock. */
export class PgShardCoordinator implements ShardCoordinator {
  constructor(private readonly pool: Pool) {}

  async heartbeat(replicaId: string, ttlMs: number): Promise<string[]> {
    await this.pool.query('INSERT INTO indexer_replicas (replica_id) VALUES ($1) ON CONFLICT (replica_id) DO UPDATE SET heartbeat_at = now()', [replicaId]);
    // Rows of replicas long gone are dropped so the table does not grow with every pod name.
    await this.pool.query('DELETE FROM indexer_replicas WHERE heartbeat_at < now() - make_interval(secs => $1)', [(ttlMs * 20) / 1000]);
    const { rows } = await this.pool.query<{ replica_id: string }>(
      'SELECT replica_id FROM indexer_replicas WHERE heartbeat_at > now() - make_interval(secs => $1) ORDER BY replica_id',
      [ttlMs / 1000],
    );
    return rows.map((r) => r.replica_id);
  }

  async leave(replicaId: string): Promise<void> {
    await this.pool.query('DELETE FROM indexer_replicas WHERE replica_id = $1', [replicaId]);
  }

  async checkpoints(keys: string[]): Promise<Map<string, number>> {
    if (!keys.length) return new Map();
    const { rows } = await this.pool.query<{ shard_key: string; synced_until: string }>('SELECT shard_key, synced_until FROM indexer_checkpoints WHERE shard_key = ANY($1)', [keys]);
    return new Map(rows.map((r) => [r.shard_key, Number(r.synced_until)]));
  }

  async saveCheckpoints(entries: Map<string, number>, by: string): Promise<void> {
    if (!entries.size) return;
    await this.pool.query(
      `INSERT INTO indexer_checkpoints (shard_key, synced_until, updated_by)
       SELECT k, v, $3 FROM unnest($1::text[], $2::bigint[]) AS t(k, v)
       ON CONFLICT (shard_key) DO UPDATE SET synced_until = GREATEST(indexer_checkpoints.synced_until, EXCLUDED.synced_until), updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [[...entries.keys()], [...entries.values()], by],
    );
  }

  async claimJob(job: string, intervalMs: number, by: string): Promise<boolean> {
    // ON CONFLICT DO UPDATE locks the row and re-checks the WHERE on its latest version: one winner.
    const r = await this.pool.query(
      `INSERT INTO indexer_jobs (job, last_run_at, run_by) VALUES ($1, now(), $3)
       ON CONFLICT (job) DO UPDATE SET last_run_at = now(), run_by = EXCLUDED.run_by
       WHERE indexer_jobs.last_run_at <= now() - make_interval(secs => $2) RETURNING job`,
      [job, intervalMs / 1000, by],
    );
    return r.rowCount === 1;
  }
}
