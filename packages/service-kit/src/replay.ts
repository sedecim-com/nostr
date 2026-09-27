import { fileURLToPath } from 'node:url';
import type pg from 'pg';
import { migrate } from './db';

/**
 * NIP-98 anti-replay (IR-2026-09-04): each accepted auth event id is usable once until it leaves the
 * ±60 s window. `use` must be atomic: of N concurrent calls with the same id exactly one returns true.
 */
export interface ReplayStore {
  /** Records `eventId` until `expiresAt` (unix seconds); false if it was already recorded. */
  use(eventId: string, expiresAt: number): Promise<boolean>;
  close?(): Promise<void> | void;
}

export class ReplayStoreFullError extends Error {}

/** Per-process store (default). With several replicas an event can be replayed once per replica. */
export class MemoryReplayStore implements ReplayStore {
  private readonly seen = new Map<string, number>();
  private nextSweep = 0;

  constructor(private readonly opts: { maxEntries?: number; now?: () => number } = {}) {}

  private nowS() {
    return (this.opts.now?.() ?? Date.now()) / 1000;
  }

  private sweep(now: number) {
    for (const [id, exp] of this.seen) if (exp < now) this.seen.delete(id);
    this.nextSweep = now + 10;
  }

  async use(eventId: string, expiresAt: number): Promise<boolean> {
    const now = this.nowS();
    const max = this.opts.maxEntries ?? 200_000;
    if (now >= this.nextSweep || this.seen.size >= max) this.sweep(now);
    const exp = this.seen.get(eventId);
    if (exp !== undefined && exp >= now) return false;
    // Evicting live ids would reopen replays: refuse instead (the rate limiter keeps this far away).
    if (this.seen.size >= max) throw new ReplayStoreFullError('replay cache full');
    this.seen.set(eventId, expiresAt);
    return true;
  }

  get size() {
    return this.seen.size;
  }
}

/** Table `nip98_replay`, shared by every service and replica using the same database. */
export const REPLAY_MIGRATIONS_DIR = fileURLToPath(new URL('../migrations', import.meta.url));

/** Creates the shared table (idempotent; tracked under the `service-kit` migration scope). */
export async function migrateReplayStore(pool: pg.Pool): Promise<void> {
  // Several services (and replicas) share this scope and may start at once: serialize them.
  const lock = await pool.connect();
  try {
    await lock.query("SELECT pg_advisory_lock(hashtext('sedecim:service-kit:migrate'))");
    await migrate(pool, REPLAY_MIGRATIONS_DIR, 'service-kit');
  } finally {
    await lock.query("SELECT pg_advisory_unlock(hashtext('sedecim:service-kit:migrate'))").catch(() => {});
    lock.release();
  }
}

/**
 * Postgres store shared across replicas: `INSERT … ON CONFLICT DO NOTHING` decides atomically which
 * request wins. Expired rows are deleted periodically (with a grace period for clock skew).
 */
export class PgReplayStore implements ReplayStore {
  private readonly timer?: NodeJS.Timeout;

  constructor(private readonly pool: pg.Pool, opts: { cleanupIntervalMs?: number } = {}) {
    const every = opts.cleanupIntervalMs ?? 60_000;
    if (every > 0) {
      this.timer = setInterval(() => void this.cleanup().catch(() => {}), every);
      this.timer.unref();
    }
  }

  async use(eventId: string, expiresAt: number): Promise<boolean> {
    const r = await this.pool.query('INSERT INTO nip98_replay (event_id, expires_at) VALUES ($1, to_timestamp($2::double precision)) ON CONFLICT (event_id) DO NOTHING', [eventId, expiresAt]);
    return r.rowCount === 1;
  }

  /** Deletes rows expired more than a minute ago; returns how many. */
  async cleanup(): Promise<number> {
    const r = await this.pool.query("DELETE FROM nip98_replay WHERE expires_at < now() - interval '60 seconds'");
    return r.rowCount ?? 0;
  }

  close() {
    if (this.timer) clearInterval(this.timer);
  }
}
