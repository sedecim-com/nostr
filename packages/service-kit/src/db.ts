import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';

export type Pool = pg.Pool;

export function createPgPool(connectionString: string): pg.Pool {
  return new pg.Pool({ connectionString, max: 10 });
}

/** Applies *.sql files from a directory in lexical order, once each (tracked in schema_migrations). */
export async function migrate(pool: pg.Pool, dir: string, scope: string): Promise<string[]> {
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (scope text NOT NULL, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (scope, name))');
  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
  const applied: string[] = [];
  for (const f of files) {
    const { rowCount } = await pool.query('SELECT 1 FROM schema_migrations WHERE scope = $1 AND name = $2', [scope, f]);
    if (rowCount) continue;
    const sql = await readFile(join(dir, f), 'utf8');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (scope, name) VALUES ($1, $2)', [scope, f]);
      await client.query('COMMIT');
      applied.push(f);
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
  return applied;
}

/** Test helper: drop a service's tables and forget its migrations so they re-run cleanly. */
export async function resetScope(pool: pg.Pool, scope: string, tables: string[]): Promise<void> {
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (scope text NOT NULL, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (scope, name))');
  await pool.query(`DROP TABLE IF EXISTS ${tables.join(', ')} CASCADE`);
  await pool.query('DELETE FROM schema_migrations WHERE scope = $1', [scope]);
}
