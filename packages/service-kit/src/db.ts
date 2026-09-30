import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';
import { activeSpan, inChildSpan } from '@sedecim/telemetry-policy';

export type Pool = pg.Pool;

export function createPgPool(connectionString: string): pg.Pool {
  return traceQueries(new pg.Pool({ connectionString, max: 10 }));
}

/**
 * NFR007-02: promise-style `pool.query` calls made inside a sampled trace become `db.query` child spans that only
 * carry the first keyword of the statement, never the SQL or its values. Outside a recorded trace, and for callback
 * or submittable queries, the call goes straight through.
 */
export function traceQueries(pool: pg.Pool): pg.Pool {
  const query = pool.query.bind(pool) as unknown as (...args: unknown[]) => unknown;
  pool.query = ((...args: unknown[]) => {
    const first = args[0] as { submit?: unknown; text?: unknown } | string | null | undefined;
    if (!activeSpan() || typeof args[args.length - 1] === 'function' || (typeof first === 'object' && typeof first?.submit === 'function')) return query(...args);
    const text = typeof first === 'string' ? first : typeof first?.text === 'string' ? first.text : '';
    const attributes = { 'db.system': 'postgresql', 'db.operation.name': /^\s*([A-Za-z]+)/.exec(text)?.[1]?.toUpperCase() ?? '_OTHER' };
    return inChildSpan('db.query', () => query(...args), { kind: 'client', attributes });
  }) as unknown as typeof pool.query;
  return pool;
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
