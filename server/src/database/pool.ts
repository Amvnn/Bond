/**
 * PostgreSQL access.
 *
 * Every query in this codebase goes through `query` or `withTransaction` and
 * uses parameterised placeholders. There is no string-concatenated SQL
 * anywhere, and adding any would be a security defect, not a style choice.
 */

import { Pool, type PoolClient, type QueryResultRow } from 'pg';
import type { Config } from '../config/env.ts';

let pool: Pool | undefined;

export function initDatabase(config: Config): Pool {
  if (pool) return pool;

  pool = new Pool({
    connectionString: config.databaseUrl,
    ssl: config.databaseSsl ? { rejectUnauthorized: true } : false,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    // Bound how long a single statement may run. An unbounded statement is a
    // denial-of-service surface.
    statement_timeout: 10_000,
    query_timeout: 10_000,
  });

  // An idle-client error must not take the process down silently.
  pool.on('error', (error) => {
    process.emitWarning(`postgres idle client error: ${error.message}`);
  });

  return pool;
}

export function getPool(): Pool {
  if (!pool) throw new Error('Database not initialised. Call initDatabase first.');
  return pool;
}

/**
 * Parameterised query. `params` are bound by the driver and never interpolated.
 */
export async function query<T extends QueryResultRow>(
  sql: string,
  params: readonly unknown[] = [],
): Promise<T[]> {
  const result = await getPool().query<T>(sql, params as unknown[]);
  return result.rows;
}

/**
 * Exactly-one-row query. Returns undefined when nothing matched, and throws if
 * more than one row came back, which means the query or a constraint is wrong.
 */
export async function queryOne<T extends QueryResultRow>(
  sql: string,
  params: readonly unknown[] = [],
): Promise<T | undefined> {
  const rows = await query<T>(sql, params);
  if (rows.length > 1) {
    throw new Error(`Expected at most one row, received ${rows.length}`);
  }
  return rows[0];
}

/**
 * Runs `fn` inside a transaction, rolling back on any thrown error.
 *
 * Security-relevant operations that must be atomic use this: consuming an
 * invitation (single-use), consuming a one-time prekey (never reused), and
 * rotating a refresh token (reuse detection).
 */
export async function withTransaction<T>(
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // A failed rollback must not mask the original error.
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function closeDatabase(): Promise<void> {
  if (!pool) return;
  const current = pool;
  pool = undefined;
  await current.end();
}

/** Liveness check for the health endpoint and for startup ordering. */
export async function databaseHealthy(): Promise<boolean> {
  try {
    await query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}

export type { PoolClient };
