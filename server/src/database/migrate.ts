/**
 * Minimal forward-only migration runner.
 *
 * Deliberately not a migration framework: each file in migrations/ is applied
 * once, in filename order, inside a transaction, and recorded with a checksum.
 * A changed checksum on an already-applied file is a hard failure — silently
 * editing applied migrations is how schemas drift apart between environments.
 */

import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import { loadConfig } from '../config/env.ts';
import { closeDatabase, getPool, initDatabase } from './pool.ts';

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'migrations');

const TRACKING_TABLE = `
  CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    TEXT        PRIMARY KEY,
    checksum    TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
  )
`;

function checksum(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export async function runMigrations(): Promise<void> {
  const pool = getPool();
  await pool.query(TRACKING_TABLE);

  const files = (await readdir(MIGRATIONS_DIR))
    .filter((name) => name.endsWith('.sql'))
    .sort();

  const { rows: applied } = await pool.query<{ filename: string; checksum: string }>(
    'SELECT filename, checksum FROM schema_migrations',
  );
  const appliedByName = new Map(applied.map((row) => [row.filename, row.checksum]));

  let appliedCount = 0;

  for (const filename of files) {
    const content = await readFile(join(MIGRATIONS_DIR, filename), 'utf8');
    const digest = checksum(content);
    const previous = appliedByName.get(filename);

    if (previous !== undefined) {
      if (previous !== digest) {
        throw new Error(
          `Migration ${filename} has changed since it was applied. ` +
            'Applied migrations are immutable; add a new migration instead.',
        );
      }
      continue;
    }

    const client = await pool.connect();
    try {
      // The migration file supplies its own BEGIN/COMMIT, so the tracking
      // insert is committed separately and immediately after.
      await client.query(content);
      await client.query(
        'INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)',
        [filename, digest],
      );
      process.stdout.write(`applied ${filename}\n`);
      appliedCount += 1;
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Nothing to roll back if the file committed itself.
      }
      throw new Error(
        `Migration ${filename} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      client.release();
    }
  }

  process.stdout.write(
    appliedCount === 0
      ? 'schema up to date, nothing to apply\n'
      : `${appliedCount} migration(s) applied\n`,
  );
}

/** CLI entry point: `npm run migrate`. */
async function main(): Promise<void> {
  const config = loadConfig();
  initDatabase(config);
  try {
    await runMigrations();
  } finally {
    await closeDatabase();
  }
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
