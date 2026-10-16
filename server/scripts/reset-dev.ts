/**
 * Resets the development database and rate-limit counters.
 *
 * Why this exists as its own script: the invite-only model means user #1 can
 * only be created through the env-gated bootstrap path, and that path refuses
 * once any user exists. So any end-to-end run that starts from "nobody has an
 * account" — the demo, and the Flutter client's vertical-slice test — needs the
 * database empty first, and each of them reimplementing the reset would be
 * three places to keep correct.
 *
 * It also clears Redis rate-limit counters. Those are keyed per IP with
 * hour-long windows, so a previous run from 127.0.0.1 will throttle the next
 * one and the failure looks like a bug in the thing being tested.
 *
 * TRUNCATES THE DATABASE IT POINTS AT. It refuses to run against a production
 * configuration, but there is no second safety net: do not point it anywhere
 * you care about.
 */

import { loadConfig } from '../src/config/env.ts';
import { closeRedis, initRedis, waitForRedis } from '../src/core/redis.ts';
import { closeDatabase, initDatabase, query } from '../src/database/pool.ts';

async function main(): Promise<void> {
  process.env['LOG_LEVEL'] = process.env['LOG_LEVEL'] ?? 'silent';

  const config = loadConfig();
  if (config.isProduction) {
    throw new Error('refusing to reset a production configuration');
  }

  initDatabase(config);
  const redis = initRedis(config);
  await waitForRedis();

  try {
    // users cascades to devices, sessions, prekeys, invitations, friendships
    // and messages. security_events has no user FK in every case, so it is
    // named explicitly rather than relied on to cascade.
    await query('TRUNCATE users, security_events RESTART IDENTITY CASCADE');

    const limitKeys = await redis.keys('fastify-rate-limit-*');
    if (limitKeys.length > 0) await redis.del(...limitKeys);

    process.stdout.write(
      `reset: database truncated, ${limitKeys.length} rate-limit keys cleared\n`,
    );
  } finally {
    await closeRedis();
    await closeDatabase();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`reset failed: ${String(error)}\n`);
  process.exitCode = 1;
});
