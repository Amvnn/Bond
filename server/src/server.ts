/**
 * Process entry point.
 *
 * Startup is fail-closed: configuration is validated, then the database and
 * Redis must answer before the HTTP listener opens. A server that accepts
 * requests it cannot serve is worse than one that refuses to start.
 */

import { buildApp } from './app.ts';
import { loadConfig } from './config/env.ts';
import { closeRedis, initRedis, redisHealthy, waitForRedis } from './core/redis.ts';
import { closeDatabase, databaseHealthy, initDatabase } from './database/pool.ts';

async function main(): Promise<void> {
  // Throws on any invalid or placeholder configuration, before anything binds.
  const config = loadConfig();

  initDatabase(config);
  initRedis(config);

  if (!(await databaseHealthy())) {
    throw new Error('database is not reachable; refusing to start');
  }
  await waitForRedis();
  if (!(await redisHealthy())) {
    throw new Error('redis is not reachable; refusing to start');
  }

  const app = await buildApp(config);

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');
    try {
      // Stop accepting first, then drain, then release backends.
      await app.close();
      await Promise.allSettled([closeDatabase(), closeRedis()]);
      process.exit(0);
    } catch (error) {
      app.log.error({ err: error }, 'error during shutdown');
      process.exit(1);
    }
  };

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => void shutdown(signal));
  }

  // An unhandled rejection leaves the process in an unknown state. Log it and
  // exit rather than continuing to serve from a corrupt one.
  process.on('unhandledRejection', (reason) => {
    app.log.fatal({ err: reason }, 'unhandled rejection');
    void shutdown('unhandledRejection');
  });

  await app.listen({ port: config.port, host: '127.0.0.1' });
  app.log.info(
    { port: config.port, env: config.nodeEnv },
    'listening (bind 127.0.0.1; expose only through the reverse proxy)',
  );
}

main().catch((error: unknown) => {
  process.stderr.write(
    `startup failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
