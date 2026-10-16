/**
 * Redis access.
 *
 * Redis holds only ephemeral operational state: presence, the connection
 * registry and rate-limit counters. Nothing durable, and nothing secret — the
 * dev container runs with persistence disabled precisely so a stolen disk
 * yields nothing.
 *
 * Never store in Redis: plaintext, ciphertext, private keys, tokens.
 */

import { Redis } from 'ioredis';

import type { Config } from '../config/env.ts';

let client: Redis | undefined;

export function initRedis(config: Config): Redis {
  if (client) return client;

  client = new Redis(config.redisUrl, {
    // Fail fast rather than queueing commands forever behind a dead Redis.
    maxRetriesPerRequest: 3,
    enableOfflineQueue: false,
    lazyConnect: false,
    connectTimeout: 5_000,
  });

  client.on('error', (error: Error) => {
    process.emitWarning(`redis error: ${error.message}`);
  });

  return client;
}

export function getRedis(): Redis {
  if (!client) throw new Error('Redis not initialised. Call initRedis first.');
  return client;
}

/**
 * Waits until the connection is usable.
 *
 * `initRedis` returns as soon as connecting STARTS, and `enableOfflineQueue` is
 * false by design (fail fast rather than queue behind a dead Redis) — so a
 * command issued in between throws "Stream isn't writeable". Anything that
 * touches Redis during startup must await this first.
 */
export async function waitForRedis(timeoutMs = 10_000): Promise<void> {
  const current = getRedis();
  if (current.status === 'ready') return;

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      current.off('ready', onReady);
      reject(new Error(`redis did not become ready within ${timeoutMs}ms`));
    }, timeoutMs);

    function onReady(): void {
      clearTimeout(timer);
      current.off('ready', onReady);
      resolve();
    }

    current.once('ready', onReady);
  });
}

export async function closeRedis(): Promise<void> {
  if (!client) return;
  const current = client;
  client = undefined;
  await current.quit().catch(() => current.disconnect());
}

export async function redisHealthy(): Promise<boolean> {
  try {
    return (await getRedis().ping()) === 'PONG';
  } catch {
    return false;
  }
}
