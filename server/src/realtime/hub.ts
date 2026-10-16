/**
 * WebSocket connection registry and fan-out.
 *
 * A deliberate design choice: the socket carries NOTIFICATIONS, never message
 * bodies. A client is told "there is something for you" and fetches it over
 * HTTPS. Two consequences, both good:
 *
 *   1. There is exactly one authorisation path for message bodies, instead of
 *      one for REST and a second, easier-to-get-wrong one for sockets.
 *   2. Duplicate or stale connections cannot corrupt delivery. Both sockets get
 *      the notification, both fetch, and acknowledgement is idempotent — so the
 *      "duplicate active connection" hazard in the brief is designed out rather
 *      than guarded against.
 */

import type { Redis } from 'ioredis';
import type { FastifyBaseLogger } from 'fastify';

import { getRedis } from '../core/redis.ts';
import { deviceChannel, type RealtimeEvent } from './dispatch.ts';

/** Cap per device: enough for a reconnect overlapping an old socket, not more. */
const MAX_CONNECTIONS_PER_DEVICE = 4;

/** Presence key TTL. Refreshed on every heartbeat. */
const PRESENCE_TTL_SECONDS = 90;

export interface Sendable {
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export class RealtimeHub {
  private readonly sockets = new Map<string, Set<Sendable>>();
  private readonly subscriber: Redis;
  private closed = false;

  constructor(private readonly logger: FastifyBaseLogger) {
    // A connection in subscribe mode cannot issue normal commands, so the
    // subscriber must be separate from the command client.
    this.subscriber = getRedis().duplicate();

    this.subscriber.on('message', (channel: string, payload: string) => {
      this.deliverLocally(channel, payload);
    });
    this.subscriber.on('error', (error: Error) => {
      this.logger.warn({ err: error.message }, 'realtime subscriber error');
    });
  }

  /**
   * Registers a socket for a device. Returns false when the device already has
   * too many connections, in which case the caller must close the new one.
   */
  async register(deviceId: string, socket: Sendable): Promise<boolean> {
    if (this.closed) return false;

    let set = this.sockets.get(deviceId);
    if (set !== undefined && set.size >= MAX_CONNECTIONS_PER_DEVICE) {
      return false;
    }

    if (set === undefined) {
      set = new Set();
      this.sockets.set(deviceId, set);
      // Subscribe once per device, on the first socket.
      await this.subscriber.subscribe(deviceChannel(deviceId));
    }
    set.add(socket);

    await getRedis().set(presenceKey(deviceId), '1', 'EX', PRESENCE_TTL_SECONDS);
    return true;
  }

  async unregister(deviceId: string, socket: Sendable): Promise<void> {
    const set = this.sockets.get(deviceId);
    if (set === undefined) return;

    set.delete(socket);
    if (set.size > 0) return;

    this.sockets.delete(deviceId);
    try {
      await this.subscriber.unsubscribe(deviceChannel(deviceId));
      await getRedis().del(presenceKey(deviceId));
    } catch (error) {
      this.logger.warn(
        { err: error instanceof Error ? error.message : String(error) },
        'failed to clean up realtime subscription',
      );
    }
  }

  /** Refreshes presence. Called on each heartbeat so a dead socket expires. */
  async touchPresence(deviceId: string): Promise<void> {
    try {
      await getRedis().set(presenceKey(deviceId), '1', 'EX', PRESENCE_TTL_SECONDS);
    } catch {
      // Presence is a convenience, not a correctness requirement.
    }
  }

  async isOnline(deviceId: string): Promise<boolean> {
    return (await getRedis().exists(presenceKey(deviceId))) === 1;
  }

  localConnectionCount(deviceId: string): number {
    return this.sockets.get(deviceId)?.size ?? 0;
  }

  /** Closes every socket for a device. Used when a device is revoked. */
  closeDevice(deviceId: string, reason: string): void {
    const set = this.sockets.get(deviceId);
    if (set === undefined) return;
    for (const socket of set) {
      try {
        socket.close(4403, reason);
      } catch {
        // Already gone.
      }
    }
  }

  private deliverLocally(channel: string, payload: string): void {
    for (const [deviceId, set] of this.sockets) {
      if (deviceChannel(deviceId) !== channel) continue;

      for (const socket of set) {
        try {
          socket.send(payload);
        } catch (error) {
          this.logger.debug(
            { err: error instanceof Error ? error.message : String(error) },
            'failed to write to socket',
          );
        }
      }

      // Revocation must take effect on connections that are already open,
      // whichever instance holds them — otherwise a revoked device keeps
      // receiving notifications until it happens to disconnect.
      if (isRevocation(payload)) {
        this.logger.info({ deviceId }, 'closing sockets for revoked device');
        this.closeDevice(deviceId, 'device revoked');
      }
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const [deviceId] of this.sockets) {
      this.closeDevice(deviceId, 'server shutting down');
    }
    this.sockets.clear();
    await this.subscriber.quit().catch(() => this.subscriber.disconnect());
  }
}

export function serialiseEvent(event: RealtimeEvent): string {
  return JSON.stringify(event);
}

function presenceKey(deviceId: string): string {
  return `pm:presence:${deviceId}`;
}

/** Payloads arrive as opaque strings from Redis, so parse defensively. */
function isRevocation(payload: string): boolean {
  try {
    const parsed: unknown = JSON.parse(payload);
    return (
      typeof parsed === 'object' &&
      parsed !== null &&
      (parsed as { type?: unknown }).type === 'device.revoked'
    );
  } catch {
    return false;
  }
}

export { MAX_CONNECTIONS_PER_DEVICE, PRESENCE_TTL_SECONDS };
