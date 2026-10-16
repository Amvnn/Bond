/**
 * Authenticated WebSocket endpoint.
 *
 * Authentication uses the ordinary Authorization header via the same
 * `authenticate` hook as every REST route — deliberately NOT a token in the
 * query string, which would land the credential in access logs. Native clients
 * (dart:io) can set headers on a WebSocket handshake; there is no browser
 * client in Phase 1, so nothing needs the query-string fallback.
 *
 * The socket carries notifications only. See hub.ts for why.
 */

import { Type } from '@sinclair/typebox';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { WebSocket } from 'ws';

import type { Config } from '../config/env.ts';
import {
  authenticate,
  requireDevice,
  requireDeviceSession,
} from '../middleware/authenticate.ts';
import { touchDeviceLastSeen } from '../modules/devices/devices.service.ts';
import { fetchQueued } from '../modules/messages/messages.service.ts';
import { recordSecurityEvent } from '../modules/security/security-events.ts';
import type { RealtimeHub } from './hub.ts';

const PING_INTERVAL_MS = 30_000;
/** Two missed pongs closes the socket. */
const MAX_MISSED_PONGS = 2;
/** Client frames are tiny by design; anything larger is rejected unparsed. */
const MAX_CLIENT_FRAME_BYTES = 1_024;

export function registerWebSocketRoutes(
  app: FastifyInstance,
  hub: RealtimeHub,
  config: Config,
): void {
  app.get(
    '/ws',
    {
      websocket: true,
      // Both hooks run before the upgrade, so an unauthorised handshake never
      // becomes an open socket.
      preHandler: [authenticate, requireDeviceSession],
      config: {
        rateLimit: { max: config.rateLimits.wsConnectPerMinute, timeWindow: '1 minute' },
      },
      schema: {
        // Documented for the generated API surface; the handshake carries no body.
        response: { 101: Type.Null() },
      },
    },
    async (socket: WebSocket, request: FastifyRequest) => {
      // Throws if the session is account-scoped rather than device-scoped, and
      // `authenticate` has already rejected revoked devices and dead sessions.
      const auth = requireDevice(request);
      const deviceId = auth.deviceId;

      // One wrapper object, reused for register and unregister. The hub stores
      // it by identity, so constructing a second equivalent object on teardown
      // would silently leak the registration.
      const handle = {
        send: (data: string) => socket.send(data),
        close: (code?: number, reason?: string) => socket.close(code, reason),
      };

      const accepted = await hub.register(deviceId, handle);

      if (!accepted) {
        await recordSecurityEvent(request.log, {
          type: 'ws.rejected_revoked_device',
          userId: auth.userId,
          deviceId,
          metadata: { reason: 'too_many_connections' },
        });
        socket.close(4429, 'too many connections for this device');
        return;
      }

      await recordSecurityEvent(request.log, {
        type: 'ws.connected',
        userId: auth.userId,
        deviceId,
      });
      await touchDeviceLastSeen(deviceId);

      // Tell the client whether it has catching up to do. The queue itself is
      // fetched over HTTPS; this is only a hint so it need not poll blindly.
      const queued = await fetchQueued(deviceId, 1);
      socket.send(
        JSON.stringify({
          type: 'ready',
          deviceId,
          hasQueuedMessages: queued.length > 0,
          at: new Date().toISOString(),
        }),
      );

      let missedPongs = 0;
      let alive = true;

      const heartbeat = setInterval(() => {
        if (!alive) return;
        if (missedPongs >= MAX_MISSED_PONGS) {
          // A half-open connection looks alive to the OS but never answers.
          // Closing it frees the slot and lets the client reconnect.
          request.log.info({ deviceId }, 'closing unresponsive websocket');
          socket.terminate();
          return;
        }
        missedPongs += 1;
        try {
          socket.ping();
        } catch {
          socket.terminate();
        }
      }, PING_INTERVAL_MS);

      socket.on('pong', () => {
        missedPongs = 0;
        void hub.touchPresence(deviceId);
      });

      socket.on('message', (raw: Buffer | ArrayBuffer | Buffer[]) => {
        const size = Buffer.isBuffer(raw)
          ? raw.length
          : Array.isArray(raw)
            ? raw.reduce((total, chunk) => total + chunk.length, 0)
            : raw.byteLength;

        // Reject before parsing: an oversized frame is never worth decoding.
        if (size > MAX_CLIENT_FRAME_BYTES) {
          request.log.warn({ deviceId, size }, 'oversized websocket frame rejected');
          socket.close(1009, 'frame too large');
          return;
        }

        // The client has nothing it must say over this socket. Keep-alive is
        // accepted; everything else is ignored rather than interpreted, so the
        // socket is not a second command surface.
        try {
          const parsed: unknown = JSON.parse(raw.toString());
          if (
            typeof parsed === 'object' &&
            parsed !== null &&
            (parsed as { type?: unknown }).type === 'ping'
          ) {
            missedPongs = 0;
            socket.send(JSON.stringify({ type: 'pong', at: new Date().toISOString() }));
            void hub.touchPresence(deviceId);
          }
        } catch {
          // Malformed JSON is ignored, not an error worth closing over.
        }
      });

      const teardown = (): void => {
        if (!alive) return;
        alive = false;
        clearInterval(heartbeat);
        void hub.unregister(deviceId, handle);
        void recordSecurityEvent(request.log, {
          type: 'ws.disconnected',
          userId: auth.userId,
          deviceId,
        });
      };

      socket.on('close', teardown);
      socket.on('error', (error: Error) => {
        request.log.debug({ deviceId, err: error.message }, 'websocket error');
        teardown();
      });
    },
  );
}

export { MAX_CLIENT_FRAME_BYTES, PING_INTERVAL_MS };
