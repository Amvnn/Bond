/**
 * Authentication and authorisation guards.
 *
 * The rule this file exists to enforce: authorisation is derived from the
 * verified token, never from anything the client sent in a path, query or body.
 * A handler that reads `request.params.userId` and trusts it has an IDOR.
 * Handlers read `request.auth` instead, which only this file can populate.
 */

// Side-effect import: @fastify/jwt declaration-merges `jwt` onto FastifyInstance.
// Without it, `request.server.jwt` does not exist as far as the compiler knows.
import '@fastify/jwt';
import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from 'fastify';

import { AppError } from '../core/errors.ts';
import { getPool } from '../database/pool.ts';
import { isSessionActive } from '../modules/auth/session.service.ts';

export interface AuthContext {
  readonly userId: string;
  readonly sessionId: string;
  /** Present once the session is bound to a registered device. */
  readonly deviceId: string | undefined;
}

export interface AccessTokenClaims {
  readonly sub: string;
  readonly sid: string;
  readonly did?: string;
  readonly typ: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

function extractBearer(request: FastifyRequest): string {
  const header = request.headers.authorization;
  if (header === undefined) {
    throw new AppError('token_invalid', { logMessage: 'missing authorization header' });
  }
  // Exactly "Bearer <token>". Being lenient here (case-insensitive schemes,
  // extra whitespace, token in a query parameter) widens the surface for no
  // benefit, and a token in a URL ends up in access logs.
  if (!header.startsWith('Bearer ')) {
    throw new AppError('token_invalid', { logMessage: 'malformed authorization header' });
  }
  const token = header.slice('Bearer '.length);
  if (token.length === 0) {
    throw new AppError('token_invalid', { logMessage: 'empty bearer token' });
  }
  return token;
}

/**
 * Verifies the access token, then confirms the session and device are still
 * live. The second half matters: a JWT is valid until it expires, so without a
 * server-side check a revoked session or device keeps working for the rest of
 * the access token's lifetime. Short TTLs shrink that window; this closes it.
 */
export const authenticate: preHandlerHookHandler = async function authenticate(
  request: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  const token = extractBearer(request);

  let claims: AccessTokenClaims;
  try {
    claims = await request.server.jwt.verify<AccessTokenClaims>(token);
  } catch (error) {
    const expired =
      error instanceof Error && /expired/i.test(error.message);
    throw new AppError(expired ? 'token_expired' : 'token_invalid', {
      logMessage: 'access token verification failed',
      cause: error,
    });
  }

  // A refresh token must never be accepted as an access token. They are
  // different secrets with different lifetimes; conflating them would let a
  // long-lived credential act as a short-lived one.
  if (claims.typ !== 'access') {
    throw new AppError('token_invalid', {
      logMessage: 'token presented with wrong type',
      logContext: { presentedType: claims.typ },
      securityEvent: true,
    });
  }

  if (typeof claims.sub !== 'string' || typeof claims.sid !== 'string') {
    throw new AppError('token_invalid', { logMessage: 'access token missing required claims' });
  }

  const client = await getPool().connect();
  try {
    // Device revocation is checked FIRST, deliberately.
    //
    // Revoking a device also revokes its sessions, so checking the session
    // first would answer 401 "credential invalid" — and a client seeing that
    // would prompt the user to log in again, which succeeds, leaving them
    // confused about why nothing works. Checking the device first returns
    // 403 device_revoked, which a client can act on correctly ("this device
    // was removed from your account"). Neither order is less strict; this one
    // is honest about the reason.
    if (claims.did !== undefined) {
      const { rows: deviceRows } = await client.query<{
        user_id: string;
        revoked_at: Date | null;
      }>('SELECT user_id, revoked_at FROM devices WHERE id = $1', [claims.did]);
      const device = deviceRows[0];

      if (device === undefined || device.revoked_at !== null) {
        throw new AppError('device_revoked', {
          logMessage: 'request from a revoked or missing device',
          logContext: { userId: claims.sub, deviceId: claims.did },
          securityEvent: true,
        });
      }
      // Defence in depth: the token says which device, but the database says
      // who owns it. A mismatch means a forged or stale claim.
      if (device.user_id !== claims.sub) {
        throw new AppError('forbidden', {
          logMessage: 'token device does not belong to token subject',
          logContext: { userId: claims.sub, deviceId: claims.did },
          securityEvent: true,
        });
      }
    }

    if (!(await isSessionActive(client, claims.sid))) {
      throw new AppError('token_invalid', {
        logMessage: 'session revoked or expired',
        logContext: { userId: claims.sub, sessionId: claims.sid },
        securityEvent: true,
      });
    }

    // Account status is checked here rather than only at login, so suspending an
    // account takes effect immediately.
    const { rows: userRows } = await client.query<{ status: string }>(
      'SELECT status FROM users WHERE id = $1',
      [claims.sub],
    );
    const user = userRows[0];
    if (user === undefined || user.status !== 'active') {
      throw new AppError('forbidden', {
        logMessage: 'authenticated user is not active',
        logContext: { userId: claims.sub, status: user?.status ?? 'missing' },
        securityEvent: true,
      });
    }
  } finally {
    client.release();
  }

  request.auth = {
    userId: claims.sub,
    sessionId: claims.sid,
    deviceId: claims.did,
  };
};

/** Narrows `request.auth` for handlers behind {@link authenticate}. */
export function requireAuth(request: FastifyRequest): AuthContext {
  if (request.auth === undefined) {
    // Reaching here means a route was registered without the guard.
    throw new AppError('internal_error', {
      logMessage: 'requireAuth called on a route without the authenticate hook',
    });
  }
  return request.auth;
}

/**
 * preHandler form of {@link requireDevice}, for the WebSocket route.
 *
 * This must run BEFORE the upgrade. Calling requireDevice inside a websocket
 * handler is too late: the handshake has already completed, so an
 * account-scoped token gets an open socket and only then an error. Caught by
 * the realtime test "rejects an account-scoped token with no device".
 */
export const requireDeviceSession: preHandlerHookHandler = async function requireDeviceSession(
  request: FastifyRequest,
): Promise<void> {
  requireDevice(request);
};

/**
 * For endpoints that act as a specific device (sending a message, opening a
 * WebSocket). An account-level session is not enough.
 */
export function requireDevice(request: FastifyRequest): AuthContext & { deviceId: string } {
  const auth = requireAuth(request);
  if (auth.deviceId === undefined) {
    throw new AppError('forbidden', {
      logMessage: 'endpoint requires a device-bound session',
      logContext: { userId: auth.userId },
    });
  }
  return { ...auth, deviceId: auth.deviceId };
}
