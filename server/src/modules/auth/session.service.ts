/**
 * Session lifecycle: refresh-token rotation with theft detection.
 *
 * The model:
 *   - An access token is a short-lived JWT. It is not stored server-side.
 *   - A refresh token is an opaque 256-bit random string. Only its keyed hash
 *     is stored, so a stolen database yields no usable tokens.
 *   - Each refresh consumes the presented token and issues a new one in the
 *     same *family*. Presenting an already-consumed token means two parties
 *     hold it, so the whole family is revoked immediately.
 *
 * That last rule is the point of the design: without it, a stolen refresh token
 * grants indefinite access, because the thief can keep rotating it.
 */

import type { PoolClient } from '../../database/pool.ts';
import { withTransaction } from '../../database/pool.ts';
import { generateToken, hashToken, isWellFormedToken } from '../../core/tokens.ts';
import { AppError } from '../../core/errors.ts';

export interface SessionDeps {
  /** HMAC key for refresh-token hashing. Lives in the environment, not the DB. */
  readonly refreshPepper: string;
  readonly refreshTtlDays: number;
}

export interface IssuedSession {
  readonly sessionId: string;
  readonly familyId: string;
  /** Returned to the client once. Never logged, never stored. */
  readonly refreshToken: string;
  readonly expiresAt: Date;
}

export interface SessionRow {
  id: string;
  user_id: string;
  device_id: string | null;
  family_id: string;
  expires_at: Date;
  rotated_at: Date | null;
  revoked_at: Date | null;
}

type RevocationReason =
  | 'logout'
  | 'rotation'
  | 'reuse_detected'
  | 'device_revoked'
  | 'admin'
  | 'password_change';

function expiryFromNow(days: number): Date {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

/**
 * Creates a brand-new session family. Used at login, and at registration when
 * the account is created.
 */
export async function createSession(
  client: PoolClient,
  deps: SessionDeps,
  params: {
    userId: string;
    deviceId?: string | undefined;
    userAgent?: string | undefined;
    /** Continue an existing family (rotation) instead of starting a new one. */
    familyId?: string | undefined;
  },
): Promise<IssuedSession> {
  const { token, hash } = generateToken(deps.refreshPepper);
  const expiresAt = expiryFromNow(deps.refreshTtlDays);

  const { rows } = await client.query<{ id: string; family_id: string }>(
    `INSERT INTO auth_sessions
       (user_id, device_id, family_id, refresh_token_hash, expires_at, user_agent)
     VALUES ($1, $2, COALESCE($3, gen_random_uuid()), $4, $5, $6)
     RETURNING id, family_id`,
    [
      params.userId,
      params.deviceId ?? null,
      params.familyId ?? null,
      hash,
      expiresAt,
      // Truncated: a user agent is operational metadata, not a place to store
      // an arbitrary-length client string.
      params.userAgent?.slice(0, 256) ?? null,
    ],
  );

  const row = rows[0];
  if (row === undefined) throw new Error('session insert returned no row');

  return { sessionId: row.id, familyId: row.family_id, refreshToken: token, expiresAt };
}

export interface RotationResult {
  readonly session: IssuedSession;
  readonly userId: string;
  readonly deviceId: string | null;
  /** Session the presented token belonged to, for audit logging. */
  readonly previousSessionId: string;
}

/**
 * Why this is not one transaction.
 *
 * Revoking a session family is a side effect that must SURVIVE the failure that
 * triggered it. Doing the revoke and then throwing inside a single transaction
 * rolls the revoke back, so a stolen token's successor keeps working — which
 * defeats the entire point of reuse detection. Caught by integration test
 * "detects reuse and revokes the whole session family".
 *
 * So the transaction below only decides *what happened*; acting on a failure
 * happens afterwards, in its own committed transaction.
 */
type RotationOutcome =
  | { kind: 'ok'; result: RotationResult }
  | { kind: 'unknown_token' }
  | { kind: 'expired'; userId: string }
  | { kind: 'reuse'; userId: string; familyId: string }
  | { kind: 'device_revoked'; userId: string; deviceId: string | null; familyId: string };

/**
 * Consumes a refresh token and issues its successor.
 *
 * Throws `token_invalid` for anything unusable, deliberately without saying
 * why: an attacker probing tokens learns nothing from the response. The reason
 * goes to the audit log instead.
 */
export async function rotateSession(
  deps: SessionDeps,
  presentedToken: string,
): Promise<RotationResult> {
  if (!isWellFormedToken(presentedToken)) {
    throw new AppError('token_invalid', {
      logMessage: 'refresh token failed shape check',
      securityEvent: true,
    });
  }

  const hash = hashToken(presentedToken, deps.refreshPepper);

  const outcome = await withTransaction<RotationOutcome>(async (client) => {
    // Lock the row: two concurrent refreshes with the same token must not both
    // succeed, or rotation stops being single-use.
    const { rows } = await client.query<SessionRow>(
      `SELECT id, user_id, device_id, family_id, expires_at, rotated_at, revoked_at
         FROM auth_sessions
        WHERE refresh_token_hash = $1
        FOR UPDATE`,
      [hash],
    );

    const session = rows[0];
    if (session === undefined) {
      return { kind: 'unknown_token' };
    }

    // Reuse detection. An already-rotated or already-revoked token being
    // presented means it leaked, so the entire family dies rather than just
    // this row. Revocation happens after this transaction commits.
    if (session.rotated_at !== null || session.revoked_at !== null) {
      return { kind: 'reuse', userId: session.user_id, familyId: session.family_id };
    }

    if (session.expires_at.getTime() <= Date.now()) {
      return { kind: 'expired', userId: session.user_id };
    }

    // A revoked device must not be able to refresh its way back in.
    if (session.device_id !== null) {
      const { rows: deviceRows } = await client.query<{ revoked_at: Date | null }>(
        'SELECT revoked_at FROM devices WHERE id = $1',
        [session.device_id],
      );
      const device = deviceRows[0];
      if (device === undefined || device.revoked_at !== null) {
        return {
          kind: 'device_revoked',
          userId: session.user_id,
          deviceId: session.device_id,
          familyId: session.family_id,
        };
      }
    }

    await client.query(
      `UPDATE auth_sessions
          SET rotated_at = now(), revoked_at = now(), revoked_reason = 'rotation'
        WHERE id = $1`,
      [session.id],
    );

    const issued = await createSession(client, deps, {
      userId: session.user_id,
      deviceId: session.device_id ?? undefined,
      familyId: session.family_id,
    });

    return {
      kind: 'ok',
      result: {
        session: issued,
        userId: session.user_id,
        deviceId: session.device_id,
        previousSessionId: session.id,
      },
    };
  });

  switch (outcome.kind) {
    case 'ok':
      return outcome.result;

    case 'unknown_token':
      throw new AppError('token_invalid', {
        logMessage: 'refresh token not recognised',
        securityEvent: true,
      });

    case 'expired':
      throw new AppError('token_expired', {
        logMessage: 'refresh token expired',
        logContext: { userId: outcome.userId },
      });

    case 'reuse':
      // Committed in its own transaction, so it survives the throw below.
      await revokeFamily(outcome.familyId, 'reuse_detected');
      throw new AppError('token_invalid', {
        logMessage: 'refresh token reuse detected; session family revoked',
        logContext: { userId: outcome.userId, familyId: outcome.familyId },
        securityEvent: true,
      });

    case 'device_revoked':
      await revokeFamily(outcome.familyId, 'device_revoked');
      throw new AppError('device_revoked', {
        logMessage: 'refresh attempted by a revoked or missing device',
        logContext: { userId: outcome.userId, deviceId: outcome.deviceId },
        securityEvent: true,
      });
  }
}

/** Revokes every live session in a family, in its own committed transaction. */
export async function revokeFamily(
  familyId: string,
  reason: RevocationReason,
): Promise<number> {
  return withTransaction(async (client) => {
    const { rowCount } = await client.query(
      `UPDATE auth_sessions
          SET revoked_at = now(), revoked_reason = $2
        WHERE family_id = $1 AND revoked_at IS NULL`,
      [familyId, reason],
    );
    return rowCount ?? 0;
  });
}

/** Revokes one session by its refresh token. Used by logout. */
export async function revokeSessionByToken(
  deps: SessionDeps,
  presentedToken: string,
): Promise<boolean> {
  if (!isWellFormedToken(presentedToken)) return false;
  const hash = hashToken(presentedToken, deps.refreshPepper);

  return withTransaction(async (client) => {
    const { rowCount } = await client.query(
      `UPDATE auth_sessions
          SET revoked_at = now(), revoked_reason = 'logout'
        WHERE refresh_token_hash = $1 AND revoked_at IS NULL`,
      [hash],
    );
    return (rowCount ?? 0) > 0;
  });
}

/** Server-side revocation of every session for a user. */
export async function revokeAllSessionsForUser(
  userId: string,
  reason: RevocationReason,
): Promise<number> {
  return withTransaction(async (client) => {
    const { rowCount } = await client.query(
      `UPDATE auth_sessions
          SET revoked_at = now(), revoked_reason = $2
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId, reason],
    );
    return rowCount ?? 0;
  });
}

/** Server-side revocation of every session bound to a device. */
export async function revokeSessionsForDevice(
  client: PoolClient,
  deviceId: string,
  reason: RevocationReason = 'device_revoked',
): Promise<number> {
  const { rowCount } = await client.query(
    `UPDATE auth_sessions
        SET revoked_at = now(), revoked_reason = $2
      WHERE device_id = $1 AND revoked_at IS NULL`,
    [deviceId, reason],
  );
  return rowCount ?? 0;
}

/**
 * Confirms a session is still live. Called on access-token verification so a
 * revoked session cannot be used for the remainder of the access token's life.
 */
export async function isSessionActive(
  client: PoolClient,
  sessionId: string,
): Promise<boolean> {
  const { rows } = await client.query<{ ok: boolean }>(
    `SELECT (revoked_at IS NULL AND expires_at > now()) AS ok
       FROM auth_sessions WHERE id = $1`,
    [sessionId],
  );
  return rows[0]?.ok ?? false;
}
