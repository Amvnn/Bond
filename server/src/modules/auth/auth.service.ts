/**
 * Account registration and login.
 *
 * Registration is invite-controlled. The invitation both authorises the account
 * and establishes the friendship, per docs/decisions.md D3. Consumption is
 * atomic: the invitation row is locked, validated and marked used inside the
 * same transaction that creates the account, so two concurrent redemptions of
 * one token cannot both succeed.
 *
 * Nothing in this module logs or returns a password, a token, or a hash.
 */

import type { FastifyBaseLogger } from 'fastify';

import { AppError, authenticationFailed } from '../../core/errors.ts';
import { queryOne, withTransaction } from '../../database/pool.ts';
// Invitation claiming, consumption and friendship creation are shared with the
// invitations module so single-use enforcement exists in exactly one place.
import {
  claimInvitation,
  consumeInvitation,
  createFriendship,
  type InvitationRow,
} from '../invitations/invitations.service.ts';
import { recordSecurityEvent } from '../security/security-events.ts';
import {
  hashPassword,
  needsRehash,
  spendVerificationTime,
  verifyPassword,
} from './password.ts';
import { createSession, type IssuedSession, type SessionDeps } from './session.service.ts';

export interface AuthDeps extends SessionDeps {
  /** HMAC key for invitation-token hashing. Distinct from the refresh pepper. */
  readonly invitationPepper: string;
  readonly allowBootstrapAccount: boolean;
}

export interface RegisterParams {
  readonly username: string;
  readonly password: string;
  /** Omitted only on the bootstrap path, which creates user #1. */
  readonly invitationToken?: string | undefined;
  readonly userAgent?: string | undefined;
}

export interface AuthResult {
  readonly userId: string;
  readonly session: IssuedSession;
}

const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;

function normaliseUsername(raw: string): string {
  const username = raw.trim().toLowerCase();
  if (!USERNAME_PATTERN.test(username)) {
    throw new AppError('validation_failed', {
      logMessage: 'username failed shape policy',
      logContext: { length: username.length },
    });
  }
  return username;
}

export async function register(
  logger: FastifyBaseLogger,
  deps: AuthDeps,
  params: RegisterParams,
): Promise<AuthResult> {
  const username = normaliseUsername(params.username);
  // Hash before opening the transaction: Argon2id at 64 MiB takes real time and
  // holding a database transaction open across it wastes a connection.
  const passwordHash = await hashPassword(params.password);

  const bootstrap = params.invitationToken === undefined;
  if (bootstrap && !deps.allowBootstrapAccount) {
    throw new AppError('invitation_unusable', {
      logMessage: 'registration attempted without an invitation while bootstrap is disabled',
      securityEvent: true,
    });
  }

  const result = await withTransaction(async (client) => {
    let invitation: InvitationRow | undefined;

    if (params.invitationToken !== undefined) {
      invitation = await claimInvitation(client, deps.invitationPepper, params.invitationToken);
    } else {
      // The bootstrap path may create user #1 and nobody else. Checked inside
      // the transaction so it cannot race a second bootstrap request.
      const { rows } = await client.query<{ count: string }>('SELECT count(*) FROM users');
      if ((rows[0]?.count ?? '0') !== '0') {
        throw new AppError('invitation_unusable', {
          logMessage: 'bootstrap registration attempted when users already exist',
          securityEvent: true,
        });
      }
    }

    let userId: string;
    try {
      const { rows } = await client.query<{ id: string }>(
        `INSERT INTO users (username, invited_by_user_id)
         VALUES ($1, $2)
         RETURNING id`,
        [username, invitation?.creator_user_id ?? null],
      );
      const row = rows[0];
      if (row === undefined) throw new Error('user insert returned no row');
      userId = row.id;
    } catch (error) {
      // 23505 = unique_violation on lower(username).
      if (isUniqueViolation(error)) {
        throw new AppError('already_exists', {
          logMessage: 'username already taken',
          cause: error,
        });
      }
      throw error;
    }

    await client.query(
      'INSERT INTO user_credentials (user_id, password_hash) VALUES ($1, $2)',
      [userId, passwordHash],
    );

    if (invitation !== undefined) {
      await consumeInvitation(client, invitation.id, userId);

      if (invitation.purpose === 'register_and_befriend') {
        // Goes straight to active: creating the invitation was the inviter's
        // consent. Verification is separate state (docs/decisions.md D7).
        await createFriendship(client, {
          userA: invitation.creator_user_id,
          userB: userId,
          invitationId: invitation.id,
        });
      }
    }

    const session = await createSession(client, deps, {
      userId,
      ...(params.userAgent !== undefined ? { userAgent: params.userAgent } : {}),
    });

    return { userId, session, invitationId: invitation?.id };
  });

  await recordSecurityEvent(logger, {
    type: 'auth.register.success',
    userId: result.userId,
    metadata: { bootstrap, invited: result.invitationId !== undefined },
  });

  return { userId: result.userId, session: result.session };
}

export interface LoginParams {
  readonly username: string;
  readonly password: string;
  readonly userAgent?: string | undefined;
}

export async function login(
  logger: FastifyBaseLogger,
  deps: SessionDeps,
  params: LoginParams,
): Promise<AuthResult> {
  // Not normaliseUsername: a malformed username must fail like a wrong password,
  // not with a distinguishable validation error.
  const username = params.username.trim().toLowerCase();

  const account = await queryOne<{
    id: string;
    status: string;
    password_hash: string;
  }>(
    `SELECT u.id, u.status, c.password_hash
       FROM users u
       JOIN user_credentials c ON c.user_id = u.id
      WHERE lower(u.username) = $1`,
    [username],
  );

  if (account === undefined) {
    // Spend comparable time so the response cannot be used to enumerate
    // usernames by timing.
    await spendVerificationTime(params.password);
    await recordSecurityEvent(logger, {
      type: 'auth.login.failed',
      metadata: { reason: 'unknown_account' },
    });
    throw authenticationFailed('login for unknown username');
  }

  const passwordOk = await verifyPassword(account.password_hash, params.password);
  if (!passwordOk) {
    await recordSecurityEvent(logger, {
      type: 'auth.login.failed',
      userId: account.id,
      metadata: { reason: 'bad_password' },
    });
    throw authenticationFailed('login with incorrect password', { userId: account.id });
  }

  // Checked after password verification so account status is not an oracle for
  // an attacker who does not know the password.
  if (account.status !== 'active') {
    await recordSecurityEvent(logger, {
      type: 'auth.login.failed',
      userId: account.id,
      metadata: { reason: 'inactive_account', status: account.status },
    });
    throw authenticationFailed('login for inactive account', { userId: account.id });
  }

  const session = await withTransaction(async (client) => {
    if (needsRehash(account.password_hash)) {
      // Opportunistic upgrade: we hold the correct password only here.
      const upgraded = await hashPassword(params.password);
      await client.query(
        'UPDATE user_credentials SET password_hash = $2, updated_at = now() WHERE user_id = $1',
        [account.id, upgraded],
      );
    }
    return createSession(client, deps, {
      userId: account.id,
      ...(params.userAgent !== undefined ? { userAgent: params.userAgent } : {}),
    });
  });

  await recordSecurityEvent(logger, { type: 'auth.login.success', userId: account.id });

  return { userId: account.id, session };
}

function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === '23505'
  );
}
