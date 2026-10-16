/**
 * Invitations.
 *
 * One invitation both authorises registration and establishes the friendship
 * (docs/decisions.md D3). The token is high-entropy, stored only as a keyed
 * hash, single-use, expiring and revocable.
 *
 * `claimInvitation` is shared with the registration path so single-use
 * enforcement exists in exactly one place. Two copies of this logic would
 * eventually disagree, and the one that disagreed would be the exploitable one.
 */

import type { FastifyBaseLogger } from 'fastify';

import { AppError } from '../../core/errors.ts';
import { generateToken, hashToken, isWellFormedToken } from '../../core/tokens.ts';
import type { PoolClient } from '../../database/pool.ts';
import { query, withTransaction } from '../../database/pool.ts';
import { recordSecurityEvent } from '../security/security-events.ts';

export type InvitationPurpose = 'register_and_befriend' | 'register_only' | 'befriend_only';

export interface InvitationRow {
  readonly id: string;
  readonly creator_user_id: string;
  readonly purpose: string;
}

export interface CreatedInvitation {
  readonly invitationId: string;
  /** Returned exactly once. Never persisted, never logged. */
  readonly token: string;
  readonly expiresAt: string;
  readonly purpose: InvitationPurpose;
}

export interface InvitationSummary {
  readonly invitationId: string;
  readonly purpose: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly usedAt: string | null;
  readonly revokedAt: string | null;
  readonly status: 'pending' | 'used' | 'revoked' | 'expired';
}

export async function createInvitation(
  logger: FastifyBaseLogger,
  params: {
    creatorUserId: string;
    pepper: string;
    ttlHours: number;
    purpose?: InvitationPurpose | undefined;
  },
): Promise<CreatedInvitation> {
  const purpose = params.purpose ?? 'register_and_befriend';
  const { token, hash } = generateToken(params.pepper);
  const expiresAt = new Date(Date.now() + params.ttlHours * 60 * 60 * 1000);

  const rows = await query<{ id: string; expires_at: Date }>(
    `INSERT INTO invitations (creator_user_id, token_hash, purpose, expires_at)
     VALUES ($1, $2, $3, $4)
     RETURNING id, expires_at`,
    [params.creatorUserId, hash, purpose, expiresAt],
  );
  const row = rows[0];
  if (row === undefined) throw new Error('invitation insert returned no row');

  await recordSecurityEvent(logger, {
    type: 'invitation.created',
    userId: params.creatorUserId,
    // The invitation id is safe to log. The token is not, and is not passed here.
    metadata: { invitationId: row.id, purpose },
  });

  return {
    invitationId: row.id,
    token,
    expiresAt: row.expires_at.toISOString(),
    purpose,
  };
}

/**
 * Locks and validates an invitation, returning the row so the caller can mark
 * it used in the same transaction.
 *
 * Every rejection collapses to one client-facing error, so probing cannot
 * distinguish "expired" from "already used" from "never existed".
 */
export async function claimInvitation(
  client: PoolClient,
  pepper: string,
  token: string,
): Promise<InvitationRow> {
  if (!isWellFormedToken(token)) {
    throw new AppError('invitation_unusable', {
      logMessage: 'invitation token failed shape check',
      securityEvent: true,
    });
  }

  const { rows } = await client.query<
    InvitationRow & { used_at: Date | null; revoked_at: Date | null; expires_at: Date }
  >(
    `SELECT id, creator_user_id, purpose, used_at, revoked_at, expires_at
       FROM invitations
      WHERE token_hash = $1
      FOR UPDATE`,
    [hashToken(token, pepper)],
  );

  const invitation = rows[0];
  if (invitation === undefined) {
    throw new AppError('invitation_unusable', {
      logMessage: 'invitation not recognised',
      securityEvent: true,
    });
  }

  const reason =
    invitation.revoked_at !== null
      ? 'revoked'
      : invitation.used_at !== null
        ? 'already used'
        : invitation.expires_at.getTime() <= Date.now()
          ? 'expired'
          : undefined;

  if (reason !== undefined) {
    throw new AppError('invitation_unusable', {
      logMessage: `invitation ${reason}`,
      logContext: { invitationId: invitation.id },
      securityEvent: true,
    });
  }

  return invitation;
}

/**
 * Marks an invitation used. The WHERE clause re-asserts the precondition, so
 * single-use holds even if the row lock above were ever removed.
 */
export async function consumeInvitation(
  client: PoolClient,
  invitationId: string,
  usedByUserId: string,
): Promise<void> {
  const { rowCount } = await client.query(
    `UPDATE invitations
        SET used_at = now(), used_by_user_id = $2
      WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`,
    [invitationId, usedByUserId],
  );
  if ((rowCount ?? 0) !== 1) {
    throw new AppError('invitation_unusable', {
      logMessage: 'invitation consumption raced and lost',
      logContext: { invitationId },
      securityEvent: true,
    });
  }
}

/**
 * Creates the friendship for an accepted invitation.
 *
 * Goes straight to `active`: creating an invitation is the inviter's consent,
 * and verification is tracked separately (docs/decisions.md D7). Messaging is
 * therefore possible while unverified, and the client must show that state.
 *
 * LEAST/GREATEST enforces the canonical pair ordering the table requires, so one
 * relationship cannot be stored twice in opposite orders.
 */
export async function createFriendship(
  client: PoolClient,
  params: { userA: string; userB: string; invitationId: string },
): Promise<void> {
  await client.query(
    `INSERT INTO friendships (user_a_id, user_b_id, status, accepted_at, invitation_id)
     VALUES (LEAST($1::uuid, $2::uuid), GREATEST($1::uuid, $2::uuid), 'active', now(), $3)
     ON CONFLICT (user_a_id, user_b_id) DO UPDATE
        SET status = 'active',
            accepted_at = COALESCE(friendships.accepted_at, now())
      WHERE friendships.status <> 'blocked'`,
    [params.userA, params.userB, params.invitationId],
  );
}

export interface AcceptedInvitation {
  readonly contactUserId: string;
  readonly invitationId: string;
}

/**
 * Accepts an invitation as an EXISTING account.
 *
 * A brand-new user accepts implicitly by registering with the token; that path
 * lives in modules/auth/auth.service.ts and shares the helpers above.
 */
export async function acceptInvitation(
  logger: FastifyBaseLogger,
  params: { accepterUserId: string; token: string; pepper: string },
): Promise<AcceptedInvitation> {
  const accepted = await withTransaction(async (client) => {
    const invitation = await claimInvitation(client, params.pepper, params.token);

    if (invitation.creator_user_id === params.accepterUserId) {
      // Self-acceptance would violate friendships_no_self anyway; rejecting it
      // here gives a clear error instead of a constraint violation, and avoids
      // burning the invitation.
      throw new AppError('invalid_state', {
        logMessage: 'user attempted to accept their own invitation',
        logContext: { userId: params.accepterUserId, invitationId: invitation.id },
      });
    }

    if (invitation.purpose === 'register_only') {
      throw new AppError('invitation_unusable', {
        logMessage: 'registration-only invitation presented for acceptance',
        logContext: { invitationId: invitation.id },
      });
    }

    await consumeInvitation(client, invitation.id, params.accepterUserId);
    await createFriendship(client, {
      userA: invitation.creator_user_id,
      userB: params.accepterUserId,
      invitationId: invitation.id,
    });

    return { contactUserId: invitation.creator_user_id, invitationId: invitation.id };
  });

  await recordSecurityEvent(logger, {
    type: 'invitation.accepted',
    userId: params.accepterUserId,
    metadata: { invitationId: accepted.invitationId, contactUserId: accepted.contactUserId },
  });

  return accepted;
}

export async function listInvitations(userId: string): Promise<InvitationSummary[]> {
  // Note the absence of token_hash: there is no endpoint that can return a
  // token after creation, by construction.
  const rows = await query<{
    id: string;
    purpose: string;
    created_at: Date;
    expires_at: Date;
    used_at: Date | null;
    revoked_at: Date | null;
  }>(
    `SELECT id, purpose, created_at, expires_at, used_at, revoked_at
       FROM invitations
      WHERE creator_user_id = $1
      ORDER BY created_at DESC
      LIMIT 100`,
    [userId],
  );

  return rows.map((row) => ({
    invitationId: row.id,
    purpose: row.purpose,
    createdAt: row.created_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
    usedAt: row.used_at?.toISOString() ?? null,
    revokedAt: row.revoked_at?.toISOString() ?? null,
    status:
      row.revoked_at !== null
        ? 'revoked'
        : row.used_at !== null
          ? 'used'
          : row.expires_at.getTime() <= Date.now()
            ? 'expired'
            : 'pending',
  }));
}

export async function revokeInvitation(
  logger: FastifyBaseLogger,
  params: { userId: string; invitationId: string },
): Promise<void> {
  const rows = await query<{ id: string }>(
    `UPDATE invitations
        SET revoked_at = now()
      WHERE id = $1 AND creator_user_id = $2 AND used_at IS NULL AND revoked_at IS NULL
      RETURNING id`,
    [params.invitationId, params.userId],
  );

  // Same 404 whether it does not exist, belongs to someone else, or is already
  // spent. A caller learns nothing about other people's invitations.
  if (rows[0] === undefined) {
    throw new AppError('not_found', {
      logMessage: 'revoke attempted for an invitation the caller cannot revoke',
      logContext: { userId: params.userId, invitationId: params.invitationId },
    });
  }

  await recordSecurityEvent(logger, {
    type: 'invitation.revoked',
    userId: params.userId,
    metadata: { invitationId: params.invitationId },
  });
}
