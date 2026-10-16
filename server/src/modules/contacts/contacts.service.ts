/**
 * Contacts.
 *
 * A contact listing includes each of the contact's active devices and their
 * PUBLIC identity keys, because the client needs them to derive safety numbers
 * and to notice when an identity key has changed.
 *
 * `verifiedAt` here is ADVISORY METADATA. Verification is a client-local trust
 * decision (docs/decisions.md D4). A client must not render "verified" because
 * this field is set — a compromised server could set it for a key it
 * substituted, which is precisely the attack verification exists to catch.
 */

import type { FastifyBaseLogger } from 'fastify';

import { AppError } from '../../core/errors.ts';
import { encodeBase64 } from '../../core/encoding.ts';
import { query, queryOne } from '../../database/pool.ts';
import { recordSecurityEvent } from '../security/security-events.ts';

export interface ContactDevice {
  readonly deviceId: string;
  readonly deviceIndex: number;
  readonly registrationId: number;
  readonly publicIdentityKey: string;
  readonly lastSeenAt: string | null;
}

export interface Contact {
  readonly contactUserId: string;
  readonly username: string;
  readonly status: string;
  /** Advisory only. See the module note. */
  readonly verifiedAt: string | null;
  readonly createdAt: string;
  readonly devices: ContactDevice[];
}

interface ContactRow {
  contact_user_id: string;
  username: string;
  status: string;
  verified_at: Date | null;
  created_at: Date;
}

const CONTACT_SELECT = `
  SELECT CASE WHEN f.user_a_id = $1 THEN f.user_b_id ELSE f.user_a_id END AS contact_user_id,
         u.username,
         f.status,
         f.verified_at,
         f.created_at
    FROM friendships f
    JOIN users u
      ON u.id = CASE WHEN f.user_a_id = $1 THEN f.user_b_id ELSE f.user_a_id END
   WHERE (f.user_a_id = $1 OR f.user_b_id = $1)
     AND f.status <> 'blocked'
     AND u.status = 'active'
`;

export async function listContacts(userId: string): Promise<Contact[]> {
  const rows = await query<ContactRow>(`${CONTACT_SELECT} ORDER BY u.username`, [userId]);
  return Promise.all(rows.map(async (row) => toContact(row, await listContactDevices(row.contact_user_id))));
}

export async function getContact(userId: string, contactUserId: string): Promise<Contact> {
  const row = await queryOne<ContactRow>(
    `${CONTACT_SELECT} AND (CASE WHEN f.user_a_id = $1 THEN f.user_b_id ELSE f.user_a_id END) = $2`,
    [userId, contactUserId],
  );

  // Not a contact and does not exist produce the same 404: this endpoint must
  // not confirm whether an arbitrary user id is real.
  if (row === undefined) {
    throw new AppError('not_found', {
      logMessage: 'contact lookup for a non-contact',
      logContext: { userId, contactUserId },
    });
  }

  return toContact(row, await listContactDevices(contactUserId));
}

function toContact(row: ContactRow, devices: ContactDevice[]): Contact {
  return {
    contactUserId: row.contact_user_id,
    username: row.username,
    status: row.status,
    verifiedAt: row.verified_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    devices,
  };
}

/** Active devices only: a revoked device must not appear as a send target. */
async function listContactDevices(contactUserId: string): Promise<ContactDevice[]> {
  const rows = await query<{
    id: string;
    device_index: number;
    registration_id: number;
    public_identity_key: Buffer;
    last_seen_at: Date | null;
  }>(
    `SELECT id, device_index, registration_id, public_identity_key, last_seen_at
       FROM devices
      WHERE user_id = $1 AND revoked_at IS NULL
      ORDER BY device_index`,
    [contactUserId],
  );

  return rows.map((row) => ({
    deviceId: row.id,
    deviceIndex: row.device_index,
    registrationId: row.registration_id,
    publicIdentityKey: encodeBase64(row.public_identity_key),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
  }));
}

/**
 * Records that a user marked a contact verified, or cleared it.
 *
 * Stored for convenience across reinstalls. It carries no authority: the client
 * decides what "verified" means to it, and must keep its own record.
 */
export async function setContactVerification(
  logger: FastifyBaseLogger,
  params: { userId: string; contactUserId: string; verified: boolean },
): Promise<{ verifiedAt: string | null }> {
  const rows = await query<{ verified_at: Date | null }>(
    `UPDATE friendships
        SET verified_at = CASE WHEN $3 THEN now() ELSE NULL END
      WHERE user_a_id = LEAST($1::uuid, $2::uuid)
        AND user_b_id = GREATEST($1::uuid, $2::uuid)
        AND status = 'active'
      RETURNING verified_at`,
    [params.userId, params.contactUserId, params.verified],
  );

  const row = rows[0];
  if (row === undefined) {
    throw new AppError('not_found', {
      logMessage: 'verification set for a non-contact or inactive friendship',
      logContext: { userId: params.userId, contactUserId: params.contactUserId },
    });
  }

  await recordSecurityEvent(logger, {
    type: 'contact.verified',
    userId: params.userId,
    metadata: { contactUserId: params.contactUserId, verified: params.verified },
  });

  return { verifiedAt: row.verified_at?.toISOString() ?? null };
}
