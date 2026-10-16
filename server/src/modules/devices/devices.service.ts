/**
 * Device registration and prekey distribution.
 *
 * A device is one installation with its own cryptographic identity. This module
 * stores and hands out PUBLIC key material only; a private key reaching here
 * would be a security incident, not a bug.
 */

import type { FastifyBaseLogger } from 'fastify';

import { AppError } from '../../core/errors.ts';
import {
  CIPHERTEXT_BYTES,
  decodeBase64,
  encodeBase64,
  KYBER_PUBLIC_KEY_BYTES,
  PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES,
} from '../../core/encoding.ts';
import type { PoolClient } from '../../database/pool.ts';
import { query, queryOne, withTransaction } from '../../database/pool.ts';
import { publishToDevice } from '../../realtime/dispatch.ts';
import { recordSecurityEvent } from '../security/security-events.ts';
import { revokeSessionsForDevice } from '../auth/session.service.ts';

/**
 * libsignal ProtocolAddress device ids are limited to 1..127, so each device
 * carries a small per-user index in addition to its opaque UUID.
 */
const MAX_DEVICE_INDEX = 127;

/** Bounds on a registration payload, so one request cannot flood the table. */
const MAX_ONE_TIME_PREKEYS_PER_REQUEST = 100;
const MIN_ONE_TIME_PREKEYS_AT_REGISTRATION = 10;

export type Platform = 'android' | 'ios' | 'windows' | 'linux' | 'macos';

export interface PreKeyInput {
  readonly id: number;
  readonly publicKey: string;
}

export interface SignedPreKeyInput extends PreKeyInput {
  readonly signature: string;
}

export interface KyberPreKeyInput extends SignedPreKeyInput {
  readonly isLastResort?: boolean | undefined;
}

export interface RegisterDeviceParams {
  readonly userId: string;
  readonly sessionId: string;
  readonly deviceName: string;
  readonly platform: Platform;
  readonly registrationId: number;
  readonly publicIdentityKey: string;
  readonly signedPreKey: SignedPreKeyInput;
  /** Required: libsignal 0.103 mandates PQXDH, so a bundle needs a Kyber prekey. */
  readonly kyberPreKey: KyberPreKeyInput;
  readonly oneTimePreKeys: readonly PreKeyInput[];
}

export interface RegisteredDevice {
  readonly deviceId: string;
  readonly deviceIndex: number;
}

export interface DeviceSummary {
  readonly deviceId: string;
  readonly deviceIndex: number;
  readonly deviceName: string;
  readonly platform: string;
  readonly publicIdentityKey: string;
  readonly registrationId: number;
  readonly createdAt: string;
  readonly lastSeenAt: string | null;
  readonly revokedAt: string | null;
  readonly availableOneTimePreKeys: number;
}

export interface PreKeyBundle {
  readonly deviceId: string;
  readonly userId: string;
  readonly deviceIndex: number;
  readonly registrationId: number;
  readonly publicIdentityKey: string;
  readonly signedPreKey: { id: number; publicKey: string; signature: string };
  readonly kyberPreKey: { id: number; publicKey: string; signature: string };
  /** Null when the one-time supply is exhausted. X3DH still works without one. */
  readonly oneTimePreKey: { id: number; publicKey: string } | null;
}

/**
 * Allocates the next device index for a user.
 *
 * Indexes are allocated monotonically and NEVER reused, including after
 * revocation. A peer caches sessions keyed by (userId, deviceIndex); handing a
 * retired index to a new installation with a different identity key would let
 * that peer send messages addressed to the old device straight to the new one.
 * Gaps in the sequence are harmless, so this is the cheap safe choice.
 */
async function allocateDeviceIndex(client: PoolClient, userId: string): Promise<number> {
  // Lock the user row so two concurrent registrations cannot pick the same index.
  const { rows: locked } = await client.query<{ id: string }>(
    'SELECT id FROM users WHERE id = $1 FOR UPDATE',
    [userId],
  );
  if (locked[0] === undefined) {
    throw new AppError('not_found', { logMessage: 'user disappeared during device registration' });
  }

  const { rows } = await client.query<{ next_index: number }>(
    `SELECT COALESCE(MAX(device_index), 0) + 1 AS next_index
       FROM devices WHERE user_id = $1`,
    [userId],
  );
  const next = rows[0]?.next_index ?? 1;

  if (next > MAX_DEVICE_INDEX) {
    throw new AppError('invalid_state', {
      logMessage: 'device index space exhausted for user',
      logContext: { userId, attempted: next },
    });
  }
  return next;
}

export async function registerDevice(
  logger: FastifyBaseLogger,
  params: RegisterDeviceParams,
): Promise<RegisteredDevice> {
  // Decode and bound-check everything before touching the database.
  const identityKey = decodeBase64(params.publicIdentityKey, PUBLIC_KEY_BYTES, 'publicIdentityKey');
  const signedPreKeyPublic = decodeBase64(params.signedPreKey.publicKey, PUBLIC_KEY_BYTES, 'signedPreKey.publicKey');
  const signedPreKeySignature = decodeBase64(params.signedPreKey.signature, SIGNATURE_BYTES, 'signedPreKey.signature');
  const kyberPublic = decodeBase64(params.kyberPreKey.publicKey, KYBER_PUBLIC_KEY_BYTES, 'kyberPreKey.publicKey');
  const kyberSignature = decodeBase64(params.kyberPreKey.signature, SIGNATURE_BYTES, 'kyberPreKey.signature');

  if (params.oneTimePreKeys.length < MIN_ONE_TIME_PREKEYS_AT_REGISTRATION) {
    throw new AppError('validation_failed', {
      logMessage: 'too few one-time prekeys at registration',
      logContext: { provided: params.oneTimePreKeys.length, minimum: MIN_ONE_TIME_PREKEYS_AT_REGISTRATION },
    });
  }
  const oneTimeKeys = decodeOneTimePreKeys(params.oneTimePreKeys);

  const registered = await withTransaction(async (client) => {
    const deviceIndex = await allocateDeviceIndex(client, params.userId);

    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO devices
         (user_id, device_name, platform, public_identity_key, registration_id,
          device_index, last_seen_at)
       VALUES ($1, $2, $3, $4, $5, $6, now())
       RETURNING id`,
      [
        params.userId,
        params.deviceName,
        params.platform,
        identityKey,
        params.registrationId,
        deviceIndex,
      ],
    );
    const device = rows[0];
    if (device === undefined) throw new Error('device insert returned no row');

    await client.query(
      `INSERT INTO device_signed_prekeys (device_id, prekey_id, public_key, signature)
       VALUES ($1, $2, $3, $4)`,
      [device.id, params.signedPreKey.id, signedPreKeyPublic, signedPreKeySignature],
    );

    await client.query(
      `INSERT INTO device_kyber_prekeys
         (device_id, prekey_id, public_key, signature, is_last_resort)
       VALUES ($1, $2, $3, $4, $5)`,
      [device.id, params.kyberPreKey.id, kyberPublic, kyberSignature, params.kyberPreKey.isLastResort ?? false],
    );

    await insertOneTimePreKeys(client, device.id, oneTimeKeys);

    // Bind this account session to the new device, so subsequent tokens for it
    // are device-scoped and device revocation can kill them.
    await client.query('UPDATE auth_sessions SET device_id = $2 WHERE id = $1', [
      params.sessionId,
      device.id,
    ]);

    return { deviceId: device.id, deviceIndex };
  });

  await recordSecurityEvent(logger, {
    type: 'device.registered',
    userId: params.userId,
    deviceId: registered.deviceId,
    metadata: {
      platform: params.platform,
      deviceIndex: registered.deviceIndex,
      oneTimePreKeys: oneTimeKeys.length,
    },
  });

  return registered;
}

function decodeOneTimePreKeys(
  input: readonly PreKeyInput[],
): ReadonlyArray<{ id: number; publicKey: Buffer }> {
  if (input.length > MAX_ONE_TIME_PREKEYS_PER_REQUEST) {
    throw new AppError('validation_failed', {
      logMessage: 'too many one-time prekeys in one request',
      logContext: { provided: input.length, maximum: MAX_ONE_TIME_PREKEYS_PER_REQUEST },
    });
  }

  const seen = new Set<number>();
  return input.map((prekey) => {
    if (seen.has(prekey.id)) {
      throw new AppError('validation_failed', {
        logMessage: 'duplicate one-time prekey id in request',
        logContext: { prekeyId: prekey.id },
      });
    }
    seen.add(prekey.id);
    return {
      id: prekey.id,
      publicKey: decodeBase64(prekey.publicKey, PUBLIC_KEY_BYTES, 'oneTimePreKeys[].publicKey'),
    };
  });
}

async function insertOneTimePreKeys(
  client: PoolClient,
  deviceId: string,
  keys: ReadonlyArray<{ id: number; publicKey: Buffer }>,
): Promise<void> {
  for (const key of keys) {
    // ON CONFLICT DO NOTHING: replenishment may legitimately resend an id the
    // server already holds. It must never overwrite an existing prekey, because
    // that could substitute a key for one already handed out.
    await client.query(
      `INSERT INTO device_one_time_prekeys (device_id, prekey_id, public_key)
       VALUES ($1, $2, $3)
       ON CONFLICT (device_id, prekey_id) DO NOTHING`,
      [deviceId, key.id, key.publicKey],
    );
  }
}

export async function replenishOneTimePreKeys(
  logger: FastifyBaseLogger,
  params: { userId: string; deviceId: string; oneTimePreKeys: readonly PreKeyInput[] },
): Promise<{ availableOneTimePreKeys: number }> {
  const keys = decodeOneTimePreKeys(params.oneTimePreKeys);

  const available = await withTransaction(async (client) => {
    // Ownership check inside the transaction: a device may only publish its own
    // key material.
    const { rows } = await client.query<{ user_id: string; revoked_at: Date | null }>(
      'SELECT user_id, revoked_at FROM devices WHERE id = $1 FOR UPDATE',
      [params.deviceId],
    );
    const device = rows[0];
    if (device === undefined || device.user_id !== params.userId) {
      // Same answer whether it does not exist or belongs to someone else.
      throw new AppError('not_found', {
        logMessage: 'prekey replenishment for a device the caller does not own',
        logContext: { userId: params.userId, deviceId: params.deviceId },
        securityEvent: true,
      });
    }
    if (device.revoked_at !== null) {
      throw new AppError('device_revoked', {
        logMessage: 'prekey replenishment for a revoked device',
        logContext: { deviceId: params.deviceId },
        securityEvent: true,
      });
    }

    await insertOneTimePreKeys(client, params.deviceId, keys);

    const { rows: countRows } = await client.query<{ count: string }>(
      `SELECT count(*) FROM device_one_time_prekeys
        WHERE device_id = $1 AND consumed_at IS NULL`,
      [params.deviceId],
    );
    return Number(countRows[0]?.count ?? '0');
  });

  await recordSecurityEvent(logger, {
    type: 'device.prekeys_replenished',
    userId: params.userId,
    deviceId: params.deviceId,
    metadata: { added: keys.length, available },
  });

  return { availableOneTimePreKeys: available };
}

export async function listDevices(userId: string): Promise<DeviceSummary[]> {
  const rows = await query<{
    id: string;
    device_index: number;
    device_name: string;
    platform: string;
    public_identity_key: Buffer;
    registration_id: number;
    created_at: Date;
    last_seen_at: Date | null;
    revoked_at: Date | null;
    available: string;
  }>(
    `SELECT d.id, d.device_index, d.device_name, d.platform, d.public_identity_key,
            d.registration_id, d.created_at, d.last_seen_at, d.revoked_at,
            (SELECT count(*) FROM device_one_time_prekeys o
              WHERE o.device_id = d.id AND o.consumed_at IS NULL) AS available
       FROM devices d
      WHERE d.user_id = $1
      ORDER BY d.device_index`,
    [userId],
  );

  return rows.map((row) => ({
    deviceId: row.id,
    deviceIndex: row.device_index,
    deviceName: row.device_name,
    platform: row.platform,
    publicIdentityKey: encodeBase64(row.public_identity_key),
    registrationId: row.registration_id,
    createdAt: row.created_at.toISOString(),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
    revokedAt: row.revoked_at?.toISOString() ?? null,
    availableOneTimePreKeys: Number(row.available),
  }));
}

/**
 * Revokes a device.
 *
 * Note what this does and does not achieve. It stops the device establishing
 * new sessions and kills its server sessions. It does NOT remove plaintext
 * already decrypted and stored on that device. See docs/crypto-design.md s6.
 */
export async function revokeDevice(
  logger: FastifyBaseLogger,
  params: { userId: string; deviceId: string },
): Promise<void> {
  await withTransaction(async (client) => {
    const { rows } = await client.query<{ user_id: string; revoked_at: Date | null }>(
      'SELECT user_id, revoked_at FROM devices WHERE id = $1 FOR UPDATE',
      [params.deviceId],
    );
    const device = rows[0];
    if (device === undefined || device.user_id !== params.userId) {
      throw new AppError('not_found', {
        logMessage: 'revoke attempted for a device the caller does not own',
        logContext: { userId: params.userId, deviceId: params.deviceId },
        securityEvent: true,
      });
    }
    if (device.revoked_at !== null) return; // Idempotent.

    await client.query('UPDATE devices SET revoked_at = now() WHERE id = $1', [params.deviceId]);

    // Withdraw unused prekeys so no peer can start a new session with it.
    await client.query(
      `DELETE FROM device_one_time_prekeys WHERE device_id = $1 AND consumed_at IS NULL`,
      [params.deviceId],
    );
    await client.query(
      `UPDATE device_signed_prekeys SET retired_at = now()
        WHERE device_id = $1 AND retired_at IS NULL`,
      [params.deviceId],
    );

    await revokeSessionsForDevice(client, params.deviceId);
  });

  await recordSecurityEvent(logger, {
    type: 'device.revoked',
    userId: params.userId,
    deviceId: params.deviceId,
  });

  // Close any live socket for the device, on whichever instance holds it.
  // Without this, a revoked device keeps receiving notifications until it
  // happens to disconnect.
  try {
    await publishToDevice(params.deviceId, {
      type: 'device.revoked',
      recipientDeviceId: params.deviceId,
      at: new Date().toISOString(),
    });
  } catch (error) {
    // The database state is already authoritative: the next request from this
    // device is rejected by the auth guard regardless.
    logger.warn(
      { err: error instanceof Error ? error.message : String(error) },
      'failed to publish device revocation',
    );
  }
}

/**
 * Hands out a prekey bundle, consuming one one-time prekey atomically.
 *
 * Authorisation: the caller must be an active contact of the device's owner, or
 * the owner. Without that check this endpoint is a public key-material
 * directory and an enumeration oracle.
 */
export async function fetchPreKeyBundle(
  logger: FastifyBaseLogger,
  params: { requesterUserId: string; requesterDeviceId: string | undefined; targetDeviceId: string },
): Promise<PreKeyBundle> {
  return withTransaction(async (client) => {
    const { rows: deviceRows } = await client.query<{
      id: string;
      user_id: string;
      device_index: number;
      registration_id: number;
      public_identity_key: Buffer;
      revoked_at: Date | null;
    }>(
      `SELECT id, user_id, device_index, registration_id, public_identity_key, revoked_at
         FROM devices WHERE id = $1`,
      [params.targetDeviceId],
    );
    const device = deviceRows[0];

    // A device that does not exist and one the caller may not see produce the
    // same 404, so this cannot be used to probe for device ids.
    if (device === undefined) {
      throw new AppError('not_found', { logMessage: 'prekey bundle requested for unknown device' });
    }

    if (device.user_id !== params.requesterUserId) {
      const friends = await areActiveContacts(client, params.requesterUserId, device.user_id);
      if (!friends) {
        throw new AppError('not_found', {
          logMessage: 'prekey bundle requested for a non-contact',
          logContext: { requesterUserId: params.requesterUserId, targetDeviceId: params.targetDeviceId },
          securityEvent: true,
        });
      }
    }

    if (device.revoked_at !== null) {
      throw new AppError('device_revoked', {
        logMessage: 'prekey bundle requested for a revoked device',
        logContext: { targetDeviceId: params.targetDeviceId },
      });
    }

    const { rows: signedRows } = await client.query<{
      prekey_id: number;
      public_key: Buffer;
      signature: Buffer;
    }>(
      `SELECT prekey_id, public_key, signature FROM device_signed_prekeys
        WHERE device_id = $1 AND retired_at IS NULL`,
      [device.id],
    );
    const signed = signedRows[0];
    if (signed === undefined) {
      throw new AppError('invalid_state', {
        logMessage: 'device has no current signed prekey',
        logContext: { deviceId: device.id },
      });
    }

    const kyber = await consumeKyberPreKey(client, device.id);

    // Atomic one-time prekey consumption. SKIP LOCKED means concurrent
    // requesters take different keys instead of serialising or colliding.
    const { rows: oneTimeRows } = await client.query<{ prekey_id: number; public_key: Buffer }>(
      `WITH picked AS (
         SELECT device_id, prekey_id
           FROM device_one_time_prekeys
          WHERE device_id = $1 AND consumed_at IS NULL
          ORDER BY prekey_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE device_one_time_prekeys o
          SET consumed_at = now(), consumed_by_device_id = $2
         FROM picked p
        WHERE o.device_id = p.device_id AND o.prekey_id = p.prekey_id
       RETURNING o.prekey_id, o.public_key`,
      [device.id, params.requesterDeviceId ?? null],
    );
    const oneTime = oneTimeRows[0];

    if (oneTime === undefined) {
      // Degrade rather than fail open or reuse a key: X3DH still works without a
      // one-time prekey, with weaker forward secrecy for the first message.
      await recordSecurityEvent(logger, {
        type: 'device.prekeys_exhausted',
        userId: device.user_id,
        deviceId: device.id,
      });
    }

    return {
      deviceId: device.id,
      userId: device.user_id,
      deviceIndex: device.device_index,
      registrationId: device.registration_id,
      publicIdentityKey: encodeBase64(device.public_identity_key),
      signedPreKey: {
        id: signed.prekey_id,
        publicKey: encodeBase64(signed.public_key),
        signature: encodeBase64(signed.signature),
      },
      kyberPreKey: kyber,
      oneTimePreKey:
        oneTime === undefined
          ? null
          : { id: oneTime.prekey_id, publicKey: encodeBase64(oneTime.public_key) },
    };
  });
}

/**
 * Picks a Kyber prekey, preferring a single-use one and falling back to the
 * reusable last-resort key. PQXDH is mandatory, so failing to find one is a
 * hard error rather than an omitted field.
 */
async function consumeKyberPreKey(
  client: PoolClient,
  deviceId: string,
): Promise<{ id: number; publicKey: string; signature: string }> {
  const { rows: singleUse } = await client.query<{
    prekey_id: number;
    public_key: Buffer;
    signature: Buffer;
  }>(
    `WITH picked AS (
       SELECT device_id, prekey_id
         FROM device_kyber_prekeys
        WHERE device_id = $1 AND consumed_at IS NULL AND NOT is_last_resort
        ORDER BY prekey_id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
     )
     UPDATE device_kyber_prekeys k
        SET consumed_at = now()
       FROM picked p
      WHERE k.device_id = p.device_id AND k.prekey_id = p.prekey_id
     RETURNING k.prekey_id, k.public_key, k.signature`,
    [deviceId],
  );

  const chosen =
    singleUse[0] ??
    (
      await client.query<{ prekey_id: number; public_key: Buffer; signature: Buffer }>(
        `SELECT prekey_id, public_key, signature FROM device_kyber_prekeys
          WHERE device_id = $1 AND is_last_resort
          LIMIT 1`,
        [deviceId],
      )
    ).rows[0];

  if (chosen === undefined) {
    throw new AppError('invalid_state', {
      logMessage: 'device has no usable kyber prekey',
      logContext: { deviceId },
    });
  }

  return {
    id: chosen.prekey_id,
    publicKey: encodeBase64(chosen.public_key),
    signature: encodeBase64(chosen.signature),
  };
}

/** True when the two users have an active friendship. Order-independent. */
export async function areActiveContacts(
  client: PoolClient,
  userA: string,
  userB: string,
): Promise<boolean> {
  const { rows } = await client.query<{ exists: boolean }>(
    `SELECT true AS exists FROM friendships
      WHERE status = 'active'
        AND user_a_id = LEAST($1::uuid, $2::uuid)
        AND user_b_id = GREATEST($1::uuid, $2::uuid)`,
    [userA, userB],
  );
  return rows[0]?.exists ?? false;
}

/** Active devices of a user, for message fan-out. */
export async function listActiveDeviceIds(userId: string): Promise<string[]> {
  const rows = await queryOneColumn(
    `SELECT id FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY device_index`,
    [userId],
  );
  return rows;
}

async function queryOneColumn(sql: string, params: readonly unknown[]): Promise<string[]> {
  const rows = await query<{ id: string }>(sql, params);
  return rows.map((row) => row.id);
}

export async function touchDeviceLastSeen(deviceId: string): Promise<void> {
  await query('UPDATE devices SET last_seen_at = now() WHERE id = $1', [deviceId]);
}

export async function getDeviceOwner(
  deviceId: string,
): Promise<{ userId: string; revoked: boolean } | undefined> {
  const row = await queryOne<{ user_id: string; revoked_at: Date | null }>(
    'SELECT user_id, revoked_at FROM devices WHERE id = $1',
    [deviceId],
  );
  return row === undefined ? undefined : { userId: row.user_id, revoked: row.revoked_at !== null };
}

export { CIPHERTEXT_BYTES, MAX_DEVICE_INDEX, MAX_ONE_TIME_PREKEYS_PER_REQUEST };
