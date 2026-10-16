/**
 * Encrypted message envelopes.
 *
 * This module routes opaque bytes. It never inspects, parses, decrypts or
 * indexes `ciphertext`, and there is no code path here that could.
 *
 * Fan-out is the client's job: a sender encrypts separately for each of the
 * recipient's active devices and submits one envelope per device in a single
 * request (docs/decisions.md D8). The server authorises each envelope
 * independently — a batch is not a trust boundary.
 */

import type { FastifyBaseLogger } from 'fastify';

import { AppError } from '../../core/errors.ts';
import { CIPHERTEXT_BYTES, decodeBase64, encodeBase64 } from '../../core/encoding.ts';
import { query, withTransaction } from '../../database/pool.ts';
import { publishToDevice } from '../../realtime/dispatch.ts';
import { areActiveContacts } from '../devices/devices.service.ts';
import { recordSecurityEvent } from '../security/security-events.ts';

/** Bounds one request, independent of the per-envelope ciphertext limit. */
export const MAX_ENVELOPES_PER_REQUEST = 20;
export const MAX_QUEUE_FETCH = 200;

export type EnvelopeMessageType = 'prekey' | 'signal';

export interface EnvelopeInput {
  readonly recipientDeviceId: string;
  readonly envelopeVersion: number;
  readonly messageType: EnvelopeMessageType;
  readonly ciphertext: string;
  /** Sender-assigned, strictly increasing per (sender device, recipient device). */
  readonly senderSequence: number;
  readonly protocolMetadata?: Record<string, unknown> | undefined;
}

export type EnvelopeOutcome =
  | { readonly recipientDeviceId: string; readonly status: 'accepted'; readonly messageId: string }
  | { readonly recipientDeviceId: string; readonly status: 'duplicate' };

export interface QueuedEnvelope {
  readonly messageId: string;
  readonly envelopeVersion: number;
  readonly senderDeviceId: string;
  readonly senderUserId: string;
  readonly senderDeviceIndex: number;
  readonly recipientDeviceId: string;
  readonly protocol: string;
  readonly messageType: EnvelopeMessageType;
  readonly ciphertext: string;
  readonly protocolMetadata: Record<string, unknown>;
  readonly senderSequence: number;
  readonly createdAt: string;
}

interface RecipientCheck {
  user_id: string;
  revoked_at: Date | null;
}

export async function sendMessages(
  logger: FastifyBaseLogger,
  params: {
    senderUserId: string;
    senderDeviceId: string;
    envelopes: readonly EnvelopeInput[];
    queuedTtlDays: number;
  },
): Promise<EnvelopeOutcome[]> {
  if (params.envelopes.length === 0) {
    throw new AppError('validation_failed', { logMessage: 'no envelopes in request' });
  }

  // One envelope per recipient device. A repeated recipient in one batch is
  // either a client bug or an attempt to confuse sequence accounting.
  const recipients = new Set<string>();
  for (const envelope of params.envelopes) {
    if (recipients.has(envelope.recipientDeviceId)) {
      throw new AppError('validation_failed', {
        logMessage: 'duplicate recipient device in one batch',
      });
    }
    recipients.add(envelope.recipientDeviceId);
    if (envelope.recipientDeviceId === params.senderDeviceId) {
      throw new AppError('validation_failed', {
        logMessage: 'envelope addressed to the sending device',
      });
    }
  }

  // Decode before opening a transaction: bound-checking is pure work.
  const decoded = params.envelopes.map((envelope) => ({
    envelope,
    ciphertext: decodeBase64(envelope.ciphertext, CIPHERTEXT_BYTES, 'ciphertext'),
  }));

  const expiresAt = new Date(Date.now() + params.queuedTtlDays * 24 * 60 * 60 * 1000);

  const outcomes = await withTransaction(async (client) => {
    // The sending device must belong to the caller and be live. Checked against
    // the database rather than trusting the token's device claim alone.
    const { rows: senderRows } = await client.query<RecipientCheck>(
      'SELECT user_id, revoked_at FROM devices WHERE id = $1',
      [params.senderDeviceId],
    );
    const sender = senderRows[0];
    if (sender === undefined || sender.user_id !== params.senderUserId) {
      throw new AppError('forbidden', {
        logMessage: 'send attempted from a device the caller does not own',
        logContext: { userId: params.senderUserId, deviceId: params.senderDeviceId },
        securityEvent: true,
      });
    }
    if (sender.revoked_at !== null) {
      throw new AppError('device_revoked', {
        logMessage: 'send attempted from a revoked device',
        logContext: { deviceId: params.senderDeviceId },
        securityEvent: true,
      });
    }

    const results: EnvelopeOutcome[] = [];

    for (const { envelope, ciphertext } of decoded) {
      const { rows: recipientRows } = await client.query<RecipientCheck>(
        'SELECT user_id, revoked_at FROM devices WHERE id = $1',
        [envelope.recipientDeviceId],
      );
      const recipient = recipientRows[0];

      // Unknown device and non-contact device give the same answer, so this
      // cannot be used to enumerate device ids.
      if (recipient === undefined) {
        throw new AppError('not_contacts', {
          logMessage: 'send attempted to an unknown device',
          logContext: { recipientDeviceId: envelope.recipientDeviceId },
          securityEvent: true,
        });
      }

      // A sender may address a contact's device, or another of their own.
      const ownDevice = recipient.user_id === params.senderUserId;
      if (!ownDevice) {
        const permitted = await areActiveContacts(client, params.senderUserId, recipient.user_id);
        if (!permitted) {
          throw new AppError('not_contacts', {
            logMessage: 'send attempted to a non-contact',
            logContext: {
              senderUserId: params.senderUserId,
              recipientDeviceId: envelope.recipientDeviceId,
            },
            securityEvent: true,
          });
        }
      }

      if (recipient.revoked_at !== null) {
        throw new AppError('device_revoked', {
          logMessage: 'send attempted to a revoked device',
          logContext: { recipientDeviceId: envelope.recipientDeviceId },
        });
      }

      // The unique index on (sender_device, recipient_device, sender_sequence)
      // makes replay and accidental resend a no-op rather than a duplicate row.
      const { rows: inserted } = await client.query<{ id: string }>(
        `INSERT INTO messages
           (envelope_version, sender_device_id, recipient_device_id, ciphertext,
            protocol_metadata, sender_sequence, expires_at, message_type)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (sender_device_id, recipient_device_id, sender_sequence)
           DO NOTHING
         RETURNING id`,
        [
          envelope.envelopeVersion,
          params.senderDeviceId,
          envelope.recipientDeviceId,
          ciphertext,
          JSON.stringify(envelope.protocolMetadata ?? {}),
          envelope.senderSequence,
          expiresAt,
          envelope.messageType,
        ],
      );

      const row = inserted[0];
      results.push(
        row === undefined
          ? { recipientDeviceId: envelope.recipientDeviceId, status: 'duplicate' }
          : { recipientDeviceId: envelope.recipientDeviceId, status: 'accepted', messageId: row.id },
      );
    }

    return results;
  });

  // Push notifications happen after the transaction commits, so a recipient is
  // never told about a message that was rolled back.
  for (const outcome of outcomes) {
    if (outcome.status !== 'accepted') continue;
    try {
      await publishToDevice(outcome.recipientDeviceId, {
        type: 'message.queued',
        messageId: outcome.messageId,
        senderDeviceId: params.senderDeviceId,
        recipientDeviceId: outcome.recipientDeviceId,
        at: new Date().toISOString(),
      });
    } catch (error) {
      // The message is already durably stored. Real-time delivery is an
      // optimisation over store-and-forward, so a publish failure is logged and
      // the recipient picks the message up on reconnect.
      logger.warn(
        { err: error instanceof Error ? error.message : String(error) },
        'realtime publish failed; message remains queued',
      );
    }
  }

  const duplicates = outcomes.filter((outcome) => outcome.status === 'duplicate').length;
  if (duplicates > 0) {
    await recordSecurityEvent(logger, {
      type: 'message.duplicate',
      userId: params.senderUserId,
      deviceId: params.senderDeviceId,
      metadata: { duplicates, batchSize: params.envelopes.length },
    });
  }

  return outcomes;
}

/**
 * Drains queued envelopes for one device.
 *
 * Ordering is explicit rather than incidental: per sending device, envelopes
 * come back in the sender's own sequence order, which is the only ordering the
 * sender can guarantee. Across different senders, order is by arrival.
 */
export async function fetchQueued(
  deviceId: string,
  limit: number,
): Promise<QueuedEnvelope[]> {
  const rows = await query<{
    id: string;
    envelope_version: number;
    sender_device_id: string;
    sender_user_id: string;
    sender_device_index: number;
    recipient_device_id: string;
    protocol: string;
    message_type: string;
    ciphertext: Buffer;
    protocol_metadata: Record<string, unknown>;
    sender_sequence: string;
    created_at: Date;
  }>(
    `SELECT m.id, m.envelope_version, m.sender_device_id, d.user_id AS sender_user_id,
            d.device_index AS sender_device_index, m.recipient_device_id, m.protocol,
            m.message_type, m.ciphertext, m.protocol_metadata,
            m.sender_sequence, m.created_at
       FROM messages m
       JOIN devices d ON d.id = m.sender_device_id
      WHERE m.recipient_device_id = $1
        AND m.delivery_state = 'queued'
      ORDER BY m.created_at, m.sender_device_id, m.sender_sequence
      LIMIT $2`,
    [deviceId, Math.min(limit, MAX_QUEUE_FETCH)],
  );

  return rows.map((row) => ({
    messageId: row.id,
    envelopeVersion: row.envelope_version,
    senderDeviceId: row.sender_device_id,
    senderUserId: row.sender_user_id,
    senderDeviceIndex: row.sender_device_index,
    recipientDeviceId: row.recipient_device_id,
    protocol: row.protocol,
    messageType: row.message_type as EnvelopeMessageType,
    ciphertext: encodeBase64(row.ciphertext),
    protocolMetadata: row.protocol_metadata,
    senderSequence: Number(row.sender_sequence),
    createdAt: row.created_at.toISOString(),
  }));
}

export type AckKind = 'delivered' | 'read';

/**
 * Acknowledges a message.
 *
 * Only the recipient device may acknowledge, and the state machine only moves
 * forward: queued to delivered to read. Acknowledgements carry no plaintext.
 */
export async function acknowledge(
  logger: FastifyBaseLogger,
  params: { deviceId: string; messageId: string; kind: AckKind },
): Promise<{ deliveryState: string }> {
  const result = await withTransaction(async (client) => {
    const { rows } = await client.query<{
      recipient_device_id: string;
      sender_device_id: string;
      delivery_state: string;
    }>(
      `SELECT recipient_device_id, sender_device_id, delivery_state
         FROM messages WHERE id = $1 FOR UPDATE`,
      [params.messageId],
    );
    const message = rows[0];

    // Not found and not yours are the same answer.
    if (message === undefined || message.recipient_device_id !== params.deviceId) {
      throw new AppError('not_found', {
        logMessage: 'acknowledgement for a message the device cannot see',
        logContext: { deviceId: params.deviceId, messageId: params.messageId },
        securityEvent: true,
      });
    }

    if (params.kind === 'delivered') {
      // Idempotent, and never moves 'read' backwards.
      const { rows: updated } = await client.query<{ delivery_state: string }>(
        `UPDATE messages
            SET delivery_state = 'delivered', delivered_at = COALESCE(delivered_at, now())
          WHERE id = $1 AND delivery_state = 'queued'
          RETURNING delivery_state`,
        [params.messageId],
      );
      return {
        deliveryState: updated[0]?.delivery_state ?? message.delivery_state,
        senderDeviceId: message.sender_device_id,
      };
    }

    // Marking read implies delivered, so set both and keep the timestamps
    // consistent with the table's CHECK constraints.
    const { rows: updated } = await client.query<{ delivery_state: string }>(
      `UPDATE messages
          SET delivery_state = 'read',
              delivered_at = COALESCE(delivered_at, now()),
              read_at = COALESCE(read_at, now())
        WHERE id = $1 AND delivery_state IN ('queued', 'delivered')
        RETURNING delivery_state`,
      [params.messageId],
    );
    return {
      deliveryState: updated[0]?.delivery_state ?? message.delivery_state,
      senderDeviceId: message.sender_device_id,
    };
  });

  // Tell the sender, so its UI can show the receipt without polling.
  try {
    await publishToDevice(result.senderDeviceId, {
      type: params.kind === 'delivered' ? 'message.delivered' : 'message.read',
      messageId: params.messageId,
      recipientDeviceId: params.deviceId,
      at: new Date().toISOString(),
    });
  } catch (error) {
    logger.warn(
      { err: error instanceof Error ? error.message : String(error) },
      'receipt publish failed',
    );
  }

  return { deliveryState: result.deliveryState };
}

/**
 * Deletes delivered messages and expired queued ones.
 *
 * The server is a relay, not an archive: once a message is acknowledged it has
 * no reason to exist here, and deleting it is the single largest reduction in
 * what a stolen database yields. See docs/security-model.md section 3.
 */
export async function sweepMessages(
  logger: FastifyBaseLogger,
): Promise<{ deliveredRemoved: number; expiredRemoved: number }> {
  const delivered = await query<{ id: string }>(
    `DELETE FROM messages
      WHERE delivery_state IN ('delivered', 'read')
      RETURNING id`,
  );
  const expired = await query<{ id: string }>(
    `DELETE FROM messages
      WHERE delivery_state = 'queued' AND expires_at <= now()
      RETURNING id`,
  );

  if (delivered.length > 0 || expired.length > 0) {
    logger.info(
      { deliveredRemoved: delivered.length, expiredRemoved: expired.length },
      'message retention sweep',
    );
  }

  return { deliveredRemoved: delivered.length, expiredRemoved: expired.length };
}
