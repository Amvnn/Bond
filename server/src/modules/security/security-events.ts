/**
 * Security audit log.
 *
 * Recording an event must never be able to break the request that triggered it:
 * a failed audit write is logged and swallowed, because refusing a legitimate
 * logout because the audit table is full would be a worse outcome.
 *
 * `metadata` is non-sensitive context ONLY. The sanitiser below enforces that
 * rather than trusting callers, because the one place a token will eventually
 * be passed by accident is an audit call.
 */

import type { FastifyBaseLogger } from 'fastify';

import { query } from '../../database/pool.ts';

export type SecurityEventType =
  // Authentication
  | 'auth.register.success'
  | 'auth.register.rejected'
  | 'auth.login.success'
  | 'auth.login.failed'
  | 'auth.refresh.success'
  | 'auth.refresh.reuse_detected'
  | 'auth.logout'
  | 'auth.session.revoked'
  // Invitations
  | 'invitation.created'
  | 'invitation.accepted'
  | 'invitation.rejected'
  | 'invitation.revoked'
  // Devices
  | 'device.registered'
  | 'device.revoked'
  | 'device.prekeys_replenished'
  | 'device.prekeys_exhausted'
  // Contacts and identity
  | 'contact.verified'
  | 'contact.identity_changed'
  // Messaging
  | 'message.rejected_unauthorised'
  | 'message.rejected_malformed'
  | 'message.duplicate'
  // Transport
  | 'ws.connected'
  | 'ws.disconnected'
  | 'ws.auth_failed'
  | 'ws.rejected_revoked_device'
  // Abuse
  | 'rate_limit.exceeded';

export type Severity = 'info' | 'warning' | 'critical';

const SEVERITY_BY_TYPE: Partial<Record<SecurityEventType, Severity>> = {
  'auth.login.failed': 'warning',
  'auth.register.rejected': 'warning',
  'auth.refresh.reuse_detected': 'critical',
  'invitation.rejected': 'warning',
  'contact.identity_changed': 'critical',
  'message.rejected_unauthorised': 'warning',
  'message.rejected_malformed': 'warning',
  'ws.auth_failed': 'warning',
  'ws.rejected_revoked_device': 'critical',
  'rate_limit.exceeded': 'warning',
};

/**
 * Keys that must never appear in audit metadata. Matching is on the key name,
 * case-insensitively, including substrings, so `userRefreshToken` is caught as
 * well as `token`.
 */
const FORBIDDEN_KEY_PATTERNS = [
  'password',
  'token',
  'secret',
  'ciphertext',
  'plaintext',
  'privatekey',
  'private_key',
  'message',
  'hash',
];

/** Caps applied to whatever survives the key filter. */
const MAX_METADATA_KEYS = 20;
const MAX_STRING_LENGTH = 256;

export interface SecurityEventInput {
  readonly type: SecurityEventType;
  readonly userId?: string | undefined;
  readonly deviceId?: string | undefined;
  readonly metadata?: Readonly<Record<string, unknown>> | undefined;
  readonly severity?: Severity | undefined;
}

/**
 * Strips anything that looks sensitive and flattens the rest to primitives.
 * Defence in depth: the logger redacts by path (core/logging.ts) and this
 * redacts by key name before the value reaches the database.
 */
export function sanitiseMetadata(
  metadata: Readonly<Record<string, unknown>> | undefined,
): Record<string, string | number | boolean | null> {
  if (metadata === undefined) return {};

  const result: Record<string, string | number | boolean | null> = {};
  let count = 0;

  for (const [key, value] of Object.entries(metadata)) {
    if (count >= MAX_METADATA_KEYS) break;

    const normalisedKey = key.toLowerCase();
    if (FORBIDDEN_KEY_PATTERNS.some((pattern) => normalisedKey.includes(pattern))) {
      result[key] = '[omitted]';
      count += 1;
      continue;
    }

    if (value === null) {
      result[key] = null;
    } else if (typeof value === 'string') {
      result[key] = value.length > MAX_STRING_LENGTH ? `${value.slice(0, MAX_STRING_LENGTH)}...` : value;
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      result[key] = value;
    } else if (typeof value === 'boolean') {
      result[key] = value;
    } else {
      // Objects, arrays, functions and symbols are dropped rather than
      // serialised: nested structures are how a secret sneaks in.
      result[key] = '[unsupported]';
    }
    count += 1;
  }

  return result;
}

export async function recordSecurityEvent(
  logger: FastifyBaseLogger,
  event: SecurityEventInput,
): Promise<void> {
  const severity = event.severity ?? SEVERITY_BY_TYPE[event.type] ?? 'info';
  const metadata = sanitiseMetadata(event.metadata);

  try {
    await query(
      `INSERT INTO security_events (user_id, device_id, event_type, severity, metadata)
       VALUES ($1, $2, $3, $4, $5)`,
      [event.userId ?? null, event.deviceId ?? null, event.type, severity, JSON.stringify(metadata)],
    );
  } catch (error) {
    // Never propagate: an audit failure must not fail the user's request.
    logger.error(
      { event: event.type, err: error instanceof Error ? error.message : String(error) },
      'failed to record security event',
    );
  }

  const line = { event: event.type, severity, userId: event.userId, deviceId: event.deviceId, ...metadata };
  if (severity === 'critical') logger.error(line, 'security event');
  else if (severity === 'warning') logger.warn(line, 'security event');
  else logger.info(line, 'security event');
}
