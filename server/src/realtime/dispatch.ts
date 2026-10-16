/**
 * Cross-process dispatch channel.
 *
 * The message service publishes here; the WebSocket hub subscribes. Going via
 * Redis rather than an in-process emitter means a recipient connected to a
 * different server instance still receives the push.
 *
 * What travels over this channel: a message id and routing metadata, so the
 * recipient knows to fetch. The ciphertext itself is fetched over HTTPS. That
 * keeps exactly one authorisation path for message bodies instead of two.
 */

import { getRedis } from '../core/redis.ts';

export type RealtimeEventType =
  | 'message.queued'
  | 'message.delivered'
  | 'message.read'
  | 'device.revoked';

export interface RealtimeEvent {
  readonly type: RealtimeEventType;
  /** Opaque message id, never ciphertext. */
  readonly messageId?: string;
  readonly senderDeviceId?: string;
  readonly recipientDeviceId?: string;
  readonly at: string;
}

export function deviceChannel(deviceId: string): string {
  return `pm:device:${deviceId}`;
}

/**
 * Publishes to a device's channel. Failure is logged by the caller but must not
 * fail the request: the message is already durably stored, so the recipient
 * will still receive it on its next poll or reconnect. Real-time delivery is an
 * optimisation over store-and-forward, never the system of record.
 */
export async function publishToDevice(
  deviceId: string,
  event: RealtimeEvent,
): Promise<void> {
  await getRedis().publish(deviceChannel(deviceId), JSON.stringify(event));
}
