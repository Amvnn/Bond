/**
 * Shared test helpers.
 *
 * IMPORTANT, and worth being precise about: the key material here is random
 * bytes of the correct SHAPE, not real Signal keys, and the "ciphertext" is
 * random bytes too. These tests therefore prove the SERVER's behaviour —
 * routing, authorisation, state machines, storage — and deliberately prove that
 * the server works without understanding any of it.
 *
 * They do NOT prove end-to-end encryption. That is proven separately, against
 * the real library, by client/test/libsignal_validation_test.dart. Conflating
 * the two would be exactly the sort of "it has encryption so it is secure"
 * claim the project brief warns against.
 */

import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { expect } from 'vitest';

export const PASSWORD = 'correct-horse-battery-staple';

/** X25519 public keys serialise to 33 bytes in libsignal. */
export function publicKeyB64(): string {
  return randomBytes(33).toString('base64');
}

/** XEdDSA signatures are 64 bytes. */
export function signatureB64(): string {
  return randomBytes(64).toString('base64');
}

/** Kyber-1024 public keys are ~1568 bytes. */
export function kyberKeyB64(): string {
  return randomBytes(1568).toString('base64');
}

export function ciphertextB64(bytes = 128): string {
  return randomBytes(bytes).toString('base64');
}

export interface SessionTokens {
  userId: string;
  accessToken: string;
  refreshToken: string;
}

export interface DeviceHandle {
  deviceId: string;
  deviceIndex: number;
  /** Device-scoped token; messaging endpoints require the device claim. */
  accessToken: string;
}

export interface Actor extends SessionTokens {
  username: string;
  device?: DeviceHandle;
}

function auth(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

export async function registerActor(
  app: FastifyInstance,
  username: string,
  invitationToken?: string,
): Promise<Actor> {
  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: {
      username,
      password: PASSWORD,
      ...(invitationToken !== undefined ? { invitationToken } : {}),
    },
  });
  expect(response.statusCode, `register ${username}: ${response.body}`).toBe(201);
  const body = response.json<SessionTokens>();
  return { ...body, username };
}

/**
 * Registers a device with a full set of public key material, mirroring the
 * provisioning flow in docs/architecture.md section 6.
 */
export async function registerDeviceFor(
  app: FastifyInstance,
  actor: Actor,
  options: { deviceName?: string; oneTimePreKeyCount?: number } = {},
): Promise<DeviceHandle> {
  const count = options.oneTimePreKeyCount ?? 10;
  const response = await app.inject({
    method: 'POST',
    url: '/devices/register',
    headers: auth(actor.accessToken),
    payload: {
      deviceName: options.deviceName ?? `${actor.username}-windows`,
      platform: 'windows',
      registrationId: 1 + Math.floor(Math.random() * 16_000),
      publicIdentityKey: publicKeyB64(),
      signedPreKey: { id: 1, publicKey: publicKeyB64(), signature: signatureB64() },
      kyberPreKey: {
        id: 1,
        publicKey: kyberKeyB64(),
        signature: signatureB64(),
        isLastResort: true,
      },
      oneTimePreKeys: Array.from({ length: count }, (_, index) => ({
        id: index + 1,
        publicKey: publicKeyB64(),
      })),
    },
  });

  expect(response.statusCode, `register device for ${actor.username}: ${response.body}`).toBe(201);
  const device = response.json<DeviceHandle>();
  actor.device = device;
  return device;
}

export async function createInvitation(
  app: FastifyInstance,
  actor: Actor,
): Promise<{ invitationId: string; token: string }> {
  const response = await app.inject({
    method: 'POST',
    url: '/invitations',
    headers: auth(actor.accessToken),
    payload: {},
  });
  expect(response.statusCode, `create invitation: ${response.body}`).toBe(201);
  return response.json<{ invitationId: string; token: string }>();
}

export function authHeader(token: string): Record<string, string> {
  return auth(token);
}

export function deviceToken(actor: Actor): string {
  if (actor.device === undefined) {
    throw new Error(`${actor.username} has no registered device`);
  }
  return actor.device.accessToken;
}

export function deviceId(actor: Actor): string {
  if (actor.device === undefined) {
    throw new Error(`${actor.username} has no registered device`);
  }
  return actor.device.deviceId;
}
