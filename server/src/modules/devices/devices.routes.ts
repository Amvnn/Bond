/**
 * Device and prekey endpoints.
 *
 * `/devices/{id}/public-keys` is the most security-sensitive route in the
 * system: it is where a malicious server would substitute a key. It is
 * authorised to contacts only, rate-limited against prekey drain, and consumes
 * one-time prekeys atomically.
 */

import { Type } from '@sinclair/typebox';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { FastifyInstance } from 'fastify';

import type { Config } from '../../config/env.ts';
import { base64Pattern } from '../../core/encoding.ts';
import { authenticate, requireAuth, requireDevice } from '../../middleware/authenticate.ts';
import { issueAccessToken } from '../auth/access-token.ts';
import {
  fetchPreKeyBundle,
  listDevices,
  MAX_ONE_TIME_PREKEYS_PER_REQUEST,
  registerDevice,
  replenishOneTimePreKeys,
  revokeDevice,
  type Platform,
} from './devices.service.ts';

const Base64 = (maxLength: number) =>
  Type.String({ pattern: base64Pattern(), minLength: 4, maxLength });

const PreKeySchema = Type.Object(
  {
    id: Type.Integer({ minimum: 0, maximum: 16_777_215 }),
    publicKey: Base64(64),
  },
  { additionalProperties: false },
);

const SignedPreKeySchema = Type.Object(
  {
    id: Type.Integer({ minimum: 0, maximum: 16_777_215 }),
    publicKey: Base64(64),
    signature: Base64(128),
  },
  { additionalProperties: false },
);

const KyberPreKeySchema = Type.Object(
  {
    id: Type.Integer({ minimum: 0, maximum: 16_777_215 }),
    publicKey: Base64(4096),
    signature: Base64(128),
    isLastResort: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);

const DeviceSummarySchema = Type.Object(
  {
    deviceId: Type.String({ format: 'uuid' }),
    deviceIndex: Type.Integer(),
    deviceName: Type.String(),
    platform: Type.String(),
    publicIdentityKey: Type.String(),
    registrationId: Type.Integer(),
    createdAt: Type.String(),
    lastSeenAt: Type.Union([Type.String(), Type.Null()]),
    revokedAt: Type.Union([Type.String(), Type.Null()]),
    availableOneTimePreKeys: Type.Integer(),
  },
  { additionalProperties: false },
);

const DeviceIdParams = Type.Object(
  { deviceId: Type.String({ format: 'uuid' }) },
  { additionalProperties: false },
);

export function registerDeviceRoutes(app: FastifyInstance, config: Config): void {
  const typed = app.withTypeProvider<TypeBoxTypeProvider>();

  typed.post(
    '/devices/register',
    {
      preHandler: authenticate,
      schema: {
        body: Type.Object(
          {
            deviceName: Type.String({ minLength: 1, maxLength: 64 }),
            platform: Type.Union([
              Type.Literal('android'),
              Type.Literal('ios'),
              Type.Literal('windows'),
              Type.Literal('linux'),
              Type.Literal('macos'),
            ]),
            registrationId: Type.Integer({ minimum: 1, maximum: 16_383 }),
            publicIdentityKey: Base64(64),
            signedPreKey: SignedPreKeySchema,
            // Mandatory: libsignal requires a Kyber prekey to assemble a bundle.
            kyberPreKey: KyberPreKeySchema,
            oneTimePreKeys: Type.Array(PreKeySchema, {
              minItems: 10,
              maxItems: MAX_ONE_TIME_PREKEYS_PER_REQUEST,
            }),
          },
          { additionalProperties: false },
        ),
        response: {
          201: Type.Object(
            {
              deviceId: Type.String({ format: 'uuid' }),
              deviceIndex: Type.Integer(),
              // Device-scoped replacement for the account-scoped token used to
              // make this call. Messaging endpoints require the device claim.
              accessToken: Type.String(),
            },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      const auth = requireAuth(request);

      const registered = await registerDevice(request.log, {
        userId: auth.userId,
        sessionId: auth.sessionId,
        deviceName: request.body.deviceName,
        platform: request.body.platform as Platform,
        registrationId: request.body.registrationId,
        publicIdentityKey: request.body.publicIdentityKey,
        signedPreKey: request.body.signedPreKey,
        kyberPreKey: request.body.kyberPreKey,
        oneTimePreKeys: request.body.oneTimePreKeys,
      });

      const accessToken = issueAccessToken(
        app,
        { userId: auth.userId, sessionId: auth.sessionId, deviceId: registered.deviceId },
        config.accessTokenTtl,
      );

      return reply.code(201).send({ ...registered, accessToken });
    },
  );

  typed.get(
    '/devices',
    {
      preHandler: authenticate,
      schema: { response: { 200: Type.Array(DeviceSummarySchema) } },
    },
    async (request, reply) => {
      // Scoped to the token subject: there is no way to ask for anyone else's.
      const auth = requireAuth(request);
      return reply.code(200).send(await listDevices(auth.userId));
    },
  );

  typed.post(
    '/devices/:deviceId/revoke',
    {
      preHandler: authenticate,
      schema: { params: DeviceIdParams, response: { 204: Type.Null() } },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      await revokeDevice(request.log, {
        userId: auth.userId,
        deviceId: request.params.deviceId,
      });
      return reply.code(204).send(null);
    },
  );

  typed.post(
    '/devices/:deviceId/key-material',
    {
      preHandler: authenticate,
      schema: {
        params: DeviceIdParams,
        body: Type.Object(
          {
            oneTimePreKeys: Type.Array(PreKeySchema, {
              minItems: 1,
              maxItems: MAX_ONE_TIME_PREKEYS_PER_REQUEST,
            }),
          },
          { additionalProperties: false },
        ),
        response: {
          200: Type.Object(
            { availableOneTimePreKeys: Type.Integer() },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      const result = await replenishOneTimePreKeys(request.log, {
        userId: auth.userId,
        deviceId: request.params.deviceId,
        oneTimePreKeys: request.body.oneTimePreKeys,
      });
      return reply.code(200).send(result);
    },
  );

  typed.get(
    '/devices/:deviceId/public-keys',
    {
      preHandler: authenticate,
      config: {
        // Each fetch consumes a one-time prekey, so an unthrottled caller could
        // drain a contact's supply and force weaker first-message secrecy.
        rateLimit: { max: config.rateLimits.prekeyFetchPerHour, timeWindow: '1 hour' },
      },
      schema: {
        params: DeviceIdParams,
        response: {
          200: Type.Object(
            {
              deviceId: Type.String({ format: 'uuid' }),
              userId: Type.String({ format: 'uuid' }),
              deviceIndex: Type.Integer(),
              registrationId: Type.Integer(),
              publicIdentityKey: Type.String(),
              signedPreKey: Type.Object({
                id: Type.Integer(),
                publicKey: Type.String(),
                signature: Type.String(),
              }),
              kyberPreKey: Type.Object({
                id: Type.Integer(),
                publicKey: Type.String(),
                signature: Type.String(),
              }),
              oneTimePreKey: Type.Union([
                Type.Object({ id: Type.Integer(), publicKey: Type.String() }),
                Type.Null(),
              ]),
            },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      // Device-bound session required: the consuming device is recorded against
      // the one-time prekey, which is useful audit trail if a key is misused.
      const auth = requireDevice(request);
      const bundle = await fetchPreKeyBundle(request.log, {
        requesterUserId: auth.userId,
        requesterDeviceId: auth.deviceId,
        targetDeviceId: request.params.deviceId,
      });
      return reply.code(200).send(bundle);
    },
  );
}
