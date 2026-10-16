/**
 * Message endpoints.
 *
 * All four require a DEVICE-bound session, not merely an authenticated account:
 * messages are addressed device to device, and an account-level token has no
 * device to be the sender or the recipient of an acknowledgement.
 */

import { Type } from '@sinclair/typebox';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { FastifyInstance } from 'fastify';

import type { Config } from '../../config/env.ts';
import { base64Pattern } from '../../core/encoding.ts';
import { authenticate, requireDevice } from '../../middleware/authenticate.ts';
import { touchDeviceLastSeen } from '../devices/devices.service.ts';
import {
  acknowledge,
  fetchQueued,
  MAX_ENVELOPES_PER_REQUEST,
  MAX_QUEUE_FETCH,
  sendMessages,
} from './messages.service.ts';

const MessageTypeSchema = Type.Union([Type.Literal('prekey'), Type.Literal('signal')]);

const EnvelopeSchema = Type.Object(
  {
    recipientDeviceId: Type.String({ format: 'uuid' }),
    // Versioned so the protocol can change without ambiguity.
    envelopeVersion: Type.Integer({ minimum: 1, maximum: 1 }),
    messageType: MessageTypeSchema,
    // Base64 of authenticated ciphertext. 65536 bytes raw -> ~87400 base64.
    ciphertext: Type.String({ pattern: base64Pattern(), minLength: 4, maxLength: 87_400 }),
    senderSequence: Type.Integer({ minimum: 0 }),
    // Deliberately a free-form object so protocol metadata can evolve. There is
    // no field here for a preview, a subject or anything plaintext-derived.
    protocolMetadata: Type.Optional(Type.Object({}, { additionalProperties: true })),
  },
  { additionalProperties: false },
);

const QueuedEnvelopeSchema = Type.Object(
  {
    messageId: Type.String({ format: 'uuid' }),
    envelopeVersion: Type.Integer(),
    senderDeviceId: Type.String({ format: 'uuid' }),
    senderUserId: Type.String({ format: 'uuid' }),
    senderDeviceIndex: Type.Integer(),
    recipientDeviceId: Type.String({ format: 'uuid' }),
    protocol: Type.String(),
    messageType: Type.String(),
    ciphertext: Type.String(),
    protocolMetadata: Type.Object({}, { additionalProperties: true }),
    senderSequence: Type.Integer(),
    createdAt: Type.String(),
  },
  { additionalProperties: false },
);

const MessageIdParams = Type.Object(
  { messageId: Type.String({ format: 'uuid' }) },
  { additionalProperties: false },
);

export function registerMessageRoutes(app: FastifyInstance, config: Config): void {
  const typed = app.withTypeProvider<TypeBoxTypeProvider>();

  typed.post(
    '/messages',
    {
      preHandler: authenticate,
      config: {
        rateLimit: { max: config.rateLimits.messageSendPerMinute, timeWindow: '1 minute' },
      },
      schema: {
        body: Type.Object(
          {
            // One envelope per recipient device: the client encrypts separately
            // for each, so a single logical message to a multi-device contact
            // arrives as several envelopes in one request.
            envelopes: Type.Array(EnvelopeSchema, {
              minItems: 1,
              maxItems: MAX_ENVELOPES_PER_REQUEST,
            }),
          },
          { additionalProperties: false },
        ),
        response: {
          201: Type.Object(
            {
              results: Type.Array(
                Type.Object(
                  {
                    recipientDeviceId: Type.String({ format: 'uuid' }),
                    status: Type.String(),
                    messageId: Type.Optional(Type.String({ format: 'uuid' })),
                  },
                  { additionalProperties: false },
                ),
              ),
            },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      const auth = requireDevice(request);
      const results = await sendMessages(request.log, {
        senderUserId: auth.userId,
        senderDeviceId: auth.deviceId,
        envelopes: request.body.envelopes,
        queuedTtlDays: config.retention.queuedMessageTtlDays,
      });
      await touchDeviceLastSeen(auth.deviceId);
      return reply.code(201).send({ results });
    },
  );

  typed.get(
    '/messages',
    {
      preHandler: authenticate,
      schema: {
        querystring: Type.Object(
          {
            // A bounded numeric STRING, not an Integer.
            //
            // Query parameters arrive as strings, and Ajv runs with
            // coerceTypes: false (see app.ts) on purpose. An Integer schema
            // here could therefore never match, so the documented
            // `?limit=N` was rejected as validation_failed for every value —
            // found by the client's vertical-slice test, which was the first
            // caller to actually pass it.
            //
            // Fixed this way rather than by enabling coercion, which is global
            // and would weaken every other schema in the API: "1" would
            // satisfy a number and "true" a boolean everywhere.
            limit: Type.Optional(Type.String({ pattern: '^[1-9][0-9]{0,2}$' })),
          },
          { additionalProperties: false },
        ),
        response: { 200: Type.Array(QueuedEnvelopeSchema) },
      },
    },
    async (request, reply) => {
      // Scoped to the calling device. There is no parameter for whose queue to
      // read, so one device cannot drain another's.
      const auth = requireDevice(request);
      // The pattern bounds this to 1-999; fetchQueued clamps to
      // MAX_QUEUE_FETCH, so the ceiling is enforced server-side regardless.
      const limit =
        request.query.limit === undefined ? 50 : Number(request.query.limit);
      const queued = await fetchQueued(auth.deviceId, Math.min(limit, MAX_QUEUE_FETCH));
      await touchDeviceLastSeen(auth.deviceId);
      return reply.code(200).send(queued);
    },
  );

  for (const kind of ['delivered', 'read'] as const) {
    typed.post(
      `/messages/:messageId/${kind}`,
      {
        preHandler: authenticate,
        schema: {
          params: MessageIdParams,
          response: {
            200: Type.Object({ deliveryState: Type.String() }, { additionalProperties: false }),
          },
        },
      },
      async (request, reply) => {
        const auth = requireDevice(request);
        const result = await acknowledge(request.log, {
          deviceId: auth.deviceId,
          messageId: request.params.messageId,
          kind,
        });
        return reply.code(200).send(result);
      },
    );
  }
}
