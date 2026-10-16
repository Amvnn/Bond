/**
 * Contact endpoints.
 *
 * There is deliberately no search, no directory and no lookup-by-username.
 * Contacts are reachable only through an accepted invitation, so this surface
 * cannot be used to discover who else has an account.
 */

import { Type } from '@sinclair/typebox';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { FastifyInstance } from 'fastify';

import { authenticate, requireAuth } from '../../middleware/authenticate.ts';
import { getContact, listContacts, setContactVerification } from './contacts.service.ts';

const ContactDeviceSchema = Type.Object(
  {
    deviceId: Type.String({ format: 'uuid' }),
    deviceIndex: Type.Integer(),
    registrationId: Type.Integer(),
    publicIdentityKey: Type.String(),
    lastSeenAt: Type.Union([Type.String(), Type.Null()]),
  },
  { additionalProperties: false },
);

const ContactSchema = Type.Object(
  {
    contactUserId: Type.String({ format: 'uuid' }),
    username: Type.String(),
    status: Type.String(),
    // Advisory only; the client holds the authoritative verification state.
    verifiedAt: Type.Union([Type.String(), Type.Null()]),
    createdAt: Type.String(),
    devices: Type.Array(ContactDeviceSchema),
  },
  { additionalProperties: false },
);

const ContactIdParams = Type.Object(
  { contactId: Type.String({ format: 'uuid' }) },
  { additionalProperties: false },
);

export function registerContactRoutes(app: FastifyInstance): void {
  const typed = app.withTypeProvider<TypeBoxTypeProvider>();

  typed.get(
    '/contacts',
    {
      preHandler: authenticate,
      schema: { response: { 200: Type.Array(ContactSchema) } },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      return reply.code(200).send(await listContacts(auth.userId));
    },
  );

  typed.get(
    '/contacts/:contactId',
    {
      preHandler: authenticate,
      schema: { params: ContactIdParams, response: { 200: ContactSchema } },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      return reply.code(200).send(await getContact(auth.userId, request.params.contactId));
    },
  );

  typed.post(
    '/contacts/:contactId/verify',
    {
      preHandler: authenticate,
      schema: {
        params: ContactIdParams,
        body: Type.Object({ verified: Type.Boolean() }, { additionalProperties: false }),
        response: {
          200: Type.Object(
            { verifiedAt: Type.Union([Type.String(), Type.Null()]) },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      const result = await setContactVerification(request.log, {
        userId: auth.userId,
        contactUserId: request.params.contactId,
        verified: request.body.verified,
      });
      return reply.code(200).send(result);
    },
  );
}
