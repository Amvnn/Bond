/**
 * Invitation endpoints.
 *
 * Two deliberate deviations from the endpoint names in the project brief, which
 * allows adjusting them where the protocol requires:
 *
 *   brief: POST /invitations/{token}/accept   here: POST /invitations/accept  (token in body)
 *   brief: POST /invitations/{token}/revoke   here: POST /invitations/{id}/revoke
 *
 * An invitation token is a credential. A credential in a URL path lands in
 * access logs, proxy logs, browser history and error reports, and our own
 * request logger would have to special-case it. Keeping it in the body means it
 * is covered by the existing redaction rules instead.
 */

import { Type } from '@sinclair/typebox';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { FastifyInstance } from 'fastify';

import type { Config } from '../../config/env.ts';
import { TOKEN_LENGTH } from '../../core/tokens.ts';
import { authenticate, requireAuth } from '../../middleware/authenticate.ts';
import {
  acceptInvitation,
  createInvitation,
  listInvitations,
  revokeInvitation,
} from './invitations.service.ts';

const OpaqueTokenSchema = Type.String({
  minLength: TOKEN_LENGTH,
  maxLength: TOKEN_LENGTH,
  pattern: '^[A-Za-z0-9_-]+$',
});

export function registerInvitationRoutes(app: FastifyInstance, config: Config): void {
  const typed = app.withTypeProvider<TypeBoxTypeProvider>();

  typed.post(
    '/invitations',
    {
      preHandler: authenticate,
      config: {
        rateLimit: { max: config.rateLimits.inviteCreatePerDay, timeWindow: '1 day' },
      },
      schema: {
        body: Type.Object(
          {
            purpose: Type.Optional(
              Type.Union([
                Type.Literal('register_and_befriend'),
                Type.Literal('register_only'),
                Type.Literal('befriend_only'),
              ]),
            ),
          },
          { additionalProperties: false },
        ),
        response: {
          201: Type.Object(
            {
              invitationId: Type.String({ format: 'uuid' }),
              // The ONLY time this value is ever returned. It is not stored and
              // cannot be retrieved again.
              token: Type.String(),
              expiresAt: Type.String(),
              purpose: Type.String(),
            },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      const invitation = await createInvitation(request.log, {
        creatorUserId: auth.userId,
        pepper: config.invitationTokenPepper,
        ttlHours: config.retention.invitationTtlHours,
        purpose: request.body.purpose,
      });
      return reply.code(201).send(invitation);
    },
  );

  typed.get(
    '/invitations',
    {
      preHandler: authenticate,
      schema: {
        response: {
          200: Type.Array(
            Type.Object(
              {
                invitationId: Type.String({ format: 'uuid' }),
                purpose: Type.String(),
                createdAt: Type.String(),
                expiresAt: Type.String(),
                usedAt: Type.Union([Type.String(), Type.Null()]),
                revokedAt: Type.Union([Type.String(), Type.Null()]),
                status: Type.String(),
              },
              { additionalProperties: false },
            ),
          ),
        },
      },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      return reply.code(200).send(await listInvitations(auth.userId));
    },
  );

  typed.post(
    '/invitations/accept',
    {
      preHandler: authenticate,
      config: {
        rateLimit: { max: config.rateLimits.inviteAcceptPerHour, timeWindow: '1 hour' },
      },
      schema: {
        body: Type.Object({ token: OpaqueTokenSchema }, { additionalProperties: false }),
        response: {
          200: Type.Object(
            {
              contactUserId: Type.String({ format: 'uuid' }),
              invitationId: Type.String({ format: 'uuid' }),
            },
            { additionalProperties: false },
          ),
        },
      },
    },
    async (request, reply) => {
      // For an account that already exists. A brand-new user accepts implicitly
      // by registering with the token.
      const auth = requireAuth(request);
      const accepted = await acceptInvitation(request.log, {
        accepterUserId: auth.userId,
        token: request.body.token,
        pepper: config.invitationTokenPepper,
      });
      return reply.code(200).send(accepted);
    },
  );

  typed.post(
    '/invitations/:invitationId/revoke',
    {
      preHandler: authenticate,
      schema: {
        params: Type.Object(
          { invitationId: Type.String({ format: 'uuid' }) },
          { additionalProperties: false },
        ),
        response: { 204: Type.Null() },
      },
    },
    async (request, reply) => {
      const auth = requireAuth(request);
      await revokeInvitation(request.log, {
        userId: auth.userId,
        invitationId: request.params.invitationId,
      });
      return reply.code(204).send(null);
    },
  );
}
