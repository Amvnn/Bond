/**
 * Authentication endpoints.
 *
 * Every schema is strict (`additionalProperties: false`): an unexpected field is
 * a rejected request, not a silently ignored one.
 *
 * Refresh tokens travel in the response body rather than a cookie. The clients
 * are native apps that store them in platform secure storage, so there is no
 * browser to protect and no CSRF surface to reason about.
 */

import { Type } from '@sinclair/typebox';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { FastifyInstance } from 'fastify';

import type { Config } from '../../config/env.ts';
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from './password.ts';
import { issueAccessToken } from './access-token.ts';
import { login, register, type AuthDeps } from './auth.service.ts';
import {
  revokeSessionByToken,
  rotateSession,
  type SessionDeps,
} from './session.service.ts';
import { recordSecurityEvent } from '../security/security-events.ts';
import { TOKEN_LENGTH } from '../../core/tokens.ts';

const UsernameSchema = Type.String({
  pattern: '^[A-Za-z0-9_]{3,32}$',
  description: 'Login handle. Not a cryptographic identity.',
});

const PasswordSchema = Type.String({
  minLength: MIN_PASSWORD_LENGTH,
  maxLength: MAX_PASSWORD_LENGTH,
});

const OpaqueTokenSchema = Type.String({
  minLength: TOKEN_LENGTH,
  maxLength: TOKEN_LENGTH,
  pattern: '^[A-Za-z0-9_-]+$',
});

const SessionResponse = Type.Object(
  {
    userId: Type.String({ format: 'uuid' }),
    accessToken: Type.String(),
    refreshToken: Type.String(),
    accessTokenExpiresIn: Type.String(),
    refreshTokenExpiresAt: Type.String({ format: 'date-time' }),
  },
  { additionalProperties: false },
);

export function registerAuthRoutes(app: FastifyInstance, config: Config): void {
  const typed = app.withTypeProvider<TypeBoxTypeProvider>();

  const authDeps: AuthDeps = {
    refreshPepper: config.refreshTokenSecret,
    refreshTtlDays: config.refreshTokenTtlDays,
    invitationPepper: config.invitationTokenPepper,
    allowBootstrapAccount: config.allowBootstrapAccount,
  };
  const sessionDeps: SessionDeps = {
    refreshPepper: config.refreshTokenSecret,
    refreshTtlDays: config.refreshTokenTtlDays,
  };

  typed.post(
    '/auth/register',
    {
      config: {
        rateLimit: { max: config.rateLimits.registerPerHour, timeWindow: '1 hour' },
      },
      schema: {
        body: Type.Object(
          {
            username: UsernameSchema,
            password: PasswordSchema,
            // Absent only on the bootstrap path, which is env-gated and may
            // create user #1 alone. See docs/decisions.md D3.
            invitationToken: Type.Optional(OpaqueTokenSchema),
          },
          { additionalProperties: false },
        ),
        response: { 201: SessionResponse },
      },
    },
    async (request, reply) => {
      const result = await register(request.log, authDeps, {
        username: request.body.username,
        password: request.body.password,
        invitationToken: request.body.invitationToken,
        userAgent: request.headers['user-agent'],
      });

      const accessToken = issueAccessToken(
        app,
        { userId: result.userId, sessionId: result.session.sessionId },
        config.accessTokenTtl,
      );

      return reply.code(201).send({
        userId: result.userId,
        accessToken,
        refreshToken: result.session.refreshToken,
        accessTokenExpiresIn: config.accessTokenTtl,
        refreshTokenExpiresAt: result.session.expiresAt.toISOString(),
      });
    },
  );

  typed.post(
    '/auth/login',
    {
      config: {
        rateLimit: { max: config.rateLimits.authPer15m, timeWindow: '15 minutes' },
      },
      schema: {
        body: Type.Object(
          { username: Type.String({ maxLength: 64 }), password: Type.String({ maxLength: MAX_PASSWORD_LENGTH }) },
          { additionalProperties: false },
        ),
        response: { 200: SessionResponse },
      },
    },
    async (request, reply) => {
      const result = await login(request.log, sessionDeps, {
        username: request.body.username,
        password: request.body.password,
        userAgent: request.headers['user-agent'],
      });

      const accessToken = issueAccessToken(
        app,
        { userId: result.userId, sessionId: result.session.sessionId },
        config.accessTokenTtl,
      );

      return reply.code(200).send({
        userId: result.userId,
        accessToken,
        refreshToken: result.session.refreshToken,
        accessTokenExpiresIn: config.accessTokenTtl,
        refreshTokenExpiresAt: result.session.expiresAt.toISOString(),
      });
    },
  );

  typed.post(
    '/auth/refresh',
    {
      config: {
        rateLimit: { max: config.rateLimits.authPer15m, timeWindow: '15 minutes' },
      },
      schema: {
        body: Type.Object({ refreshToken: OpaqueTokenSchema }, { additionalProperties: false }),
        response: { 200: SessionResponse },
      },
    },
    async (request, reply) => {
      const rotated = await rotateSession(sessionDeps, request.body.refreshToken);

      await recordSecurityEvent(request.log, {
        type: 'auth.refresh.success',
        userId: rotated.userId,
        ...(rotated.deviceId !== null ? { deviceId: rotated.deviceId } : {}),
      });

      const accessToken = issueAccessToken(
        app,
        {
          userId: rotated.userId,
          sessionId: rotated.session.sessionId,
          deviceId: rotated.deviceId ?? undefined,
        },
        config.accessTokenTtl,
      );

      return reply.code(200).send({
        userId: rotated.userId,
        accessToken,
        refreshToken: rotated.session.refreshToken,
        accessTokenExpiresIn: config.accessTokenTtl,
        refreshTokenExpiresAt: rotated.session.expiresAt.toISOString(),
      });
    },
  );

  typed.post(
    '/auth/logout',
    {
      schema: {
        body: Type.Object({ refreshToken: OpaqueTokenSchema }, { additionalProperties: false }),
        response: {
          204: Type.Null(),
        },
      },
    },
    async (request, reply) => {
      // Always 204. Whether the token existed is not disclosed, and a client
      // clearing its local state should not be told its token was already dead.
      const revoked = await revokeSessionByToken(sessionDeps, request.body.refreshToken);
      if (revoked) {
        await recordSecurityEvent(request.log, { type: 'auth.logout' });
      }
      return reply.code(204).send(null);
    },
  );
}
