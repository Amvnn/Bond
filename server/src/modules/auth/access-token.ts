/**
 * Access-token issuing.
 *
 * Access tokens are short-lived JWTs and are NOT stored server-side. They carry
 * only identifiers — never a username, never key material, never anything that
 * would leak if the token were logged by an intermediary.
 *
 * `typ: 'access'` is load-bearing: the guard in middleware/authenticate.ts
 * refuses any token without it, so a credential minted for another purpose
 * cannot be replayed as an access token.
 */

import '@fastify/jwt';
import type { FastifyInstance } from 'fastify';

export interface AccessTokenParams {
  readonly userId: string;
  readonly sessionId: string;
  /** Present once the session is bound to a registered device. */
  readonly deviceId?: string | undefined;
}

export function issueAccessToken(
  app: FastifyInstance,
  params: AccessTokenParams,
  ttl: string,
): string {
  return app.jwt.sign(
    {
      sub: params.userId,
      sid: params.sessionId,
      typ: 'access',
      ...(params.deviceId !== undefined ? { did: params.deviceId } : {}),
    },
    { expiresIn: ttl },
  );
}
