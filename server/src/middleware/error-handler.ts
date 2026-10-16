/**
 * Central error handling.
 *
 * One rule: the client gets a code and a request id, the log gets the detail.
 * A stack trace or a database message in a response body tells an attacker
 * about the internals, so production responses never carry either.
 */

import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { AppError, isAppError } from '../core/errors.ts';
import { recordSecurityEvent } from '../modules/security/security-events.ts';

interface ErrorBody {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly requestId: string;
  };
}

function body(code: string, message: string, requestId: string): ErrorBody {
  return { error: { code, message, requestId } };
}

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler(async function errorHandler(
    error: FastifyError | AppError,
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const requestId = String(request.id);

    if (isAppError(error)) {
      // The log gets the internal message and context; the client gets neither.
      request.log.warn(
        { code: error.code, statusCode: error.statusCode, ...error.logContext, err: error.message },
        'request rejected',
      );

      if (error.securityEvent) {
        await recordSecurityEvent(request.log, {
          type:
            error.code === 'authentication_failed'
              ? 'auth.login.failed'
              : error.code === 'invitation_unusable'
                ? 'invitation.rejected'
                : error.code === 'device_revoked'
                  ? 'ws.rejected_revoked_device'
                  : 'message.rejected_unauthorised',
          ...(request.auth?.userId !== undefined ? { userId: request.auth.userId } : {}),
          ...(request.auth?.deviceId !== undefined ? { deviceId: request.auth.deviceId } : {}),
          metadata: { code: error.code, route: request.routeOptions?.url ?? 'unknown' },
        });
      }

      await reply
        .code(error.statusCode)
        .send(body(error.code, error.publicMessage, requestId));
      return;
    }

    // Fastify's own validation failures. The validation message describes the
    // schema, not the data, so it is safe to return and genuinely useful.
    if (error.validation !== undefined) {
      request.log.info({ err: error.message }, 'schema validation failed');
      await reply
        .code(400)
        .send(body('validation_failed', error.message, requestId));
      return;
    }

    if (error.statusCode === 429) {
      await recordSecurityEvent(request.log, {
        type: 'rate_limit.exceeded',
        ...(request.auth?.userId !== undefined ? { userId: request.auth.userId } : {}),
        metadata: { route: request.routeOptions?.url ?? 'unknown' },
      });
      await reply
        .code(429)
        .send(body('rate_limited', 'Too many requests. Try again later.', requestId));
      return;
    }

    // Body too large, malformed JSON and similar client faults.
    if (typeof error.statusCode === 'number' && error.statusCode >= 400 && error.statusCode < 500) {
      request.log.info({ err: error.message, statusCode: error.statusCode }, 'client error');
      await reply
        .code(error.statusCode)
        .send(body('validation_failed', 'The request was not valid.', requestId));
      return;
    }

    // Anything else is ours. Log everything, disclose nothing.
    request.log.error({ err: error, stack: error.stack }, 'unhandled error');
    await reply
      .code(500)
      .send(body('internal_error', 'An internal error occurred.', requestId));
  });

  app.setNotFoundHandler(async function notFoundHandler(request, reply) {
    // Deliberately identical whether the route exists or the caller lacks
    // access to it, so route probing learns nothing.
    await reply.code(404).send(body('not_found', 'Not found.', String(request.id)));
  });
}
