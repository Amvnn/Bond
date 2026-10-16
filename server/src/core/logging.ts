/**
 * Logging policy, enforced at the logger rather than at each call site.
 *
 * Per-call-site discipline fails eventually: someone logs a whole request body
 * during a debugging session and it ships. So redaction is centralised here and
 * the deny-list is applied to every log record.
 *
 * NEVER logged: message plaintext, ciphertext, private keys, passwords, access
 * tokens, refresh tokens, invitation tokens, session secrets.
 *
 * See docs/security-model.md section 4.
 */

import type { FastifyServerOptions } from 'fastify';
import type { Config } from '../config/env.ts';

export const REDACTED = '[redacted]';

/**
 * Paths pino redacts. Covers the request/response shapes Fastify logs
 * automatically plus the field names used by this application's payloads.
 */
const REDACT_PATHS: readonly string[] = [
  // Credentials and tokens anywhere in a logged object.
  'password',
  '*.password',
  'newPassword',
  '*.newPassword',
  'token',
  '*.token',
  'accessToken',
  '*.accessToken',
  'refreshToken',
  '*.refreshToken',
  'invitationToken',
  '*.invitationToken',
  'secret',
  '*.secret',

  // Cryptographic payloads. Public keys are not secret, but there is no reason
  // to fill logs with them, and a mislabelled field could carry a private key.
  'ciphertext',
  '*.ciphertext',
  'privateKey',
  '*.privateKey',
  'identityKey',
  '*.identityKey',
  'preKeys',
  '*.preKeys',
  'signedPreKey',
  '*.signedPreKey',

  // Headers that carry credentials.
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["sec-websocket-protocol"]',
  'res.headers["set-cookie"]',

  // Bodies are not logged at all (see serializers below), but if a body ever
  // reaches a log through another path, redact it wholesale.
  'req.body',
  'body',
];

/**
 * Request/response serialisers. Deliberately minimal: method, path, status and
 * identifiers only. Query strings and bodies are excluded, because a query
 * string can carry a token if someone builds a URL carelessly.
 */
// The `| undefined` on each optional is required, not noise: under
// exactOptionalPropertyTypes a bare `url?: string` rejects Fastify's
// `string | undefined`, and the serialiser silently fails to typecheck.
const serializers = {
  req(request: {
    id?: string | undefined;
    method?: string | undefined;
    url?: string | undefined;
    ip?: string | undefined;
    routeOptions?: { url?: string | undefined } | undefined;
  }) {
    // Values are coerced to definite strings: Fastify's serialiser contract
    // requires them, and a log line reading "unknown" is more useful than one
    // with a missing field.
    return {
      id: request.id ?? 'unknown',
      method: request.method ?? 'unknown',
      // Prefer the route pattern over the concrete URL: it cannot contain an
      // invitation token or any other path parameter value.
      route: request.routeOptions?.url ?? stripQuery(request.url) ?? 'unknown',
      ip: request.ip ?? 'unknown',
    };
  },
  res(reply: { statusCode?: number | undefined }) {
    return { statusCode: reply.statusCode ?? 0 };
  },
  err(error: Error & { code?: string | undefined; statusCode?: number | undefined }) {
    return {
      type: error.name,
      code: error.code ?? 'none',
      statusCode: error.statusCode ?? 0,
      message: error.message,
      // Stack traces stay in the log and never reach a response body.
      stack: error.stack ?? '',
    };
  },
};

function stripQuery(url: string | undefined): string | undefined {
  if (url === undefined) return undefined;
  const index = url.indexOf('?');
  return index === -1 ? url : url.slice(0, index);
}

// NonNullable: under exactOptionalPropertyTypes, a return type that includes
// `undefined` cannot be assigned to Fastify's `logger` option, which silently
// pushes overload resolution onto the HTTP/2 signature and buries the real error.
export function buildLoggerOptions(
  config: Config,
): NonNullable<FastifyServerOptions['logger']> {
  return {
    level: config.logLevel,
    redact: {
      paths: [...REDACT_PATHS],
      censor: REDACTED,
      remove: false,
    },
    serializers,
    ...(config.isProduction
      ? {}
      : {
          transport: {
            target: 'pino-pretty',
            options: { translateTime: 'HH:MM:ss.l', ignore: 'pid,hostname' },
          },
        }),
  };
}

/**
 * Guard for use in tests: asserts a serialised log line carries none of the
 * strings we promise never to log. Used by the security test suite so the
 * promise in docs/security-model.md is checked, not merely stated.
 */
export function containsForbiddenValue(
  logLine: string,
  forbiddenValues: readonly string[],
): string | undefined {
  for (const value of forbiddenValues) {
    if (value.length >= 8 && logLine.includes(value)) return value;
  }
  return undefined;
}
