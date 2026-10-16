/**
 * Error taxonomy.
 *
 * Two rules drive the design:
 *
 *   1. Security-sensitive failures fail closed. There is no "warn and continue"
 *      path for an authorisation failure or a revoked device.
 *   2. Client-facing messages are deliberately uninformative. Distinguishing
 *      "no such user" from "wrong password" turns the login endpoint into a
 *      username oracle, so both produce the same response.
 *
 * `logContext` carries detail for the server log. It must never contain a
 * token, a password, key material, ciphertext or plaintext.
 */

export type ErrorCode =
  // 400
  | 'validation_failed'
  | 'malformed_envelope'
  // 401
  | 'authentication_failed'
  | 'token_invalid'
  | 'token_expired'
  // 403
  | 'forbidden'
  | 'device_revoked'
  | 'not_contacts'
  // 404
  | 'not_found'
  // 409
  | 'already_exists'
  | 'duplicate_message'
  | 'invalid_state'
  // 410
  | 'invitation_unusable'
  // 429
  | 'rate_limited'
  // 500
  | 'internal_error'
  // 503
  | 'service_unavailable';

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  validation_failed: 400,
  malformed_envelope: 400,
  authentication_failed: 401,
  token_invalid: 401,
  token_expired: 401,
  forbidden: 403,
  device_revoked: 403,
  not_contacts: 403,
  not_found: 404,
  already_exists: 409,
  duplicate_message: 409,
  invalid_state: 409,
  invitation_unusable: 410,
  rate_limited: 429,
  internal_error: 500,
  service_unavailable: 503,
};

/**
 * Safe, generic messages. These are what the client sees. They are intentionally
 * vague where being specific would leak account existence or internal state.
 */
const PUBLIC_MESSAGE_BY_CODE: Record<ErrorCode, string> = {
  validation_failed: 'The request was not valid.',
  malformed_envelope: 'The message envelope was not valid.',
  authentication_failed: 'Authentication failed.',
  token_invalid: 'The credential presented was not valid.',
  token_expired: 'The credential presented has expired.',
  forbidden: 'This action is not permitted.',
  device_revoked: 'This device has been revoked.',
  not_contacts: 'This action is not permitted.',
  not_found: 'Not found.',
  already_exists: 'That already exists.',
  duplicate_message: 'This message has already been accepted.',
  invalid_state: 'The requested state change is not allowed.',
  invitation_unusable: 'This invitation cannot be used.',
  rate_limited: 'Too many requests. Try again later.',
  internal_error: 'An internal error occurred.',
  service_unavailable: 'The service is temporarily unavailable.',
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly publicMessage: string;
  readonly logContext: Readonly<Record<string, unknown>>;
  readonly securityEvent: boolean;

  constructor(
    code: ErrorCode,
    options: {
      /** Detail for the server log only. Never returned to the client. */
      logMessage?: string;
      logContext?: Readonly<Record<string, unknown>>;
      /** Record this as a security event in the audit log. */
      securityEvent?: boolean;
      cause?: unknown;
    } = {},
  ) {
    super(options.logMessage ?? PUBLIC_MESSAGE_BY_CODE[code]);
    this.name = 'AppError';
    this.code = code;
    this.statusCode = STATUS_BY_CODE[code];
    this.publicMessage = PUBLIC_MESSAGE_BY_CODE[code];
    this.logContext = options.logContext ?? {};
    this.securityEvent = options.securityEvent ?? false;
    if (options.cause !== undefined) this.cause = options.cause;
  }
}

export function isAppError(value: unknown): value is AppError {
  return value instanceof AppError;
}

/**
 * Login and registration failures deliberately collapse to one error, so the
 * response cannot be used to enumerate usernames.
 */
export function authenticationFailed(
  logMessage: string,
  logContext: Readonly<Record<string, unknown>> = {},
): AppError {
  return new AppError('authentication_failed', {
    logMessage,
    logContext,
    securityEvent: true,
  });
}
