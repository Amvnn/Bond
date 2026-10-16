/**
 * Opaque token generation and hashing.
 *
 * Used for invitation tokens and refresh tokens. Both are high-entropy random
 * strings: never structured, never guessable, never derived from anything about
 * the user.
 *
 * One rule for all opaque tokens: the database stores
 * HMAC-SHA256(pepper, token) and never the token. This means
 *   - a stolen database yields no usable tokens, and cannot be used to mint or
 *     verify one either, because the pepper lives in the environment rather than
 *     in the database;
 *   - lookup is by hash, so application code never compares two secrets and
 *     there is no timing-comparison surface to get wrong.
 *
 * A fast keyed hash is correct here and deliberately different from password
 * handling. These tokens carry 256 bits of CSPRNG entropy, so there is nothing
 * to brute-force or dictionary-attack and a slow KDF would add only latency.
 * Passwords are low-entropy and user-chosen, which is why they use Argon2id
 * instead (see modules/auth/password.ts).
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** 32 bytes = 256 bits of entropy. */
const TOKEN_BYTES = 32;

/** base64url of 32 bytes, unpadded. */
const TOKEN_LENGTH = 43;

export interface GeneratedToken {
  /** Returned to the client exactly once. Never persisted, never logged. */
  readonly token: string;
  /** Persisted in place of the token. */
  readonly hash: Buffer;
}

/**
 * Generates a token and its stored hash.
 *
 * @param pepper Server-side key. Distinct peppers keep invitation tokens and
 *   refresh tokens in separate keyspaces, so a hash from one table can never
 *   match a row in the other.
 */
export function generateToken(pepper: string): GeneratedToken {
  const token = randomBytes(TOKEN_BYTES).toString('base64url');
  return { token, hash: hashToken(token, pepper) };
}

export function hashToken(token: string, pepper: string): Buffer {
  return createHmac('sha256', pepper).update(token, 'utf8').digest();
}

/**
 * Shape check to run before a database lookup, so a malformed token never
 * becomes a query.
 */
export function isWellFormedToken(value: string): boolean {
  return value.length === TOKEN_LENGTH && /^[A-Za-z0-9_-]+$/.test(value);
}

/**
 * Constant-time buffer comparison. Not needed for hash-keyed lookups, but
 * required anywhere two secrets are compared directly.
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export { TOKEN_LENGTH };
