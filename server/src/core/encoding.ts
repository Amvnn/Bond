/**
 * Strict decoding for binary material arriving over JSON.
 *
 * Node's Buffer.from(x, 'base64') is permissive: it ignores invalid characters
 * and accepts truncated input, so two different strings can decode to the same
 * bytes. For key material that is unacceptable — it would let a caller smuggle
 * variations of the "same" key past a uniqueness check. Everything here
 * round-trips the decode and rejects anything non-canonical.
 *
 * The server treats all of this as opaque bytes. It validates sizes and
 * encoding, never meaning. See the note in decodeBase64 about what the server
 * deliberately does NOT check.
 */

import { AppError } from './errors.ts';

export interface SizeBounds {
  readonly min: number;
  readonly max: number;
}

/** libsignal serialises X25519 public keys with a leading type byte. */
export const PUBLIC_KEY_BYTES: SizeBounds = { min: 32, max: 33 };

/** XEdDSA signatures over a prekey. */
export const SIGNATURE_BYTES: SizeBounds = { min: 64, max: 64 };

/** Kyber public keys are much larger; bounded generously but not unboundedly. */
export const KYBER_PUBLIC_KEY_BYTES: SizeBounds = { min: 800, max: 2048 };

/** One text message's ciphertext. Matches the messages table constraint. */
export const CIPHERTEXT_BYTES: SizeBounds = { min: 1, max: 65_536 };

/**
 * Decodes standard base64 and rejects anything that is not canonical.
 *
 * What this does NOT do: verify that a key is a valid curve point, or that a
 * signature verifies against an identity key. Both would require the server to
 * run the cryptographic protocol, and it has no business doing that. The
 * recipient's client verifies the signed-prekey signature when it builds a
 * session — libsignal enforces it, and our validation suite proves a bundle
 * signed by the wrong identity key is rejected there. Server-side checks here
 * are about well-formedness and resource bounds only.
 */
export function decodeBase64(
  value: string,
  bounds: SizeBounds,
  fieldName: string,
): Buffer {
  const decoded = Buffer.from(value, 'base64');

  // Re-encoding must reproduce the input exactly. Catches invalid characters,
  // bad padding and truncation, all of which Buffer silently tolerates.
  if (decoded.toString('base64') !== value) {
    throw new AppError('validation_failed', {
      logMessage: `${fieldName} is not canonical base64`,
      logContext: { field: fieldName },
    });
  }

  if (decoded.length < bounds.min || decoded.length > bounds.max) {
    throw new AppError('validation_failed', {
      logMessage: `${fieldName} has an unacceptable length`,
      // Length only — never the value itself.
      logContext: { field: fieldName, bytes: decoded.length, min: bounds.min, max: bounds.max },
    });
  }

  return decoded;
}

export function encodeBase64(value: Buffer | Uint8Array): string {
  return Buffer.from(value).toString('base64');
}

/** JSON schema fragment for a base64 field, so malformed input fails at the router. */
export function base64Pattern(): string {
  return '^[A-Za-z0-9+/]+={0,2}$';
}
