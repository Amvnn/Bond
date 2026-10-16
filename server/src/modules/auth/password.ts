/**
 * Password hashing.
 *
 * Argon2id with explicit parameters. Passwords are low-entropy and user-chosen,
 * which is why they get a memory-hard KDF rather than the plain SHA-256 used for
 * high-entropy random tokens (see core/tokens.ts for why those differ).
 *
 * This module never logs, returns or throws a value containing the password.
 */

import { hash, parseOptions, verify } from '@node-rs/argon2';

import { AppError } from '../../core/errors.ts';

/**
 * `Algorithm` and `Version` in @node-rs/argon2 are *ambient const enums*, which
 * cannot be referenced under `verbatimModuleSyntax`. The values below come from
 * the package's own type declarations:
 *   Algorithm.Argon2id = 2
 *   Version.V0x13      = 1   (Argon2 v19, the current version)
 * Asserted against a real hash in the test suite, so a value drifting upstream
 * fails loudly rather than silently selecting a weaker algorithm.
 */
const ALGORITHM_ARGON2ID = 2;
const VERSION_V0X13 = 1;

/**
 * Parameters exceed the OWASP Argon2id minimum (m=19456, t=2, p=1). Login
 * volume on a private, invite-only server is low, so we can afford more memory
 * per hash than a public service could.
 */
const PARAMS = {
  algorithm: ALGORITHM_ARGON2ID,
  version: VERSION_V0X13,
  memoryCost: 65_536, // 64 MiB
  timeCost: 3,
  parallelism: 1,
  outputLen: 32,
} as const;

const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 256;

/**
 * A precomputed hash of a value nobody can supply, used to spend the same work
 * on a failed lookup as on a real verification. Without this, "no such user"
 * returns measurably faster than "wrong password", which turns login into a
 * username oracle regardless of how careful the error messages are.
 */
let decoyHash: string | undefined;

export async function hashPassword(password: string): Promise<string> {
  assertAcceptablePassword(password);
  return hash(password, PARAMS);
}

/**
 * Verifies a password against a stored hash.
 *
 * Returns false rather than throwing on a malformed or unparseable stored hash:
 * a corrupt row must fail closed as a rejected login, not as a 500 that reveals
 * the row exists.
 */
export async function verifyPassword(
  storedHash: string,
  password: string,
): Promise<boolean> {
  try {
    return await verify(storedHash, password, PARAMS);
  } catch {
    return false;
  }
}

/**
 * Call on the "user does not exist" path so that branch costs the same as a
 * real verification.
 */
export async function spendVerificationTime(password: string): Promise<void> {
  decoyHash ??= await hash(
    // Never a plausible password: no account can be created with this value,
    // because registration enforces the same length limits used here.
    'decoy.'.repeat(16),
    PARAMS,
  );
  try {
    await verify(decoyHash, password, PARAMS);
  } catch {
    // Result is irrelevant; the point is the elapsed work.
  }
}

/**
 * True when a stored hash was produced with weaker parameters than current
 * policy, so it should be rehashed on the next successful login.
 */
export function needsRehash(storedHash: string): boolean {
  try {
    const actual = parseOptions(storedHash);
    return (
      // Number() because the parsed fields are typed as ambient const enums.
      Number(actual.algorithm) !== PARAMS.algorithm ||
      Number(actual.version) !== PARAMS.version ||
      actual.memoryCost < PARAMS.memoryCost ||
      actual.timeCost < PARAMS.timeCost ||
      actual.outputLen < PARAMS.outputLen
    );
  } catch {
    // Unparseable: treat as needing replacement.
    return true;
  }
}

function assertAcceptablePassword(password: string): void {
  // Length is measured in code points, not UTF-16 units, so a passphrase using
  // astral characters is not unfairly penalised.
  const length = [...password].length;
  if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new AppError('validation_failed', {
      logMessage: 'password failed length policy',
      // Length only. The password itself never enters an error or a log.
      logContext: { providedLength: length },
    });
  }
}

export { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH };
