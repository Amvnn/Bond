/**
 * Test environment setup.
 *
 * Loads server/.env so tests run against the local development stack, then
 * overrides the few values that must differ under test.
 *
 * Note it does NOT weaken any security behaviour: rate limits are raised so a
 * test suite is not throttled, but authentication, authorisation and constraint
 * enforcement are exercised exactly as they run in production.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const envPath = join(dirname(fileURLToPath(import.meta.url)), '..', '.env');

for (const line of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
  const trimmed = line.trim();
  if (trimmed === '' || trimmed.startsWith('#')) continue;
  const separator = trimmed.indexOf('=');
  if (separator === -1) continue;
  const key = trimmed.slice(0, separator).trim();
  const value = trimmed.slice(separator + 1).trim();
  // Real environment wins, so CI can override without editing files.
  process.env[key] ??= value;
}

process.env['NODE_ENV'] = 'test';
process.env['LOG_LEVEL'] = 'silent';

// User #1 cannot be invited by anyone, so the bootstrap path is needed to
// create the first account in a fresh database.
process.env['ALLOW_BOOTSTRAP_ACCOUNT'] = 'true';

// Raised so the suite is not rate-limited. Rate limiting itself is covered by
// its own test, which sets a low limit explicitly.
process.env['RATE_LIMIT_AUTH_PER_15M'] = '1000';
process.env['RATE_LIMIT_REGISTER_PER_HOUR'] = '1000';
process.env['RATE_LIMIT_INVITE_CREATE_PER_DAY'] = '1000';
process.env['RATE_LIMIT_INVITE_ACCEPT_PER_HOUR'] = '1000';

// WebSocket connect limit is raised too: the realtime suite opens many sockets
// in quick succession. The limit itself is exercised by its own test.
process.env['RATE_LIMIT_WS_CONNECT_PER_MINUTE'] = '1000';
process.env['RATE_LIMIT_PREKEY_FETCH_PER_HOUR'] = '1000';
process.env['RATE_LIMIT_MESSAGE_SEND_PER_MINUTE'] = '1000';
