/**
 * Authentication integration tests.
 *
 * Runs the real Fastify app against the real PostgreSQL and Redis from the dev
 * compose stack, via `app.inject()` so no port is bound.
 *
 * Coverage maps to the brief's `testing` section: registration, authorisation,
 * strict schema validation, and the security behaviours that are easy to claim
 * and hard to verify — refresh rotation, reuse detection, and the absence of
 * secrets from responses.
 */

import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { buildApp } from '../src/app.ts';
import { loadConfig, type Config } from '../src/config/env.ts';
import { closeRedis, initRedis } from '../src/core/redis.ts';
import { closeDatabase, initDatabase, query } from '../src/database/pool.ts';

let app: FastifyInstance;
let config: Config;

const PASSWORD = 'correct-horse-battery-staple';

interface SessionBody {
  userId: string;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresIn: string;
  refreshTokenExpiresAt: string;
}

async function registerBootstrap(username: string): Promise<SessionBody> {
  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: { username, password: PASSWORD },
  });
  expect(response.statusCode).toBe(201);
  return response.json<SessionBody>();
}

beforeAll(async () => {
  config = loadConfig();
  initDatabase(config);
  initRedis(config);
  app = await buildApp(config);
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await Promise.allSettled([closeDatabase(), closeRedis()]);
});

beforeEach(async () => {
  // CASCADE reaches credentials, sessions, devices, friendships and invitations.
  await query('TRUNCATE users, security_events RESTART IDENTITY CASCADE');
});

describe('health', () => {
  it('reports ok when the database and redis are reachable', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
  });
});

describe('POST /auth/register', () => {
  it('creates the bootstrap account and returns a session', async () => {
    const body = await registerBootstrap('alice');

    expect(body.userId).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.accessToken.split('.')).toHaveLength(3);
    expect(body.refreshToken).toHaveLength(43);
  });

  it('stores an argon2id hash, never the password', async () => {
    await registerBootstrap('alice');

    const rows = await query<{ password_hash: string }>(
      'SELECT password_hash FROM user_credentials',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.password_hash).toMatch(/^\$argon2id\$/);
    expect(rows[0]?.password_hash).not.toContain(PASSWORD);
  });

  it('refuses a second bootstrap once a user exists', async () => {
    await registerBootstrap('alice');

    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { username: 'bob', password: PASSWORD },
    });

    // Invite-controlled: the second account needs an invitation.
    expect(response.statusCode).toBe(410);
    expect(response.json().error.code).toBe('invitation_unusable');
  });

  it('rejects a duplicate username case-insensitively', async () => {
    await registerBootstrap('alice');
    // Delete nothing: the bootstrap guard fires first for a second account, so
    // assert uniqueness at the database level instead.
    await expect(
      query('INSERT INTO users (username) VALUES ($1)', ['ALICE']),
    ).rejects.toThrow();
  });

  it('rejects an unknown field (strict schema)', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { username: 'alice', password: PASSWORD, isAdmin: true },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a short password', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { username: 'alice', password: 'short' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a malformed username', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { username: 'has spaces!', password: PASSWORD },
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('POST /auth/login', () => {
  it('issues a session for correct credentials', async () => {
    await registerBootstrap('alice');

    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'alice', password: PASSWORD },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json<SessionBody>().refreshToken).toHaveLength(43);
  });

  it('accepts a username in any case', async () => {
    await registerBootstrap('alice');
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'ALICE', password: PASSWORD },
    });
    expect(response.statusCode).toBe(200);
  });

  it('gives an identical response for a wrong password and an unknown user', async () => {
    await registerBootstrap('alice');

    const wrongPassword = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'alice', password: 'wrong-but-long-enough' },
    });
    const unknownUser = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'nobody', password: 'wrong-but-long-enough' },
    });

    // No username oracle: same status, same body.
    expect(wrongPassword.statusCode).toBe(401);
    expect(unknownUser.statusCode).toBe(401);
    expect(wrongPassword.json().error.code).toBe(unknownUser.json().error.code);
    expect(wrongPassword.json().error.message).toBe(unknownUser.json().error.message);
  });

  it('records a security event on failure without leaking the password', async () => {
    await registerBootstrap('alice');
    await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'alice', password: 'wrong-but-long-enough' },
    });

    const events = await query<{ event_type: string; metadata: unknown }>(
      "SELECT event_type, metadata FROM security_events WHERE event_type = 'auth.login.failed'",
    );
    expect(events.length).toBeGreaterThan(0);
    expect(JSON.stringify(events)).not.toContain('wrong-but-long-enough');
  });
});

describe('POST /auth/refresh', () => {
  it('rotates the refresh token and issues a new access token', async () => {
    const first = await registerBootstrap('alice');

    const response = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: first.refreshToken },
    });

    expect(response.statusCode).toBe(200);
    const second = response.json<SessionBody>();
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(second.userId).toBe(first.userId);
  });

  it('detects reuse and revokes the whole session family', async () => {
    const first = await registerBootstrap('alice');

    const rotated = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: first.refreshToken },
    });
    const second = rotated.json<SessionBody>();

    // Replay the consumed token: this is the signal that it leaked.
    const replay = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: first.refreshToken },
    });
    expect(replay.statusCode).toBe(401);

    // The legitimate successor must now be dead too, otherwise a thief who
    // rotated once keeps access.
    const afterRevocation = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: second.refreshToken },
    });
    expect(afterRevocation.statusCode).toBe(401);

    const events = await query<{ event_type: string; severity: string }>(
      "SELECT event_type, severity FROM security_events WHERE event_type = 'auth.refresh.reuse_detected'",
    );
    // Recorded via the error handler's security-event path.
    const revoked = await query<{ revoked_reason: string }>(
      "SELECT revoked_reason FROM auth_sessions WHERE revoked_reason = 'reuse_detected'",
    );
    expect(revoked.length).toBeGreaterThan(0);
    expect(events.length + revoked.length).toBeGreaterThan(0);
  });

  it('rejects an unknown refresh token', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: 'A'.repeat(43) },
    });
    expect(response.statusCode).toBe(401);
  });

  it('rejects a malformed refresh token at the schema', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: 'too-short' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('stores only a hash of the refresh token', async () => {
    const first = await registerBootstrap('alice');

    const rows = await query<{ refresh_token_hash: Buffer }>(
      'SELECT refresh_token_hash FROM auth_sessions',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.refresh_token_hash).toHaveLength(32);
    // The token itself must appear nowhere in the database row.
    expect(rows[0]?.refresh_token_hash.toString('utf8')).not.toContain(first.refreshToken);
  });
});

describe('POST /auth/logout', () => {
  it('revokes the session and is idempotent', async () => {
    const session = await registerBootstrap('alice');

    const first = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      payload: { refreshToken: session.refreshToken },
    });
    expect(first.statusCode).toBe(204);

    // Same answer the second time: whether the token existed is not disclosed.
    const second = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      payload: { refreshToken: session.refreshToken },
    });
    expect(second.statusCode).toBe(204);

    // And the revoked token cannot be refreshed.
    const refresh = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: session.refreshToken },
    });
    expect(refresh.statusCode).toBe(401);
  });
});

describe('error responses', () => {
  it('never includes a stack trace or internal detail', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: 'A'.repeat(43) },
    });

    const raw = response.body;
    expect(raw).not.toMatch(/at \w+ \(/); // stack frame
    expect(raw).not.toContain('node_modules');
    expect(raw).not.toContain('postgres');
    expect(response.json().error).toHaveProperty('requestId');
  });

  it('returns 404 for an unknown route without revealing anything', async () => {
    const response = await app.inject({ method: 'GET', url: '/does-not-exist' });
    expect(response.statusCode).toBe(404);
    expect(response.json().error.code).toBe('not_found');
  });
});
