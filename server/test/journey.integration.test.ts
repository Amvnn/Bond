/**
 * End-to-end user journey, and the authorisation boundaries around it.
 *
 * Read test/helpers.ts first: key material and "ciphertext" here are random
 * bytes of the right shape. These tests prove the SERVER works — and that it
 * works without understanding any of the cryptography. Real encryption is
 * proven against the real library in client/test/libsignal_validation_test.dart.
 */

import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { buildApp } from '../src/app.ts';
import { loadConfig, type Config } from '../src/config/env.ts';
import { closeRedis, initRedis } from '../src/core/redis.ts';
import { closeDatabase, initDatabase, query } from '../src/database/pool.ts';
import {
  authHeader,
  ciphertextB64,
  createInvitation,
  deviceId,
  deviceToken,
  publicKeyB64,
  registerActor,
  registerDeviceFor,
  signatureB64,
  type Actor,
} from './helpers.ts';

let app: FastifyInstance;
let config: Config;

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
  await query('TRUNCATE users, security_events RESTART IDENTITY CASCADE');
});

/** Alice (bootstrap) invites Bob; both end up with a device and an active friendship. */
async function pairAliceAndBob(): Promise<{ alice: Actor; bob: Actor }> {
  const alice = await registerActor(app, 'alice');
  await registerDeviceFor(app, alice);

  const invitation = await createInvitation(app, alice);
  const bob = await registerActor(app, 'bob', invitation.token);
  await registerDeviceFor(app, bob);

  return { alice, bob };
}

describe('the whole journey', () => {
  it('runs register -> invite -> accept -> devices -> prekeys -> verify -> send -> receive -> receipts', async () => {
    // 1. Alice creates the first account. Nobody can invite user #1, so this is
    //    the env-gated bootstrap path.
    const alice = await registerActor(app, 'alice');
    expect(alice.userId).toMatch(/^[0-9a-f-]{36}$/);

    // 2. Alice's installation becomes a cryptographic device.
    const aliceDevice = await registerDeviceFor(app, alice);
    expect(aliceDevice.deviceIndex).toBe(1);
    // The device-scoped token is distinct from the account token it replaced.
    expect(aliceDevice.accessToken).not.toBe(alice.accessToken);

    // 3. Alice invites Bob. The token is shown exactly once.
    const invitation = await createInvitation(app, alice);
    expect(invitation.token).toHaveLength(43);

    // 4. Bob registers with it. One invite both authorises the account and
    //    creates the friendship (D3), active immediately (D7).
    const bob = await registerActor(app, 'bob', invitation.token);
    const bobDevice = await registerDeviceFor(app, bob);

    // 5. The invitation is now spent and cannot be reused.
    const replayInvite = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { username: 'mallory', password: 'correct-horse-battery-staple', invitationToken: invitation.token },
    });
    expect(replayInvite.statusCode).toBe(410);

    // 6. Each sees the other as a contact, with the other's device identity key.
    const contacts = await app.inject({
      method: 'GET',
      url: '/contacts',
      headers: authHeader(alice.accessToken),
    });
    expect(contacts.statusCode).toBe(200);
    const list = contacts.json<Array<{ contactUserId: string; status: string; verifiedAt: string | null; devices: Array<{ deviceId: string; publicIdentityKey: string }> }>>();
    expect(list).toHaveLength(1);
    expect(list[0]?.contactUserId).toBe(bob.userId);
    expect(list[0]?.status).toBe('active');
    // Unverified until a human compares digits out of band.
    expect(list[0]?.verifiedAt).toBeNull();
    expect(list[0]?.devices[0]?.deviceId).toBe(bobDevice.deviceId);

    // 7. Alice fetches Bob's prekey bundle to establish a session.
    const bundleResponse = await app.inject({
      method: 'GET',
      url: `/devices/${bobDevice.deviceId}/public-keys`,
      headers: authHeader(deviceToken(alice)),
    });
    expect(bundleResponse.statusCode, bundleResponse.body).toBe(200);
    const bundle = bundleResponse.json<{
      publicIdentityKey: string;
      signedPreKey: { signature: string };
      kyberPreKey: { publicKey: string };
      oneTimePreKey: { id: number } | null;
    }>();
    // PQXDH is mandatory, so a bundle always carries a Kyber prekey.
    expect(bundle.kyberPreKey.publicKey.length).toBeGreaterThan(100);
    expect(bundle.signedPreKey.signature).toBeTruthy();
    // A one-time prekey was consumed by this fetch.
    expect(bundle.oneTimePreKey).not.toBeNull();

    // 8. Out-of-band verification happened; Alice records it. Advisory only.
    const verify = await app.inject({
      method: 'POST',
      url: `/contacts/${bob.userId}/verify`,
      headers: authHeader(alice.accessToken),
      payload: { verified: true },
    });
    expect(verify.statusCode).toBe(200);
    expect(verify.json<{ verifiedAt: string | null }>().verifiedAt).not.toBeNull();

    // 9. Alice sends an encrypted envelope. Deliberately random bytes: if the
    //    server tried to parse the envelope, this would fail.
    const ciphertext = ciphertextB64(256);
    const send = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: {
        envelopes: [
          {
            recipientDeviceId: bobDevice.deviceId,
            envelopeVersion: 1,
            messageType: 'prekey',
            ciphertext,
            senderSequence: 0,
          },
        ],
      },
    });
    expect(send.statusCode, send.body).toBe(201);
    const results = send.json<{ results: Array<{ status: string; messageId: string }> }>().results;
    expect(results[0]?.status).toBe('accepted');
    const messageId = results[0]?.messageId;

    // 10. What the server actually stored: ciphertext, byte-for-byte, and no
    //     plaintext anywhere.
    const stored = await query<{ ciphertext: Buffer; delivery_state: string; message_type: string }>(
      'SELECT ciphertext, delivery_state, message_type FROM messages WHERE id = $1',
      [messageId],
    );
    expect(stored[0]?.delivery_state).toBe('queued');
    expect(stored[0]?.message_type).toBe('prekey');
    expect(stored[0]?.ciphertext.toString('base64')).toBe(ciphertext);

    // 11. Bob drains his queue and gets the identical bytes back.
    const inbox = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(deviceToken(bob)),
    });
    expect(inbox.statusCode).toBe(200);
    const queued = inbox.json<Array<{ messageId: string; ciphertext: string; senderDeviceId: string; senderDeviceIndex: number; messageType: string }>>();
    expect(queued).toHaveLength(1);
    expect(queued[0]?.ciphertext).toBe(ciphertext);
    expect(queued[0]?.senderDeviceId).toBe(aliceDevice.deviceId);
    expect(queued[0]?.senderDeviceIndex).toBe(1);

    // 12. Bob acknowledges delivery, then read. No plaintext in either.
    const delivered = await app.inject({
      method: 'POST',
      url: `/messages/${messageId}/delivered`,
      headers: authHeader(deviceToken(bob)),
    });
    expect(delivered.statusCode).toBe(200);
    expect(delivered.json<{ deliveryState: string }>().deliveryState).toBe('delivered');

    const read = await app.inject({
      method: 'POST',
      url: `/messages/${messageId}/read`,
      headers: authHeader(deviceToken(bob)),
    });
    expect(read.statusCode).toBe(200);
    expect(read.json<{ deliveryState: string }>().deliveryState).toBe('read');

    // 13. A delivered message leaves Bob's queue.
    const emptied = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(deviceToken(bob)),
    });
    expect(emptied.json<unknown[]>()).toHaveLength(0);
  });
});

describe('offline delivery', () => {
  it('queues while the recipient is absent and delivers on return', async () => {
    const { alice, bob } = await pairAliceAndBob();

    // Bob is simply not connected. Nothing special is required of the sender.
    const ciphertext = ciphertextB64();
    const send = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: {
        envelopes: [
          {
            recipientDeviceId: deviceId(bob),
            envelopeVersion: 1,
            messageType: 'prekey',
            ciphertext,
            senderSequence: 0,
          },
        ],
      },
    });
    expect(send.statusCode).toBe(201);

    // The server held ciphertext and never needed to decrypt it.
    const row = await query<{ delivery_state: string }>(
      'SELECT delivery_state FROM messages',
    );
    expect(row[0]?.delivery_state).toBe('queued');

    // Bob comes back and finds it waiting.
    const inbox = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(deviceToken(bob)),
    });
    expect(inbox.json<Array<{ ciphertext: string }>>()[0]?.ciphertext).toBe(ciphertext);
  });

  it('preserves per-sender order on drain', async () => {
    const { alice, bob } = await pairAliceAndBob();

    for (let sequence = 0; sequence < 5; sequence += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/messages',
        headers: authHeader(deviceToken(alice)),
        payload: {
          envelopes: [
            {
              recipientDeviceId: deviceId(bob),
              envelopeVersion: 1,
              messageType: sequence === 0 ? 'prekey' : 'signal',
              ciphertext: ciphertextB64(),
              senderSequence: sequence,
            },
          ],
        },
      });
      expect(response.statusCode).toBe(201);
    }

    const inbox = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(deviceToken(bob)),
    });
    const sequences = inbox
      .json<Array<{ senderSequence: number }>>()
      .map((envelope) => envelope.senderSequence);
    expect(sequences).toEqual([0, 1, 2, 3, 4]);
  });
});

describe('duplicates and replay', () => {
  it('reports a resent sequence as duplicate instead of storing it twice', async () => {
    const { alice, bob } = await pairAliceAndBob();

    const envelope = {
      recipientDeviceId: deviceId(bob),
      envelopeVersion: 1,
      messageType: 'prekey' as const,
      ciphertext: ciphertextB64(),
      senderSequence: 7,
    };

    const first = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: { envelopes: [envelope] },
    });
    expect(first.json<{ results: Array<{ status: string }> }>().results[0]?.status).toBe('accepted');

    // Same sender, same recipient, same sequence: a replay or a retry.
    const second = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: { envelopes: [envelope] },
    });
    expect(second.statusCode).toBe(201);
    expect(second.json<{ results: Array<{ status: string }> }>().results[0]?.status).toBe('duplicate');

    const rows = await query<{ count: string }>('SELECT count(*) FROM messages');
    expect(rows[0]?.count).toBe('1');
  });

  // The `limit` query parameter had never been exercised by a test, and was
  // broken for every value: query parameters arrive as strings and Ajv runs
  // with coerceTypes: false, so the Integer schema it used could not match.
  // The client's vertical-slice test was the first caller to pass it, and got
  // validation_failed. These cover both directions of the fix.
  it('honours the limit query parameter', async () => {
    const { alice, bob } = await pairAliceAndBob();

    for (const senderSequence of [1, 2, 3]) {
      await app.inject({
        method: 'POST',
        url: '/messages',
        headers: authHeader(deviceToken(alice)),
        payload: {
          envelopes: [
            {
              recipientDeviceId: deviceId(bob),
              envelopeVersion: 1,
              messageType: 'signal' as const,
              ciphertext: ciphertextB64(),
              senderSequence,
            },
          ],
        },
      });
    }

    const limited = await app.inject({
      method: 'GET',
      url: '/messages?limit=2',
      headers: authHeader(deviceToken(bob)),
    });
    expect(limited.statusCode).toBe(200);
    expect(limited.json<unknown[]>()).toHaveLength(2);

    // Omitting it still works, and returns the rest.
    const all = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(deviceToken(bob)),
    });
    expect(all.statusCode).toBe(200);
    expect(all.json<unknown[]>()).toHaveLength(3);
  });

  it('rejects a limit that is not a plain positive number', async () => {
    const { bob } = await pairAliceAndBob();

    // Strict validation is retained: the fix widened the type to a bounded
    // numeric string, it did not enable type coercion.
    for (const bad of ['abc', '0', '-1', '1.5', '1000', '', ' 1', '0x10']) {
      const response = await app.inject({
        method: 'GET',
        url: `/messages?limit=${encodeURIComponent(bad)}`,
        headers: authHeader(deviceToken(bob)),
      });
      expect(response.statusCode, `limit=${JSON.stringify(bad)}`).toBe(400);
      expect(response.json<{ error: { code: string } }>().error.code).toBe(
        'validation_failed',
      );
    }
  });

  it('rejects two envelopes for the same recipient in one batch', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const envelope = {
      recipientDeviceId: deviceId(bob),
      envelopeVersion: 1,
      messageType: 'signal' as const,
      ciphertext: ciphertextB64(),
      senderSequence: 1,
    };
    const response = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: { envelopes: [envelope, { ...envelope, senderSequence: 2 }] },
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('authorisation boundaries', () => {
  it('refuses a prekey bundle to a non-contact, indistinguishably from not found', async () => {
    const { alice, bob } = await pairAliceAndBob();

    // Carol is a legitimate user, invited by Alice, but is not Bob's contact.
    const carolInvite = await createInvitation(app, alice);
    const carol = await registerActor(app, 'carol', carolInvite.token);
    await registerDeviceFor(app, carol);

    const response = await app.inject({
      method: 'GET',
      url: `/devices/${deviceId(bob)}/public-keys`,
      headers: authHeader(deviceToken(carol)),
    });
    // 404, not 403: this must not confirm that the device id exists.
    expect(response.statusCode).toBe(404);
  });

  it('refuses a message to a non-contact', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const carolInvite = await createInvitation(app, alice);
    const carol = await registerActor(app, 'carol', carolInvite.token);
    await registerDeviceFor(app, carol);

    const response = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(carol)),
      payload: {
        envelopes: [
          {
            recipientDeviceId: deviceId(bob),
            envelopeVersion: 1,
            messageType: 'prekey',
            ciphertext: ciphertextB64(),
            senderSequence: 0,
          },
        ],
      },
    });
    expect(response.statusCode).toBe(403);
    const rows = await query<{ count: string }>('SELECT count(*) FROM messages');
    expect(rows[0]?.count).toBe('0');
  });

  it('refuses to acknowledge a message addressed to another device', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const carolInvite = await createInvitation(app, alice);
    const carol = await registerActor(app, 'carol', carolInvite.token);
    await registerDeviceFor(app, carol);

    const send = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: {
        envelopes: [
          {
            recipientDeviceId: deviceId(bob),
            envelopeVersion: 1,
            messageType: 'prekey',
            ciphertext: ciphertextB64(),
            senderSequence: 0,
          },
        ],
      },
    });
    const messageId = send.json<{ results: Array<{ messageId: string }> }>().results[0]?.messageId;

    // Carol holds a valid device session, but not the recipient one.
    const response = await app.inject({
      method: 'POST',
      url: `/messages/${messageId}/delivered`,
      headers: authHeader(deviceToken(carol)),
    });
    expect(response.statusCode).toBe(404);
  });

  it('refuses an account-scoped token on a device-scoped endpoint', async () => {
    const { alice, bob } = await pairAliceAndBob();

    // alice.accessToken predates device registration, so it carries no device.
    const response = await app.inject({
      method: 'GET',
      url: `/devices/${deviceId(bob)}/public-keys`,
      headers: authHeader(alice.accessToken),
    });
    expect(response.statusCode).toBe(403);
  });

  it('never lists another user as a contact without an invitation', async () => {
    const alice = await registerActor(app, 'alice');
    await registerDeviceFor(app, alice);
    const invite = await createInvitation(app, alice);
    const bob = await registerActor(app, 'bob', invite.token);
    await registerDeviceFor(app, bob);

    // Alice invites Carol too; Bob and Carol never meet.
    const carolInvite = await createInvitation(app, alice);
    const carol = await registerActor(app, 'carol', carolInvite.token);

    const bobContacts = await app.inject({
      method: 'GET',
      url: '/contacts',
      headers: authHeader(bob.accessToken),
    });
    const ids = bobContacts.json<Array<{ contactUserId: string }>>().map((c) => c.contactUserId);
    expect(ids).toContain(alice.userId);
    expect(ids).not.toContain(carol.userId);
  });

  it('refuses to revoke or replenish another user\'s device', async () => {
    const { alice, bob } = await pairAliceAndBob();

    const revoke = await app.inject({
      method: 'POST',
      url: `/devices/${deviceId(bob)}/revoke`,
      headers: authHeader(alice.accessToken),
    });
    expect(revoke.statusCode).toBe(404);

    const replenish = await app.inject({
      method: 'POST',
      url: `/devices/${deviceId(bob)}/key-material`,
      headers: authHeader(alice.accessToken),
      payload: { oneTimePreKeys: [{ id: 99, publicKey: publicKeyB64() }] },
    });
    expect(replenish.statusCode).toBe(404);
  });
});

describe('prekeys', () => {
  it('consumes a one-time prekey per fetch and never reuses one', async () => {
    const { alice, bob } = await pairAliceAndBob();

    const seen = new Set<number>();
    for (let i = 0; i < 5; i += 1) {
      const response = await app.inject({
        method: 'GET',
        url: `/devices/${deviceId(bob)}/public-keys`,
        headers: authHeader(deviceToken(alice)),
      });
      const bundle = response.json<{ oneTimePreKey: { id: number } | null }>();
      expect(bundle.oneTimePreKey).not.toBeNull();
      const id = bundle.oneTimePreKey?.id;
      expect(seen.has(id as number), `prekey ${id} handed out twice`).toBe(false);
      seen.add(id as number);
    }

    const consumed = await query<{ count: string }>(
      'SELECT count(*) FROM device_one_time_prekeys WHERE consumed_at IS NOT NULL',
    );
    expect(consumed[0]?.count).toBe('5');
  });

  it('degrades to a bundle without a one-time prekey when the supply runs out', async () => {
    const alice = await registerActor(app, 'alice');
    await registerDeviceFor(app, alice);
    const invite = await createInvitation(app, alice);
    const bob = await registerActor(app, 'bob', invite.token);
    // Minimum allowed supply, so it can be drained within the test.
    await registerDeviceFor(app, bob, { oneTimePreKeyCount: 10 });

    for (let i = 0; i < 10; i += 1) {
      const drained = await app.inject({
        method: 'GET',
        url: `/devices/${deviceId(bob)}/public-keys`,
        headers: authHeader(deviceToken(alice)),
      });
      expect(drained.json<{ oneTimePreKey: unknown }>().oneTimePreKey).not.toBeNull();
    }

    // Exhausted: the bundle must still be usable, not an error, and must not
    // recycle a spent key.
    const exhausted = await app.inject({
      method: 'GET',
      url: `/devices/${deviceId(bob)}/public-keys`,
      headers: authHeader(deviceToken(alice)),
    });
    expect(exhausted.statusCode).toBe(200);
    expect(exhausted.json<{ oneTimePreKey: unknown }>().oneTimePreKey).toBeNull();

    const events = await query<{ event_type: string }>(
      "SELECT event_type FROM security_events WHERE event_type = 'device.prekeys_exhausted'",
    );
    expect(events.length).toBeGreaterThan(0);
  });

  it('accepts replenishment and never overwrites an existing prekey', async () => {
    const { bob } = await pairAliceAndBob();

    const before = await query<{ public_key: Buffer }>(
      'SELECT public_key FROM device_one_time_prekeys WHERE device_id = $1 AND prekey_id = 1',
      [deviceId(bob)],
    );

    // Resend id 1 with DIFFERENT bytes, as a buggy or malicious client might.
    const response = await app.inject({
      method: 'POST',
      url: `/devices/${deviceId(bob)}/key-material`,
      headers: authHeader(deviceToken(bob)),
      payload: { oneTimePreKeys: [{ id: 1, publicKey: publicKeyB64() }] },
    });
    expect(response.statusCode).toBe(200);

    const after = await query<{ public_key: Buffer }>(
      'SELECT public_key FROM device_one_time_prekeys WHERE device_id = $1 AND prekey_id = 1',
      [deviceId(bob)],
    );
    // Unchanged: substituting a key already published would be a downgrade path.
    expect(after[0]?.public_key.toString('base64')).toBe(before[0]?.public_key.toString('base64'));
  });

  it('rejects malformed key material', async () => {
    const alice = await registerActor(app, 'alice');

    const response = await app.inject({
      method: 'POST',
      url: '/devices/register',
      headers: authHeader(alice.accessToken),
      payload: {
        deviceName: 'bad',
        platform: 'windows',
        registrationId: 5,
        publicIdentityKey: publicKeyB64(),
        // A 10-byte "signature" is not a signature.
        signedPreKey: { id: 1, publicKey: publicKeyB64(), signature: 'AAAAAAAAAAAAAA==' },
        kyberPreKey: { id: 1, publicKey: publicKeyB64(), signature: signatureB64() },
        oneTimePreKeys: Array.from({ length: 10 }, (_, i) => ({ id: i + 1, publicKey: publicKeyB64() })),
      },
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('device revocation', () => {
  it('stops the revoked device sending, receiving and authenticating', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const bobDeviceId = deviceId(bob);
    const bobToken = deviceToken(bob);

    const revoke = await app.inject({
      method: 'POST',
      url: `/devices/${bobDeviceId}/revoke`,
      headers: authHeader(bob.accessToken),
    });
    expect(revoke.statusCode).toBe(204);

    // The revoked device's own token no longer works.
    const afterRevoke = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(bobToken),
    });
    expect(afterRevoke.statusCode).toBe(403);

    // Alice can no longer address it.
    const send = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: {
        envelopes: [
          {
            recipientDeviceId: bobDeviceId,
            envelopeVersion: 1,
            messageType: 'prekey',
            ciphertext: ciphertextB64(),
            senderSequence: 0,
          },
        ],
      },
    });
    expect(send.statusCode).toBe(403);

    // And no new session can be established with it: prekeys are withdrawn.
    const bundle = await app.inject({
      method: 'GET',
      url: `/devices/${bobDeviceId}/public-keys`,
      headers: authHeader(deviceToken(alice)),
    });
    expect(bundle.statusCode).toBe(403);

    const remaining = await query<{ count: string }>(
      'SELECT count(*) FROM device_one_time_prekeys WHERE device_id = $1 AND consumed_at IS NULL',
      [bobDeviceId],
    );
    expect(remaining[0]?.count).toBe('0');
  });

  it('drops the revoked device from the contact listing', async () => {
    const { alice, bob } = await pairAliceAndBob();
    await app.inject({
      method: 'POST',
      url: `/devices/${deviceId(bob)}/revoke`,
      headers: authHeader(bob.accessToken),
    });

    const contacts = await app.inject({
      method: 'GET',
      url: '/contacts',
      headers: authHeader(alice.accessToken),
    });
    expect(contacts.json<Array<{ devices: unknown[] }>>()[0]?.devices).toHaveLength(0);
  });

  it('does not reuse the device index of a revoked device', async () => {
    const alice = await registerActor(app, 'alice');
    const first = await registerDeviceFor(app, alice, { deviceName: 'first' });
    expect(first.deviceIndex).toBe(1);

    await app.inject({
      method: 'POST',
      url: `/devices/${first.deviceId}/revoke`,
      headers: authHeader(alice.accessToken),
    });

    // A fresh login is needed: revoking the device killed its session family.
    const relogin = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'alice', password: 'correct-horse-battery-staple' },
    });
    expect(relogin.statusCode).toBe(200);
    const reauthed: Actor = { ...relogin.json(), username: 'alice' };

    const second = await registerDeviceFor(app, reauthed, { deviceName: 'second' });
    // Index 2, not 1: a peer caching sessions by (user, index) must never find
    // a different identity key behind an index it already knows.
    expect(second.deviceIndex).toBe(2);
  });
});

describe('multi-device fan-out', () => {
  it('delivers one envelope per recipient device, independently acknowledged', async () => {
    const alice = await registerActor(app, 'alice');
    await registerDeviceFor(app, alice);
    const invite = await createInvitation(app, alice);
    const bob = await registerActor(app, 'bob', invite.token);

    const bobLaptop = await registerDeviceFor(app, bob, { deviceName: 'bob-laptop' });
    // Registering a second device rebinds the session, so log in again to get a
    // token for the first one.
    const bobDesktopLogin = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { username: 'bob', password: 'correct-horse-battery-staple' },
    });
    const bobAgain: Actor = { ...bobDesktopLogin.json(), username: 'bob' };
    const bobDesktop = await registerDeviceFor(app, bobAgain, { deviceName: 'bob-desktop' });
    expect(bobDesktop.deviceIndex).toBe(2);

    // Alice sees both devices and encrypts separately for each.
    const contacts = await app.inject({
      method: 'GET',
      url: '/contacts',
      headers: authHeader(alice.accessToken),
    });
    const devices = contacts.json<Array<{ devices: Array<{ deviceId: string }> }>>()[0]?.devices ?? [];
    expect(devices).toHaveLength(2);

    const send = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: {
        envelopes: devices.map((device, index) => ({
          recipientDeviceId: device.deviceId,
          envelopeVersion: 1,
          messageType: 'prekey' as const,
          // Distinct ciphertext per device: each has its own session.
          ciphertext: ciphertextB64(64 + index),
          senderSequence: 0,
        })),
      },
    });
    expect(send.statusCode, send.body).toBe(201);
    const results = send.json<{ results: Array<{ status: string }> }>().results;
    expect(results.every((result) => result.status === 'accepted')).toBe(true);

    // Each device has exactly its own copy.
    const laptopInbox = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(bobLaptop.accessToken),
    });
    const desktopInbox = await app.inject({
      method: 'GET',
      url: '/messages',
      headers: authHeader(bobDesktop.accessToken),
    });
    expect(laptopInbox.json<unknown[]>()).toHaveLength(1);
    expect(desktopInbox.json<unknown[]>()).toHaveLength(1);
    expect(laptopInbox.json<Array<{ ciphertext: string }>>()[0]?.ciphertext).not.toBe(
      desktopInbox.json<Array<{ ciphertext: string }>>()[0]?.ciphertext,
    );
  });
});

describe('what the server stores', () => {
  it('accepts ciphertext that is not valid UTF-8 or JSON, proving it never parses it', async () => {
    const { alice, bob } = await pairAliceAndBob();

    // Bytes chosen to be invalid UTF-8. If any layer tried to decode the
    // envelope body as text, this would corrupt or fail.
    const raw = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0xc0, 0xaf, 0xed, 0xa0, 0x80]);
    const ciphertext = raw.toString('base64');

    const send = await app.inject({
      method: 'POST',
      url: '/messages',
      headers: authHeader(deviceToken(alice)),
      payload: {
        envelopes: [
          {
            recipientDeviceId: deviceId(bob),
            envelopeVersion: 1,
            messageType: 'signal',
            ciphertext,
            senderSequence: 0,
          },
        ],
      },
    });
    expect(send.statusCode).toBe(201);

    const stored = await query<{ ciphertext: Buffer }>('SELECT ciphertext FROM messages');
    expect(stored[0]?.ciphertext.equals(raw)).toBe(true);
  });

  it('keeps no plaintext-bearing column and no token in the clear', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const invitation = await createInvitation(app, alice);

    // The invitation token is never recoverable from the database.
    const invitations = await query<{ token_hash: Buffer }>('SELECT token_hash FROM invitations');
    expect(invitations.length).toBeGreaterThan(0);
    for (const row of invitations) {
      expect(row.token_hash).toHaveLength(32);
      expect(row.token_hash.toString('utf8')).not.toContain(invitation.token);
    }

    // And no column exists that could hold message content.
    const columns = await query<{ table_name: string; column_name: string }>(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = 'public'
          AND (column_name ILIKE '%plaintext%' OR column_name ILIKE '%search%'
               OR column_name ILIKE '%preview%' OR column_name ILIKE '%private_key%')`,
    );
    expect(columns).toEqual([]);
    expect(bob.userId).toBeTruthy();
  });

  it('records security events for the journey without leaking secrets', async () => {
    const { alice } = await pairAliceAndBob();
    const invitation = await createInvitation(app, alice);

    const events = await query<{ event_type: string; metadata: unknown }>(
      'SELECT event_type, metadata FROM security_events',
    );
    const types = events.map((event) => event.event_type);
    expect(types).toContain('auth.register.success');
    expect(types).toContain('device.registered');
    expect(types).toContain('invitation.created');

    // No audit row may contain the invitation token.
    expect(JSON.stringify(events)).not.toContain(invitation.token);
  });
});
