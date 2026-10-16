/**
 * Runnable walkthrough of the Phase 1 user journey.
 *
 * Run it with the dev stack up:
 *   cd server && ./node_modules/.bin/tsx --env-file=.env scripts/demo-journey.ts
 *
 * It starts the real server on an ephemeral port, drives it over real HTTP and
 * a real WebSocket, and prints what the server database actually holds at the
 * point where a message is in flight.
 *
 * ---------------------------------------------------------------------------
 * READ THIS ABOUT THE ENCRYPTION IN THIS SCRIPT
 *
 * The product's cryptography is the Signal Protocol (X3DH/PQXDH + Double
 * Ratchet) via libsignal, and it runs on the FLUTTER CLIENT. That is proven by
 * client/test/libsignal_validation_test.dart, not here.
 *
 * This script is Node, so it cannot call the Dart client. To show a real
 * plaintext -> opaque bytes -> plaintext round trip, it uses AES-256-GCM from
 * Node's standard library as a STAND-IN for a Signal session, with a key
 * generated in-process that is never sent to the server. That is a
 * demonstration device only. It is NOT the product's protocol, it has none of
 * the ratchet's forward secrecy, and no product code does this.
 *
 * What the demo genuinely proves: the server stores and routes bytes it cannot
 * read, and every authorisation rule holds. What it does not prove: anything
 * about the real protocol.
 * ---------------------------------------------------------------------------
 *
 * It TRUNCATES the database it points at. Development only.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomInt,
} from 'node:crypto';
import type { AddressInfo } from 'node:net';
import WebSocket from 'ws';

import { buildApp } from '../src/app.ts';
import { loadConfig } from '../src/config/env.ts';
import { closeRedis, initRedis, waitForRedis } from '../src/core/redis.ts';
import { closeDatabase, initDatabase, query } from '../src/database/pool.ts';

const PASSWORD = 'correct-horse-battery-staple';

let step = 0;
function heading(text: string): void {
  step += 1;
  process.stdout.write(`\n${String(step).padStart(2, ' ')}. ${text}\n`);
}
function detail(text: string): void {
  process.stdout.write(`    ${text}\n`);
}
function ok(text: string): void {
  process.stdout.write(`    [ok] ${text}\n`);
}
function warn(text: string): void {
  process.stdout.write(`    [!!] ${text}\n`);
}
function rule(text = ''): void {
  process.stdout.write(`\n${'-'.repeat(74)}\n${text ? `${text}\n` : ''}`);
}

// --------------------------------------------------------------------------
// Key material. Random bytes of the right SHAPE; the server validates sizes
// and encoding and treats the contents as opaque.
// --------------------------------------------------------------------------
const publicKey = (): string => randomBytes(33).toString('base64');
const signature = (): string => randomBytes(64).toString('base64');
const kyberKey = (): string => randomBytes(1568).toString('base64');

// Stand-in session key. See the header. Never leaves this process.
const demoSessionKey = randomBytes(32);

function demoEncrypt(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', demoSessionKey, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64');
}

function demoDecrypt(envelopeB64: string): string {
  const raw = Buffer.from(envelopeB64, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', demoSessionKey, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

interface Actor {
  username: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  deviceId?: string;
  deviceIndex?: number;
  deviceToken?: string;
}

let origin = '';

/**
 * Builds request headers.
 *
 * content-type is set ONLY when there is a body. Declaring application/json
 * with no body makes Fastify reject the request with 400 "body cannot be
 * empty", which is correct of Fastify and was a bug in this script: the
 * body-less acknowledge endpoints were failing for that reason alone.
 */
function headersFor(token: string | undefined, hasBody: boolean): Record<string, string> {
  return {
    ...(hasBody ? { 'content-type': 'application/json' } : {}),
    ...(token !== undefined ? { authorization: `Bearer ${token}` } : {}),
  };
}

async function call<T>(
  method: string,
  path: string,
  options: { token?: string; body?: unknown; expect?: number } = {},
): Promise<T> {
  const response = await fetch(`${origin}${path}`, {
    method,
    headers: headersFor(options.token, options.body !== undefined),
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });

  const expected = options.expect;
  if (expected !== undefined && response.status !== expected) {
    const text = await response.text();
    throw new Error(`${method} ${path} -> ${response.status} (expected ${expected}): ${text}`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Calls an endpoint expecting it to be REFUSED, and reports the refusal. */
async function expectRefusal(
  method: string,
  path: string,
  options: { token?: string; body?: unknown },
): Promise<void> {
  const response = await fetch(`${origin}${path}`, {
    method,
    headers: headersFor(options.token, options.body !== undefined),
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });
  const payload = (await response.json().catch(() => ({}))) as {
    error?: { code?: string };
  };
  if (response.status < 400) {
    warn(`${method} ${path} was ALLOWED (${response.status}) — this is a bug`);
    return;
  }
  ok(`${method} ${path} refused: ${response.status} ${payload.error?.code ?? ''}`);
}

async function register(username: string, invitationToken?: string): Promise<Actor> {
  const body = await call<{ userId: string; accessToken: string; refreshToken: string }>(
    'POST',
    '/auth/register',
    {
      body: {
        username,
        password: PASSWORD,
        ...(invitationToken !== undefined ? { invitationToken } : {}),
      },
      expect: 201,
    },
  );
  return { username, ...body };
}

async function provisionDevice(actor: Actor, name: string): Promise<void> {
  const device = await call<{ deviceId: string; deviceIndex: number; accessToken: string }>(
    'POST',
    '/devices/register',
    {
      token: actor.accessToken,
      expect: 201,
      body: {
        deviceName: name,
        platform: 'windows',
        registrationId: randomInt(1, 16_000),
        publicIdentityKey: publicKey(),
        signedPreKey: { id: 1, publicKey: publicKey(), signature: signature() },
        kyberPreKey: { id: 1, publicKey: kyberKey(), signature: signature(), isLastResort: true },
        oneTimePreKeys: Array.from({ length: 20 }, (_, i) => ({
          id: i + 1,
          publicKey: publicKey(),
        })),
      },
    },
  );
  actor.deviceId = device.deviceId;
  actor.deviceIndex = device.deviceIndex;
  actor.deviceToken = device.accessToken;
}

interface Frame {
  type: string;
  messageId?: string;
  hasQueuedMessages?: boolean;
}

/** Every socket opened, so shutdown can close them all rather than hang. */
const openSockets: WebSocket[] = [];

/** A socket that buffers frames, so nothing is missed between steps. */
function openSocket(token: string): { socket: WebSocket; frames: Frame[]; ready: Promise<void> } {
  const socket = new WebSocket(`${origin.replace('http', 'ws')}/ws`, {
    headers: { authorization: `Bearer ${token}` },
  });
  openSockets.push(socket);
  const frames: Frame[] = [];
  socket.on('message', (raw) => {
    try {
      frames.push(JSON.parse(raw.toString()) as Frame);
    } catch {
      /* not protocol */
    }
  });
  const ready = new Promise<void>((resolve, reject) => {
    socket.once('open', () => resolve());
    socket.once('error', reject);
  });
  return { socket, frames, ready };
}

async function awaitFrame(frames: Frame[], type: string, timeoutMs = 5_000): Promise<Frame> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const index = frames.findIndex((frame) => frame.type === type);
    if (index !== -1) return frames.splice(index, 1)[0] as Frame;
    if (Date.now() > deadline) throw new Error(`timed out waiting for '${type}'`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function main(): Promise<void> {
  // Quiet the request log so the walkthrough is readable. Security events are
  // read back from the database at the end instead. Set DEMO_LOG_LEVEL to see
  // the server's own logs when debugging.
  process.env['LOG_LEVEL'] = process.env['DEMO_LOG_LEVEL'] ?? 'silent';

  const config = loadConfig();
  if (config.isProduction) {
    throw new Error('refusing to run the demo against a production configuration');
  }

  initDatabase(config);
  const redis = initRedis(config);
  await waitForRedis();

  // Rate-limit counters live in Redis with hour-long windows and are keyed per
  // IP, so a previous demo or test run on 127.0.0.1 would throttle this one.
  // Clearing them is consistent with the TRUNCATE below: both reset dev state.
  const limitKeys = await redis.keys('fastify-rate-limit-*');
  if (limitKeys.length > 0) await redis.del(...limitKeys);

  rule('Bond — Phase 1 journey walkthrough');
  detail('Server cryptography: none. The server routes bytes it cannot read.');
  detail('Encryption in THIS SCRIPT is an AES-GCM stand-in, not the product protocol.');
  detail('The real protocol (libsignal, X3DH/PQXDH + Double Ratchet) runs on the');
  detail('Flutter client and is proven by client/test/libsignal_validation_test.dart.');
  rule();

  const app = await buildApp(config);
  await app.listen({ port: 0, host: '127.0.0.1' });
  origin = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;

  try {
    await query('TRUNCATE users, security_events RESTART IDENTITY CASCADE');

    heading('Alice creates the first account');
    detail('Registration is invite-only, so user #1 uses the env-gated bootstrap path.');
    const alice = await register('alice');
    ok(`alice userId = ${alice.userId}`);

    heading("Alice's installation becomes a cryptographic device");
    await provisionDevice(alice, 'alice-windows');
    ok(`deviceId = ${alice.deviceId}`);
    detail(`deviceIndex = ${alice.deviceIndex} (libsignal addressing, 1..127)`);
    detail('Published: public identity key, signed prekey + signature, Kyber prekey, 20 one-time prekeys.');
    detail('Private keys: generated on the device, never sent. The server has no copy.');

    heading('Alice invites Bob');
    const invitation = await call<{ invitationId: string; token: string; expiresAt: string }>(
      'POST',
      '/invitations',
      { token: alice.accessToken, body: {}, expect: 201 },
    );
    ok(`token = ${invitation.token.slice(0, 12)}... (43 chars, shown once, never stored)`);
    const storedInvite = await query<{ token_hash: Buffer }>('SELECT token_hash FROM invitations');
    detail(`database holds only: ${storedInvite[0]?.token_hash.toString('hex').slice(0, 32)}... (HMAC-SHA256)`);

    heading('Bob registers with the invitation');
    const bob = await register('bob', invitation.token);
    ok(`bob userId = ${bob.userId}`);
    detail('One invitation both authorised the account and created the friendship.');
    await provisionDevice(bob, 'bob-windows');
    ok(`bob deviceId = ${bob.deviceId}`);

    heading('The invitation is now spent');
    await expectRefusal('POST', '/auth/register', {
      body: { username: 'mallory', password: PASSWORD, invitationToken: invitation.token },
    });

    heading('Bob connects his WebSocket');
    const bobSocket = openSocket(bob.deviceToken as string);
    await bobSocket.ready;
    const bobReady = await awaitFrame(bobSocket.frames, 'ready');
    ok(`ready received; queued messages waiting: ${bobReady.hasQueuedMessages}`);

    heading('Alice sees Bob as a contact, with his device identity key');
    const contacts = await call<
      Array<{
        contactUserId: string;
        username: string;
        status: string;
        verifiedAt: string | null;
        devices: Array<{ deviceId: string; deviceIndex: number; publicIdentityKey: string }>;
      }>
    >('GET', '/contacts', { token: alice.accessToken, expect: 200 });
    const bobContact = contacts[0];
    ok(`contact: ${bobContact?.username} (${bobContact?.status})`);
    detail(`verified: ${bobContact?.verifiedAt ?? 'NO — unverified until humans compare digits'}`);
    detail(`bob device identity key: ${bobContact?.devices[0]?.publicIdentityKey.slice(0, 24)}...`);

    heading("Alice fetches Bob's prekey bundle to start a session");
    const bundle = await call<{
      kyberPreKey: { id: number; publicKey: string };
      oneTimePreKey: { id: number } | null;
      signedPreKey: { id: number; signature: string };
    }>('GET', `/devices/${bob.deviceId}/public-keys`, {
      token: alice.deviceToken,
      expect: 200,
    });
    ok(`signed prekey #${bundle.signedPreKey.id} with signature (client verifies this)`);
    ok(`Kyber prekey #${bundle.kyberPreKey.id} — PQXDH is mandatory, not optional`);
    ok(`one-time prekey #${bundle.oneTimePreKey?.id} consumed — never handed out again`);
    const remaining = await query<{ count: string }>(
      'SELECT count(*) FROM device_one_time_prekeys WHERE device_id = $1 AND consumed_at IS NULL',
      [bob.deviceId],
    );
    detail(`bob's remaining one-time prekeys: ${remaining[0]?.count} of 20`);

    heading('Alice and Bob compare safety numbers out of band, then Alice records it');
    await call('POST', `/contacts/${bob.userId}/verify`, {
      token: alice.accessToken,
      body: { verified: true },
      expect: 200,
    });
    ok('verified_at set on the server — ADVISORY ONLY');
    detail('A client must never render "verified" because of this field: a compromised');
    detail('server could set it for a key it substituted. Authority is client-local.');

    heading('Alice sends a message');
    const plaintext = 'Hey Bob — the server cannot read this.';
    detail(`plaintext (exists only in this process): "${plaintext}"`);
    const ciphertext = demoEncrypt(plaintext);
    const sent = await call<{ results: Array<{ status: string; messageId: string }> }>(
      'POST',
      '/messages',
      {
        token: alice.deviceToken,
        expect: 201,
        body: {
          envelopes: [
            {
              recipientDeviceId: bob.deviceId,
              envelopeVersion: 1,
              messageType: 'prekey',
              ciphertext,
              senderSequence: 0,
            },
          ],
        },
      },
    );
    const messageId = sent.results[0]?.messageId as string;
    ok(`accepted, messageId = ${messageId}`);

    heading("Bob's socket is notified in real time");
    const queuedFrame = await awaitFrame(bobSocket.frames, 'message.queued');
    ok(`notification for ${queuedFrame.messageId}`);
    detail('The socket carries a notification only — no ciphertext, no plaintext.');
    detail('The body is fetched over HTTPS, so there is ONE authorisation path for content.');

    rule('WHAT THE SERVER DATABASE HOLDS RIGHT NOW');
    const row = await query<{
      id: string;
      sender_device_id: string;
      recipient_device_id: string;
      ciphertext: Buffer;
      message_type: string;
      delivery_state: string;
      sender_sequence: string;
      created_at: Date;
    }>('SELECT * FROM messages WHERE id = $1', [messageId]);
    const message = row[0];
    if (message !== undefined) {
      detail(`id                  ${message.id}`);
      detail(`sender_device_id    ${message.sender_device_id}`);
      detail(`recipient_device_id ${message.recipient_device_id}`);
      detail(`message_type        ${message.message_type}`);
      detail(`delivery_state      ${message.delivery_state}`);
      detail(`sender_sequence     ${message.sender_sequence}`);
      detail(`created_at          ${message.created_at.toISOString()}`);
      detail(`ciphertext (${String(message.ciphertext.length).padStart(3)} bytes)`);
      detail(`  hex   ${message.ciphertext.toString('hex').slice(0, 56)}...`);
      detail(`  utf8  ${JSON.stringify(message.ciphertext.toString('utf8').slice(0, 28))} <- unreadable`);
    }
    const columns = await query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema='public' AND table_name='messages' ORDER BY ordinal_position`,
    );
    detail('');
    detail(`columns: ${columns.map((c) => c.column_name).join(', ')}`);
    detail('No plaintext column. No preview column. No search index. By construction.');
    rule();

    heading('Bob fetches and decrypts locally');
    const inbox = await call<Array<{ messageId: string; ciphertext: string; senderDeviceIndex: number }>>(
      'GET',
      '/messages',
      { token: bob.deviceToken, expect: 200 },
    );
    ok(`${inbox.length} envelope(s) from device index ${inbox[0]?.senderDeviceIndex}`);
    detail(`decrypted on Bob's side: "${demoDecrypt(inbox[0]?.ciphertext as string)}"`);

    heading('Bob acknowledges; Alice gets the receipts over her socket');
    const aliceSocket = openSocket(alice.deviceToken as string);
    await aliceSocket.ready;
    await awaitFrame(aliceSocket.frames, 'ready');
    await call('POST', `/messages/${messageId}/delivered`, { token: bob.deviceToken, expect: 200 });
    ok(`delivered receipt: ${(await awaitFrame(aliceSocket.frames, 'message.delivered')).messageId}`);
    await call('POST', `/messages/${messageId}/read`, { token: bob.deviceToken, expect: 200 });
    ok(`read receipt: ${(await awaitFrame(aliceSocket.frames, 'message.read')).messageId}`);

    heading('Offline delivery: Bob disconnects, Alice sends anyway');
    bobSocket.socket.close();
    await new Promise((resolve) => setTimeout(resolve, 200));
    await call('POST', '/messages', {
      token: alice.deviceToken,
      expect: 201,
      body: {
        envelopes: [
          {
            recipientDeviceId: bob.deviceId,
            envelopeVersion: 1,
            messageType: 'signal',
            ciphertext: demoEncrypt('Sent while you were offline.'),
            senderSequence: 1,
          },
        ],
      },
    });
    ok('accepted and queued while the recipient was absent');
    const stillQueued = await query<{ count: string }>(
      "SELECT count(*) FROM messages WHERE delivery_state = 'queued'",
    );
    detail(`queued rows: ${stillQueued[0]?.count} — the server never decrypted anything`);

    heading('Bob reconnects and is told there is work waiting');
    const bobAgain = openSocket(bob.deviceToken as string);
    await bobAgain.ready;
    const readyAgain = await awaitFrame(bobAgain.frames, 'ready');
    ok(`hasQueuedMessages = ${readyAgain.hasQueuedMessages}`);
    const afterReconnect = await call<Array<{ ciphertext: string }>>('GET', '/messages', {
      token: bob.deviceToken,
      expect: 200,
    });
    detail(`decrypted after reconnect: "${demoDecrypt(afterReconnect[0]?.ciphertext as string)}"`);

    rule('AUTHORISATION BOUNDARIES (these must all be refused)');
    const carolInvite = await call<{ token: string }>('POST', '/invitations', {
      token: alice.accessToken,
      body: {},
      expect: 201,
    });
    const carol = await register('carol', carolInvite.token);
    await provisionDevice(carol, 'carol-windows');
    detail('Carol is a real user invited by Alice, but is not Bob\'s contact.');
    await expectRefusal('GET', `/devices/${bob.deviceId}/public-keys`, { token: carol.deviceToken });
    await expectRefusal('POST', '/messages', {
      token: carol.deviceToken,
      body: {
        envelopes: [
          {
            recipientDeviceId: bob.deviceId,
            envelopeVersion: 1,
            messageType: 'prekey',
            ciphertext: demoEncrypt('let me in'),
            senderSequence: 0,
          },
        ],
      },
    });
    await expectRefusal('POST', `/devices/${bob.deviceId}/revoke`, { token: carol.accessToken });
    await expectRefusal('GET', '/messages', { token: undefined });
    await expectRefusal('GET', `/devices/${bob.deviceId}/public-keys`, { token: alice.accessToken });
    detail('(the last one: an account-scoped token on a device-scoped endpoint)');

    rule('DEVICE REVOCATION');
    heading("Bob revokes his device while its socket is open");
    const closeCode = new Promise<number>((resolve) =>
      bobAgain.socket.once('close', (code: number) => resolve(code)),
    );
    await call('POST', `/devices/${bob.deviceId}/revoke`, {
      token: bob.accessToken,
      expect: 204,
    });
    ok(`live socket closed by the server, code ${await closeCode}`);
    await expectRefusal('GET', '/messages', { token: bob.deviceToken });
    await expectRefusal('POST', '/messages', {
      token: alice.deviceToken,
      body: {
        envelopes: [
          {
            recipientDeviceId: bob.deviceId,
            envelopeVersion: 1,
            messageType: 'signal',
            ciphertext: demoEncrypt('are you there'),
            senderSequence: 2,
          },
        ],
      },
    });
    const withdrawn = await query<{ count: string }>(
      'SELECT count(*) FROM device_one_time_prekeys WHERE device_id = $1 AND consumed_at IS NULL',
      [bob.deviceId],
    );
    ok(`unused prekeys withdrawn: ${withdrawn[0]?.count} remain — no new session possible`);
    detail('Note what revocation does NOT do: plaintext already decrypted on that');
    detail('device stays in its local store. Revocation is not remote wipe.');

    rule('SECURITY EVENTS RECORDED');
    const events = await query<{ event_type: string; severity: string; count: string }>(
      'SELECT event_type, severity, count(*) FROM security_events GROUP BY 1, 2 ORDER BY 1',
    );
    for (const event of events) {
      detail(`${event.count.padStart(3)} x ${event.event_type} (${event.severity})`);
    }
    const audit = await query<{ metadata: unknown }>('SELECT metadata FROM security_events');
    const leaked = JSON.stringify(audit).includes(invitation.token);
    detail('');
    (leaked ? warn : ok)(
      leaked ? 'INVITATION TOKEN FOUND IN AUDIT LOG — bug' : 'no invitation token in the audit log',
    );

    rule('SUMMARY');
    detail('Proven here: invite-only registration, single-use invitations, device');
    detail('provisioning with public-key-only publication, atomic prekey consumption,');
    detail('contact-scoped authorisation, store-and-forward, real-time notification,');
    detail('receipts, offline delivery across a reconnect, and device revocation');
    detail('taking effect on a live connection.');
    detail('');
    detail('NOT proven here: the real cryptography. That is the Flutter client, and');
    detail('client/test/libsignal_validation_test.dart is where it is verified.');
    rule();

    aliceSocket.socket.close();
    bobAgain.socket.close();
  } finally {
    // Close client sockets BEFORE the server: app.close() waits for live
    // connections, so leaving one open turns a failed demo into a hang.
    for (const socket of openSockets) {
      try {
        socket.terminate();
      } catch {
        /* already gone */
      }
    }
    await app.close();
    await Promise.allSettled([closeDatabase(), closeRedis()]);
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`\ndemo failed: ${error instanceof Error ? error.stack : String(error)}\n`);
  process.exit(1);
});
