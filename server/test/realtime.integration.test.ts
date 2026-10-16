/**
 * WebSocket delivery and offline/reconnect behaviour.
 *
 * Needs a real listening socket, so unlike the other suites this one binds an
 * ephemeral port rather than using app.inject().
 *
 * As in the journey suite, "ciphertext" is random bytes — these tests prove
 * transport and authorisation, not encryption.
 */

import type { AddressInfo } from 'node:net';
import type { FastifyInstance } from 'fastify';
import WebSocket from 'ws';
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
  registerActor,
  registerDeviceFor,
  type Actor,
} from './helpers.ts';

let app: FastifyInstance;
let config: Config;
let baseWsUrl: string;

interface RealtimeFrame {
  type: string;
  messageId?: string;
  hasQueuedMessages?: boolean;
}

/**
 * Frames received per socket, buffered from the moment it is created.
 *
 * Needed because the server sends `ready` immediately on connect: a listener
 * attached after `connect()` resolves can miss frames that already arrived.
 * Buffering removes the race instead of sprinkling sleeps through the tests.
 */
const received = new WeakMap<WebSocket, RealtimeFrame[]>();

/** Opens a socket and resolves once it is connected. */
async function connect(token: string): Promise<WebSocket> {
  const socket = new WebSocket(`${baseWsUrl}/ws`, {
    // Authorization header, not a query parameter: a token in a URL lands in
    // access logs.
    headers: { authorization: `Bearer ${token}` },
  });

  const buffer: RealtimeFrame[] = [];
  received.set(socket, buffer);
  // Attached before 'open' is awaited, so no frame can slip through.
  socket.on('message', (raw: WebSocket.RawData) => {
    try {
      buffer.push(JSON.parse(raw.toString()) as RealtimeFrame);
    } catch {
      // Non-JSON frames are not part of the protocol.
    }
  });

  await new Promise<void>((resolve, reject) => {
    socket.once('open', () => resolve());
    socket.once('error', reject);
  });
  return socket;
}

/** Consumes the next frame of a given type, from the buffer or as it arrives. */
async function waitForFrame(
  socket: WebSocket,
  type: string,
  timeoutMs = 5_000,
): Promise<RealtimeFrame> {
  const buffer = received.get(socket) ?? [];

  const take = (): RealtimeFrame | undefined => {
    const index = buffer.findIndex((frame) => frame.type === type);
    return index === -1 ? undefined : buffer.splice(index, 1)[0];
  };

  const alreadyHere = take();
  if (alreadyHere !== undefined) return alreadyHere;

  return new Promise<RealtimeFrame>((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const poll = setInterval(() => {
      const frame = take();
      if (frame !== undefined) {
        clearInterval(poll);
        resolve(frame);
        return;
      }
      if (Date.now() >= deadline) {
        clearInterval(poll);
        reject(new Error(`timed out waiting for frame '${type}'`));
      }
    }, 10);
  });
}

async function waitForClose(socket: WebSocket, timeoutMs = 5_000): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for close')), timeoutMs);
    socket.once('close', (code: number) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

async function pairAliceAndBob(): Promise<{ alice: Actor; bob: Actor }> {
  const alice = await registerActor(app, 'alice');
  await registerDeviceFor(app, alice);
  const invitation = await createInvitation(app, alice);
  const bob = await registerActor(app, 'bob', invitation.token);
  await registerDeviceFor(app, bob);
  return { alice, bob };
}

async function sendTo(sender: Actor, recipient: Actor, sequence: number): Promise<string> {
  const response = await app.inject({
    method: 'POST',
    url: '/messages',
    headers: authHeader(deviceToken(sender)),
    payload: {
      envelopes: [
        {
          recipientDeviceId: deviceId(recipient),
          envelopeVersion: 1,
          messageType: sequence === 0 ? 'prekey' : 'signal',
          ciphertext: ciphertextB64(),
          senderSequence: sequence,
        },
      ],
    },
  });
  expect(response.statusCode, response.body).toBe(201);
  const messageId = response.json<{ results: Array<{ messageId: string }> }>().results[0]?.messageId;
  if (messageId === undefined) throw new Error('send returned no message id');
  return messageId;
}

beforeAll(async () => {
  config = loadConfig();
  initDatabase(config);
  initRedis(config);
  app = await buildApp(config);
  await app.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.address() as AddressInfo;
  baseWsUrl = `ws://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await app.close();
  await Promise.allSettled([closeDatabase(), closeRedis()]);
});

beforeEach(async () => {
  await query('TRUNCATE users, security_events RESTART IDENTITY CASCADE');
});

describe('websocket authentication', () => {
  it('rejects an unauthenticated connection', async () => {
    const socket = new WebSocket(`${baseWsUrl}/ws`);
    await expect(
      new Promise<void>((resolve, reject) => {
        socket.once('open', () => resolve());
        socket.once('error', reject);
      }),
    ).rejects.toThrow(/401|Unexpected server response/);
  });

  it('rejects a garbage token', async () => {
    const socket = new WebSocket(`${baseWsUrl}/ws`, {
      headers: { authorization: 'Bearer not-a-real-token' },
    });
    await expect(
      new Promise<void>((resolve, reject) => {
        socket.once('open', () => resolve());
        socket.once('error', reject);
      }),
    ).rejects.toThrow(/401|Unexpected server response/);
  });

  it('rejects an account-scoped token with no device', async () => {
    const alice = await registerActor(app, 'alice');
    // Account token: valid, but carries no device claim.
    const socket = new WebSocket(`${baseWsUrl}/ws`, {
      headers: { authorization: `Bearer ${alice.accessToken}` },
    });
    await expect(
      new Promise<void>((resolve, reject) => {
        socket.once('open', () => resolve());
        socket.once('error', reject);
      }),
    ).rejects.toThrow(/403|Unexpected server response/);
  });

  it('accepts a device-scoped token and announces readiness', async () => {
    const { bob } = await pairAliceAndBob();
    const socket = await connect(deviceToken(bob));
    try {
      const ready = await waitForFrame(socket, 'ready');
      expect(ready.hasQueuedMessages).toBe(false);
    } finally {
      socket.close();
    }
  });
});

describe('realtime delivery', () => {
  it('notifies the recipient when a message is queued', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const socket = await connect(deviceToken(bob));

    try {
      await waitForFrame(socket, 'ready');

      // Start listening BEFORE sending, or the notification can arrive first.
      const notification = waitForFrame(socket, 'message.queued');
      const messageId = await sendTo(alice, bob, 0);

      const frame = await notification;
      expect(frame.messageId).toBe(messageId);

      // The notification carries no ciphertext: the body is fetched over HTTPS,
      // so there is one authorisation path for message content, not two.
      expect(JSON.stringify(frame)).not.toContain('ciphertext');
    } finally {
      socket.close();
    }
  });

  it('notifies the sender of delivery and read receipts', async () => {
    const { alice, bob } = await pairAliceAndBob();
    const aliceSocket = await connect(deviceToken(alice));

    try {
      await waitForFrame(aliceSocket, 'ready');
      const messageId = await sendTo(alice, bob, 0);

      const deliveredFrame = waitForFrame(aliceSocket, 'message.delivered');
      const ack = await app.inject({
        method: 'POST',
        url: `/messages/${messageId}/delivered`,
        headers: authHeader(deviceToken(bob)),
      });
      expect(ack.statusCode).toBe(200);
      expect((await deliveredFrame).messageId).toBe(messageId);

      const readFrame = waitForFrame(aliceSocket, 'message.read');
      await app.inject({
        method: 'POST',
        url: `/messages/${messageId}/read`,
        headers: authHeader(deviceToken(bob)),
      });
      expect((await readFrame).messageId).toBe(messageId);
    } finally {
      aliceSocket.close();
    }
  });

  it('answers an application-level ping', async () => {
    const { bob } = await pairAliceAndBob();
    const socket = await connect(deviceToken(bob));
    try {
      await waitForFrame(socket, 'ready');
      const pong = waitForFrame(socket, 'pong');
      socket.send(JSON.stringify({ type: 'ping' }));
      expect((await pong).type).toBe('pong');
    } finally {
      socket.close();
    }
  });

  it('closes a connection that sends an oversized frame', async () => {
    const { bob } = await pairAliceAndBob();
    const socket = await connect(deviceToken(bob));
    await waitForFrame(socket, 'ready');

    const closed = waitForClose(socket);
    // Beyond the plugin's maxPayload, so the socket is torn down unparsed.
    socket.send('x'.repeat(8 * 1024));
    const code = await closed;
    expect(code).toBeGreaterThanOrEqual(1001);
  });
});

describe('offline then reconnect', () => {
  it('reports queued work on reconnect and the queue survives the disconnect', async () => {
    const { alice, bob } = await pairAliceAndBob();

    // Bob connects, then drops.
    const first = await connect(deviceToken(bob));
    await waitForFrame(first, 'ready');
    first.close();
    await waitForClose(first);

    // Alice sends while he is away.
    await sendTo(alice, bob, 0);
    await sendTo(alice, bob, 1);

    // Bob returns and is told there is something waiting.
    const second = await connect(deviceToken(bob));
    try {
      const ready = await waitForFrame(second, 'ready');
      expect(ready.hasQueuedMessages).toBe(true);

      const inbox = await app.inject({
        method: 'GET',
        url: '/messages',
        headers: authHeader(deviceToken(bob)),
      });
      expect(inbox.json<unknown[]>()).toHaveLength(2);
    } finally {
      second.close();
    }
  });

  it('tolerates two concurrent connections for one device', async () => {
    const { alice, bob } = await pairAliceAndBob();

    // A reconnect can briefly overlap an old socket. Both must receive the
    // notification, and acknowledgement must stay idempotent.
    const a = await connect(deviceToken(bob));
    const b = await connect(deviceToken(bob));

    try {
      await Promise.all([waitForFrame(a, 'ready'), waitForFrame(b, 'ready')]);

      const onA = waitForFrame(a, 'message.queued');
      const onB = waitForFrame(b, 'message.queued');
      const messageId = await sendTo(alice, bob, 0);

      expect((await onA).messageId).toBe(messageId);
      expect((await onB).messageId).toBe(messageId);

      // Both sockets' clients ack; the second must not error or double-count.
      const firstAck = await app.inject({
        method: 'POST',
        url: `/messages/${messageId}/delivered`,
        headers: authHeader(deviceToken(bob)),
      });
      const secondAck = await app.inject({
        method: 'POST',
        url: `/messages/${messageId}/delivered`,
        headers: authHeader(deviceToken(bob)),
      });
      expect(firstAck.statusCode).toBe(200);
      expect(secondAck.statusCode).toBe(200);
      expect(secondAck.json<{ deliveryState: string }>().deliveryState).toBe('delivered');
    } finally {
      a.close();
      b.close();
    }
  });
});

describe('revocation closes live sockets', () => {
  it('disconnects a device as soon as it is revoked', async () => {
    const { bob } = await pairAliceAndBob();
    const socket = await connect(deviceToken(bob));
    await waitForFrame(socket, 'ready');

    const closed = waitForClose(socket);
    const revoke = await app.inject({
      method: 'POST',
      url: `/devices/${deviceId(bob)}/revoke`,
      headers: authHeader(bob.accessToken),
    });
    expect(revoke.statusCode).toBe(204);

    // Without this, a revoked device keeps receiving notifications until it
    // happens to disconnect on its own.
    await expect(closed).resolves.toBeGreaterThanOrEqual(1000);
  });
});
