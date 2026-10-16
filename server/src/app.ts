/**
 * Fastify application assembly.
 *
 * Order matters here. Security plugins register before routes so nothing can be
 * served without headers, body limits and rate limiting already in place.
 */

import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import Fastify, { type FastifyInstance } from 'fastify';

import type { Config } from './config/env.ts';
import { buildLoggerOptions } from './core/logging.ts';
import { getRedis, redisHealthy, waitForRedis } from './core/redis.ts';
import { databaseHealthy } from './database/pool.ts';
import { registerErrorHandler } from './middleware/error-handler.ts';
import { registerAuthRoutes } from './modules/auth/auth.routes.ts';
import { registerContactRoutes } from './modules/contacts/contacts.routes.ts';
import { registerDeviceRoutes } from './modules/devices/devices.routes.ts';
import { registerInvitationRoutes } from './modules/invitations/invitations.routes.ts';
import { registerMessageRoutes } from './modules/messages/messages.routes.ts';
import { RealtimeHub } from './realtime/hub.ts';
import { registerWebSocketRoutes } from './realtime/ws.routes.ts';

export async function buildApp(config: Config): Promise<FastifyInstance> {
  // Rate limiting and the realtime hub both issue Redis commands as soon as
  // they are registered, and the offline queue is disabled by design.
  await waitForRedis();

  const app = Fastify({
    logger: buildLoggerOptions(config),
    // Cap request bodies globally. An individual route may lower this, never raise it.
    bodyLimit: config.maxRequestBodyBytes,
    // Only trust X-Forwarded-For when actually behind our reverse proxy.
    // Trusting it otherwise lets a client spoof its IP and walk past every
    // per-IP rate limit.
    trustProxy: config.trustProxy,
    // Reject absurdly long path parameters before routing.
    // Nested under routerOptions: the top-level form is deprecated in Fastify 5
    // and removed in 6.
    routerOptions: { maxParamLength: 128 },
    genReqId: () => crypto.randomUUID(),

    ajv: {
      customOptions: {
        // Fastify defaults to removeAdditional: true, which SILENTLY STRIPS
        // unknown fields instead of rejecting them. That turns every
        // `additionalProperties: false` in our schemas into a no-op and invites
        // mass-assignment bugs. Verified by test: without this, a payload
        // carrying `isAdmin: true` returns 201.
        removeAdditional: false,
        // Fastify also defaults to coerceTypes: true, so "1" would satisfy a
        // number schema and "true" a boolean. For a security-sensitive API the
        // request either matches the contract or it does not.
        coerceTypes: false,
        useDefaults: true,
        allErrors: false,
      },
    },
  });

  await app.register(helmet, {
    // No browser client in Phase 1, so a restrictive CSP costs nothing.
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    hsts: config.enableHsts
      ? { maxAge: 31_536_000, includeSubDomains: true, preload: false }
      : false,
    referrerPolicy: { policy: 'no-referrer' },
  });

  await app.register(cors, {
    // Empty by default: native clients do not send Origin, so there is nothing
    // to allow. A wildcard would only help a browser we do not have.
    origin: config.corsAllowedOrigins.length > 0 ? [...config.corsAllowedOrigins] : false,
    credentials: false,
  });

  await app.register(rateLimit, {
    // Counters live in Redis so limits hold across restarts and instances
    // rather than resetting whenever the process does.
    redis: getRedis(),
    global: true,
    max: 300,
    timeWindow: '1 minute',
    // Per authenticated user where known, per IP otherwise.
    keyGenerator: (request) => request.auth?.userId ?? request.ip,
    continueExceeding: false,
    skipOnError: false,
  });

  await app.register(jwt, {
    secret: config.accessTokenSecret,
    sign: { algorithm: 'HS256' },
    verify: { algorithms: ['HS256'] },
  });

  registerErrorHandler(app);

  // Liveness and readiness. Deliberately unauthenticated and deliberately
  // uninformative: it reports up or down, never versions or connection strings.
  app.get('/health', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (_request, reply) => {
    const [db, redis] = await Promise.all([databaseHealthy(), redisHealthy()]);
    const ok = db && redis;
    return reply.code(ok ? 200 : 503).send({ status: ok ? 'ok' : 'degraded' });
  });

  await app.register(websocket, {
    options: {
      // Client frames are tiny notifications/keep-alives. Bodies travel over
      // HTTPS, so a large frame here is either a bug or an attack.
      maxPayload: 4 * 1024,
      clientTracking: false,
    },
  });

  const hub = new RealtimeHub(app.log);
  // Close subscriber connection and live sockets with the server, so a restart
  // does not leave orphaned Redis subscriptions behind.
  app.addHook('onClose', async () => {
    await hub.close();
  });
  app.decorate('realtime', hub);

  registerAuthRoutes(app, config);
  registerDeviceRoutes(app, config);
  registerInvitationRoutes(app, config);
  registerContactRoutes(app);
  registerMessageRoutes(app, config);
  registerWebSocketRoutes(app, hub, config);

  return app;
}

declare module 'fastify' {
  interface FastifyInstance {
    realtime: RealtimeHub;
  }
}
