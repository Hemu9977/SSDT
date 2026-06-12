/**
 * Redis connection factory using ioredis.
 * Redis Cloud requires TLS — always enabled.
 *
 * Two singletons are maintained:
 *   publisher  — for PUBLISH / general commands
 *   subscriber — dedicated connection for SUBSCRIBE (ioredis requirement)
 *
 * BullMQ workers/queues call createRedisClient() to get their own connection.
 *
 * Retry strategy:
 *   - Never gives up permanently (previous 10-attempt limit caused ECS task failures
 *     after transient Redis Cloud disconnects; once disconnected, workers stopped cold).
 *   - Exponential backoff capped at 30 s so reconnects happen quickly at first and
 *     don't flood the Redis Cloud endpoint under sustained outage.
 *   - BullMQ worker connections additionally set enableOfflineQueue:false so queued
 *     commands are rejected immediately rather than piling up during a disconnect
 *     (BullMQ re-issues them itself when the connection recovers).
 */
const Redis = require('ioredis');

let publisherClient = null;
let subscriberClient = null;

const REDIS_URL = () => {
  const url = process.env.REDIS_URL;
  if (!url) throw new Error('REDIS_URL environment variable is not set');
  return url;
};

// Shared exponential-backoff retry strategy — never gives up.
// Delay: min(attempt * 200 ms, 30 000 ms).  Logs every 10 attempts so the
// log stream has signal without being flooded.
function resilientRetryStrategy(times) {
  const delay = Math.min(times * 200, 30_000);
  if (times % 10 === 1) {
    console.warn(`[Redis] Reconnect attempt ${times} — next retry in ${delay}ms`);
  }
  return delay;
}

function buildOptions(overrides = {}) {
  // rediss:// = TLS required (Redis Cloud); redis:// = plain (local dev)
  const useTLS = REDIS_URL().startsWith('rediss://');
  return {
    ...(useTLS ? { tls: {} } : {}),
    retryStrategy: resilientRetryStrategy,
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    connectTimeout: 10000,
    lazyConnect: false,
    ...overrides
  };
}

/**
 * Create a fresh ioredis client. Use for BullMQ connections (each needs its own).
 *
 * For BullMQ worker connections, pass { maxRetriesPerRequest: null, enableOfflineQueue: false }.
 *   - maxRetriesPerRequest: null  — BullMQ requirement; prevents per-command retry limit
 *                                   which would throw before the reconnect strategy fires.
 *   - enableOfflineQueue: false   — reject commands immediately while disconnected so
 *                                   BullMQ can handle the error and retry the job itself,
 *                                   rather than silently queuing commands that may never
 *                                   be flushed if the connection never recovers.
 */
function createRedisClient(overrides = {}) {
  const client = new Redis(REDIS_URL(), buildOptions(overrides));

  client.on('error', (err) => {
    console.error('[Redis] Client error:', err.message);
  });
  client.on('connect', () => {
    console.log('[Redis] Client connected');
  });
  client.on('reconnecting', (delay) => {
    console.warn(`[Redis] Client reconnecting in ${delay}ms...`);
  });
  client.on('ready', () => {
    console.log('[Redis] Client ready');
  });
  client.on('end', () => {
    console.warn('[Redis] Client connection ended (will not reconnect unless recreated)');
  });

  return client;
}

/** Singleton publisher client — for PUBLISH and general key ops */
function getPublisher() {
  if (!publisherClient || publisherClient.status === 'end') {
    publisherClient = createRedisClient();
    publisherClient.on('ready', () => console.log('[Redis] Publisher ready'));
  }
  return publisherClient;
}

/** Singleton subscriber client — dedicated for SUBSCRIBE (cannot share with publisher) */
function getSubscriber() {
  if (!subscriberClient || subscriberClient.status === 'end') {
    subscriberClient = createRedisClient();
    subscriberClient.on('ready', () => console.log('[Redis] Subscriber ready'));
  }
  return subscriberClient;
}

async function disconnectAll() {
  const tasks = [];
  if (publisherClient) {
    tasks.push(publisherClient.quit().catch(() => {}));
    publisherClient = null;
  }
  if (subscriberClient) {
    tasks.push(subscriberClient.quit().catch(() => {}));
    subscriberClient = null;
  }
  await Promise.all(tasks);
}

module.exports = { createRedisClient, getPublisher, getSubscriber, disconnectAll };
