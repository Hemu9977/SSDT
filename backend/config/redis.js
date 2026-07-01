const Redis = require('ioredis');

let publisherClient = null;
let subscriberClient = null;
let bullMqSharedConnection = null;

const activeConnections = new Set();
let connectionCounter = 0;

const REDIS_URL = () => {
  const url = process.env.REDIS_URL;
  if (!url) throw new Error('REDIS_URL environment variable is not set');
  return url;
};

// Shared exponential-backoff retry strategy — never gives up.
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
 * Create a fresh ioredis client. Use for BullMQ dedicated connections.
 */
function createRedisClient(purpose = 'generic', overrides = {}) {
  connectionCounter++;
  const connectionId = connectionCounter;

  console.log(`[Redis] Creating connection id=${connectionId} purpose="${purpose}"`);

  const client = new Redis(REDIS_URL(), buildOptions(overrides));
  activeConnections.add(client);
  client.connectionId = connectionId;
  client.connectionPurpose = purpose;

  client.on('connect', () => {
    if (client.hasConnected) {
      console.log(`[Redis] Reconnected... (id=${connectionId}, purpose="${purpose}")`);
    } else {
      console.log(`[Redis] Connected... (id=${connectionId}, purpose="${purpose}")`);
      client.hasConnected = true;
    }
    console.log(`[Redis] Current active clients=${activeConnections.size}`);
  });
  client.on('ready', () => {
    console.log(`[Redis] Client ready id=${connectionId} purpose="${purpose}"`);
  });
  client.on('reconnecting', (delay) => {
    console.warn(`[Redis] Reconnecting... (id=${connectionId}, purpose="${purpose}", delay=${delay}ms)`);
  });
  client.on('error', (err) => {
    console.error(`[Redis] Client error id=${connectionId} purpose="${purpose}":`, err.message);
  });
  client.on('close', () => {
    console.log(`[Redis] Client connection closed id=${connectionId} purpose="${purpose}"`);
  });
  client.on('end', () => {
    activeConnections.delete(client);
    console.log(`[Redis] Closed id=${connectionId} purpose="${purpose}"`);
    console.log(`[Redis] Current active clients=${activeConnections.size}`);
  });

  return client;
}

/**
 * Execute a Redis operation with retries on stream errors
 */
async function executeWithRetry(operation, maxRetries = 5, delayMs = 2000) {
  let lastError;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (err) {
      lastError = err;
      const isStreamError = err.message.includes("Stream isn't writeable") || 
                            err.message.includes("closed") || 
                            err.message.includes("enableOfflineQueue");
      if (isStreamError && attempt < maxRetries) {
        console.warn(`[Redis] Command failed (attempt ${attempt}/${maxRetries}): ${err.message}. Retrying in ${delayMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
        continue;
      }
      throw err;
    }
  }
  throw lastError;
}

/** Singleton publisher client — for PUBLISH and general key ops */
function getPublisher() {
  if (!publisherClient || publisherClient.status === 'end') {
    // Make publisher resilient to short network blips by allowing offline queueing
    // and unlimited per-request retries (BullMQ-compatible settings).
    publisherClient = createRedisClient('publisher', {
      enableOfflineQueue: true,
      maxRetriesPerRequest: null
    });
    publisherClient.on('ready', () => console.log('[Redis] Publisher ready'));
  }
  return publisherClient;
}

/** Singleton subscriber client — dedicated for SUBSCRIBE */
function getSubscriber() {
  if (!subscriberClient || subscriberClient.status === 'end') {
    subscriberClient = createRedisClient('subscriber');
    subscriberClient.on('ready', () => console.log('[Redis] Subscriber ready'));
  }
  return subscriberClient;
}

/** Singleton shared connection for BullMQ Queues (non-blocking ops) */
function getBullMQConnection() {
  if (!bullMqSharedConnection || bullMqSharedConnection.status === 'end') {
    bullMqSharedConnection = createRedisClient('bullmq-shared', {
      lazyConnect: false,
      maxRetriesPerRequest: null,
      enableOfflineQueue: false
    });
    bullMqSharedConnection.on('ready', () => console.log('[Redis] BullMQ Shared Connection ready'));
  }
  return bullMqSharedConnection;
}

/** Create a dedicated Redis connection for blocking BullMQ Workers and QueueEvents */
function createDedicatedConnection(purpose, overrides = {}) {
  return createRedisClient(purpose, {
    lazyConnect: false,
    maxRetriesPerRequest: null,
    enableOfflineQueue: false,
    ...overrides
  });
}

/**
 * Startup diagnostic health check querying Redis client count
 */
async function checkRedisClientHealth() {
  let tempClient = null;
  try {
    const useTLS = REDIS_URL().startsWith('rediss://');
    tempClient = new Redis(REDIS_URL(), {
      ...(useTLS ? { tls: {} } : {}),
      connectTimeout: 5000,
      lazyConnect: false
    });

    const info = await tempClient.info('clients');
    let connectedClients = 0;
    let maxClients = 0;

    const lines = info.split('\n');
    for (const line of lines) {
      if (line.startsWith('connected_clients:')) {
        connectedClients = parseInt(line.split(':')[1].trim(), 10);
      }
      if (line.startsWith('maxclients:')) {
        maxClients = parseInt(line.split(':')[1].trim(), 10);
      }
    }

    console.log(`[Redis] Health check: connected_clients=${connectedClients}, maxclients=${maxClients}`);

    if (maxClients > 0 && connectedClients > 0.8 * maxClients) {
      console.warn(`[Redis] ⚠️ WARNING: connected_clients (${connectedClients}) is above 80% of maxclients (${maxClients})`);
    }
  } catch (err) {
    console.error('[Redis] Health check failed:', err.message);
  } finally {
    if (tempClient) {
      await tempClient.quit().catch(() => {});
    }
  }
}

async function disconnectAll() {
  console.log(`[Cleanup] Closing all active Redis connections...`);
  const tasks = [];

  publisherClient = null;
  subscriberClient = null;
  bullMqSharedConnection = null;

  for (const client of activeConnections) {
    try {
      tasks.push(client.quit().catch(() => {}));
    } catch (_) {}
  }

  activeConnections.clear();
  await Promise.all(tasks);
  console.log(`[Cleanup] Successfully cleaned up all connections.`);
}

module.exports = {
  createRedisClient,
  getPublisher,
  getSubscriber,
  getBullMQConnection,
  createDedicatedConnection,
  checkRedisClientHealth,
  disconnectAll,
  executeWithRetry
};
