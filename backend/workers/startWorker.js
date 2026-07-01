/**
 * Standalone Worker Entry Point
 *
 * Run this as a SEPARATE process when you want to scale workers independently
 * from the API server (e.g., a second ECS task just for scan processing):
 *
 *   node backend/workers/startWorker.js
 *
 * For single-container deployments (default), the worker is started inside
 * server.js automatically. Set DISABLE_WORKER=true in server env to prevent
 * a double worker when running this process alongside the server.
 */

'use strict';

if (process.env.DISABLE_WORKER === 'true') {
  console.log('ℹ️  DISABLE_WORKER=true — standalone worker will not start in this environment');
  process.exit(0);
}

{
  const path = require('path');
  const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env';
  require('dotenv').config({ path: path.resolve(__dirname, '..', envFile) });
}

const connectDB             = require('../db');
const { createRedisClient, disconnectAll } = require('../config/redis');
const { createScanWorker }  = require('./scanWorker');
const { createZapWorker }   = require('./zapWorker');
const { setPublisher }      = require('../services/scanProgressService');
const { closeScanQueue }    = require('../queues/scanQueue');
const { closeZapQueue }     = require('../queues/zapQueue');

async function main() {
  console.log('\n=================================');
  console.log('🔧 Starting Standalone Scan Worker');
  console.log('=================================\n');

  // MongoDB is required by scan services
  await connectDB();
  console.log('✅ MongoDB connected');

  // Publisher client — used by scanProgressService to emit Redis pub/sub events
  const publisher = createRedisClient();
  setPublisher(publisher);
  console.log('✅ Redis publisher ready');

  // Start BullMQ workers
  const scanWorker = createScanWorker(publisher);
  const zapWorker  = createZapWorker(publisher);
  console.log('✅ BullMQ scan + ZAP workers running\n');

  // ── Graceful shutdown ────────────────────────────────────────────────────
  const shutdown = async (signal) => {
    console.log(`\n${signal} received — shutting down workers...`);
    try {
      console.log(`[Cleanup] Closing worker connection...`);
      await Promise.all([scanWorker.close(), zapWorker.close()]);
      // Close scan and zap queue connections created inside workers/queues
      await Promise.all([closeScanQueue(), closeZapQueue()]);
      // Close all active Redis connections cleanly (workers' dedicated connections + publisher)
      await disconnectAll();
      console.log('✅ Workers shut down cleanly');
    } catch (err) {
      console.error('⚠️  Error during shutdown:', err.message);
    }
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    console.error('[Worker] Unhandled rejection:', reason);
  });
  process.on('uncaughtException', (err) => {
    console.error('[Worker] Uncaught exception:', err.message);
    shutdown('uncaughtException');
  });
}

main().catch((err) => {
  console.error('❌ Worker failed to start:', err.message);
  process.exit(1);
});
