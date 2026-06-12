/**
 * BullMQ scan queue.
 *
 * All scan jobs flow through this queue so that:
 *   - Duplicate jobs are prevented (jobId = scanId)
 *   - Failed jobs are retried with exponential back-off
 *   - Concurrency is bounded across workers
 *
 * Usage:
 *   const { addScanJob } = require('./queues/scanQueue');
 *   await addScanJob(scanId, url, userId);
 */
const { Queue, QueueEvents } = require('bullmq');
const { createRedisClient } = require('../config/redis');

const QUEUE_NAME = 'scan-queue';
let _queue = null;
let _queueEvents = null;
let _connection = null;

async function closeScanQueue() {
  try {
    // Close QueueEvents first — it holds BullMQ's internal blocking XREAD connection
    if (_queueEvents) { await _queueEvents.close().catch(() => {}); _queueEvents = null; }
    if (_queue)        { await _queue.close().catch(() => {});       _queue       = null; }
    if (_connection)   { await _connection.quit().catch(() => {});   _connection  = null; }
  } catch (err) {
    console.error('[ScanQueue] Error during close:', err.message);
  }
}

const SCAN_JOB_OPTIONS = {
  attempts: 3,
  backoff: { type: 'exponential', delay: 10000 },
  timeout: 30 * 60 * 1000, // fast scanners + ZAP/WebCheck kick-off only
  removeOnComplete: { count: 200, age: 3600 },
  removeOnFail: { count: 200, age: 86400 }
};

function getScanQueue() {
  if (!_queue) {
    if (!_connection) {
      // One BullMQ connection per process for queue + queue events.
      _connection = createRedisClient({ lazyConnect: false, maxRetriesPerRequest: null, enableOfflineQueue: false });
    }

    _queue = new Queue(QUEUE_NAME, {
      // BullMQ recommends maxRetriesPerRequest=null to avoid ioredis aborting
      // long/blocking commands used internally by BullMQ.
      connection: _connection,
      defaultJobOptions: {
        ...SCAN_JOB_OPTIONS
      }
    });

    _queue.on('error', (err) => {
      console.error('[ScanQueue] Queue error:', err.message);
    });

    console.log(`[ScanQueue] Queue "${QUEUE_NAME}" ready`);
  }

  if (!_queueEvents) {
    _queueEvents = new QueueEvents(QUEUE_NAME, {
      connection: _connection
    });
    _queueEvents.on('completed', ({ jobId }) => {
      console.log(`[ScanQueueEvents] ✅ completed jobId=${jobId}`);
    });
    _queueEvents.on('failed', ({ jobId, failedReason }) => {
      console.error(`[ScanQueueEvents] ❌ failed jobId=${jobId}: ${failedReason}`);
    });
    _queueEvents.on('error', (err) => {
      console.error('[ScanQueueEvents] error:', err.message);
    });
  }

  return _queue;
}

/**
 * Enqueue a new scan job.
 * Using scanId as jobId prevents the same scan from being queued twice.
 *
 * @param {string} scanId   - UUID used as both jobId and DB analysisId
 * @param {string} url      - Target URL to scan
 * @param {string} userId   - MongoDB ObjectId string of the owning user
 * @returns {Promise<Job>}
 */
async function addScanJob(scanId, url, userId) {
  const queue = getScanQueue();

  const job = await queue.add(
    'run-scan',
    { scanId, url, userId: String(userId) },
    {
      jobId: scanId, // idempotent: second add with same jobId is a no-op
      ...SCAN_JOB_OPTIONS
    }
  );

  console.log(`[ScanQueue] Enqueued job ${job.id} for scanId=${scanId}`);
  return job;
}

module.exports = { getScanQueue, addScanJob, closeScanQueue, QUEUE_NAME };
