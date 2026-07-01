/**
 * BullMQ ZAP scan queue.
 *
 * Separating ZAP from the fast-scanner queue lets us:
 *   - Set a long job timeout (13 h) without affecting PSI/Observatory jobs
 *   - Scale ZAP workers independently from the API server
 *   - Use BullMQ retry/backoff for ZAP container startup failures
 */
const { Queue } = require('bullmq');
const { getBullMQConnection } = require('../config/redis');

const ZAP_QUEUE_NAME = 'zap-queue';
const ZAP_JOB_TIMEOUT_MS = 13 * 60 * 60 * 1000; // 13 h — 1 h buffer over the 12 h scan max

let _queue = null;

async function closeZapQueue() {
  try {
    if (_queue) {
      await _queue.close().catch(() => {});
      _queue = null;
    }
  } catch (err) {
    console.error('[ZapQueue] Error during close:', err.message);
  }
}

function getZapQueue() {
  if (!_queue) {
    const connection = getBullMQConnection();
    _queue = new Queue(ZAP_QUEUE_NAME, {
      connection,
      defaultJobOptions: {
        attempts: 3,
        backoff: { type: 'exponential', delay: 30000 }, // 30 s, 60 s, 120 s
        timeout: ZAP_JOB_TIMEOUT_MS,
        removeOnComplete: { count: 200, age: 3600 },
        removeOnFail: { count: 200, age: 86400 }
      }
    });
    _queue.on('error', (err) => console.error('[ZapQueue] Queue error:', err.message));
    console.log(`[Queue] Created: ${ZAP_QUEUE_NAME}`);
  }
  return _queue;
}

/**
 * Enqueue a ZAP scan job.
 * jobId = "zap-<scanId>" prevents the same scan from being queued twice.
 */
async function addZapJob(scanId, targetUrl, userId) {
  const queue = getZapQueue();
  const job = await queue.add(
    'run-zap-scan',
    { scanId, targetUrl, userId: String(userId) },
    {
      jobId: `zap-${scanId}`,
      attempts: 3,
      backoff: { type: 'exponential', delay: 30000 },
      timeout: ZAP_JOB_TIMEOUT_MS
    }
  );
  console.log(`[ZapQueue] Enqueued ZAP job ${job.id} for scanId=${scanId}`);
  return job;
}

module.exports = { getZapQueue, addZapJob, closeZapQueue, ZAP_QUEUE_NAME, ZAP_JOB_TIMEOUT_MS };
