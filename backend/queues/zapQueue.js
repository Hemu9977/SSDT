/**
 * BullMQ ZAP scan queue.
 *
 * Separating ZAP from the fast-scanner queue lets us:
 *   - Give ZAP its own concurrency and retry policy, independent of PSI/Observatory
 *   - Scale ZAP workers independently from the API server
 *   - Use BullMQ retry/backoff for ZAP container startup failures
 *
 * NOTE: BullMQ has no per-job `timeout` option (it was removed in v4; this project is on
 * v5). Passing one is silently ignored, so the 13 h "job timeout" this file used to set
 * never existed. The bound that actually applies is the 12 h in-process globalDeadline in
 * zapService.runAsyncZapScanBackground. ZAP_JOB_TIMEOUT_MS is retained solely because
 * zapWorker derives its lockDuration from it.
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
      backoff: { type: 'exponential', delay: 30000 }
    }
  );
  console.log(`[ZapQueue] Enqueued ZAP job ${job.id} for scanId=${scanId}`);
  return job;
}

module.exports = { getZapQueue, addZapJob, closeZapQueue, ZAP_QUEUE_NAME, ZAP_JOB_TIMEOUT_MS };
