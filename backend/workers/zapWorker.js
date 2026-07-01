/**
 * BullMQ ZAP Worker
 *
 * Processes jobs from "zap-queue". Each job runs the full ZAP lifecycle
 * (spider → AJAX spider → active scan → alerts → GridFS) for one target URL.
 *
 * Key design decisions:
 *   - lockDuration = 14 h  → longer than the 13 h job timeout so BullMQ never
 *     re-assigns a running job to another worker mid-scan.
 *   - concurrency = ZAP_WORKER_CONCURRENCY (default 3) — each ZAP container
 *     handles one scan at a time, so set this to the number of ZAP containers.
 *   - On final failure (all attempts exhausted): marks zapResult as failed in DB
 *     and triggers Gemini so the overall scan doesn't stay stuck in "combining".
 *
 * Can run in two modes:
 *   1. In-process  — started inside server.js (default for single-ECS-task deploys)
 *   2. Standalone  — `node backend/workers/startWorker.js` for a dedicated worker task
 */

const { Worker } = require('bullmq');
const { createDedicatedConnection } = require('../config/redis');
const { setPublisher, publishScanProgress } = require('../services/scanProgressService');
const { ZAP_QUEUE_NAME, ZAP_JOB_TIMEOUT_MS } = require('../queues/zapQueue');

async function processZapJob(job) {
  const { scanId, targetUrl, userId } = job.data;
  console.log(`[ZapWorker] ▶ Job ${job.id} (attempt ${job.attemptsMade + 1}) — scanId=${scanId}`);

  const ScanResult = require('../models/ScanResult');
  const scan = await ScanResult.findOne({ analysisId: scanId });
  if (!scan) throw new Error(`ScanResult ${scanId} not found in DB`);

  if (['stopped', 'cancelled', 'failed', 'completed'].includes(scan.status) || 
      (scan.zapResult && ['stopped', 'completed', 'failed'].includes(scan.zapResult.status))) {
    console.log(`[ZapWorker] Scan ${scanId} is already in terminal state (${scan.status}), skipping ZAP processing`);
    return { scanId, skipped: true };
  }

  // Lazy-require to avoid circular-dep issues and allow in-process + standalone usage.
  const { runAsyncZapScanBackground } = require('../services/zapService');
  if (typeof runAsyncZapScanBackground !== 'function') {
    throw new Error(
      'runAsyncZapScanBackground is not a function (deployment mismatch). ' +
      'Ensure backend/services/zapService.js exports it and ECS is running the latest image.'
    );
  }
  await runAsyncZapScanBackground(targetUrl, scanId, userId);

  console.log(`[ZapWorker] ✅ Job ${job.id} complete — scanId=${scanId}`);
  return { scanId };
}

function createZapWorker(publisherClient) {
  setPublisher(publisherClient);

  const concurrency = Math.max(1, parseInt(process.env.ZAP_WORKER_CONCURRENCY || '3', 10));

  const worker = new Worker(ZAP_QUEUE_NAME, processZapJob, {
    connection: createDedicatedConnection('zap-worker'),
    concurrency,
    // lockDuration must exceed the job timeout so BullMQ never re-assigns a
    // running long scan to another worker process.
    lockDuration: ZAP_JOB_TIMEOUT_MS + 60 * 60 * 1000 // job timeout + 1 h
  });

  console.log(`[Worker] Created: zap-worker`);

  worker.on('completed', (job, result) => {
    console.log(`[ZapWorker] Job ${job.id} completed — scanId=${result?.scanId}`);
  });

  worker.on('failed', async (job, err) => {
    console.error(`[ZapWorker] Job ${job?.id} failed (attempt ${job?.attemptsMade}):`, err.message);
    if (err.message === 'STOPPED_BY_USER') {
      console.log(`[ZapWorker] Job ${job?.id} (scanId=${job?.data?.scanId}) was stopped by user. Skipping failure actions.`);
      return;
    }
    if (!job?.data?.scanId) return;

    const { scanId, userId } = job.data;
    const maxAttempts = job.opts?.attempts ?? 3;
    const isLastAttempt = job.attemptsMade >= maxAttempts;

    if (!isLastAttempt) {
      console.log(`[ZapWorker] Will retry scanId=${scanId} (${job.attemptsMade}/${maxAttempts} attempts used)`);
      return;
    }

    // All retries exhausted — make sure DB reflects failure and Gemini can proceed.
    console.warn(`[ZapWorker] All retries exhausted for scanId=${scanId} — marking failed`);
    try {
      const ScanResult = require('../models/ScanResult');
      await ScanResult.updateOne(
        { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
        {
          $set: {
            'zapResult.status': 'failed',
            'zapResult.phase': 'failed',
            'zapResult.error': err.message,
            'zapResult.failedAt': new Date(),
            updatedAt: new Date()
          }
        }
      );

      await publishScanProgress(scanId, userId, {
        status: 'combining',
        progress: 50,
        message: 'ZAP scan failed after all retries — generating report with available data...',
        zapResult: { status: 'failed', error: err.message }
      });

      // Trigger Gemini even on ZAP failure so the overall scan completes.
      const { checkAndGenerateGemini } = require('../services/geminiCompletionService');
      checkAndGenerateGemini(scanId, String(userId)).catch(e =>
        console.error('[ZapWorker] checkAndGenerateGemini error after final failure:', e.message)
      );
    } catch (updateErr) {
      console.error('[ZapWorker] Failed to handle final job failure:', updateErr.message);
    }
  });

  let lastStreamErrorTime = 0;
  worker.on('error', (err) => {
    if (err.message.includes("Stream isn't writeable") || err.message.includes("enableOfflineQueue")) {
      const now = Date.now();
      if (now - lastStreamErrorTime > 30000) {
        console.error(`[ZapWorker] Worker error: ${err.message} (throttled)`);
        lastStreamErrorTime = now;
      }
    } else {
      console.error('[ZapWorker] Worker error:', err.message);
    }
  });

  console.log(`[ZapWorker] BullMQ ZAP worker started on queue "${ZAP_QUEUE_NAME}" (concurrency: ${concurrency})`);
  return worker;
}

module.exports = { createZapWorker };
