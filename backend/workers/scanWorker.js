/**
 * BullMQ Scan Worker
 *
 * Processes jobs from "scan-queue". Each job runs the fast scanners
 * (PageSpeed, Observatory, URLScan) in parallel, saves results to MongoDB,
 * then kicks off ZAP and WebCheck as non-blocking background tasks.
 *
 * Progress is published to Redis pub/sub after each milestone so the
 * main server can forward events to the browser via Socket.IO.
 *
 * Can run in two modes:
 *   1. In-process  — created inside server.js (default, simplest for single ECS task)
 *   2. Standalone  — `node backend/workers/startWorker.js` for horizontal scaling
 */

const { Worker } = require('bullmq');
const { createRedisClient } = require('../config/redis');
const { setPublisher, publishScanProgress } = require('../services/scanProgressService');
const { QUEUE_NAME } = require('../queues/scanQueue');
const scanConfig = require('../config/scanConfig');

// ──────────────────────────────────────────────────────────────────────────────
// Job processor
// ──────────────────────────────────────────────────────────────────────────────

async function processScanJob(job) {
  const { scanId, url, userId } = job.data;
  console.log(`[Worker] ▶ Job ${job.id} started — scanId=${scanId}, url=${url}`);

  // Lazy-require services (avoids circular-dep issues and allows both in-process
  // and standalone usage without importing everything at module load time).
  const { getPageSpeedReport }      = require('../services/pagespeedService');
  const { scanHost }                 = require('../services/observatoryService');
  const { runUrlScan }               = require('../services/urlscanService');
  const { startAsyncZapScan }        = require('../services/zapService');
  const { startAsyncWebCheckScan }   = require('../services/webCheckService');
  const ScanResult                   = require('../models/ScanResult');

  // ── 1. Guard: fetch scan + check it hasn't already been stopped ───────────
  const scan = await ScanResult.findOne({ analysisId: scanId });
  if (!scan) throw new Error(`Scan ${scanId} not found in DB`);

  if (['stopped', 'cancelled', 'failed', 'completed'].includes(scan.status)) {
    console.log(`[Worker] Scan ${scanId} already in terminal state (${scan.status}), skipping`);
    return { skipped: true, reason: scan.status };
  }

  // ── 2. Mark scan as running ───────────────────────────────────────────────
  await ScanResult.updateOne(
    { analysisId: scanId, status: { $nin: ['stopped', 'cancelled'] } },
    { $set: { status: 'combining', updatedAt: new Date() } }
  );

  await publishScanProgress(scanId, userId, {
    status: 'combining',
    progress: 10,
    message: 'Scan started — running PageSpeed, Observatory and URLScan in parallel...'
  });

  // ── 3. Fast scanners (parallel, non-blocking) ─────────────────────────────
  console.log(`[Worker] Running fast scanners for ${scanId}`);
  const hostname = new URL(url).hostname;

  // Idempotency: on BullMQ retry, don't recompute scanners that already have results.
  const needsPsi = !scan.pagespeedResult;
  const needsObs = !scan.observatoryResult;
  const needsUrlscan = !scan.urlscanResult;

  const [psiSettled, obsSettled, urlscanSettled] = await Promise.allSettled([
    needsPsi ? getPageSpeedReport(url) : Promise.resolve(scan.pagespeedResult),
    needsObs ? scanHost(hostname) : Promise.resolve(scan.observatoryResult),
    needsUrlscan ? runUrlScan(url) : Promise.resolve(scan.urlscanResult)
  ]);

  const pagespeedResult = psiSettled.status === 'fulfilled'
    ? psiSettled.value
    : { error: psiSettled.reason?.message || 'PageSpeed scan failed' };

  const observatoryResult = obsSettled.status === 'fulfilled'
    ? obsSettled.value
    : { error: obsSettled.reason?.message || 'Observatory scan failed' };

  const urlscanResult = urlscanSettled.status === 'fulfilled'
    ? urlscanSettled.value
    : { error: urlscanSettled.reason?.message || 'URLScan failed' };

  if (needsPsi && psiSettled.status === 'rejected')     console.error(`[Worker] PSI failed for ${scanId}:`, psiSettled.reason?.message);
  if (needsObs && obsSettled.status === 'rejected')     console.error(`[Worker] Observatory failed for ${scanId}:`, obsSettled.reason?.message);
  if (needsUrlscan && urlscanSettled.status === 'rejected') console.error(`[Worker] URLScan failed for ${scanId}:`, urlscanSettled.reason?.message);

  // ── 4. Persist fast results ───────────────────────────────────────────────
  // Persist fast results (only overwrite missing fields; keep existing data on retries)
  const fastUpdate = { updatedAt: new Date() };
  if (needsPsi) fastUpdate.pagespeedResult = pagespeedResult;
  if (needsObs) fastUpdate.observatoryResult = observatoryResult;
  if (needsUrlscan) fastUpdate.urlscanResult = urlscanResult;

  await ScanResult.updateOne(
    { analysisId: scanId, status: { $nin: ['stopped', 'cancelled'] } },
    { $set: fastUpdate }
  );

  await publishScanProgress(scanId, userId, {
    status: 'combining',
    progress: 40,
    message: 'Fast scans complete — starting deep vulnerability scans...',
    pagespeedResult,
    observatoryResult,
    urlscanResult
  });

  // ── 5. Start ZAP (non-blocking) ───────────────────────────────────────────
  // Idempotency: don't start ZAP again if it's already started/running/completed.
  // 'pending' is included so we retry when the DB was updated to 'pending' but
  // addZapJob() threw (e.g. transient Redis error) — the job was never enqueued.
  let zapInitResult = scan.zapResult || { status: 'failed', error: 'Failed to start' };
  const zapStatusExisting = scan.zapResult?.status;
  const shouldStartZap = !zapStatusExisting || zapStatusExisting === 'failed' || zapStatusExisting === 'pending';

  if (shouldStartZap) {
    try {
      zapInitResult = await startAsyncZapScan(url, scanId, userId);
      console.log(`[Worker] ZAP started for ${scanId}: ${zapInitResult?.status}`);
    } catch (err) {
      console.error(`[Worker] ZAP failed to start for ${scanId}:`, err.message);
      zapInitResult = { status: 'failed', error: err.message };
    }
  } else {
    console.log(`[Worker] ZAP already ${zapStatusExisting} for ${scanId} — not restarting`);
  }

  // ── 6. Start WebCheck (non-blocking) ─────────────────────────────────────
  // Idempotency: don't start WebCheck again if it's already started/running/completed.
  let webCheckInitResult = scan.webCheckResult || { status: 'failed', error: 'Failed to start' };
  const webCheckStatusExisting = scan.webCheckResult?.status;
  const shouldStartWebCheck = !webCheckStatusExisting || webCheckStatusExisting === 'failed';

  if (shouldStartWebCheck) {
    try {
      webCheckInitResult = await startAsyncWebCheckScan(url, scanId, userId);
      console.log(`[Worker] WebCheck started for ${scanId}: ${webCheckInitResult?.status}`);
    } catch (err) {
      console.error(`[Worker] WebCheck failed to start for ${scanId}:`, err.message);
      webCheckInitResult = { status: 'failed', error: err.message };
    }
  } else {
    console.log(`[Worker] WebCheck already ${webCheckStatusExisting} for ${scanId} — not restarting`);
  }

  // ── 7. Persist initial ZAP/WebCheck status (only if not already set by racing background) ──
  const updateFields = {};
  const fresh = await ScanResult.findOne({ analysisId: scanId }, { zapResult: 1, webCheckResult: 1 });
  if (!fresh?.zapResult?.status)      updateFields.zapResult      = zapInitResult;
  if (!fresh?.webCheckResult?.status) updateFields.webCheckResult = webCheckInitResult;

  if (Object.keys(updateFields).length > 0) {
    await ScanResult.updateOne(
      { analysisId: scanId, status: { $nin: ['stopped', 'cancelled'] } },
      { $set: { ...updateFields, updatedAt: new Date() } }
    );
  }

  await publishScanProgress(scanId, userId, {
    status: 'combining',
    progress: 45,
    message: 'Deep scans running in background — you will see results as they arrive...',
    zapResult:      zapInitResult,
    webCheckResult: webCheckInitResult
  });

  console.log(`[Worker] ✅ Job ${job.id} handed off. ZAP + WebCheck running async.`);

  return {
    scanId,
    zapStarted:      zapInitResult.status !== 'failed',
    webCheckStarted: webCheckInitResult.status !== 'failed'
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Worker factory
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Create and start a BullMQ Worker.
 *
 * @param {Redis} publisherClient  - ioredis client used by scanProgressService
 * @returns {Worker}
 */
function createScanWorker(publisherClient) {
  // Wire the publisher so scanProgressService can emit events from the worker process
  setPublisher(publisherClient);

  const concurrency = Math.max(1, scanConfig.worker.concurrency);

  const worker = new Worker(QUEUE_NAME, processScanJob, {
    connection: createRedisClient({ lazyConnect: false, maxRetriesPerRequest: null, enableOfflineQueue: false }),
    concurrency,
    limiter: {
      max:      scanConfig.worker.rateLimitMax,
      duration: scanConfig.worker.rateLimitWindowMs,
    },
  });

  worker.on('completed', (job, result) => {
    if (result?.skipped) {
      console.log(`[Worker] Job ${job.id} skipped (already in terminal state)`);
    } else {
      console.log(`[Worker] Job ${job.id} completed — scanId=${result?.scanId}`);
    }
  });

  worker.on('failed', async (job, err) => {
    console.error(`[Worker] Job ${job?.id} failed:`, err.message);

    if (!job?.data?.scanId) return;
    const { scanId, userId } = job.data;

    try {
      const ScanResult = require('../models/ScanResult');
      await ScanResult.updateOne(
        { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
        { $set: { status: 'failed', updatedAt: new Date() } }
      );
      await publishScanProgress(scanId, userId, {
        status: 'failed',
        progress: 0,
        error: err.message || 'Scan job failed'
      });
    } catch (updateErr) {
      console.error('[Worker] Failed to mark scan as failed in DB:', updateErr.message);
    }
  });

  worker.on('error', (err) => {
    console.error('[Worker] Worker error:', err.message);
  });

  console.log(
    `[Worker] BullMQ worker started on queue "${QUEUE_NAME}" ` +
    `concurrency=${concurrency} rateLimit=${scanConfig.worker.rateLimitMax}/${scanConfig.worker.rateLimitWindowMs}ms`
  );
  return worker;
}

module.exports = { createScanWorker };
