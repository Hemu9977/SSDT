/**
 * Scan Progress Service
 *
 * Publishes scan progress events to Redis pub/sub channel `scan_progress`.
 * The main server subscribes to this channel and re-emits each event to the
 * correct Socket.IO user room so the browser receives live updates.
 *
 * This decoupling means the BullMQ worker (separate process) can publish
 * progress without needing direct access to the Socket.IO server.
 *
 * Channel payload shape:
 *   { scanId, userId, status, progress, message, timestamp, ...extra }
 */

const { executeWithRetry } = require('../config/redis');
const CHANNEL = 'scan_progress';
const SCAN_STATE_TTL_S = 3600; // 1 h
const SCAN_STATE_WRITE_TIMEOUT_MS = 250;

let _publisher = null;
let _directEmit = null; // Optional: in-process fast-path (bypasses Redis)

function _sanitizeForRedisState(data) {
  // Never store large payloads (Lighthouse, WebCheck full results, etc.) in Redis.
  const status = data?.status;
  const progress = typeof data?.progress === 'number' ? data.progress : undefined;
  const message = typeof data?.message === 'string' ? data.message : undefined;
  const error = typeof data?.error === 'string' ? data.error : undefined;

  const zapStatus = data?.zapResult?.status || data?.zapStatus;
  const webCheckStatus = data?.webCheckResult?.status || data?.webCheckStatus;

  return {
    status,
    progress,
    message,
    error,
    modules: {
      pagespeed: !!data?.pagespeedResult,
      observatory: !!data?.observatoryResult,
      urlscan: !!data?.urlscanResult,
      zapStatus: zapStatus || null,
      webCheckStatus: webCheckStatus || null,
      ai: !!data?.aiReport
    }
  };
}

async function _saveScanState(scanId, userId, data) {
  if (!_publisher) return;
  const key = `scan:${scanId}`;
  const state = {
    scanId,
    userId: String(userId),
    updatedAt: Date.now(),
    ..._sanitizeForRedisState(data)
  };
  try {
    await executeWithRetry(() => _publisher.set(key, JSON.stringify(state), 'EX', SCAN_STATE_TTL_S));
  } catch (err) {
    // Best-effort only — never block scan flow on Redis state persistence.
    console.warn('[ScanProgress] Failed to persist scan state after retries:', err.message);
  }
}

async function _saveScanStateBeforeEmit(scanId, userId, data) {
  // Guarantee ordering (snapshot-before-emit) without risking a new stall path.
  // If Redis is slow, proceed after a short timeout.
  await Promise.race([
    _saveScanState(scanId, userId, data),
    new Promise((resolve) => setTimeout(resolve, SCAN_STATE_WRITE_TIMEOUT_MS))
  ]);
}

/**
 * Set the Redis publisher client used for cross-process pub/sub.
 * Called once during server/worker startup.
 */
function setPublisher(redisClient) {
  _publisher = redisClient;
}

/**
 * Set a direct in-process emitter (notificationService.emitScanProgress).
 * When set, progress is emitted via Socket.IO directly AND via Redis pub/sub
 * so that any external workers also get the message.
 * Call this from server.js after both Socket.IO and Redis are ready.
 */
function setDirectEmitter(fn) {
  _directEmit = fn;
}

/**
 * Publish a scan progress event.
 * - If a direct emitter is registered (in-process), calls it immediately.
 * - Always publishes to Redis pub/sub so standalone worker processes work too.
 *
 * @param {string} scanId
 * @param {string} userId
 * @param {object} data   - { status, progress, message, ...optional result fields }
 */
async function publishScanProgress(scanId, userId, data) {
  // Persist lightweight scan state for late-joining clients and polling fallbacks.
  // Must happen before emit to satisfy join-replay correctness.
  try {
    await _saveScanStateBeforeEmit(scanId, userId, data);
  } catch (_) {
    // best-effort only
  }

  // Fast path: in-process direct Socket.IO emit.
  // Return immediately — do NOT also publish to Redis. If we published, the server's
  // Redis subscriber would call emitScanProgress a second time and the client would
  // receive every scan:update event twice.
  if (_directEmit) {
    try {
      _directEmit(scanId, String(userId), data);
    } catch (e) {
      console.error('[ScanProgress] Direct emit failed:', e.message);
    }
    return;
  }

  // Cross-process path: standalone worker has no _directEmit, so publish via Redis.
  // The server's subscriber will receive this and forward to Socket.IO.
  if (!_publisher) {
    console.warn('[ScanProgress] No publisher or direct emitter — skipping progress for', scanId);
    return;
  }

  try {
    const payload = JSON.stringify({
      scanId,
      userId: String(userId),
      timestamp: Date.now(),
      ...data
    });
    await executeWithRetry(() => _publisher.publish(CHANNEL, payload));
  } catch (err) {
    console.error('[ScanProgress] Redis publish failed for', scanId, 'after retries:', err.message);
  }
}

module.exports = { CHANNEL, setPublisher, setDirectEmitter, publishScanProgress };
