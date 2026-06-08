/**
 * WebCheck Scanning Service
 *
 * Production-grade orchestration for the WebCheck container (port 3002).
 * Key reliability features added for ECS Fargate deployment:
 *
 *  1. Controlled concurrency  — createConcurrencyLimiter() replaces the old fixed
 *     batch-of-5 loop; all scan slots share a bounded queue so fast scans never
 *     wait behind slow ones.
 *
 *  2. Retry with backoff+jitter — withRetry() retries transient network errors
 *     (ECONNRESET, socket hang up, DNS hiccup, 5xx) up to WEBCHECK_RETRY_ATTEMPTS
 *     times with exponential backoff and ±jitter to spread retries.
 *
 *  3. Shared HTTP client       — getHttpClient() reuses TCP connections via
 *     keep-alive agents; prevents ephemeral port exhaustion on ECS Fargate.
 *
 *  4. Per-scan AbortController — each scan type gets its own controller so a hung
 *     scan (tls handshake, whois query) is hard-killed after perScanTimeoutMs.
 *     A parent controller on the analysis-level allows full scan cancellation.
 *
 *  5. Structured logging       — every log line includes analysisId, scanType,
 *     error classification, and duration so CloudWatch queries are self-contained.
 *
 *  6. No hardcoded values      — everything comes from scanConfig.js / env vars.
 */

const ScanResult             = require('../models/ScanResult');
const gridfsService          = require('./gridfsService');
const { publishScanProgress } = require('./scanProgressService');
const { getHttpClient }      = require('../utils/httpClient');
const { withRetry }          = require('../utils/retryUtils');
const { classifyError }      = require('../utils/errorClassifier');
const { createConcurrencyLimiter } = require('../utils/concurrencyLimiter');
const { CircuitBreaker }     = require('../utils/circuitBreaker');
const { validateScanResult } = require('../utils/resultValidation');
const config                 = require('../config/scanConfig');

const WEBCHECK_BASE_URL = config.webcheck.baseUrl;
const WEBCHECK_BUCKET   = 'webcheck_results';

// All scan types executed per URL.
// 'screenshot' is omitted — we use urlscan.io's screenshot instead.
const ALLOWED_SCANS = [
  'ssl', 'dns', 'headers', 'cookies', 'firewall', 'ports',
  'tech-stack', 'hsts', 'security-txt', 'block-lists',
  'social-tags', 'linked-pages', 'robots-txt', 'sitemap', 'status',
  'redirects', 'mail-config', 'trace-route', 'http-security', 'get-ip',
  'dns-server', 'dnssec', 'txt-records', 'carbon', 'archives',
  'legacy-rank', 'whois', 'tls', 'quality',
];

// Lightweight scans should finish quickly and provide early value. Heavy scans
// are isolated to a lower-concurrency pool to avoid starving lightweight scans.
const LIGHT_SCANS = [
  'headers', 'cookies', 'redirects', 'dns', 'robots-txt', 'sitemap',
  'tech-stack', 'status',
  'hsts', 'security-txt', 'block-lists', 'social-tags', 'linked-pages',
  'mail-config', 'http-security', 'get-ip', 'dns-server', 'dnssec',
  'txt-records', 'carbon', 'archives',
];

const HEAVY_SCANS = [
  'whois', 'tls', 'ssl', 'ports', 'trace-route', 'firewall', 'quality', 'legacy-rank',
];

// Validate we didn't accidentally omit any scan types.
const _SCAN_SET = new Set([...LIGHT_SCANS, ...HEAVY_SCANS]);
if (_SCAN_SET.size !== ALLOWED_SCANS.length) {
  console.warn('[WebCheck] Scan pool definitions do not cover all scans. Falling back to ALLOWED_SCANS ordering.');
}

// ── Per-scan-type circuit breakers (process-local) ─────────────────────────
const _breakers = new Map();
function getBreaker(scanType) {
  if (!_breakers.has(scanType)) {
    _breakers.set(
      scanType,
      new CircuitBreaker({
        name: `webcheck/${scanType}`,
        threshold: config.breaker.threshold,
        resetMs: config.breaker.resetMs,
        windowMs: config.breaker.resetMs,
      })
    );
  }
  return _breakers.get(scanType);
}

function snapshotMemory() {
  const mu = process.memoryUsage();
  return {
    rssMB: Number((mu.rss / 1048576).toFixed(1)),
    heapUsedMB: Number((mu.heapUsed / 1048576).toFixed(1)),
    heapTotalMB: Number((mu.heapTotal / 1048576).toFixed(1)),
  };
}

function makeWebCheckError(code, message, extra) {
  const err = new Error(message);
  err.code = code;
  if (extra && typeof extra === 'object') Object.assign(err, extra);
  return err;
}

function shouldCountAsBreakerFailure(errType) {
  // Don't open breakers due to client mistakes or intentional aborts.
  return !['aborted', 'invalid_url', 'upstream_4xx'].includes(errType);
}

function validateOrEmptyFailure(scanType, data) {
  const v = validateScanResult(scanType, data);
  if (!v.success) {
    const err = makeWebCheckError('WEBCHECK_EMPTY_RESULT', `${scanType}: empty_result`);
    err.scanType = scanType;
    err.validation = v;
    throw err;
  }
  return v.data;
}

function emptyResultPayload(scanType) {
  return {
    success: false,
    error: 'empty_result',
    scanType,
    timestamp: new Date().toISOString(),
  };
}

// ── In-memory scan registry ───────────────────────────────────────────────────
// Maps analysisId → { url, userId, startTime, completed, total, controller }
// The AbortController stored here is the "parent" cancel signal for the scan.
const activeWebCheckScans = new Map();

// Process-wide scheduler for WebCheck analyses (not individual scan types).
// Prevents starting too many analyses at once (each analysis triggers 29 calls).
const _analysisScheduler = createConcurrencyLimiter({
  concurrency: Math.max(1, config.scan.maxActiveScans || 1),
  maxQueueSize: config.scan.maxQueueSize,
  queueTimeoutMs: config.scan.queueTimeoutMs,
  name: 'webcheck/analysisScheduler',
});

/** How many WebCheck scans are currently in progress (for health endpoint). */
const getActiveScanCount = () => activeWebCheckScans.size;

// ── Simple in-memory metrics counters ────────────────────────────────────────
const _metrics = { started: 0, completed: 0, failed: 0 };
const getMetrics = () => ({ ..._metrics, active: activeWebCheckScans.size });

// ─────────────────────────────────────────────────────────────────────────────
// Core scan runner
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute a single WebCheck scan type with retry logic.
 *
 * @param {string}      scanType    - e.g. 'ssl', 'tls', 'whois'
 * @param {string}      url         - Target URL
 * @param {AbortSignal} [signal]    - Optional AbortSignal for cancellation / timeout
 * @returns {Promise<object>}       - Raw scan data from WebCheck container
 */
const runScan = async (scanType, url, signal) => {
  if (!ALLOWED_SCANS.includes(scanType)) {
    throw new Error(`Invalid scan type: ${scanType}. Allowed: ${ALLOWED_SCANS.join(', ')}`);
  }

  const client = getHttpClient();
  const label  = `WebCheck/${scanType}`;

  const breaker = getBreaker(scanType);
  const breakerCheck = breaker.canRequest();
  if (!breakerCheck.allowed) {
    const err = makeWebCheckError(
      'WEBCHECK_CIRCUIT_OPEN',
      `${scanType}: circuit_open`,
      { retryAfterMs: breakerCheck.retryAfterMs, breakerState: breakerCheck.state }
    );
    throw err;
  }

  return withRetry(
    async (attempt) => {
      // Bail immediately if the parent scan was cancelled
      if (signal?.aborted) {
        const err = new Error(`${scanType} scan aborted`);
        err.code = 'ERR_ABORTED';
        throw err;
      }

      const t0 = Date.now();
      if (attempt > 1) {
        console.log(`[WebCheck] ${label} retry attempt ${attempt}`);
      }

      const response = await client.get(`${WEBCHECK_BASE_URL}/api/${scanType}`, {
        params:  { url },
        timeout: config.http.scanRequestTimeoutMs,
        signal,
      });

      const durationMs = Date.now() - t0;
      const data = validateOrEmptyFailure(scanType, response.data);
      console.log(`[WebCheck] ${label} OK in ${durationMs}ms (attempt ${attempt})`);
      breaker.recordSuccess();
      return data;
    },
    {
      maxAttempts:    config.retry.maxAttempts,
      initialDelayMs: config.retry.initialDelayMs,
      maxDelayMs:     config.retry.maxDelayMs,
      backoffFactor:  config.retry.backoffFactor,
      jitterFactor:   config.retry.jitterFactor,
      label,
    }
  ).catch(err => {
    const { type: errType } = classifyError(err);
    if (shouldCountAsBreakerFailure(errType)) {
      breaker.recordFailure();
    }
    throw err;
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Public helpers
// ─────────────────────────────────────────────────────────────────────────────

const getAvailableScans = () => ALLOWED_SCANS;

/** Check if the WebCheck container is reachable. */
const checkHealth = async () => {
  try {
    const client   = getHttpClient();
    const response = await client.get(`${WEBCHECK_BASE_URL}/health`, {
      timeout: config.http.healthCheckTimeoutMs,
    });
    return response.data?.status === 'healthy';
  } catch (error) {
    const { type } = classifyError(error);
    console.error(`[WebCheck] Health check failed (${type}):`, error.message);
    return false;
  }
};

/**
 * Run ALL scan types in parallel with bounded concurrency.
 * Used by the one-off /api/webcheck/scan route.
 */
const runAllScans = async (url) => {
  console.log(`[WebCheck] runAllScans: ${ALLOWED_SCANS.length} scans, concurrency=${config.scan.concurrency}`);
  const limit = createConcurrencyLimiter({
    concurrency: config.scan.concurrency,
    maxQueueSize: config.scan.maxQueueSize,
    queueTimeoutMs: config.scan.queueTimeoutMs,
    name: 'webcheck/runAllScans',
  });

  const settled = await Promise.allSettled(
    ALLOWED_SCANS.map(scanType =>
      limit(async () => {
        try {
          const data = await runScan(scanType, url);
          return { type: scanType, success: true, data };
        } catch (error) {
          const { type: errType } = classifyError(error);
          return { type: scanType, success: false, error: error.message, errorType: errType };
        }
      })
    )
  );

  const scanResults = {};
  settled.forEach((result, index) => {
    const type = ALLOWED_SCANS[index];
    if (result.status === 'fulfilled' && result.value.success) {
      scanResults[type] = result.value.data;
    } else {
      scanResults[type] = {
        error:     result.reason?.message || result.value?.error || 'Scan failed',
        errorType: result.value?.errorType,
      };
    }
  });

  return scanResults;
};

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight summary extractor (for MongoDB document — GridFS holds full data)
// ─────────────────────────────────────────────────────────────────────────────

const extractWebCheckSummary = (results) => {
  const summary = {};

  if (results.ssl && !results.ssl.error) {
    summary.ssl = {
      valid:    results.ssl.valid,
      issuer:   results.ssl.issuer,
      expires:  results.ssl.expires,
      protocol: results.ssl.protocol,
    };
  }

  if (results.tls && !results.tls.error) {
    summary.tls = {
      grade: results.tls.tlsInfo?.grade || results.tls.grade,
      score: results.tls.tlsInfo?.score || results.tls.score,
    };
  }

  if (results.headers && !results.headers.error) {
    summary.headers = {
      hasHSTS:         !!results.headers['strict-transport-security'],
      hasCSP:          !!results.headers['content-security-policy'],
      hasXFrameOptions: !!results.headers['x-frame-options'],
      hasXContentType:  !!results.headers['x-content-type-options'],
    };
  }

  if (results.hsts && !results.hsts.error) {
    summary.hsts = {
      enabled: results.hsts.enabled || results.hsts.preloaded || false,
      maxAge:  results.hsts.maxAge,
    };
  }

  if (results.firewall && !results.firewall.error) {
    summary.firewall = {
      detected: results.firewall.detected || results.firewall.hasWaf || false,
      name:     results.firewall.name || results.firewall.wafName,
    };
  }

  if (results['tech-stack'] && !results['tech-stack'].error) {
    const techs = results['tech-stack'].technologies || results['tech-stack'];
    summary.techStack = Array.isArray(techs) ? techs.slice(0, 10) : [];
  }

  if (results.dns && !results.dns.error) {
    summary.dns = {
      hasA:    !!results.dns.A?.length,
      hasAAAA: !!results.dns.AAAA?.length,
      hasMX:   !!results.dns.MX?.length,
    };
  }

  if (results.whois && !results.whois.error) {
    summary.whois = {
      registrar:    results.whois.registrar,
      createdDate:  results.whois.createdDate,
      expiresDate:  results.whois.expiresDate,
    };
  }

  if (results.quality && !results.quality.error) {
    summary.quality = {
      score: results.quality.score,
      grade: results.quality.grade,
    };
  }

  summary.errorCount   = Object.values(results).filter(r => r?.error).length;
  summary.successCount = Object.values(results).filter(r => r && !r.error).length;

  return summary;
};

// ─────────────────────────────────────────────────────────────────────────────
// Async scan orchestration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Start WebCheck scans asynchronously (non-blocking, saves results to MongoDB).
 * Idempotent — checks both DB state and in-memory map before launching.
 */
const startAsyncWebCheckScan = async (url, analysisId, userId) => {
  console.log(`[WebCheck] startAsyncWebCheckScan | analysisId=${analysisId} url=${url}`);

  // ── 1. DB check (source of truth, prevents restarts after ECS task replacement) ──
  try {
    const existing = await ScanResult.findOne({ analysisId, userId });

    if (existing && ['stopped', 'completed', 'failed'].includes(existing.status)) {
      console.log(`[WebCheck] Refusing to start — scan ${analysisId} is in terminal state (${existing.status})`);
      return existing.webCheckResult || { status: existing.status };
    }

    if (existing?.webCheckResult?.status === 'running') {
      console.log(`[WebCheck] Already running in DB for ${analysisId}`);
      return {
        status:    'running',
        message:   'WebCheck scan already in progress',
        progress:  existing.webCheckResult.progress || 0,
        analysisId,
      };
    }

    if (['completed', 'completed_with_errors', 'completed_partial'].includes(existing?.webCheckResult?.status)) {
      console.log(`[WebCheck] Already completed in DB for ${analysisId}`);
      return existing.webCheckResult;
    }
  } catch (dbError) {
    console.error(`[WebCheck] DB pre-check failed for ${analysisId}:`, dbError.message);
    // Continue — better to risk a duplicate attempt than silently fail
  }

  // ── 2. In-memory check (same-request race condition guard) ────────────────
  if (activeWebCheckScans.has(analysisId)) {
    console.log(`[WebCheck] Already active in memory for ${analysisId}`);
    return { status: 'running', message: 'WebCheck scan already in progress', analysisId };
  }

  // ── 2b. Global/per-user backpressure (process-local) ─────────────────────
  const maxActive = config.scan.maxActiveScans;
  if (Number.isInteger(maxActive) && maxActive > 0 && activeWebCheckScans.size >= maxActive) {
    const err = makeWebCheckError('WEBCHECK_QUEUE_FULL', 'WebCheck overloaded: too many active scans');
    console.warn(`[WebCheck] Backpressure reject | analysisId=${analysisId} active=${activeWebCheckScans.size} maxActive=${maxActive}`);
    ScanResult.findOneAndUpdate(
      { analysisId, userId },
      {
        $set: {
          'webCheckResult.status': 'failed',
          'webCheckResult.error': err.message,
          'webCheckResult.errorType': 'queue_full',
          'webCheckResult.completedAt': new Date(),
        },
      }
    ).catch(() => {});
    return { status: 'failed', error: err.message, errorType: 'queue_full' };
  }

  const perUserMax = config.scan.perUserMaxActiveScans;
  if (Number.isInteger(perUserMax) && perUserMax > 0) {
    let userActive = 0;
    for (const entry of activeWebCheckScans.values()) {
      if (String(entry.userId) === String(userId)) userActive++;
    }
    if (userActive >= perUserMax) {
      const err = makeWebCheckError('WEBCHECK_QUEUE_FULL', 'WebCheck overloaded: per-user limit reached');
      console.warn(`[WebCheck] Per-user backpressure reject | analysisId=${analysisId} userId=${userId} userActive=${userActive} perUserMax=${perUserMax}`);
      ScanResult.findOneAndUpdate(
        { analysisId, userId },
        {
          $set: {
            'webCheckResult.status': 'failed',
            'webCheckResult.error': err.message,
            'webCheckResult.errorType': 'queue_full',
            'webCheckResult.completedAt': new Date(),
          },
        }
      ).catch(() => {});
      return { status: 'failed', error: err.message, errorType: 'queue_full' };
    }
  }

  // ── 3. Register in memory + create cancel controller ─────────────────────
  const controller = new AbortController();
  activeWebCheckScans.set(analysisId, {
    url,
    userId,
    startTime:  Date.now(),
    completed:  0,
    total:      ALLOWED_SCANS.length,
    controller,
  });

  // ── 4. Atomic DB init (prevents duplicate if two requests race) ───────────
  try {
    const result = await ScanResult.findOneAndUpdate(
      {
        analysisId,
        userId,
        $or: [
          { webCheckResult: null },
          { webCheckResult: { $exists: false } },
          { 'webCheckResult.status': { $exists: false } },
          { 'webCheckResult.status': { $nin: ['running', 'completed', 'completed_with_errors', 'completed_partial'] } },
        ],
      },
      {
        $set: {
          webCheckResult: {
            status:       'running',
            progress:     0,
            completedScans: 0,
            totalScans:   ALLOWED_SCANS.length,
            message:      'Starting WebCheck scans...',
            startedAt:    new Date(),
          },
        },
      },
      { new: true }
    );

    if (!result) {
      // Another concurrent request already won the race
      console.log(`[WebCheck] Concurrent request already initialized scan ${analysisId}`);
      const current = await ScanResult.findOne({ analysisId, userId });
      return current?.webCheckResult || { status: 'running', analysisId };
    }
  } catch (dbError) {
    console.error(`[WebCheck] DB init failed for ${analysisId}:`, dbError.message);
  }

  // ── 5. Launch background scan (fire-and-forget) ───────────────────────────
  _metrics.started++;
  _analysisScheduler(
    async () => {
      const s = _analysisScheduler.stats();
      console.log(`[WebCheck] Analysis scheduled | analysisId=${analysisId} schedulerActive=${s.active} schedulerQueued=${s.queued}`);
      return runWebCheckInBackground(url, analysisId, userId, controller);
    },
    { signal: controller.signal }
  ).catch(err => {
    const { type: errType } = classifyError(err);
    console.error(`[WebCheck] Background scan error | analysisId=${analysisId} errorType=${errType}:`, err.message);
    // Persist failure so polling endpoints don't treat it as success.
    ScanResult.findOneAndUpdate(
      { analysisId, userId },
      { $set: { 'webCheckResult.status': 'failed', 'webCheckResult.error': err.message, 'webCheckResult.errorType': errType, 'webCheckResult.completedAt': new Date(), updatedAt: new Date() } }
    ).catch(() => {});
  });

  return {
    status:     'running',
    message:    'WebCheck scan started in background',
    progress:   0,
    totalScans: ALLOWED_SCANS.length,
    analysisId,
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// Background scan execution
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute all WebCheck scans in the background with controlled concurrency.
 * Saves results progressively to MongoDB and triggers Gemini on completion.
 *
 * @param {string}          url          - Target URL
 * @param {string}          analysisId   - Scan identifier
 * @param {string}          userId       - Owner
 * @param {AbortController} controller   - Controls cancellation for this scan
 */
const runWebCheckInBackground = async (url, analysisId, userId, controller) => {
  const parentSignal = controller.signal;
  const wallStart    = Date.now();

  const globalTimeoutMs = config.scan.globalTimeoutMs;
  let globalTimeoutHandle = null;
  if (Number.isInteger(globalTimeoutMs) && globalTimeoutMs > 0) {
    globalTimeoutHandle = setTimeout(() => {
      console.warn(`[WebCheck] Global timeout exceeded — aborting | analysisId=${analysisId} timeoutMs=${globalTimeoutMs}`);
      controller.abort();
    }, globalTimeoutMs);
  }

  console.log(
    `[WebCheck] Background scan started | analysisId=${analysisId} ` +
    `url=${url} totalScans=${ALLOWED_SCANS.length} concurrency=${config.scan.concurrency}`
  );

  // Shared mutable state — safe because Node.js is single-threaded
  const results  = {};
  let completedCount = 0;
  let hasErrors      = false;

  const recordScanResult = (scanType, scanResult) => {
    completedCount++;

    if (scanResult.success) {
      results[scanType] = scanResult.data;
    } else {
      if (scanResult.errorType === 'empty_result') {
        results[scanType] = emptyResultPayload(scanType);
      } else {
        results[scanType] = { error: scanResult.error, errorType: scanResult.errorType };
      }
      hasErrors = true;
    }

    const progress = Math.round((completedCount / ALLOWED_SCANS.length) * 100);

    ScanResult.findOneAndUpdate(
      { analysisId, userId },
      {
        $set: {
          'webCheckResult.progress':       progress,
          'webCheckResult.completedScans': completedCount,
          'webCheckResult.message':        `Completed ${completedCount}/${ALLOWED_SCANS.length} scans...`,
          'webCheckResult.partialSummary': extractWebCheckSummary(results),
        },
      }
    ).catch(e => console.error(`[WebCheck] Progress DB update failed | analysisId=${analysisId}:`, e.message));

    publishScanProgress(analysisId, userId, {
      status:  'combining',
      progress: Math.round(45 + (progress * 0.25)),
      message: `WebCheck: ${completedCount}/${ALLOWED_SCANS.length} scans complete`,
      webCheckResult: {
        status:         'running',
        progress,
        completedScans: completedCount,
        totalScans:     ALLOWED_SCANS.length,
      },
    }).catch(() => {});
  };

  // Two bounded pools so heavy scans cannot starve lightweight scans.
  const lightLimit = createConcurrencyLimiter({
    concurrency: Math.max(1, config.scan.lightConcurrency),
    maxQueueSize: config.scan.maxQueueSize,
    queueTimeoutMs: config.scan.queueTimeoutMs,
    name: 'webcheck/light',
  });
  const heavyLimit = createConcurrencyLimiter({
    concurrency: Math.max(1, config.scan.heavyConcurrency),
    maxQueueSize: config.scan.maxQueueSize,
    queueTimeoutMs: config.scan.queueTimeoutMs,
    name: 'webcheck/heavy',
  });

  // Memory-aware throttling (best-effort): if heap is under pressure, reduce heavy concurrency.
  const muStart = process.memoryUsage();
  const heapRatio = muStart.heapUsed / Math.max(1, muStart.heapTotal);
  if (heapRatio > config.scan.memoryPressureHeapRatio) {
    heavyLimit.setConcurrency(1);
  }

  function chooseLimiter(scanType) {
    return HEAVY_SCANS.includes(scanType) ? heavyLimit : lightLimit;
  }

  const scanOrder = (_SCAN_SET.size === ALLOWED_SCANS.length)
    ? [...LIGHT_SCANS.filter(s => ALLOWED_SCANS.includes(s)), ...HEAVY_SCANS.filter(s => ALLOWED_SCANS.includes(s))]
    : [...ALLOWED_SCANS];

  // ── Launch lightweight first, then heavy (queued separately) ─────────────
  const scanPromises = scanOrder.map(scanType => {
    const limiter = chooseLimiter(scanType);

    const p = limiter(async () => {
      // ── Pre-flight cancellation check ──────────────────────────────────
      if (parentSignal.aborted) {
        return { type: scanType, success: false, error: 'Scan cancelled', errorType: 'aborted' };
      }

      // ── Per-scan-type AbortController (enforces perScanTimeoutMs) ───────
      const perScanController = new AbortController();
      const poolTimeoutMs = HEAVY_SCANS.includes(scanType) ? config.scan.heavyPerScanTimeoutMs : config.scan.lightPerScanTimeoutMs;
      const timeoutHandle     = setTimeout(
        () => perScanController.abort(),
        poolTimeoutMs
      );

      // Forward parent cancellation to the per-scan controller
      const onParentAbort = () => perScanController.abort();
      parentSignal.addEventListener('abort', onParentAbort, { once: true });

      const t0 = Date.now();
      let scanResult;
      try {
        const data = await runScan(scanType, url, perScanController.signal);
        const durationMs = Date.now() - t0;
        console.log(
          `[WebCheck] ${scanType} OK | durationMs=${durationMs} analysisId=${analysisId} ` +
          `pool=${HEAVY_SCANS.includes(scanType) ? 'heavy' : 'light'} ` +
          `queueDepthLight=${lightLimit.stats().queued} queueDepthHeavy=${heavyLimit.stats().queued} ` +
          `activeLight=${lightLimit.stats().active} activeHeavy=${heavyLimit.stats().active} ` +
          `mem=${JSON.stringify(snapshotMemory())}`
        );
        scanResult = { type: scanType, success: true, data };
      } catch (error) {
        const durationMs = Date.now() - t0;
        const { type: errType, isTransient } = classifyError(error);
        const breakerSnap = getBreaker(scanType).snapshot();
        console.warn(
          `[WebCheck] ${scanType} FAIL | errorType=${errType} ` +
          `isTransient=${isTransient} durationMs=${durationMs} ` +
          `error="${error.message}" analysisId=${analysisId} ` +
          `breakerState=${breakerSnap.state} breakerFailures=${breakerSnap.failureCountWindow} ` +
          `pool=${HEAVY_SCANS.includes(scanType) ? 'heavy' : 'light'} ` +
          `queueDepthLight=${lightLimit.stats().queued} queueDepthHeavy=${heavyLimit.stats().queued} ` +
          `activeLight=${lightLimit.stats().active} activeHeavy=${heavyLimit.stats().active} ` +
          `mem=${JSON.stringify(snapshotMemory())}`
        );
        scanResult = { type: scanType, success: false, error: error.message, errorType: errType };
      } finally {
        clearTimeout(timeoutHandle);
        parentSignal.removeEventListener('abort', onParentAbort);
      }

      // ── Update shared state (single-threaded — no lock needed) ──────────
      recordScanResult(scanType, scanResult);

      return scanResult;
    }, { signal: parentSignal });

    // If enqueue itself fails (queue_full/queue_timeout), we still need to record a result.
    return p.catch((error) => {
      const { type: errType } = classifyError(error);
      console.warn(
        `[WebCheck] ${scanType} ENQUEUE FAIL | errorType=${errType} ` +
        `error="${error.message}" analysisId=${analysisId} ` +
        `pool=${HEAVY_SCANS.includes(scanType) ? 'heavy' : 'light'} ` +
        `queueDepthLight=${lightLimit.stats().queued} queueDepthHeavy=${heavyLimit.stats().queued} ` +
        `activeLight=${lightLimit.stats().active} activeHeavy=${heavyLimit.stats().active} ` +
        `mem=${JSON.stringify(snapshotMemory())}`
      );

      const scanResult = { type: scanType, success: false, error: error.message, errorType: errType };
      recordScanResult(scanType, scanResult);
      return scanResult;
    });
  });

  // Wait for all scans (including queued ones) to finish
  await Promise.allSettled(scanPromises);

  // ── Check if scan was cancelled mid-flight ────────────────────────────────
  if (parentSignal.aborted) {
    console.log(`[WebCheck] Scan cancelled mid-flight | analysisId=${analysisId}`);
    activeWebCheckScans.delete(analysisId);
    if (globalTimeoutHandle) clearTimeout(globalTimeoutHandle);
    return;
  }

  // ── Finalize results ──────────────────────────────────────────────────────
  const wallDurationMs = Date.now() - wallStart;
  const wallDurationS  = (wallDurationMs / 1000).toFixed(1);
  console.log(
    `[WebCheck] All scans complete | analysisId=${analysisId} ` +
    `durationS=${wallDurationS} errors=${hasErrors} completed=${completedCount}`
  );

  if (globalTimeoutHandle) clearTimeout(globalTimeoutHandle);

  // Log per-scan sizes to identify bloat (helps tune WEBCHECK_GRIDFS_THRESHOLD_MB)
  const scanSizes = Object.entries(results)
    .map(([type, data]) => {
      const bytes = Buffer.byteLength(JSON.stringify(data), 'utf-8');
      return { type, bytes, sizeMB: (bytes / 1048576).toFixed(3) };
    })
    .sort((a, b) => b.bytes - a.bytes);

  console.log('[WebCheck] Size breakdown (largest first):');
  scanSizes.forEach((s, i) => console.log(`  ${i + 1}. ${s.type}: ${s.sizeMB}MB`));

  // ── Truncate bloated arrays ───────────────────────────────────────────────
  if (Array.isArray(results.archives) && results.archives.length > config.storage.maxArchiveEntries) {
    const original = results.archives.length;
    results.archives = results.archives.slice(0, config.storage.maxArchiveEntries);
    console.log(`[WebCheck] Truncated archives ${original} → ${config.storage.maxArchiveEntries} entries | analysisId=${analysisId}`);
  }

  // ── Decide storage strategy ───────────────────────────────────────────────
  const resultsJson   = JSON.stringify(results, null, 2);
  const resultsSizeB  = Buffer.byteLength(resultsJson, 'utf-8');
  const resultsSizeMB = (resultsSizeB / 1048576).toFixed(2);
  const summary       = extractWebCheckSummary(results);

  let resultsFileId = null;
  let fullResults   = null;

  if (resultsSizeB > config.storage.gridfsThresholdBytes) {
    console.log(`[WebCheck] Results ${resultsSizeMB}MB > threshold, uploading to GridFS | analysisId=${analysisId}`);

    try {
      await ScanResult.findOneAndUpdate(
        { analysisId, userId },
        {
          $set: {
            'webCheckResult.status':         'uploading',
            'webCheckResult.uploadProgress': 0,
            'webCheckResult.message':        `Uploading ${resultsSizeMB}MB to storage...`,
          },
        }
      );
    } catch (e) {
      console.warn(`[WebCheck] Could not update upload status | analysisId=${analysisId}:`, e.message);
    }

    const onUploadProgress = async ({ percent, uploadedMB, totalMB, elapsed }) => {
      ScanResult.findOneAndUpdate(
        { analysisId, userId },
        {
          $set: {
            'webCheckResult.uploadProgress': percent,
            'webCheckResult.message':        `Uploading: ${uploadedMB}MB / ${totalMB}MB (${percent}%) ${elapsed}s`,
          },
        }
      ).catch(() => {});
    };

    try {
      resultsFileId = await gridfsService.uploadFile(
        resultsJson,
        `webcheck_results_${analysisId}.json`,
        { analysisId, userId, contentType: 'application/json' },
        WEBCHECK_BUCKET,
        600_000,
        onUploadProgress
      );
      console.log(`[WebCheck] GridFS upload complete | fileId=${resultsFileId} analysisId=${analysisId}`);
    } catch (gridfsError) {
      console.error(`[WebCheck] GridFS upload failed | analysisId=${analysisId}:`, gridfsError.message);
      // Fallback: try to save inline (may fail for very large results)
      fullResults = results;
    }
  } else {
    console.log(`[WebCheck] Results ${resultsSizeMB}MB under threshold, saving inline | analysisId=${analysisId}`);
    fullResults = results;
  }

  // ── Persist final state ───────────────────────────────────────────────────
  const finalStatus = hasErrors ? 'completed_with_errors' : 'completed';
  try {
    await ScanResult.findOneAndUpdate(
      { analysisId, userId },
      {
        $set: {
          webCheckResult: {
            status:         finalStatus,
            progress:       100,
            completedScans: ALLOWED_SCANS.length,
            totalScans:     ALLOWED_SCANS.length,
            message:        'WebCheck scan completed',
            summary,
            fullResults,
            resultsFileId,
            hasErrors,
            durationMs:     wallDurationMs,
            duration:       parseFloat(wallDurationS),
            completedAt:    new Date(),
          },
        },
      }
    );
    console.log(`[WebCheck] Results persisted | status=${finalStatus} analysisId=${analysisId}`);
  } catch (dbError) {
    console.error(`[WebCheck] Failed to persist final results | analysisId=${analysisId}:`, dbError.message);
  }

  // ── Cleanup ───────────────────────────────────────────────────────────────
  activeWebCheckScans.delete(analysisId);
  _metrics.completed++;

  // ── Emit completion progress event ────────────────────────────────────────
  publishScanProgress(analysisId, userId, {
    status:   'combining',
    progress: 70,
    message:  'WebCheck complete — waiting for ZAP or generating AI report...',
    webCheckResult: { status: finalStatus, progress: 100 },
  }).catch(() => {});

  // ── Trigger Gemini (checks internally if ZAP is also done) ───────────────
  setImmediate(() => {
    try {
      const { checkAndGenerateGemini } = require('./geminiCompletionService');
      checkAndGenerateGemini(analysisId, String(userId)).catch(e =>
        console.error(`[WebCheck] checkAndGenerateGemini error | analysisId=${analysisId}:`, e.message)
      );
    } catch (e) {
      console.error(`[WebCheck] Failed to load geminiCompletionService | analysisId=${analysisId}:`, e.message);
    }
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Scan control
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cancel an active WebCheck scan.
 * Aborts the AbortController so all in-flight HTTP requests and queued scans
 * see the signal and stop immediately.
 */
const stopWebCheckScan = (analysisId) => {
  const entry = activeWebCheckScans.get(analysisId);
  if (entry) {
    console.log(`[WebCheck] Stopping scan | analysisId=${analysisId}`);
    entry.controller.abort();
    activeWebCheckScans.delete(analysisId);
    _metrics.failed++;
    return true;
  }
  return false;
};

/** @returns {object|null} In-memory entry for a running scan, or null */
const getActiveScanStatus = (analysisId) => activeWebCheckScans.get(analysisId) || null;

// ─────────────────────────────────────────────────────────────────────────────
// GridFS result retrieval (with in-memory cache)
// ─────────────────────────────────────────────────────────────────────────────

const _gridfsCache = new Map();

/**
 * Retrieve full WebCheck results.
 * Checks inline fullResults first, then an in-memory cache, then GridFS.
 */
const getFullResults = async (webCheckResult) => {
  if (!webCheckResult) return null;

  if (webCheckResult.fullResults) {
    return webCheckResult.fullResults;
  }

  if (!webCheckResult.resultsFileId) return null;

  const fileId = webCheckResult.resultsFileId.toString();
  const ttl    = config.storage.gridfsCacheTtlMs;

  const cached = _gridfsCache.get(fileId);
  if (cached && (Date.now() - cached.ts < ttl)) {
    console.log(`[WebCheck] GridFS cache HIT | fileId=${fileId}`);
    return cached.data;
  }

  console.log(`[WebCheck] Fetching from GridFS | fileId=${fileId}`);
  try {
    const buffer  = await gridfsService.downloadFile(webCheckResult.resultsFileId, WEBCHECK_BUCKET);
    const results = JSON.parse(buffer.toString('utf-8'));

    _gridfsCache.set(fileId, { data: results, ts: Date.now() });

    // Evict expired entries to cap memory usage
    if (_gridfsCache.size > 10) {
      const now = Date.now();
      for (const [k, v] of _gridfsCache) {
        if (now - v.ts > ttl) _gridfsCache.delete(k);
      }
    }

    return results;
  } catch (error) {
    console.error(`[WebCheck] GridFS download failed | fileId=${fileId}:`, error.message);
    return null;
  }
};

// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  runScan,
  runAllScans,
  getAvailableScans,
  checkHealth,
  startAsyncWebCheckScan,
  stopWebCheckScan,
  getActiveScanStatus,
  getActiveScanCount,
  getMetrics,
  getFullResults,
  extractWebCheckSummary,
  ALLOWED_SCANS,
};
