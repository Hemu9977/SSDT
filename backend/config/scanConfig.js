/**
 * Centralized scan configuration.
 *
 * Every tunable value lives here, read from environment variables with
 * production-safe defaults. Nothing is hardcoded in service files.
 *
 * ECS-recommended production values are documented inline and in .env.example.
 */

function getInt(envVar, defaultValue) {
  const val = parseInt(process.env[envVar], 10);
  return Number.isFinite(val) ? val : defaultValue;
}

function getFloat(envVar, defaultValue) {
  const val = parseFloat(process.env[envVar]);
  return Number.isFinite(val) ? val : defaultValue;
}

function getBool(envVar, defaultValue) {
  const val = process.env[envVar];
  if (val === undefined || val === null || val === '') return defaultValue;
  return val.toLowerCase() !== 'false';
}

const scanConfig = {
  // ── WebCheck container ────────────────────────────────────────────────────
  webcheck: {
    // Internal ECS service name or localhost for dev
    baseUrl: process.env.WEBCHECK_URI || 'http://localhost:3002',
  },

  // ── HTTP client (shared axios instance) ──────────────────────────────────
  http: {
    // Per-request timeout for WebCheck scan calls (ms). Heavy scans (tls, whois)
    // can take 30-60 s; 120 s gives enough room without letting sockets hang forever.
    scanRequestTimeoutMs: getInt('WEBCHECK_REQUEST_TIMEOUT_MS', 120_000),

    // Timeout for lightweight health-check pings (ms)
    healthCheckTimeoutMs: getInt('WEBCHECK_HEALTH_TIMEOUT_MS', 5_000),

    // HTTP keep-alive: reuse sockets instead of opening a new TCP connection per
    // request. Critical for preventing ephemeral port exhaustion on ECS Fargate.
    keepAlive: getBool('HTTP_KEEPALIVE', true),

    // Max open sockets PER HOST in the agent pool.
    // ECS tasks have a limited file-descriptor budget; 10 is plenty for WebCheck.
    maxSockets: getInt('HTTP_MAX_SOCKETS', 10),

    // Max idle (free) sockets kept alive per host
    maxFreeSockets: getInt('HTTP_MAX_FREE_SOCKETS', 5),

    // How long (ms) to keep an idle socket alive before closing it
    keepAliveMsecs: getInt('HTTP_KEEPALIVE_MSECS', 30_000),
  },

  // ── Scan execution ────────────────────────────────────────────────────────
  scan: {
    // Max simultaneous HTTP requests to the WebCheck container at any moment.
    // Raising this speeds up scans but increases socket usage. 5 is the sweet spot
    // for a single WebCheck container without exhausting its connection pool.
    concurrency: getInt('WEBCHECK_CONCURRENCY', 5),

    // Split pools: lightweight scans run first with higher concurrency,
    // heavy scans run after with lower concurrency to prevent overload.
    lightConcurrency: getInt('WEBCHECK_LIGHT_SCAN_CONCURRENCY', getInt('WEBCHECK_CONCURRENCY', 5)),
    heavyConcurrency: getInt('WEBCHECK_HEAVY_SCAN_CONCURRENCY', Math.max(1, Math.floor(getInt('WEBCHECK_CONCURRENCY', 5) / 2))),

    // Global backpressure: cap concurrently running WebCheck analyses within this backend instance.
    // Prevents Promise/HTTP storms when many users trigger scans at once.
    maxActiveScans: getInt('WEBCHECK_MAX_ACTIVE_SCANS', 5),

    // Bounded queue size for analysis scheduling and per-analysis scan pools.
    maxQueueSize: getInt('WEBCHECK_MAX_QUEUE_SIZE', 200),

    // How long a task is allowed to sit queued before we fail fast (ms).
    queueTimeoutMs: getInt('WEBCHECK_QUEUE_TIMEOUT_MS', 300_000),

    // Hard wall-clock limit per individual scan type, including all retry delays (ms).
    // A scan that stalls (tls handshake, whois query) is aborted after this.
    perScanTimeoutMs: getInt('WEBCHECK_PER_SCAN_TIMEOUT_MS', 150_000),

    // Optional: override timeouts for each pool (defaults to perScanTimeoutMs).
    lightPerScanTimeoutMs: getInt('WEBCHECK_LIGHT_PER_SCAN_TIMEOUT_MS', getInt('WEBCHECK_PER_SCAN_TIMEOUT_MS', 150_000)),
    heavyPerScanTimeoutMs: getInt('WEBCHECK_HEAVY_PER_SCAN_TIMEOUT_MS', getInt('WEBCHECK_PER_SCAN_TIMEOUT_MS', 150_000)),

    // Optional: hard cap for the whole WebCheck analysis. If exceeded, aborts remaining scans.
    globalTimeoutMs: getInt('WEBCHECK_GLOBAL_TIMEOUT_MS', 0),

    // Optional: per-user backpressure (default 0 = disabled / unlimited within instance).
    perUserMaxActiveScans: getInt('WEBCHECK_MAX_ACTIVE_SCANS_PER_USER', 0),

    // Memory pressure protection: if heapUsed/heapTotal exceeds this ratio,
    // heavy scan pool is throttled to reduce GC pressure.
    memoryPressureHeapRatio: getFloat('WEBCHECK_MEMORY_PRESSURE_HEAP_RATIO', 0.85),
  },

  // ── Circuit breaker (per scan type) ─────────────────────────────────────
  breaker: {
    // Open the breaker after N failures in the rolling window.
    threshold: getInt('WEBCHECK_CIRCUIT_BREAKER_THRESHOLD', 5),

    // How long to keep the breaker open before allowing a half-open probe (ms).
    resetMs: getInt('WEBCHECK_CIRCUIT_BREAKER_RESET_MS', 60_000),
  },

  // ── Retry policy for WebCheck HTTP calls ─────────────────────────────────
  retry: {
    // Total attempts (first attempt + N retries).
    // 3 = 1 original + 2 retries. Only transient network errors are retried.
    maxAttempts: getInt('WEBCHECK_RETRY_ATTEMPTS', 3),

    // Delay before the first retry (ms)
    initialDelayMs: getInt('WEBCHECK_RETRY_INITIAL_DELAY_MS', 1_000),

    // Cap on retry delay regardless of backoff calculation (ms)
    maxDelayMs: getInt('WEBCHECK_RETRY_MAX_DELAY_MS', 15_000),

    // Exponential multiplier: delay = initialDelayMs * factor^(attempt-1)
    backoffFactor: getFloat('WEBCHECK_RETRY_BACKOFF_FACTOR', 2),

    // ±jitter fraction applied to each delay to spread concurrent retries.
    // 0.3 = ±30 % of the computed delay.
    jitterFactor: getFloat('WEBCHECK_RETRY_JITTER_FACTOR', 0.3),
  },

  // ── Storage thresholds ────────────────────────────────────────────────────
  storage: {
    // Results whose JSON size exceeds this threshold are stored in GridFS
    // rather than inline in MongoDB (16 MB document limit). Default: 10 MB.
    gridfsThresholdBytes: getInt('WEBCHECK_GRIDFS_THRESHOLD_MB', 10) * 1024 * 1024,

    // Wayback Machine archive responses can contain tens of thousands of entries
    // for old domains. Cap them to prevent unbounded result sizes.
    maxArchiveEntries: getInt('WEBCHECK_MAX_ARCHIVE_ENTRIES', 20),

    // TTL for the in-memory GridFS download cache (ms).
    // Prevents redundant GridFS reads for the same scan within this window.
    gridfsCacheTtlMs: getInt('WEBCHECK_GRIDFS_CACHE_TTL_MS', 60_000),
  },

  // ── DNS caching (cacheable-lookup) ───────────────────────────────────────
  dns: {
    // How long (seconds) to cache a successful DNS response in-process.
    // Eliminates repeated Route 53 resolver calls for the same hostname under
    // concurrent scan load. 30 s is short enough to pick up IP changes quickly.
    // ECS Fargate recommended: 30
    cacheTtlSeconds: getInt('DNS_CACHE_TTL_SECONDS', 30),
  },

  // ── BullMQ worker settings ────────────────────────────────────────────────
  worker: {
    // Max simultaneous scan jobs processed by the scan-queue worker
    concurrency: getInt('WORKER_CONCURRENCY', 3),

    // Max simultaneous ZAP jobs processed by the zap-queue worker
    zapConcurrency: getInt('ZAP_WORKER_CONCURRENCY', 3),

    // BullMQ rate limiter: max jobs processed per window (prevents thundering herd)
    rateLimitMax: getInt('WORKER_RATE_LIMIT_MAX', 10),
    rateLimitWindowMs: getInt('WORKER_RATE_LIMIT_WINDOW_MS', 60_000),
  },
};

module.exports = scanConfig;
