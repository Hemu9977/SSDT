/**
 * backend/services/systemHealth.js
 *
 * Runs the checks behind GET /api/admin/system-health, one per service in
 * config/healthInventory.js (statuses are defined there).
 *
 * Rules every check follows:
 *   - Read-only. Nothing here creates, updates or deletes customer data,
 *     billing state or infrastructure: Mongo `ping` and counts, Redis PING and
 *     BullMQ counts, HTTP GETs, Stripe `prices.retrieve`, and AWS Describe and
 *     Get calls only.
 *   - No paid quota: no scan, no Lighthouse run, no model call, no email.
 *   - Bounded: each check has its own timeout (inventory `timeoutMs`); a check
 *     that overruns reports its `onTimeout` status instead of holding the request.
 *   - Independent: checks run concurrently and one failing never hides another.
 *   - Sanitized: failures become a fixed `reason` code. Raw error text, stack
 *     traces, hostnames, connection strings, keys and job payloads stay in the
 *     server log and never reach the response.
 *   - Fixed resources: every AWS resource comes from server configuration. The
 *     caller can choose which inventory service to re-check, nothing else.
 *
 * Results are kept for CACHE_TTL_MS so several admins (or tabs) do not multiply
 * calls to Stripe, urlscan and AWS; each result carries its own `checkedAt`, so
 * the page always shows how fresh it is.
 */

const { INVENTORY, getService, SERVICE_IDS } = require('../config/healthInventory');

const CACHE_TTL_MS = 10_000;
const FORCE_MIN_INTERVAL_MS = 3_000; // a per-service retry re-runs at most this often
const REFRESH_INTERVAL_SEC = 60;     // what the page should auto-refresh at

// ─── Dependencies (lazy; tests replace them with setDependencies) ────────────

const defaultDeps = () => ({
  env: process.env,
  now: () => Date.now(),
  mongoose: () => require('mongoose'),
  getPublisher: () => require('../config/redis').getPublisher(),
  getScanQueue: () => require('../queues/scanQueue').getScanQueue(),
  getZapQueue: () => require('../queues/zapQueue').getZapQueue(),
  http: () => require('axios'),
  webCheckBaseUrl: () => require('../config/scanConfig').webcheck.baseUrl,
  zapInstance: (key) => require('../config/zapInstances').getInstance(key),
  zapCapacity: () => require('./zapCapacityManager'),
  gemini: () => require('./geminiService'),
  signals: () => require('./healthSignals'),
  stripe: () => require('../config/stripe'),
  ScanResult: () => require('../models/ScanResult'),
  StripeEvent: () => require('../models/StripeEvent'),
  aws: awsClients,
  taskMetadata: fetchTaskMetadata,
});

let deps = defaultDeps();

// ─── Helpers ─────────────────────────────────────────────────────────────────

const withTimeout = (promise, ms) => {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(`timed out after ${ms}ms`), { timedOut: true })), ms);
    }),
  ]).finally(() => clearTimeout(timer));
};

const log = (id, reason, err) =>
  console.warn(`⚠️ [system-health] ${id}: ${reason}${err && err.message ? ` (${err.message})` : ''}`);

const NET_UNREACHABLE = ['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ECONNRESET', 'ENETUNREACH', 'EPIPE'];

/** Reason code for a failed request to a service we probe directly. */
function netReason(err) {
  if (!err) return 'check_failed';
  if (err.timedOut || err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') return 'timeout';
  if (NET_UNREACHABLE.includes(err.code)) return 'unreachable';
  if (err.response) return 'http_error';
  return 'check_failed';
}

/**
 * Reason code for a failed AWS call. These are failures of the *monitoring*
 * call, not of the resource, so callers report them as `unknown`.
 */
function awsReason(err) {
  if (!err) return 'aws_error';
  if (err.timedOut || err.name === 'TimeoutError') return 'timeout';
  const name = err.name || err.Code || err.code || '';
  // Credential errors first: AWS answers an invalid or expired key with HTTP 403
  // too (verified against the real APIs), and that is not a missing permission.
  if (/CredentialsProviderError|ExpiredToken|InvalidClientTokenId|UnrecognizedClient|InvalidSignature|SignatureDoesNotMatch|InvalidAccessKeyId/i.test(name)) return 'credentials';
  if (/AccessDenied|UnauthorizedOperation|NotAuthorized|Forbidden/i.test(name) || err.$metadata?.httpStatusCode === 403) {
    return 'permission_denied';
  }
  if (/Throttl|TooManyRequests|RequestLimitExceeded/i.test(name)) return 'rate_limited';
  if (/NotFound|ClusterNotFound|ServiceNotFound|TargetGroupNotFound|InvalidParameter|ValidationError/i.test(name)) return 'misconfigured';
  if (/Region is missing/i.test(err.message || '')) return 'not_configured';
  if (NET_UNREACHABLE.includes(err.code)) return 'aws_unreachable';
  return 'aws_error';
}

/**
 * Google API errors (PageSpeed via axios, Gemini via @google/genai), classified
 * from the machine-readable fields Google returns — shapes observed against the
 * real APIs: an invalid key is 400 with ErrorInfo reason API_KEY_INVALID, a
 * disabled API is 403 SERVICE_DISABLED, quota is 429.
 * @returns {{status: string, reason: string}}
 */
function googleError(httpStatus, body, { notFound = 'http_error' } = {}) {
  const e = (body && body.error) || {};
  const reasons = [
    ...(e.errors || []).map((x) => x && x.reason),
    ...(e.details || []).map((d) => d && d.reason),
  ].filter(Boolean);
  const has = (...r) => r.some((x) => reasons.includes(x));
  if (httpStatus === 401 || has('API_KEY_INVALID', 'API_KEY_EXPIRED')) return { status: 'unavailable', reason: 'auth_failed' };
  if (has('SERVICE_DISABLED', 'accessNotConfigured')) return { status: 'unavailable', reason: 'api_disabled' };
  if (httpStatus === 403) return { status: 'unavailable', reason: 'permission_denied' };
  if (httpStatus === 404) return { status: 'unavailable', reason: notFound };
  if (httpStatus === 429) {
    return { status: 'degraded', reason: /per day/i.test(e.message || '') ? 'quota_exhausted' : 'rate_limited' };
  }
  return { status: 'unavailable', reason: 'http_error' };
}

/** A thrown error from a Google client: HTTP answer, credential problem or network. */
function googleThrown(err, opts) {
  if (!err) return { status: 'unavailable', reason: 'check_failed' };
  // @google/genai ApiError: HTTP status, Google's error JSON in the message.
  if (err.name === 'ApiError' && Number.isFinite(err.status)) {
    let body = null;
    try { body = JSON.parse(err.message); } catch (_) { body = null; }
    return googleError(err.status, body, opts);
  }
  if (err.timedOut || err.name === 'AbortError' || /aborted|timed? ?out/i.test(err.message || '')) {
    return { status: 'unavailable', reason: 'timeout' };
  }
  // Credential source missing or unreadable (e.g. the WIF config file), or the
  // AWS credentials the WIF exchange starts from.
  if (err.code === 'ENOENT' || /default credentials|credential|\[WIF\]/i.test(err.message || '')) {
    return { status: 'unavailable', reason: 'credentials' };
  }
  // Token exchange refused by Google STS / IAM credentials (gaxios error).
  if (err.response && Number.isFinite(err.response.status)) {
    return [400, 401, 403].includes(err.response.status)
      ? { status: 'unavailable', reason: 'auth_failed' }
      : { status: 'unavailable', reason: 'http_error' };
  }
  // fetch-based clients (genai) wrap the socket error: TypeError('fetch failed', { cause }).
  const reason = netReason(err.cause && err.cause.code ? err.cause : err);
  return { status: 'unavailable', reason: reason === 'check_failed' ? 'unreachable' : reason };
}

/** Never report a key or connection string even if one ends up in a value. */
const SECRET_PATTERN = /(sk|rk|pk|whsec)_(live|test)_|mongodb(\+srv)?:\/\/|rediss?:\/\/|AKIA[0-9A-Z]{12,}|-----BEGIN|apikey=|password/i;

function cleanValue(v, depth) {
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string') return v.length <= 120 && !SECRET_PATTERN.test(v) ? v : undefined;
  if (depth >= 3) return undefined;
  if (Array.isArray(v)) return v.slice(0, 20).map((x) => cleanValue(x, depth + 1)).filter((x) => x !== undefined);
  if (typeof v === 'object') {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      const c = cleanValue(x, depth + 1);
      if (c !== undefined) out[k] = c;
    }
    return out;
  }
  return undefined;
}

// Fixed vocabularies. Anything else a check returns is replaced, so a coding
// mistake cannot turn an error message into a "reason".
const REASONS = new Set([
  'timeout', 'unreachable', 'http_error', 'auth_failed', 'permission_denied', 'credentials',
  'not_configured', 'misconfigured', 'disconnected', 'not_connected', 'slow', 'event_loop_lag',
  'memory_pressure', 'queue_backlog', 'no_workers', 'capacity_check_failed', 'no_recent_activity',
  'recent_failures', 'quota_exhausted', 'rate_limited', 'test_mode_in_production', 'price_inactive',
  'webhook_failures', 'sending_paused', 'quota_nearly_used', 'no_running_tasks', 'tasks_below_desired',
  'deployment_failed', 'no_healthy_targets', 'targets_unhealthy', 'no_targets', 'http_5xx',
  'partial_check', 'alarm', 'no_alarms', 'aws_error', 'aws_unreachable', 'check_failed',
  'api_disabled', 'model_unavailable',
]);
const NOTES = new Set([
  'failed_jobs', 'small_sample', 'last_report_fallback', 'deployment_in_progress', 'backend_alarms_missing',
  'possible_sandbox', 'not_on_ecs', 'insufficient_data_alarms', 'smtp_not_verified', 'no_recent_activity',
  'since_task_start', 'cold_start',
]);
const STATUS_SET = new Set(['healthy', 'degraded', 'unavailable', 'starting', 'idle', 'configured', 'unknown']);

// ─── Checks ──────────────────────────────────────────────────────────────────
// Each returns { status, reason?, latencyMs?, metrics?, notes? }.

// Event-loop delay is sampled continuously; each api check reads and resets it,
// so the figure covers the time since the previous check.
let loopMonitor = null;
let loopWindowStart = Date.now();
function eventLoop() {
  if (!loopMonitor) {
    const { monitorEventLoopDelay } = require('perf_hooks');
    loopMonitor = monitorEventLoopDelay({ resolution: 20 });
    loopMonitor.enable();
    loopWindowStart = Date.now();
  }
  return loopMonitor;
}
eventLoop();

/** ECS task metadata endpoint v4 (link-local, no IAM). Cached once it answers. */
let taskMetaCache = null;
async function fetchTaskMetadata(env) {
  if (taskMetaCache) return taskMetaCache;
  const base = env.ECS_CONTAINER_METADATA_URI_V4;
  if (!base) return null;
  const resp = await require('axios').get(`${base}/task`, { timeout: 1000 });
  const d = resp.data || {};
  // Image without the registry host (which holds the account id), e.g.
  // "fortexa-backend:v58" or "fortexa-backend@sha256:0d5a9e1c98ad".
  const rawImage = (d.Containers || []).find((c) => c.Name === 'backend')?.Image
    || (d.Containers || [])[0]?.Image || '';
  const repo = rawImage.split('/').pop() || '';
  const image = repo.includes('@sha256:') ? repo.replace(/@sha256:([0-9a-f]{12})[0-9a-f]*/, '@sha256:$1') : repo;
  taskMetaCache = {
    taskDefinition: d.Family && d.Revision ? `${d.Family}:${d.Revision}` : null,
    image: image || null,
  };
  return taskMetaCache;
}

async function checkApi(svc) {
  const v8 = require('v8');
  const mem = process.memoryUsage();
  const heapLimit = v8.getHeapStatistics().heap_size_limit;
  const monitor = eventLoop();
  const p99Ms = Math.round(monitor.percentile(99) / 1e6);
  const windowSec = Math.round((Date.now() - loopWindowStart) / 1000);
  monitor.reset();
  loopWindowStart = Date.now();

  let meta = null;
  const notes = [];
  try {
    meta = await withTimeout(deps.taskMetadata(deps.env), 1000);
  } catch (err) {
    log('api', 'task metadata unavailable', err);
  }
  if (!deps.env.ECS_CONTAINER_METADATA_URI_V4) notes.push('not_on_ecs');

  const gitSha = /^[0-9a-f]{7,40}$/i.test(deps.env.GIT_SHA || '') ? deps.env.GIT_SHA.slice(0, 12) : null;
  const heapUsedRatio = heapLimit ? mem.heapUsed / heapLimit : null;
  const metrics = {
    uptimeSec: Math.floor(process.uptime()),
    heapUsedMB: Math.round(mem.heapUsed / 1048576),
    heapLimitMB: Math.round(heapLimit / 1048576),
    rssMB: Math.round(mem.rss / 1048576),
    eventLoopP99Ms: p99Ms,
    eventLoopWindowSec: windowSec,
    nodeVersion: process.version,
    taskDefinition: meta ? meta.taskDefinition : null,
    image: meta ? meta.image : null,
    gitSha,
  };
  let status = 'healthy';
  let reason;
  if (p99Ms > svc.thresholds.eventLoopP99Ms) { status = 'degraded'; reason = 'event_loop_lag'; }
  if (heapUsedRatio !== null && heapUsedRatio > svc.thresholds.heapUsedRatio) { status = 'degraded'; reason = 'memory_pressure'; }
  return { status, reason, metrics, notes };
}

const MONGO_STATES = ['disconnected', 'connected', 'connecting', 'disconnecting'];

async function checkMongo(svc) {
  const conn = deps.mongoose().connection;
  const connectionState = MONGO_STATES[conn.readyState] || 'unknown';
  if (conn.readyState !== 1) {
    return { status: 'unavailable', reason: 'disconnected', metrics: { connectionState } };
  }
  const start = deps.now();
  try {
    await conn.db.admin().command({ ping: 1 });
  } catch (err) {
    const reason = err.timedOut ? 'timeout' : (/auth/i.test(err.codeName || err.message || '') ? 'auth_failed' : 'unreachable');
    log('mongodb', reason, err);
    return { status: 'unavailable', reason, metrics: { connectionState } };
  }
  const latencyMs = deps.now() - start;
  const slow = latencyMs > svc.thresholds.degradedLatencyMs;
  return { status: slow ? 'degraded' : 'healthy', reason: slow ? 'slow' : undefined, latencyMs, metrics: { connectionState } };
}

async function checkRedis(svc) {
  if (!deps.env.REDIS_URL) return { status: 'unavailable', reason: 'not_configured' };
  let pub;
  try {
    pub = deps.getPublisher();
  } catch (err) {
    log('redis', 'no publisher', err);
    return { status: 'unavailable', reason: 'not_connected' };
  }
  if (!pub || pub.status !== 'ready') {
    return { status: 'unavailable', reason: 'not_connected', metrics: { connectionState: (pub && pub.status) || null } };
  }
  const start = deps.now();
  try {
    await pub.ping();
  } catch (err) {
    log('redis', 'ping failed', err);
    return { status: 'unavailable', reason: netReason(err) === 'check_failed' ? 'unreachable' : netReason(err) };
  }
  const latencyMs = deps.now() - start;
  const slow = latencyMs > svc.thresholds.degradedLatencyMs;
  return { status: slow ? 'degraded' : 'healthy', reason: slow ? 'slow' : undefined, latencyMs, metrics: { connectionState: 'ready' } };
}

async function queueSnapshot(queue, now) {
  const counts = await queue.getJobCounts('waiting', 'active', 'delayed', 'failed', 'completed');
  let oldestWaitingSec = null;
  if (counts.waiting > 0) {
    // Oldest first; only the timestamp is read, the payload goes nowhere.
    const [oldest] = await queue.getJobs(['waiting'], 0, 0, true);
    if (oldest && oldest.timestamp) oldestWaitingSec = Math.max(0, Math.round((now - oldest.timestamp) / 1000));
  }
  return {
    waiting: counts.waiting || 0,
    active: counts.active || 0,
    delayed: counts.delayed || 0,
    failed: counts.failed || 0,
    completed: counts.completed || 0,
    oldestWaitingSec,
  };
}

async function checkQueues(svc) {
  if (!deps.env.REDIS_URL) return { status: 'unavailable', reason: 'not_configured' };
  const now = deps.now();
  const getters = { scan: deps.getScanQueue, zap: deps.getZapQueue };
  const names = Object.keys(getters);
  const settled = await Promise.allSettled(names.map(async (name) => {
    const queue = getters[name]();
    if (!queue) throw Object.assign(new Error('queue not initialised'), { code: 'NO_QUEUE' });
    return queueSnapshot(queue, now);
  }));

  const queues = {};
  const signals = deps.signals();
  const notes = [];
  let status = 'idle';
  let reason;
  const worse = (s, r) => {
    const rank = { idle: 0, healthy: 1, degraded: 2, unavailable: 3 };
    if (rank[s] > rank[status]) { status = s; reason = r; }
  };

  settled.forEach((r, i) => {
    const name = names[i];
    const worker = signals.workerRunning(name);
    if (r.status === 'rejected') {
      log('queues', `${name} queue unreadable`, r.reason);
      queues[name] = { reachable: false, workerRunning: worker };
      worse('unavailable', r.reason && r.reason.timedOut ? 'timeout' : 'unreachable');
      return;
    }
    const q = { reachable: true, ...r.value, workerRunning: worker };
    queues[name] = q;
    if (q.failed > 0 && !notes.includes('failed_jobs')) notes.push('failed_jobs');
    const pending = q.waiting + q.active + q.delayed;
    if (pending > 0) worse('healthy');
    // A worker that this task started has stopped, with work waiting for it.
    // (Null = no worker here, e.g. a separate worker service; not judged.)
    if (q.waiting > 0 && worker === false) worse('degraded', 'no_workers');
    const limit = svc.thresholds.oldestWaitingSec[name];
    if (q.oldestWaitingSec !== null && q.oldestWaitingSec > limit) worse('degraded', 'queue_backlog');
  });

  return { status, reason, metrics: { queues }, notes };
}

async function checkWebCheck(svc) {
  const base = deps.webCheckBaseUrl();
  const start = deps.now();
  try {
    const resp = await deps.http().get(`${base}/health`, { timeout: svc.timeoutMs - 500 });
    const latencyMs = deps.now() - start;
    if (resp.data?.status !== 'healthy') return { status: 'degraded', reason: 'http_error', latencyMs };
    const slow = latencyMs > svc.thresholds.degradedLatencyMs;
    return { status: slow ? 'degraded' : 'healthy', reason: slow ? 'slow' : undefined, latencyMs };
  } catch (err) {
    const reason = netReason(err);
    log('webcheck', reason, err);
    return { status: 'unavailable', reason: reason === 'check_failed' ? 'unreachable' : reason };
  }
}

/** The capacity manager's own state in Redis ('scaling_up' during a cold start). */
async function capacityState(inst) {
  try {
    const pub = deps.getPublisher();
    if (!pub || pub.status !== 'ready') return null;
    const raw = await withTimeout(pub.get(inst.capacityStateKey), 1000);
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed.state === 'string' ? parsed.state : null;
  } catch (_) {
    return null;
  }
}

// ZAP instances are scaled to zero when idle (services/zapCapacityManager.js),
// so "the API does not answer" is only a fault when ECS says a task should be up.
async function checkZap(key, svc) {
  const inst = deps.zapInstance(key);
  const start = deps.now();
  let apiErr = null;
  try {
    // Same request config as the scan path (the auth instance is Host-header
    // sensitive), so "healthy" means a scan could actually reach it.
    const resp = await deps.http().get(`${inst.baseUrl()}/JSON/core/view/version/`, {
      timeout: 3000,
      ...inst.probeConfig(),
    });
    if (resp.data?.version) {
      return { status: 'healthy', latencyMs: deps.now() - start, metrics: { version: String(resp.data.version).slice(0, 20) } };
    }
    apiErr = Object.assign(new Error('no version in response'), { response: { status: resp.status } });
  } catch (err) {
    apiErr = err;
  }

  const capacity = deps.zapCapacity();
  if (!capacity.isManagedKey(key)) {
    const reason = netReason(apiErr);
    log(svc.id, reason, apiErr);
    return { status: 'unavailable', reason: reason === 'check_failed' ? 'unreachable' : reason };
  }

  let cap;
  try {
    cap = await withTimeout(capacity.describeCapacity(key), 2500);
  } catch (err) {
    // The API is down and we cannot tell whether that is by design.
    log(svc.id, 'capacity unknown', err);
    return { status: 'unknown', reason: 'capacity_check_failed' };
  }
  const metrics = { desiredCount: cap.desiredCount, runningCount: cap.runningCount, pendingCount: cap.pendingCount };
  if (cap.desiredCount === 0 && cap.runningCount === 0) return { status: 'idle', metrics };
  if (cap.pendingCount > 0 || cap.runningCount < cap.desiredCount) return { status: 'starting', metrics };
  // A task is running but its API is not answering yet: ZAP's JVM boots for a
  // minute or two after ECS marks the task RUNNING.
  if ((await capacityState(inst)) === 'scaling_up') return { status: 'starting', metrics, notes: ['cold_start'] };
  const reason = netReason(apiErr);
  log(svc.id, reason, apiErr);
  return { status: 'unavailable', reason: reason === 'check_failed' ? 'unreachable' : reason, metrics };
}

async function checkGemini(svc) {
  const gemini = deps.gemini();
  const mode = typeof gemini.GEMINI_AUTH_MODE === 'function' ? gemini.GEMINI_AUTH_MODE() : null;
  const authMode = mode === 'AI_STUDIO' ? 'api_key' : mode ? 'vertex' : null;
  if (!authMode) return { status: 'unavailable', reason: 'not_configured' };

  const reports = deps.signals().getOutcome('gemini_report');
  const metrics = {
    authMode,
    reportsSinceStart: { generated: reports.ok, fallback: reports.failed },
    lastFallbackAt: reports.lastFailureAt,
    since: reports.since,
  };
  const notes = ['since_task_start'];

  // countTokens on each model the scans use (geminiService.probeModelAccess):
  // non-generative and not billed, but needs the same auth, project, API, IAM
  // permission and regional model availability as a real report.
  const start = deps.now();
  let probe;
  try {
    probe = await gemini.probeModelAccess({ timeoutMs: svc.timeoutMs - 1000 });
  } catch (err) {
    const out = googleThrown(err, { notFound: 'model_unavailable' });
    log('gemini', out.reason, err);
    return { ...out, metrics, notes };
  }
  const latencyMs = deps.now() - start;
  metrics.location = probe.location || null;
  const verdicts = probe.models.map((m) => {
    if (m.ok) return null;
    const out = googleThrown(m.error, { notFound: 'model_unavailable' });
    log('gemini', `${m.model}: ${out.reason}`, m.error);
    return out;
  });
  metrics.models = probe.models.map((m, i) => ({
    model: String(m.model).slice(0, 60), ok: Boolean(m.ok), reason: verdicts[i] ? verdicts[i].reason : null,
  }));
  const failed = verdicts.filter(Boolean);
  if (failed.length === metrics.models.length) {
    // Nothing reachable. Throttling (429) is still "degraded": Vertex answered.
    const worst = failed.find((v) => v.status === 'unavailable') || failed[0];
    return { status: worst.status, reason: worst.reason, latencyMs, metrics, notes };
  }
  // One model reachable: reports still work through the fallback, but not as configured.
  if (failed.length) return { status: 'degraded', reason: failed[0].reason, latencyMs, metrics, notes };

  const recent = reports.recentOk + reports.recentFailed;
  if (recent >= svc.thresholds.minSamples && reports.recentFailed / recent >= svc.thresholds.failureRatio) {
    return { status: 'degraded', reason: 'recent_failures', latencyMs, metrics, notes };
  }
  if (reports.lastOutcome === 'failed') notes.push('last_report_fallback');
  return { status: 'healthy', latencyMs, metrics, notes };
}

/** Successes/failures of one scanner in customer scans over the window. */
async function recentOutcomes(field, windowHours) {
  const ScanResult = deps.ScanResult();
  const since = new Date(deps.now() - windowHours * 3600_000);
  const [ok, failed] = await Promise.all([
    ScanResult.countDocuments({ createdAt: { $gte: since }, [field]: { $ne: null }, [`${field}.error`]: { $exists: false } }),
    ScanResult.countDocuments({ createdAt: { $gte: since }, [`${field}.error`]: { $exists: true } }),
  ]);
  return { ok, failed, windowHours };
}

/**
 * Judge recent outcomes. Never `unavailable`: a failure can be specific to the
 * site that was scanned, so this indirect signal only ever degrades.
 */
function judgeRecent(recent, svc) {
  const total = recent.ok + recent.failed;
  if (total === 0) return null;
  const notes = total < svc.thresholds.minSamples ? ['small_sample'] : [];
  if (recent.failed / total >= svc.thresholds.failureRatio) return { status: 'degraded', reason: 'recent_failures', notes };
  return { status: 'healthy', notes };
}

async function checkRecentScanner(field, svc, { keyEnv } = {}) {
  if (keyEnv && !deps.env[keyEnv]) return { status: 'unavailable', reason: 'not_configured' };
  const recent = await recentOutcomes(field, svc.thresholds.windowHours);
  const metrics = { recentScans: recent };
  const judged = judgeRecent(recent, svc);
  if (!judged) {
    // Configured but not exercised in the window: nothing to judge.
    return keyEnv
      ? { status: 'configured', metrics, notes: ['no_recent_activity'] }
      : { status: 'unknown', reason: 'no_recent_activity', metrics };
  }
  return { ...judged, metrics };
}

const PSI_URL = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed';
// Deliberately not a URL. Google checks the key and API access first and then
// rejects the parameter — 400 INVALID_ARGUMENT / INVALID_PARAMETER in ~0.5 s
// (verified against the real API) — so nothing is fetched and no Lighthouse run
// happens. It is one query against the key's daily quota (default 25,000).
const PSI_PROBE_TARGET = 'not-a-url';

async function checkPagespeed(svc) {
  const key = deps.env.PSI_API_KEY;
  if (!key) return { status: 'unavailable', reason: 'not_configured' };

  const [probeRes, recentRes] = await Promise.allSettled([
    (async () => {
      const start = deps.now();
      const resp = await deps.http().get(PSI_URL, {
        params: { url: PSI_PROBE_TARGET, key },
        timeout: svc.timeoutMs - 500,
        validateStatus: () => true,
      });
      return { resp, latencyMs: deps.now() - start };
    })(),
    recentOutcomes('pagespeedResult', svc.thresholds.windowHours),
  ]);

  const metrics = {};
  if (recentRes.status === 'fulfilled') metrics.recentScans = recentRes.value;
  if (probeRes.status === 'rejected') {
    // Only the axios message is logged: it never contains the request URL (and key).
    const reason = netReason(probeRes.reason);
    log('pagespeed', reason, probeRes.reason);
    return { status: 'unavailable', reason: reason === 'check_failed' ? 'unreachable' : reason, metrics };
  }
  const { resp, latencyMs } = probeRes.value;
  metrics.httpStatus = resp.status;
  const body = resp.data && typeof resp.data === 'object' ? resp.data : null;
  const reasons = ((body && body.error && body.error.details) || []).map((d) => d && d.reason)
    .concat(((body && body.error && body.error.errors) || []).map((x) => x && x.reason));
  // The expected answer: key accepted, API enabled, the bogus URL rejected.
  const accepted = resp.status === 200
    || (resp.status === 400 && reasons.includes('INVALID_PARAMETER') && !reasons.includes('API_KEY_INVALID'));
  if (!accepted) {
    const out = googleError(resp.status, body);
    log('pagespeed', `${out.reason} (HTTP ${resp.status})`);
    return { ...out, latencyMs, metrics };
  }
  const judged = recentRes.status === 'fulfilled' ? judgeRecent(recentRes.value, svc) : null;
  if (judged && judged.status === 'degraded') return { ...judged, latencyMs, metrics };
  return { status: 'healthy', latencyMs, metrics, notes: judged ? judged.notes : [] };
}

const URLSCAN_QUOTA_URL = 'https://urlscan.io/user/quotas/';

async function checkUrlscan(svc) {
  const key = deps.env.URLSCAN_API_KEY;
  if (!key) return { status: 'unavailable', reason: 'not_configured' };

  const [quotaRes, recentRes] = await Promise.allSettled([
    (async () => {
      const start = deps.now();
      const resp = await deps.http().get(URLSCAN_QUOTA_URL, {
        headers: { 'API-Key': key },
        timeout: svc.timeoutMs - 500,
        validateStatus: () => true,
      });
      return { resp, latencyMs: deps.now() - start };
    })(),
    recentOutcomes('urlscanResult', svc.thresholds.windowHours),
  ]);

  const metrics = {};
  if (recentRes.status === 'fulfilled') metrics.recentScans = recentRes.value;

  if (quotaRes.status === 'rejected') {
    const reason = netReason(quotaRes.reason);
    log('urlscan', reason, quotaRes.reason);
    return { status: 'unavailable', reason: reason === 'check_failed' ? 'unreachable' : reason, metrics };
  }
  const { resp, latencyMs } = quotaRes.value;
  metrics.httpStatus = resp.status;
  if (resp.status === 401 || resp.status === 403) return { status: 'unavailable', reason: 'auth_failed', latencyMs, metrics };
  if (resp.status === 429) return { status: 'degraded', reason: 'rate_limited', latencyMs, metrics };
  if (resp.status !== 200) return { status: 'unavailable', reason: 'http_error', latencyMs, metrics };
  // Without a recognised key the endpoint answers for the caller's IP address.
  if (resp.data?.scope === 'ip-address') return { status: 'unavailable', reason: 'auth_failed', latencyMs, metrics };

  // Fortexa submits `unlisted` scans and polls results (`retrieve`).
  const limits = resp.data?.limits || {};
  const num = (v) => (Number.isFinite(v) ? v : null);
  metrics.quota = {
    unlistedDayRemaining: num(limits.unlisted?.day?.remaining),
    unlistedDayLimit: num(limits.unlisted?.day?.limit),
    unlistedHourRemaining: num(limits.unlisted?.hour?.remaining),
    retrieveDayRemaining: num(limits.retrieve?.day?.remaining),
  };
  if (metrics.quota.unlistedDayRemaining === 0 || metrics.quota.unlistedHourRemaining === 0) {
    return { status: 'degraded', reason: 'quota_exhausted', latencyMs, metrics };
  }
  const judged = recentRes.status === 'fulfilled' ? judgeRecent(recentRes.value, svc) : null;
  if (judged && judged.status === 'degraded') return { ...judged, latencyMs, metrics };
  return { status: 'healthy', latencyMs, metrics, notes: judged ? judged.notes : [] };
}

// The price ids checkout uses, in a fixed order; the first configured one is read.
const STRIPE_PRICE_ENVS = [
  'STRIPE_PRICE_LIGHT_MONTHLY', 'STRIPE_PRICE_BASIC_MONTHLY', 'STRIPE_PRICE_PRO_MONTHLY',
  'STRIPE_PRICE_LIGHT_ANNUAL', 'STRIPE_PRICE_BASIC_ANNUAL', 'STRIPE_PRICE_PRO_ANNUAL',
  'STRIPE_PRICE_TRIAL1', 'STRIPE_PRICE_TRIAL2',
];

function stripeReason(err) {
  switch (err && err.type) {
    case 'StripeAuthenticationError': return { status: 'unavailable', reason: 'auth_failed' };
    case 'StripePermissionError': return { status: 'unavailable', reason: 'permission_denied' };
    case 'StripeConnectionError': return { status: 'unavailable', reason: 'unreachable' };
    case 'StripeRateLimitError': return { status: 'degraded', reason: 'rate_limited' };
    case 'StripeInvalidRequestError':
      return err.code === 'resource_missing'
        ? { status: 'degraded', reason: 'misconfigured' }
        : { status: 'unavailable', reason: 'http_error' };
    default:
      return err && err.timedOut ? { status: 'unavailable', reason: 'timeout' } : { status: 'unavailable', reason: 'http_error' };
  }
}

async function checkStripe(svc) {
  if (!deps.env.STRIPE_SECRET_KEY) return { status: 'unavailable', reason: 'not_configured' };
  const stripe = deps.stripe();
  const priceEnv = STRIPE_PRICE_ENVS.find((k) => deps.env[k]);
  // Request options: one attempt, bounded — the SDK default is 80 s.
  const opts = { timeout: svc.timeoutMs - 500, maxNetworkRetries: 0 };
  const start = deps.now();
  let livemode = null;
  let priceActive = null;
  try {
    if (priceEnv) {
      const price = await stripe.prices.retrieve(deps.env[priceEnv], {}, opts);
      livemode = typeof price.livemode === 'boolean' ? price.livemode : null;
      priceActive = typeof price.active === 'boolean' ? price.active : null;
    } else {
      const list = await stripe.prices.list({ limit: 1 }, opts);
      livemode = list.data && list.data[0] && typeof list.data[0].livemode === 'boolean' ? list.data[0].livemode : null;
    }
  } catch (err) {
    const out = stripeReason(err);
    log('stripe', out.reason, err);
    return { ...out, metrics: { priceConfigured: Boolean(priceEnv) } };
  }
  const latencyMs = deps.now() - start;
  const metrics = { livemode, priceConfigured: Boolean(priceEnv), priceActive };
  if (deps.env.NODE_ENV === 'production' && livemode === false) {
    return { status: 'degraded', reason: 'test_mode_in_production', latencyMs, metrics };
  }
  if (!priceEnv) return { status: 'degraded', reason: 'misconfigured', latencyMs, metrics };
  if (priceActive === false) return { status: 'degraded', reason: 'price_inactive', latencyMs, metrics };
  return { status: 'healthy', latencyMs, metrics };
}

async function checkStripeWebhooks() {
  const mongoose = deps.mongoose();
  const StripeEvent = deps.StripeEvent();
  const outcome = deps.signals().getOutcome('stripe_webhook');
  const secretConfigured = Boolean(deps.env.STRIPE_WEBHOOK_SECRET);

  // StripeEvent holds one row per webhook event that was processed (a failed
  // one deletes its row so Stripe can retry), kept for 7 days. Checkout claims
  // share the collection as `checkout:<id>` and are excluded. Only counts and
  // the newest row's creation time (from its ObjectId) are read.
  const since = new Date(deps.now() - 7 * 86400_000);
  const sinceId = mongoose.Types.ObjectId.createFromTime(Math.floor(since.getTime() / 1000));
  const filter = { eventId: { $regex: '^evt_' } };
  const [processedLast7d, newest] = await Promise.all([
    StripeEvent.countDocuments({ ...filter, _id: { $gte: sinceId } }),
    StripeEvent.findOne(filter).sort({ _id: -1 }).select('_id').lean(),
  ]);
  const lastProcessedAt = newest && newest._id && typeof newest._id.getTimestamp === 'function'
    ? newest._id.getTimestamp().toISOString()
    : null;

  const metrics = {
    secretConfigured,
    processedLast7d,
    lastProcessedAt,
    sinceStart: { processed: outcome.ok, failed: outcome.failed, since: outcome.since },
    lastFailureAt: outcome.lastFailureAt,
    lastFailureCode: outcome.lastFailureCode,
  };
  const notes = ['since_task_start'];
  if (!secretConfigured) return { status: 'unavailable', reason: 'not_configured', metrics, notes };
  if (outcome.lastOutcome === 'failed') return { status: 'degraded', reason: 'webhook_failures', metrics, notes };
  if (processedLast7d === 0 && outcome.ok === 0) return { status: 'idle', metrics, notes: [...notes, 'no_recent_activity'] };
  return { status: 'healthy', metrics, notes };
}

// ─── AWS ─────────────────────────────────────────────────────────────────────

const awsCache = {};
function awsClients(env) {
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION;
  // A cold TLS connection to the CloudWatch endpoint took ~3.8 s in testing from
  // outside AWS, so the connect limit leaves room for that; clients are cached and
  // reuse their sockets afterwards. Both stay inside the 5 s inventory budget.
  const base = { region, maxAttempts: 1, requestHandler: { requestTimeout: 4500, connectionTimeout: 4000 } };
  const make = (key, pkg, ctor) => {
    if (!awsCache[key]) {
      const sdk = require(pkg);
      awsCache[key] = { sdk, client: new sdk[ctor](base) };
    }
    return awsCache[key];
  };
  return {
    region,
    ecs: () => make('ecs', '@aws-sdk/client-ecs', 'ECSClient'),
    elb: () => make('elb', '@aws-sdk/client-elastic-load-balancing-v2', 'ElasticLoadBalancingV2Client'),
    cloudwatch: () => make('cw', '@aws-sdk/client-cloudwatch', 'CloudWatchClient'),
    ses: () => make('ses', '@aws-sdk/client-ses', 'SESClient'),
  };
}

async function checkEmail(svc) {
  const env = deps.env;
  if (env.USE_AWS_SES !== 'true') {
    // SMTP mode (development). Verifying it would log in to the mail server on
    // every refresh, so it is reported as configured, never healthy.
    return env.EMAIL_USER
      ? { status: 'configured', metrics: { transport: 'smtp' }, notes: ['smtp_not_verified'] }
      : { status: 'unavailable', reason: 'not_configured' };
  }
  const aws = deps.aws(env);
  if (!aws.region) return { status: 'unknown', reason: 'not_configured' };
  const { sdk, client } = aws.ses();
  const start = deps.now();
  let enabled;
  let quota;
  try {
    [enabled, quota] = await Promise.all([
      client.send(new sdk.GetAccountSendingEnabledCommand({})),
      client.send(new sdk.GetSendQuotaCommand({})),
    ]);
  } catch (err) {
    const reason = awsReason(err);
    log('email', reason, err);
    return { status: 'unknown', reason, metrics: { transport: 'ses' } };
  }
  const max = num(quota.Max24HourSend);
  const sent = num(quota.SentLast24Hours);
  const metrics = {
    transport: 'ses',
    sendingEnabled: typeof enabled.Enabled === 'boolean' ? enabled.Enabled : null,
    sentLast24h: sent,
    max24h: max,
    maxSendRatePerSec: num(quota.MaxSendRate),
  };
  const notes = max === 200 ? ['possible_sandbox'] : [];
  const latencyMs = deps.now() - start;
  if (metrics.sendingEnabled === false) return { status: 'unavailable', reason: 'sending_paused', latencyMs, metrics, notes };
  if (max > 0 && sent !== null && sent / max >= svc.thresholds.quotaUsedRatio) {
    return { status: 'degraded', reason: 'quota_nearly_used', latencyMs, metrics, notes };
  }
  return { status: 'healthy', latencyMs, metrics, notes };
}

function num(v) {
  return Number.isFinite(v) ? v : null;
}

/** Combine sub-checks: any definite problem wins; otherwise an unknown part makes the whole unknown. */
function combineParts(parts) {
  const order = ['unavailable', 'degraded'];
  for (const s of order) {
    const hit = Object.values(parts).find((p) => p.status === s);
    if (hit) return { status: s, reason: hit.reason };
  }
  const unknown = Object.values(parts).filter((p) => p.status === 'unknown');
  if (unknown.length === Object.keys(parts).length) return { status: 'unknown', reason: unknown[0].reason };
  if (unknown.length) return { status: 'unknown', reason: 'partial_check' };
  return { status: 'healthy' };
}

async function checkAwsBackend(svc) {
  const env = deps.env;
  const cluster = env.ECS_CLUSTER_NAME;
  const service = env.HEALTH_ECS_SERVICE;
  const tgArn = env.HEALTH_ALB_TARGET_GROUP_ARN;
  const lbArn = env.HEALTH_ALB_LOAD_BALANCER_ARN;
  if (!(cluster && service) && !tgArn) return { status: 'unknown', reason: 'not_configured' };
  const aws = deps.aws(env);
  if (!aws.region) return { status: 'unknown', reason: 'not_configured' };

  const parts = {};
  const metrics = {};
  const notes = [];
  const tasks = [];

  if (cluster && service) {
    tasks.push((async () => {
      const { sdk, client } = aws.ecs();
      const res = await client.send(new sdk.DescribeServicesCommand({ cluster, services: [service] }));
      const s = res.services && res.services[0];
      if (!s) throw Object.assign(new Error('service not found'), { name: 'ServiceNotFoundException' });
      const primary = (s.deployments || []).find((d) => d.status === 'PRIMARY') || {};
      metrics.ecs = {
        desiredCount: num(s.desiredCount),
        runningCount: num(s.runningCount),
        pendingCount: num(s.pendingCount),
        deployments: (s.deployments || []).length,
        rolloutState: primary.rolloutState || null,
        taskDefinition: primary.taskDefinition ? primary.taskDefinition.split('/').pop() : null,
      };
      const e = metrics.ecs;
      if (e.deployments > 1) notes.push('deployment_in_progress');
      if (e.runningCount === 0) return { status: 'unavailable', reason: 'no_running_tasks' };
      if (e.rolloutState === 'FAILED') return { status: 'degraded', reason: 'deployment_failed' };
      if (e.runningCount < e.desiredCount) return { status: 'degraded', reason: 'tasks_below_desired' };
      return { status: 'healthy' };
    })().then((p) => { parts.ecs = p; }, (err) => { log('aws_backend', 'ecs', err); parts.ecs = { status: 'unknown', reason: awsReason(err) }; }));
  }

  if (tgArn) {
    tasks.push((async () => {
      const { sdk, client } = aws.elb();
      const res = await client.send(new sdk.DescribeTargetHealthCommand({ TargetGroupArn: tgArn }));
      const counts = { healthy: 0, unhealthy: 0, initial: 0, draining: 0, other: 0 };
      for (const d of res.TargetHealthDescriptions || []) {
        const st = d.TargetHealth && d.TargetHealth.State;
        counts[st in counts ? st : 'other'] += 1;
      }
      metrics.targets = counts;
      const total = Object.values(counts).reduce((a, b) => a + b, 0);
      if (total === 0) return { status: 'unavailable', reason: 'no_targets' };
      if (counts.healthy === 0) return { status: 'unavailable', reason: 'no_healthy_targets' };
      if (counts.unhealthy > 0) return { status: 'degraded', reason: 'targets_unhealthy' };
      return { status: 'healthy' };
    })().then((p) => { parts.targets = p; }, (err) => { log('aws_backend', 'elb', err); parts.targets = { status: 'unknown', reason: awsReason(err) }; }));
  }

  if (tgArn && lbArn) {
    tasks.push((async () => {
      const { sdk, client } = aws.cloudwatch();
      const lbDim = lbArn.split(':loadbalancer/')[1];
      const tgDim = tgArn.split(':').pop();
      if (!lbDim || !tgDim) throw Object.assign(new Error('bad ARN'), { name: 'ValidationError' });
      const end = new Date(deps.now());
      const start = new Date(end.getTime() - 15 * 60_000);
      const q = (Id, MetricName, withTg) => ({
        Id,
        MetricStat: {
          Metric: {
            Namespace: 'AWS/ApplicationELB',
            MetricName,
            Dimensions: [{ Name: 'LoadBalancer', Value: lbDim }, ...(withTg ? [{ Name: 'TargetGroup', Value: tgDim }] : [])],
          },
          Period: 900,
          Stat: 'Sum',
        },
      });
      const res = await client.send(new sdk.GetMetricDataCommand({
        StartTime: start,
        EndTime: end,
        MetricDataQueries: [q('req', 'RequestCount', true), q('t5xx', 'HTTPCode_Target_5XX_Count', true), q('e5xx', 'HTTPCode_ELB_5XX_Count', false)],
      }));
      // ALB publishes these only for periods that had such requests, so a
      // successful query with no datapoint is a real zero (and a failed query
      // leaves the figure null, never zero).
      const sumOf = (id) => {
        const r = (res.MetricDataResults || []).find((m) => m.Id === id);
        return r ? (r.Values || []).reduce((a, b) => a + b, 0) : 0;
      };
      metrics.http15m = { requests: sumOf('req'), target5xx: sumOf('t5xx'), lb5xx: sumOf('e5xx') };
      const h = metrics.http15m;
      if (h.requests >= svc.thresholds.minRequests && (h.target5xx + h.lb5xx) / h.requests >= svc.thresholds.http5xxRatio) {
        return { status: 'degraded', reason: 'http_5xx' };
      }
      return { status: 'healthy' };
    })().then((p) => { parts.http = p; }, (err) => { log('aws_backend', 'cloudwatch', err); metrics.http15m = null; parts.http = { status: 'unknown', reason: awsReason(err) }; }));
  }

  await Promise.all(tasks);
  metrics.parts = Object.fromEntries(Object.entries(parts).map(([k, v]) => [k, { status: v.status, reason: v.reason || null }]));
  return { ...combineParts(parts), metrics, notes };
}

async function checkAwsAlarms() {
  const env = deps.env;
  const prefix = env.HEALTH_ALARM_PREFIX;
  if (!prefix) return { status: 'unknown', reason: 'not_configured' };
  const aws = deps.aws(env);
  if (!aws.region) return { status: 'unknown', reason: 'not_configured' };
  const { sdk, client } = aws.cloudwatch();
  let res;
  try {
    res = await client.send(new sdk.DescribeAlarmsCommand({
      AlarmNamePrefix: prefix,
      AlarmTypes: ['MetricAlarm', 'CompositeAlarm'],
      MaxRecords: 100,
    }));
  } catch (err) {
    const reason = awsReason(err);
    log('aws_alarms', reason, err);
    return { status: 'unknown', reason };
  }
  const alarms = [...(res.MetricAlarms || []), ...(res.CompositeAlarms || [])];
  const counts = { OK: 0, ALARM: 0, INSUFFICIENT_DATA: 0 };
  for (const a of alarms) counts[a.StateValue] = (counts[a.StateValue] || 0) + 1;
  const firing = alarms.filter((a) => a.StateValue === 'ALARM').map((a) => a.AlarmName).slice(0, 10);
  const metrics = {
    total: alarms.length,
    ok: counts.OK,
    alarm: counts.ALARM,
    insufficientData: counts.INSUFFICIENT_DATA,
    firing,
    backendAlarms: alarms.filter((a) => /^fortexa-backend/.test(a.AlarmName || '')).length,
  };
  const notes = [];
  if (metrics.backendAlarms === 0) notes.push('backend_alarms_missing');
  if (metrics.insufficientData > 0) notes.push('insufficient_data_alarms');
  if (alarms.length === 0) return { status: 'unknown', reason: 'no_alarms', metrics, notes };
  if (counts.ALARM > 0) return { status: 'degraded', reason: 'alarm', metrics, notes };
  return { status: 'healthy', metrics, notes };
}

const CHECKS = {
  api: checkApi,
  mongodb: checkMongo,
  redis: checkRedis,
  queues: checkQueues,
  webcheck: checkWebCheck,
  zap: (svc) => checkZap('normal', svc),
  zap_auth: (svc) => checkZap('auth', svc),
  gemini: checkGemini,
  pagespeed: checkPagespeed,
  observatory: (svc) => checkRecentScanner('observatoryResult', svc),
  urlscan: checkUrlscan,
  stripe: checkStripe,
  stripe_webhooks: checkStripeWebhooks,
  email: checkEmail,
  aws_backend: checkAwsBackend,
  aws_alarms: checkAwsAlarms,
};

// ─── Runner ──────────────────────────────────────────────────────────────────

const cache = new Map();    // id → { result, at }
const inflight = new Map(); // id → Promise<result>

function finalize(svc, out, startedAt) {
  const status = STATUS_SET.has(out && out.status) ? out.status : 'unknown';
  const reason = out && out.reason ? (REASONS.has(out.reason) ? out.reason : 'check_failed') : null;
  const notes = [...new Set((out && out.notes) || [])].filter((n) => NOTES.has(n));
  return {
    id: svc.id,
    category: svc.category,
    critical: svc.critical,
    basis: svc.basis,
    status,
    reason,
    notes,
    latencyMs: Number.isFinite(out && out.latencyMs) ? Math.round(out.latencyMs) : null,
    metrics: cleanValue((out && out.metrics) || {}, 0) || {},
    checkedAt: new Date(deps.now()).toISOString(),
    durationMs: Math.max(0, deps.now() - startedAt),
  };
}

// How long a result is reused. Services that call a third-party API with a quota
// (inventory `cacheTtlMs`) keep a good result for that long and a failure for at
// most a minute, so a fixed key shows up quickly; a forced re-check of them runs
// at most every 30 s. Everything else: CACHE_TTL_MS / FORCE_MIN_INTERVAL_MS.
const FAILED_RESULT_TTL_MS = 60_000;
const QUOTA_FORCE_MIN_INTERVAL_MS = 30_000;
const ttlFor = (svc, result) => {
  if (!svc.cacheTtlMs) return CACHE_TTL_MS;
  return result.status === 'healthy' ? svc.cacheTtlMs : Math.min(svc.cacheTtlMs, FAILED_RESULT_TTL_MS);
};

async function runCheck(id, { force = false } = {}) {
  const svc = getService(id);
  const cached = cache.get(id);
  const age = cached ? deps.now() - cached.at : Infinity;
  const forceMin = svc.cacheTtlMs ? QUOTA_FORCE_MIN_INTERVAL_MS : FORCE_MIN_INTERVAL_MS;
  if (cached && age < (force ? forceMin : cached.ttl)) {
    return { ...cached.result, cached: true };
  }
  if (inflight.has(id)) return inflight.get(id);

  const p = (async () => {
    const startedAt = deps.now();
    let out;
    try {
      out = await withTimeout(CHECKS[id](svc), svc.timeoutMs);
    } catch (err) {
      if (err && err.timedOut) {
        log(id, 'timeout', err);
        out = { status: svc.onTimeout, reason: 'timeout' };
      } else {
        log(id, 'check threw', err);
        out = { status: 'unknown', reason: 'check_failed' };
      }
    }
    const result = finalize(svc, out, startedAt);
    cache.set(id, { result, at: deps.now(), ttl: ttlFor(svc, result) });
    return { ...result, cached: false };
  })().finally(() => inflight.delete(id));
  inflight.set(id, p);
  return p;
}

/**
 * Overall state from the real results. Configured and unknown are never
 * counted as working: they are "not verified".
 *   outage    a critical service is unavailable
 *   degraded  any service is degraded or unavailable
 *   healthy   nothing failing (some may still be unverified — see counts)
 *   unknown   nothing could be verified at all
 */
function summarize(results) {
  const counts = { healthy: 0, degraded: 0, unavailable: 0, starting: 0, idle: 0, configured: 0, unknown: 0 };
  results.forEach((r) => { counts[r.status] += 1; });
  const operational = counts.healthy + counts.idle;
  const notVerified = counts.configured + counts.unknown;
  let overall = 'healthy';
  if (results.some((r) => r.critical && r.status === 'unavailable')) overall = 'outage';
  else if (counts.degraded + counts.unavailable > 0) overall = 'degraded';
  else if (notVerified === results.length) overall = 'unknown';
  return {
    overall,
    total: results.length,
    operational,
    notVerified,
    problems: counts.degraded + counts.unavailable,
    counts,
  };
}

/**
 * @param {object}  [opts]
 * @param {string}  [opts.retry]  inventory id to re-check now (other results may come from cache)
 */
async function getReport({ retry = null } = {}) {
  if (retry && !SERVICE_IDS.includes(retry)) throw Object.assign(new Error('unknown service'), { code: 'UNKNOWN_SERVICE' });
  const results = await Promise.all(INVENTORY.map((svc) => runCheck(svc.id, { force: svc.id === retry })));
  return {
    generatedAt: new Date(deps.now()).toISOString(),
    services: results,
    summary: summarize(results),
    refreshIntervalSec: REFRESH_INTERVAL_SEC,
    cacheTtlSec: CACHE_TTL_MS / 1000,
  };
}

// ─── Test hooks ──────────────────────────────────────────────────────────────

function setDependencies(overrides) {
  deps = { ...defaultDeps(), ...overrides };
  cache.clear();
  inflight.clear();
}

function clearCache() {
  cache.clear();
  inflight.clear();
}

module.exports = {
  getReport,
  summarize,
  CHECKS,
  CACHE_TTL_MS,
  REFRESH_INTERVAL_SEC,
  // tests
  setDependencies,
  clearCache,
  _internals: { netReason, awsReason, cleanValue, combineParts, REASONS, NOTES },
};
