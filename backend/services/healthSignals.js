/**
 * backend/services/healthSignals.js
 *
 * Outcome counters for work this process performs, read by the admin System
 * Health page (services/systemHealth.js). Used where the only other record of a
 * failure is a log line — a Gemini call that fell back to the structured report,
 * a Stripe webhook that failed — so the health page can show it.
 *
 * Process-local and reset on restart: the page labels these "since this task
 * started". Production runs one backend task; with more, each task reports only
 * its own outcomes. Holds no payloads, ids or error text — only counts, times
 * and a fixed reason code.
 *
 * Also holds the in-process BullMQ workers (registered by server.js), so the
 * queue check can tell whether anything in this task is consuming jobs. BullMQ's
 * own worker count uses CLIENT LIST, which the production Valkey ACL denies.
 */

const STARTED_AT = new Date().toISOString();
const RECENT_WINDOW = 10; // the last N outcomes decide "recent failures"
const signals = new Map();
const workers = new Map();

/**
 * @param {string}  name   fixed signal name, e.g. 'gemini_report'
 * @param {boolean} ok
 * @param {string}  [code] fixed reason code for a failure (never error text)
 */
function recordOutcome(name, ok, code = null) {
  const s = signals.get(name) || {
    ok: 0, failed: 0, lastOkAt: null, lastFailureAt: null, lastFailureCode: null, lastOutcome: null, recent: [],
  };
  const at = new Date().toISOString();
  if (ok) {
    s.ok += 1;
    s.lastOkAt = at;
    s.lastOutcome = 'ok';
  } else {
    s.failed += 1;
    s.lastFailureAt = at;
    s.lastFailureCode = code;
    s.lastOutcome = 'failed';
  }
  s.recent.push(Boolean(ok));
  if (s.recent.length > RECENT_WINDOW) s.recent.shift();
  signals.set(name, s);
}

/** A copy of the counters for `name`; zeros when nothing has been recorded. */
function getOutcome(name) {
  const s = signals.get(name);
  const recent = s ? s.recent : [];
  return {
    since: STARTED_AT,
    ok: s ? s.ok : 0,
    failed: s ? s.failed : 0,
    recentOk: recent.filter(Boolean).length,
    recentFailed: recent.filter((r) => !r).length,
    lastOkAt: s ? s.lastOkAt : null,
    lastFailureAt: s ? s.lastFailureAt : null,
    lastFailureCode: s ? s.lastFailureCode : null,
    lastOutcome: s ? s.lastOutcome : null,
  };
}

/** server.js registers each in-process BullMQ worker it starts. */
function registerWorker(name, worker) {
  if (worker) workers.set(name, worker);
}

/**
 * Whether this task's worker for `name` is consuming jobs: true / false, or
 * null when no worker was started here (e.g. DISABLE_WORKER=true).
 */
function workerRunning(name) {
  const w = workers.get(name);
  if (!w) return null;
  try {
    return typeof w.isRunning === 'function' ? Boolean(w.isRunning()) : null;
  } catch (_) {
    return null;
  }
}

/** Tests only. */
function resetSignals() {
  signals.clear();
  workers.clear();
}

module.exports = { recordOutcome, getOutcome, registerWorker, workerRunning, resetSignals, STARTED_AT };
