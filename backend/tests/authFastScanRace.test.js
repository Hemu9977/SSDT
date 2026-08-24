'use strict';

/**
 * Authenticated-scan fast-scanner race tests.
 *
 * These EXECUTE the real readiness gate in geminiCompletionService and the real
 * ensureAuthFastScans orchestration against a stubbed model/scanner layer — no
 * database, no scanners, no server.
 *
 * They exist because this defect shipped and cost a customer a scan. In production
 * on 2026-08-24 (scan zap-auth-1787581094591-ixfe24):
 *
 *   15:24:09  WebCheck finished in 9.9s and called checkAndGenerateGemini
 *   15:24:09  "Missing fast-scan data — finishing with fallback"  -> 47-char report
 *   15:24:09  "[Billing] Scan completed - quota deducted"
 *   15:24:18  PageSpeed / Observatory / URLScan persisted — 9 seconds too late
 *
 * The scan was marked completed and billed with a placeholder where the AI report
 * should have been. Both halves of the fix are covered here: the completion service
 * must treat missing fast-scan data as NOT READY, and the orchestration must persist
 * those results before WebCheck can trigger completion.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const BACKEND = path.join(__dirname, '..');

// ─── Shared stub state ───────────────────────────────────────────────────────
const state = {
  scan: null,
  billed: 0,          // finalizeSuccessfulScan calls
  failed: 0,          // _finishAsFailed -> status 'failed'
  updates: [],        // every $set applied
  geminiCalls: 0,     // checkAndGenerateGemini triggered from the route
  started: { psi: 0, obs: 0, urlscan: 0, webcheck: 0 },
  order: [],          // sequence of significant events, for ordering assertions
};

function resetState(scan) {
  state.scan = scan;
  state.billed = 0;
  state.failed = 0;
  state.updates = [];
  state.geminiCalls = 0;
  state.started = { psi: 0, obs: 0, urlscan: 0, webcheck: 0 };
  state.order = [];
}

function applySet(doc, $set) {
  for (const [k, v] of Object.entries($set || {})) {
    if (k.includes('.')) {
      const [a, b] = k.split('.');
      doc[a] = doc[a] || {};
      doc[a][b] = v;
    } else doc[k] = v;
  }
}

// ─── Stub the model layer ────────────────────────────────────────────────────
require.cache[path.join(BACKEND, 'models/ScanResult.js')] = {
  id: 'sr', filename: 'sr', loaded: true,
  exports: {
    findOne: async () => state.scan,
    updateOne: async (filter, update) => {
      state.updates.push(update.$set || {});
      if (update.$set) {
        applySet(state.scan, update.$set);
        if (update.$set.status === 'failed') { state.failed++; state.order.push('failed'); }
        if (update.$set.pagespeedResult !== undefined) state.order.push('persist-fast-scans');
        if (update.$set.webCheckResult !== undefined) state.order.push('persist-webcheck');
      }
      return { matchedCount: 1, modifiedCount: 1 };
    },
    /** Models Mongo's atomic single-document find-and-set for the fastScansStartedAt claim. */
    findOneAndUpdate: async (filter, update) => {
      if ('fastScansStartedAt' in filter) {
        const cur = state.scan.fastScansStartedAt;
        // filter is { fastScansStartedAt: null } — matches null AND absent.
        if (cur !== null && cur !== undefined) return null;
        const before = JSON.parse(JSON.stringify(state.scan));
        applySet(state.scan, update.$set);
        return before;
      }
      applySet(state.scan, update.$set || {});
      return state.scan;
    },
  }
};

// ─── Stub everything geminiCompletionService pulls in ────────────────────────
require.cache[path.join(BACKEND, 'services/planService.js')] = {
  id: 'ps', filename: 'ps', loaded: true,
  exports: {
    finalizeSuccessfulScan: async () => { state.billed++; state.order.push('billed'); },
  }
};

const noop = () => {};
require.cache[path.join(BACKEND, 'services/scanProgressService.js')] = {
  id: 'sps', filename: 'sps', loaded: true,
  exports: { publishScanProgress: async () => {}, setPublisher: noop, setDirectEmitter: noop }
};
require.cache[path.join(BACKEND, 'services/notificationService.js')] = {
  id: 'ns', filename: 'ns', loaded: true,
  exports: { handleScanComplete: async () => {}, handleScanFailed: async () => {}, emitScanStarted: noop }
};

const gemini = require(path.join(BACKEND, 'services/geminiCompletionService.js'));

// Capture the real implementation NOW. PART 2 replaces this same export object's
// checkAndGenerateGemini with a counting stub (so the route's internal require picks
// it up), and node:test runs every test after all top-level code — so without this
// reference PART 1 would silently exercise the stub instead of the code under test.
const checkAndGenerateGemini = gemini.checkAndGenerateGemini;

// ─── Helpers ─────────────────────────────────────────────────────────────────
const READY_ZAP = { status: 'completed' };
const READY_WC  = { status: 'completed_with_errors' };

let idSeq = 0;
const nextId = () => `zap-auth-test-${++idSeq}`;

function scanDoc(over = {}) {
  return {
    analysisId: nextId(),
    userId: 'u1',
    target: 'http://demo.testfire.net/',
    status: 'combining',
    zapResult: READY_ZAP,
    webCheckResult: READY_WC,
    authScanResult: { status: 'completed' },
    refinedReport: null,
    quotaConsumed: false,
    createdAt: new Date(),
    fastScansStartedAt: null,
    ...over,
  };
}

// ═══ PART 1 — the completion service must not finalize without fast-scan data ══

test('missing fast-scan data is NOT READY: no completion, no billing, no failure', async () => {
  resetState(scanDoc({ fastScansStartedAt: new Date() }));   // just started, inside grace

  await checkAndGenerateGemini(state.scan.analysisId, 'u1');

  assert.equal(state.billed, 0, 'a scan with no fast-scan data must never be billed');
  assert.equal(state.failed, 0, 'inside the grace window it must not fail either');
  assert.notEqual(state.scan.status, 'completed', 'must not be marked completed');
  assert.equal(state.scan.refinedReport, null, 'must not write a placeholder report');
});

test('the placeholder-and-bill path is gone entirely', () => {
  const src = fs.readFileSync(path.join(BACKEND, 'services/geminiCompletionService.js'), 'utf8');
  assert.ok(!/async function _finishWithFallback/.test(src),
    '_finishWithFallback wrote status:completed with a placeholder AND billed — it must not exist');
  assert.ok(!/_finishWithFallback\(/.test(src.replace(/^\s*\/\/.*$/gm, '')),
    'nothing may call the fallback-complete path');
});

test('fast-scan data still missing after the grace window fails explicitly and is not billed', async () => {
  process.env.GEMINI_FAST_SCAN_GRACE_MS = '1000';
  resetState(scanDoc({ fastScansStartedAt: new Date(Date.now() - 60_000) }));  // long past grace

  await checkAndGenerateGemini(state.scan.analysisId, 'u1');

  assert.equal(state.scan.status, 'failed', 'exhausted grace must fail, not complete');
  assert.equal(state.scan.failureReason, 'scan_data_unavailable');
  assert.equal(state.billed, 0, 'an explicit failure must never be billed');
  delete process.env.GEMINI_FAST_SCAN_GRACE_MS;
});

test('finalization proceeds once fast-scan results become available', async () => {
  // Same scan, now with PageSpeed persisted — it must get past the readiness gate.
  resetState(scanDoc({ fastScansStartedAt: new Date(), pagespeedResult: { score: 91 } }));

  await checkAndGenerateGemini(state.scan.analysisId, 'u1');

  // It proceeds past the gate: it is no longer refused for missing fast-scan data.
  // (It then stops at the Redis lock in this stubbed environment, which is fine —
  // what matters is that it did NOT fail or bill a placeholder.)
  assert.equal(state.scan.failureReason ?? null, null,
    'with fast-scan data present it must not fail as scan_data_unavailable');
  assert.notEqual(state.scan.refinedReport, 'Required scan data unavailable for AI analysis.');
});

test('WebCheck completed_with_errors alone never blocks or fails the scan', async () => {
  resetState(scanDoc({
    fastScansStartedAt: new Date(),
    pagespeedResult: { score: 91 },
    webCheckResult: { status: 'completed_with_errors' },
  }));

  await checkAndGenerateGemini(state.scan.analysisId, 'u1');

  // Documented policy (finalizeSuccessfulScan): a failed or errored WebCheck renders
  // its section N/A and does NOT void the scan. So the scan is allowed to reach
  // 'completed' here — what must never happen is it being failed or refused.
  assert.notEqual(state.scan.status, 'failed', 'completed_with_errors must not fail the scan');
  assert.equal(state.scan.failureReason ?? null, null, 'and must not set a failure reason');
});

test('a failed ZAP leg still fails the scan and is still not billed', async () => {
  resetState(scanDoc({ zapResult: { status: 'failed' }, pagespeedResult: { score: 50 } }));

  await checkAndGenerateGemini(state.scan.analysisId, 'u1');

  assert.equal(state.scan.status, 'failed');
  assert.equal(state.scan.failureReason, 'vulnerability_scan_failed');
  assert.equal(state.billed, 0);
});

// ═══ PART 2 — the orchestration: ordering, idempotency, no polling needed ═════

// Stub the four scanners, then load the route module.
require.cache[path.join(BACKEND, 'services/pagespeedService.js')] = {
  id: 'psi', filename: 'psi', loaded: true,
  exports: { getPageSpeedReport: async () => { state.started.psi++; return { score: 91 }; } }
};
require.cache[path.join(BACKEND, 'services/observatoryService.js')] = {
  id: 'obs', filename: 'obs', loaded: true,
  exports: { scanHost: async () => { state.started.obs++; return { grade: 'B' }; } }
};
require.cache[path.join(BACKEND, 'services/urlscanService.js')] = {
  id: 'us', filename: 'us', loaded: true,
  // Deliberately the slowest, mirroring production: urlscan polls its own API (~20s)
  // while WebCheck finishes in ~10s. This is the exact skew that caused the race.
  exports: { runUrlScan: async () => { await new Promise(r => setTimeout(r, 30)); state.started.urlscan++; return { uuid: 'x' }; } }
};
require.cache[path.join(BACKEND, 'services/webCheckService.js')] = {
  id: 'wc', filename: 'wc', loaded: true,
  exports: {
    startAsyncWebCheckScan: async () => {
      state.started.webcheck++;
      state.order.push('webcheck-started');
      return { status: 'running' };
    },
    getFullResults: async () => ({}),
  }
};
require.cache[path.join(BACKEND, 'services/geminiCompletionService.js')].exports.checkAndGenerateGemini =
  async () => { state.geminiCalls++; state.order.push('gemini-triggered'); };

const authRoutes = require(path.join(BACKEND, 'routes/zapAuthRoutes.js'));
const ensureAuthFastScans = authRoutes.ensureAuthFastScans;

test('ensureAuthFastScans is exported so it can be driven without an HTTP poll', () => {
  assert.equal(typeof ensureAuthFastScans, 'function',
    'the fast scanners must be startable at scan acceptance, not only from GET /status');
});

test('fast scanners run and are persisted BEFORE WebCheck starts', async (t) => {
  if (typeof ensureAuthFastScans !== 'function') return t.skip('not exported');
  resetState(scanDoc({ zapResult: undefined, webCheckResult: undefined }));

  await ensureAuthFastScans(state.scan.analysisId, 'u1');

  assert.equal(state.started.psi, 1);
  assert.equal(state.started.obs, 1);
  assert.equal(state.started.urlscan, 1);
  assert.equal(state.started.webcheck, 1);

  const persistIdx = state.order.indexOf('persist-fast-scans');
  const wcIdx      = state.order.indexOf('webcheck-started');
  assert.ok(persistIdx !== -1, 'fast-scan results must be persisted');
  assert.ok(wcIdx !== -1, 'WebCheck must be started');
  assert.ok(persistIdx < wcIdx,
    'THE RACE: fast-scan results must be durable before WebCheck can complete and trigger Gemini');
});

test('the scan document carries the fast-scan results before WebCheck is started', async (t) => {
  if (typeof ensureAuthFastScans !== 'function') return t.skip('not exported');
  resetState(scanDoc({ zapResult: undefined, webCheckResult: undefined }));

  await ensureAuthFastScans(state.scan.analysisId, 'u1');

  assert.deepEqual(state.scan.pagespeedResult, { score: 91 });
  assert.deepEqual(state.scan.observatoryResult, { grade: 'B' });
  assert.deepEqual(state.scan.urlscanResult, { uuid: 'x' });
});

test('concurrent callers start the scanners exactly once', async (t) => {
  if (typeof ensureAuthFastScans !== 'function') return t.skip('not exported');
  resetState(scanDoc({ zapResult: undefined, webCheckResult: undefined }));

  // Scan acceptance and three status polls all racing.
  const results = await Promise.all([
    ensureAuthFastScans(state.scan.analysisId, 'u1'),
    ensureAuthFastScans(state.scan.analysisId, 'u1'),
    ensureAuthFastScans(state.scan.analysisId, 'u1'),
    ensureAuthFastScans(state.scan.analysisId, 'u1'),
  ]);

  assert.equal(state.started.psi, 1, 'PageSpeed must not run twice');
  assert.equal(state.started.obs, 1, 'Observatory must not run twice');
  assert.equal(state.started.urlscan, 1, 'urlscan must not run twice');
  assert.equal(state.started.webcheck, 1, 'WebCheck must not be started twice');
  assert.equal(results.filter(r => r.started).length, 1, 'exactly one caller may win the claim');
});

test('a second call after completion is a no-op, not a restart', async (t) => {
  if (typeof ensureAuthFastScans !== 'function') return t.skip('not exported');
  resetState(scanDoc({ zapResult: undefined, webCheckResult: undefined }));

  await ensureAuthFastScans(state.scan.analysisId, 'u1');
  const after = { ...state.started };
  const second = await ensureAuthFastScans(state.scan.analysisId, 'u1');

  assert.equal(second.started, false);
  assert.equal(second.reason, 'already-started');
  assert.deepEqual(state.started, after, 'a later poll must start nothing');
});

test('completion is triggered after the fast scanners finish, without any poll', async (t) => {
  if (typeof ensureAuthFastScans !== 'function') return t.skip('not exported');
  resetState(scanDoc({ zapResult: undefined, webCheckResult: undefined }));

  await ensureAuthFastScans(state.scan.analysisId, 'u1');

  assert.ok(state.geminiCalls >= 1,
    'the ZAP leg may already be done, so nothing else would re-trigger completion');
});

// ═══ PART 3 — every authenticated entry point must drive the orchestration ════
//
// Static, because executing schedulerService.triggerAuthenticatedScan would pull in
// the cron runner, the login browser and the whole ZAP recycler. What has to be true
// is structural: a scheduled authenticated scan has no browser polling
// GET /status/:scanId, so if the scheduler does not start the fast scanners itself,
// nothing ever does — the scan reaches 'combining' with no PageSpeed, Observatory,
// urlscan or WebCheck data and can only time out into 'scan_data_unavailable'.

const stripComments = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

test('the orchestration lives in a service, not in the route module', () => {
  const svc = path.join(BACKEND, 'services/authFastScanService.js');
  assert.ok(fs.existsSync(svc),
    'both the route and the scheduler need it, so it cannot live inside a route');
  const src = fs.readFileSync(svc, 'utf8');
  assert.ok(/async function ensureAuthFastScans/.test(src));
  assert.ok(/module\.exports\s*=\s*\{\s*ensureAuthFastScans\s*\}/.test(src));
});

test('scheduled authenticated scans start the fast scanners', () => {
  const src = stripComments(
    fs.readFileSync(path.join(BACKEND, 'services/schedulerService.js'), 'utf8'));

  const authFn = src.slice(src.indexOf('async function triggerAuthenticatedScan'));
  assert.ok(authFn.length > 0, 'triggerAuthenticatedScan must exist');
  assert.ok(/ensureAuthFastScans\(/.test(authFn),
    'a scheduled auth scan has nothing polling GET /status, so the scheduler must ' +
    'start PageSpeed / Observatory / urlscan / WebCheck itself');
});

test('the scheduled auth skeleton is visible to the capacity idle guard', () => {
  const src = stripComments(
    fs.readFileSync(path.join(BACKEND, 'services/schedulerService.js'), 'utf8'));
  const authFn = src.slice(src.indexOf('async function triggerAuthenticatedScan'));

  assert.ok(/authScanResult:\s*\{\s*status:\s*'provisioning'/.test(authFn),
    "the skeleton must record authScanResult.status 'provisioning' — without it " +
    'zapCapacityManager cannot tell the scan owes ZAP work and may scale the auth ' +
    'instance to zero while it waits for the lock');

  const cap = fs.readFileSync(path.join(BACKEND, 'services/zapCapacityManager.js'), 'utf8');
  const active = cap.match(/ACTIVE_ZAP_STATUSES\s*=\s*\[([^\]]*)\]/);
  assert.ok(active, 'ACTIVE_ZAP_STATUSES must exist');
  assert.ok(active[1].includes("'provisioning'"),
    'and the idle guard must count that status as active');
});

test('both authenticated entry points warm capacity and hold the ZAP lock', () => {
  const sched = stripComments(
    fs.readFileSync(path.join(BACKEND, 'services/schedulerService.js'), 'utf8'));
  const route = stripComments(
    fs.readFileSync(path.join(BACKEND, 'routes/zapAuthRoutes.js'), 'utf8'));
  const authFn = sched.slice(sched.indexOf('async function triggerAuthenticatedScan'));

  for (const [name, src] of [['scheduler', authFn], ['route', route]]) {
    assert.ok(/withZapInstance\('auth'/.test(src),
      `${name}: auth scans must run under zap:lock:auth — ZAP newSession is global ` +
      'and two concurrent scans wipe each other');
    assert.ok(/ensureZapCapacity\('auth'/.test(src),
      `${name}: must warm the auth instance, or under scale-to-zero the scan fires ` +
      'at a Service Connect alias with no endpoints behind it');
    assert.ok(/markZapDemand\('auth'/.test(src),
      `${name}: must mark demand so the idle check does not scale in behind it`);
  }
});
