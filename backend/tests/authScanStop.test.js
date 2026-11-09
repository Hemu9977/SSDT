'use strict';

/**
 * Stopping an authenticated scan.
 *
 * Runs the real worker (zapAuthService.runAuthenticatedScanBackground), the real stop
 * (stopAuthScan), the real start guard (startAsyncAuthScan), the real fast-scanner
 * orchestration (authFastScanService) and the real ZAP instance lock
 * (zapRecycler.withZapInstance) against an in-memory scan store that honours the
 * status filters the fix relies on, and a fake ZAP API server that records every call.
 *
 * What it pins down — each was broken before:
 *   - a stop ends the worker at once, not at its next 3–5 s poll (or never, in the
 *     AJAX phase, whose catch swallowed the signal), and revokes ZAP before returning;
 *   - a stop sends nothing to ZAP when this scan has no running worker — the auth ZAP
 *     is shared, and its current scan belongs to someone else;
 *   - a scan stopped while provisioning or queueing is never started afterwards (it
 *     used to be reset to 'pending', scanned in full, and billed);
 *   - a stop landing while the report is saved is not overwritten by 'combining';
 *   - a repeat stop is a no-op; another user's scan cannot be stopped;
 *   - the fast scanners' browser checks are aborted and WebCheck is never started;
 *   - a stopped scan leaves the ZAP lock queue without taking or leaking the lock.
 *
 * No Docker, database, Redis or network beyond 127.0.0.1.
 * Run with: node --test backend/tests/authScanStop.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
process.env.ZAP_RECYCLE_ENABLED = 'false';
delete process.env.ZAP_CAPACITY_MANAGED;

// ─── In-memory scan store that honours the filters used here ─────────────────
const docs = new Map();
const getPath = (o, k) => k.split('.').reduce((v, p) => (v == null ? v : v[p]), o);
function matches(doc, filter) {
  for (const [k, cond] of Object.entries(filter || {})) {
    const val = getPath(doc, k);
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
      if ('$nin' in cond && cond.$nin.includes(val)) return false;
      if ('$in' in cond && !cond.$in.includes(val)) return false;
    } else if (cond === null) {
      if (val != null) return false;
    } else if (String(val) !== String(cond)) {
      return false;
    }
  }
  return true;
}
function applySet(doc, $set) {
  for (const [k, v] of Object.entries($set || {})) {
    const parts = k.split('.');
    let o = doc;
    while (parts.length > 1) { const p = parts.shift(); o[p] = o[p] || {}; o = o[p]; }
    o[parts[0]] = v;
  }
}
const find = (filter) => [...docs.values()].find(d => matches(d, filter)) || null;
class Query {
  constructor(doc) { this.doc = doc; }
  select() { return this; }
  lean() { return Promise.resolve(this.doc ? JSON.parse(JSON.stringify(this.doc)) : null); }
  then(res, rej) { return Promise.resolve(this.doc).then(res, rej); }
}
function ScanResultStub(data) { Object.assign(this, data); }
ScanResultStub.prototype.save = async function () { docs.set(this.analysisId, this); return this; };
ScanResultStub.findOne = (filter) => new Query(find(filter));
ScanResultStub.updateOne = async (filter, update) => {
  const doc = find(filter);
  if (doc) applySet(doc, update.$set);
  return { matchedCount: doc ? 1 : 0, modifiedCount: doc ? 1 : 0 };
};
ScanResultStub.findOneAndUpdate = async (filter, update) => {
  const doc = find(filter);
  if (!doc) return null;
  const before = JSON.parse(JSON.stringify(doc));
  applySet(doc, update.$set);
  return before;
};

const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};
stub('models/ScanResult.js', ScanResultStub);

// Redis is unreachable in tests: the ZAP lock falls back to its in-memory mode.
stub('config/redis.js', { getPublisher: () => { throw new Error('no redis in tests'); } });

const deleted = [];
const gridfs = {
  onUpload: null,
  uploadFile: async (buf, filename) => {
    if (gridfs.onUpload) gridfs.onUpload(filename);
    return `file-${filename}`;
  },
  deleteFile: async (id) => { deleted.push(id); }
};
stub('services/gridfsService.js', gridfs);

const published = [];
stub('services/scanProgressService.js', { publishScanProgress: async (id, user, data) => { published.push({ id, data }); } });
stub('services/geminiCompletionService.js', { checkAndGenerateGemini: async () => {} });

// Fast scanners: everything external is stubbed; authFastScanService itself is real.
const fast = { webCheckStarted: [], webCheckStopped: [], lighthouse: [], capture: [] };
const waitForAbort = (signal, label) => new Promise((_, reject) => {
  if (!signal) return reject(new Error(`${label}: no signal passed`));
  signal.addEventListener('abort', () => reject(Object.assign(new Error(`${label} aborted`), { code: 'ERR_ABORTED' })), { once: true });
});
stub('services/pagespeedService.js', { getPageSpeedReport: async () => ({ lighthouseResult: {} }) });
stub('services/observatoryService.js', { scanHost: async () => ({ grade: 'B', score: 70 }) });
stub('services/urlscanService.js', { runUrlScan: async () => ({ uuid: 'u' }) });
stub('services/webCheckService.js', {
  startAsyncWebCheckScan: async (url, id) => { fast.webCheckStarted.push(id); return { status: 'running' }; },
  stopWebCheckScan: (id) => { fast.webCheckStopped.push(id); return false; },
  getFullResults: async () => null
});
stub('services/inHouse/lighthouseAudit.js', {
  runLighthouseAudit: (url, { signal } = {}) => { fast.lighthouse.push(signal); return waitForAbort(signal, 'lighthouse'); }
});
stub('services/inHouse/pageCapture.js', {
  runPageCapture: (url, _t, { signal } = {}) => { fast.capture.push(signal); return waitForAbort(signal, 'capture'); }
});

// ─── Fake ZAP ────────────────────────────────────────────────────────────────
function fakeZap({ spiderStatus = '10', ajaxStatus = 'stopped' } = {}) {
  const state = { calls: [] };
  const json = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const p = new URL(req.url, 'http://zap').pathname;
      state.calls.push({ path: p, at: Date.now() });
      if (p === '/JSON/context/action/newContext/') return json(res, 200, { contextId: '7' });
      if (p === '/JSON/replacer/view/rules/') return json(res, 200, { rules: [] });
      if (p === '/JSON/spider/action/scan/') return json(res, 200, { scan: '1' });
      if (p === '/JSON/spider/view/status/') return json(res, 200, { status: spiderStatus });
      if (p === '/JSON/spider/view/results/') return json(res, 200, { results: [] });
      if (p === '/JSON/ajaxSpider/view/status/') return json(res, 200, { status: ajaxStatus });
      if (p === '/JSON/core/view/urls/') return json(res, 200, { urls: [] });
      if (p === '/JSON/pscan/view/recordsToScan/') return json(res, 200, { recordsToScan: '0' });
      if (p === '/JSON/ascan/action/scan/') return json(res, 200, { scan: '3' });
      if (p === '/JSON/ascan/view/status/') return json(res, 200, { status: '100' });
      if (p === '/JSON/core/view/numberOfAlerts/') return json(res, 200, { numberOfAlerts: '0' });
      if (p === '/JSON/core/view/alerts/') return json(res, 200, { alerts: [] });
      if (p === '/JSON/search/view/urlsByUrlRegex/') return json(res, 200, { urlsByUrlRegex: [] });
      if (p === '/OTHER/core/other/htmlreport/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<html></html>'); }
      return json(res, 200, { Result: 'OK' });
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({
    server, state, url: `http://127.0.0.1:${server.address().port}`,
    close() { server.closeAllConnections(); server.close(); },
    callsSince(t) { return state.calls.filter(c => c.at >= t).map(c => c.path); }
  })));
}

async function waitFor(pred, what, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return;
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const TARGET = 'https://target.test/';
let seq = 0;
function newScan(fields = {}) {
  const scanId = `zap-auth-stoptest-${++seq}`;
  docs.set(scanId, {
    analysisId: scanId, userId: 'u1', target: TARGET, status: 'pending',
    authScanResult: { status: 'running', phase: 'queued' }, ...fields
  });
  return scanId;
}

// The module-level ZAP client (the one the old stop used) points here. Nothing may
// ever reach it from a stop: in production it is whichever scan holds the auth ZAP.
let sharedZap;
let svc;
let fastSvc;
let vault;
test.before(async () => {
  sharedZap = await fakeZap();
  process.env.ZAP_AUTH_API_URL = sharedZap.url;
  svc = require('../services/zapAuthService');
  fastSvc = require('../services/authFastScanService');
  vault = require('../services/scanCredentialVault');
});
test.after(() => { sharedZap.close(); });

test('a stop ends a running worker at once and revokes ZAP before answering', async () => {
  const zap = await fakeZap({ spiderStatus: '10' });
  const scanId = newScan();
  const run = svc.runAuthenticatedScanBackground(TARGET, 'https://target.test/login', [], scanId, 'u1', zap.url, null);
  await waitFor(() => zap.state.calls.some(c => c.path === '/JSON/spider/action/scan/'), 'spider start');

  const t0 = Date.now();
  const result = await svc.stopAuthScan(scanId, 'u1');
  const outcome = await run;
  const elapsed = Date.now() - t0;

  assert.equal(result.success, true);
  assert.equal(result.workerStopped, true, 'the stop waited for the worker to exit');
  assert.deepEqual(outcome, { success: false, reason: 'stopped' });
  // The spider loop sleeps 3 s between polls; a stop must not wait it out.
  assert.ok(elapsed < 1500, `worker exited ${elapsed}ms after the stop`);

  const after = zap.callsSince(t0);
  assert.ok(after.includes('/JSON/ascan/action/stopAllScans/'), 'active scan halted');
  assert.ok(after.includes('/JSON/spider/action/stopAllScans/'), 'spider halted');
  assert.ok(after.includes('/JSON/core/action/newSession/'), 'session discarded (credentials revoked)');
  for (const p of ['/JSON/ajaxSpider/action/scan/', '/JSON/ascan/action/scan/', '/JSON/core/view/alerts/']) {
    assert.ok(!after.includes(p), `no further scan work after the stop (${p})`);
  }

  const doc = docs.get(scanId);
  assert.equal(doc.status, 'stopped');
  assert.equal(doc.authScanResult.status, 'stopped');
  assert.equal(svc._runningWorkers.has(scanId), false, 'worker deregistered');
  assert.deepEqual(fast.webCheckStopped.slice(-1), [scanId], 'WebCheck halted');
  assert.ok(published.some(p => p.id === scanId && p.data.status === 'stopped'), 'other tabs told');
  assert.equal(sharedZap.state.calls.length, 0, 'nothing sent to the shared ZAP client');
  zap.close();
});

test('a stop during the AJAX spider is not swallowed by that phase\'s error handler', async () => {
  const zap = await fakeZap({ spiderStatus: '100', ajaxStatus: 'running' });
  const scanId = newScan();
  const run = svc.runAuthenticatedScanBackground(TARGET, null, [], scanId, 'u1', zap.url, null);
  await waitFor(() => zap.state.calls.some(c => c.path === '/JSON/ajaxSpider/action/scan/'), 'AJAX spider start', 20000);

  const t0 = Date.now();
  await svc.stopAuthScan(scanId, 'u1');
  assert.deepEqual(await run, { success: false, reason: 'stopped' });

  const after = zap.callsSince(t0);
  // Before the fix the AJAX phase's catch swallowed the stop and the worker carried
  // on past it — first to the post-AJAX URL count, then into the passive scan.
  assert.ok(!after.includes('/JSON/core/view/urls/'), 'the AJAX phase did not swallow the stop');
  assert.ok(!after.includes('/JSON/pscan/view/recordsToScan/'), 'passive phase never entered');
  assert.ok(!after.includes('/JSON/ascan/action/scan/'), 'active scan never started');
  assert.equal(docs.get(scanId).status, 'stopped');
  zap.close();
});

test('a scan stopped while queued sends nothing to ZAP and can never start afterwards', async () => {
  const scanId = newScan({ status: 'queued', authScanResult: { status: 'provisioning', phase: 'provisioning' } });
  const before = sharedZap.state.calls.length;

  const result = await svc.stopAuthScan(scanId, 'u1');
  assert.equal(result.success, true);
  assert.equal(result.workerStopped, true, 'no worker to wait for');
  assert.equal(sharedZap.state.calls.length, before, 'the shared ZAP was not touched');
  assert.equal(await svc.isAuthScanCancelled(scanId), true);

  // The provisioning path reaches the start afterwards — it must refuse.
  let completed = false;
  const zap = await fakeZap();
  const started = await svc.startAsyncAuthScan(TARGET, null, [], scanId, 'u1', zap.url, () => { completed = true; }, null);
  assert.equal(started.status, 'not_started');
  await new Promise(r => setTimeout(r, 200));
  assert.equal(zap.state.calls.length, 0, 'no scan ran');
  assert.equal(completed, false, 'onComplete is not fired for a scan that never started');
  assert.equal(docs.get(scanId).status, 'stopped', 'not resurrected to pending');
  zap.close();
});

test('stopping twice is a no-op, and another user cannot stop the scan', async () => {
  const scanId = newScan({ status: 'queued' });
  await assert.rejects(svc.stopAuthScan(scanId, 'someone-else'), /not found/);
  assert.equal(docs.get(scanId).status, 'queued');

  await svc.stopAuthScan(scanId, 'u1');
  const publishes = published.filter(p => p.id === scanId).length;
  const again = await svc.stopAuthScan(scanId, 'u1');
  assert.equal(again.alreadyStopped, true);
  assert.equal(again.status, 'stopped');
  assert.equal(published.filter(p => p.id === scanId).length, publishes, 'the repeat did nothing');

  // A finished scan is not turned into a stopped one.
  const done = newScan({ status: 'completed' });
  const r = await svc.stopAuthScan(done, 'u1');
  assert.equal(r.alreadyStopped, true);
  assert.equal(docs.get(done).status, 'completed');
});

test('a stop that lands while the report is saved is not overwritten by "combining"', async () => {
  const zap = await fakeZap({ spiderStatus: '100', ajaxStatus: 'stopped' });
  const scanId = newScan();
  // A stop from another process: only the database knows (no in-process signal).
  gridfs.onUpload = (filename) => {
    if (filename.includes(scanId) && filename.endsWith('.json')) docs.get(scanId).status = 'stopped';
  };
  try {
    const outcome = await svc.runAuthenticatedScanBackground(TARGET, null, [], scanId, 'u1', zap.url, null);
    assert.deepEqual(outcome, { success: false, reason: 'stopped' });
  } finally {
    gridfs.onUpload = null;
  }
  const doc = docs.get(scanId);
  assert.equal(doc.status, 'stopped', 'still stopped — it used to become combining, then completed and billed');
  assert.notEqual(doc.authScanResult.status, 'completed');
  assert.deepEqual(deleted.filter(id => id.includes(scanId)).sort(), [
    `file-zap_auth_detailed_alerts_${scanId}.json`,
    `file-zap_auth_report_${scanId}.html`
  ], 'the orphaned report files are removed');
  zap.close();
});

test('a stop aborts the fast scanners\' browser checks and never starts WebCheck', async () => {
  const scanId = newScan({ authScanResult: { status: 'running', authMethod: 'basic' } });
  vault.put(scanId, { username: 'alice', password: 'pw-fast-Secr3t', origin: 'https://target.test' });

  const run = fastSvc.ensureAuthFastScans(scanId, 'u1');
  await waitFor(() => fast.lighthouse.length && fast.capture.length, 'browser checks to start');
  const [lhSignal] = fast.lighthouse.slice(-1);

  const result = await svc.stopAuthScan(scanId, 'u1');
  assert.equal(result.fastScansStopped, true);
  assert.equal(lhSignal.aborted, true, 'the browser check was aborted, freeing the shared Chromium slot');
  assert.deepEqual(await run, { started: false, reason: 'stopped' });

  const doc = docs.get(scanId);
  assert.equal(doc.pagespeedResult, undefined, 'nothing written after the stop');
  assert.ok(!fast.webCheckStarted.includes(scanId), 'WebCheck never started');
  assert.equal(vault.get(scanId), null, 'credential purged');

  // And a stopped scan's fast scanners cannot be claimed again (status-poll self-heal).
  docs.get(scanId).fastScansStartedAt = null;
  assert.deepEqual(await fastSvc.ensureAuthFastScans(scanId, 'u1'), { started: false, reason: 'already-started' });
});

test('a stopped scan leaves the ZAP lock queue without taking or leaking the lock', async () => {
  const { withZapInstance } = require('../services/zapRecycler');

  // Another scan holds the auth instance.
  let releaseHolder;
  const holder = withZapInstance('auth', 'holder', () => new Promise(r => { releaseHolder = r; }));
  await new Promise(r => setTimeout(r, 50));

  // A queued scan is stopped while it waits.
  let stopped = false;
  let ran = false;
  setTimeout(() => { stopped = true; }, 100);
  const t0 = Date.now();
  const queued = await withZapInstance('auth', 'queued', async () => { ran = true; }, { isCancelled: async () => stopped });
  assert.equal(queued, undefined);
  assert.equal(ran, false, 'a stopped scan never runs');
  assert.ok(Date.now() - t0 < 8000, 'left the queue at the next check, not after the 30-minute wait');

  releaseHolder();
  await holder;

  // Stopped during the capacity wait / recycle: the check after it catches it.
  let checks = 0;
  const late = await withZapInstance('auth', 'late', async () => { ran = true; }, {
    isCancelled: async () => ++checks >= 3
  });
  assert.equal(late, undefined);
  assert.equal(ran, false);
  assert.equal(checks, 3, 'checked while queueing, on taking the lock, and after the recycle');

  // Nothing leaked: the next scan gets the instance immediately.
  const t1 = Date.now();
  assert.equal(await withZapInstance('auth', 'next', async () => 'ran'), 'ran');
  assert.ok(Date.now() - t1 < 1000, 'lock was free');

  // A failing status read must never abandon a live scan.
  assert.equal(await withZapInstance('auth', 'flaky', async () => 'ran', {
    isCancelled: async () => { throw new Error('db down'); }
  }), 'ran');
});
