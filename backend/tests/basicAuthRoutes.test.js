'use strict';

/**
 * Route-level behaviour of HTTP Basic auth: POST /api/zap-auth/test-basic,
 * the Basic branch of POST /api/zap-auth/scan, and the schedule refusal.
 * Executes the real handlers with the scan record, ZAP provisioning, the scan
 * worker and the probe stubbed (same idiom as historicalScanLoad.test.js).
 *
 * Run with: node --test backend/tests/basicAuthRoutes.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};

const records = new Map();
stub('models/ScanResult.js', {
  updateOne: async (filter, update) => {
    const id = filter.analysisId;
    const doc = records.get(id) || {};
    Object.assign(doc, update.$setOnInsert || {});
    for (const [k, v] of Object.entries(update.$set || {})) doc[k] = v;
    records.set(id, doc);
    return { matchedCount: 1 };
  },
  findOne: async () => null
});
stub('services/planService.js', { claimScanSlot: async () => true });
stub('services/zapCapacityManager.js', { markZapDemand: async () => {}, ensureZapCapacity: async () => {} });
const provisioning = { fail: false };
stub('services/zapContainerManager.js', {
  requestContainer: async () => { if (provisioning.fail) throw new Error('no capacity'); return { zapUrl: 'http://zap.invalid' }; },
  releaseContainer: async () => {}
});
stub('services/zapRecycler.js', { withZapInstance: async (_k, _id, fn) => fn() });
stub('services/authFastScanService.js', { ensureAuthFastScans: async () => ({ started: true }) });
const started = [];
stub('services/zapAuthService.js', {
  checkZapAuthHealth: async () => ({}),
  startAsyncAuthScan: async (...args) => { started.push(args); args[6] && args[6](args[3]); return { status: 'started' }; },
  getAuthScanStatus: async () => ({}),
  stopAuthScan: async () => ({}),
  isAuthScanCancelled: async () => false
});
const probeImpl = { next: null };
const realProbe = require('../services/basicAuthProbe');
stub('services/basicAuthProbe.js', { ...realProbe, probeBasicAuth: async (input) => probeImpl.next(input) });

const router = require('../routes/zapAuthRoutes');
const scheduleRouter = require('../routes/scheduleRoutes');
const vault = require('../services/scanCredentialVault');
const { checkScanTarget } = require('../utils/scanTargetGuard');

const handlerFor = (r, p, method) => {
  const layer = r.stack.find(l => l.route?.path === p && l.route.methods[method]);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle;
};
function call(handler, body) {
  return new Promise((resolve) => {
    const res = {
      statusCode: 200,
      status(c) { this.statusCode = c; return this; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); return this; }
    };
    handler({ body, user: { id: 'u1' }, organization: { _id: 'org1' }, params: {}, query: {} }, res);
  });
}
const testBasic = handlerFor(router, '/test-basic', 'post');
const startScan = handlerFor(router, '/scan', 'post');
const createSchedule = handlerFor(scheduleRouter, '/', 'post');

const PASS = 'R0ute-S3cret!';
const confirmed = (input) => ({ code: realProbe.CODES.CONFIRMED, origin: new URL(input.targetUrl).origin, verifyUrl: input.targetUrl, warnings: [], requests: 2, authenticatedRequests: 1, serverRealm: 'x' });

async function withConsoleCapture(fn) {
  const lines = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(orig)) console[k] = (...a) => { lines.push(a.map(String).join(' ')); };
  try { return { result: await fn(), lines }; } finally { Object.assign(console, orig); }
}
async function verifiedSession(targetUrl = 'https://site.example/') {
  probeImpl.next = confirmed;
  const r = await call(testBasic, { targetUrl, username: 'alice', password: PASS });
  assert.equal(r.status, 200);
  return r.body.tempSessionId;
}

test('test-basic: success returns a session id only — never the credential, never logged', async () => {
  probeImpl.next = confirmed;
  const { result: r, lines } = await withConsoleCapture(() => call(testBasic, { targetUrl: 'https://site.example/', username: 'alice', password: PASS }));
  assert.equal(r.status, 200);
  assert.equal(r.body.authConfirmed, 'confirmed');
  assert.match(r.body.tempSessionId, /^[0-9a-f-]{36}$/);
  assert.ok(!JSON.stringify(r.body).includes(PASS));
  assert.ok(!lines.join('\n').includes(PASS), 'password reached a log line');
  assert.ok(!lines.join('\n').includes(Buffer.from(`alice:${PASS}`).toString('base64')));
});

test('test-basic: probe failures map to stable codes; client errors are 400; nothing is stored', async () => {
  for (const [code, status] of [['BASIC_INVALID_CREDENTIALS', 200], ['BASIC_NOT_REQUIRED', 200], ['BASIC_REQUIRES_HTTPS', 400],
    ['URL_HAS_CREDENTIALS', 400], ['BASIC_INVALID_INPUT', 400], ['BLOCKED_TARGET', 400], ['BASIC_TARGET_FORBIDDEN', 200]]) {
    probeImpl.next = () => ({ code, warnings: [], requests: 0, authenticatedRequests: 0 });
    const r = await call(testBasic, { targetUrl: 'https://site.example/', username: 'a', password: PASS });
    assert.equal(r.status, status, code);
    assert.equal(r.body.errorCode, code);
    assert.equal(r.body.tempSessionId, undefined);
    assert.ok(!JSON.stringify(r.body).includes(PASS));
  }
});

test('scan (Basic): credential moves to the vault; the worker gets no password, no cookies, no login URL', async () => {
  vault._clear(); started.length = 0;
  const sid = await verifiedSession();
  const r = await call(startScan, { targetUrl: 'https://site.example/', tempSessionId: sid });
  assert.equal(r.status, 200);
  const scanId = r.body.scanId;
  await new Promise(res => setImmediate(res));
  const cred = vault.get(scanId);
  assert.ok(cred, 'credential in the vault for this scan');
  assert.equal(cred.origin, 'https://site.example');
  assert.equal(cred.password, PASS);
  assert.equal(records.get(scanId).authScanResult.authMethod, 'basic');
  assert.ok(!JSON.stringify(records.get(scanId)).includes(PASS), 'scan record holds the password');
  const [, loginUrl, cookies, sId, , , , authState] = started[0];
  assert.equal(sId, scanId);
  assert.equal(loginUrl, null);
  assert.deepEqual(cookies, []);
  assert.deepEqual(Object.keys(authState).sort(), ['authConfirmed', 'method', 'origin', 'reloginAttempts', 'verifyUrl']);
  assert.ok(!JSON.stringify(authState).includes(PASS));
  const again = await call(startScan, { targetUrl: 'https://site.example/', tempSessionId: sid });
  assert.equal(again.body.code, 'SESSION_EXPIRED', 'session is single-use');
  vault._clear();
});

test('scan (Basic): a different target origin than the one verified is refused', async () => {
  vault._clear();
  const sid = await verifiedSession('https://site.example/');
  for (const t of ['https://other.example/', 'https://site.example:8443/', 'https://sub.site.example/']) {
    const r = await call(startScan, { targetUrl: t, tempSessionId: sid });
    assert.equal(r.status, 400, t);
    assert.equal(r.body.code, 'BASIC_ORIGIN_MISMATCH');
  }
  assert.equal(vault.size(), 0, 'nothing put in the vault');
});

test('scan (Basic): a verified session expires after 15 minutes', async () => {
  const sid = await verifiedSession();
  const realNow = Date.now;
  Date.now = () => realNow() + 16 * 60 * 1000;
  try {
    const r = await call(startScan, { targetUrl: 'https://site.example/', tempSessionId: sid });
    assert.equal(r.body.code, 'SESSION_EXPIRED');
  } finally { Date.now = realNow; }
});

test('scan (Basic): provisioning failure purges the credential', async () => {
  vault._clear(); provisioning.fail = true;
  try {
    const sid = await verifiedSession();
    const r = await call(startScan, { targetUrl: 'https://site.example/', tempSessionId: sid });
    await new Promise(res => setTimeout(res, 20));
    assert.ok(!vault.has(r.body.scanId), 'credential survived a provisioning failure');
    assert.equal(records.get(r.body.scanId).status, 'failed');
  } finally { provisioning.fail = false; }
});

test('schedules refuse HTTP Basic (manual-only, no stored passwords)', async () => {
  const base = { scanType: 'authenticated', targetUrl: 'https://site.example/', scheduleType: 'one-time',
    scheduledAt: new Date(Date.now() + 86400000).toISOString(), timezone: 'Asia/Tokyo' };
  for (const authConfig of [{ authMethod: 'basic', username: 'a' }, { basic: { username: 'a' } }, { loginUrl: 'https://site.example/login', password: 'x' }]) {
    const r = await call(createSchedule, { ...base, authConfig });
    assert.equal(r.status, 400, JSON.stringify(authConfig));
    assert.equal(r.body.code, 'BASIC_AUTH_MANUAL_ONLY');
  }
});

test('URLs carrying credentials are refused everywhere targets are checked', () => {
  for (const u of ['https://user:pass@site.example/', 'https://user@site.example/', 'http://:pass@site.example/']) {
    assert.equal(checkScanTarget(u).code, 'URL_HAS_CREDENTIALS', u);
  }
  assert.equal(checkScanTarget('https://site.example/').ok, true);
});
