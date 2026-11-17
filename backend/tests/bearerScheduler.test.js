'use strict';

/**
 * Scheduled authenticated scans and token sessions: the real
 * schedulerService.triggerAuthenticatedScan (background login → scan hand-off)
 * with the login, the model layer and the ZAP start stubbed.
 *
 * Proves the scheduler applies the same Bearer policy as POST /test-login
 * (utils/bearerApiScope.js):
 *  - credit.villdesign.com's shape (no cookie, token to its onrender.com API)
 *    hands the scan exactly that API host, its vetted seeds, no logout URL;
 *  - a token sent to a shared third-party API is dropped — and when that was the
 *    only "session", the login counts as failed and the scan is labelled so;
 *  - a site that signed in with a session cookie is scanned with its cookies
 *    only, exactly as before Bearer support;
 *  - a login result without any `bearer` field (cookie-only, as before) is
 *    handed over unchanged;
 *  - no token reaches the scan record or the logs.
 *
 * Run with: node --test backend/tests/bearerScheduler.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};

// ─── Model layer ─────────────────────────────────────────────────────────────
const saved = new Map();
function ScanResultStub(data) { Object.assign(this, data); }
ScanResultStub.prototype.save = async function save() { saved.set(this.analysisId, JSON.parse(JSON.stringify(this))); return this; };
ScanResultStub.updateOne = async (filter, update) => {
  const doc = saved.get(filter.analysisId);
  if (doc && update.$set) Object.assign(doc, update.$set);
  return { matchedCount: doc ? 1 : 0 };
};
ScanResultStub.findOne = async () => null;
stub('models/ScanResult.js', ScanResultStub);
stub('models/ScheduledScan.js', { find: async () => [], updateOne: async () => ({}) });
stub('models/User.js', { findById: async () => null });
stub('models/Organization.js', { findById: async () => null });
stub('services/notificationService.js', {
  handleScanFailed: async () => {}, handleScheduledScanTriggered: async () => {}, emitScanStarted: () => {}
});
stub('services/pagespeedService.js', { getPageSpeedReport: async () => ({}) });
stub('services/observatoryService.js', { scanHost: async () => ({}) });
stub('services/urlscanService.js', { runUrlScan: async () => ({}) });
stub('services/zapService.js', { startAsyncZapScan: async () => ({}) });
stub('services/webCheckService.js', { startAsyncWebCheckScan: async () => ({}) });
stub('services/planService.js', { checkScanQuota: async () => ({ allowed: true }), claimScanSlot: async () => true });

// The login: what the real testLogin returns for each scenario.
let loginResult = null;
stub('services/loginTestService.js', { testLogin: async () => loginResult });

// The ZAP start: records exactly what the scan is handed.
const started = [];
stub('services/zapAuthService.js', {
  startAsyncAuthScan: async (targetUrl, loginUrl, cookies, scanId, userId, zapUrl, onComplete, authState) => {
    started.push({ targetUrl, loginUrl, cookies, scanId, authState });
    setImmediate(onComplete);
    return { status: 'started' };
  },
  isAuthScanCancelled: async () => false
});
stub('services/zapRecycler.js', { withZapInstance: async (_kind, _id, fn) => fn() });
stub('services/zapCapacityManager.js', { markZapDemand: async () => {}, ensureZapCapacity: async () => {} });
stub('services/authFastScanService.js', { ensureAuthFastScans: async () => ({ started: true }) });

const { triggerAuthenticatedScan } = require('../services/schedulerService');

const TARGET = 'https://credit.villdesign.com/';
const RENDER = 'https://credit-managment-managment.onrender.com';
const TOKEN = 'eyJhbGciOi.scheduled-user-token.Q1w2';
const STRIPE_TOKEN = 'sk_live_scheduled-shared-token-9';
const AUTH_CONFIG = {
  loginUrl: 'https://credit.villdesign.com/login',
  credentials: [{ selector: '#login-email', value: 'qa@example.test' }, { selector: '#login-password', value: 'pw-Secret-1' }],
  submitButton: 'button[type="submit"]'
};

let seq = 0;
async function runScheduled(result) {
  loginResult = result;
  const scanId = `sched-bearer-${++seq}`;
  const lines = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(orig)) console[k] = (...a) => { lines.push(a.map(String).join(' ')); };
  try {
    const out = await triggerAuthenticatedScan(scanId, TARGET, 'u1', AUTH_CONFIG, { scheduleId: 's1' }, 'org1');
    // The ZAP leg is detached (withZapInstance is not awaited): let it run.
    for (let i = 0; i < 20 && !started.some(s => s.scanId === scanId); i++) await new Promise(r => setImmediate(r));
    return { out, scanId, start: started.find(s => s.scanId === scanId) || null, doc: saved.get(scanId), lines };
  } finally {
    Object.assign(console, orig);
  }
}

const renderSession = {
  origin: RENDER, authorization: `Bearer ${TOKEN}`, verifyUrl: `${RENDER}/api/auth/logout`,
  seedUrls: [`${RENDER}/api/me`, `${RENDER}/api/applications?page=1`, `${RENDER}/api/auth/logout`]
};
const stripeSession = { origin: 'https://api.stripe.com', authorization: `Bearer ${STRIPE_TOKEN}`, seedUrls: [], verifyUrl: null };
const base = { authenticated: true, authConfirmed: 'confirmed', marker: 'Log out', markerCheckableInBody: false, markerConfidence: 'high' };

let R;
test.before(async () => {
  R = {};
  R.token = await runScheduled({ ...base, cookies: [], hasSessionCookie: false, bearer: [renderSession, stripeSession] });
  R.sharedOnly = await runScheduled({ ...base, cookies: [], hasSessionCookie: false, bearer: [stripeSession] });
  R.cookieAndToken = await runScheduled({
    ...base, cookies: [{ name: 'sid', value: 'scheduled-cookie-value' }], hasSessionCookie: true, bearer: [renderSession]
  });
  R.legacyCookie = await runScheduled({ ...base, cookies: [{ name: 'sid', value: 'scheduled-cookie-value' }] });
});

test('credit.villdesign.com shape: the scan gets the onrender.com API host with vetted seeds, nothing else', () => {
  const { start, doc } = R.token;
  assert.ok(start, 'the scan was started');
  assert.equal(start.targetUrl, TARGET);
  assert.deepEqual(start.cookies, []);
  assert.deepEqual(start.authState.bearer, [{
    origin: RENDER, authorization: `Bearer ${TOKEN}`,
    seedUrls: [`${RENDER}/api/me`, `${RENDER}/api/applications?page=1`],
    verifyUrl: `${RENDER}/api/me`
  }], 'shared third-party API dropped; logout seed and logout probe dropped');
  assert.equal(start.authState.recipe.loginUrl, AUTH_CONFIG.loginUrl);
  assert.equal(doc.authScanResult.loginOutcome, 'confirmed');
  assert.equal(doc.authScanResult.authVerified, true);
  assert.equal(doc.authScanResult.authDegraded, false);
});

test('a token sent only to a shared third-party API is no session: login failed, scan labelled, no authState', () => {
  const { start, doc, lines } = R.sharedOnly;
  assert.ok(start, 'a public scan still runs, labelled as one');
  assert.deepEqual(start.cookies, []);
  assert.equal(start.authState, null);
  assert.equal(doc.authScanResult.loginOutcome, 'failed');
  assert.equal(doc.authScanResult.authDegraded, true);
  assert.equal(doc.authScanResult.authDegradedReason, 'scheduled_login_failed');
  assert.ok(lines.some(l => /Background login failed .*no_session_cookies/.test(l)));
});

test('a site that signed in with a session cookie is scanned with its cookies only', () => {
  const { start, doc } = R.cookieAndToken;
  assert.deepEqual(start.cookies, [{ name: 'sid', value: 'scheduled-cookie-value' }]);
  assert.deepEqual(start.authState.bearer, [], 'no token host for a cookie site');
  assert.equal(doc.authScanResult.loginOutcome, 'confirmed');
});

test('a cookie-only login result (no bearer field) is handed over as before', () => {
  const { start } = R.legacyCookie;
  assert.deepEqual(start.cookies, [{ name: 'sid', value: 'scheduled-cookie-value' }]);
  assert.deepEqual(start.authState.bearer, []);
  assert.equal(start.authState.marker, 'Log out');
  assert.equal(start.authState.reloginAttempts, 0);
});

test('no token reaches the scan record or the logs', () => {
  for (const [name, r] of Object.entries(R)) {
    assert.ok(!JSON.stringify(r.doc).includes(TOKEN) && !JSON.stringify(r.doc).includes(STRIPE_TOKEN), `${name}: record`);
    const log = r.lines.join('\n');
    assert.ok(!log.includes(TOKEN) && !log.includes(STRIPE_TOKEN) && !log.includes('pw-Secret-1'), `${name}: logs`);
  }
});
