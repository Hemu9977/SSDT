'use strict';

/**
 * The real authenticated scan worker (zapAuthService.runAuthenticatedScanBackground,
 * unmodified) against a fake ZAP API server that records every call.
 *
 * Proves, for HTTP Basic and for the existing form-login flow:
 *   - the credential reaches ZAP only in a POST body, scoped and initiator-limited;
 *   - it is revoked on every exit (success, failure, cancellation, watchdog,
 *     missing credential) in the order Phase 0 showed is required:
 *     stop every scan → remove rules → newSession;
 *   - nothing stored (scan record, GridFS files) contains the credential;
 *   - two simultaneous scans with different credentials never mix.
 *
 * The scan record, GridFS and the completion service are in-memory stubs; ZAP is
 * a local HTTP server. No Docker, database or network beyond 127.0.0.1.
 *
 * Run with: node --test backend/tests/basicAuthScanLifecycle.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
process.env.ZAP_AUTH_API_KEY = 'test-zap-api-key';

// ─── In-memory scan records ──────────────────────────────────────────────────
const docs = new Map();
function applySet(doc, $set) {
  for (const [k, v] of Object.entries($set || {})) {
    const parts = k.split('.');
    let o = doc;
    while (parts.length > 1) { const p = parts.shift(); o[p] = o[p] || {}; o = o[p]; }
    o[parts[0]] = v;
  }
}
class Query {
  constructor(doc) { this.doc = doc; }
  select() { return this; }
  lean() { return Promise.resolve(this.doc ? JSON.parse(JSON.stringify(this.doc)) : null); }
  then(res, rej) { return Promise.resolve(this.doc).then(res, rej); }
}
function ScanResultStub(data) { Object.assign(this, data); }
ScanResultStub.prototype.save = async function () { docs.set(this.analysisId, this); return this; };
ScanResultStub.findOne = (filter) => new Query(docs.get(filter.analysisId) || null);
ScanResultStub.updateOne = async (filter, update) => {
  const doc = docs.get(filter.analysisId);
  if (doc) applySet(doc, update.$set);
  return { matchedCount: doc ? 1 : 0 };
};
const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};
stub('models/ScanResult.js', ScanResultStub);

const uploads = [];
const gridfs = {
  failFor: new Set(),
  uploadFile: async (buf, filename) => {
    const scanId = Object.keys(Object.fromEntries([...docs.keys()].map(k => [k, 1]))).find(id => filename.includes(id));
    if (scanId && gridfs.failFor.has(scanId)) throw new Error('injected storage failure');
    uploads.push({ filename, text: Buffer.from(buf).toString('utf8') });
    return `file-${uploads.length}`;
  }
};
stub('services/gridfsService.js', gridfs);
stub('services/scanProgressService.js', { publishScanProgress: async () => {} });
stub('services/geminiCompletionService.js', { checkAndGenerateGemini: async () => {} });

const zapAuthService = require('../services/zapAuthService');
const vault = require('../services/scanCredentialVault');
const { secretVariants } = require('../utils/credentialRedaction');

// ─── Fake ZAP ────────────────────────────────────────────────────────────────
function fakeZap({ secretForEvidence, authHeader, onCall = () => {}, ascanFails = false, searchCode = '200' }) {
  const state = { calls: [], rules: new Map(), insecureAuthRuleEnabled: true, keyMissing: 0 };
  const json = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://zap');
      const params = Object.fromEntries(u.searchParams);
      const form = req.method === 'POST' ? Object.fromEntries(new URLSearchParams(body)) : {};
      const p = u.pathname;
      if (req.headers['x-zap-api-key'] !== 'test-zap-api-key') state.keyMissing++;
      state.calls.push({ method: req.method, path: p, rawUrl: req.url, body, params, form });
      onCall(p, state);
      const all = { ...params, ...form };
      if (p === '/JSON/replacer/action/addRule/') {
        if (state.rules.has(all.description)) return json(res, 400, { code: 'already_exists' });
        state.rules.set(all.description, all);
        return json(res, 200, { Result: 'OK' });
      }
      if (p === '/JSON/replacer/action/removeRule/') {
        if (!state.rules.delete(all.description)) return json(res, 400, { code: 'does_not_exist' });
        return json(res, 200, { Result: 'OK' });
      }
      if (p === '/JSON/replacer/view/rules/') return json(res, 200, { rules: [...state.rules.values()] });
      if (p === '/JSON/pscan/action/disableScanners/' && all.ids === '10105') { state.insecureAuthRuleEnabled = false; return json(res, 200, { Result: 'OK' }); }
      if (p === '/JSON/pscan/action/enableScanners/' && all.ids === '10105') { state.insecureAuthRuleEnabled = true; return json(res, 200, { Result: 'OK' }); }
      if (p === '/JSON/context/action/newContext/') return json(res, 200, { contextId: '7' });
      if (p === '/JSON/spider/action/scan/') return json(res, 200, { scan: '1' });
      if (p === '/JSON/spider/view/status/') return json(res, 200, { status: '100' });
      if (p === '/JSON/spider/view/results/') return json(res, 200, { results: ['https://target.test/admin/'] });
      if (p === '/JSON/ajaxSpider/view/status/') return json(res, 200, { status: 'stopped' });
      if (p === '/JSON/core/view/urls/') return json(res, 200, { urls: ['https://target.test/', 'https://target.test/admin/'] });
      if (p === '/JSON/pscan/view/recordsToScan/') return json(res, 200, { recordsToScan: '0' });
      if (p === '/JSON/ascan/action/scan/') return ascanFails ? json(res, 500, { code: 'internal_error' }) : json(res, 200, { scan: '3' });
      if (p === '/JSON/ascan/view/status/') return json(res, 200, { status: '100' });
      if (p === '/JSON/core/view/numberOfAlerts/') return json(res, 200, { numberOfAlerts: '1' });
      if (p === '/JSON/search/view/urlsByUrlRegex/') {
        const start = Number(all.start || 0);
        const rows = start > 0 ? [] : Array.from({ length: 6 }, (_, i) => ({ id: String(i + 1), code: searchCode, url: 'https://target.test/admin/' }));
        return json(res, 200, { urlsByUrlRegex: rows });
      }
      if (p === '/JSON/core/view/alerts/') {
        const start = Number(all.start || 0);
        if (start > 0) return json(res, 200, { alerts: [] });
        return json(res, 200, { alerts: [{
          alert: 'Authentication Credentials Captured', risk: 'Medium', confidence: 'High', pluginId: '10105',
          description: 'd', solution: 's', url: 'https://target.test/admin/', messageId: '42',
          other: `revealing username [u] and password [${secretForEvidence}]`, evidence: authHeader || ''
        }] });
      }
      if (p === '/JSON/core/view/message/') {
        return json(res, 200, { message: {
          requestHeader: `GET https://target.test/admin/ HTTP/1.1\r\nHost: target.test\r\n${authHeader ? `Authorization: ${authHeader}\r\n` : ''}Cookie: sid=cookie-secret-123\r\n\r\n`,
          requestBody: '', responseHeader: 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=cookie-secret-456; HttpOnly\r\n\r\n', responseBody: 'ok'
        } });
      }
      if (p === '/JSON/core/view/messages/') return json(res, 200, { messages: [] });
      if (p === '/OTHER/core/other/htmlreport/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(`<td>password [${secretForEvidence}]</td><td>${authHeader || ''}</td>`); }
      return json(res, 200, { Result: 'OK' });
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, state, url: `http://127.0.0.1:${server.address().port}` })));
}

// ─── Scenario runner ─────────────────────────────────────────────────────────
const TARGET = 'https://target.test/';
const ORIGIN = 'https://target.test';
let seq = 0;

async function runScenario({ name, basic = true, cred = { username: 'alice', password: `pw-${name}-Secr3t` },
  putInVault = true, ascanFails = false, searchCode = '200', stopAt = null, stopStatus = 'stopped', failUpload = false, cookies = [] }) {
  const scanId = `zap-auth-lifecycle-${name}-${++seq}`;
  const authHeader = basic ? `Basic ${Buffer.from(`${cred.username}:${cred.password}`).toString('base64')}` : null;
  docs.set(scanId, { analysisId: scanId, status: 'running', target: TARGET, authScanResult: { status: 'running', ...(basic ? { authMethod: 'basic' } : {}) } });
  if (basic && putInVault) vault.put(scanId, { ...cred, origin: ORIGIN });
  if (failUpload) gridfs.failFor.add(scanId);
  const zap = await fakeZap({
    secretForEvidence: basic ? cred.password : 'cookie-secret-123',
    authHeader,
    ascanFails,
    searchCode,
    onCall: (p) => { if (stopAt && p === stopAt) docs.get(scanId).status = stopStatus; }
  });
  const authState = basic
    ? { method: 'basic', origin: ORIGIN, verifyUrl: 'https://target.test/admin/', authConfirmed: 'confirmed', reloginAttempts: 0 }
    : null;
  let outcome;
  try {
    outcome = await zapAuthService.runAuthenticatedScanBackground(TARGET, basic ? null : 'https://target.test/login', cookies, scanId, 'u1', zap.url, authState);
  } catch (err) {
    outcome = { threw: err.message };
  }
  // The scan client uses a keep-alive agent; drop its sockets or the process never exits.
  zap.server.closeAllConnections();
  zap.server.close();
  const secrets = basic ? secretVariants(cred) : ['cookie-secret-123', 'cookie-secret-456'];
  return { name, scanId, cred, secrets, authHeader, outcome, state: zap.state, doc: docs.get(scanId),
    uploads: uploads.filter(u => u.filename.includes(scanId)) };
}

function revocationOrder(calls) {
  // Indices within the tail of the call list (after the last scan-phase call).
  const tailStart = calls.map(c => c.path).lastIndexOf('/JSON/ascan/action/stopAllScans/');
  return { tailStart, tail: calls.slice(tailStart).map(c => c.path) };
}
const leakedIn = (text, secrets) => secrets.filter(s => text.includes(s));

let R;
test.before(async () => {
  const scenarios = await Promise.all([
    runScenario({ name: 'basic-success' }),
    runScenario({ name: 'basic-only401', searchCode: '401' }),
    runScenario({ name: 'basic-ascan-fails', ascanFails: true }),
    runScenario({ name: 'basic-cancelled', stopAt: '/JSON/spider/view/status/', stopStatus: 'stopped' }),
    runScenario({ name: 'basic-watchdog', stopAt: '/JSON/pscan/view/recordsToScan/', stopStatus: 'failed' }),
    runScenario({ name: 'basic-storage-fails', failUpload: true }),
    runScenario({ name: 'basic-no-vault', putInVault: false }),
    runScenario({ name: 'form-login', basic: false, cookies: [{ name: 'sid', value: 'cookie-secret-123' }] }),
    runScenario({ name: 'concurrent-a', cred: { username: 'tenant-a', password: 'AAAA-first-password' } }),
    runScenario({ name: 'concurrent-b', cred: { username: 'tenant-b', password: 'BBBB-second-password' } }),
  ]);
  R = Object.fromEntries(scenarios.map(s => [s.name, s]));
});

test('every ZAP call carries the API key', () => {
  for (const s of Object.values(R)) assert.equal(s.state.keyMissing, 0, `${s.name}: ${s.state.keyMissing} unkeyed calls`);
});

test('Basic: the credential reaches ZAP only in a POST body, scoped to the origin, scanner initiators only', () => {
  const s = R['basic-success'];
  const adds = s.state.calls.filter(c => c.path === '/JSON/replacer/action/addRule/');
  assert.equal(adds.length, 1);
  assert.equal(adds[0].method, 'POST');
  assert.equal(adds[0].form.replacement, s.authHeader);
  assert.equal(adds[0].form.initiators, '2,3,6,10');
  assert.equal(adds[0].form.url, '(?i)^https://target\\.test(:443)?(/.*)?$');
  assert.equal(adds[0].form.description, `auth_basic_${s.scanId}`);
  for (const sc of Object.values(R)) {
    for (const c of sc.state.calls) {
      assert.deepEqual(leakedIn(decodeURIComponent(c.rawUrl), sc.secrets), [], `${sc.name}: credential in URL ${c.path}`);
    }
  }
});

test('Basic: rule 10105 is off during the scan and back on afterwards', () => {
  const s = R['basic-success'];
  const seqPaths = s.state.calls.map(c => c.path);
  assert.ok(seqPaths.indexOf('/JSON/pscan/action/disableScanners/') < seqPaths.indexOf('/JSON/replacer/action/addRule/'));
  assert.equal(s.state.insecureAuthRuleEnabled, true);
  assert.ok(!R['form-login'].state.calls.some(c => c.path.startsWith('/JSON/pscan/action/')), 'form scans leave 10105 alone');
});

test('revocation runs on EVERY exit, in order: stop scans → remove rules → newSession', () => {
  for (const s of Object.values(R)) {
    const { tailStart, tail } = revocationOrder(s.state.calls);
    assert.ok(tailStart >= 0, `${s.name}: active scans never stopped`);
    const iStopSpider = tail.indexOf('/JSON/spider/action/stopAllScans/');
    const iStopAjax = tail.indexOf('/JSON/ajaxSpider/action/stop/');
    const iRules = tail.indexOf('/JSON/replacer/view/rules/');
    const iSession = tail.lastIndexOf('/JSON/core/action/newSession/');
    assert.ok(iStopSpider > 0 && iStopAjax > 0, `${s.name}: spiders not stopped`);
    assert.ok(iRules > iStopAjax, `${s.name}: rules removed before scans stopped`);
    assert.ok(iSession > iRules, `${s.name}: session not discarded after rule removal`);
    assert.equal(s.state.rules.size, 0, `${s.name}: rules left in ZAP: ${[...s.state.rules.keys()]}`);
  }
});

test('outcomes: success completes; failure, cancellation and watchdog end the worker cleanly', () => {
  assert.deepEqual(R['basic-success'].outcome, { success: true, scanId: R['basic-success'].scanId });
  assert.equal(R['basic-success'].doc.status, 'combining');
  assert.match(R['basic-ascan-fails'].outcome.threw || '', /status code 500/);
  assert.equal(R['basic-ascan-fails'].doc.status, 'failed');
  assert.deepEqual(R['basic-cancelled'].outcome, { success: false, reason: 'stopped' });
  assert.deepEqual(R['basic-watchdog'].outcome, { success: false, reason: 'stopped' });
  assert.match(R['basic-storage-fails'].outcome.threw || '', /injected storage failure/);
});

test('a lost credential (process restart) fails closed: no rule, no unauthenticated "authenticated" scan', () => {
  const s = R['basic-no-vault'];
  assert.match(s.outcome.threw || '', /Basic credentials unavailable/);
  assert.equal(s.doc.status, 'failed');
  assert.ok(!s.state.calls.some(c => c.path === '/JSON/replacer/action/addRule/'));
  assert.ok(!s.state.calls.some(c => c.path === '/JSON/spider/action/scan/'), 'no crawling without the credential');
});

test('nothing stored contains the credential: scan record, detailed alerts, HTML report', () => {
  for (const s of Object.values(R)) {
    assert.deepEqual(leakedIn(JSON.stringify(s.doc), s.secrets), [], `${s.name}: scan record`);
    for (const u of s.uploads) assert.deepEqual(leakedIn(u.text, s.secrets), [], `${s.name}: ${u.filename}`);
  }
  const ok = R['basic-success'];
  const detailed = ok.uploads.find(u => u.filename.includes('detailed_alerts'));
  assert.ok(detailed, 'detailed alerts stored');
  assert.match(detailed.text, /Authorization: Basic \[REDACTED\]/, 'header kept as evidence, value redacted');
  assert.match(detailed.text, /Cookie: sid=\[REDACTED\]/);
  assert.ok(ok.uploads.some(u => u.filename.includes('zap_auth_report_') && u.text.includes('[REDACTED]')), 'HTML report scrubbed');
});

test('Basic coverage: a scan that only met 401 is reported degraded, not authenticated', () => {
  const good = R['basic-success'].doc.authScanResult;
  assert.equal(good.authMethod, 'basic');
  assert.equal(good.authEvidence.verdict, 'authenticated');
  assert.equal(good.loginUrl, null);
  assert.ok(!good.authDegraded);
  const bad = R['basic-only401'].doc.authScanResult;
  assert.equal(bad.authEvidence.verdict, 'failed');
  assert.equal(bad.authDegraded, true);
  assert.equal(bad.authDegradedReason, 'basic_only_unauthorized');
  assert.equal(bad.authVerified, false);
});

test('vault: the ZAP leg releases its hold on every path', () => {
  for (const name of ['basic-success', 'basic-ascan-fails', 'basic-cancelled', 'basic-watchdog', 'basic-storage-fails']) {
    const id = R[name].scanId;
    assert.ok(vault.has(id), `${name}: the fast-scan holder should still be holding`);
    vault.release(id, 'fast');
    assert.ok(!vault.has(id), `${name}: entry should be gone once both holders released`);
  }
});

test('form login (regression): cookie rule by POST with scanner initiators, revoked, evidence redacted', () => {
  const s = R['form-login'];
  const add = s.state.calls.find(c => c.path === '/JSON/replacer/action/addRule/');
  assert.equal(add.method, 'POST');
  assert.equal(add.form.description, 'auth_cookie');
  assert.equal(add.form.matchString, 'Cookie');
  assert.equal(add.form.replacement, 'sid=cookie-secret-123');
  assert.equal(add.form.initiators, '2,3,6,10');
  assert.ok(!add.form.url, 'cookie rule scope unchanged (no url restriction added)');
  assert.ok(s.state.calls.some(c => c.path === '/JSON/core/action/accessUrl/' && c.params.url === 'https://target.test/login'), 'login URL still visited');
  assert.deepEqual(s.outcome, { success: true, scanId: s.scanId });
});

test('two simultaneous scans with different credentials never mix', () => {
  const a = R['concurrent-a'], b = R['concurrent-b'];
  const ruleA = a.state.calls.find(c => c.path === '/JSON/replacer/action/addRule/').form;
  const ruleB = b.state.calls.find(c => c.path === '/JSON/replacer/action/addRule/').form;
  assert.equal(ruleA.replacement, a.authHeader);
  assert.equal(ruleB.replacement, b.authHeader);
  assert.notEqual(ruleA.description, ruleB.description);
  const allA = JSON.stringify(a.state.calls) + JSON.stringify(a.doc) + a.uploads.map(u => u.text).join('');
  const allB = JSON.stringify(b.state.calls) + JSON.stringify(b.doc) + b.uploads.map(u => u.text).join('');
  assert.deepEqual(leakedIn(allA, b.secrets), [], 'scan A saw B\'s credential');
  assert.deepEqual(leakedIn(allB, a.secrets), [], 'scan B saw A\'s credential');
  vault.release(a.scanId, 'fast'); vault.release(b.scanId, 'fast');
});
