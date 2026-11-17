'use strict';

/**
 * Token sessions in the authenticated scan: the real worker
 * (zapAuthService.runAuthenticatedScanBackground) against a fake ZAP API that
 * records every call. Models credit.villdesign.com: a single-page app on one
 * origin whose session is a Bearer token it sends to an API on another origin
 * (credit-managment-managment.onrender.com in production).
 *
 * Proves:
 *  - the token reaches ZAP only in a POST body, as a Replacer rule scoped to the
 *    exact API origin, scanner initiators only, named per scan — and the rule
 *    never matches a logout-shaped URL;
 *  - scope: the site is scanned exactly as entered (url = target, site context,
 *    boundary-safe include regexes); each API host gets its own context (logout
 *    paths excluded) and its own active scan (url = that origin);
 *  - logout-shaped seeds / probes and shared third-party API hosts never reach ZAP;
 *  - findings on the API host are collected, and alerts on look-alike hosts
 *    (`<host>.evil.net`) are not;
 *  - the session is checked through the app's own "who am I" call and, when the
 *    token stops working, renewed by logging in again (rule replaced, new token
 *    scrubbed too) — never widening to new origins;
 *  - an API that only ever answered 401 is reported degraded, not authenticated;
 *  - on every exit — success, failure, a refused API scan, a user stop mid-API
 *    scan — every rule and context is revoked (stop → remove → newSession) and
 *    the token appears in no stored output or URL;
 *  - cookie-only scans make the same requests they made before.
 *
 * Run with: node --test backend/tests/bearerScanLifecycle.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
process.env.ZAP_AUTH_API_KEY = 'test-zap-api-key';

// ─── In-memory scan records / storage ───────────────────────────────────────
const docs = new Map();
function applySet(doc, $set) {
  for (const [k, v] of Object.entries($set || {})) {
    const parts = k.split('.');
    let o = doc;
    while (parts.length > 1) { const p = parts.shift(); o[p] = o[p] || {}; o = o[p]; }
    o[parts[0]] = v;
  }
}
const TERMINAL = ['stopped', 'cancelled', 'failed', 'completed'];
class Query {
  constructor(doc) { this.doc = doc; }
  select() { return this; }
  lean() { return Promise.resolve(this.doc ? JSON.parse(JSON.stringify(this.doc)) : null); }
  then(res, rej) { return Promise.resolve(this.doc).then(res, rej); }
}
function ScanResultStub(data) { Object.assign(this, data); }
ScanResultStub.findOne = (filter) => new Query(docs.get(filter.analysisId) || null);
ScanResultStub.updateOne = async (filter, update) => {
  const doc = docs.get(filter.analysisId);
  // Honour the `status: { $nin: [...] }` guards the worker and stop path rely on.
  const nin = filter.status && filter.status.$nin;
  if (!doc || (nin && nin.includes(doc.status))) return { matchedCount: 0 };
  applySet(doc, update.$set);
  return { matchedCount: 1 };
};
const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};
stub('models/ScanResult.js', ScanResultStub);
const uploads = [];
stub('services/gridfsService.js', {
  uploadFile: async (buf, filename) => { uploads.push({ filename, text: Buffer.from(buf).toString('utf8') }); return `file-${uploads.length}`; },
  deleteFile: async () => {}
});
stub('services/scanProgressService.js', { publishScanProgress: async () => {} });
stub('services/geminiCompletionService.js', { checkAndGenerateGemini: async () => {} });
// stopAuthScan halts these too; nothing of theirs runs in this test.
stub('services/authFastScanService.js', { stopAuthFastScans: () => false, ensureAuthFastScans: async () => ({}) });
stub('services/webCheckService.js', { stopWebCheckScan: () => false });
stub('services/zapContainerManager.js', { releaseContainer: async () => {}, requestContainer: async () => ({}) });

// Re-login: the real testLogin would drive a browser; here it returns a fresh token.
const relogins = [];
stub('services/loginTestService.js', {
  testLogin: async (opts) => {
    relogins.push(opts);
    return {
      authenticated: true, authConfirmed: 'confirmed', cookies: [],
      bearer: [
        { origin: API_ORIGIN, authorization: `Bearer ${NEW_TOKEN}`, seedUrls: [], verifyUrl: `${API_ORIGIN}/api/me` },
        // A new origin appearing at re-login must not widen the scan.
        { origin: 'https://other-api.example', authorization: 'Bearer other-origin-token-999', seedUrls: [], verifyUrl: null }
      ]
    };
  }
});

const zapAuthService = require('../services/zapAuthService');
const rules = require('../services/zapCredentialRules');

const TARGET = 'https://credit.example.test/';
const SITE_ORIGIN = 'https://credit.example.test';
const API_ORIGIN = 'https://api-host.example.test';
const OLD_TOKEN = 'eyJold.session-token-value.AAA111';
const NEW_TOKEN = 'eyJnew.session-token-value.BBB222';
const STRIPE_TOKEN = 'sk_live_shared-provider-token-777';
const COOKIE = 'cookie-secret-value-123';

// Java `(?i)` → JS flag, so the regexes ZAP receives can be exercised here.
const asJs = (javaRegex) => new RegExp(javaRegex.replace(/^\(\?i\)/, ''), javaRegex.startsWith('(?i)') ? 'i' : '');

// ─── Fake ZAP ────────────────────────────────────────────────────────────────
function fakeZap({ probeCodes = ['200'], apiCode = '200', failApiScanStart = false, failHtmlReport = false, onApiScanStart = null } = {}) {
  const state = { calls: [], rules: new Map(), probes: [...probeCodes], contexts: new Map(), scans: new Map() };
  const json = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://zap');
      const params = Object.fromEntries(u.searchParams);
      const form = req.method === 'POST' ? Object.fromEntries(new URLSearchParams(body)) : {};
      const all = { ...params, ...form };
      const p = u.pathname;
      state.calls.push({ method: req.method, path: p, rawUrl: req.url, params, form });
      if (p === '/JSON/replacer/action/addRule/') {
        if (state.rules.has(all.description)) return json(res, 400, { code: 'already_exists' });
        state.rules.set(all.description, all); return json(res, 200, { Result: 'OK' });
      }
      if (p === '/JSON/replacer/action/removeRule/') {
        if (!state.rules.delete(all.description)) return json(res, 400, { code: 'does_not_exist' });
        return json(res, 200, { Result: 'OK' });
      }
      if (p === '/JSON/replacer/view/rules/') return json(res, 200, { rules: [...state.rules.values()] });
      if (p === '/JSON/context/action/newContext/') {
        const id = String(7 + state.contexts.size);
        state.contexts.set(all.contextName, { id, include: [], exclude: [] });
        return json(res, 200, { contextId: id });
      }
      if (p === '/JSON/context/action/includeInContext/') { state.contexts.get(all.contextName)?.include.push(all.regex); return json(res, 200, { Result: 'OK' }); }
      if (p === '/JSON/context/action/excludeFromContext/') { state.contexts.get(all.contextName)?.exclude.push(all.regex); return json(res, 200, { Result: 'OK' }); }
      if (p === '/JSON/context/action/removeContext/') {
        if (!state.contexts.delete(all.contextName)) return json(res, 400, { code: 'context_not_found' });
        return json(res, 200, { Result: 'OK' });
      }
      if (p === '/JSON/core/action/newSession/') { state.contexts.clear(); return json(res, 200, { Result: 'OK' }); }
      if (p === '/JSON/spider/action/scan/') return json(res, 200, { scan: '1' });
      if (p === '/JSON/spider/view/status/') return json(res, 200, { status: '100' });
      if (p === '/JSON/spider/view/results/') return json(res, 200, { results: [] });
      if (p === '/JSON/ajaxSpider/view/status/') return json(res, 200, { status: 'stopped' });
      if (p === '/JSON/core/view/urls/') return json(res, 200, { urls: [TARGET] });
      if (p === '/JSON/pscan/view/recordsToScan/') return json(res, 200, { recordsToScan: '0' });
      if (p === '/JSON/ascan/action/scan/') {
        const isApi = all.url === API_ORIGIN;
        if (isApi && failApiScanStart) return json(res, 400, { code: 'url_not_found', message: 'URL Not Found in the Scan Tree' });
        const id = String(3 + state.scans.size);
        state.scans.set(id, { url: all.url, contextId: all.contextId, isApi });
        if (isApi && onApiScanStart) setImmediate(onApiScanStart);
        return json(res, 200, { scan: id });
      }
      if (p === '/JSON/ascan/view/status/') {
        const scan = state.scans.get(all.scanId);
        // A user stop arrives while the API scan runs: it never reaches 100 here.
        return json(res, 200, { status: scan && scan.isApi && onApiScanStart ? '50' : '100' });
      }
      if (p === '/JSON/search/view/urlsByUrlRegex/') {
        if (Number(all.start || 0) > 0) return json(res, 200, { urlsByUrlRegex: [] });
        // Exact-URL lookups are the session probe; origin regexes are coverage.
        if (/\$$/.test(all.regex) && /^\^/.test(all.regex)) {
          const code = state.probes.length > 1 ? state.probes.shift() : state.probes[0];
          return json(res, 200, { urlsByUrlRegex: [{ id: String(state.calls.length), code }] });
        }
        return json(res, 200, { urlsByUrlRegex: Array.from({ length: 5 }, (_, i) => ({ id: String(i + 1), code: apiCode })) });
      }
      if (p === '/JSON/core/view/alerts/') {
        if (Number(all.start || 0) > 0) return json(res, 200, { alerts: [] });
        if (String(all.baseurl).startsWith(API_ORIGIN)) {
          return json(res, 200, { alerts: [
            { id: '20', alert: 'SQL Injection', risk: 'High', confidence: 'Medium', pluginId: '40018',
              description: 'd', solution: 's', url: `${API_ORIGIN}/api/applications?page=1`, messageId: '42', param: 'page',
              other: `token seen: ${OLD_TOKEN} / ${NEW_TOKEN}`, evidence: `Bearer ${OLD_TOKEN}` },
            // ZAP's baseurl is a prefix match: a look-alike host must not be reported.
            { id: '21', alert: 'Lookalike API Finding', risk: 'High', confidence: 'High', pluginId: '1',
              description: 'd', solution: 's', url: `${API_ORIGIN}.evil.net/x`, messageId: '43', other: '', evidence: '' }
          ] });
        }
        return json(res, 200, { alerts: [
          { id: '10', alert: 'Content Security Policy Header Not Set', risk: 'Medium', confidence: 'High', pluginId: '10038',
            description: 'd', solution: 's', url: TARGET, messageId: '41', other: '', evidence: '' },
          { id: '11', alert: 'Lookalike Site Finding', risk: 'High', confidence: 'High', pluginId: '1',
            description: 'd', solution: 's', url: 'https://credit.example.test.evil.net/', messageId: '44', other: '', evidence: '' }
        ] });
      }
      if (p === '/JSON/core/view/message/') {
        return json(res, 200, { message: {
          requestHeader: `GET ${API_ORIGIN}/api/applications?page=1 HTTP/1.1\r\nHost: api-host.example.test\r\nAuthorization: Bearer ${OLD_TOKEN}\r\nCookie: sid=${COOKIE}\r\n\r\n`,
          requestBody: '', responseHeader: 'HTTP/1.1 200 OK\r\n\r\n', responseBody: `{"echo":"${NEW_TOKEN}"}`
        } });
      }
      if (p === '/JSON/core/view/messages/') return json(res, 200, { messages: [] });
      if (p === '/OTHER/core/other/htmlreport/') {
        if (failHtmlReport) return json(res, 400, { code: 'internal_error' });
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(`<td>Bearer ${OLD_TOKEN}</td><td>${NEW_TOKEN}</td><td>${COOKIE}</td>`);
      }
      return json(res, 200, { Result: 'OK' });
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, state, url: `http://127.0.0.1:${server.address().port}` })));
}

const apiSession = (extra = {}) => ({
  origin: API_ORIGIN, authorization: `Bearer ${OLD_TOKEN}`,
  seedUrls: [`${API_ORIGIN}/api/me`, `${API_ORIGIN}/api/applications?page=1`], verifyUrl: `${API_ORIGIN}/api/me`,
  ...extra
});

let seq = 0;
async function runScenario({ name, bearer, cookies = [], probeCodes, apiCode, zapOpts = {}, stopDuringApiScan = false }) {
  const scanId = `zap-auth-bearer-${name}-${++seq}`;
  docs.set(scanId, { analysisId: scanId, userId: 'u1', status: 'running', target: TARGET, authScanResult: { status: 'running' } });
  let stopResult = null;
  const zap = await fakeZap({
    probeCodes, apiCode, ...zapOpts,
    ...(stopDuringApiScan ? { onApiScanStart: () => { zapAuthService.stopAuthScan(scanId, 'u1', { waitMs: 20000 }).then(r => { stopResult = r; }); } } : {})
  });
  const authState = {
    marker: 'Log out', markerCheckableInBody: false, markerConfidence: 'high', authConfirmed: 'confirmed', reloginAttempts: 0,
    recipe: { loginUrl: 'https://credit.example.test/login', credentials: [{ selector: '#e', value: 'user@example.test' }] },
    bearer: bearer === undefined ? [apiSession()] : bearer
  };
  let outcome;
  try {
    outcome = await zapAuthService.runAuthenticatedScanBackground(TARGET, 'https://credit.example.test/login', cookies, scanId, 'u1', zap.url, authState);
  } catch (err) {
    outcome = { threw: err.message };
  }
  // Let a stop request that was waiting on the worker settle.
  for (let i = 0; i < 50 && stopDuringApiScan && !stopResult; i++) await new Promise(r => setTimeout(r, 100));
  zap.server.closeAllConnections();
  zap.server.close();
  return { name, scanId, outcome, stopResult, state: zap.state, doc: docs.get(scanId), authState, uploads: uploads.filter(u => u.filename.includes(scanId)) };
}

// What each scan held, and so must have kept out of its output. (The fake
// report quotes all of them; a scan can only scrub the secrets it actually had.)
const SECRETS_OF = {
  ok: [OLD_TOKEN], relogin: [OLD_TOKEN, NEW_TOKEN], api401: [OLD_TOKEN], cookie: [COOKIE],
  failed: [OLD_TOKEN], apiNotStarted: [OLD_TOKEN], stopped: [OLD_TOKEN], sameOrigin: [OLD_TOKEN]
};
const ALL_SECRETS = [OLD_TOKEN, NEW_TOKEN, COOKIE, STRIPE_TOKEN];
const leaked = (text, secrets = ALL_SECRETS) => secrets.filter(x => text.includes(x));
const calls = (s, p) => s.state.calls.filter(c => c.path === p);
const withoutKey = ({ apikey, ...rest }) => rest; // eslint-disable-line no-unused-vars

let R;
test.before(async () => {
  // Independent scans (own fake ZAP, own scan id), run side by side.
  const scenarios = [
    // credit.villdesign.com's shape, plus what must be dropped before ZAP: a
    // logout-shaped seed and probe, and a token sent to a shared third-party API.
    { name: 'ok', bearer: [
      apiSession({ seedUrls: [`${API_ORIGIN}/api/me`, `${API_ORIGIN}/api/applications?page=1`, `${API_ORIGIN}/api/auth/logout`, `${API_ORIGIN}/api/session/signOut?all=1`] }),
      { origin: 'https://api.stripe.com', authorization: `Bearer ${STRIPE_TOKEN}`, seedUrls: ['https://api.stripe.com/v1/customers'], verifyUrl: 'https://api.stripe.com/v1/customers' }
    ] },
    { name: 'relogin', probeCodes: ['401', '200'] },
    { name: 'api401', apiCode: '401' },
    { name: 'cookie', bearer: [], cookies: [{ name: 'sid', value: COOKIE }] },
    // Fails after the token rule, the seeds and both active scans: at the report.
    { name: 'failed', zapOpts: { failHtmlReport: true } },
    // ZAP refuses the API scan (no seed reached the sites tree).
    { name: 'apiNotStarted', zapOpts: { failApiScanStart: true } },
    // The customer presses Stop while the API host is being scanned.
    { name: 'stopped', stopDuringApiScan: true },
    // A token the app sends to the site's own origin: no API host, no extra scan.
    { name: 'sameOrigin', bearer: [{
      origin: SITE_ORIGIN, authorization: `Bearer ${OLD_TOKEN}`,
      seedUrls: [`${SITE_ORIGIN}/api/me`, `${SITE_ORIGIN}/logout`], verifyUrl: `${SITE_ORIGIN}/logout`
    }] }
  ];
  const results = await Promise.all(scenarios.map(runScenario));
  R = Object.fromEntries(results.map(r => [r.name, r]));
});

test('the scan completes for a token session', () => {
  assert.deepEqual(R.ok.outcome, { success: true, scanId: R.ok.scanId });
  assert.equal(R.ok.doc.status, 'combining');
});

test('the token reaches ZAP only as a POST rule scoped to the exact API origin, never on a logout path', () => {
  const adds = calls(R.ok, '/JSON/replacer/action/addRule/');
  assert.equal(adds.length, 1, 'one rule: the shared third-party API token never reaches ZAP');
  const [add] = adds;
  assert.equal(add.method, 'POST');
  assert.equal(add.form.description, `auth_bearer_${R.ok.scanId}_0`);
  assert.equal(add.form.matchType, 'REQ_HEADER');
  assert.equal(add.form.matchString, 'Authorization');
  assert.equal(add.form.replacement, `Bearer ${OLD_TOKEN}`);
  assert.equal(add.form.initiators, '2,3,6,10');
  assert.equal(add.form.url, rules.bearerRuleRegex(API_ORIGIN));
  const rx = asJs(add.form.url);
  for (const ok of [`${API_ORIGIN}`, `${API_ORIGIN}/`, `${API_ORIGIN}/api/me`, `${API_ORIGIN}:443/api/applications?page=1`, `${API_ORIGIN}/api/users?next=/logout`]) {
    assert.ok(rx.test(ok), `token applies to ${ok}`);
  }
  for (const no of [`${API_ORIGIN}/api/auth/logout`, `${API_ORIGIN}/api/signOut`, `${API_ORIGIN}:443/LOGOUT`, `${API_ORIGIN}/api/tokens/revoke`,
    `${API_ORIGIN}/sessions/destroy`, `${API_ORIGIN}.evil.net/api/me`, `http://api-host.example.test/api/me`, `https://x.api-host.example.test/`]) {
    assert.ok(!rx.test(no), `token never applies to ${no}`);
  }
  for (const s of Object.values(R)) {
    for (const c of s.state.calls) assert.deepEqual(leaked(decodeURIComponent(c.rawUrl)), [], `${s.name}: token in URL ${c.path}`);
    assert.ok(!calls(s, '/JSON/replacer/action/addRule/').some(c => /stripe/i.test(c.form.url || '') || c.form.replacement?.includes(STRIPE_TOKEN)));
  }
});

test('scope: the site context holds the site and its subdomains only, on a label boundary', () => {
  const site = R.ok.state.calls.filter(c => c.path === '/JSON/context/action/includeInContext/' && c.params.contextName === `auth_scan_${R.ok.scanId}`)
    .map(c => c.params.regex);
  assert.deepEqual(site, rules.siteScopeRegexes('credit.example.test'));
  const inSite = (url) => site.some(r => asJs(r).test(url));
  for (const yes of [TARGET, 'https://credit.example.test', 'http://credit.example.test:8080/a?b', 'https://www.credit.example.test/x']) assert.ok(inSite(yes), yes);
  for (const no of ['https://credit.example.test.evil.net/', 'https://x.credit.example.test.evil.net/a', 'https://evilcredit.example.test/',
    'https://credit.example.test@evil.net/', API_ORIGIN + '/api/me']) assert.ok(!inSite(no), no);
});

test('scope: the site is scanned exactly as entered; each API host gets its own context and its own scan', () => {
  const ascans = calls(R.ok, '/JSON/ascan/action/scan/').map(c => withoutKey(c.params));
  assert.equal(ascans.length, 2);
  const siteCtx = R.ok.state.calls.find(c => c.path === '/JSON/context/action/newContext/' && c.params.contextName === `auth_scan_${R.ok.scanId}`);
  assert.ok(siteCtx);
  assert.deepEqual(ascans[0], { url: TARGET, recurse: 'true', inScopeOnly: 'true', contextId: '7' }, 'the site scan is the request it always was');
  assert.deepEqual(ascans[1], { url: API_ORIGIN, recurse: 'true', inScopeOnly: 'true', contextId: '8' }, 'separate API scan');
  const apiIncludes = R.ok.state.calls.filter(c => c.path === '/JSON/context/action/includeInContext/' && c.params.contextName === `auth_api_${R.ok.scanId}_0`).map(c => c.params.regex);
  assert.deepEqual(apiIncludes, [rules.exactOriginRegex(API_ORIGIN)], 'exactly the API origin');
  const apiExcludes = R.ok.state.calls.filter(c => c.path === '/JSON/context/action/excludeFromContext/' && c.params.contextName === `auth_api_${R.ok.scanId}_0`).map(c => c.params.regex);
  assert.deepEqual(apiExcludes, rules.apiContextExcludeRegexes(API_ORIGIN));
  const ex = asJs(apiExcludes[0]);
  assert.ok(ex.test(`${API_ORIGIN}/api/auth/logout`) && ex.test(`${API_ORIGIN}/v1/SignOut`) && !ex.test(`${API_ORIGIN}/api/me`));
  // Only one API context: the shared third-party API got none.
  assert.equal(R.ok.state.calls.filter(c => c.path === '/JSON/context/action/newContext/').length, 2);
});

test('logout replay: logout-shaped seeds and probes, and shared third-party APIs, are never requested', () => {
  for (const s of Object.values(R)) {
    const accessed = calls(s, '/JSON/core/action/accessUrl/').map(c => c.params.url);
    assert.ok(!accessed.some(u => /logout|signout|stripe/i.test(u)), `${s.name}: ${accessed.join(', ')}`);
    const probes = calls(s, '/JSON/search/view/urlsByUrlRegex/').map(c => c.params.regex).filter(r => /^\^/.test(r));
    assert.ok(!probes.some(r => /logout|signout/i.test(r)), `${s.name}: probe on a logout URL`);
  }
  const accessed = calls(R.ok, '/JSON/core/action/accessUrl/').map(c => c.params.url);
  assert.ok(accessed.includes(`${API_ORIGIN}/api/me`));
  assert.ok(accessed.includes(`${API_ORIGIN}/api/applications?page=1`));
  assert.deepEqual(R.ok.authState.bearer.map(b => b.origin), [API_ORIGIN]);
});

test('findings on the API host are collected alongside the site; look-alike hosts are not', () => {
  const bases = calls(R.ok, '/JSON/core/view/alerts/').map(c => c.params.baseurl);
  assert.deepEqual(bases, [TARGET, `${API_ORIGIN}/`], 'API base ends in "/" so the prefix match cannot reach api-host.example.test.evil.net');
  const detailed = R.ok.uploads.find(u => u.filename.includes('detailed_alerts'));
  assert.ok(detailed && detailed.text.includes('SQL Injection'), 'API finding stored');
  assert.ok(detailed.text.includes('Content Security Policy'), 'site finding stored');
  assert.ok(!detailed.text.includes('Lookalike'), 'no finding from a look-alike host');
  assert.ok(!JSON.stringify(R.ok.doc).includes('Lookalike'));
});

test('session health: the "who am I" probe confirms the token; host names and API scans are recorded', () => {
  const a = R.ok.doc.authScanResult;
  assert.equal(a.authVerifiedReason, 'bearer_accepted');
  assert.equal(a.authVerifiedPhase, 'before_api_scan', 'checked again before the API scan');
  assert.equal(a.sessionKind, 'bearer');
  assert.deepEqual(a.authHosts, ['api-host.example.test']);
  assert.equal(a.apiAuthEvidence[0].verdict, 'authenticated');
  assert.deepEqual(a.apiScans, [{ host: 'api-host.example.test', status: 'completed' }]);
  assert.ok(!a.authDegraded);
  assert.equal(relogins.length, 1, 'only the relogin scenario logged in again');
});

test('a token that stops working is renewed by logging in again — same origins only, new token scrubbed too', () => {
  const s = R.relogin;
  const adds = calls(s, '/JSON/replacer/action/addRule/').filter(c => c.form.description.startsWith('auth_bearer_'));
  assert.equal(adds.length, 2, 'initial rule + renewed rule');
  assert.equal(adds[1].form.replacement, `Bearer ${NEW_TOKEN}`);
  assert.equal(adds[1].form.description, adds[0].form.description, 'replaced, not added alongside');
  assert.equal(adds[1].form.url, rules.bearerRuleRegex(API_ORIGIN), 'the renewed rule keeps the logout exclusion');
  assert.ok(!adds.some(c => /other-api/.test(c.form.url || '')), 'a re-login never widens the scan');
  assert.equal(s.doc.authScanResult.authRepaired, true);
  assert.deepEqual(s.authState.bearer.map(b => b.origin), [API_ORIGIN]);
  assert.equal(calls(s, '/JSON/ascan/action/scan/').filter(c => c.params.url === 'https://other-api.example').length, 0);
});

test('an API that only ever answered 401 is degraded, not authenticated', () => {
  const a = R.api401.doc.authScanResult;
  assert.equal(a.authDegraded, true);
  assert.equal(a.authDegradedReason, 'api_only_unauthorized');
  assert.equal(a.authVerified, false);
});

test('failure: a scan that fails after the token was injected is marked failed and the token revoked', () => {
  const s = R.failed;
  assert.ok(s.outcome.threw, 'the worker reports the failure');
  assert.equal(s.doc.status, 'failed');
  assert.equal(s.doc.authScanResult.status, 'failed');
  assert.equal(calls(s, '/JSON/ascan/action/scan/').length, 2, 'it failed after both scans');
  assert.equal(s.uploads.length, 0, 'nothing stored');
});

test('failure: a refused API scan is recorded and the site scan still completes', () => {
  const s = R.apiNotStarted;
  assert.deepEqual(s.outcome, { success: true, scanId: s.scanId });
  assert.deepEqual(s.doc.authScanResult.apiScans, [{ host: 'api-host.example.test', status: 'not_started' }]);
});

test('cancellation: Stop during the API scan ends the worker at once and revokes the token', () => {
  const s = R.stopped;
  assert.deepEqual(s.outcome, { success: false, reason: 'stopped' });
  assert.equal(s.doc.status, 'stopped');
  assert.ok(s.stopResult && s.stopResult.success && s.stopResult.workerStopped, 'the stop waited for the worker to exit');
  assert.equal(s.uploads.length, 0, 'no report for a stopped scan');
  assert.equal(calls(s, '/JSON/core/view/alerts/').length, 0, 'no alert collection after a stop');
  assert.equal(zapAuthService._runningWorkers.has(s.scanId), false);
});

test('a token sent to the site\'s own origin rides with the site scan: no API context, no extra scan', () => {
  const s = R.sameOrigin;
  assert.deepEqual(s.outcome, { success: true, scanId: s.scanId });
  assert.deepEqual(calls(s, '/JSON/ascan/action/scan/').map(c => c.params.url), [TARGET]);
  assert.equal(calls(s, '/JSON/context/action/newContext/').length, 1);
  const [add] = calls(s, '/JSON/replacer/action/addRule/');
  assert.equal(add.form.url, rules.bearerRuleRegex(SITE_ORIGIN));
  const probes = calls(s, '/JSON/search/view/urlsByUrlRegex/').map(c => c.params.regex).filter(r => /^\^/.test(r));
  assert.ok(probes.length > 0 && probes.every(r => r.includes('/api/me')), 'the logout "probe" was replaced by the who-am-I seed');
});

test('revoked on every exit — success, failure, refused API scan, stop — and no token or cookie in any stored output', () => {
  for (const s of Object.values(R)) {
    assert.equal(s.state.rules.size, 0, `${s.name}: rules left in ZAP: ${[...s.state.rules.keys()]}`);
    assert.equal(s.state.contexts.size, 0, `${s.name}: contexts left in ZAP: ${[...s.state.contexts.keys()]}`);
    const paths = s.state.calls.map(c => c.path);
    const iStop = paths.lastIndexOf('/JSON/ascan/action/stopAllScans/');
    const iRemove = paths.lastIndexOf('/JSON/replacer/action/removeRule/');
    assert.ok(iStop > 0 && iRemove > iStop && paths.lastIndexOf('/JSON/core/action/newSession/') > iRemove, `${s.name}: stop → remove → newSession`);
    if (calls(s, '/JSON/context/action/newContext/').length > 1) {
      const removed = calls(s, '/JSON/context/action/removeContext/').map(c => c.params.contextName);
      assert.ok(removed.includes(`auth_api_${s.scanId}_0`), `${s.name}: API context removed`);
    }
    assert.deepEqual(leaked(JSON.stringify(s.doc)), [], `${s.name}: scan record`);
    assert.deepEqual(leaked(JSON.stringify(s.authState.bearer.map(b => b.seedUrls))), [], `${s.name}: seeds`);
    for (const u of s.uploads) assert.deepEqual(leaked(u.text, SECRETS_OF[s.name]), [], `${s.name}: ${u.filename}`);
  }
  const detailed = R.ok.uploads.find(u => u.filename.includes('detailed_alerts'));
  assert.match(detailed.text, /Authorization: Bearer \[REDACTED\]|Authorization: \[REDACTED\]/);
});

test('cookie-only scans are unchanged: same active-scan request, no bearer rule, no API context, one alert base', () => {
  const s = R.cookie;
  const ascans = calls(s, '/JSON/ascan/action/scan/');
  assert.equal(ascans.length, 1);
  assert.deepEqual(withoutKey(ascans[0].params), { url: TARGET, recurse: 'true', inScopeOnly: 'true', contextId: '7' });
  assert.ok(!calls(s, '/JSON/replacer/action/addRule/').some(c => c.form.description.startsWith('auth_bearer_')));
  assert.ok(calls(s, '/JSON/replacer/action/addRule/').some(c => c.form.description === 'auth_cookie'));
  assert.equal(calls(s, '/JSON/context/action/newContext/').length, 1);
  assert.deepEqual(calls(s, '/JSON/core/view/alerts/').map(c => c.params.baseurl), [TARGET]);
  assert.equal(s.doc.authScanResult.sessionKind, undefined);
  assert.equal(s.doc.authScanResult.apiScans, undefined);
  // The legacy site excludes are untouched for cookie scans.
  const excludes = calls(s, '/JSON/context/action/excludeFromContext/').map(c => c.params.regex);
  assert.ok(excludes.includes('.*logout.*') && excludes.includes('.*signout.*'));
});
