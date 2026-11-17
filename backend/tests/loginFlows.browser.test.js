'use strict';

/**
 * Form-login detection and outcome, end to end, in real Chromium against local
 * fixture sites. Each fixture is a login page shape seen in the wild; the
 * first is a faithful copy of the one behind the 2026-11-13 failure
 * (credit.villdesign.com: React form, password show/hide toggle *before* an
 * id-less "Sign In", JSON login to a cross-origin API, refusals shown only as a
 * `role="status"` toast).
 *
 * What it proves:
 *  - detection gives every button a selector that resolves to that button only
 *    (the old `form:nth-of-type(1) button` clicked the toggle);
 *  - the login test tells "nothing was sent" (SUBMIT_NO_EFFECT), "the site said
 *    no" (LOGIN_REJECTED) and "the site never answered" (LOGIN_NO_RESPONSE)
 *    apart, and never sends the password twice;
 *  - conventional cookie logins and the route's NO_SESSION_COOKIES are unchanged;
 *  - token sessions: the app's Bearer is recorded only for a site without a
 *    session cookie, and a logout-shaped call is never kept to be replayed;
 *  - a toast never becomes the signed-in marker;
 *  - nothing logged contains a credential.
 *
 * Skips (does not fail) when Chromium cannot be launched.
 * Run with: node --test backend/tests/loginFlows.browser.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};
// The route module pulls in scan orchestration; none of it runs for /test-login.
stub('models/ScanResult.js', { updateOne: async () => ({}), findOne: async () => null });
stub('services/planService.js', { claimScanSlot: async () => true });
stub('services/zapCapacityManager.js', { markZapDemand: async () => {}, ensureZapCapacity: async () => {} });
stub('services/zapContainerManager.js', { requestContainer: async () => ({}), releaseContainer: async () => {} });
stub('services/zapRecycler.js', { withZapInstance: async (_k, _id, fn) => fn() });
stub('services/authFastScanService.js', { ensureAuthFastScans: async () => ({ started: true }) });
stub('services/zapAuthService.js', {
  checkZapAuthHealth: async () => ({}), startAsyncAuthScan: async () => ({}), getAuthScanStatus: async () => ({}),
  stopAuthScan: async () => ({}), isAuthScanCancelled: async () => false
});

const puppeteer = require('puppeteer');
const { LAUNCH_ARGS, chromiumPath } = require('../services/inHouse/browserSlot');
const { detectLoginFields } = require('../services/loginDetectionService');
const { testLogin } = require('../services/loginTestService');
const router = require('../routes/zapAuthRoutes');

const EMAIL = 'qa.fx@fixture.test';
const PASS = 'Fx-Secr3t-77';
const USER_TOKEN = 'eyJfx.user-session-token.Zq81';
const RESOLVER = '--host-resolver-rules=MAP *.fxtest 127.0.0.1';

let PORT = 0;
let server = null;
let browserOk = false;
let skipReason = '';
const hits = { login: 0, classic: 0 };
const hanging = [];
const captured = [];
const originalConsole = {};

const SITE = () => `http://login.fxtest:${PORT}`;
const API = () => `http://api.fxtest:${PORT}`;

// ── Fixture pages ────────────────────────────────────────────────────────────

const SPA_SCRIPT = `
const params = new URLSearchParams(location.search);
const mode = params.get('mode') || 'ok';
const transport = params.get('transport') || 'fetch';
const apiBase = params.get('api') === 'cross' ? '__API__' : '';
const app = document.getElementById('app');
function toast(text) {
  // react-hot-toast's shape: generated class names, role="status", no "error".
  const wrap = document.createElement('div'); wrap.className = 'go2072408551';
  const msg = document.createElement('div'); msg.setAttribute('role', 'status'); msg.setAttribute('aria-live', 'polite');
  msg.textContent = text; wrap.appendChild(msg); document.body.appendChild(wrap);
}
function send(body) {
  const url = apiBase + '/api/auth/login?mode=' + mode;
  if (transport === 'xhr') {
    return new Promise((resolve, reject) => {
      const x = new XMLHttpRequest(); x.open('POST', url); x.setRequestHeader('Content-Type', 'application/json');
      x.onload = () => { let j = null; try { j = JSON.parse(x.responseText); } catch (e) {} resolve({ status: x.status, json: j }); };
      x.onerror = () => reject(new Error('net')); x.send(body);
    });
  }
  return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body })
    .then(async r => { let j = null; try { j = await r.json(); } catch (e) {} return { status: r.status, json: j }; });
}
async function submit() {
  const btn = document.getElementById('signin') || app.querySelector('button[type=submit]');
  btn.disabled = true; btn.textContent = 'Signing in...';
  try {
    const r = await send(JSON.stringify({ email: document.getElementById('login-email').value, password: document.getElementById('login-password').value }));
    if (r.status >= 400 || !r.json || r.json.success === false) {
      toast('Invalid email or password.'); btn.disabled = false; btn.textContent = 'Sign In'; return;
    }
    localStorage.setItem('tok', r.json.token || 'x');
    history.pushState({}, '', '/home' + location.search);
    renderSignedIn();
    toast('Welcome Alice');
    if (params.get('lazy') !== '1') loadSignedInData();
  } catch (e) { toast('Cannot connect to the server.'); btn.disabled = false; }
}
function renderSignedIn() {
  app.innerHTML = '<h1>Account summary page</h1>' + (params.get('nav') === '1' ? '<button type="button">Log out</button>' : '');
}
// Like credit.villdesign.com: the token lives in localStorage and the app adds
// it as a Bearer header to calls to its API (unless useToken=0).
function loadSignedInData() {
  if (params.get('useToken') === '0') return;
  const auth = { Authorization: 'Bearer ' + localStorage.getItem('tok') };
  fetch(apiBase + '/api/me', { headers: auth });
  fetch(apiBase + '/api/applications?page=1', { headers: auth });
  // A logout-shaped GET the app makes with its token (some apps "clear other
  // sessions" on sign-in): it must never become a seed or the session probe.
  if (params.get('logoutCall') === '1') fetch(apiBase + '/api/auth/logout?others=1', { headers: auth });
  fetch(apiBase + '/api/audit', { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: '{}' });
  fetch(apiBase + '/api/config', { headers: { Authorization: 'Bearer public-config-key-123' } });
}
// A public key the app sends before anyone signs in: never a session.
fetch(apiBase + '/api/config', { headers: { Authorization: 'Bearer public-config-key-123' } }).catch(() => {});
const pwBlock = '<div class="pw"><input id="login-password" type="password"><button type="button" class="_passwordToggle_11nnc_109" __TOGGLE_ATTRS__></button></div>';
if (__NO_FORM__) {
  app.innerHTML = '<h2>Member login</h2><div class="card"><input id="login-email" type="email">' + pwBlock +
    '<button type="button" id="signin" class="primary">Sign In</button></div>';
  document.getElementById('signin').onclick = submit;
} else {
  // As on the real site: no id, no name, no test hook on "Sign In".
  app.innerHTML = '<h2>Member login</h2><form><input id="login-email" type="email">' + pwBlock +
    '<button type="submit" class="btn btn-primary">Sign In</button></form>';
  app.querySelector('form').onsubmit = (e) => { e.preventDefault(); submit(); };
}
const pw = document.getElementById('login-password');
app.querySelector('.pw button').onclick = () => { pw.type = pw.type === 'password' ? 'text' : 'password'; };
// Reloading a signed-in page: the app reads its token and resumes, as SPAs do.
if (location.pathname === '/home' && localStorage.getItem('tok')) {
  renderSignedIn();
  loadSignedInData();
}
`;

function spaPage({ noForm = false } = {}) {
  const script = SPA_SCRIPT
    .replace('__API__', API())
    .replace('__NO_FORM__', noForm ? 'true' : 'false')
    .replace('__TOGGLE_ATTRS__', noForm ? 'aria-label="Show password"' : '');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Fixture</title></head><body><div id="app"></div><script>${script}</script></body></html>`;
}

const CLASSIC_FORM = `<!doctype html><html><head><meta charset="utf-8"><title>Classic</title></head><body>
<h2>Sign in to continue</h2>
<form method="post" action="/classic-login">
  <input name="username">
  <div class="pw"><input name="password" type="password"><button type="button" class="eye-btn" title="Show password">o</button></div>
  <button type="submit">Log in</button>
</form>
<script>document.querySelector('.eye-btn').onclick = () => { const p = document.querySelector('[name=password]'); p.type = p.type === 'password' ? 'text' : 'password'; };</script>
</body></html>`;

const GENERIC = `<!doctype html><html><head><meta charset="utf-8"><title>Generic</title></head><body>
<form>
  <button type="button">Cancel</button>
  <input type="email" name="email">
  <div><input type="password" name="password"><button type="button" class="reveal">Show</button></div>
  <button type="submit">Log in</button>
</form>
<div><form><input name="newsletter"><button type="submit">Subscribe</button></form></div>
</body></html>`;

const UNIQUE = `<!doctype html><html><head><meta charset="utf-8"><title>Unique</title></head><body>
<form><input id="user" type="text"><div><input id="pass" type="password"><button type="button" class="pw-toggle">o</button></div>
<button id="login-btn" type="submit">Log in</button></form></body></html>`;

const DECOY = `<!doctype html><html><head><meta charset="utf-8"><title>Decoy</title></head><body>
<form><input id="user" type="text"><input id="pass" type="password"><button type="submit" id="go">Log in</button></form>
<script>document.querySelector('form').onsubmit = (e) => e.preventDefault();
document.getElementById('go').onclick = (e) => { e.preventDefault(); e.stopPropagation(); };</script></body></html>`;

function readBody(req) {
  return new Promise(resolve => { let b = ''; req.on('data', c => { b += c; }); req.on('end', () => resolve(b)); });
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  const html = (body, headers = {}) => { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...headers }); res.end(body); };
  const cors = { 'Access-Control-Allow-Origin': SITE(), 'Access-Control-Allow-Headers': 'content-type, authorization', 'Access-Control-Allow-Methods': 'GET, POST' };

  if (['/api/me', '/api/applications', '/api/audit', '/api/config', '/api/auth/logout'].includes(url.pathname)) {
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    await readBody(req);
    const auth = req.headers.authorization || '';
    const ok = url.pathname === '/api/config' ? auth === 'Bearer public-config-key-123' : auth === `Bearer ${USER_TOKEN}`;
    res.writeHead(ok ? 200 : 401, { 'Content-Type': 'application/json', ...cors });
    return res.end(ok ? '{"ok":true}' : '{"message":"unauthorized"}');
  }

  if (url.pathname === '/api/auth/login') {
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    await readBody(req);
    hits.login++;
    const mode = url.searchParams.get('mode');
    const json = (status, payload, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', ...cors, ...headers }); res.end(JSON.stringify(payload));
    };
    if (mode === '401') return json(401, { message: 'Invalid email or password' });
    if (mode === '200false') return json(200, { success: false, message: 'Invalid credentials' });
    if (mode === 'hang') { hanging.push(res); return undefined; }
    if (mode === 'tokenonly') return json(200, { token: USER_TOKEN, user: { name: 'Alice' } });
    const ok = () => json(200, { token: USER_TOKEN, user: { name: 'Alice' } }, { 'Set-Cookie': 'sid=s3ss10n; HttpOnly; Path=/' });
    if (mode === 'slow') { setTimeout(ok, 4000); return undefined; }
    return ok();
  }
  if (url.pathname === '/classic-login' && req.method === 'POST') {
    await readBody(req);
    hits.classic++;
    res.writeHead(302, { Location: '/welcome', 'Set-Cookie': 'session=abc123; HttpOnly; Path=/' });
    return res.end();
  }
  if (url.pathname === '/welcome') {
    const signedIn = /(?:^|;\s*)session=abc123/.test(req.headers.cookie || '');
    return html(signedIn ? '<!doctype html><html><body><h1>Welcome page</h1><a href="/logout">Sign out</a></body></html>' : CLASSIC_FORM);
  }
  if (url.pathname === '/spa' || url.pathname === '/home') return html(spaPage());
  if (url.pathname === '/noform') return html(spaPage({ noForm: true }));
  if (url.pathname === '/classic') return html(CLASSIC_FORM);
  if (url.pathname === '/generic') return html(GENERIC);
  if (url.pathname === '/unique') return html(UNIQUE);
  if (url.pathname === '/decoy') return html(DECOY);
  res.writeHead(404); return res.end('not found');
}

// ── Harness ─────────────────────────────────────────────────────────────────

test.before(async () => {
  server = http.createServer((req, res) => { handler(req, res).catch(() => { try { res.writeHead(500); res.end(); } catch { /* gone */ } }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  PORT = server.address().port;

  // The services launch through puppeteer.launch; give them the fixture DNS.
  const realLaunch = puppeteer.launch.bind(puppeteer);
  puppeteer.launch = (opts = {}) => realLaunch({ ...opts, args: [...(opts.args || []), RESOLVER] });
  try {
    const b = await realLaunch({ headless: true, executablePath: chromiumPath(), args: [...LAUNCH_ARGS, RESOLVER] });
    await b.close();
    browserOk = true;
  } catch (e) {
    skipReason = `Chromium unavailable: ${String(e.message).split('\n')[0]}`;
  }

  // Everything the code under test prints, for the no-credentials check.
  for (const k of ['log', 'info', 'warn', 'error', 'debug']) {
    originalConsole[k] = console[k];
    console[k] = (...a) => { captured.push(a.map(x => (x instanceof Error ? `${x.message}\n${x.stack}` : String(x))).join(' ')); };
  }
});

test.after(() => {
  Object.assign(console, originalConsole);
  for (const res of hanging) { try { res.destroy(); } catch { /* gone */ } }
  server.closeAllConnections?.();
  server.close();
});

const creds = (emailSel, passSel) => [
  { selector: emailSel, value: EMAIL, inputType: 'email' },
  { selector: passSel, value: PASS, inputType: 'password' }
];

async function inPage(url, fn, arg) {
  const b = await puppeteer.launch({ headless: true, args: LAUNCH_ARGS });
  try {
    const p = await b.newPage();
    await p.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
    return await p.evaluate(fn, arg);
  } finally {
    await b.close();
  }
}

const resolvesOnlyTo = (selector) => {
  const found = document.querySelectorAll(selector);
  return { count: found.length, type: found[0] && found[0].getAttribute('type'), text: found[0] && found[0].textContent.trim() };
};

// ── 1. Selectors ────────────────────────────────────────────────────────────

test('1. toggle before an id-less Sign In: the old selector hit the toggle; detection now resolves to Sign In only', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const legacy = await inPage(`${SITE()}/spa`, resolvesOnlyTo, 'form:nth-of-type(1) button');
  assert.equal(legacy.count, 2, 'fixture must reproduce the ambiguous selector');
  assert.equal(legacy.type, 'button', 'the old selector resolved to the password toggle first');

  const detected = await detectLoginFields(`${SITE()}/spa`);
  assert.equal(detected.success, true);
  const form = detected.forms[0];
  const submits = form.fields.filter(f => f.tagName === 'BUTTON');
  assert.equal(submits.length, 1, 'the toggle is not offered as a submit button');
  assert.ok(form.submitButton && form.submitButton.selector);
  assert.notEqual(form.submitButton.selector, 'form:nth-of-type(1) button');
  const target = await inPage(`${SITE()}/spa`, resolvesOnlyTo, form.submitButton.selector);
  assert.deepEqual(target, { count: 1, type: 'submit', text: 'Sign In' });
});

test('1b. a stale selector that hits the toggle is not clicked; the detected one sends exactly one login', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  // Old detection's selector, as still stored in schedules. Before the guard,
  // the click unmasked the password and no login was sent (reproduced on the
  // production image: LOGIN_ANALYSIS_FAILED, 0 POSTs).
  const before = hits.login;
  const legacy = await testLogin({
    loginUrl: `${SITE()}/spa?mode=401&api=cross`, credentials: creds('#login-email', '#login-password'),
    submitButton: { selector: 'form:nth-of-type(1) button' }, submitAlternates: []
  });
  assert.equal(hits.login - before, 1, 'the toggle is skipped and Enter submits the form once');
  assert.equal(legacy.submitStrategy, 'enter_key');
  assert.equal(legacy.errorCode, 'LOGIN_REJECTED');

  const detected = await detectLoginFields(`${SITE()}/spa`);
  const fixedBefore = hits.login;
  const fixed = await testLogin({
    loginUrl: `${SITE()}/spa?mode=401&api=cross`, credentials: creds('#login-email', '#login-password'),
    submitButton: detected.forms[0].submitButton, submitAlternates: detected.forms[0].submitAlternates
  });
  assert.equal(hits.login - fixedBefore, 1);
  assert.equal(fixed.errorCode, 'LOGIN_REJECTED');
});

test('1c. a submit button given as a bare selector string is clicked, not ignored', async (t) => {
  // The scan form's dropdown sent a string; `submitButton.selector` on a string
  // is undefined, so production pressed Enter only and reported SUBMIT_NO_EFFECT
  // for a login it had in fact sent (reproduced on the v67 image).
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/spa`);
  const before = hits.login;
  const result = await testLogin({
    loginUrl: `${SITE()}/spa?mode=401&api=cross`, credentials: creds('#login-email', '#login-password'),
    submitButton: detected.forms[0].submitButton.selector, submitAlternates: []
  });
  assert.equal(hits.login - before, 1);
  assert.equal(result.submitStrategy, 'primary_button');
  assert.equal(result.errorCode, 'LOGIN_REJECTED');
});

test('2. several generic id-less buttons each get a distinct selector that resolves to that button only', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/generic`);
  const buttons = detected.forms.flatMap(f => f.fields.filter(x => x.tagName === 'BUTTON'));
  const labels = buttons.map(b => b.label).sort();
  assert.deepEqual(labels, ['Log in', 'Subscribe'], 'Cancel and Show are not offered as submit buttons');
  const selectors = new Set(buttons.map(b => b.selector));
  assert.equal(selectors.size, buttons.length);
  for (const b of buttons) {
    const r = await inPage(`${SITE()}/generic`, resolvesOnlyTo, b.selector);
    assert.equal(r.count, 1, b.selector);
    assert.equal(r.text, b.label, b.selector);
  }
  // Inputs without ids: unique too.
  for (const f of detected.forms[0].fields.filter(x => x.tagName === 'INPUT')) {
    const r = await inPage(`${SITE()}/generic`, (s) => document.querySelectorAll(s).length, f.selector);
    assert.equal(r, 1, f.selector);
  }
  assert.equal(detected.forms[0].submitButton.label, 'Log in');
});

test('3. a uniquely identified submit keeps its id selector', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/unique`);
  const form = detected.forms[0];
  assert.equal(form.submitButton.selector, '#login-btn');
  assert.equal(form.usernameField.selector, '#user');
  assert.equal(form.passwordField.selector, '#pass');
  assert.ok(!form.fields.some(f => /toggle/.test(f.className || '')), 'toggle not offered');
});

// ── 2. Outcomes ─────────────────────────────────────────────────────────────

async function runSpa(query, { path: p = '/spa', responseWaitMs } = {}) {
  const detected = await detectLoginFields(`${SITE()}${p}`);
  const form = detected.forms[0];
  const before = hits.login;
  const result = await testLogin({
    loginUrl: `${SITE()}${p}?${query}`,
    credentials: creds(form.usernameField.selector, form.passwordField.selector),
    submitButton: form.submitButton,
    submitAlternates: form.submitAlternates,
    responseWaitMs
  });
  return { result, posts: hits.login - before, form };
}

test('4. a no-form SPA posting JSON (fetch and XHR) is recognised; the show-password control is never chosen', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  for (const transport of ['fetch', 'xhr']) {
    const { result, posts, form } = await runSpa(`mode=401&transport=${transport}`, { path: '/noform' });
    // No-form branch: a button's text is `buttonText`; `label` is <label>/aria-label.
    assert.equal(form.submitButton.buttonText, 'Sign In', transport);
    assert.equal(form.submitButton.selector, '#signin', transport);
    assert.ok(!form.submitAlternates.some(a => a.ariaLabel === 'Show password'), 'toggle never auto-retried');
    assert.equal(posts, 1, transport);
    assert.equal(result.errorCode, 'LOGIN_REJECTED', transport);
    assert.equal(result.loginRequest.detected, true);
    assert.equal(result.loginRequest.matchedBy, 'credential_value');
  }
});

test('5. HTTP 401 answered with a role="status" toast → LOGIN_REJECTED, exactly one POST', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result, posts } = await runSpa('mode=401&api=cross');
  assert.equal(posts, 1, 'the password is never sent twice');
  assert.equal(result.errorCode, 'LOGIN_REJECTED');
  assert.deepEqual(result.loginRequest, { detected: true, matchedBy: 'credential_value', status: 401, outcome: 'http_error' });
  assert.deepEqual(result.evidenceCodes, ['login_http_error']);
});

test('6. HTTP 200 with {success:false} → LOGIN_REJECTED', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result, posts } = await runSpa('mode=200false');
  assert.equal(posts, 1);
  assert.equal(result.errorCode, 'LOGIN_REJECTED');
  assert.equal(result.loginRequest.outcome, 'app_error');
  assert.equal(result.loginRequest.status, 200);
});

test('7. a slow answer (4 s) is waited for: signed in, cookie kept, no failure code', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result, posts } = await runSpa('mode=slow');
  assert.equal(posts, 1);
  assert.equal(result.authenticated, true);
  assert.ok(!['SUBMIT_NO_EFFECT', 'LOGIN_REJECTED', 'LOGIN_NO_RESPONSE'].includes(result.errorCode), String(result.errorCode));
  assert.ok(result.cookies.some(c => c.name === 'sid'));
  assert.equal(result.loginRequest.outcome, 'ok');
});

test('8. a login request that is never answered → LOGIN_NO_RESPONSE, one POST, no retries', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const started = Date.now();
  const { result, posts } = await runSpa('mode=hang&api=cross', { responseWaitMs: 3000 });
  assert.equal(posts, 1, 'no second attempt while the first is in flight');
  assert.equal(result.errorCode, 'LOGIN_NO_RESPONSE');
  assert.deepEqual(result.loginRequest, { detected: true, matchedBy: 'credential_value', status: null, outcome: 'timeout' });
  assert.ok(Date.now() - started < 45000);
});

test('9. a form that submits nothing → SUBMIT_NO_EFFECT, and no request is attributed', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const result = await testLogin({
    loginUrl: `${SITE()}/decoy`, credentials: creds('#user', '#pass'), submitButton: { selector: '#go' }, submitAlternates: []
  });
  assert.equal(result.errorCode, 'SUBMIT_NO_EFFECT');
  assert.equal(result.loginRequest.detected, false);
});

test('10. conventional cookie login (form POST → 302 + Set-Cookie) still signs in and is confirmed', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/classic`);
  const form = detected.forms[0];
  assert.equal(form.submitButton.label, 'Log in');
  assert.equal(form.usernameField.selector, 'input[name="username"]');
  const before = hits.classic;
  const result = await testLogin({
    loginUrl: `${SITE()}/classic`,
    credentials: [
      { selector: form.usernameField.selector, value: EMAIL, inputType: 'text' },
      { selector: form.passwordField.selector, value: PASS, inputType: 'password' }
    ],
    submitButton: form.submitButton, submitAlternates: form.submitAlternates
  });
  assert.equal(hits.classic - before, 1);
  assert.equal(result.authenticated, true);
  assert.equal(result.authConfirmed, 'confirmed');
  assert.equal(result.errorCode, null);
  assert.ok(result.cookies.some(c => c.name === 'session'));
  assert.equal(result.marker, 'Sign out');
  assert.equal(result.loginRequest.detected, true);
  assert.equal(result.loginRequest.outcome, 'ok');
});

test('11. a "Welcome" toast is never chosen as the signed-in marker', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result } = await runSpa('mode=ok');
  assert.equal(result.authenticated, true);
  assert.notEqual(result.marker, 'Welcome Alice', 'a toast fades; a marker taken from it would read as a lost session');
  assert.ok(!(result.markerAlternates || []).includes('Welcome Alice'));
  assert.equal(result.marker, 'Account summary page');
});

// ── 3. Route: codes, the localStorage-only case, and the log line ───────────

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
    handler({ body, user: { id: 'u1' }, params: {}, query: {} }, res);
  });
}

test('route: a refused login answers LOGIN_REJECTED and logs codes only', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/spa`);
  const form = detected.forms[0];
  const mark = captured.length;
  const r = await call(handlerFor(router, '/test-login', 'post'), {
    loginUrl: `${SITE()}/spa?mode=401&api=cross`,
    credentials: creds('#login-email', '#login-password'),
    submitButton: form.submitButton, submitAlternates: form.submitAlternates
  });
  await new Promise(res => setImmediate(res));
  assert.equal(r.status, 200);
  assert.equal(r.body.authenticated, false);
  assert.equal(r.body.errorCode, 'LOGIN_REJECTED');
  assert.equal(r.body.tempSessionId, undefined);
  assert.equal(r.body.loginRequest, undefined, 'request details stay on the server');
  const line = captured.slice(mark).find(l => l.startsWith('[ZAP-AUTH] Login test failed:'));
  assert.ok(line, 'the failure outcome is logged');
  assert.match(line, /code=LOGIN_REJECTED strategy=primary_button loginRequest=detected matchedBy=credential_value status=401 outcome=http_error timedOut=false evidence=login_http_error cookies=0/);
});

test('token login: the Bearer token the app sends to its API is the session (cookie-less SPA)', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result, posts } = await runSpa('mode=tokenonly&api=cross&nav=1');
  assert.equal(posts, 1);
  assert.equal(result.authenticated, true);
  assert.equal(result.authConfirmed, 'confirmed', 'a sign-out control appeared');
  assert.equal(result.cookies.filter(c => c.name === 'sid').length, 0, 'no session cookie on this site');
  assert.equal(result.bearer.length, 1);
  const [session] = result.bearer;
  assert.equal(session.origin, API());
  assert.equal(session.authorization, `Bearer ${USER_TOKEN}`);
  assert.ok(session.seedUrls.includes(`${API()}/api/me`));
  assert.ok(session.seedUrls.includes(`${API()}/api/applications?page=1`));
  assert.ok(!session.seedUrls.some(u => u.includes('/api/audit')), 'a POST is never kept to be replayed');
  assert.equal(session.verifyUrl, `${API()}/api/me`, 'the "who am I" call is the session probe');
  assert.ok(!JSON.stringify(result.bearer).includes('public-config-key'), 'a key used before the login is not the session');
});

test('token login: a logout-shaped call the app makes with its token is never kept to be replayed', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result } = await runSpa('mode=tokenonly&api=cross&nav=1&logoutCall=1');
  assert.equal(result.authenticated, true);
  assert.equal(result.bearer.length, 1);
  assert.ok(!result.bearer[0].seedUrls.some(u => /logout/i.test(u)), result.bearer[0].seedUrls.join(', '));
  assert.ok(result.bearer[0].seedUrls.includes(`${API()}/api/me`));
  assert.equal(result.bearer[0].verifyUrl, `${API()}/api/me`);
});

test('token login: a site that signs in with a session cookie gets no token hosts, even though it also sends a Bearer', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  // Same-origin login that sets `sid` AND has the app send its token to /api/*.
  const { result } = await runSpa('mode=ok&nav=1');
  assert.equal(result.authenticated, true);
  assert.ok(result.cookies.some(c => c.name === 'sid'), 'the cookie session is kept');
  assert.equal(result.hasSessionCookie, true);
  assert.deepEqual(result.bearer, [], 'the cookie is the session: no token API host is discovered');
});

test('token login: an app that only sends its token on start-up is caught by reloading the signed-in page', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const { result } = await runSpa('mode=tokenonly&api=cross&nav=1&lazy=1');
  assert.equal(result.authenticated, true);
  assert.equal(result.bearer.length, 1);
  assert.equal(result.bearer[0].authorization, `Bearer ${USER_TOKEN}`);
});

test('route: a token login succeeds — session stored server-side, only host names reach the browser', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/spa`);
  const form = detected.forms[0];
  const mark = captured.length;
  const r = await call(handlerFor(router, '/test-login', 'post'), {
    loginUrl: `${SITE()}/spa?mode=tokenonly&api=cross&nav=1`,
    credentials: creds('#login-email', '#login-password'),
    submitButton: form.submitButton, submitAlternates: form.submitAlternates
  });
  await new Promise(res => setImmediate(res));
  assert.equal(r.status, 200);
  assert.equal(r.body.authenticated, true);
  assert.equal(r.body.authConfirmed, 'confirmed');
  assert.equal(r.body.errorCode, null);
  assert.equal(typeof r.body.tempSessionId, 'string');
  assert.equal(r.body.sessionKind, 'bearer');
  assert.deepEqual(r.body.authHosts, [new URL(API()).host]);
  assert.ok(!JSON.stringify(r.body).includes(USER_TOKEN), 'the token never goes to the browser');
  const line = captured.slice(mark).find(l => l.startsWith('[ZAP-AUTH] Login confirmed. Session stored:'));
  assert.ok(line, 'success logged');
  assert.match(line, /session=bearer, apiOrigins=1\)/);
});

test('route: a cookie site that also sends a Bearer keeps a cookie session with no API hosts', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/spa`);
  const form = detected.forms[0];
  const r = await call(handlerFor(router, '/test-login', 'post'), {
    loginUrl: `${SITE()}/spa?mode=ok&nav=1`,
    credentials: creds('#login-email', '#login-password'),
    submitButton: form.submitButton, submitAlternates: form.submitAlternates
  });
  assert.equal(r.body.authenticated, true);
  assert.equal(r.body.sessionKind, 'cookie');
  assert.deepEqual(r.body.authHosts, []);
});

test('route: a site that keeps no cookie and never sends a token still answers NO_SESSION_COOKIES', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  const detected = await detectLoginFields(`${SITE()}/spa`);
  const form = detected.forms[0];
  const mark = captured.length;
  const r = await call(handlerFor(router, '/test-login', 'post'), {
    loginUrl: `${SITE()}/spa?mode=tokenonly&useToken=0`,
    credentials: creds('#login-email', '#login-password'),
    submitButton: form.submitButton, submitAlternates: form.submitAlternates
  });
  await new Promise(res => setImmediate(res));
  assert.equal(r.body.errorCode, 'NO_SESSION_COOKIES');
  assert.equal(r.body.authenticated, false);
  assert.equal(r.body.tempSessionId, undefined);
  const line = captured.slice(mark).find(l => l.startsWith('[ZAP-AUTH] Login test failed:'));
  assert.match(line, /code=NO_SESSION_COOKIES .*loginRequest=detected .*status=200 outcome=ok/);
});

// ── 4. Credentials never reach a log ────────────────────────────────────────

test('12. nothing printed during any of the above contains a credential value or token', (t) => {
  if (!browserOk) return t.skip(skipReason);
  assert.ok(captured.length > 0, 'expected the route to log something');
  const forms = [EMAIL, PASS, encodeURIComponent(EMAIL), encodeURIComponent(PASS), USER_TOKEN];
  const leaks = captured.filter(line => forms.some(v => line.includes(v)));
  assert.deepEqual(leaks, []);
});
