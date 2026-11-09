'use strict';

/**
 * Real Chromium: the origin-scoped Basic handler (services/inHouse/scopedBasicAuth.js),
 * the real page capture (capturePage) and the real performance audit
 * (runLighthouseAudit with basicAuth), against local HTTPS servers.
 *
 * Origins (all 127.0.0.1, mapped by --host-resolver-rules):
 *   target   https://target.fxtest:<A>      Basic-protected, the scan target
 *   sub      https://sub.target.fxtest:<A>  subdomain, challenges
 *   other    https://other.fxtest:<B>       third party, challenges
 *   http     http://target.fxtest:<C>       same host over plain HTTP, challenges
 *   site2    https://site2.fxtest:<D>       a second customer site, own credential
 * Every non-target server records each Authorization header it receives: "never
 * sent elsewhere" is measured. Skips (does not fail) when no Chromium is available.
 *
 * Run with: node --test backend/tests/scopedBasicAuth.browser.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
// pageCapture stores screenshots through GridFS; not used by capturePage itself.
require.cache[path.join(BACKEND, 'services/gridfsService.js')] = { id: 'g', filename: 'g', loaded: true, exports: {} };

const puppeteer = require('puppeteer');
const { LAUNCH_ARGS, chromiumPath } = require('../services/inHouse/browserSlot');
const { installScopedBasicAuth } = require('../services/inHouse/scopedBasicAuth');
const { _capturePage } = require('../services/inHouse/pageCapture');
const { runLighthouseAudit } = require('../services/inHouse/lighthouseAudit');

const TLS = { key: fs.readFileSync(path.join(__dirname, 'fixtures/tls/test-key.pem')), cert: fs.readFileSync(path.join(__dirname, 'fixtures/tls/test-cert.pem')) };
const CRED = { username: 'alice', password: 'Br0wser-S3cret!' };
const CRED2 = { username: 'bob', password: 'Second-Site-Pw!' };
const hdr = (c) => `Basic ${Buffer.from(`${c.username}:${c.password}`).toString('base64')}`;
const TEST_ARGS = ['--ignore-certificate-errors', '--host-resolver-rules=MAP *.fxtest 127.0.0.1'];

const log = { target: [], sub: [], other: [], http: [], site2: [] };
let A, B, C, D, servers = [], browserOk = false, skipReason = '';
const O = {};

const challenge = (res, realm) => { res.writeHead(401, { 'WWW-Authenticate': `Basic realm="${realm}"`, 'Access-Control-Allow-Origin': '*' }); res.end('auth required'); };
const html = (res, body) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(`<!doctype html><html><body>${body}</body></html>`); };

function targetHandler(req, res) {
  const host = (req.headers.host || '').split(':')[0];
  if (host === 'sub.target.fxtest') {
    log.sub.push({ url: req.url, auth: req.headers.authorization || null });
    return challenge(res, 'Sub');
  }
  log.target.push({ url: req.url, auth: req.headers.authorization || null });
  const ok = req.headers.authorization === hdr(CRED);
  if (req.url === '/go-cross') { res.writeHead(302, { Location: `${O.other}/challenge` }); return res.end(); }
  if (!ok) return challenge(res, 'Target');
  if (req.url === '/') {
    return html(res, `<h1 id="canary">FXTEST-PROTECTED-HOME</h1>
      <img src="${O.other}/challenge.png">
      <img src="${O.sub}/sub-challenge.png">
      <img src="${O.http}/http-challenge.png">
      <iframe id="xo" src="${O.other}/frame"></iframe>
      <iframe id="so" src="/inner"></iframe>
      <script>
        window.workerResult = null;
        const w = new Worker('/worker.js');
        w.onmessage = (e) => { window.workerResult = e.data; };
        if (navigator.serviceWorker) navigator.serviceWorker.register('/sw.js').then(() => { window.swRegistered = true; }, (e) => { window.swRegistered = String(e); });
      </script>`);
  }
  if (req.url === '/inner') return html(res, '<p id="inner">FXTEST-SAME-ORIGIN-IFRAME</p>');
  if (req.url === '/worker.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    return res.end(`Promise.all([
      fetch('/api/data').then(r => r.status, e => 'error'),
      fetch('${O.other}/worker-challenge', { mode: 'cors' }).then(r => r.status, e => 'error')
    ]).then(([same, cross]) => postMessage({ same, cross }));`);
  }
  if (req.url === '/sw.js') { res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end(`self.addEventListener('install', () => fetch('${O.other}/sw-challenge').catch(() => {}));`); }
  if (req.url === '/api/data') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"ok":true}'); }
  return html(res, 'ok');
}
function recorder(name, realm) {
  return (req, res) => {
    log[name].push({ url: req.url, auth: req.headers.authorization || null });
    if (name === 'site2') return req.headers.authorization === hdr(CRED2) ? html(res, '<h1>FXTEST-SITE2</h1>') : challenge(res, realm);
    if (req.url === '/landing') return html(res, 'landing');
    return challenge(res, realm);
  };
}
const listen = (srv) => new Promise(r => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));
const reset = () => { for (const k of Object.keys(log)) log[k].length = 0; };
const authedElsewhere = () => [...log.sub, ...log.other, ...log.http, ...log.site2].filter(e => e.auth);

const launch = () => puppeteer.launch({ headless: true, executablePath: chromiumPath(), args: [...LAUNCH_ARGS, ...TEST_ARGS] });

test.before(async () => {
  const t = https.createServer(TLS, targetHandler); A = await listen(t);
  const o = https.createServer(TLS, recorder('other', 'Other')); B = await listen(o);
  const h = http.createServer(recorder('http', 'Plain')); C = await listen(h);
  const s2 = https.createServer(TLS, recorder('site2', 'Site2')); D = await listen(s2);
  servers = [t, o, h, s2];
  Object.assign(O, { target: `https://target.fxtest:${A}`, sub: `https://sub.target.fxtest:${A}`, other: `https://other.fxtest:${B}`,
    http: `http://target.fxtest:${C}`, site2: `https://site2.fxtest:${D}` });
  // Real code launches through puppeteer.launch; give it the test-only flags.
  const realLaunch = puppeteer.launch.bind(puppeteer);
  puppeteer.launch = (opts = {}) => realLaunch({ ...opts, args: [...(opts.args || []), ...TEST_ARGS] });
  try { const b = await realLaunch({ headless: true, executablePath: chromiumPath(), args: [...LAUNCH_ARGS, ...TEST_ARGS] }); await b.close(); browserOk = true; } catch (e) { skipReason = `Chromium unavailable: ${e.message.split('\n')[0]}`; }
});
test.after(() => { for (const s of servers) { s.closeAllConnections?.(); s.close(); } });

test('page: protected content loads; iframes, workers, subdomain, HTTP and third parties never get the credential', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  reset();
  const browser = await launch();
  try {
    const page = await browser.newPage();
    const h = await installScopedBasicAuth(page, { origin: O.target, ...CRED });
    const res = await page.goto(`${O.target}/`, { waitUntil: 'networkidle2', timeout: 30000 });
    await page.waitForFunction('window.workerResult !== null', { timeout: 15000 }).catch(() => {});
    await new Promise(r => setTimeout(r, 1000));
    assert.equal(res.status(), 200);
    assert.match(await page.$eval('#canary', el => el.textContent), /FXTEST-PROTECTED-HOME/);
    const inner = page.frames().find(f => f.url().endsWith('/inner'));
    assert.ok(inner && /FXTEST-SAME-ORIGIN-IFRAME/.test(await inner.content()), 'same-origin iframe should load with the credential');
    const worker = await page.evaluate(() => window.workerResult);
    const sw = await page.evaluate(() => window.swRegistered);
    t.diagnostic(`dedicated worker: same-origin fetch=${worker && worker.same}, cross-origin fetch=${worker && worker.cross}; service worker registration=${sw}`);
    t.diagnostic(`handler: answered=${h.answered}, refused origins=${[...new Set(h.refused)].join(', ')}`);
    // A plain-HTTP subresource on an https page is blocked by Chrome's mixed-content
    // rules before any request, so the HTTP origin is exercised by navigating to it.
    await page.goto(`${O.http}/`, { waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});
    t.diagnostic(`requests seen: other=${log.other.map(e => e.url).join(',')} sub=${log.sub.map(e => e.url).join(',')} http=${log.http.map(e => e.url).join(',')}`);
    assert.deepEqual(authedElsewhere(), [], 'credential reached a non-target origin');
    for (const u of ['/challenge.png', '/frame', '/worker-challenge']) {
      assert.ok(log.other.some(e => e.url === u), `other origin never received ${u}`);
    }
    assert.ok(log.sub.length > 0, 'subdomain never contacted');
    assert.ok(log.http.length > 0, 'plain-HTTP origin never contacted');
    assert.ok(worker && worker.cross !== 200, 'cross-origin worker fetch must not succeed');
  } finally { await browser.close(); }
});

test('page: a redirect to a challenging origin is refused; wrong password is tried exactly once', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  reset();
  let browser = await launch();
  try {
    const page = await browser.newPage();
    await installScopedBasicAuth(page, { origin: O.target, ...CRED });
    await page.goto(`${O.target}/go-cross`, { waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});
    assert.deepEqual(authedElsewhere(), []);
    assert.ok(log.other.some(e => e.url === '/challenge'), 'redirect target was reached');
  } finally { await browser.close(); }
  reset();
  browser = await launch();
  try {
    const page = await browser.newPage();
    const h = await installScopedBasicAuth(page, { origin: O.target, username: 'alice', password: 'wrong' });
    let status = null;
    page.on('response', r => { if (r.request().isNavigationRequest()) status = r.status(); });
    await page.goto(`${O.target}/`, { waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});
    assert.equal(log.target.filter(e => e.url === '/' && e.auth).length, 1, 'wrong password retried');
    assert.equal(h.answered, 1);
    assert.ok(status === 401 || status === null, `unexpected status ${status}`);
  } finally { await browser.close(); }
});

test('the handler refuses non-https origins outright', async () => {
  await assert.rejects(() => installScopedBasicAuth({ createCDPSession: async () => ({}) }, { origin: 'http://x.example', ...CRED }), /https/);
});

test('real capturePage: authenticated screenshot, credential only to the target origin', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  reset();
  const out = await _capturePage(`${O.target}/`, { signal: new AbortController().signal, basicAuth: { origin: O.target, ...CRED } });
  assert.ok(out.screenshot && out.screenshot.length > 1000, 'screenshot captured');
  assert.equal(out.capture.page.url, `${O.target}/`);
  assert.deepEqual(authedElsewhere(), []);
  const anon = await _capturePage(`${O.target}/`, { signal: new AbortController().signal }).catch(e => e);
  assert.ok(anon instanceof Error, 'without credentials the capture is refused, not a picture of the 401 page');
});

test('real runLighthouseAudit with basicAuth: scores the protected page, nothing sent elsewhere', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  reset();
  const psi = await runLighthouseAudit(`${O.target}/`, { strategy: 'desktop', basicAuth: { origin: O.target, ...CRED } });
  const cats = psi.lighthouseResult.categories;
  assert.ok(['performance', 'accessibility', 'best-practices', 'seo'].every(k => cats[k] && typeof cats[k].score === 'number'));
  assert.ok(log.target.some(e => e.url === '/' && e.auth === hdr(CRED)), 'audited the authenticated page');
  assert.deepEqual(authedElsewhere(), []);
  await assert.rejects(() => runLighthouseAudit(`${O.target}/`, { strategy: 'desktop', basicAuth: { origin: O.target, username: 'alice', password: 'wrong' } }),
    /could not audit/, 'wrong credentials fail closed');
});

test('two concurrent sessions for two sites never exchange credentials', async (t) => {
  if (!browserOk) return t.skip(skipReason);
  reset();
  const [a, b] = await Promise.all([
    _capturePage(`${O.target}/`, { signal: new AbortController().signal, basicAuth: { origin: O.target, ...CRED } }),
    _capturePage(`${O.site2}/`, { signal: new AbortController().signal, basicAuth: { origin: O.site2, ...CRED2 } })
  ]);
  assert.ok(a.screenshot && b.screenshot);
  assert.ok(log.target.filter(e => e.auth).every(e => e.auth === hdr(CRED)), 'target saw another credential');
  assert.ok(log.site2.filter(e => e.auth).length > 0 && log.site2.filter(e => e.auth).every(e => e.auth === hdr(CRED2)), 'site2 saw another credential');
  assert.deepEqual([...log.sub, ...log.other, ...log.http].filter(e => e.auth), []);
});
