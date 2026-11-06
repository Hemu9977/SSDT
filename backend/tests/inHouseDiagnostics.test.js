'use strict';

/**
 * External diagnostics first, in-house fallback when they cannot reach the site.
 *
 * PageSpeed Insights, the public header-grading API and the page-analysis
 * service (and WebCheck's tls/quality, which call two of them) fetch the target
 * from third-party servers. A client who allowlists only Fortexa's egress IP
 * refuses those: they fail, or report on the 403 page. Then the same checks run
 * in-house, from our egress IP (services/inHouse/).
 *
 * These tests pin three things:
 *   1. A usable external result is returned untouched - reports are as before.
 *   2. When it is not usable, the in-house result is used, in the same shape:
 *      every field the report reads (score cards, details panels, PDF, AI prompt).
 *   3. When neither can reach the site, the outcome is what it was before.
 *
 * Browser runs and network lookups are not exercised here (no Chromium, no
 * DNS); the pure adapters, the fallback decisions and their wiring are.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { PassThrough, Readable } = require('stream');

const BACKEND = path.join(__dirname, '..');

const axios = require('axios');
const { _toPsiShape, _loadingExperienceFromCrux } = require('../services/inHouse/lighthouseAudit');
const headerGrade = require('../services/inHouse/headerGrade');
const { _buildCaptureResult, SCREENSHOT_BUCKET } = require('../services/inHouse/pageCapture');
const { _classify, _isSinkhole } = require('../services/inHouse/threatVerdict');
const { runInBrowserSlot } = require('../services/inHouse/browserSlot');
const { withInHouseFallback, lighthouseUnusable } = require('../services/inHouse/fallback');
const { _observatoryUnusable } = require('../services/observatoryService');
const { _urlscanUnusable } = require('../services/urlscanService');
const { countryOf } = require('../utils/ipCountry');

/** Re-require `mod` after patching exports of modules it destructures at load. */
function fresh(mod, patches = []) {
  for (const [dep, key, value] of patches) require(dep)[key] = value;
  delete require.cache[require.resolve(mod)];
  return require(mod);
}

// ─────────────────────────────────────────────────────────────────────────────
// The fallback rule
// ─────────────────────────────────────────────────────────────────────────────

const unusable403 = (r) => (r?.status_code >= 400 ? `http_${r.status_code}` : null);

test('a usable external result is returned untouched and nothing runs in-house', async () => {
  let inHouseCalls = 0;
  const external = { grade: 'A', status_code: 200 };
  const out = await withInHouseFallback({
    name: 't', external: async () => external, inHouse: async () => { inHouseCalls++; return {}; }, unusable: unusable403,
  });
  assert.equal(out, external);
  assert.deepEqual(out, { grade: 'A', status_code: 200 }, 'no fallback fields added');
  assert.equal(inHouseCalls, 0);
});

test('external refused (error, or a 403 page) -> the in-house result is used', async () => {
  const failed = await withInHouseFallback({
    name: 't', external: async () => { throw new Error('Lighthouse returned error: ERRORED_DOCUMENT_REQUEST'); },
    inHouse: async () => ({ grade: 'B', status_code: 200 }), unusable: unusable403,
  });
  assert.deepEqual([failed.grade, failed.diagnosticSource], ['B', 'in-house']);
  assert.match(failed.fallbackReason, /ERRORED_DOCUMENT_REQUEST/);

  const blockPage = await withInHouseFallback({
    name: 't', external: async () => ({ grade: 'F', status_code: 403 }),
    inHouse: async () => ({ grade: 'B', status_code: 200 }), unusable: unusable403,
  });
  assert.deepEqual([blockPage.grade, blockPage.fallbackReason], ['B', 'http_403']);
});

test('when our IP is refused too, the outcome is what it was before', async () => {
  // A site that answers 403 to everyone: the external result stands.
  const external = { grade: 'F', status_code: 403 };
  assert.equal(await withInHouseFallback({
    name: 't', external: async () => external, inHouse: async () => ({ grade: 'F', status_code: 403 }), unusable: unusable403,
  }), external);
  assert.equal(await withInHouseFallback({
    name: 't', external: async () => external, inHouse: async () => { throw new Error('down'); }, unusable: unusable403,
  }), external);
  // External failed and in-house failed or only saw an error page: the external error, as before.
  const err = new Error('external down');
  await assert.rejects(withInHouseFallback({
    name: 't', external: async () => { throw err; }, inHouse: async () => { throw new Error('in-house down'); },
  }), (e) => e === err);
  await assert.rejects(withInHouseFallback({
    name: 't', external: async () => { throw err; }, inHouse: async () => ({ grade: 'F', status_code: 403 }), unusable: unusable403,
  }), (e) => e === err);
});

test('what counts as "could not reach the site", per service', () => {
  // Header grading: the public API grades 401/403 pages and reports failures in `error`.
  assert.equal(_observatoryUnusable({ grade: 'B', status_code: 200, error: null }), null);
  assert.equal(_observatoryUnusable({ grade: 'D', status_code: 403, error: null }), 'http_403');
  assert.equal(_observatoryUnusable({ grade: null, error: 'site-down' }), 'error_site-down');
  // Page analysis: a timeout, or a captured error page.
  assert.equal(_urlscanUnusable({ page: { status: 200 }, verdicts: {} }), null);
  assert.equal(_urlscanUnusable({ page: { status: '403' }, verdicts: {} }), 'http_403');
  assert.equal(_urlscanUnusable({ uuid: 'x', status: 'timeout' }), 'timeout');
  // Performance: no scores, or Lighthouse could not audit the page.
  assert.equal(lighthouseUnusable({ lighthouseResult: { categories: { performance: { score: 0.9 } } } }), null);
  assert.equal(lighthouseUnusable({ lighthouseResult: { runtimeError: { code: 'ERRORED_DOCUMENT_REQUEST' }, categories: {} } }), 'lighthouse_ERRORED_DOCUMENT_REQUEST');
  assert.equal(lighthouseUnusable({ lighthouseResult: { categories: { performance: { score: null } } } }), 'no_scores');
  assert.equal(lighthouseUnusable({ error: 'x' }), 'error');
});

// ─────────────────────────────────────────────────────────────────────────────
// Wiring: each service tries the external check first
// ─────────────────────────────────────────────────────────────────────────────

test('PageSpeed: PSI first; its failure runs the in-house audit with desktop settings', async () => {
  const get = axios.get;
  process.env.PSI_API_KEY = process.env.PSI_API_KEY || 'test-key';
  const calls = [];
  const svc = fresh('../services/pagespeedService', [[
    '../services/inHouse/lighthouseAudit', 'runLighthouseAudit',
    async (url, opts) => { calls.push([url, opts.strategy]); return _toPsiShape(lhr()); },
  ]]);
  try {
    axios.get = async () => ({ data: { lighthouseResult: lhr() } });
    const ok = await svc.getPageSpeedReport('https://example.test/');
    assert.equal(ok.lighthouseResult.audits['first-contentful-paint'].numericValue, 812, 'PSI response untouched');
    assert.deepEqual(calls, []);

    axios.get = async () => { throw Object.assign(new Error('400'), { response: { status: 400, data: { error: { message: 'Lighthouse returned error: ERRORED_DOCUMENT_REQUEST' } } } }); };
    const fb = await svc.getPageSpeedReport('https://example.test/');
    assert.deepEqual(calls, [['https://example.test/', 'desktop']]);
    assert.equal(fb.diagnosticSource, 'in-house');
    assert.equal(fb.lighthouseResult.categories.performance.score, 0.93);
  } finally {
    axios.get = get;
  }
});

test('Observatory: the API first; a grade of the 403 page runs the in-house engine', async () => {
  const post = axios.post;
  const graded = [];
  const svc = fresh('../services/observatoryService', [[
    '../services/inHouse/headerGrade', 'gradeHost',
    async (host) => { graded.push(host); return { grade: 'B', score: 70, status_code: 200, error: null }; },
  ]]);
  try {
    axios.post = async () => ({ data: { grade: 'A+', score: 110, status_code: 200, error: null } });
    assert.equal((await svc.scanHost('example.test')).grade, 'A+');
    assert.deepEqual(graded, []);

    axios.post = async () => ({ data: { grade: 'F', score: 0, status_code: 403, error: null } });
    const fb = await svc.scanHost('example.test');
    assert.deepEqual([fb.grade, fb.diagnosticSource, graded], ['B', 'in-house', ['example.test']]);
  } finally {
    axios.post = post;
  }
});

test('URLScan: the service first; a timeout runs the in-house capture', async () => {
  const post = axios.post;
  process.env.URLSCAN_API_KEY = process.env.URLSCAN_API_KEY || 'test-key';
  const captured = [];
  const svc = fresh('../services/urlscanService', [[
    '../services/inHouse/pageCapture', 'runPageCapture',
    async (url) => { captured.push(url); return { page: { domain: 'example.test', status: 200 }, verdicts: { overall: { malicious: false, score: 0 } }, screenshot: '/api/scan/screenshot/x.jpg' }; },
  ]]);
  try {
    axios.post = async () => ({ data: { uuid: 'u1' } });
    const fb = await svc.runUrlScan('https://example.test/', 0); // no polling budget -> timeout
    assert.deepEqual(captured, ['https://example.test/']);
    assert.equal(fb.diagnosticSource, 'in-house');
    assert.equal(fb.fallbackReason, 'timeout');
    assert.equal(fb.page.domain, 'example.test');
  } finally {
    axios.post = post;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Performance audit (fallback for PageSpeed Insights)
// ─────────────────────────────────────────────────────────────────────────────

const lhr = (over = {}) => ({
  lighthouseVersion: '13.6.0',
  fetchTime: '2026-11-05T00:00:00.000Z',
  configSettings: { formFactor: 'desktop' },
  categories: {
    performance: { title: 'Performance', score: 0.93 },
    accessibility: { title: 'Accessibility', score: 0.88 },
    'best-practices': { title: 'Best Practices', score: 1 },
    seo: { title: 'SEO', score: 0.8 },
  },
  audits: { 'first-contentful-paint': { numericValue: 812 } },
  ...over,
});

test('audit result keeps the PSI paths the report reads, and nothing heavy', () => {
  const out = _toPsiShape(lhr());
  const { lighthouseScores } = require('../utils/scoreFormat');
  assert.deepEqual(lighthouseScores(out), lighthouseScores({ lighthouseResult: lhr() }));
  assert.equal(out.lighthouseResult.categories.performance.score, 0.93);
  assert.equal(out.lighthouseResult.categories['best-practices'].score, 1);
  assert.equal(out.lighthouseResult.audits, undefined, 'the multi-MB audit list is not stored');
  assert.ok(JSON.stringify(out).length < 1000);
});

test('a page the audit could not load is an error, not scores for the error page', () => {
  // e.g. a 403 from an IP allowlist that does not include our egress IP
  assert.throws(() => _toPsiShape(lhr({ runtimeError: { code: 'ERRORED_DOCUMENT_REQUEST' } })), /ERRORED_DOCUMENT_REQUEST/);
  const allNull = lhr();
  for (const c of Object.values(allNull.categories)) c.score = null;
  assert.throws(() => _toPsiShape(allNull), /no category scores/);
});

test('field data becomes PSI loadingExperience; overall is the slowest Core Web Vital', () => {
  const record = {
    metrics: {
      largest_contentful_paint: { percentiles: { p75: 2300 }, histogram: [{ start: 0, end: 2500, density: 0.8 }, { start: 2500, end: 4000, density: 0.15 }, { start: 4000, density: 0.05 }] },
      interaction_to_next_paint: { percentiles: { p75: 260 }, histogram: [] },
      cumulative_layout_shift: { percentiles: { p75: '0.05' }, histogram: [{ start: '0.00', end: '0.10', density: 0.9 }] },
      first_contentful_paint: { percentiles: { p75: 3500 }, histogram: [] },
    },
  };
  const le = _loadingExperienceFromCrux(record, { initialUrl: 'https://example.test/', originFallback: false });
  assert.equal(le.metrics.LARGEST_CONTENTFUL_PAINT_MS.category, 'FAST');
  assert.equal(le.metrics.INTERACTION_TO_NEXT_PAINT.category, 'AVERAGE');
  assert.equal(le.metrics.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile, 5, 'CLS reported x100, as PSI does');
  assert.deepEqual(le.metrics.CUMULATIVE_LAYOUT_SHIFT_SCORE.distributions[0], { min: 0, max: 10, proportion: 0.9 });
  assert.equal(le.metrics.FIRST_CONTENTFUL_PAINT_MS.category, 'SLOW');
  assert.equal(le.overall_category, 'AVERAGE', 'FCP is not a Core Web Vital, so it does not decide overall');
  assert.equal(le.origin_fallback, undefined);

  const origin = _loadingExperienceFromCrux(record, { initialUrl: 'https://example.test/', originFallback: true });
  assert.equal(origin.origin_fallback, true);
  assert.equal(_loadingExperienceFromCrux({ metrics: {} }, { initialUrl: 'x' }), null);
});

// ─────────────────────────────────────────────────────────────────────────────
// Security-header grading (fallback for the public header-grading API)
// ─────────────────────────────────────────────────────────────────────────────

const engineResult = {
  scan: { algorithmVersion: 6, grade: 'B', score: 70, statusCode: 200, testsFailed: 3, testsPassed: 9, testsQuantity: 12 },
  tests: { 'content-security-policy': { expectation: 'csp-implemented-with-no-unsafe', pass: false, result: 'csp-not-implemented', scoreModifier: -25 } },
};

test('header grade keeps the v2 /scan fields the report reads', () => {
  const out = headerGrade._toApiShape(engineResult);
  assert.deepEqual(
    { grade: out.grade, score: out.score, tests_passed: out.tests_passed, tests_failed: out.tests_failed, tests_quantity: out.tests_quantity },
    { grade: 'B', score: 70, tests_passed: 9, tests_failed: 3, tests_quantity: 12 }
  );
  assert.equal(out.error, null);
  assert.equal(out.algorithm_version, 6);
});

test('when both fall back, the score card and WebCheck TLS section share one scan per host', async () => {
  headerGrade._cache.clear();
  headerGrade._cache.set('example.test', { at: Date.now(), promise: Promise.resolve(engineResult) });
  const grade = await headerGrade.gradeHost('Example.test');
  const tls = await headerGrade.getTlsReport('https://example.test/login');
  assert.equal(grade.grade, 'B');
  // The fields WebCheckDetails, the TLS score card, the PDF and the summary read:
  assert.deepEqual(tls.tlsInfo, { grade: 'B', score: 70, endTime: tls.scan.scanned_at, host: 'example.test', statusCode: 200 });
  assert.equal(tls.scan.grade, 'B');
  assert.equal(tls.tests['content-security-policy'].pass, false);
  headerGrade._cache.clear();
});

test('WebCheck tls: the container first; when it cannot grade the site, the in-house grade', async () => {
  const src = fs.readFileSync(path.join(BACKEND, 'services/webCheckService.js'), 'utf8');
  assert.match(src, /quality:\s*\{\s*inHouse:\s*\(url, signal\)\s*=>\s*runLighthouseAudit\(url, \{ strategy: 'mobile', signal \}\)/);
  // One container attempt: retrying a refused third party (~20 s each) would use up
  // the 150 s per-check limit before the in-house check could run.
  assert.match(src, /external:\s*\(\)\s*=>\s*runContainerScan\(scanType, url, signal, \{ maxAttempts: 1 \}\)/);

  // No WebCheck container runs here, so the container call fails and the
  // in-house grade (stubbed for this host) is the only place 'B' / 9 can come from.
  headerGrade._cache.clear();
  headerGrade._cache.set('example.test', { at: Date.now(), promise: Promise.resolve(engineResult) });
  try {
    const { runScan } = require('../services/webCheckService');
    const out = await runScan('tls', 'https://example.test/');
    assert.deepEqual([out.tlsInfo.grade, out.scan.tests_passed, out.diagnosticSource], ['B', 9, 'in-house']);
  } finally {
    headerGrade._cache.clear();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Page capture (fallback for the external page-analysis service)
// ─────────────────────────────────────────────────────────────────────────────

test('page capture produces every page and network field the report reads', () => {
  const now = Math.floor(Date.now() / 1000);
  const out = _buildCaptureResult({
    requestedUrl: 'http://example.test/',
    finalUrl: 'https://www.example.test/home',
    main: { ip: '133.242.0.1', server: 'nginx', tlsIssuer: 'R11', validFrom: now - 30 * 86400, validTo: now + 60 * 86400 },
    responses: [
      { url: 'https://www.example.test/home', ip: '133.242.0.1' },
      { url: 'https://cdn.example.test/app.js', ip: '133.242.0.1' },
      { url: 'https://fonts.example.test/a.woff2', ip: '8.8.8.8' },
    ],
    requestCount: 4,
    dataLength: 123456,
  });
  assert.deepEqual(out.page, {
    url: 'https://www.example.test/home',
    domain: 'www.example.test',
    ip: '133.242.0.1',
    country: 'JP',
    server: 'nginx',
    tlsIssuer: 'R11',
    tlsValidDays: 90,
    tlsAgeDays: 30,
  });
  assert.deepEqual(out.stats, { uniqIPs: 2, uniqCountries: 2, dataLength: 123456, requests: 4 });
  assert.deepEqual(out.lists.ips, ['133.242.0.1', '8.8.8.8']);
  assert.deepEqual(out.lists.domains, ['www.example.test', 'cdn.example.test', 'fonts.example.test']);
});

test('country lookup is local and answers only for public addresses', () => {
  assert.equal(countryOf('133.242.0.1'), 'JP');
  assert.equal(countryOf('54.178.209.53'), 'JP');
  assert.equal(countryOf('10.0.0.1'), null);
  assert.equal(countryOf('not-an-ip'), null);
  assert.equal(countryOf(null), null);
});

// ─────────────────────────────────────────────────────────────────────────────
// Threat verdict (with the in-house page capture)
// ─────────────────────────────────────────────────────────────────────────────

const ok = (...addresses) => ({ addresses });
const fail = (code) => ({ code });
const sec = (answers) => Object.entries(answers).map(([name, answer]) => ({ name, answer }));
const RESOLVES = [{ answer: ok('93.184.215.14') }, { answer: ok('93.184.215.14') }];

test('verdict has every field the report reads, clean when nothing blocks the domain', () => {
  const v = _classify(sec({ Quad9: ok('93.184.215.14'), OpenDNS: ok('93.184.215.14') }), RESOLVES);
  assert.equal(v.overall.malicious, false);
  assert.equal(v.overall.score, 0);
  assert.equal(v.urlscan.score, 0);
  assert.equal(v.engines.malicious, 0);
  assert.equal(v.community.score, 0);
});

test('a sinkhole answer or a "no such domain" for a live domain is a blocklist hit', () => {
  const v = _classify(sec({
    OpenDNS: ok('146.112.61.108'),         // block page
    Quad9: fail('ENOTFOUND'),              // refused to resolve a domain that exists
    'Cloudflare Security': ok('0.0.0.0'),
    'Comodo Secure': ok('93.184.215.14'),
  }), RESOLVES);
  assert.equal(v.overall.malicious, true);
  assert.equal(v.engines.malicious, 3);
  assert.equal(v.engines.enginesTotal, 4);
  assert.equal(v.overall.score, 75);
  assert.deepEqual(v.engines.maliciousEngines.sort(), ['Cloudflare Security', 'OpenDNS', 'Quad9']);
});

test('a domain nobody resolves, or a resolver that times out, is not called malicious', () => {
  const nowhere = [{ answer: fail('ENOTFOUND') }, { answer: fail('ENOTFOUND') }];
  assert.equal(_classify(sec({ Quad9: fail('ENOTFOUND'), OpenDNS: fail('ENOTFOUND') }), nowhere).overall.malicious, false);
  const v = _classify(sec({ Quad9: fail('ETIMEOUT'), OpenDNS: fail('ECONNREFUSED'), 'Comodo Secure': ok('93.184.215.14') }), RESOLVES);
  assert.equal(v.overall.malicious, false);
  assert.equal(v.engines.enginesTotal, 1, 'resolvers that gave no answer are not counted');
  // A domain that really resolves to a "sinkhole-looking" address for everyone.
  const loopback = [{ answer: ok('127.0.0.1') }, { answer: ok('127.0.0.1') }];
  assert.equal(_classify(sec({ Quad9: ok('127.0.0.1'), OpenDNS: ok('127.0.0.1') }), loopback).overall.malicious, false);
  // Filters answering for a name the public resolvers don't know (e.g. 'localhost').
  assert.equal(_classify(sec({ Quad9: ok('127.0.0.1'), OpenDNS: ok('0.0.0.0') }), [{ answer: fail('ENOTFOUND') }]).overall.malicious, false);
  assert.equal(_isSinkhole('146.112.61.104'), true);
  assert.equal(_isSinkhole('93.184.215.14'), false);
});

// ─────────────────────────────────────────────────────────────────────────────
// Browser slot
// ─────────────────────────────────────────────────────────────────────────────

test('browser jobs run one at a time, and a timed-out job releases the slot', async () => {
  let running = 0;
  let peak = 0;
  const job = (ms) => async () => {
    running++; peak = Math.max(peak, running);
    await new Promise(r => setTimeout(r, ms));
    running--;
    return ms;
  };
  const results = await Promise.all([runInBrowserSlot('a', job(30)), runInBrowserSlot('b', job(10)), runInBrowserSlot('c', job(10))]);
  assert.deepEqual(results, [30, 10, 10]);
  assert.equal(peak, 1);

  let aborted = false;
  const hung = runInBrowserSlot('hung', ({ signal }) => new Promise(() => {
    signal.addEventListener('abort', () => { aborted = true; });
  }), { timeoutMs: 20 });
  await assert.rejects(hung, /timed out/);
  assert.equal(aborted, true, 'the job is told to stop its browser');
  assert.equal(await runInBrowserSlot('next', async () => 'ran'), 'ran');

  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runInBrowserSlot('cancelled', async () => 'x', { signal: controller.signal }), /aborted/);
});

// ─────────────────────────────────────────────────────────────────────────────
// Screenshot route
// ─────────────────────────────────────────────────────────────────────────────

const router = require('../routes/virustotalRoutes');
const gridfsService = require('../services/gridfsService');
const screenshotRoute = router.stack.find((l) => l.route?.path === '/screenshot/:file' && l.route.methods.get);

function callScreenshot(file, files) {
  const opened = [];
  gridfsService.initialize = (bucket) => {
    assert.equal(bucket, SCREENSHOT_BUCKET);
    return {
      find: (q) => ({ limit: () => ({ toArray: async () => files.filter(f => f.filename === q.filename) }) }),
      openDownloadStream: (id) => { opened.push(id); return Readable.from([Buffer.from('JPEGDATA')]); },
    };
  };
  return new Promise((resolve) => {
    const res = new PassThrough();
    const chunks = [];
    res.statusCode = 200;
    res.headers = {};
    res.headersSent = false;
    res.status = (c) => { res.statusCode = c; return res; };
    res.set = (h) => { Object.assign(res.headers, h); return res; };
    res.end = ((end) => function (...a) { end.apply(res, a); resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString(), opened }); return res; })(res.end);
    res.on('data', (c) => chunks.push(c));
    screenshotRoute.route.stack[0].handle({ params: { file } }, res);
  });
}

test('screenshot route: the unguessable token is the only key, served cross-origin for the <img>', async () => {
  assert.equal(screenshotRoute.route.stack.length, 1, 'no auth middleware: an <img> cannot send x-auth-token');
  const token = 'a'.repeat(64);
  const files = [{ _id: 'f1', filename: `${token}.jpg`, length: 8 }];

  const hit = await callScreenshot(`${token}.jpg`, files);
  assert.equal(hit.status, 200);
  assert.equal(hit.body, 'JPEGDATA');
  assert.equal(hit.headers['Content-Type'], 'image/jpeg');
  assert.equal(hit.headers['Cross-Origin-Resource-Policy'], 'cross-origin');

  for (const bad of ['b'.repeat(64) + '.jpg', 'f1', '../../etc/passwd', `${token}.png`, token]) {
    const miss = await callScreenshot(bad, files);
    assert.equal(miss.status, 404, bad);
    assert.deepEqual(miss.opened, [], `${bad}: nothing is read`);
  }
});
