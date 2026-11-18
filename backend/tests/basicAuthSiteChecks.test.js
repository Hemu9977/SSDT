'use strict';

/**
 * HTTP Basic scans: the report's header grade and site configuration rows
 * (TLS grade, WAF, HSTS, technologies) are measured signed in, with the credential
 * sent to the target origin only — so a Basic report has the same sections, filled
 * the same way, as a public or form-login report.
 *
 *   1. siteChecks: WebCheck's firewall / hsts / tech-stack rules, ported; the hsts
 *      normalization every report needed (the container never set `enabled`).
 *   2. The header grade's credential guard, against REAL local HTTPS servers and the
 *      real grading engine: the credential reaches the target origin, and never a
 *      redirect target, an automatic redirect hop, plain HTTP, or a concurrent
 *      unauthenticated grading.
 *   3. The Basic fast-scan orchestration (stubbed scanners): what is stored, what is
 *      handed to WebCheck, and that no external service is called.
 *   4. WebCheck takes the handed-over results and never asks the container for them.
 *
 * Run with: node --test backend/tests/basicAuthSiteChecks.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const siteChecks = require('../services/inHouse/siteChecks');

// ── 1. siteChecks ────────────────────────────────────────────────────────────────

test('WAF detection follows the container rules, header names in any case', () => {
  assert.deepEqual(siteChecks.detectWaf({ Server: 'cloudflare' }), { hasWaf: true, waf: 'Cloudflare' });
  assert.deepEqual(siteChecks.detectWaf({ 'X-Sucuri-ID': '1' }), { hasWaf: true, waf: 'Sucuri CloudProxy WAF' });
  assert.deepEqual(siteChecks.detectWaf({ 'set-cookie': ['a=1', '_citrix_ns_id=x'] }), { hasWaf: true, waf: 'Citrix NetScaler' });
  assert.deepEqual(siteChecks.detectWaf({ server: 'nginx' }), { hasWaf: false });
});

test('HSTS: the container verdicts, plus `enabled` and `maxAge` that every reader expects', () => {
  assert.deepEqual(siteChecks.hstsResult({}),
    { message: 'Site does not serve any HSTS headers.', compatible: false, hstsHeader: null, enabled: false, maxAge: null });
  const short = siteChecks.hstsResult({ 'Strict-Transport-Security': 'max-age=300' });
  assert.deepEqual([short.enabled, short.compatible, short.maxAge, short.message], [true, false, 300, 'HSTS max-age is less than 10886400.']);
  const full = siteChecks.hstsResult({ 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' });
  assert.deepEqual([full.enabled, full.compatible, full.hstsHeader], [true, true, 'max-age=31536000; includeSubDomains; preload']);
});

test('HSTS from the container: `enabled` is recovered from its message (it was always read as "No")', () => {
  const none = { message: 'Site does not serve any HSTS headers.', compatible: false, hstsHeader: null };
  const sent = { message: 'HSTS header does not contain the preload directive.', compatible: false, hstsHeader: null };
  assert.equal(siteChecks.normalizeHsts(none).enabled, false);
  assert.equal(siteChecks.normalizeHsts(sent).enabled, true);
  assert.equal(siteChecks.isHstsEnabled(sent), true, 'legacy stored result (no `enabled`)');
  assert.equal(siteChecks.isHstsEnabled({ error: 'x' }), false);
  assert.equal(siteChecks.isHstsEnabled({ enabled: false, preloaded: true }), true);
  assert.deepEqual(siteChecks.normalizeHsts({ error: 'x' }), { error: 'x' });
});

test('HSTS reaches the PDF, the AI prompt and the completion summary through the shared helper', () => {
  const src = (f) => fs.readFileSync(path.join(BACKEND, f), 'utf8');
  for (const f of ['services/pdfService.js', 'services/geminiService.js', 'services/geminiCompletionService.js']) {
    assert.ok(!/hsts\??\.enabled/.test(src(f)), `${f} still reads hsts.enabled directly`);
    assert.match(src(f), /isHstsEnabled\(/, `${f} does not use isHstsEnabled`);
  }
});

test('tech-stack: the container patterns; nothing found is the container\'s error', () => {
  const pageData = { scripts: ['https://x.test/wp-includes/js/jquery/jquery.min.js'], inlineScripts: '', metas: { generator: 'WordPress 6.6' }, html: '<link href="/wp-content/x.css">', globals: ['jQuery'] };
  const out = siteChecks.detectTechStack(pageData, { Server: 'nginx/1.25' }, 'https://x.test/');
  const names = out.technologies.map(t => t.name);
  assert.ok(names.includes('WordPress') && names.includes('jQuery') && names.includes('Nginx'), names.join(','));
  assert.equal(out.technologies.find(t => t.name === 'WordPress').categories[0], 'CMS');
  assert.ok(out.technologies[0].confidence >= out.technologies.at(-1).confidence, 'sorted by confidence');
  assert.deepEqual(siteChecks.detectTechStack({ scripts: [], inlineScripts: '', metas: {}, html: '', globals: [] }, {}, 'u'),
    { error: 'Unable to find any technologies for site' });
});

// ── 2. The header grade's credential guard (real engine, real servers) ──────────
//
// Each scenario runs in its own process (tests/support/basicGradeScenario.js): the
// engine's sockets and the patched dns.lookup stay out of the test runner's channel
// (under full-suite load they corrupted its frames: "Unable to deserialize cloned data").

const { spawnSync } = require('node:child_process');
const USER = 'scan-user';
const PASS = 'S3cret-basic-PW';

function scenario(name) {
  const r = spawnSync(process.execPath, [path.join(__dirname, 'support/basicGradeScenario.js'), name], { encoding: 'utf8', timeout: 120_000 });
  const line = (r.stdout || '').split(/\r?\n/).reverse().find(l => l.startsWith('RESULT '));
  assert.ok(line, `scenario ${name} printed no result (exit ${r.status}): ${(r.stderr || '').slice(-400)}`);
  const out = JSON.parse(line.slice(7));
  assert.ok(!out.error, `scenario ${name} failed: ${out.error}`);
  assert.ok(!(r.stdout + r.stderr).includes(PASS), 'the password was printed');
  return out;
}

test('header grade, HTTP Basic: the credential reaches the target origin only — not a redirect hop (even to a subdomain), plain HTTP or a concurrent grading', () => {
  const out = scenario('hop');
  const main = out.target.filter(r => !r.host.startsWith('sub.'));
  const subdomain = out.target.filter(r => r.host.startsWith('sub.'));
  assert.ok(main.some(r => r.auth === 'credential'), 'the target never received the credential');
  assert.equal(out.graded.status, 200, 'graded the signed-in page, not the 401');
  assert.ok(out.graded.grade && out.graded.tlsGrade === out.graded.grade, 'one run serves both readers');
  assert.equal(out.publicStatus, 401, 'the unauthenticated grading saw the 401');
  assert.ok(subdomain.length >= 1, 'the redirect hop never happened — the test proves nothing');
  assert.deepEqual(subdomain.filter(r => r.auth), [], 'credential sent to a subdomain on an automatic redirect hop');
  assert.deepEqual(out.plain.filter(r => r.auth), [], 'credential sent over plain HTTP');
  assert.ok(main.some(r => !r.auth), 'every target request had a credential — the concurrent grading inherited it');
});

test('header grade, HTTP Basic: a manual redirect to another origin does not carry the credential', () => {
  const out = scenario('manual');
  assert.ok(out.target.some(r => r.auth === 'credential'));
  assert.ok(out.other.some(r => r.path === '/landing'), 'the redirect was followed');
  assert.deepEqual(out.other.filter(r => r.auth), [], 'credential followed the redirect to another origin');
  assert.deepEqual(out.plain.filter(r => r.auth), [], 'credential sent over plain HTTP');
});

test('header grade, HTTP Basic: refuses a non-https origin or another host\'s credential', async () => {
  const headerGrade = require('../services/inHouse/headerGrade');
  await assert.rejects(headerGrade.gradeHostWithBasicAuth('example.test', { origin: 'http://example.test', username: 'u', password: 'p' }), /https/);
  await assert.rejects(headerGrade.gradeHostWithBasicAuth('example.test', { origin: 'https://other.test', username: 'u', password: 'p' }), /another host/);
});

// ── 3. The Basic fast-scan orchestration (stubbed) ──────────────────────────────

function stub(rel, exportsObj) {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports: exportsObj };
}

function loadFastScans({ capture, grade }) {
  const calls = { external: [], webcheckOpts: null, updates: [] };
  const scan = {
    analysisId: 'zap-auth-1-basic', target: 'https://stg.example.jp/entry/', status: 'running', userId: 'u1',
    authScanResult: { authMethod: 'basic' }, fastScansStartedAt: null,
  };
  stub('models/ScanResult.js', {
    findOneAndUpdate: async () => ({ ...scan }),
    updateOne: async (_f, u) => { calls.updates.push(u.$set); return {}; },
    findOne: async () => scan,
  });
  stub('services/pagespeedService.js', { getPageSpeedReport: async () => { calls.external.push('psi'); return {}; } });
  stub('services/observatoryService.js', { scanHost: async () => { calls.external.push('observatory'); return {}; } });
  stub('services/urlscanService.js', { runUrlScan: async () => { calls.external.push('urlscan'); return {}; } });
  stub('services/webCheckService.js', { startAsyncWebCheckScan: async (url, id, uid, opts) => { calls.webcheckOpts = opts; return { status: 'running' }; } });
  stub('services/inHouse/lighthouseAudit.js', { runLighthouseAudit: async () => ({ lighthouseResult: { categories: { performance: { score: 0.9 } } } }) });
  stub('services/inHouse/pageCapture.js', { runPageCapture: capture });
  stub('services/inHouse/headerGrade.js', { gradeHostWithBasicAuth: grade });
  stub('services/geminiCompletionService.js', { checkAndGenerateGemini: async () => {} });
  const vault = require('../services/scanCredentialVault');
  vault.put(scan.analysisId, { origin: 'https://stg.example.jp', username: USER, password: PASS });
  delete require.cache[require.resolve('../services/authFastScanService')];
  const svc = require('../services/authFastScanService');
  return { svc, calls, scan, vault };
}

test('Basic fast scans: header grade and site checks are signed-in and in-house; nothing external; WebCheck gets them', async () => {
  const seenCreds = [];
  const { svc, calls, scan } = loadFastScans({
    capture: async (url, _w, { basicAuth, siteChecks: wanted }) => {
      seenCreds.push(basicAuth);
      assert.equal(wanted, true, 'the capture was not asked for the site checks');
      return { page: { domain: 'stg.example.jp', ip: '203.0.113.5' }, verdicts: { overall: { malicious: false } },
        siteChecks: { firewall: { hasWaf: false }, hsts: { enabled: true, message: 'm' }, 'tech-stack': { technologies: [{ name: 'Nginx' }] } } };
    },
    grade: async (host, basicAuth) => {
      seenCreds.push(basicAuth);
      return { observatory: { grade: 'B', score: 70, status_code: 200 }, tls: { tlsInfo: { grade: 'B' }, scan: { grade: 'B' } } };
    },
  });
  await svc.ensureAuthFastScans(scan.analysisId, 'u1');

  assert.deepEqual(calls.external, [], 'an external service was called for a Basic scan');
  assert.ok(seenCreds.length === 2 && seenCreds.every(c => c && c.origin === 'https://stg.example.jp'), 'checks did not get the scoped credential');

  const stored = Object.assign({}, ...calls.updates);
  assert.deepEqual([stored.observatoryResult.grade, stored.observatoryResult.diagnosticSource], ['B', 'in-house']);
  assert.ok(!('tls' in stored.observatoryResult) && !('observatory' in stored.observatoryResult), 'grading wrapper stored');
  assert.ok(!('siteChecks' in stored.urlscanResult), 'site checks stored with the capture');
  assert.equal(stored.urlscanResult.page.ip, '203.0.113.5');
  assert.ok(!JSON.stringify(calls.updates).includes(PASS), 'credential written to the scan record');

  const pre = calls.webcheckOpts?.precomputed;
  assert.ok(pre, 'WebCheck was not given the signed-in results');
  assert.deepEqual(Object.keys(pre).sort(), ['firewall', 'hsts', 'tech-stack', 'tls']);
  assert.equal(pre.tls.tlsInfo.grade, 'B');
  assert.equal(pre.tls.diagnosticSource, 'in-house');
  assert.equal(pre.hsts.enabled, true);
  assert.ok(!JSON.stringify(pre).includes(PASS));
});

test('Basic fast scans: a failed signed-in check is handed over as unavailable, never left to the unauthenticated container', async () => {
  const { svc, calls, scan } = loadFastScans({
    capture: async () => { throw new Error('Page answered HTTP 401'); },
    grade: async () => { throw new Error('Observatory scan failed: x'); },
  });
  await svc.ensureAuthFastScans(scan.analysisId, 'u1');
  const pre = calls.webcheckOpts?.precomputed;
  for (const k of ['tls', 'firewall', 'hsts', 'tech-stack']) assert.deepEqual(pre[k], { error: 'unavailable' }, k);
  const stored = Object.assign({}, ...calls.updates);
  assert.match(stored.observatoryResult.error, /Observatory scan failed/);
  assert.match(stored.urlscanResult.error, /401/);
});

// ── 4. WebCheck uses what it was handed ─────────────────────────────────────────

test('WebCheck takes precomputed checks instead of asking the container (source contract)', () => {
  const src = fs.readFileSync(path.join(BACKEND, 'services/webCheckService.js'), 'utf8');
  assert.match(src, /precomputed && Object\.prototype\.hasOwnProperty\.call\(precomputed, scanType\)\s*\?\s*takePrecomputed\(scanType, precomputed\[scanType\]\)\s*:\s*await runScan\(/);
  assert.match(src, /runWebCheckInBackground\(url, analysisId, userId, controller, \{ precomputed \}\)/);
  assert.match(src, /scanType === 'hsts' \? normalizeHsts\(scanResult\.data\)/, 'hsts not normalized when recorded');
});

// ── 5. The report rows ──────────────────────────────────────────────────────────

test('PDF scan-results rows: a Basic scan with signed-in results has no N/A; container HSTS reads correctly', () => {
  for (const mod of ['models/ScanResult.js', 'services/geminiService.js', 'services/gridfsService.js', 'services/reportTemplateDocx.js']) {
    const file = path.join(BACKEND, mod);
    if (!require.cache[file]) require.cache[file] = { id: file, filename: file, loaded: true, exports: {} };
  }
  const { _buildScanDataForPdf } = require('../services/pdfService');
  const tls = { scan: { grade: 'B' }, tlsInfo: { grade: 'B', statusCode: 200 }, diagnosticSource: 'in-house' };
  const basicScan = {
    target: 'https://stg.example.jp/entry/', analysisId: 'zap-auth-1-basic', status: 'completed',
    authScanResult: { authMethod: 'basic' },
    pagespeedResult: { lighthouseResult: { categories: { performance: { score: 0.81 }, accessibility: { score: 0.9 }, 'best-practices': { score: 0.77 }, seo: { score: 0.88 } } } },
    observatoryResult: { grade: 'B', score: 70, tests_passed: 8, tests_failed: 2, status_code: 200, diagnosticSource: 'in-house' },
    urlscanResult: { page: { domain: 'stg.example.jp', ip: '203.0.113.5', country: 'JP', server: 'nginx' }, verdicts: { overall: { malicious: false, score: 0 } } },
    zapResult: { riskCounts: { High: 1, Medium: 2, Low: 3, Informational: 4 }, totalAlerts: 10, alerts: [] },
    webCheckResult: { status: 'completed_with_errors', fullResults: {
      tls, firewall: { hasWaf: false }, hsts: { enabled: true, maxAge: 31536000 }, 'tech-stack': { technologies: [{ name: 'Nginx' }, { name: 'jQuery' }] },
    } },
  };
  const rows = (scan) => Object.fromEntries(_buildScanDataForPdf(scan).sections.flatMap(s => s.items.map(i => [`${s.id}.${i.label.en}`, typeof i.value === 'object' ? i.value.en : i.value])));
  const r = rows(basicScan);
  const na = Object.entries(r).filter(([, v]) => v === 'N/A' || v === undefined || v === null);
  assert.deepEqual(na, [], 'rows still N/A for a signed-in Basic scan');
  assert.equal(r['webcheck.TLS Grade'], 'B');
  assert.equal(r['webcheck.HSTS Enabled'], 'Yes');
  assert.equal(r['webcheck.Technologies'], 'Nginx, jQuery');
  // A scan stored before this change: the container's hsts shape (no `enabled`).
  const legacy = JSON.parse(JSON.stringify(basicScan));
  legacy.webCheckResult.fullResults.hsts = { message: 'HSTS max-age is less than 10886400.', compatible: false, hstsHeader: null };
  assert.equal(rows(legacy)['webcheck.HSTS Enabled'], 'Yes', 'legacy hsts read as "No"');
  legacy.webCheckResult.fullResults.hsts = { message: 'Site does not serve any HSTS headers.', compatible: false, hstsHeader: null };
  assert.equal(rows(legacy)['webcheck.HSTS Enabled'], 'No');
});
