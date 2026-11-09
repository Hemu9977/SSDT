'use strict';

/**
 * Credentials never reach a user-facing output or an AI prompt:
 *   - PDF evidence (EN and JA), drawn text captured from PDFKit
 *   - the PDF "Assessment scope" note for HTTP Basic scans (EN and JA)
 *   - JSON export / evidence endpoints (getSanitizedAlerts)
 *   - the Gemini report input (sanitizeScanForLLM + getSanitizedZapReport)
 *   - the JA translation payload sent to Gemini for the PDF
 * Inputs are ZAP-shaped alerts that contain the credential the way ZAP actually
 * emits it (Phase 0: request headers, rule 10105's `other` field, HTML report).
 *
 * Run with: node --test backend/tests/basicAuthOutputs.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const BACKEND = path.join(__dirname, '..');
for (const mod of ['models/ScanResult.js', 'services/geminiService.js', 'services/gridfsService.js', 'services/reportTemplateDocx.js']) {
  const file = path.join(BACKEND, mod);
  require.cache[file] = { id: file, filename: file, loaded: true, exports: {} };
}

const PDFDocument = require('pdfkit');
const pdf = require('../services/pdfService');
const { getSanitizedAlerts, getSanitizedZapReport } = require('../utils/vulnFilter');
const { sanitizeScanForLLM } = require('../services/geminiSanitizer');
const { secretVariants } = require('../utils/credentialRedaction');
const { _createDualVersionAlerts } = require('../services/zapAuthService');

const CRED = { username: 'alice', password: 'Out-Put-S3cret!' };
const SECRETS = secretVariants(CRED);
const AUTH = `Basic ${Buffer.from(`${CRED.username}:${CRED.password}`).toString('base64')}`;
const leaks = (text) => SECRETS.filter(s => text.includes(s));

const MARGIN = { top: 60, bottom: 60, left: 55, right: 55 };
function drawn(lang, fn) {
  const doc = new PDFDocument({ size: 'A4', bufferPages: true, margins: { top: 0, bottom: 0, left: 0, right: 0 } });
  pdf.registerPdfFonts(doc);
  const ctx = {
    doc, templateStatic: { lang }, margin: MARGIN, contentX: MARGIN.left,
    contentWidth: doc.page.width - MARGIN.left - MARGIN.right, topY: MARGIN.top, bottomY: doc.page.height - MARGIN.bottom,
    framedPages: 1, initFramedPage() { doc.x = this.contentX; doc.y = this.topY; }, addFramedPage() { doc.addPage(); this.framedPages++; this.initFramedPage(); }
  };
  ctx.initFramedPage();
  const lines = [];
  const original = doc._fragment.bind(doc);
  doc._fragment = (text, x, y, o) => { lines.push(String(text)); return original(text, x, y, o); };
  fn(ctx);
  doc.end();
  return lines.join('\n');
}

// Unredacted, as evidence stored before this change could be.
const legacyVulns = () => [{
  name: 'Cookie No HttpOnly Flag', risk: 'Low', confidence: 'Medium', description: 'd', solution: 's',
  occurrences: [{ method: 'GET', url: 'https://t.example/admin/',
    request: { header: `GET https://t.example/admin/ HTTP/1.1\r\nHost: t.example\r\nAuthorization: ${AUTH}\r\nCookie: sid=legacy-session-value\r\n\r\n`, body: '' },
    response: { header: 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=legacy-session-value2; Path=/\r\n\r\n', body: '<html>ok</html>' } }]
}];

test('PDF evidence never draws a credential (EN and JA), even from unredacted stored data', () => {
  for (const lang of ['en', 'ja']) {
    const text = drawn(lang, (ctx) => pdf.renderVulnerabilityDetailsSection(ctx, legacyVulns(), lang));
    assert.deepEqual(leaks(text), [], `${lang}: credential drawn`);
    for (const s of ['legacy-session-value', 'legacy-session-value2']) assert.ok(!text.includes(s), `${lang}: cookie ${s} drawn`);
    assert.match(text, /Authorization: Basic \[REDACTED\]/, `${lang}: header kept as evidence`);
    assert.match(text, /Path=\//, `${lang}: cookie attributes kept`);
  }
});

test('PDF assessment-scope note for Basic scans renders in EN and JA, with no engine names', () => {
  const en = drawn('en', (ctx) => pdf.renderAuthScopeNote(ctx, 'en'));
  const ja = drawn('ja', (ctx) => pdf.renderAuthScopeNote(ctx, 'ja'));
  assert.match(en.replace(/\n/g, ' '), /Assessment scope/);
  assert.match(en.replace(/\n/g, ' '), /without credentials/);
  assert.match(ja, /評価範囲/);
  const banned = /ZAP|OWASP|WebCheck|urlscan|Observatory|PageSpeed|Lighthouse|Gemini|Mozilla/i;
  for (const t of [pdf.AUTH_SCOPE_TEXT.en.body, pdf.AUTH_SCOPE_TEXT.ja.body, en, ja]) assert.ok(!banned.test(t), 'engine name in customer-facing text');
});

test('JSON export / evidence endpoints: every alert they return is redacted', () => {
  const out = JSON.stringify(getSanitizedAlerts(legacyVulns().map(v => ({ ...v, alert: v.name })), 'all'));
  assert.deepEqual(leaks(out), []);
  assert.ok(!out.includes('legacy-session-value'));
  // Every route that serves stored alerts goes through getSanitizedAlerts.
  const src = (f) => fs.readFileSync(path.join(BACKEND, f), 'utf8');
  assert.match(src('routes/virustotalRoutes.js'), /fullZapAlerts = getSanitizedAlerts\(rawAlerts/);
  assert.match(src('routes/zapAuthRoutes.js'), /getSanitizedAlerts\(alerts, accessLevel\)/);
  assert.match(src('routes/zapAuthRoutes.js'), /getSanitizedAlerts\(rawAlerts, accessLevel\)/);
  assert.match(src('services/zapService.js'), /getSanitizedAlerts\(alerts, accessLevel\)/);
});

// Build what a Basic scan stores, through the real alert processing.
async function storedScan() {
  const rawAlerts = [{
    alert: 'Authentication Credentials Captured', risk: 'Medium', confidence: 'High', pluginId: '10105',
    description: `Credentials captured: ${CRED.username}:${CRED.password}`, solution: 'Use HTTPS',
    url: 'https://t.example/admin/', messageId: '42',
    other: `revealing username [${CRED.username}] and password [${CRED.password}]`, evidence: AUTH
  }, {
    alert: 'Missing Anti-clickjacking Header', risk: 'High', confidence: 'Medium', description: 'd', solution: 's',
    url: 'https://t.example/', messageId: '43', param: 'x-frame-options', evidence: ''
  }];
  const client = { get: async () => ({ data: { message: {
    requestHeader: `GET / HTTP/1.1\r\nAuthorization: ${AUTH}\r\n\r\n`, requestBody: '', responseHeader: 'HTTP/1.1 200 OK\r\n\r\n', responseBody: 'ok' } } }) };
  const { summaryAlerts, detailedAlerts } = await _createDualVersionAlerts(rawAlerts, client, SECRETS);
  const auth = { status: 'completed', authMethod: 'basic', alerts: summaryAlerts, riskCounts: { High: 1, Medium: 1, Low: 0, Informational: 0 } };
  return { scan: { target: 'https://t.example/', analysisId: 'a1', authScanResult: auth, zapResult: auth }, detailedAlerts };
}

test('stored alerts (summary and detailed) are scrubbed at capture, including rule 10105 text', async () => {
  const { scan, detailedAlerts } = await storedScan();
  assert.deepEqual(leaks(JSON.stringify(scan)), [], 'summary alerts in the scan record');
  assert.deepEqual(leaks(JSON.stringify(detailedAlerts)), [], 'detailed alerts file');
});

test('Gemini report input: no credential after sanitizeScanForLLM + getSanitizedZapReport', async () => {
  const { scan } = await storedScan();
  const llm = sanitizeScanForLLM(scan);
  const zapReport = getSanitizedZapReport(llm.zapResult, 'all', llm.target);
  assert.deepEqual(leaks(JSON.stringify(zapReport)), []);
  assert.deepEqual(leaks(JSON.stringify(llm)), []);
});

test('JA PDF translation payload sent to Gemini carries no credential and no raw evidence', async () => {
  const sent = [];
  const findings = getSanitizedAlerts(legacyVulns().map(v => ({ ...v, alert: v.name })), 'all');
  await pdf.translateReportToJapanese({ vulnsEn: findings }, {
    translateVulnChunk: async (chunk) => { sent.push(JSON.stringify(chunk)); return chunk; }
  });
  assert.ok(sent.length > 0, 'translation was requested');
  for (const payload of sent) {
    assert.deepEqual(leaks(payload), []);
    assert.ok(!payload.includes('legacy-session-value'));
    assert.ok(!/"occurrences"|"request"|"response"/.test(payload), 'raw evidence sent for translation');
  }
});
