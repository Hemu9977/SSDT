'use strict';

/**
 * Real-model smoke test for PDF report localization (local use only).
 *
 *   node scripts/pdfLocalizationSmoke.js <outDir> [--outage]
 *
 * Generates, through the REAL translation model on Vertex AI (ambient gcloud ADC —
 * the same model, region and project as production), every combination of
 *   {HTTP Basic, form login, public, public with XSS findings} × {full report,
 *   vulnerability report} × {en, ja}
 * plus fixtures for a long finding, an unknown alert type and missing text, and
 * writes the PDFs and a drawn-text dump of each to <outDir>.
 *
 * Nothing touches a database: scan data comes from tests/fixtures (example
 * hosts only), and the translation store is a JSON file in <outDir> — run the
 * script twice to see the second run make zero model calls. Only scrubbed scanner
 * and AI prose is sent to the model, exactly as in production.
 *
 * --outage: the model fails every call; every Japanese report must be refused
 * (REPORT_TRANSLATION_UNAVAILABLE) and no PDF written.
 *
 * Prints counts, timings and audit results only, never report text.
 */

const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');

const BACKEND = path.join(__dirname, '..');
const outDir = path.resolve(process.argv[2] || '');
const OUTAGE = process.argv.includes('--outage');
if (!process.argv[2]) { process.stderr.write('usage: node scripts/pdfLocalizationSmoke.js <outDir> [--outage]\n'); process.exit(2); }
fs.mkdirSync(outDir, { recursive: true });

require('dotenv').config({ path: path.join(BACKEND, '.env') });
require('../utils/logRedaction').install(); // before anything that logs (utils/logRedaction.js)
// Production path: Vertex AI with ambient ADC — never AI Studio, never the ECS-only WIF file.
delete process.env.GEMINI_API_KEY;
delete process.env.GOOGLE_API_KEY;
delete process.env.GOOGLE_APPLICATION_CREDENTIALS;

const out = (s) => process.stdout.write(`${s}\n`);
const stubModule = (mod, exports) => {
  const file = path.join(BACKEND, mod);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};

// ── Stubs: scan history, GridFS, translation store (JSON file) ─────────────────
const owner = { name: '山田太郎', email: 'yamada@example.co.jp' };
const historyChain = { sort: () => historyChain, limit: () => historyChain, select: () => historyChain,
  populate: () => historyChain, lean: async () => [{ createdAt: new Date('2026-11-08T15:48:00Z'), userId: owner, status: 'completed' }] };
stubModule('models/ScanResult.js', { find: () => historyChain });

const storeFile = path.join(outDir, OUTAGE ? 'store-outage.json' : 'store.json');
const rows = new Map(fs.existsSync(storeFile) ? JSON.parse(fs.readFileSync(storeFile, 'utf8')) : []);
const saveStore = () => fs.writeFileSync(storeFile, JSON.stringify([...rows]));
stubModule('models/ReportTranslation.js', {
  find: ({ _id }) => {
    const result = _id.$in.filter(id => rows.has(id)).map(id => ({ _id: id, translation: rows.get(id).translation }));
    const chain = { select: () => chain, maxTimeMS: () => chain, lean: async () => result };
    return chain;
  },
  bulkWrite: async (ops) => { for (const op of ops) if (!rows.has(op.updateOne.filter._id)) rows.set(op.updateOne.filter._id, op.updateOne.update.$setOnInsert); saveStore(); },
  updateMany: () => Promise.resolve(),
});

const gridfs = new Map();
stubModule('services/gridfsService.js', { downloadFileStream: (id) => Readable.from([Buffer.from(JSON.stringify(gridfs.get(id)))]) });

// Count real model calls (and simulate an outage) around the real function.
const quietLoad = () => { const s = { log: console.log, warn: console.warn }; console.log = console.warn = () => {}; return () => Object.assign(console, s); };
let restore = quietLoad();
const gemini = require(path.join(BACKEND, 'services/geminiService'));
restore();
const realTranslate = gemini.translateReportUnits;
const stats = { calls: 0, units: 0, failures: {} };
gemini.translateReportUnits = async (units, lang, opts) => {
  stats.calls++; stats.units += units.length;
  if (OUTAGE) throw new gemini.ReportTranslationError('transient', { httpStatus: 503 });
  try { return await realTranslate(units, lang, opts); }
  catch (e) { stats.failures[e.category] = (stats.failures[e.category] || 0) + 1; throw e; }
};

// Record what PDFKit draws (text + font size) for the audit dump.
const PDFDocument = require('pdfkit');
let drawn = [];
const realText = PDFDocument.prototype.text;
PDFDocument.prototype.text = function (str, ...rest) {
  if (typeof str === 'string') drawn.push({ text: str, size: this._fontSize });
  return realText.call(this, str, ...rest);
};

const logLines = [];
console.log = (...a) => { const s = a.join(' '); if (s.startsWith('[Localization]')) logLines.push(s); };
console.warn = (...a) => { const s = a.join(' '); if (s.startsWith('[Localization]')) logLines.push(s); };

const { generateSingleLanguagePdf, generateZapPdf } = require(path.join(BACKEND, 'services/pdfService'));
const { _cache: alertsCache } = require(path.join(BACKEND, 'services/zapDetailedAlerts'));
const { auditProse } = require(path.join(BACKEND, 'i18n/languageAudit'));
const fixture = require(path.join(BACKEND, 'tests/fixtures/zapAlerts/stgEbx8.en.json'));
// Production 2026-11-17: every JA report with an XSS finding was refused. A public
// scan with this report (two XSS findings, exact scanner text) runs as kind 'xss'.
const xssFixture = require(path.join(BACKEND, 'tests/fixtures/zapAlerts/xssReport.en.json'));

// ── Fixture scans ──────────────────────────────────────────────────────────────
const BODY = '<!DOCTYPE html>\n<html lang="ja">\n<head>\n  <meta charset="UTF-8">\n  <title>エントリー | e-ATRAI</title>\n</head>';
const occurrence = (i) => ({
  url: `https://stg.example.jp/entry/camp/${i % 2 ? 'v' : ''}`, method: i % 2 ? 'POST' : 'GET', param: i % 2 ? 'extra_fld2' : '', messageId: i,
  request: { header: `POST https://stg.example.jp/entry/camp/ HTTP/1.1\r\nhost: stg.example.jp\r\nuser-agent: Mozilla/5.0\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\nCookie: PHPSESSID=abc123; visited=1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\n`,
    body: 'name_sei=ZAP&name_mei=ZAP&email=zaproxy%40example.com&extra_fld2=..%2F..%2Fetc%2Fpasswd' },
  response: { header: 'HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=315360000; includeSubDomains\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n', body: BODY },
});
const EXTRA = [
  { alert: 'Custom Header Reflection Detected', pluginId: '99999', risk: 'Low', confidence: 'Medium', cweid: '79', wascid: '8',
    description: 'The application reflects the value of a custom request header in the response body without encoding it. An attacker who can influence that header may be able to inject content into the page.',
    solution: 'Do not reflect request header values in responses. If a value must be shown, encode it for the HTML context in which it appears.',
    reference: 'https://example.org/guidance/header-reflection' },
  { alert: 'Information Disclosure - Suspicious Comments', pluginId: '10027', risk: 'Informational', confidence: 'Low', cweid: '200', wascid: '13',
    description: '', solution: '', reference: '' },
];
const alertsFile = (kind) => [...(kind === 'xss' ? xssFixture : fixture), ...EXTRA]
  .map(a => ({ ...a, totalOccurrences: 5, occurrences: [1, 2, 3, 4, 5].map(occurrence) }));

const AI_REPORT = fs.readFileSync(path.join(BACKEND, 'tests/fixtures/zapAlerts/aiReport.en.md'), 'utf8');

function makeScan(kind) {
  const pub = kind === 'public' || kind === 'xss';
  const id = `${pub ? 'scan' : 'zap-auth'}-1794152897672-${kind}`;
  const zap = { status: 'completed', authMethod: pub ? undefined : kind,
    riskCounts: { High: 1, Medium: 1, Low: 2, Informational: 6 }, totalAlerts: 10,
    reportFiles: [{ filename: `zap${pub ? '' : '_auth'}_detailed_alerts_${id}.json`, fileId: `file-${kind}` }] };
  return {
    analysisId: id, target: 'https://stg.example.jp/entry/camp/', status: 'completed',
    createdAt: new Date('2026-11-08T15:48:00Z'), userId: owner,
    pagespeedResult: { lighthouseResult: { categories: { performance: { score: 0.99 }, accessibility: { score: 0.9 }, 'best-practices': { score: 0.96 }, seo: { score: 0.63 } } } },
    observatoryResult: { grade: 'B', score: 70, tests_passed: 8, tests_failed: 2 },
    urlscanResult: { verdicts: { overall: { malicious: false, score: 0 } }, page: { domain: 'stg.example.jp', ip: '203.0.113.7', country: 'JP', server: 'Apache' } },
    zapResult: zap, authScanResult: pub ? undefined : zap, refinedReport: AI_REPORT,
  };
}

// ── Run ────────────────────────────────────────────────────────────────────────
(async () => {
  out(`auth mode: ${gemini.GEMINI_AUTH_MODE()}  model: ${process.env.GEMINI_MODEL_FLASH || 'gemini-2.5-flash'}  location: ${process.env.VERTEX_LOCATION}  outage: ${OUTAGE}`);
  out(`store rows at start: ${rows.size}`);
  const results = [];
  // JA first: it needs the most translation; EN reuses nothing from it.
  for (const lang of ['ja', 'en']) for (const kind of ['basic', 'form', 'public', 'xss']) for (const generator of ['full', 'zap']) {
    gridfs.set(`file-${kind}`, alertsFile(kind));
    alertsCache.clear();
    drawn = [];
    const name = `${kind}-${generator}-${lang}`;
    const before = { calls: stats.calls, units: stats.units };
    const t0 = Date.now();
    try {
      const scan = makeScan(kind);
      const buf = generator === 'full' ? await generateSingleLanguagePdf(scan, lang, 'all') : await generateZapPdf(scan, lang, 'all');
      fs.writeFileSync(path.join(outDir, `${name}.pdf`), buf);
      fs.writeFileSync(path.join(outDir, `${name}.drawn.json`), JSON.stringify(drawn, null, 1));
      const failures = drawn.filter(d => d.size > 8).flatMap(d => d.text.split('\n'))
        .filter(l => l.trim() && !auditProse(l.trim(), lang).ok).length;
      results.push({ name, ok: true, ms: Date.now() - t0, calls: stats.calls - before.calls, units: stats.units - before.units, bytes: buf.length, auditFailures: failures });
    } catch (e) {
      results.push({ name, ok: false, ms: Date.now() - t0, code: e.code || e.name, detail: e.detail ? {
        unresolvedUnits: e.detail.unresolvedUnits, auditFailures: e.detail.auditFailures,
        unresolved: e.detail.unresolved, gate: e.detail.gate } : undefined });
    }
  }
  for (const r of results) out(JSON.stringify(r));
  out(`model calls: ${stats.calls}, units sent: ${stats.units}, call failures by category: ${JSON.stringify(stats.failures)}`);
  out(`store rows at end: ${rows.size}`);
  fs.writeFileSync(path.join(outDir, OUTAGE ? 'localization-log-outage.txt' : 'localization-log.txt'), logLines.join('\n'));
  if (OUTAGE) {
    const bad = results.filter(r => r.name.endsWith('-ja') && (r.ok || r.code !== 'REPORT_TRANSLATION_UNAVAILABLE'));
    out(bad.length ? `OUTAGE CHECK FAILED: ${bad.map(b => b.name).join(', ')}` : 'outage check: every JA report refused, no JA PDF written');
  } else {
    const bad = results.filter(r => !r.ok || r.auditFailures);
    out(bad.length ? `CHECK FAILED: ${bad.map(b => b.name).join(', ')}` : `check: all ${results.length} PDFs generated, every drawn prose string passed the audit`);
  }
})().catch(e => { out(`fatal: ${e.name} ${e.code || ''}`); process.exitCode = 1; });
