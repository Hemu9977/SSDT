'use strict';

/**
 * The English report for a Japanese customer and a Japanese site.
 *
 * These EXECUTE the real generateSingleLanguagePdf with the model layer, GridFS,
 * the DOCX template and Gemini stubbed, and record every string PDFKit draws.
 * They exist because, for a Japanese site, the English report never downloaded
 * while the Japanese one always did: it aborted with EN_CONTENT_NOT_ENGLISH on any
 * Japanese character — including each occurrence's `evidence`, which the report
 * never even draws, so the site's own HTML was enough (production, 26 Oct 2026:
 * eleven attempts on one scan, all failed). The English report now translates the
 * site's Japanese, keeps raw HTTP evidence verbatim, and — since reports are
 * never rendered with mixed-language prose — refuses with
 * REPORT_TRANSLATION_UNAVAILABLE when that translation is unavailable.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Readable } = require('node:stream');

const BACKEND = path.join(__dirname, '..');
const stub = (mod, exports) => {
  const file = path.join(BACKEND, mod);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};

const owner = { name: '山田太郎', email: 'yamada@example.co.jp' };
let historyRecords = [];
const chain = {
  sort: () => chain, limit: () => chain, select: () => chain, populate: () => chain,
  lean: async () => historyRecords
};
stub('models/ScanResult.js', { find: () => chain });

// The translation store, in memory (same query shapes as models/ReportTranslation.js).
const { memoryTranslationModel, fakeJapanese } = require('./support/localizationStubs');
const translationModel = memoryTranslationModel();
stub('models/ReportTranslation.js', translationModel);

// GridFS: the detailed-alerts file, streamed in small chunks.
const gridfs = { files: new Map(), opened: [] };
stub('services/gridfsService.js', {
  downloadFileStream: (id) => {
    gridfs.opened.push(id);
    const buf = Buffer.from(JSON.stringify(gridfs.files.get(id), null, 2));
    const chunks = [];
    for (let i = 0; i < buf.length; i += 997) chunks.push(buf.subarray(i, i + 997));
    return Readable.from(chunks);
  }
});
stub('services/reportTemplateDocx.js', { getReportTemplateStaticContent: async () => ({}) });

// Gemini: a phrasebook translator (JA→EN) that records what it was sent. Into
// Japanese it uses a deterministic stand-in. Text it does not know comes back
// unchanged, which the engine rejects as untranslated.
const PHRASES = {
  'The site is in good shape. ページタイトル「株式会社サンプル」 is served over HTTPS.':
    'The site is in good shape. The page title "Sample Co., Ltd." is served over HTTPS.',
  '詳細は {{T0}} をご覧ください': 'See {{T0}} for details',
  'お問い合わせフォームに入力検証がありません': 'The contact form has no input validation',
};
const gemini = { sent: [], fail: false };
stub('services/geminiService.js', {
  translateReportUnits: async (units, lang) => {
    const texts = units.map(u => u.text);
    gemini.sent.push({ texts, lang });
    if (gemini.fail) throw Object.assign(new Error('report translation failed: transient'), { category: 'transient' });
    return { translations: new Map(units.map(u => [u.id, lang === 'ja' ? fakeJapanese(u.text) : (PHRASES[u.text] ?? u.text)])) };
  },
  formatAiAnalysisForPdf: async () => null,
});

// Record everything drawn.
const PDFDocument = require('pdfkit');
let drawn = [];
const realText = PDFDocument.prototype.text;
PDFDocument.prototype.text = function (str, ...rest) {
  if (typeof str === 'string') drawn.push(str);
  return realText.call(this, str, ...rest);
};

// Keep test output readable; the generator logs every stage.
for (const k of ['log', 'warn']) console[k] = () => {};

const { generateSingleLanguagePdf, buildScanHistoryTable } = require('../services/pdfService');
const { _cache: alertsCache } = require('../services/zapDetailedAlerts');

const JA = /[぀-ヿ㐀-鿿]/;
const isPdf = (buf) => Buffer.isBuffer(buf) && buf.length > 1000 && buf.subarray(0, 5).toString() === '%PDF-';
const drawnText = () => drawn.join('\n');

// A Japanese site: Japanese in the AI analysis, in a finding, and in the pages
// ZAP captured (evidence and the response body).
const pageBody = '<html><head><title>会社概要</title></head><body>お問い合わせはこちら</body></html>';
const occurrence = (i) => ({
  url: `https://example.co.jp/contact?p=${i}`, method: 'POST', param: 'name', messageId: i,
  evidence: '<input name="氏名">',
  request: { header: 'POST https://example.co.jp/contact HTTP/1.1\r\n\r\n', body: 'name=%E5%B1%B1' },
  response: { header: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n', body: pageBody }
});
const detailedAlerts = () => [{
  alert: 'Absence of Anti-CSRF Tokens', risk: 'Medium', confidence: 'Low',
  description: 'No Anti-CSRF tokens were found.\nお問い合わせフォームに入力検証がありません',
  solution: 'Use a vetted library.', reference: 'https://owasp.org/csrf', cweid: '352', wascid: '9',
  totalOccurrences: 25, occurrences: Array.from({ length: 25 }, (_, i) => occurrence(i))
}, {
  alert: 'Server Leaks Version Information', risk: 'Low', confidence: 'High',
  description: 'The server leaks its version.', solution: 'Hide it.', totalOccurrences: 1,
  occurrences: [occurrence(99)]
}];

const makeScan = (overrides = {}) => ({
  analysisId: 'scan-ja-1', target: 'https://example.co.jp', status: 'completed',
  createdAt: new Date('2026-10-20T03:00:00Z'), userId: owner,
  observatoryResult: { grade: 'B', score: 70, tests_passed: 8, tests_failed: 2 },
  zapResult: {
    status: 'completed', riskCounts: { High: 0, Medium: 1, Low: 1, Informational: 0 },
    reportFiles: [{ filename: 'zap_auth_detailed_alerts_scan-ja-1.json', fileId: 'file-1' }]
  },
  refinedReport: [
    '# Security Analysis',
    '## Summary',
    'The site is in good shape. ページタイトル「株式会社サンプル」 is served over HTTPS.',
    '- 詳細は https://example.co.jp/company をご覧ください'
  ].join('\n'),
  ...overrides
});

test.beforeEach(() => {
  drawn = [];
  gemini.sent = [];
  gemini.fail = false;
  translationModel.rows.clear();
  alertsCache.clear();
  gridfs.opened = [];
  gridfs.files.set('file-1', detailedAlerts());
  historyRecords = [{ createdAt: new Date('2026-10-20T03:00:00Z'), userId: owner, status: 'completed' }];
});

for (const order of [['ja', 'en'], ['en', 'ja']]) {
  test(`${order.join(' then ').toUpperCase()}: both reports generate for the same Japanese-site scan`, async () => {
    const scan = makeScan();
    for (const lang of order) {
      assert.ok(isPdf(await generateSingleLanguagePdf(scan, lang, 'all')), `${lang} report is a PDF`);
    }
  });
}

test('EN: the site\'s Japanese is drawn translated, with URLs restored', async () => {
  assert.ok(isPdf(await generateSingleLanguagePdf(makeScan(), 'en', 'all')));
  const text = drawnText();
  assert.match(text, /The site is in good shape\. The page title "Sample Co\., Ltd\." is served over HTTPS\./);
  assert.match(text, /See https:\/\/example\.co\.jp\/company for details/);
  assert.match(text, /The contact form has no input validation/);
  assert.ok(!text.includes('株式会社サンプル') && !text.includes('入力検証'), 'translated passages are not also drawn in Japanese');
});

test('EN: raw HTTP evidence stays verbatim', async () => {
  await generateSingleLanguagePdf(makeScan(), 'en', 'all');
  assert.ok(drawnText().includes('お問い合わせはこちら'), 'the response body is evidence, never translated');
  for (const { texts } of gemini.sent) {
    assert.ok(!texts.some(t => t.includes('お問い合わせはこちら') || t.includes('氏名')), 'evidence is never sent for translation');
  }
});

test('nothing identifying reaches Gemini: no URL, host, operator name or email', async () => {
  for (const lang of ['en', 'ja']) await generateSingleLanguagePdf(makeScan(), lang, 'all');
  const sent = JSON.stringify(gemini.sent);
  assert.ok(gemini.sent.length > 0);
  for (const secret of ['example.co.jp', 'https://', owner.email, owner.name]) {
    assert.ok(!sent.includes(secret), `${secret} was sent to Gemini`);
  }
});

test('EN is refused, not drawn half-Japanese, when the site\'s Japanese cannot be translated', async () => {
  gemini.fail = true;
  await assert.rejects(generateSingleLanguagePdf(makeScan(), 'en', 'all'),
    (e) => e.code === 'REPORT_TRANSLATION_UNAVAILABLE' && e.detail.lang === 'en' && e.detail.unresolvedUnits > 0);
  assert.equal(drawn.length, 0, 'nothing was rendered');
});

test('EN of an English-only site needs no translation and generates during an outage', async () => {
  gemini.fail = true;
  const scan = makeScan({ refinedReport: '# Security Analysis\n## Summary\nThe site is in good shape.' });
  gridfs.files.set('file-1', detailedAlerts().map(a => ({ ...a, description: a.description.split('\n')[0] })));
  assert.ok(isPdf(await generateSingleLanguagePdf(scan, 'en', 'all')));
  assert.equal(gemini.sent.length, 0, 'no translation was requested');
});

test('downloading the English report again reuses the stored translations', async () => {
  await generateSingleLanguagePdf(makeScan(), 'en', 'all');
  const firstCalls = gemini.sent.length;
  assert.ok(firstCalls > 0);
  drawn = [];
  await generateSingleLanguagePdf(makeScan(), 'en', 'all');
  assert.equal(gemini.sent.length, firstCalls, 'no new Gemini calls');
  assert.match(drawnText(), /The page title "Sample Co\., Ltd\."/);
});

test('repeated reports of one scan read the detailed-alerts file once', async () => {
  const scan = makeScan();
  await Promise.all([generateSingleLanguagePdf(scan, 'en', 'all'), generateSingleLanguagePdf(scan, 'ja', 'all')]);
  await generateSingleLanguagePdf(scan, 'en', 'all');
  assert.deepEqual(gridfs.opened, ['file-1']);
});

test('evidence: three occurrences drawn, the rest counted from the whole file', async () => {
  await generateSingleLanguagePdf(makeScan(), 'en', 'all');
  const text = drawnText();
  assert.match(text, /22 more request\/response pair\(s\) available in the JSON export/);
  assert.ok(!/more request\/response pair/.test(text.split('Server Leaks Version Information')[1] || ''),
    'a finding with one occurrence has no "more" line');
});

test('the plan severity filter applies when the detailed file is missing', async () => {
  const scan = makeScan({
    zapResult: {
      status: 'completed', riskCounts: { High: 1, Medium: 1, Low: 0, Informational: 0 },
      alerts: [{ alert: 'SQL Injection', risk: 'High' }, { alert: 'Absence of Anti-CSRF Tokens', risk: 'Medium' }]
    }
  });
  await generateSingleLanguagePdf(scan, 'en', 'critical-high');
  const text = drawnText();
  assert.match(text, /SQL Injection/);
  assert.ok(!text.includes('Absence of Anti-CSRF Tokens'));
});

test('scan history table comes from the database rows, English rows English-only', () => {
  const table = buildScanHistoryTable([
    { dateEn: '20/10/2026', dateJa: '2026/10/20', executedByEn: owner.email, executedByJa: owner.name, status: 'completed' },
    { dateEn: '19/10/2026', dateJa: '2026/10/19', executedByEn: owner.email, executedByJa: owner.name, status: 'combining' },
    { dateEn: '18/10/2026', dateJa: '2026/10/18', executedByEn: 'Unknown', executedByJa: '（不明）', status: 'cancelled' }
  ]);
  assert.deepEqual(table.rows.en, [
    ['20/10/2026', owner.email, 'Completed'],
    ['19/10/2026', owner.email, 'Scanning'],
    ['18/10/2026', 'Unknown', 'Cancelled']
  ]);
  assert.deepEqual(table.rows.ja, [
    ['2026/10/20', owner.name, '診断終了'],
    ['2026/10/19', owner.name, 'スキャン中'],
    ['2026/10/18', '（不明）', '停止']
  ]);
  assert.ok(!JA.test(JSON.stringify([table.title.en, table.headers.en, table.rows.en])));
  assert.deepEqual(buildScanHistoryTable(undefined).rows, { en: [], ja: [] });
});
