'use strict';

/**
 * Both PDF generators, every scan type, both languages — judged on what PDFKit
 * actually draws.
 *
 * Matrix: {HTTP Basic, form login, public} × {generateSingleLanguagePdf,
 * generateZapPdf} × {en, ja}, with the eight findings of the production report
 * that showed English in a Japanese PDF (exact scanner text, including the 5.8k-
 * character Path Traversal finding and User Agent Fuzzer, which has no solution
 * text), plus a finding type unknown to the curated titles.
 *
 * Every string drawn above 8pt is report prose or a label and must pass the
 * language audit for the report language. Evidence (7pt), affected URLs and
 * references (8pt) are data: they must be drawn byte for byte, in both languages.
 * The real DOCX template is used; the model layer, GridFS and Gemini are stubbed.
 *
 * Run with: node --test backend/tests/pdfLocalization.test.js
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
const chain = { sort: () => chain, limit: () => chain, select: () => chain, populate: () => chain,
  lean: async () => [{ createdAt: new Date('2026-11-08T15:48:00Z'), userId: owner, status: 'completed' }] };
stub('models/ScanResult.js', { find: () => chain });

const { memoryTranslationModel, fakeJapanese } = require('./support/localizationStubs');
const translationModel = memoryTranslationModel();
stub('models/ReportTranslation.js', translationModel);

const gridfs = new Map();
stub('services/gridfsService.js', {
  downloadFileStream: (id) => Readable.from([Buffer.from(JSON.stringify(gridfs.get(id)))]),
});

const gemini = { mode: 'ok', sent: [] };
stub('services/geminiService.js', {
  translateReportUnits: async (units, lang) => {
    gemini.sent.push(...units.map(u => u.text));
    if (gemini.mode === 'outage') throw Object.assign(new Error('report translation failed: transient'), { category: 'transient' });
    return { translations: new Map(units.map(u => [u.id, lang === 'ja' ? fakeJapanese(u.text) : u.text])) };
  },
  // Used by the template loader for template text with no built-in English.
  translateText: async (texts) => texts,
  formatAiAnalysisForPdf: async () => null,
});

// Record every text() call (with its font size) and every drawn line fragment.
const PDFDocument = require('pdfkit');
let calls = [], fragments = [];
const realText = PDFDocument.prototype.text;
PDFDocument.prototype.text = function (str, ...rest) {
  if (typeof str === 'string') calls.push({ text: str, size: this._fontSize });
  return realText.call(this, str, ...rest);
};
const realFragment = PDFDocument.prototype._fragment;
PDFDocument.prototype._fragment = function (rawText, x, y, options) {
  const text = `${rawText}`.replace(/\n/g, '');
  fragments.push({
    text, x, size: this._fontSize,
    missing: [...text].filter(ch => !this._font.font.hasGlyphForCodePoint(ch.codePointAt(0))),
    right: x + this.widthOfString(text, options),
  });
  return realFragment.call(this, rawText, x, y, options);
};

for (const k of ['log', 'warn']) console[k] = () => {};

const { generateSingleLanguagePdf, generateZapPdf } = require('../services/pdfService');
const { _cache: alertsCache } = require('../services/zapDetailedAlerts');
const { createLocalizer } = require('../services/reportLocalization');
const { auditProse } = require('../i18n/languageAudit');
const fixture = require('./fixtures/zapAlerts/stgEbx8.en.json');

const PAGE_RIGHT = 595.28 - 55;
const BODY = '<!DOCTYPE html>\n<html lang="ja">\n<head><title>エントリー | e-ATRAI</title></head>';
const REQUEST_HEADER = 'POST https://stg.example.jp/entry/camp/ HTTP/1.1\r\nhost: stg.example.jp\r\nAuthorization: Basic dXNlcjpwYXNz\r\nCookie: PHPSESSID=abc123\r\n\r\n';
const occurrence = (i) => ({
  url: `https://stg.example.jp/entry/camp/?p=${i}`, method: 'POST', param: 'extra_fld2', messageId: i,
  request: { header: REQUEST_HEADER, body: 'name_sei=ZAP&email=zaproxy%40example.com' },
  response: { header: 'HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n', body: BODY },
});
const alerts = () => [...fixture, {
  alert: 'Custom Header Reflection Detected', pluginId: '99999', risk: 'Low', confidence: 'Medium',
  description: 'The application reflects a custom request header in the response body.',
  solution: 'Do not reflect request headers in responses.', reference: 'https://example.org/guidance', cweid: '79', wascid: '8',
}].map(a => ({ ...a, totalOccurrences: 4, occurrences: [occurrence(1), occurrence(2), occurrence(3), occurrence(4)] }));

const AI_REPORT = [
  '# Security Analysis',
  '## Executive Summary',
  'The site has one high risk issue and several low risk issues. The `Strict-Transport-Security` header is set correctly.',
  '## Recommendations',
  '- Set the Content-Security-Policy header on every response.',
  '- SEO: 63/100',
].join('\n');

function makeScan(kind) {
  // Shaped like real analysis ids (zap-auth-1794152897672-vmzt6y).
  const id = `${kind === 'public' ? 'scan' : 'zap-auth'}-1794152897672-${kind}`;
  const zap = { status: 'completed', authMethod: kind === 'public' ? undefined : kind,
    riskCounts: { High: 1, Medium: 1, Low: 2, Informational: 5 },
    reportFiles: [{ filename: `zap${kind === 'public' ? '' : '_auth'}_detailed_alerts_${id}.json`, fileId: `file-${kind}` }] };
  return {
    analysisId: id, target: 'https://stg.example.jp/entry/camp/', status: 'completed',
    createdAt: new Date('2026-11-08T15:48:00Z'), userId: owner,
    pagespeedResult: { lighthouseResult: { categories: { performance: { score: 0.99 }, accessibility: { score: 0.9 }, 'best-practices': { score: 0.96 }, seo: { score: 0.63 } } } },
    observatoryResult: { grade: 'B', score: 70, tests_passed: 8, tests_failed: 2 },
    urlscanResult: { verdicts: { overall: { malicious: false, score: 0 } }, page: { domain: 'stg.example.jp', ip: '203.0.113.7', country: 'JP', server: 'Apache' } },
    zapResult: zap,
    authScanResult: kind === 'public' ? undefined : zap,
    refinedReport: AI_REPORT,
  };
}

async function render(generator, kind, lang) {
  calls = []; fragments = [];
  const scan = makeScan(kind);
  const buf = generator === 'single' ? await generateSingleLanguagePdf(scan, lang, 'all') : await generateZapPdf(scan, lang, 'all');
  assert.ok(Buffer.isBuffer(buf) && buf.subarray(0, 5).toString() === '%PDF-', 'a PDF was produced');
  return { calls: calls.slice(), fragments: fragments.slice() };
}

test.beforeEach(() => {
  gemini.mode = 'ok';
  alertsCache.clear();
  for (const kind of ['basic', 'form', 'public']) gridfs.set(`file-${kind}`, alerts());
});

const MATRIX = [];
for (const kind of ['basic', 'form', 'public']) for (const generator of ['single', 'zap']) for (const lang of ['ja', 'en']) {
  MATRIX.push({ kind, generator, lang });
}

for (const { kind, generator, lang } of MATRIX) {
  test(`${kind} scan · ${generator === 'single' ? 'full report' : 'vulnerability report'} · ${lang.toUpperCase()}: every drawn prose string is ${lang === 'ja' ? 'Japanese' : 'English'}`, async () => {
    const { calls: drawnCalls, fragments: drawnFragments } = await render(generator, kind, lang);

    // Prose and labels (> 8pt): audited for the report language.
    const failures = [];
    for (const c of drawnCalls) {
      if (c.size <= 8) continue;
      for (const line of c.text.split('\n')) {
        if (!line.trim()) continue;
        const r = auditProse(line.trim(), lang);
        if (!r.ok) failures.push(`${r.issues.map(i => i.reason).join(',')}: ${line.trim().slice(0, 80)}`);
      }
    }
    assert.deepEqual(failures, [], 'prose in the wrong language');

    const prose = drawnCalls.filter(c => c.size > 8).map(c => c.text).join('\n');
    // Label and value are separate text() calls on one line ("信頼度: " + "中").
    const inline = drawnCalls.filter(c => c.size > 8).map(c => c.text).join('');
    if (lang === 'ja') {
      assert.match(prose, /\d+\. パストラバーサル/, 'JA title drawn');
      assert.ok(!/\(Path Traversal\)|^Path Traversal$/m.test(prose), 'no English title or subtitle');
      assert.match(inline, /信頼度: (高|中|低)/, 'confidence localized');
      assert.ok(!/信頼度: (High|Medium|Low)/.test(inline), 'confidence drawn in English');
    } else {
      assert.match(prose, /\d+\. Path Traversal/);
      assert.match(inline, /Confidence: (High|Medium|Low)/);
    }
    // Missing solution (User Agent Fuzzer) is the catalog text in the report language.
    assert.ok(!prose.includes('No solution provided') || lang === 'en');

    // No scan type gets a section the others do not (HTTP Basic used to add one).
    assert.ok(!prose.includes(lang === 'ja' ? '評価範囲' : 'Assessment scope'), 'Basic-only scope section drawn');

    // Evidence (7pt) is verbatim and redacted, identical in both languages.
    const evidence = drawnCalls.filter(c => c.size === 7).map(c => c.text).join(' ');
    assert.ok(evidence.includes('[REDACTED]'), 'credential headers redacted');
    assert.ok(!evidence.includes('dXNlcjpwYXNz') && !evidence.includes('abc123'), 'credential drawn');
    for (const token of ['<title>エントリー', 'name_sei=ZAP&email=zaproxy%40example.com', 'charset=UTF-8']) {
      assert.ok(evidence.includes(token), `evidence token missing: ${token}`);
    }
    const data = drawnCalls.filter(c => c.size === 8).map(c => c.text).join('\n');
    assert.ok(data.includes('https://stg.example.jp/entry/camp/?p=1'), 'affected URL drawn verbatim');
    assert.ok(data.includes('https://www.zaproxy.org/') || data.includes('https://owasp.org/') || data.includes('https://example.org/guidance'),
      'reference drawn verbatim');

    // No missing glyphs; nothing past the right margin.
    const missing = drawnFragments.filter(f => f.missing.length).map(f => f.text.slice(0, 40));
    assert.deepEqual(missing, [], 'characters drawn without a glyph');
    const overflow = drawnFragments.filter(f => f.right > PAGE_RIGHT + 1).map(f => `${f.text.slice(0, 40)} (${f.right.toFixed(1)})`);
    assert.deepEqual(overflow, [], 'text past the right margin');
  });
}

for (const generator of ['single', 'zap']) for (const lang of ['ja', 'en']) {
  test(`${generator === 'single' ? 'full report' : 'vulnerability report'} · ${lang.toUpperCase()}: HTTP Basic, form-login and public scans have exactly the same sections`, async () => {
    const headings = {};
    for (const kind of ['basic', 'form', 'public']) {
      const { calls } = await render(generator, kind, lang);
      headings[kind] = calls.filter(c => c.size === 14).map(c => c.text.trim()).filter(Boolean);
    }
    assert.ok(headings.public.length >= (generator === 'single' ? 4 : 1), `too few sections: ${headings.public.join(' | ')}`);
    assert.deepEqual(headings.basic, headings.public, 'HTTP Basic sections differ from a public scan');
    assert.deepEqual(headings.form, headings.public, 'form-login sections differ from a public scan');
  });
}

test('page breaks in Japanese text never strand a bullet marker at the foot of a page', () => {
  // Found in the real-model smoke run (form-auth JA report, page 3): Japanese has
  // no spaces, so the page-break helper backed up to the space after "•" and drew
  // the marker alone, with the bullet's text on the next page.
  const { renderAiAnalysisSection, registerPdfFonts } = require('../services/pdfService');
  const bullet = 'スクリプト、スタイル、フレームについて、信頼できるソースのみを許可する厳格なコンテンツセキュリティポリシーを実装してください。'.repeat(3);
  const first = 'まずパストラバーサルの問題を修正してください。';
  let splitAcrossPages = 0;
  for (let gap = 80; gap <= 400; gap += 3) {
    const doc = new PDFDocument({ size: 'A4', bufferPages: true, margins: { top: 0, bottom: 0, left: 0, right: 0 } });
    registerPdfFonts(doc);
    const ctx = { doc, templateStatic: { lang: 'ja' }, contentX: 55, contentWidth: 595.28 - 110, topY: 60, bottomY: 841.89 - 60,
      initFramedPage() { doc.x = this.contentX; doc.y = this.topY; }, addFramedPage() { doc.addPage(); this.initFramedPage(); } };
    ctx.initFramedPage();
    doc.y = ctx.bottomY - gap;
    const lines = [];
    const orig = doc._fragment.bind(doc);
    doc._fragment = (text, x, y, o) => { lines.push({ text: String(text), page: doc.bufferedPageRange().count }); return orig(text, x, y, o); };
    // Several short bullets, then a long one: like the AI recommendations list.
    renderAiAnalysisSection(ctx, { title: 'AIによるセキュリティ分析',
      sections: [{ content: [{ type: 'bullets', items: [first, first, first, bullet] }] }] }, 'ja');
    doc.end();
    const markers = lines.filter(l => l.text.includes('•'));
    assert.equal(markers.length, 4, `gap ${gap}: every bullet marker drawn`);
    for (const m of markers) {
      assert.notEqual(m.text.replace('•', '').trim(), '', `gap ${gap}: a bullet marker was drawn without its text`);
    }
    const last = lines.indexOf(markers[3]);
    if (lines.slice(last).some(l => l.page !== markers[3].page)) splitAcrossPages++;
  }
  assert.ok(splitAcrossPages > 0, 'the sweep exercised a bullet split across pages');
});

test('Gemini outage: the Japanese report is refused for every scan type and generator — no PDF, nothing drawn', async () => {
  for (const kind of ['basic', 'form', 'public']) {
    for (const generator of ['single', 'zap']) {
      translationModel.rows.clear();
      gemini.mode = 'outage';
      calls = [];
      const scan = makeScan(kind);
      const run = generator === 'single' ? generateSingleLanguagePdf(scan, 'ja', 'all') : generateZapPdf(scan, 'ja', 'all');
      await assert.rejects(run, (e) => e.code === 'REPORT_TRANSLATION_UNAVAILABLE' && e.detail.lang === 'ja');
      assert.equal(calls.length, 0, `${kind}/${generator}: something was drawn`);
    }
  }
});

test('English reports of English scanner text need no translation at all', async () => {
  gemini.sent = [];
  translationModel.rows.clear();
  gemini.mode = 'outage';
  await render('single', 'public', 'en');
  await render('zap', 'basic', 'en');
  assert.deepEqual(gemini.sent, []);
});

test('JA and EN share every non-prose field: findings, severity, confidence, ids, references, URLs and evidence', async () => {
  const rows = new Map();
  const store = { getMany: async (ids) => new Map(ids.filter(i => rows.has(i)).map(i => [i, rows.get(i)])),
    putIfAbsent: async (l) => l.forEach(r => rows.set(r.id, r.translation)), touch() {} };
  const loc = createLocalizer({ logger: () => {}, sleep: async () => {}, store,
    translate: async (units, lang) => ({ translations: new Map(units.map(u => [u.id, lang === 'ja' ? fakeJapanese(u.text) : u.text])) }) });
  const findings = alerts().map(a => ({ name: a.alert, pluginId: a.pluginId, risk: a.risk, confidence: a.confidence,
    description: a.description, solution: a.solution, reference: a.reference, cweid: a.cweid, wascid: a.wascid,
    totalOccurrences: a.totalOccurrences, sampleUrls: a.occurrences.map(o => o.url), occurrences: a.occurrences }));
  const ja = await loc.localizeReport({ findings }, 'ja');
  const en = await loc.localizeReport({ findings }, 'en');
  const DATA = ['originalName', 'pluginId', 'risk', 'confidence', 'reference', 'cweid', 'wascid', 'totalOccurrences', 'sampleUrls', 'occurrences'];
  assert.equal(ja.findings.length, findings.length);
  ja.findings.forEach((f, i) => {
    for (const k of DATA) assert.deepEqual(f[k], en.findings[i][k], `${f.originalName}.${k}`);
    assert.equal(f.occurrences, findings[i].occurrences, 'evidence objects are the originals');
  });
});

test('a second JA download is served from the store: zero model calls, identical text', async () => {
  translationModel.rows.clear();
  gemini.sent = [];
  const first = await render('single', 'basic', 'ja');
  const callsAfterFirst = gemini.sent.length;
  assert.ok(callsAfterFirst > 0);
  alertsCache.clear();
  const second = await render('single', 'basic', 'ja');
  assert.equal(gemini.sent.length, callsAfterFirst, 'no new translation calls');
  const prose = (r) => r.calls.filter(c => c.size > 8).map(c => c.text).join('\n');
  assert.equal(prose(second), prose(first));
});

// ── Production 2026-11-17: a report with XSS findings, both languages ─────────
// Every JA report with a Cross Site Scripting finding was refused (one solution
// line, see reportLocalization.test.js). Rendered here end to end with the exact
// scanner text of a realistic report: two XSS findings, Path Traversal, CSP,
// HSTS, cookie and header findings, several occurrences each (multiple pages).
const xssAlerts = () => require('./fixtures/zapAlerts/xssReport.en.json')
  .map(a => ({ ...a, totalOccurrences: 3, occurrences: [occurrence(1), occurrence(2), occurrence(3)] }));

for (const generator of ['single', 'zap']) for (const lang of ['ja', 'en']) {
  test(`XSS report · ${generator === 'single' ? 'full report' : 'vulnerability report'} · ${lang.toUpperCase()}: generated, every drawn prose line in ${lang === 'ja' ? 'Japanese' : 'English'}`, async () => {
    translationModel.rows.clear();
    gridfs.set('file-public', xssAlerts());
    const { calls: drawn, fragments: frags } = await render(generator, 'public', lang);
    const failures = [];
    for (const c of drawn) {
      if (c.size <= 8) continue;
      for (const line of c.text.split('\n')) {
        if (!line.trim()) continue;
        const r = auditProse(line.trim(), lang);
        if (!r.ok) failures.push(`${r.issues.map(i => i.reason).join(',')}: ${line.trim().slice(0, 80)}`);
      }
    }
    assert.deepEqual(failures, [], 'prose in the wrong language');
    const prose = drawn.filter(c => c.size > 8).map(c => c.text).join('\n');
    if (lang === 'ja') {
      assert.match(prose, /XSS対策チートシートを参照してください。/, 'the line that refused production reports is drawn in Japanese');
      assert.ok(!prose.includes('Consult the XSS Prevention Cheat Sheet'));
      // Kanji, hiragana, katakana and Japanese punctuation all drawn with a glyph.
      assert.match(prose, /[一-鿿]/);
      assert.match(prose, /[぀-ゟ]/);
      assert.match(prose, /[゠-ヿ]/);
      assert.match(prose, /[、。]/);
      assert.match(prose, /[（）「」]/);
    } else {
      assert.match(prose, /Consult the XSS Prevention Cheat Sheet/);
    }
    assert.deepEqual(frags.filter(f => f.missing.length).map(f => f.text.slice(0, 40)), [], 'characters drawn without a glyph');
    assert.deepEqual(frags.filter(f => f.right > PAGE_RIGHT + 1).map(f => f.text.slice(0, 40)), [], 'text past the right margin');
    // Evidence identical and verbatim in both languages.
    const evidence = drawn.filter(c => c.size === 7).map(c => c.text).join(' ');
    assert.ok(evidence.includes('<title>エントリー') && evidence.includes('name_sei=ZAP&email=zaproxy%40example.com'));
    gridfs.set('file-public', alerts());
  });
}
