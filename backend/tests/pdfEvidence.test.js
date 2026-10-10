'use strict';

/**
 * Request/Response evidence in the PDF reports (EN and JA).
 *
 * These EXECUTE the real renderVulnerabilityDetailsSection into a PDFKit document
 * and inspect every line PDFKit draws. They exist because the evidence section
 * shipped with four defects, all invisible to anything that does not look at
 * drawn output:
 *  - tabs, U+FFFD, emoji and other code points outside Noto Sans JP drew as squares,
 *    and Arabic/Hebrew/Thai/Devanagari text was unreadable (now drawn with the
 *    bundled Noto fallback fonts);
 *  - the evidence went through the prose sanitizer, which decoded `&lt;` in both
 *    languages and, in JA only, decoded backslash escapes and NFKC-folded `ＡＢＣ™`;
 *  - the `#1 GET <url>` line had no width, so long URLs ran past the frame;
 *  - a `Request:` / `Response:` label could be stranded at the foot of a page.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');

// pdfService pulls in the model layer, Gemini and GridFS; none are used here.
for (const mod of ['models/ScanResult.js', 'services/geminiService.js',
                   'services/gridfsService.js', 'services/reportTemplateDocx.js']) {
  const file = path.join(BACKEND, mod);
  require.cache[file] = { id: file, filename: file, loaded: true, exports: {} };
}

const PDFDocument = require('pdfkit');
const { renderVulnerabilityDetailsSection, buildEvidenceText, sanitizeEvidenceForPdf, registerPdfFonts } =
  require('../services/pdfService');

const MARGIN = { top: 60, bottom: 60, left: 55, right: 55 };

// ─── Fixture: what ZAP actually captures ─────────────────────────────────────
const htmlBody =
  '<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<title>ＡＢＣ ™</title>\n' +
  '\t\t<script>var s = "a\\nb"; var t = "\\u003cb\\u003e"; /** doc **/ src/**/*.js</script>\n' +
  '\t<body><p>&lt;tag&gt; &amp; 😀 ا \u202E \uFFFD\u0001 lone\rCR</p>\n' +
  '\t<p>هذا النطاق مخصص</p><p>דומיין זה מיועד</p><p>โดเมนนี้</p><p>यह डोमेन</p>\n';
const header = (extra = '') =>
  'GET https://example.com/search?q=%3Cscript%3E HTTP/1.1\r\nHost: example.com\r\n' +
  `Cookie: session=${'A'.repeat(400)}\r\n${extra}\r\n`;
const occ = (i, body, extra) => ({
  method: 'GET', url: `https://example.com/search?page=${i}&token=${'z'.repeat(200)}`, param: 'q',
  request: { header: header(extra), body: '' },
  response: { header: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n', body }
});
const VULNS = [
  { name: 'Cross Site Scripting (Reflected)', risk: 'High', confidence: 'Medium',
    description: 'd', solution: 's', reference: 'https://owasp.org/a\nhttps://owasp.org/b',
    occurrences: [occ(1, htmlBody), occ(2, htmlBody), occ(3, htmlBody), occ(4, htmlBody)] },
  { name: 'Content Security Policy (CSP) Header Not Set On Static Binary Resources Served From The Asset Pipeline',
    risk: 'Medium', confidence: 'High', description: 'd', solution: 's',
    occurrences: [
      { method: 'GET', url: 'https://example.com/logo.png', request: { header: header(), body: '' },
        response: { header: 'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n',
                    body: '\uFFFDPNG\r\n\u001a\n\u0000\u0000' + '\uFFFD\u0003x'.repeat(200) } },
      occ(5, '', `X-Long: ${'Q'.repeat(1500)}\r\n`)
    ] }
];

// One short finding, swept across many start positions so every label lands at
// a page foot at least once.
const SMALL = [{ name: 'X-Content-Type-Options Header Missing', risk: 'Low', confidence: 'Medium',
  occurrences: [{ method: 'GET', url: 'https://example.com/',
    request: { header: 'GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n', body: '' },
    response: { header: 'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n', body: '<html>\n\t<body>ok</body>\n</html>' } }] }];
const SWEEP_GAPS = Array.from({ length: 60 }, (_, i) => 4 + i * 3);

const rendered = new Map();
function render(lang, startGap) {
  const key = `${lang}@${startGap}`;
  if (!rendered.has(key)) rendered.set(key, renderRuns(lang, [{ vulns: VULNS, startGap }]));
  return rendered.get(key);
}
function renderSweep(lang) {
  const key = `${lang}@sweep`;
  if (!rendered.has(key)) rendered.set(key, renderRuns(lang, SWEEP_GAPS.map(startGap => ({ vulns: SMALL, startGap }))));
  return rendered.get(key);
}

/**
 * Render each run on a fresh page, starting `startGap` points above the bottom of
 * the frame, and record every line fragment PDFKit draws with the page it landed on.
 */
function renderRuns(lang, runs) {
  const doc = new PDFDocument({ size: 'A4', bufferPages: true, margins: { top: 0, bottom: 0, left: 0, right: 0 } });
  registerPdfFonts(doc);
  assert.equal(typeof doc._fragment, 'function', 'pdfkit internals changed — update this test hook');

  const ctx = {
    doc, templateStatic: { lang }, margin: MARGIN, contentX: MARGIN.left,
    contentWidth: doc.page.width - MARGIN.left - MARGIN.right,
    topY: MARGIN.top, bottomY: doc.page.height - MARGIN.bottom,
    framedPages: 1,
    initFramedPage() { doc.x = this.contentX; doc.y = this.topY; },
    addFramedPage() { doc.addPage(); this.framedPages++; this.initFramedPage(); }
  };
  ctx.initFramedPage();

  const lines = [];
  const original = doc._fragment.bind(doc);
  doc._fragment = (rawText, x, y, options) => {
    const text = `${rawText}`.replace(/\n/g, ''); // PDFKit strips these before drawing
    lines.push({
      text, x, y, page: doc.bufferedPageRange().count,
      // Code points the font active for this draw cannot render (they would be squares).
      missing: [...text].filter(ch => !doc._font.font.hasGlyphForCodePoint(ch.codePointAt(0))),
      right: x + doc.widthOfString(text, options), bottom: y + doc.currentLineHeight()
    });
    return original(rawText, x, y, options);
  };
  runs.forEach(({ vulns, startGap }, i) => {
    if (i > 0) ctx.addFramedPage();
    doc.y = ctx.bottomY - startGap;
    renderVulnerabilityDetailsSection(ctx, vulns, lang);
  });
  const pages = doc.bufferedPageRange().count;
  doc.end();
  return { ctx, lines, pages };
}

const LANGS = ['en', 'ja'];
const START_GAPS = [700, 45, 20];

test('every drawn character has a glyph in the font it is drawn with (no squares)', () => {
  for (const lang of LANGS) for (const gap of START_GAPS) {
    for (const { text, missing } of render(lang, gap).lines) {
      assert.deepEqual(missing.map(ch => `U+${ch.codePointAt(0).toString(16).toUpperCase()}`), [],
        `${lang}: no glyph in "${text.slice(0, 60)}"`);
    }
  }
});

test('Arabic, Hebrew, Thai and Devanagari are drawn as text, not escapes', () => {
  for (const lang of LANGS) {
    const drawn = render(lang, 700).lines.map(l => l.text);
    for (const word of ['النطاق', 'مخصص', 'דומיין', 'מיועד', 'โดเมนนี้', 'डोमेन']) {
      assert.ok(drawn.some(t => t.includes(word)), `${lang}: "${word}" not drawn`);
    }
    assert.ok(!drawn.some(t => /\\u0(5|6|9|E)[0-9A-F]{2}/.test(t)), `${lang}: script text escaped`);
  }
});

// Every rendering under test: the stress fixture at a few start positions, plus the sweep.
const allRenders = lang => [...START_GAPS.map(gap => [`${lang}@${gap}`, render(lang, gap)]),
                            [`${lang}@sweep`, renderSweep(lang)]];

test('every line stays inside the content frame, and only framed pages are added', () => {
  for (const lang of LANGS) for (const [label, { ctx, lines, pages }] of allRenders(lang)) {
    assert.equal(pages, ctx.framedPages, `${label}: PDFKit added a page without the template frame`);
    for (const l of lines) {
      const where = `${label} p${l.page}: "${l.text.slice(0, 50)}"`;
      assert.ok(l.x >= ctx.contentX - 0.5, `left overflow ${where}`);
      assert.ok(l.right <= ctx.contentX + ctx.contentWidth + 0.5, `right overflow ${where}`);
      assert.ok(l.bottom <= ctx.bottomY + 0.5, `bottom overflow ${where}`);
    }
  }
});

test('headings and Request/Response labels are never stranded at a page foot', () => {
  const labels = new Set(['Request:', 'Response:', 'Request / Response Evidence:',
                          'リクエスト:', 'レスポンス:', 'リクエスト / レスポンスの証跡:']);
  for (const lang of LANGS) for (const [label, { lines }] of allRenders(lang)) {
    lines.forEach((l, i) => {
      if (!labels.has(l.text.trim()) || !lines[i + 1]) return;
      assert.equal(lines[i + 1].page, l.page, `${label}: "${l.text}" separated from its content`);
    });
  }
});

test('evidence text is identical in EN and JA and is not decoded or normalized', () => {
  const evidence = lang => render(lang, 700).lines
    .filter(l => !/[぀-ヿ㐀-鿿]/.test(l.text)) // drop localized labels/notes
    .map(l => l.text).join('\n');
  const en = evidence('en');
  const ja = evidence('ja');
  for (const verbatim of ['&lt;tag&gt; &amp;', '"a\\nb"', '"\\u003cb\\u003e"', 'ＡＢＣ ™',
                          '/** doc **/ src/**/*.js']) {
    assert.ok(en.includes(verbatim), `EN lost ${verbatim}`);
    assert.ok(ja.includes(verbatim), `JA lost ${verbatim}`);
  }
  assert.ok(ja.includes(`X-Long: ${'Q'.repeat(10)}`));
  assert.equal(ja.split('Q').length, en.split('Q').length, 'long header split differently per language');
});

test('sanitizeEvidenceForPdf: escapes what cannot be drawn, keeps everything else', () => {
  assert.equal(sanitizeEvidenceForPdf('a\r\nb\rc'), 'a\nb\nc');
  assert.equal(sanitizeEvidenceForPdf('\t<a>\n\t\t<b>'), '    <a>\n        <b>');
  assert.equal(sanitizeEvidenceForPdf('ab\tc'), 'ab  c');
  assert.equal(sanitizeEvidenceForPdf('x\uFFFD\u0001😀\u202E\uFEFFy'),
    'x\\uFFFD\\u0001\\u{1F600}\\u202E\\uFEFFy');
  assert.equal(sanitizeEvidenceForPdf('هذا שלום ไทย हिंदी'), 'هذا שלום ไทย हिंदी');
  assert.equal(sanitizeEvidenceForPdf('&lt; \\n ＡＢＣ ™ **b**'), '&lt; \\n ＡＢＣ ™ **b**');
  assert.equal(sanitizeEvidenceForPdf('a\n\n\n\n\n\nb  \n\n'), 'a\n\n\nb');
});

test('buildEvidenceText: binary bodies are replaced by a localized note', () => {
  const png = '\uFFFDPNG\r\n\u001a\n\u0000' + '\uFFFD'.repeat(50);
  const en = buildEvidenceText('HTTP/1.1 200 OK\r\n\r\n', png, 'en');
  const ja = buildEvidenceText('HTTP/1.1 200 OK\r\n\r\n', png, 'ja');
  assert.ok(!en.includes('\uFFFD') && en.includes('binary body not shown'));
  assert.ok(!ja.includes('\uFFFD') && ja.includes('バイナリデータ'));
  // An ordinary text body with one stray replacement character is still shown.
  assert.ok(buildEvidenceText('', `caf\uFFFD ${'x'.repeat(100)}`, 'en').startsWith('caf\uFFFD'));
});
