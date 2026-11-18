'use strict';

/**
 * The scanner's own Japanese catalog (i18n/zapCatalog.ja.json), its builder
 * (i18n/zapCatalogBuild.js) and the run-time lookup (i18n/zapJaCatalog.js).
 *
 * The catalog is substituted for scanner text with no model and no human in the
 * loop, so every line in it must be safe to draw: aligned with the right English
 * line, the same literals, and passing the same validation a model translation
 * must pass.
 *
 * Run with: node --test backend/tests/zapJaCatalog.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const geminiFile = path.join(BACKEND, 'services/geminiService.js');
require.cache[geminiFile] = { id: geminiFile, filename: geminiFile, loaded: true,
  exports: { REPORT_TRANSLATION_SPEC: { model: 'test-model' } } };

const JSZip = require('jszip');
const { validateTranslation } = require('../services/reportLocalization');
const { protect, restore, placeholderList } = require('../i18n/protectTokens');
const { buildCatalog, alignText, parseProperties, parseVulnerabilitiesXml, catalogKey, addOnVersion } =
  require('../i18n/zapCatalogBuild');
const { catalogTranslation, catalogSize } = require('../i18n/zapJaCatalog');
const catalogFile = require('../i18n/zapCatalog.ja.json');

const XSS_LINE = 'Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.';

test('checked-in catalog: built from the pinned ZAP image, and every line still validates', () => {
  assert.match(catalogFile.source.image || '', /zaproxy@sha256:[0-9a-f]{64}$/);
  const pinned = require('../../infrastructure/zap-task-def.json').containerDefinitions[0].image;
  assert.equal(catalogFile.source.image, pinned, 'catalog was built from a different ZAP image — rebuild it (scripts/buildZapJaCatalog.js)');
  const entries = Object.entries(catalogFile.entries);
  assert.ok(entries.length > 1000, `${entries.length} lines`);
  assert.equal(catalogSize(), entries.length);
  for (const [key, ja] of entries) {
    assert.match(key, /^[0-9a-f]{64}$/);
    // Every placeholder in a catalog line is numbered within its English line's tokens.
    for (const p of placeholderList(ja)) assert.match(p, /^\{\{T\d+\}\}$/);
  }
});

test('the production line has the scanner\'s reviewed Japanese', () => {
  const ja = catalogTranslation('prose', protect(XSS_LINE).masked);
  assert.equal(ja, '必要なエンコーディングとエスケープの種類の詳細については、XSS対策チートシートを参照してください。');
  assert.equal(validateTranslation(XSS_LINE, ja, 'ja', 'prose'), null);
  assert.equal(catalogTranslation('title', protect(XSS_LINE).masked), null, 'keyed by kind');
  assert.equal(catalogTranslation('prose', 'Something no scanner ever said.'), null);
});

test('literals are carried in masked form and restored exactly', () => {
  // A catalog line whose English carries a literal (a path, code, header value…).
  const withToken = Object.values(catalogFile.entries).find(ja => /\{\{T\d+\}\}/.test(ja));
  assert.ok(withToken, 'some catalog lines carry literals');
  const en = 'Use "../" sequences carefully, never pass them to realpath() unchecked.';
  const { masked, tokens } = protect(en);
  assert.equal(restore(masked, tokens), en);
});

test('parseProperties: escapes, continuation lines, separators', () => {
  const p = parseProperties([
    '# comment',
    'a.name = Cross Site Scripting',
    'a.desc=Line one\\nLine two',
    'a.soln: Use \\u30af\\u30c3\\u30ad\\u30fc \\',
    '    carefully.',
    'a.refs https\\://example.org/x',
  ].join('\n'));
  assert.equal(p.get('a.name'), 'Cross Site Scripting');
  assert.equal(p.get('a.desc'), 'Line one\nLine two');
  assert.equal(p.get('a.soln'), 'Use クッキー carefully.');
  assert.equal(p.get('a.refs'), 'https://example.org/x');
});

test('parseVulnerabilitiesXml: items with alert, desc and solution', () => {
  const m = parseVulnerabilitiesXml('<?xml version="1.0"?><vulnerabilities><vuln_items>wasc_8</vuln_items>' +
    '<vuln_item_wasc_8><alert>Cross-site Scripting</alert><desc>A &amp; B</desc><solution>Do X.\nDo Y.</solution>' +
    '<reference>https://example.org</reference></vuln_item_wasc_8></vulnerabilities>');
  assert.deepEqual(m.get('vuln_item_wasc_8'), { alert: 'Cross-site Scripting', desc: 'A & B', solution: 'Do X.\nDo Y.' });
});

test('alignText: line by line only when the structure matches; literal or validation mismatches are dropped', () => {
  const ok = alignText('Phase: Implementation\nUse an allow list of inputs.', 'フェーズ: 実装\n入力の許可リストを使用してください。', 'prose', validateTranslation);
  assert.equal(ok.pairs.length, 2);
  assert.equal(ok.pairs[1].jaMasked, '入力の許可リストを使用してください。');

  const shifted = alignText('Line one is here.\nLine two is here.', '一行目と二行目をまとめました。', 'prose', validateTranslation);
  assert.deepEqual(shifted.pairs, []);
  assert.equal(shifted.rejected.line_structure, 1);

  const literal = alignText('Never pass "../" to the file API.', 'ファイル API に "..\\" を渡さないでください。', 'prose', validateTranslation);
  assert.deepEqual(literal.pairs, []);
  assert.equal(literal.rejected.literals_differ, 1);

  // Crowdin leaves untranslated keys as English: never used.
  const untranslated = alignText('Use an allow list of inputs.', 'Use an allow list of inputs.', 'prose', validateTranslation);
  assert.deepEqual(untranslated.pairs, []);
});

test('alignText: literals that move within the Japanese sentence keep the English numbering', () => {
  const en = 'Set {{X}} to "nosniff;" and remove "X-Powered-By:" from /etc/app.conf entries.'.replace('{{X}}', 'the header');
  const { masked, tokens } = protect(en);
  const ja = '/etc/app.conf から "X-Powered-By:" を削除し、ヘッダーを "nosniff;" に設定してください。';
  const r = alignText(en, ja, 'prose', validateTranslation);
  assert.equal(r.pairs.length, 1);
  assert.equal(restore(r.pairs[0].jaMasked, tokens), ja);
  assert.equal(r.pairs[0].enMasked, masked);
});

test('buildCatalog: the newest add-on version wins; keys are (kind, masked English)', async () => {
  const mk = async (ja) => {
    const z = new JSZip();
    z.file('org/x/resources/Messages.properties', 'r.desc = Use an allow list of inputs.\nr.refs = https\\://e.org\n');
    z.file('org/x/resources/Messages_ja_JP.properties', `r.desc = ${ja}\nr.refs = https\\://e.org\n`);
    return JSZip.loadAsync(await z.generateAsync({ type: 'nodebuffer' }));
  };
  const { catalog, report } = await buildCatalog([
    { name: 'rules-release-9.zap', zip: await mk('\\u53e4\\u3044\\u8a33\\u3067\\u3059\\u3002\\u5165\\u529b\\u3092\\u8a31\\u53ef\\u30ea\\u30b9\\u30c8\\u3067\\u691c\\u8a3c\\u3057\\u307e\\u3059\\u3002') },
    { name: 'rules-release-10.zap', zip: await mk('\\u5165\\u529b\\u306e\\u8a31\\u53ef\\u30ea\\u30b9\\u30c8\\u3092\\u4f7f\\u7528\\u3057\\u3066\\u304f\\u3060\\u3055\\u3044\\u3002') },
  ], { validate: validateTranslation, source: { image: 'test' } });
  assert.equal(report.pairs, 1);
  assert.equal(catalog.entries[catalogKey('prose', 'Use an allow list of inputs.')], '入力の許可リストを使用してください。');
  assert.deepEqual(addOnVersion('ascanrules-release-83.zap'), { id: 'ascanrules', version: [83] });
  assert.deepEqual(addOnVersion('commonlib-release-1.43.0.zap'), { id: 'commonlib', version: [1, 43, 0] });
});
