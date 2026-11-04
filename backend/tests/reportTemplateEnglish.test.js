'use strict';

/**
 * The English report's template text (disclaimer, scan-history heading, closing
 * page), read from the bundled DOCX.
 *
 * It used to be translated by Gemini, and any Gemini failure threw out of
 * getReportTemplateStaticContent and aborted the English report — and the
 * rejected promise was cached, so every later English report failed too until
 * the backend restarted. Found by running the real generator end to end with
 * Gemini unavailable.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const gemini = { calls: 0, fail: false };
const geminiFile = path.join(__dirname, '..', 'services', 'geminiService.js');
require.cache[geminiFile] = {
  id: geminiFile, filename: geminiFile, loaded: true,
  exports: {
    translateText: async (texts) => {
      gemini.calls++;
      if (gemini.fail) throw new Error('RESOURCE_EXHAUSTED');
      return texts.map((t) => `EN(${t.length})`);
    }
  }
};
console.warn = () => {};

const { getReportTemplateStaticContent, translateTemplateStaticToEnglish } = require('../services/reportTemplateDocx');
const JA = /[぀-ヿ㐀-鿿]/;
const textOf = (t) => [t.disclaimerTitle, t.disclaimerBody, t.diagnosisTitle, ...t.diagnosisHeaders, ...t.finalPageLines].join('\n');

test.beforeEach(() => { gemini.calls = 0; gemini.fail = false; });

test('the bundled template is English without calling Gemini, and reads the same every time', async () => {
  gemini.fail = true;
  const ja = await getReportTemplateStaticContent({ lang: 'ja', forceReload: true });
  assert.ok(JA.test(textOf(ja)), 'the DOCX itself is Japanese');
  const en = await getReportTemplateStaticContent({ lang: 'en' });

  assert.equal(gemini.calls, 0);
  assert.ok(!JA.test(textOf(en)));
  assert.equal(en.disclaimerTitle, 'Disclaimer');
  assert.match(en.disclaimerBody, /^The information shared in this report is confidential/);
  assert.equal(en.finalPageLines.length, ja.finalPageLines.length);
  assert.equal(en.finalPageUrl, ja.finalPageUrl);
});

test('changed template text goes to Gemini; if that fails the report still gets English', async () => {
  const changed = {
    disclaimerTitle: '免責事項',
    disclaimerBody: '新しい免責事項の本文です。',
    diagnosisTitle: '診断履歴',
    diagnosisHeaders: ['日付', '担当者', 'ステータス'],
    finalPageLines: ['新しいキャッチコピー', '当社の専門知識でお客様のデータとシステムを保護します。'],
  };

  const ok = await translateTemplateStaticToEnglish(changed);
  assert.equal(gemini.calls, 1);
  assert.equal(ok.disclaimerBody, `EN(${'新しい免責事項の本文です。'.length})`);
  assert.deepEqual(ok.diagnosisHeaders, ['Date', 'EN(3)', 'Status']);

  gemini.fail = true;
  const fallback = await translateTemplateStaticToEnglish(changed);
  assert.ok(!JA.test(textOf(fallback)));
  assert.equal(fallback.disclaimerTitle, 'Disclaimer');
  assert.match(fallback.disclaimerBody, /automated scan results/);
  assert.deepEqual(fallback.diagnosisHeaders, ['Scan Date', 'Scanner', 'Result']);
  assert.deepEqual(fallback.finalPageLines, ['We protect your data and systems with our expertise.']);
});

test('a translation that comes back Japanese is not used', async () => {
  const out = await translateTemplateStaticToEnglish(
    { disclaimerTitle: '注意', disclaimerBody: '', diagnosisTitle: '診断履歴', diagnosisHeaders: [], finalPageLines: [] },
    { translate: async (texts) => texts }
  );
  assert.equal(out.disclaimerTitle, 'Disclaimer');
});
