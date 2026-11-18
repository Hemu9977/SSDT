'use strict';

/**
 * The language audit that gates every PDF report (i18n/languageAudit.js).
 *
 * A Japanese report must read as Japanese, yet Japanese security writing keeps
 * header names, identifiers, product names and notation in their original form.
 * These tables pin both sides: legitimate technical Japanese must pass (false
 * positives would refuse good reports) and untranslated English must fail (false
 * negatives would ship mixed-language reports). Each failing entry also pins the
 * reason, so a rule change cannot pass silently.
 *
 * Run with: node --test backend/tests/languageAudit.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { auditProse, isApprovedWord } = require('../i18n/languageAudit');

const reasons = (text, lang, opts) => auditProse(text, lang, opts).issues.map(i => i.reason);

// ── Japanese report: must pass (false-positive guards) ────────────────────────
const JA_PASS = [
  'Content-Security-Policy ヘッダーを設定してください。',
  'X-Frame-Options を DENY または SAMEORIGIN に設定してください。',
  'Cookie に HttpOnly 属性と Secure 属性、SameSite=Lax を付与してください。',
  'Strict-Transport-Security: max-age=31536000; includeSubDomains',
  'TLS 1.2 以上を使用してください。',
  'HTTP/1.1 の GET リクエストに対して 200 OK が返されました。',
  'CWE-79、CVE-2021-44228、WASC-8、OWASP Top 10 を参照してください。',
  'Apache 2.4.x、jQuery 3.5.0、WordPress、PHP、Ruby on Rails、Internet Explorer を確認しました。',
  'Unix の chroot jail、AppArmor、SELinux などを使用してください。',
  'Java SecurityManager の java.io.FilePermission や realpath() 関数を利用できます。',
  '"../" や ..%c0%af、%2e%2e%2f のような文字列、\'nosniff\'、UTF-8、MIME タイプ、API キー',
  '詳細は {{T3}} を参照してください。{{T0}}',
  'Server ヘッダーにバージョン情報が含まれています。',
  'クロスサイトスクリプティング（XSS）や CSRF の対策として、入力検証を実施してください。',
  'x-content-type-options ヘッダーが見つかりません。',
  'Web アプリケーションの Cookie を確認してください。',
  'パフォーマンス: 99/100',
  // Command-line options are notation (the scanner's Log4Shell solution).
  'クラスパスから JndiLookup クラスを削除してください（例: zip -q -d log4j-core-*.jar）。',
  'SEO: 63/100',
];

for (const text of JA_PASS) {
  test(`JA passes: ${text.slice(0, 50)}`, () => {
    assert.deepEqual(reasons(text, 'ja'), []);
  });
}

// Curated-style titles with technical names are short fields and still pass.
// (The last two are scanner titles found by the sweep: CSP keywords and the scanner's spelling.)
for (const title of ['X-Content-Type-Options ヘッダーの欠落', 'SQL インジェクション - PostgreSQL',
  'script-src unsafe-hashes', 'Viewstate',
  'Spring Actuator による情報漏えい', 'CSP: script-src での unsafe-inline の許可']) {
  test(`JA short field passes: ${title}`, () => {
    assert.deepEqual(reasons(title, 'ja', { short: true }), []);
  });
}

// ── Japanese report: must fail (false-negative guards) ────────────────────────
const JA_FAIL = [
  ['Use an allow list of acceptable inputs.', 'en_function_word'],
  ['これは test of the system です', 'en_function_word'],
  ['入力を検証してください。Run your code using the lowest privileges.', 'en_function_word'],
  ['Set the X-Frame-Options header', 'en_function_word'],
  ['The Content-Security-Policy and X-Frame-Options headers were not set.', 'en_function_word'],
  // Ordinary English words that are also header names must not hide a sentence.
  ['Accept known good input only', 'en_run'],
  ['Session Management Response Identified', 'en_run'],
  // Long text, mostly English with a little Japanese.
  ['Validate input carefully, reject malformed requests, canonicalize paths first です', 'en_run'],
];

for (const [text, reason] of JA_FAIL) {
  test(`JA fails (${reason}): ${text.slice(0, 50)}`, () => {
    assert.ok(reasons(text, 'ja').includes(reason), `got ${JSON.stringify(reasons(text, 'ja'))}`);
  });
}

test('JA titles: an untranslated English title fails as a short field, even with two words', () => {
  assert.ok(reasons('Path Traversal', 'ja', { short: true }).includes('en_word_in_short_field'));
  assert.ok(reasons('Path Traversal', 'ja').includes('no_japanese'));
  assert.ok(reasons('GET for POST', 'ja', { short: true }).includes('en_function_word'));
  assert.ok(reasons('パストラバーサル（Path Traversal）', 'ja', { short: true }).includes('en_word_in_short_field'),
    'an English subtitle in a JA title is rejected');
});

test('JA: a few English words in a long Japanese paragraph do not pass if they form a phrase', () => {
  const ok = 'このヘッダーはブラウザーによる MIME タイプの推測を防止し、コンテンツの安全な解釈を保証します。';
  assert.deepEqual(reasons(ok, 'ja'), []);
  const bad = 'このヘッダーは browser content sniffing を防止します。';
  assert.ok(reasons(bad, 'ja').includes('en_run'));
});

// ── Document titles (production, 2026-11-17) ─────────────────────────────────
// Gemini's correct translation of ZAP's XSS solution line keeps the OWASP document
// title; the audit read "Prevention Cheat Sheet" as an English run and every JA
// report with an XSS finding was refused.
test('JA passes: published document titles kept in Latin script', () => {
  for (const text of [
    '必要なエンコーディングとエスケープの種類について詳しくは、XSS Prevention Cheat Sheet を参照してください。',
    '詳細は OWASP Cross Site Scripting Prevention Cheat Sheet を参照してください。',
    'OWASP Cheat Sheet Series の SQL Injection Prevention Cheat Sheet を参照してください。',
    // Only capitalised title words are part of a title ("based" still counts as English).
    'DOM based XSS Prevention Cheat Sheet の推奨事項に従って、出力を適切にエンコードしてください。',
  ]) assert.deepEqual(reasons(text, 'ja'), [], text);
});

test('JA still fails: the untranslated English line, and lower-case "cheat sheet" in English prose', () => {
  const src = 'Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.';
  assert.deepEqual(reasons(src, 'ja'), ['en_function_word', 'en_run', 'no_japanese']);
  assert.ok(reasons('この cheat sheet for developers を参照してください。', 'ja').includes('en_function_word'));
  assert.ok(reasons('Please read this guide carefully and apply it before release です', 'ja').includes('en_run'));
  // A title is removed, the English sentence around it still fails.
  assert.ok(reasons('Read the XSS Prevention Cheat Sheet before you deploy.', 'ja').includes('en_function_word'));
});

// ── English report ─────────────────────────────────────────────────────────────
test('EN passes: hosts (including IDN), URLs, placeholders, headers and code', () => {
  for (const text of [
    'The site 例え.jp responded with 200 OK.',
    'See https://e.jp/日本 for details.',
    'Set Content-Security-Policy and X-Frame-Options: DENY.',
    'The value {{T0}} was reflected.',
  ]) assert.deepEqual(reasons(text, 'en'), [], text);
});

test('EN fails: Japanese prose or Japanese punctuation', () => {
  assert.ok(reasons('The page title 会社概要 is shown.', 'en').includes('ja_text'));
  assert.ok(reasons('Done。', 'en').includes('ja_punctuation'));
  assert.ok(reasons('The label 「Contact」 was found.', 'en').includes('ja_punctuation'));
});

test('approved words: plain words match only in canonical case, hyphenated names in any case', () => {
  assert.equal(isApprovedWord('Accept'), true);
  assert.equal(isApprovedWord('accept'), false);
  assert.equal(isApprovedWord('allow'), false);
  assert.equal(isApprovedWord('x-frame-options'), true);
  assert.equal(isApprovedWord('XSS'), true);
  assert.equal(isApprovedWord('HttpOnly'), true);
  assert.equal(isApprovedWord('the'), false);
});
