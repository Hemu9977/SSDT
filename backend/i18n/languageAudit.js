'use strict';

/**
 * Language audit for report PROSE (never for evidence or data).
 *
 * The Japanese report must read as Japanese and the English report as English.
 * A character-presence test is not enough: "Use an allow list of inputs." contains
 * no Japanese and must fail in a JA report, while "Content-Security-Policy ヘッダー
 * を設定してください" contains Latin script and must pass. So the JA audit works
 * on words:
 *
 *   1. Notation is removed: placeholders, URLs, emails, hostnames, quoted or
 *      backtick code, and any token carrying a digit or symbol (CWE-79, HTTP/1.1,
 *      max-age=31536000, java.io.FilePermission, realpath(), %2e%2e%2f…).
 *   2. Allowlisted multi-word names are removed (technicalTerms.PHRASES), and so are
 *      published document titles kept in Latin script (DOCUMENT_TITLE_RE: "XSS
 *      Prevention Cheat Sheet", "OWASP Cheat Sheet Series"). Production, 2026-11-17:
 *      Gemini translated ZAP's XSS solution line as "…XSS Prevention Cheat Sheet を
 *      参照してください。", which is correct Japanese, but "Prevention Cheat Sheet"
 *      counted as an English run, and every JA report with an XSS finding was refused.
 *   3. Each remaining Latin word is approved if it is an allowlisted term or header
 *      name, an X-… header, an HTTP method, an ALL-CAPS acronym (XSS, DENY) or a
 *      camelCase identifier (HttpOnly, FilePermission). Otherwise it is
 *      "unapproved" — ordinary English.
 *   4. The text fails if it has: an English function word among the unapproved
 *      words; a run of ≥3 unapproved words not broken by Japanese text; too large a
 *      share of unapproved English; unapproved English with no Japanese at all; or,
 *      in a short field (title, heading, label — the caller says so), any
 *      unapproved word.
 *
 * The EN audit rejects Japanese script or Japanese punctuation once URLs, emails,
 * hostnames (including IDN hosts) and placeholders are removed.
 *
 * Results carry reason codes and offsets only — callers must never log the text.
 */

const crypto = require('crypto');
const { PHRASES, TERMS, HEADER_NAMES, HTTP_METHODS } = require('./technicalTerms');

const AUDIT_VERSION = 3;

const JA_CHAR = /[぀-ヿ㐀-䶿一-鿿豈-﫿ｦ-ﾟ]/;
const JA_CHAR_G = new RegExp(JA_CHAR.source, 'g');
const JA_PUNCT = /[、。「-』【】〜！（），：；？]/;

// Characters that end a "chunk" of non-Japanese text: whitespace, Japanese script
// and full-width punctuation. Notation tokens are judged chunk by chunk.
const CHUNK_RE = /[^\s　-〿぀-ヿ㐀-䶿一-鿿豈-﫿＀-￯]+/g;
const PLAIN_WORD_RE = /^[A-Za-z][A-Za-z'’-]*$/;
const SYMBOL_OR_DIGIT_RE = /[0-9=\/%\\_.:@#<>{}\[\]()&+*|^~$]/;
const LATIN_WORD_RE = /[A-Za-z][A-Za-z'’-]*[A-Za-z]|[A-Za-z]/g;

const PLACEHOLDER_RE = /\{\{T\d+\}\}/g;
const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>）」]+|\bwww\.[^\s"'<>）」]+/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;
// Hostnames, including IDN hosts (例え.jp): a dotted name ending in an ASCII TLD.
const HOST_RE = /[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?)*\.[A-Za-z]{2,24}\b(?:\/[^\s"'<>]*)?/gu;
const BACKTICK_RE = /`[^`\n]*`/g;
// Quoted literals that are notation rather than words: "../", '..\', "%2e%2e%2f".
const QUOTED_LITERAL_RE = /(["'])(?=[^"'\s]*[^A-Za-z"'\s])[^"'\s]+\1/g;

const FUNCTION_WORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'nor', 'of', 'to', 'in', 'on', 'at', 'by', 'for', 'with', 'from',
  'into', 'onto', 'upon', 'about', 'over', 'under', 'between', 'through', 'without', 'within',
  'is', 'are', 'was', 'were', 'be', 'been', 'being', 'am',
  'this', 'that', 'these', 'those', 'it', 'its', 'as', 'if', 'then', 'than', 'because', 'while',
  'should', 'must', 'may', 'might', 'can', 'could', 'will', 'would', 'shall',
  'not', 'do', 'does', 'did', 'has', 'have', 'had',
  'you', 'your', 'we', 'our', 'they', 'their', 'them', 'he', 'she', 'his', 'her',
  'which', 'who', 'whom', 'whose', 'what', 'when', 'where', 'why', 'how',
  'all', 'any', 'each', 'every', 'such', 'also', 'only', 'there', 'here', 'but', 'so', 'very',
]);

const lower = (s) => s.toLowerCase();
const TERM_SET = new Set(TERMS);
const HEADER_SET = new Set(HEADER_NAMES);
const TERM_SET_CI = new Set(TERMS.filter(s => s.includes('-')).map(lower));
const HEADER_SET_CI = new Set(HEADER_NAMES.filter(s => s.includes('-')).map(lower));
const METHOD_SET = new Set(HTTP_METHODS);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Longest phrases first, so "Apache HTTP Server" wins over "Apache".
const PHRASE_RE = new RegExp(
  `(?<![A-Za-z])(?:${[...PHRASES].sort((a, b) => b.length - a.length).map(escapeRe).join('|')})(?![A-Za-z])`, 'gi');

// Published document titles that Japanese writing cites as is. Only capitalised
// title words directly before "Cheat Sheet" (case-sensitive): "the cheat sheet" in
// an English sentence is still English.
const DOCUMENT_TITLE_RE = /(?<![A-Za-z])(?:[A-Z][A-Za-z0-9+#]*(?:-[A-Za-z0-9]+)*\s+){0,7}Cheat\s+Sheets?(?:\s+Series)?(?![A-Za-z])/g;

const MAX_EN_SHARE = 0.35;
const MIN_RUN = 3;

function isApprovedWord(w) {
  // Hyphenated names (Content-Security-Policy, max-age) match in any case. A plain
  // word matches only as written in the allowlist: header names such as Accept,
  // Allow, Date or Server, and terms such as Secure or Origin, are also ordinary
  // English words, and "accept" or "allow" in a sentence must stay unapproved.
  const exact = (set, s) => set.has(s);
  if (w.includes('-')) {
    const l = lower(w);
    if (TERM_SET_CI.has(l) || HEADER_SET_CI.has(l)) return true;
  }
  if (exact(TERM_SET, w) || exact(HEADER_SET, w)) return true;
  if (w.endsWith('s') && (exact(TERM_SET, w.slice(0, -1)) || exact(HEADER_SET, w.slice(0, -1)))) return true;
  if (/^x-[a-z0-9-]+$/i.test(w)) return true;                  // any X-… header
  if (METHOD_SET.has(w)) return true;
  if (/^[A-Z]$/.test(w)) return true;                           // grades and labels: A, B, F
  if (/^[A-Z][A-Z0-9-]*[A-Z0-9]$/.test(w) && w.length <= 12) return true; // XSS, CSRF, DENY, SAMEORIGIN
  if (/^[A-Z]{2,}s$/.test(w)) return true;                     // APIs, URLs
  if (/[a-z][A-Z]/.test(w)) return true;                        // camelCase identifiers: HttpOnly, jQuery
  return false;
}

/** Blank out spans (same length, so offsets stay meaningful). */
const blank = (s, re) => s.replace(re, (m) => ' '.repeat(m.length));

function stripNotation(text) {
  let s = String(text ?? '');
  s = blank(s, PLACEHOLDER_RE);
  s = blank(s, URL_RE);
  s = blank(s, EMAIL_RE);
  s = blank(s, BACKTICK_RE);
  s = blank(s, QUOTED_LITERAL_RE);
  s = blank(s, DOCUMENT_TITLE_RE);
  s = blank(s, PHRASE_RE);
  // Chunk by chunk: a chunk carrying a digit or symbol is notation, unless it is a
  // plain word with sentence punctuation around it ("inputs." stays a word).
  s = s.replace(CHUNK_RE, (chunk) => {
    const core = chunk.replace(/^[("'“‘\[]+/, '').replace(/[)"'”’\].,;:!?]+$/, '');
    if (PLAIN_WORD_RE.test(core)) return chunk;
    // Command-line options (-q, -d, --force) are notation: "zip -q -d x.jar" in ZAP's
    // Log4Shell solution read as the English run "zip q d".
    if (SYMBOL_OR_DIGIT_RE.test(core) || HOST_RE.test(core) || /^--?[A-Za-z]/.test(core)) { HOST_RE.lastIndex = 0; return ' '.repeat(chunk.length); }
    HOST_RE.lastIndex = 0;
    return chunk;
  });
  return s;
}

function auditJapanese(text, { short = false } = {}) {
  const issues = [];
  const src = String(text ?? '');
  const stripped = stripNotation(src);
  const words = [];
  let m;
  LATIN_WORD_RE.lastIndex = 0;
  while ((m = LATIN_WORD_RE.exec(stripped)) !== null) {
    words.push({ w: m[0], index: m.index, end: m.index + m[0].length, approved: isApprovedWord(m[0]) });
  }
  const unapproved = words.filter(x => !x.approved);
  if (!unapproved.length) return { ok: true, issues };

  const fw = unapproved.find(x => FUNCTION_WORDS.has(lower(x.w)));
  if (fw) issues.push({ reason: 'en_function_word', index: fw.index });

  // Runs of words separated only by spaces / light punctuation (no Japanese).
  let run = 0, runStart = null;
  for (let i = 0; i < words.length; i++) {
    const gap = i === 0 ? '' : stripped.slice(words[i - 1].end, words[i].index);
    const continues = i > 0 && /^[\s,\-–—'"’()/]*$/.test(gap);
    if (!continues) { run = 0; runStart = words[i].index; }
    if (!words[i].approved) run++;
    if (run >= MIN_RUN) { issues.push({ reason: 'en_run', index: runStart }); break; }
  }

  const jaCount = (src.match(JA_CHAR_G) || []).length;
  const enLetters = unapproved.reduce((n, x) => n + x.w.length, 0);
  if (jaCount === 0) issues.push({ reason: 'no_japanese', index: unapproved[0].index });
  else if (enLetters / (enLetters + jaCount) > MAX_EN_SHARE) issues.push({ reason: 'en_share', index: unapproved[0].index });

  if (short) issues.push({ reason: 'en_word_in_short_field', index: unapproved[0].index });
  return { ok: issues.length === 0, issues };
}

function auditEnglish(text) {
  const issues = [];
  let s = String(text ?? '');
  s = blank(s, PLACEHOLDER_RE);
  s = blank(s, URL_RE);
  s = blank(s, EMAIL_RE);
  s = blank(s, HOST_RE);
  const ja = JA_CHAR.exec(s);
  if (ja) issues.push({ reason: 'ja_text', index: ja.index });
  const p = JA_PUNCT.exec(s);
  if (p) issues.push({ reason: 'ja_punctuation', index: p.index });
  return { ok: issues.length === 0, issues };
}

/**
 * Audit one prose string for the target report language.
 * @param {string} text
 * @param {'ja'|'en'} lang
 * @param {{ short?: boolean }} [opts] short: a title, heading or label — any
 *        unapproved English word fails it in a JA report.
 * @returns {{ ok: boolean, issues: Array<{ reason: string, index: number }> }}
 */
function auditProse(text, lang, opts = {}) {
  return lang === 'ja' ? auditJapanese(text, opts) : auditEnglish(text);
}

/** Letters in unapproved (ordinary English) words, after notation is removed. */
function englishLetterCount(text) {
  const stripped = stripNotation(text);
  let n = 0, m;
  LATIN_WORD_RE.lastIndex = 0;
  while ((m = LATIN_WORD_RE.exec(stripped)) !== null) if (!isApprovedWord(m[0])) n += m[0].length;
  return n;
}

/**
 * The ordinary English words left in a (masked) text, de-duplicated, in order —
 * used to tell the model what its previous translation failed to translate.
 * Plain Latin words only: notation, placeholders and approved terms are excluded.
 */
function unapprovedWords(text, limit = 12) {
  const stripped = stripNotation(text);
  const seen = new Set();
  let m;
  LATIN_WORD_RE.lastIndex = 0;
  while ((m = LATIN_WORD_RE.exec(stripped)) !== null && seen.size < limit) {
    if (!isApprovedWord(m[0])) seen.add(m[0]);
  }
  return [...seen];
}

/** Japanese characters (kana, kanji) in the text. */
function japaneseCharCount(text) {
  return (String(text ?? '').match(JA_CHAR_G) || []).length;
}

/** Fingerprint of the audit rules and allowlist, part of the localization ENGINE_VERSION. */
const AUDIT_FINGERPRINT = crypto.createHash('sha256')
  .update(JSON.stringify({ AUDIT_VERSION, PHRASES, TERMS, HEADER_NAMES, HTTP_METHODS,
    fw: [...FUNCTION_WORDS], MAX_EN_SHARE, MIN_RUN, titles: String(DOCUMENT_TITLE_RE) }))
  .digest('hex');

module.exports = {
  auditProse,
  stripNotation,
  isApprovedWord,
  englishLetterCount,
  unapprovedWords,
  japaneseCharCount,
  containsJapaneseScript: (s) => JA_CHAR.test(String(s ?? '')),
  AUDIT_FINGERPRINT,
};
