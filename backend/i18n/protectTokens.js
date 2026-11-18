'use strict';

/**
 * Pre-send scrub for report text that goes to the translation model.
 *
 * Every token that is sensitive (a credential, session value, URL, host, email,
 * IP, phone number, long token) or that must come back byte for byte (code,
 * encoded sequences, paths, quoted literals) is replaced by a numbered
 * placeholder {{T0}}, {{T1}}… The model sees only the placeholder; the original
 * is put back locally after translation. The translation cache stores the masked
 * text's translation, so it never holds any of these values either.
 *
 * Order matters: secrets first (so a URL inside a Cookie header is part of the
 * secret token), then identity, then technical literals. A later pattern never
 * matches inside an earlier placeholder (placeholders carry no dots, slashes or
 * quotes), and restore() unwinds nested tokens.
 */

const { IDENTITY_PATTERNS } = require('../services/geminiSanitizer');

const PROTECT_VERSION = 2;

const SECRET_PATTERNS = [
  // A credential header line, whatever its value.
  /\b(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:[^\n]*/gi,
  // Auth scheme + credential outside a header line. The credential must look like a
  // token (a digit or token symbol in it): "HTTP Basic authentication" is prose.
  /\b(?:Basic|Bearer|Digest|Negotiate|NTLM)\s+(?=[A-Za-z0-9._~+\/=-]*[0-9+\/=_~])[A-Za-z0-9._~+\/=-]{8,}/g,
  // JSON Web Tokens.
  /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g,
  // name=value where the name looks like a secret or session.
  /\b[A-Za-z0-9_.-]*(?:session|sess|sid|token|passw(?:or)?d|pwd|secret|api[_-]?key|auth|csrf|jwt)[A-Za-z0-9_.-]*\s*=\s*(?:"[^"\n]*"|'[^'\n]*'|[^\s;&,]+)/gi,
  // name: value likewise, but only when the value looks like a token — "Session
  // management: the cookie…" is prose and must stay translatable.
  /\b[A-Za-z0-9_.-]*(?:session|sess|sid|token|passw(?:or)?d|pwd|secret|api[_-]?key|csrf|jwt)[A-Za-z0-9_.-]*\s*:\s*(?=[^\s;&,]*[0-9+\/=_~])[^\s;&,]{6,}/gi,
  // Long opaque values: hex digests, base64 blobs.
  /\b[A-Fa-f0-9]{24,}\b/g,
  /(?<![A-Za-z0-9+\/])[A-Za-z0-9+\/]{32,}={0,2}(?![A-Za-z0-9+\/=])/g,
];

const PHONE_PATTERN = /(?<![\w.])\+?\d[\d\s().-]{8,}\d(?![\w.])/g;

const TECHNICAL_PATTERNS = [
  /`[^`\n]+`/g,                                               // inline code
  /(["'])(?=[^"'\s]*[^A-Za-z"'\s])[^"'\s]+\1/g,               // quoted literals with symbols: "../", "..%c0%af"
  /[^\s"'()（）「」<>]*%(?:[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4})[^\s"'()（）「」<>,]*/g, // percent-encoded sequences
  /\.\.(?:\/|\\)[^\s"'()]*/g,                                  // ../ and ..\ sequences
  /[^\s"'()（）「」<>]*\\[^\s"'()（）「」<>]*/g,                 // anything with a backslash
  /<\/?[A-Za-z][^<>\n]{0,200}>/g,                              // HTML/XML tags
  /\b[A-Za-z_$][\w$.]*\(\)/g,                                  // fn() / pkg.fn()
  /(?<![\w.])\/(?:[\w.-]+\/)*[\w.-]+/g,                        // absolute paths: /etc/passwd
];

const PLACEHOLDER_RE = /\{\{T(\d+)\}\}/g;

/**
 * @param {string} text
 * @returns {{ masked: string, tokens: string[] }}
 */
function protect(text) {
  const tokens = [];
  let masked = String(text ?? '');
  const sub = (re) => { masked = masked.replace(re, (m) => `{{T${tokens.push(m) - 1}}}`); };
  for (const re of SECRET_PATTERNS) sub(re);
  for (const re of IDENTITY_PATTERNS) sub(re);
  sub(PHONE_PATTERN);
  for (const re of TECHNICAL_PATTERNS) sub(re);
  return { masked, tokens };
}

/** Put the originals back, unwinding placeholders nested inside tokens. */
function restore(masked, tokens) {
  let out = String(masked ?? '');
  for (let pass = 0; pass <= tokens.length && PLACEHOLDER_RE.test(out); pass++) {
    PLACEHOLDER_RE.lastIndex = 0;
    out = out.replace(PLACEHOLDER_RE, (m, i) => (Number(i) < tokens.length ? tokens[Number(i)] : m));
  }
  PLACEHOLDER_RE.lastIndex = 0;
  return out;
}

/** Placeholder ids in order of appearance, e.g. ['T0', 'T2', 'T2']. */
function placeholderList(s) {
  return (String(s ?? '').match(/\{\{T\d+\}\}/g) || []);
}

module.exports = { protect, restore, placeholderList, PROTECT_VERSION,
  PATTERN_FINGERPRINT: [...SECRET_PATTERNS, PHONE_PATTERN, ...TECHNICAL_PATTERNS, ...IDENTITY_PATTERNS].map(String).join('|') };
