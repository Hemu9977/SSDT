'use strict';

/**
 * Keeps scan credentials out of everything Fortexa stores or shows.
 *
 * Two independent layers, because each one alone has a gap:
 *
 *   1. Structural: the VALUES of credential-bearing HTTP headers are replaced,
 *      whatever they contain. ZAP stores the request it actually sent, and that
 *      request carries whatever the Replacer injected (an `Authorization: Basic`
 *      header for a Basic Auth scan, the session `Cookie` for a form-login scan).
 *      Fortexa copied those headers verbatim into the GridFS evidence file, the
 *      evidence panel, the PDF and the JSON export.
 *
 *   2. Exact-secret scrub: a known secret (the password, `user:password`, its
 *      base64 form) is removed from any string, wherever it appears. This covers
 *      places that are not headers. ZAP's passive rule 10105 ("Authentication
 *      Credentials Captured") writes the decoded username and password into the
 *      alert text, and the ZAP HTML report repeats it.
 *
 * Layer 1 is applied both when data is captured and again when it is read back
 * (vulnFilter.getSanitizedAlerts, the PDF evidence renderer), so evidence stored
 * before this module existed is also redacted on the way out.
 */

const REDACTED = '[REDACTED]';

// Request and response headers whose value is a credential or a session.
const CREDENTIAL_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token']);

// Secrets shorter than this are not scrubbed by exact match: a 1–3 character
// string would also erase ordinary text from the report. Header values are still
// redacted structurally, whatever their length.
const MIN_SCRUB_LENGTH = 4;

/**
 * Redact one header line's value, keeping the parts that are evidence rather than
 * secret: the auth scheme (`Basic`), cookie names, and Set-Cookie attributes
 * (`Secure`, `HttpOnly`, `SameSite`), which is what cookie findings are about.
 * @param {string} name  header name, original case
 * @param {string} value header value
 */
function redactHeaderValue(name, value) {
  const lower = name.toLowerCase();
  if (lower === 'authorization' || lower === 'proxy-authorization') {
    const m = /^(\s*)([A-Za-z][A-Za-z0-9._~+-]*)(\s+)\S/.exec(value);
    return m ? `${m[1]}${m[2]} ${REDACTED}` : ` ${REDACTED}`;
  }
  if (lower === 'cookie') {
    return value.split(';').map(part => {
      const eq = part.indexOf('=');
      return eq === -1 ? part : `${part.slice(0, eq)}=${REDACTED}`;
    }).join(';');
  }
  if (lower === 'set-cookie') {
    const [first, ...attrs] = value.split(';');
    const eq = first.indexOf('=');
    const redactedPair = eq === -1 ? first : `${first.slice(0, eq)}=${REDACTED}`;
    return [redactedPair, ...attrs].join(';');
  }
  return ` ${REDACTED}`;
}

/**
 * Redact credential headers in a raw HTTP header block (request or response).
 * Lines are kept in place, so line numbers and the rest of the evidence are
 * unchanged. Non-string input is returned untouched.
 * @param {string} block e.g. "GET /x HTTP/1.1\r\nHost: a\r\nAuthorization: Basic …\r\n\r\n"
 * @returns {string}
 */
function redactHeaderBlock(block) {
  if (typeof block !== 'string' || block === '') return block;
  return block.replace(/^([!#$%&'*+.^_`|~0-9A-Za-z-]+):([^\r\n]*)$/gm, (line, name, value) =>
    CREDENTIAL_HEADERS.has(name.toLowerCase()) ? `${name}:${redactHeaderValue(name, value)}` : line);
}

/**
 * Every form in which a Basic Auth credential could appear in scanner output.
 * @param {{username?: string, password?: string}} cred
 * @returns {string[]} distinct secrets, longest first, below-minimum ones dropped
 */
function secretVariants(cred) {
  if (!cred || typeof cred.password !== 'string' || cred.password === '') return [];
  const user = typeof cred.username === 'string' ? cred.username : '';
  const pair = `${user}:${cred.password}`;
  const b64 = Buffer.from(pair, 'utf8').toString('base64');
  const candidates = [
    pair,
    b64,
    b64.replace(/=+$/, ''),
    cred.password,
    encodeURIComponent(cred.password),
    encodeURIComponent(pair),
  ];
  return [...new Set(candidates)]
    .filter(s => typeof s === 'string' && s.length >= MIN_SCRUB_LENGTH)
    .sort((a, b) => b.length - a.length);
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Replace every occurrence of any secret in a string.
 * @param {string} text
 * @param {string[]} secrets output of secretVariants()
 */
function scrubText(text, secrets) {
  if (typeof text !== 'string' || !text || !Array.isArray(secrets) || secrets.length === 0) return text;
  let out = text;
  for (const s of secrets) {
    if (out.includes(s)) out = out.replace(new RegExp(escapeRegExp(s), 'g'), REDACTED);
  }
  return out;
}

/**
 * Deep copy of `value` with every secret replaced in every string, including
 * object keys' values at any depth. Buffers are converted through UTF-8 text.
 * Cycles are not expected (JSON-shaped scanner data) and are cut defensively.
 * @template T
 * @param {T} value
 * @param {string[]} secrets
 * @returns {T}
 */
function scrubSecrets(value, secrets, seen = new WeakSet()) {
  if (!Array.isArray(secrets) || secrets.length === 0) return value;
  if (typeof value === 'string') return scrubText(value, secrets);
  if (Buffer.isBuffer(value)) return Buffer.from(scrubText(value.toString('utf8'), secrets), 'utf8');
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return undefined;
  seen.add(value);
  if (Array.isArray(value)) return value.map(v => scrubSecrets(v, secrets, seen));
  if (value instanceof Date) return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) out[k] = scrubSecrets(v, secrets, seen);
  return out;
}

/**
 * Redact the raw request/response captured for one alert occurrence.
 * Returns a new object; the input is not mutated.
 */
function redactOccurrence(occ) {
  if (!occ || typeof occ !== 'object') return occ;
  if (!occ.request && !occ.response) return occ;
  const part = (p) => (p && typeof p === 'object' && typeof p.header === 'string')
    ? { ...p, header: redactHeaderBlock(p.header) }
    : p;
  return { ...occ, request: part(occ.request), response: part(occ.response) };
}

/**
 * Redact credential headers in every occurrence of every alert.
 * Alerts without raw evidence are returned unchanged (same object).
 * @param {Array} alerts
 */
function redactAlertsEvidence(alerts) {
  if (!Array.isArray(alerts)) return alerts;
  return alerts.map(a => (a && Array.isArray(a.occurrences) && a.occurrences.some(o => o && (o.request || o.response)))
    ? { ...a, occurrences: a.occurrences.map(redactOccurrence) }
    : a);
}

module.exports = {
  REDACTED,
  CREDENTIAL_HEADERS,
  MIN_SCRUB_LENGTH,
  redactHeaderBlock,
  secretVariants,
  scrubText,
  scrubSecrets,
  redactOccurrence,
  redactAlertsEvidence,
};
