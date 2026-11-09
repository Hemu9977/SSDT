'use strict';

/**
 * Pre-flight check for an HTTP Basic Auth scan.
 *
 * Proves, before any scan starts, that:
 *   - the page really is protected by Basic auth (anonymous request -> 401 with a
 *     `WWW-Authenticate: Basic` challenge), and
 *   - the supplied credential is accepted on that same page (-> not 401/403).
 * A page that is simply public would otherwise "verify" any password.
 *
 * Rules (validated in the Phase 0 PoC, cases E1–E10):
 *   - HTTPS only. A Basic credential over HTTP is readable on the wire.
 *   - Every hop of every redirect passes the scan-target guard (SSRF).
 *   - Credentials are only ever sent to the exact origin being verified; a
 *     redirect elsewhere stops the check without sending them.
 *   - At most ONE authenticated request chain, so a wrong password cannot lock the
 *     customer's account through retries.
 *   - Nothing returned or logged contains the credential.
 */

const https = require('https');
const { checkScanTarget } = require('../utils/scanTargetGuard');

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 15000;
const MAX_FIELD_LENGTH = 256;
// CR/LF would allow header injection; other control characters are never valid.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

const CODES = Object.freeze({
  CONFIRMED: 'BASIC_CONFIRMED',
  INVALID_INPUT: 'BASIC_INVALID_INPUT',
  INVALID_URL: 'BASIC_INVALID_URL',
  URL_HAS_CREDENTIALS: 'URL_HAS_CREDENTIALS',
  REQUIRES_HTTPS: 'BASIC_REQUIRES_HTTPS',
  VERIFY_URL_OFF_ORIGIN: 'BASIC_VERIFY_URL_OFF_ORIGIN',
  CROSS_ORIGIN_REDIRECT: 'BASIC_CROSS_ORIGIN_REDIRECT',
  TOO_MANY_REDIRECTS: 'BASIC_TOO_MANY_REDIRECTS',
  TARGET_UNREACHABLE: 'BASIC_TARGET_UNREACHABLE',
  TARGET_FORBIDDEN: 'BASIC_TARGET_FORBIDDEN',
  NOT_REQUIRED: 'BASIC_NOT_REQUIRED',
  SCHEME_UNSUPPORTED: 'BASIC_SCHEME_UNSUPPORTED',
  UNEXPECTED_STATUS: 'BASIC_UNEXPECTED_STATUS',
  INVALID_CREDENTIALS: 'BASIC_INVALID_CREDENTIALS',
  ACCESS_DENIED: 'BASIC_ACCESS_DENIED',
  BLOCKED_TARGET: 'BLOCKED_TARGET',
  REALM_MISMATCH: 'BASIC_REALM_MISMATCH'
});

/** Parse every challenge in WWW-Authenticate header value(s). */
function parseChallenges(headerValue) {
  const value = [].concat(headerValue || []).join(', ');
  const out = [];
  const re = /(Basic|Digest|NTLM|Negotiate|Bearer)\b((?:[^,]|,(?!\s*(?:Basic|Digest|NTLM|Negotiate|Bearer)\b))*)/gi;
  for (const m of value.matchAll(re)) {
    const realm = (m[2].match(/realm="([^"]*)"/i) || [])[1] || null;
    out.push({ scheme: m[1].toLowerCase(), realm });
  }
  return out;
}

function validateInput({ username, password, realm }) {
  const okField = (v, { allowEmpty = false } = {}) =>
    typeof v === 'string' && (allowEmpty || v.length > 0) && v.length <= MAX_FIELD_LENGTH && !CONTROL_CHARS.test(v);
  if (!okField(username) || username.includes(':')) return false; // RFC 7617: no colon in user-id
  if (!okField(password)) return false;
  if (realm !== undefined && realm !== null && realm !== '' && !okField(realm)) return false;
  return true;
}

function defaultRequest(url, headers, { agent } = {}) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Fortexa-Verify/1.0)', Accept: '*/*', ...headers },
      timeout: REQUEST_TIMEOUT_MS,
      agent
    }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location, wwwAuthenticate: res.headers['www-authenticate'] }));
      res.on('error', () => resolve({ error: 'response_error' }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ error: e && e.code === 'ECONNRESET' && /timeout/.test(e.message) ? 'timeout' : (e && (e.code || e.message)) || 'error' }));
    req.end();
  });
}

/**
 * Follow redirects by hand. With `authorization`, the header is only attached to
 * hops on `origin`, and the chain stops (without sending it) on the first hop
 * anywhere else.
 */
async function followChain(startUrl, origin, authorization, deps) {
  let url = startUrl;
  let requests = 0;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const guard = deps.guard(url);
    if (!guard.ok) return { requests, blocked: guard.code || CODES.BLOCKED_TARGET };
    const sameOrigin = new URL(url).origin === origin;
    if (authorization && !sameOrigin) return { requests, crossOrigin: true };
    const res = await deps.request(url, authorization ? { Authorization: authorization } : {}, deps);
    requests++;
    const redirect = res.status >= 300 && res.status < 400 && res.location;
    if (res.error || !redirect) return { requests, last: res, url };
    let next;
    try { next = new URL(res.location, url).href; } catch (_) { return { requests, last: { error: 'bad_redirect' }, url }; }
    if (new URL(next).protocol !== 'https:') return { requests, crossOrigin: true };
    url = next;
    if (!authorization && new URL(url).origin !== origin) return { requests, crossOrigin: true };
  }
  return { requests, tooManyRedirects: true };
}

/**
 * @param {object} input
 * @param {string} input.targetUrl  scan target; defines the origin
 * @param {string} [input.verifyUrl] protected page to verify on (same origin; default: targetUrl)
 * @param {string} input.username
 * @param {string} input.password
 * @param {string} [input.realm]    optional; a mismatch is a warning, not an error
 * @param {object} [deps] injectable for tests: { request, guard, agent }
 * @returns {Promise<{code:string, origin?:string, verifyUrl?:string, serverRealm?:string|null,
 *   warnings:string[], requests:number, authenticatedRequests:number}>}
 */
async function probeBasicAuth({ targetUrl, verifyUrl, username, password, realm } = {}, deps = {}) {
  const d = { request: defaultRequest, guard: (u) => checkScanTarget(u), ...deps };
  const result = (code, extra = {}) => ({ code, warnings: [], requests: 0, authenticatedRequests: 0, ...extra });

  let target;
  try { target = new URL(targetUrl); } catch (_) { return result(CODES.INVALID_URL); }
  if (target.username || target.password) return result(CODES.URL_HAS_CREDENTIALS);
  if (target.protocol !== 'https:') return result(CODES.REQUIRES_HTTPS);
  if (!validateInput({ username, password, realm })) return result(CODES.INVALID_INPUT);
  const targetGuard = d.guard(target.href);
  if (!targetGuard.ok) return result(targetGuard.code || CODES.BLOCKED_TARGET);

  const origin = target.origin;
  let verify;
  try { verify = verifyUrl ? new URL(verifyUrl, target) : target; } catch (_) { return result(CODES.INVALID_URL); }
  if (verify.username || verify.password) return result(CODES.URL_HAS_CREDENTIALS);
  if (verify.origin !== origin) return result(CODES.VERIFY_URL_OFF_ORIGIN);

  // 1. Anonymous: is this page protected by Basic at all?
  const anon = await followChain(verify.href, origin, null, d);
  const base = { origin, verifyUrl: verify.href, requests: anon.requests };
  if (anon.blocked) return result(anon.blocked, base);
  if (anon.crossOrigin) return result(CODES.CROSS_ORIGIN_REDIRECT, base);
  if (anon.tooManyRedirects) return result(CODES.TOO_MANY_REDIRECTS, base);
  if (!anon.last || anon.last.error) return result(CODES.TARGET_UNREACHABLE, base);
  const status = anon.last.status;
  if (status === 403) return result(CODES.TARGET_FORBIDDEN, base);
  if (status >= 200 && status < 300) return result(CODES.NOT_REQUIRED, base);
  if (status !== 401) return result(CODES.UNEXPECTED_STATUS, { ...base, status });
  const challenges = parseChallenges(anon.last.wwwAuthenticate);
  const basic = challenges.find(c => c.scheme === 'basic');
  if (!basic) return result(CODES.SCHEME_UNSUPPORTED, { ...base, schemes: challenges.map(c => c.scheme) });

  // 2. One authenticated attempt on the page that challenged.
  const authorization = `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;
  const auth = await followChain(anon.url, origin, authorization, d);
  const warnings = realm && basic.realm && realm !== basic.realm ? [CODES.REALM_MISMATCH] : [];
  const out = { ...base, requests: anon.requests + auth.requests, authenticatedRequests: auth.requests, serverRealm: basic.realm, warnings };
  if (auth.blocked) return result(auth.blocked, out);
  if (auth.crossOrigin) return result(CODES.CROSS_ORIGIN_REDIRECT, out);
  if (auth.tooManyRedirects) return result(CODES.TOO_MANY_REDIRECTS, out);
  if (!auth.last || auth.last.error) return result(CODES.TARGET_UNREACHABLE, out);
  const s = auth.last.status;
  if (s === 401) return result(CODES.INVALID_CREDENTIALS, out);
  if (s === 403) return result(CODES.ACCESS_DENIED, out);
  if (s >= 200 && s < 400) return result(CODES.CONFIRMED, out);
  return result(CODES.UNEXPECTED_STATUS, { ...out, status: s });
}

module.exports = { probeBasicAuth, parseChallenges, validateInput, CODES };
