/**
 * Login Request Signals
 *
 * Pure decision logic for "which network request was the login, and what did
 * the site answer?", split out of `services/loginTestService.js` so it can be
 * tested without a browser (same pattern as `utils/loginSignals.js`).
 *
 * Why this exists: the login test used to judge a submission only by what the
 * page looked like afterwards. A single-page app that answers a sign-in with a
 * `role="status"` toast — or whose API is still waking up — looks exactly like
 * a click that did nothing, so a login that *was* sent got reported as "the
 * form had no effect, pick another button". Watching the request itself tells
 * the three cases apart: nothing was sent, the site said no, or the site never
 * answered.
 *
 * Nothing in here logs, stores or returns a request body, a response body, a
 * header value or a URL. Bodies are inspected in memory only, to decide.
 */

// Request types a sign-in can travel as. `ping` (sendBeacon) and the static
// asset types are never a login.
const LOGIN_RESOURCE_TYPES = new Set(['xhr', 'fetch', 'document', 'other']);

// Methods that carry a sign-in. GET is only accepted for a top-level document
// (a `<form method="get">`), and then only with credential evidence.
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);

// Third-party analytics, telemetry and tag hosts. A request to one of these is
// never the login, whatever its body looks like (some of them echo form fields).
const ANALYTICS_HOST_PATTERN = new RegExp(
  '(^|\\.)(' + [
    'google-analytics\\.com', 'analytics\\.google\\.com', 'googletagmanager\\.com',
    'doubleclick\\.net', 'googleadservices\\.com', 'googlesyndication\\.com',
    'facebook\\.com', 'facebook\\.net', 'sentry\\.io', 'segment\\.io', 'segment\\.com',
    'hotjar\\.com', 'hotjar\\.io', 'mixpanel\\.com', 'amplitude\\.com', 'clarity\\.ms',
    'bing\\.com', 'newrelic\\.com', 'nr-data\\.net', 'datadoghq\\.com', 'datadoghq\\.eu',
    'fullstory\\.com', 'heapanalytics\\.com', 'logrocket\\.io', 'logrocket\\.com',
    'bugsnag\\.com', 'launchdarkly\\.com', 'optimizely\\.com', 'cloudflareinsights\\.com',
    'yandex\\.ru', 'tiktok\\.com', 'linkedin\\.com', 'ads-twitter\\.com', 'intercom\\.io',
    'pendo\\.io', 'posthog\\.com', 'plausible\\.io', 'matomo\\.cloud'
  ].join('|') + ')$',
  'i'
);

// Paths that collect telemetry on a first-party host. Anchored on a whole path
// segment, so `/api/auth/login` never matches `/log`.
const TELEMETRY_PATH_PATTERN =
  /\/(collect|beacon|analytics|telemetry|tracking|track|metrics|events?|logs?|rum|vitals|pixel|ping|cdn-cgi\/rum)(\/|$)/i;

// Paths a sign-in endpoint is usually called by. Only counts together with a
// write method, and only as the weakest of the four signals.
const AUTH_PATH_PATTERN =
  /(log-?in|log-?on|sign-?in|sign-?on|auth|session|token|oauth|sso|j_security_check|credential)/i;

// Body keys that hold a password. Matched against JSON keys, URL-encoded and
// multipart field names — never against values.
const PASSWORD_KEY_PATTERN = /pass(word|wd|code|phrase)?|pwd|secret|credential/i;

// Response fields that only a successful sign-in hands back.
const TOKEN_KEY_PATTERN = /^(token|access_?token|id_?token|refresh_?token|jwt|session(_?id)?|auth_?token|user|account|profile)$/i;

// Visible wording that means the sign-in was refused. Used only on text that
// appeared after the submit, in a live region or an error element.
const FAILURE_NOTICE_PATTERN = new RegExp([
  '\\binvalid\\b', '\\bincorrect\\b', '\\bwrong\\b', '\\bfail', '\\bdenied\\b',
  '\\bunauthori[sz]ed\\b', 'not\\s+(verified|found|recogni[sz]ed|allowed|authori[sz]ed|activated)',
  '\\blocked\\b', '\\bdisabled\\b', '\\bdeactivated\\b', '\\bsuspended\\b', '\\bexpired\\b',
  'try again', 'does(n\'t| not) match', '\\bunable to\\b', '\\bcould not\\b', '\\bcannot\\b',
  '\\berror\\b', 'too many', 'verify (your|the) (email|account)', 'not been (verified|activated|confirmed)',
  '正しくありません', '間違', '失敗', '無効', 'エラー', 'できません', 'ロック', '認証されていません',
  '認証を完了', '見つかりません', '一致しません'
].join('|'), 'i');

// Values shorter than this are not compared against bodies: a one- or
// two-character value would match unrelated payloads by coincidence.
const MIN_VALUE_LENGTH = 3;

// Response bodies larger than this are not parsed. A sign-in answer is small;
// anything bigger is not one, and parsing it would cost for nothing.
const MAX_RESPONSE_JSON_BYTES = 256 * 1024;

function safeUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * The encodings a submitted value can take inside a request body.
 * @param {string} value
 * @returns {string[]}
 */
function valueEncodings(value) {
  const out = new Set([value]);
  try {
    const uri = encodeURIComponent(value);
    out.add(uri);
    out.add(uri.replace(/%20/g, '+'));
  } catch {
    // Lone surrogates cannot be URI-encoded; the raw form is still checked.
  }
  out.add(JSON.stringify(value).slice(1, -1));
  return [...out];
}

/**
 * Does the body carry one of the values the login test typed?
 * @param {string} body
 * @param {string[]} credentialValues
 */
function bodyCarriesValue(body, credentialValues) {
  if (typeof body !== 'string' || !body) return false;
  for (const value of Array.isArray(credentialValues) ? credentialValues : []) {
    if (typeof value !== 'string' || value.length < MIN_VALUE_LENGTH) continue;
    if (valueEncodings(value).some(encoded => encoded && body.includes(encoded))) return true;
  }
  return false;
}

/**
 * Field names in a request body, whatever its encoding.
 * @param {string} body
 * @param {string} contentType
 * @returns {string[]}
 */
function bodyKeys(body, contentType) {
  if (typeof body !== 'string' || !body) return [];
  const type = String(contentType || '').toLowerCase();
  const trimmed = body.trim();

  if (type.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const keys = [];
      const walk = (node, depth) => {
        if (!node || typeof node !== 'object' || depth > 4 || keys.length > 200) return;
        for (const [key, child] of Object.entries(node)) {
          keys.push(key);
          walk(child, depth + 1);
        }
      };
      walk(JSON.parse(trimmed), 0);
      return keys;
    } catch {
      // Not JSON after all; fall through to the other encodings.
    }
  }

  if (type.includes('multipart')) {
    return [...body.matchAll(/name="([^"]{1,100})"/g)].map(m => m[1]);
  }

  if (type.includes('x-www-form-urlencoded') || /^[^=&\s]{1,100}=/.test(trimmed)) {
    try {
      return [...new URLSearchParams(trimmed).keys()];
    } catch {
      return [];
    }
  }

  return [];
}

/**
 * Is this request the login submission?
 *
 * Needs at least one positive signal, strongest first:
 *  - `credential_value` — the body (or a GET form's query) carries a typed value
 *  - `password_key`     — the body has a password-shaped field name
 *  - `form_post`        — a top-level document POST, i.e. a conventional form
 *  - `auth_path`        — a write to an auth-shaped path (`/auth/login`, `/session`)
 * and is never analytics, telemetry, a beacon, or a static asset.
 *
 * @param {Object} input
 * @param {string} input.method
 * @param {string} input.url
 * @param {string} input.resourceType  Puppeteer resource type
 * @param {string} [input.contentType] request Content-Type
 * @param {string} [input.postData]    request body, if the browser exposed it
 * @param {string[]} [input.credentialValues] values the test typed (in memory only)
 * @returns {{isLogin:boolean, matchedBy:string|null}}
 */
function classifyLoginRequest({ method, url, resourceType, contentType, postData, credentialValues } = {}) {
  const no = { isLogin: false, matchedBy: null };
  const verb = String(method || '').toUpperCase();
  const type = String(resourceType || '').toLowerCase();
  const parsed = safeUrl(url);

  if (!parsed || !/^https?:$/.test(parsed.protocol)) return no;
  if (!LOGIN_RESOURCE_TYPES.has(type)) return no;
  if (ANALYTICS_HOST_PATTERN.test(parsed.hostname)) return no;
  if (TELEMETRY_PATH_PATTERN.test(parsed.pathname)) return no;

  if (!WRITE_METHODS.has(verb)) {
    // A `<form method="get">` puts the credentials in the query string. Accept
    // it only for a top-level navigation that visibly carries them.
    if (verb !== 'GET' || type !== 'document') return no;
    const query = parsed.search.slice(1);
    if (!query) return no;
    if (bodyCarriesValue(query, credentialValues)) return { isLogin: true, matchedBy: 'credential_value' };
    if (bodyKeys(query, 'application/x-www-form-urlencoded').some(k => PASSWORD_KEY_PATTERN.test(k))) {
      return { isLogin: true, matchedBy: 'password_key' };
    }
    return no;
  }

  if (bodyCarriesValue(postData, credentialValues)) return { isLogin: true, matchedBy: 'credential_value' };
  if (bodyKeys(postData, contentType).some(k => PASSWORD_KEY_PATTERN.test(k))) {
    return { isLogin: true, matchedBy: 'password_key' };
  }
  if (type === 'document') return { isLogin: true, matchedBy: 'form_post' };
  if (AUTH_PATH_PATTERN.test(parsed.pathname)) return { isLogin: true, matchedBy: 'auth_path' };
  return no;
}

function nonEmpty(value) {
  if (value === null || value === undefined || value === false) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return String(value).trim().length > 0;
}

/**
 * Does a parsed response hand back something only a successful sign-in would?
 * Looks one level into `data` / `result`, where most APIs wrap their payload.
 */
function carriesSession(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return false;
  const layers = [json, json.data, json.result].filter(l => l && typeof l === 'object' && !Array.isArray(l));
  return layers.some(layer =>
    Object.entries(layer).some(([key, value]) => TOKEN_KEY_PATTERN.test(key) && nonEmpty(value))
  );
}

/**
 * What did the site answer to the login request?
 *
 *  - `http_error` — 4xx or 5xx
 *  - `app_error`  — 2xx whose JSON says the sign-in was refused
 *                   (`success:false`, `status:"error"`, `errors:[…]` with no token…)
 *  - `ok`         — anything else, including redirects; the page decides from here
 *
 * @param {Object} input
 * @param {number} input.status
 * @param {*} [input.json] parsed JSON body, if there was one (never logged)
 * @returns {'ok'|'http_error'|'app_error'}
 */
function classifyLoginResponse({ status, json } = {}) {
  const code = Number(status);
  if (Number.isFinite(code) && code >= 400) return 'http_error';
  if (!json || typeof json !== 'object') return 'ok';

  // A token or a user object in the answer means it worked, whatever else the
  // payload carries (some APIs attach warnings to a successful sign-in).
  if (carriesSession(json)) return 'ok';

  const refusedFlag = ['success', 'ok', 'authenticated', 'loggedIn', 'logged_in', 'valid']
    .some(key => json[key] === false);
  const refusedStatus = typeof json.status === 'string' &&
    /^(error|fail|failed|failure|unauthori[sz]ed|denied|invalid)$/i.test(json.status.trim());
  const hasErrors = nonEmpty(json.error) || nonEmpty(json.errors);

  return refusedFlag || refusedStatus || hasErrors ? 'app_error' : 'ok';
}

/**
 * Does this visible text say the sign-in was refused?
 * @param {string} text
 */
function isFailureNotice(text) {
  if (typeof text !== 'string') return false;
  const line = text.replace(/\s+/g, ' ').trim();
  return line.length > 0 && line.length <= 300 && FAILURE_NOTICE_PATTERN.test(line);
}

module.exports = {
  classifyLoginRequest,
  classifyLoginResponse,
  isFailureNotice,
  bodyKeys,
  bodyCarriesValue,
  MAX_RESPONSE_JSON_BYTES,
  ANALYTICS_HOST_PATTERN,
  TELEMETRY_PATH_PATTERN,
  AUTH_PATH_PATTERN,
  PASSWORD_KEY_PATTERN
};
