'use strict';

/**
 * Last line of defence: nothing a process writes to stdout/stderr may carry a credential.
 *
 * Installed first thing by every process entry point (server.js,
 * workers/startWorker.js) and by every operational script (scripts/*.js,
 * clear-stuck-scans.js). It:
 *
 *   1. wraps console.log/info/warn/error/debug and console.dir/dirxml/trace/table, so
 *      every argument is sanitized before it is formatted:
 *      - Error objects are reduced to what diagnoses a failure — class, message, code,
 *        HTTP status, method, URL without its query string, stack. An axios error
 *        otherwise prints its whole request config: the X-ZAP-API-Key / API-Key /
 *        x-auth-token headers, `apikey` URL parameters, and the POSTed body (which,
 *        for a login test, is the customer's username and password). A Redis error's
 *        `command.args` (AUTH carries the ACL password) is reduced to a count.
 *      - Objects have every sensitive key redacted at any depth (authorization,
 *        cookie, *api-key*, password, token, secret, otp, …).
 *   2. scrubs the final text of: the exact values of secret environment variables and
 *      of passwords embedded in URL-valued variables (MONGO_URI, REDIS_URL, …);
 *      Google OAuth access tokens (ya29.…) and API keys (AIza…); JWTs;
 *      Bearer/Basic/Digest credentials (also URL-encoded); Stripe and AWS keys;
 *      passwords in `scheme://user:pass@host`; secret query parameters; credential
 *      header lines; and the value after any secret-named key in JSON, inspected
 *      objects, form bodies and prose (`"password":"…"`, `password=…`, `cookie: …`).
 *   3. scrubs anything written straight to process.stdout/stderr by other code (the
 *      `debug` module behind ioredis/socket.io/puppeteer, driver loggers) with the
 *      same text rules — the backstop for writers that never go through console.
 *   4. registers crash handlers, so an exception or rejection that arrives before the
 *      entry point has registered its own is logged through the redactor instead of
 *      Node's built-in printer (which dumps an axios error's config verbatim). They
 *      step aside as soon as the process registers handlers of its own.
 *
 * Call sites still should not log secrets (tests/secretLogging.test.js checks the
 * source for that); this catches what slips through, including logs added later.
 */

const util = require('util');

const REDACTED = '[REDACTED]';
const SUPPRESSED = '[log redaction failed — line suppressed]';
const MAX_DEPTH = 6;

const SENSITIVE_KEY = /^(authorization|proxy-authorization|cookie|cookies|set-cookie|x-api-key|x-zap-api-key|x-auth-token|x-goog-api-key|api[-_]?key|apikey|password|passwd|pwd|pass|secret|client[-_]?secret|token|tokens|access[-_]?token|refresh[-_]?token|id[-_]?token|session[-_]?token|otp|otp[-_]?hash|otphash|jwt|private[-_]?key|credentials?|secret[-_]?access[-_]?key)$/i;

// Values of environment variables with these names are secrets and are redacted
// wherever they appear in a log line. PASS/PWD only as a whole name segment
// (EMAIL_PASS, SMTP_PWD), so BYPASS_CACHE or PASSPORT_* are not swept in.
const SECRET_ENV_NAME = /(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIALS_RELATIVE_URI)|(^|_)(PASS|PWD)(_|$)/i;
const NOT_SECRET_ENV_NAME = /^(GOOGLE_APPLICATION_CREDENTIALS|ZAP_CAPACITY_KEYS|.*_(PATH|FILE|DIR|ID|ENABLED|TTL|TTL_S|MS))$/i;
const MIN_SECRET_LENGTH = 8;

// scheme://user:password@host — the password group, for any URL-valued variable.
const URL_USERINFO = /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]*:([^\s@/]+)@/gi;

const STRING_PATTERNS = [
  // Credential header lines inside text (raw HTTP, curl dumps).
  [/^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-zap-api-key|x-auth-token|x-goog-api-key|api-key)\s*:\s*).+$/gim, `$1${REDACTED}`],
  // Google OAuth access tokens and refresh tokens; Google API keys.
  [/\bya29\.[A-Za-z0-9._-]+/g, REDACTED],
  [/\b1\/\/[A-Za-z0-9_-]{20,}/g, REDACTED],
  [/\bAIza[0-9A-Za-z_-]{20,}/g, REDACTED],
  // JWTs.
  [/\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g, REDACTED],
  // Stripe secret / restricted keys and webhook secrets; AWS access key ids.
  [/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, REDACTED],
  [/\bwhsec_[A-Za-z0-9]{8,}/g, REDACTED],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, REDACTED],
  // PEM private keys (a service-account JSON pasted into a log).
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, REDACTED],
  // Password in a URL: scheme://user:password@host
  [/(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]*:)[^\s@/]+@/gi, `$1${REDACTED}@`],
  // Secret query parameters.
  [/([?&](?:apikey|api_key|api-key|key|token|access_token|id_token|refresh_token|password|secret|signature|sig|code)=)[^&\s#"']+/gi, `$1${REDACTED}`],
];

// ── Scheme credentials (Authorization: Bearer/Basic/Digest …) ──────────────────

// Separator may be a space, or URL-encoded (`Basic+…` in a form body, `Basic%20…`).
const SCHEME_CREDENTIAL = /\b(Bearer|Basic|Digest)(\s+|\+|%20)([A-Za-z0-9._~+/=%-]{8,})/g;

/**
 * Is `token` (after "Basic"/"Bearer"/"Digest") a credential rather than prose such as
 * "HTTP Basic authentication"? Any digit or base64/URL punctuation says token. A
 * Basic credential made only of letters (base64 of "user:pass" is `dXNlcjpwYXNz`)
 * is recognised by decoding to printable "user:password".
 */
function isSchemeCredential(scheme, token) {
  if (/[0-9+/=_~%]/.test(token)) return true;
  if (scheme.toLowerCase() !== 'basic' || token.length % 4 !== 0) return false;
  const decoded = Buffer.from(token, 'base64').toString('latin1');
  return decoded.includes(':') && /^[\x20-\x7e]+$/.test(decoded);
}

// ── Secret-named key followed by a value, in any text ──────────────────────────

// The key must END with one of these words (`newPassword`, `x-zap-api-key`,
// `csrf_token`), and be followed by `:` or `=`.
const KV_WORDS = 'password|passwd|secret|token|api[-_]?key|apikey|cookie|authorization|private[-_]?key|credentials?|otp|jwt|signature';
const KV_KEY = new RegExp(String.raw`(?<![A-Za-z0-9])(\\?["'\x60]?)[A-Za-z0-9_.-]*?(?:${KV_WORDS})\1\s*[:=]`, 'gi');
// Short words only as a quoted key (`"pass":`), so prose like "pass: 3/5" is kept.
const KV_KEY_QUOTED = /(?<![A-Za-z0-9])(\\?["'])(?:pass|pwd)\1\s*[:=]/gi;
// For header-like keys an unquoted value runs to the end of the line (`Cookie: a=1; b=2`,
// `Stripe-Signature: t=1,v1=…`).
const HEADER_LIKE = /(authorization|cookie|signature)\W*$/i;
const UNQUOTED_STOP = /[\s&,;}\])"'`#]/;

/** [start, end) of the value that begins at or after `i` (leading blanks skipped). */
function valueSpan(s, i, headerLike) {
  let j = i;
  while (j < s.length && (s[j] === ' ' || s[j] === '\t')) j++;
  // Double-encoded JSON: \"value\" — inner quotes appear as \\\".
  if (s[j] === '\\' && (s[j + 1] === '"' || s[j + 1] === "'")) {
    const close = s[j] + s[j + 1];
    let k = s.indexOf(close, j + 2);
    while (k > 0 && s[k - 1] === '\\') k = s.indexOf(close, k + 2);
    return [j + 2, k === -1 ? lineEnd(s, j) : k];
  }
  if (s[j] === '"' || s[j] === "'" || s[j] === '`') {
    const q = s[j];
    let k = j + 1;
    for (; k < s.length; k++) {
      if (s[k] === '\\') { k++; continue; }
      if (s[k] === q || (s[k] === '\n' && q !== '`')) break;
    }
    return [j + 1, Math.min(k, s.length)];
  }
  let k = j;
  if (headerLike) k = lineEnd(s, j);
  else while (k < s.length && !UNQUOTED_STOP.test(s[k])) k++;
  return [j, k];
}

function lineEnd(s, from) {
  const n = s.slice(from).search(/[\r\n]/);
  return n === -1 ? s.length : from + n;
}

function redactKeyValues(s, re) {
  re.lastIndex = 0;
  let out = '', last = 0, m;
  while ((m = re.exec(s)) !== null) {
    const keyEnd = m.index + m[0].length;
    // GOOGLE_APPLICATION_CREDENTIALS holds a file path, not a credential.
    if (/APPLICATION_CREDENTIALS\W*[:=]$/i.test(m[0])) { re.lastIndex = keyEnd; continue; }
    const [start, end] = valueSpan(s, keyEnd, HEADER_LIKE.test(m[0].replace(/[:=\s]+$/, '')));
    if (end > start && !s.startsWith(REDACTED, start)) {
      out += s.slice(last, start) + REDACTED;
      last = end;
    }
    re.lastIndex = Math.max(keyEnd, end);
  }
  return last === 0 ? s : out + s.slice(last);
}

// ── Strings ────────────────────────────────────────────────────────────────────

let secretValues = [];

function addSecret(values, v) {
  if (typeof v !== 'string' || v.length < MIN_SECRET_LENGTH) return;
  values.add(v);
  // The same value as it appears inside JSON.stringify / util.inspect output.
  const json = JSON.stringify(v).slice(1, -1);
  if (json !== v) values.add(json);
}

function collectSecretValues(env = process.env) {
  const values = new Set();
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== 'string') continue;
    // Passwords embedded in any URL-valued variable (MONGO_URI, REDIS_URL, …),
    // raw and percent-decoded — a Redis AUTH error carries the decoded one alone.
    for (const m of value.matchAll(URL_USERINFO)) {
      addSecret(values, m[1]);
      try { addSecret(values, decodeURIComponent(m[1])); } catch { /* not %-encoded */ }
    }
    if (!SECRET_ENV_NAME.test(name) || NOT_SECRET_ENV_NAME.test(name)) continue;
    addSecret(values, value);
  }
  // Longest first, so a secret containing another is redacted whole.
  return [...values].sort((a, b) => b.length - a.length);
}

/** Scrub one string. */
function redactString(input) {
  let s = String(input);
  for (const v of secretValues) {
    if (s.includes(v)) s = s.split(v).join(REDACTED);
  }
  for (const [re, rep] of STRING_PATTERNS) s = s.replace(re, rep);
  s = s.replace(SCHEME_CREDENTIAL, (m, scheme, sep, token) =>
    (isSchemeCredential(scheme, token) ? `${scheme}${sep}${REDACTED}` : m));
  s = redactKeyValues(s, KV_KEY);
  s = redactKeyValues(s, KV_KEY_QUOTED);
  return s;
}

/** The parts of a URL worth logging: origin and path, never the query or userinfo. */
function safeUrl(url) {
  if (!url) return undefined;
  try {
    const u = new URL(String(url), 'http://relative.invalid');
    return u.origin === 'http://relative.invalid' ? u.pathname : `${u.origin}${u.pathname}`;
  } catch {
    return redactString(String(url).split('?')[0]);
  }
}

// ── Objects and errors ─────────────────────────────────────────────────────────

// Properties of HTTP-client errors that hold the request/response (headers, body).
const TRANSPORT_KEYS = new Set(['config', 'request', 'response', 'socket', 'agent', 'res', 'req', 'options', 'headers', 'rawHeaders', '_options']);

// Redis commands whose arguments are credentials even outside a `command` property.
const CREDENTIAL_COMMAND = /^(auth|hello|acl|config|migrate)$/i;

/**
 * A Redis command as ioredis attaches it to an error (`err.command = { name, args }`):
 * the name is kept, the arguments never are — AUTH's are [user, password].
 */
function sanitizeCommand(cmd, depth, seen) {
  if (cmd && typeof cmd === 'object' && 'args' in cmd) {
    const n = Array.isArray(cmd.args) ? cmd.args.length : '?';
    return { name: typeof cmd.name === 'string' ? cmd.name : undefined, args: `[REDACTED: ${n} args]` };
  }
  return sanitize(cmd, depth, seen);
}

function isCommandShape(value) {
  return typeof value.name === 'string' && CREDENTIAL_COMMAND.test(value.name) && Array.isArray(value.args);
}

function sanitizeEntry(key, value, depth, seen) {
  if (SENSITIVE_KEY.test(key)) return REDACTED;
  if (key === 'command') return sanitizeCommand(value, depth, seen);
  return sanitize(value, depth, seen);
}

/** A sanitized error that prints like an error: its stack, then the safe extra fields. */
class SafeError {
  constructor(fields) { Object.assign(this, fields); }
  [util.inspect.custom]() {
    const { name, message, stack, ...extra } = this;
    const head = stack || `${name}: ${message}`;
    return Object.keys(extra).length ? `${head} ${util.inspect(extra, { depth: 4, breakLength: Infinity })}` : head;
  }
}

function sanitizeError(err, depth, seen) {
  const out = new SafeError({ name: redactString(err.name ?? 'Error'), message: redactString(err.message ?? '') });
  if (err.code !== undefined) out.code = sanitize(err.code, depth + 1, seen);
  const status = err.response?.status ?? err.status ?? err.statusCode;
  if (status !== undefined) out.status = sanitize(status, depth + 1, seen);
  const cfg = err.config;
  if (cfg && typeof cfg === 'object') {
    if (cfg.method) out.method = redactString(String(cfg.method).toUpperCase());
    const url = safeUrl(cfg.url);
    if (url) out.url = url;
  }
  for (const key of Object.keys(err)) {
    if (key in out || key === 'stack' || key === 'message' || TRANSPORT_KEYS.has(key)) continue;
    out[key] = sanitizeEntry(key, err[key], depth + 1, seen);
  }
  if (err.cause !== undefined && !('cause' in out)) out.cause = sanitize(err.cause, depth + 1, seen);
  // AggregateError keeps its members in a non-enumerable `errors`.
  if (Array.isArray(err.errors) && !('errors' in out)) out.errors = sanitize(err.errors, depth + 1, seen);
  if (err.stack) out.stack = redactString(err.stack);
  return out;
}

/** A log-safe copy of any value (never mutates the input). */
function sanitize(value, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactString(value);
  if (typeof value !== 'object' && typeof value !== 'function') return value;
  if (typeof value === 'function') return `[Function ${value.name || 'anonymous'}]`;
  if (Buffer.isBuffer(value)) return `<Buffer ${value.length} bytes>`;
  if (ArrayBuffer.isView(value)) return `<${value.constructor?.name || 'TypedArray'} ${value.byteLength} bytes>`;
  if (value instanceof String) return redactString(value.valueOf());
  if (value instanceof Date || value instanceof RegExp) return value;
  if (seen.has(value)) return '[Circular]';
  if (depth >= MAX_DEPTH) return '[Object]';
  seen.add(value);
  // isNativeError also recognises errors from another realm (vm, worker contexts).
  if (value instanceof Error || util.types.isNativeError(value)) return sanitizeError(value, depth, seen);
  if (Array.isArray(value)) return value.map(v => sanitize(v, depth + 1, seen));
  if (value instanceof Map) {
    return new Map([...value].map(([k, v]) => {
      const safeKey = typeof k === 'string' ? redactString(k) : sanitize(k, depth + 1, seen);
      return [safeKey, typeof k === 'string' ? sanitizeEntry(k, v, depth + 1, seen) : sanitize(v, depth + 1, seen)];
    }));
  }
  if (value instanceof Set) return new Set([...value].map(v => sanitize(v, depth + 1, seen)));
  if (isCommandShape(value)) return sanitizeCommand(value, depth, seen);
  const out = {};
  for (const key of Object.keys(value)) out[key] = sanitizeEntry(key, value[key], depth + 1, seen);
  return out;
}

/** Format console arguments exactly as console would, then scrub the result. */
function formatSafe(args) {
  return redactString(util.formatWithOptions({ colors: false, depth: MAX_DEPTH }, ...args.map(a => sanitize(a))));
}

function attempt(fn) {
  try { return fn(); } catch { return SUPPRESSED; }
}

// ── Installation ───────────────────────────────────────────────────────────────

const METHODS = ['log', 'info', 'warn', 'error', 'debug'];
const WRAPPED = [...METHODS, 'dir', 'dirxml', 'trace', 'table'];
let installed = null;
// True while the redactor itself is writing, so the stream backstop does not
// scrub (and pay for) a line that has already been scrubbed.
let writingSafeLine = false;

function installStreamBackstop() {
  const saved = [];
  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write;
    saved.push([stream, original]);
    stream.write = function write(chunk, encoding, cb) {
      // Strings only: binary chunks (e.g. a test runner's serialized protocol) pass
      // untouched. Every text logger — console, `debug`, driver loggers — writes strings.
      if (!writingSafeLine && typeof chunk === 'string') {
        chunk = attempt(() => redactString(chunk));
        if (chunk === SUPPRESSED) chunk = `${SUPPRESSED}\n`;
      }
      return original.call(this, chunk, encoding, cb);
    };
  }
  return saved;
}

function installCrashHandlers() {
  const onException = (err, origin) => {
    // The entry point has its own handler now: it logs (through console, so redacted)
    // and decides whether to shut down.
    if (process.listenerCount('uncaughtException') > 1) return;
    console.error(origin === 'unhandledRejection'
      ? '💥 Unhandled rejection (before the process registered its handlers):'
      : '💥 Uncaught exception (before the process registered its handlers):', err);
    process.exitCode = 1;
    process.stderr.write('', () => process.exit(1));
  };
  const onRejection = (reason) => {
    if (process.listenerCount('unhandledRejection') > 1) return;
    // Node's default (--unhandled-rejections=throw) turns it into an uncaught
    // exception; route it to the process's own exception handler if it has one.
    if (process.listenerCount('uncaughtException') > 1) {
      setImmediate(() => { throw reason; });
      return;
    }
    onException(reason, 'unhandledRejection');
  };
  process.on('uncaughtException', onException);
  process.on('unhandledRejection', onRejection);
  return { onException, onRejection };
}

/**
 * Wrap console.* (and, outside tests, process.stdout/stderr and the crash handlers)
 * for the rest of the process. Idempotent.
 * @param {{ env?: object, sink?: (method: string, line: string) => void,
 *           streams?: boolean, crashHandlers?: boolean }} [opts]
 *   sink: tests capture output here instead of the real console; with a sink the
 *   stream backstop and crash handlers are off unless asked for.
 */
function install(opts = {}) {
  secretValues = collectSecretValues(opts.env || process.env);
  if (installed) return;
  const sink = opts.sink;
  const originals = {};
  for (const m of WRAPPED) originals[m] = console[m];

  const emit = (method, line) => {
    if (sink) { sink(method, line); return; }
    const target = ['warn', 'error', 'trace'].includes(method) ? originals.error
      : method === 'info' || method === 'debug' ? originals[method] : originals.log;
    writingSafeLine = true;
    try { target.call(console, line); } finally { writingSafeLine = false; }
  };

  for (const m of METHODS) console[m] = (...args) => emit(m, attempt(() => formatSafe(args)));
  // console.dir normally inspects the raw object straight onto stdout.
  console.dir = (obj, options) => emit('dir', attempt(() =>
    redactString(util.inspect(sanitize(obj), { ...(options || {}), colors: false }))));
  console.dirxml = (...args) => emit('dirxml', attempt(() => formatSafe(args)));
  // console.trace normally formats the raw arguments before console.error sees them.
  console.trace = function trace(...args) {
    const line = attempt(() => {
      const t = { name: 'Trace', message: formatSafe(args) };
      Error.captureStackTrace(t, trace);
      return redactString(t.stack);
    });
    emit('trace', line);
  };
  // console.table renders the raw rows into one string; render sanitized rows instead
  // (it prints through console.log, which is wrapped above).
  console.table = (data, properties) => {
    let safe;
    try { safe = sanitize(data); } catch { emit('table', SUPPRESSED); return; }
    originals.table.call(console, safe, properties);
  };

  installed = {
    originals,
    streams: (opts.streams ?? !sink) ? installStreamBackstop() : [],
    handlers: (opts.crashHandlers ?? !sink) ? installCrashHandlers() : null,
  };
}

/** Tests only: restore the original console methods, streams and handlers. */
function uninstall() {
  if (!installed) return;
  for (const m of WRAPPED) console[m] = installed.originals[m];
  for (const [stream, original] of installed.streams) stream.write = original;
  if (installed.handlers) {
    process.removeListener('uncaughtException', installed.handlers.onException);
    process.removeListener('unhandledRejection', installed.handlers.onRejection);
  }
  installed = null;
  secretValues = [];
}

/** Re-read secret env values (call after secrets are loaded later at runtime). */
function refreshSecrets(env = process.env) { secretValues = collectSecretValues(env); }

module.exports = { install, uninstall, refreshSecrets, redactString, sanitize, formatSafe, collectSecretValues, REDACTED };
