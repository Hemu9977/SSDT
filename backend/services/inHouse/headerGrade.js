/**
 * In-house HTTP security-header grading — the fallback for Mozilla's public
 * Observatory API (the score card, and WebCheck's TLS section, which calls the
 * same API from the WebCheck container).
 *
 * That API fetches the target from Mozilla's servers. Behind a client's IP
 * allowlist it is refused — an error, or a grade for the 403 page. Then we run the
 * same open-source engine (@mdn/mdn-http-observatory, the code behind that API:
 * same algorithm version, same grades and scores) from our own egress IP.
 *
 * Results keep the API's v2 `/scan` shape (`grade`, `score`, `tests_passed`,
 * `tests_failed`, `tests_quantity`, `status_code`, ...).
 */

// A finished scan is reused for this long, so when both the score card and
// WebCheck's TLS section fall back — minutes apart, for the same host — they agree
// and the target is not fetched twice.
const CACHE_TTL_MS = 10 * 60 * 1000;
const cache = new Map(); // host -> { at, promise }

const { AsyncLocalStorage } = require('async_hooks');

let observatory = null;
async function loadObservatory() {
  if (!observatory) {
    const [{ scan }, { Site }, { Session }] = await Promise.all([
      import('@mdn/mdn-http-observatory'),
      import('@mdn/mdn-http-observatory/src/site.js'),
      import('@mdn/mdn-http-observatory/src/retriever/session.js')
    ]);
    installCredentialGuard(Session);
    observatory = { scan, Site };
  }
  return observatory;
}

// ── HTTP Basic: the credential for the target origin only ──────────────────────
//
// The engine's own `customHeaders` option is NOT used for a credential: it puts the
// header on every request of the session — redirects to other hosts, robots.txt,
// the CORS probe. Instead every HTTP client the engine creates gets a request
// interceptor that adds `Authorization` only when the request's origin (scheme +
// host + port) is exactly the target origin, and only inside a grading started by
// gradeHostWithBasicAuth (AsyncLocalStorage — concurrent unauthenticated gradings
// of other scans never see it). Automatic redirect hops strip it again unless they
// stay on the target origin (follow-redirects would otherwise keep it for
// subdomains). Plain http:// is a different origin, so it never gets it.
// The engine version is pinned exactly in package.json; tests/basicAuthSiteChecks
// fails if this guard stops applying.

const basicScope = new AsyncLocalStorage();
const guardedClients = new WeakSet();
let guardedSession = null;

function originOf(href) {
  try { return new URL(href).origin; } catch { return null; }
}

function stripAuthorization(headers) {
  if (!headers) return;
  if (typeof headers.delete === 'function') { headers.delete('Authorization'); return; }
  for (const k of Object.keys(headers)) if (k.toLowerCase() === 'authorization') delete headers[k];
}

function guardClient(client) {
  if (!client || guardedClients.has(client)) return;
  guardedClients.add(client);
  client.interceptors.request.use((config) => {
    // Nothing reaches the network with an Authorization header this guard did not set.
    stripAuthorization(config.headers);
    const scope = basicScope.getStore();
    if (!scope) return config;
    let origin = null;
    try { origin = new URL(config.url, config.baseURL || undefined).origin; } catch { /* unparseable: no credential */ }
    if (origin === scope.origin) {
      if (typeof config.headers.set === 'function') config.headers.set('Authorization', scope.authorization);
      else config.headers.Authorization = scope.authorization;
    }
    const previous = config.beforeRedirect;
    config.beforeRedirect = (options, ...rest) => {
      if (previous) previous(options, ...rest);
      const hop = originOf(`${options.protocol}//${options.hostname}${options.port ? `:${options.port}` : ''}`);
      if (hop !== scope.origin) stripAuthorization(options.headers);
    };
    return config;
  });
}

/** Guard the clients of every engine session, including the ones it re-creates after a certificate error. */
function installCredentialGuard(Session) {
  if (guardedSession === Session) return;
  const init = Session.prototype.init;
  Session.prototype.init = async function guardedInit(...args) {
    guardClient(this.clientInstanceRecordingRedirects);
    guardClient(this.clientInstance);
    return init.apply(this, args);
  };
  guardedSession = Session;
}

/** Engine result -> the v2 API `/scan` response shape. */
function toApiShape(result, scannedAt = new Date()) {
  const s = result.scan;
  return {
    id: null,
    algorithm_version: s.algorithmVersion,
    scanned_at: scannedAt.toISOString(),
    error: null,
    grade: s.grade,
    score: s.score,
    status_code: s.statusCode,
    tests_failed: s.testsFailed,
    tests_passed: s.testsPassed,
    tests_quantity: s.testsQuantity
  };
}

/** Engine tests -> a compact per-test map (the v2 `/tests` endpoint's essentials). */
function toTestsShape(result) {
  const tests = {};
  for (const [name, t] of Object.entries(result.tests || {})) {
    tests[name] = {
      name,
      expectation: t.expectation,
      pass: t.pass,
      result: t.result,
      score_modifier: t.scoreModifier
    };
  }
  return tests;
}

async function runEngine(host) {
  const { scan, Site } = await loadObservatory();
  try {
    return await scan(Site.fromSiteString(host));
  } catch (err) {
    // Same failure surface as the API used to give: a thrown error, which the
    // scan orchestrators store as { error } ("unavailable" in the report).
    const error = new Error(`Observatory scan failed: ${err.name || 'error'}: ${err.message}`);
    error.status = err.statusCode || 500;
    error.details = err.name;
    throw error;
  }
}

function scanEngineCached(host) {
  const key = String(host).toLowerCase();
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.promise;

  const promise = runEngine(key);
  cache.set(key, { at: Date.now(), promise });
  // Never cache a failure: the next caller should try again.
  promise.catch(() => cache.delete(key));
  // Keep the map from growing without bound.
  for (const [k, v] of cache) if (Date.now() - v.at >= CACHE_TTL_MS) cache.delete(k);
  return promise;
}

/**
 * Grade a hostname's HTTP security headers.
 * @param {string} host - e.g. 'example.com'
 * @returns {Promise<object>} v2 `/scan`-shaped result
 */
async function gradeHost(host) {
  console.log(`🔍 [In-house] Grading security headers: ${host}`);
  const result = await scanEngineCached(host);
  return toApiShape(result);
}

/**
 * The same scan in the shape WebCheck's `tls` check returns (it calls the same
 * public API): `{ scan, tests, tlsInfo }`.
 * @param {string} url - full URL; only the hostname is graded
 */
async function getTlsReport(url) {
  const host = new URL(url).hostname;
  return toTlsReport(await scanEngineCached(host), host);
}

function toTlsReport(result, host) {
  const scan = toApiShape(result);
  return {
    scan,
    tests: toTestsShape(result),
    tlsInfo: {
      grade: scan.grade || 'N/A',
      score: scan.score || 0,
      endTime: scan.scanned_at,
      host,
      statusCode: scan.status_code
    }
  };
}

/**
 * The same grading for an HTTP Basic scan, signed in: the credential is sent only
 * to `basicAuth.origin` (see the guard above). Never cached — the result belongs to
 * this scan's credential. One run serves both readers.
 * @param {string} host
 * @param {{origin: string, username: string, password: string}} basicAuth
 * @param {object} [engineOptions] - tests only (e.g. httpPort of a local server)
 * @returns {Promise<{observatory: object, tls: object}>} the score card's v2 `/scan` shape and WebCheck's `tls` shape
 */
async function gradeHostWithBasicAuth(host, { origin, username, password }, engineOptions = {}) {
  const target = new URL(origin);
  if (target.protocol !== 'https:') throw new Error('Basic credentials are only ever sent to an https origin');
  if (target.hostname.toLowerCase() !== String(host).toLowerCase()) throw new Error('The credential belongs to another host');
  console.log(`🔍 [In-house] Grading security headers: ${host} (HTTP Basic, target origin only)`);
  const { scan, Site } = await loadObservatory();
  const scope = {
    origin: target.origin,
    authorization: `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`
  };
  // A non-default port is graded on that port, so the origin still matches.
  const options = { ...(target.port ? { httpsPort: Number(target.port) } : {}), ...engineOptions };
  let result;
  try {
    result = await basicScope.run(scope, () => scan(Site.fromSiteString(host), options));
  } catch (err) {
    const error = new Error(`Observatory scan failed: ${err.name || 'error'}: ${err.message}`);
    error.status = err.statusCode || 500;
    throw error;
  }
  return { observatory: toApiShape(result), tls: toTlsReport(result, host) };
}

module.exports = {
  gradeHost,
  getTlsReport,
  gradeHostWithBasicAuth,
  // Tests only: an unauthenticated grading with engine options, bypassing the cache.
  _gradeUncached: async (host, options) => {
    const { scan, Site } = await loadObservatory();
    return toApiShape(await scan(Site.fromSiteString(host), options));
  },
  // Exposed for tests.
  _toApiShape: toApiShape,
  _cache: cache
};
