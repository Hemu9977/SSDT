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

let observatory = null;
async function loadObservatory() {
  if (!observatory) {
    const [{ scan }, { Site }] = await Promise.all([
      import('@mdn/mdn-http-observatory'),
      import('@mdn/mdn-http-observatory/src/site.js')
    ]);
    observatory = { scan, Site };
  }
  return observatory;
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
  const result = await scanEngineCached(host);
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

module.exports = {
  gradeHost,
  getTlsReport,
  // Exposed for tests.
  _toApiShape: toApiShape,
  _cache: cache
};
