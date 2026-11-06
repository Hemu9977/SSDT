/**
 * External check first, in-house check only when the external one cannot serve
 * this target.
 *
 * The external diagnostics (PageSpeed Insights, the public header-grading API,
 * the page-analysis service) fetch the target from their own servers. A client
 * whose site only admits allowlisted IPs refuses them — they fail, or report on
 * the 403 page instead of the site. The in-house versions fetch from Fortexa's
 * egress IP, which the client allowlists, so they stand in exactly then.
 *
 * Rules:
 *   - A usable external result is returned untouched: reports are as before.
 *   - The in-house result replaces it only if it is usable itself. A site that
 *     refuses everyone (both see 403) keeps the external outcome, as before.
 *   - If neither is usable, the external outcome stands: its result, or its
 *     error thrown so callers store `{ error }` exactly as they did.
 */

/**
 * @param {object}   o
 * @param {string}   o.name        - label for logs
 * @param {() => Promise<object>} o.external
 * @param {() => Promise<object>} o.inHouse
 * @param {(result: object) => string|null} [o.unusable] - why a result cannot be
 *   used (e.g. 'http_403'), or null when it can. Applied to both results.
 */
async function withInHouseFallback({ name, external, inHouse, unusable = () => null }) {
  let externalResult = null;
  let externalError = null;
  let reason;

  try {
    externalResult = await external();
    reason = unusable(externalResult);
    if (!reason) return externalResult;
  } catch (err) {
    externalError = err;
    reason = err?.message || 'failed';
  }

  console.warn(`[Fallback] ${name}: external check unusable (${reason}) — running the in-house check`);

  try {
    const result = await inHouse();
    const inHouseReason = unusable(result);
    if (inHouseReason) {
      // Refused from our IP as well: report what we had before, never the error page.
      console.warn(`[Fallback] ${name}: in-house check unusable too (${inHouseReason}) — keeping the external outcome`);
      if (externalResult) return externalResult;
      throw externalError;
    }
    if (result && typeof result === 'object') {
      result.diagnosticSource = 'in-house';
      result.fallbackReason = String(reason).slice(0, 200);
    }
    console.log(`[Fallback] ${name}: in-house check succeeded`);
    return result;
  } catch (inHouseErr) {
    console.warn(`[Fallback] ${name}: in-house check failed (${inHouseErr.message})`);
    if (externalResult) return externalResult;
    throw externalError;
  }
}

/** HTTP status of the page a check looked at, when it is an error page. */
function httpErrorReason(status) {
  const code = Number(status);
  return Number.isFinite(code) && code >= 400 ? `http_${code}` : null;
}

/** A PSI-shaped result that carries no scores (or Lighthouse could not audit the page). */
function lighthouseUnusable(result) {
  if (!result || result.error) return 'error';
  const lr = result.lighthouseResult;
  if (!lr) return 'no_lighthouse_result';
  if (lr.runtimeError?.code && lr.runtimeError.code !== 'NO_ERROR') return `lighthouse_${lr.runtimeError.code}`;
  const cats = Object.values(lr.categories || {});
  if (!cats.length || cats.every(c => c?.score === null || c?.score === undefined)) return 'no_scores';
  return null;
}

module.exports = { withInHouseFallback, httpErrorReason, lighthouseUnusable };
