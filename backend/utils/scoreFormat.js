/**
 * Shared formatting for Lighthouse / PageSpeed category scores.
 *
 * A category that PageSpeed did not return is genuinely UNKNOWN, not zero.
 * Coercing it with `|| 0` produced reports that told customers their site
 * scored "0/100" for accessibility when the score was simply never collected.
 * These helpers keep "not measured" and "measured as zero" distinct.
 */

const NOT_AVAILABLE = 'N/A';

/**
 * Extract the four Lighthouse category scores from a PageSpeed result.
 * Each value is a 0-100 integer, or `null` when the category is absent.
 *
 * @param {object} pagespeedResult - raw PSI response (scanResult.pagespeedResult)
 * @returns {{performance: number|null, accessibility: number|null, bestPractices: number|null, seo: number|null}}
 */
function lighthouseScores(pagespeedResult) {
  const categories = pagespeedResult?.lighthouseResult?.categories || {};

  // `score` is a 0..1 float. It can legitimately be 0, so test for presence
  // rather than truthiness.
  const toScore = (category) => {
    const score = category?.score;
    return typeof score === 'number' && isFinite(score) ? Math.round(score * 100) : null;
  };

  return {
    performance:   toScore(categories.performance),
    accessibility: toScore(categories.accessibility),
    bestPractices: toScore(categories['best-practices']),
    seo:           toScore(categories.seo)
  };
}

/**
 * Render a score for display: "84/100", or "N/A" when it was never measured.
 * @param {number|null|undefined} score
 */
function formatScore(score) {
  return score === null || score === undefined ? NOT_AVAILABLE : `${score}/100`;
}

/**
 * Render an arbitrary metric for display, preserving a real 0.
 * Used for values like Observatory score and urlscan threat score, where a
 * missing scanner result must not read as a perfect/zero measurement.
 * @param {number|null|undefined} value
 */
function formatMetric(value) {
  return typeof value === 'number' && isFinite(value) ? `${value}/100` : NOT_AVAILABLE;
}

module.exports = { lighthouseScores, formatScore, formatMetric, NOT_AVAILABLE };
