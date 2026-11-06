const axios = require('axios');
const { LAUNCH_ARGS, chromiumPath, runInBrowserSlot } = require('./browserSlot');

/**
 * In-house performance / accessibility / best-practices / SEO audit — the
 * fallback for Google PageSpeed Insights.
 *
 * PSI loads the target from Google's servers; behind a client's IP allowlist those
 * requests are refused and PSI returns an error. When that happens (or PSI is
 * unavailable) we run the same engine — Lighthouse, the version PSI itself runs —
 * with PSI's settings from our own egress IP, which the client has allowlisted.
 *
 * The result keeps PSI's response shape for every field the app reads
 * (`lighthouseResult.categories.<id>.score`, and `loadingExperience` for the mobile
 * quality audit), but never the multi-MB raw Lighthouse report.
 */

const CATEGORIES = ['performance', 'accessibility', 'best-practices', 'seo'];
const AUDIT_TIMEOUT_MS = Number(process.env.LIGHTHOUSE_TIMEOUT_MS) || 120_000;
const CRUX_ENDPOINT = 'https://chromeuxreport.googleapis.com/v1/records:queryRecord';

// Lighthouse is ESM-only; load it once, lazily, from this CommonJS module.
let lighthouseModules = null;
async function loadLighthouse() {
  if (!lighthouseModules) {
    const [{ default: lighthouse }, chromeLauncher, { default: desktopConfig }] = await Promise.all([
      import('lighthouse'),
      import('chrome-launcher'),
      import('lighthouse/core/config/desktop-config.js')
    ]);
    lighthouseModules = { lighthouse, chromeLauncher, desktopConfig };
  }
  return lighthouseModules;
}

/**
 * Reduce a Lighthouse report to the PSI-shaped fields the app reads.
 * Throws when Lighthouse could not audit the page (e.g. the page answered 403):
 * PSI fails the same way, and the caller stores `{ error }` -> "unavailable",
 * rather than scores for an error page.
 */
function toPsiShape(lhr) {
  if (lhr.runtimeError) {
    throw new Error(`Lighthouse could not audit the page: ${lhr.runtimeError.code}`);
  }
  const categories = {};
  for (const id of CATEGORIES) {
    const cat = lhr.categories?.[id];
    if (cat) categories[id] = { id, title: cat.title, score: cat.score };
  }
  if (!Object.keys(categories).length || Object.values(categories).every(c => c.score === null)) {
    throw new Error('Lighthouse returned no category scores');
  }
  return {
    analysisUTCTimestamp: lhr.fetchTime,
    lighthouseResult: {
      lighthouseVersion: lhr.lighthouseVersion,
      fetchTime: lhr.fetchTime,
      configSettings: { formFactor: lhr.configSettings?.formFactor },
      categories
    }
  };
}

// ── Field data (CrUX) ────────────────────────────────────────────────────────
// PSI's `loadingExperience` is Chrome's real-user dataset, looked up by URL. It
// never contacts the target, so an IP allowlist does not affect it. Same metric
// names, thresholds and FAST/AVERAGE/SLOW categories as PSI.
const CRUX_METRICS = {
  largest_contentful_paint:        { psi: 'LARGEST_CONTENTFUL_PAINT_MS',     good: 2500, poor: 4000, scale: 1,   cwv: true },
  interaction_to_next_paint:       { psi: 'INTERACTION_TO_NEXT_PAINT',       good: 200,  poor: 500,  scale: 1,   cwv: true },
  cumulative_layout_shift:         { psi: 'CUMULATIVE_LAYOUT_SHIFT_SCORE',   good: 10,   poor: 25,   scale: 100, cwv: true },
  first_contentful_paint:          { psi: 'FIRST_CONTENTFUL_PAINT_MS',       good: 1800, poor: 3000, scale: 1 },
  experimental_time_to_first_byte: { psi: 'EXPERIMENTAL_TIME_TO_FIRST_BYTE', good: 800,  poor: 1800, scale: 1 }
};
const CATEGORY_RANK = { FAST: 0, AVERAGE: 1, SLOW: 2 };

function categoryFor(value, { good, poor }) {
  if (value <= good) return 'FAST';
  if (value <= poor) return 'AVERAGE';
  return 'SLOW';
}

/** CrUX API record -> PSI `loadingExperience`. Returns null when there is nothing usable. */
function loadingExperienceFromCrux(record, { initialUrl, originFallback }) {
  const metrics = {};
  let overall = null;
  for (const [name, spec] of Object.entries(CRUX_METRICS)) {
    const m = record?.metrics?.[name];
    const p75 = Number(m?.percentiles?.p75);
    if (!m || !Number.isFinite(p75)) continue;
    const percentile = Math.round(p75 * spec.scale);
    const category = categoryFor(percentile, spec);
    metrics[spec.psi] = {
      percentile,
      distributions: (m.histogram || []).map(h => {
        const bin = { min: Math.round(Number(h.start) * spec.scale), proportion: h.density };
        if (h.end !== undefined) bin.max = Math.round(Number(h.end) * spec.scale);
        return bin;
      }),
      category
    };
    // PSI's overall assessment is the slowest of the Core Web Vitals.
    if (spec.cwv && (overall === null || CATEGORY_RANK[category] > CATEGORY_RANK[overall])) overall = category;
  }
  if (!Object.keys(metrics).length) return null;
  const out = { id: initialUrl, metrics, initial_url: initialUrl };
  if (overall) out.overall_category = overall;
  if (originFallback) out.origin_fallback = true;
  return out;
}

/**
 * URL-level field data, falling back to the origin like PSI does. Needs the
 * "Chrome UX Report API" enabled for the key's project; returns null otherwise
 * (the report then simply has no field-data line, as for a low-traffic site).
 */
async function fetchLoadingExperience(url, formFactor) {
  const key = process.env.CRUX_API_KEY || process.env.PSI_API_KEY;
  if (!key) return null;
  const cruxFormFactor = formFactor === 'desktop' ? 'DESKTOP' : 'PHONE';
  const attempts = [
    { body: { url, formFactor: cruxFormFactor }, originFallback: false },
    { body: { origin: new URL(url).origin, formFactor: cruxFormFactor }, originFallback: true }
  ];
  for (const { body, originFallback } of attempts) {
    try {
      const res = await axios.post(`${CRUX_ENDPOINT}?key=${encodeURIComponent(key)}`, body, { timeout: 10_000 });
      return loadingExperienceFromCrux(res.data?.record, { initialUrl: url, originFallback });
    } catch (err) {
      if (err.response?.status === 404) continue; // no data at this level
      console.warn(`[Lighthouse] Field data unavailable (${err.response?.status || err.code || err.message})`);
      return null;
    }
  }
  return null;
}

/**
 * @param {string} url
 * @param {object} [opts]
 * @param {'desktop'|'mobile'} [opts.strategy='desktop'] - desktop for the score
 *   card (as before); mobile for WebCheck's quality section (PSI's mobile run).
 * @param {AbortSignal} [opts.signal]
 */
async function runLighthouseAudit(url, { strategy = 'desktop', signal } = {}) {
  const { lighthouse, chromeLauncher, desktopConfig } = await loadLighthouse();

  const report = await runInBrowserSlot(`Lighthouse (${strategy})`, async ({ signal: jobSignal }) => {
    const chrome = await chromeLauncher.launch({
      chromePath: chromiumPath(),
      chromeFlags: ['--headless=new', ...LAUNCH_ARGS]
    });
    // chrome-launcher's kill() is synchronous and may throw if the process is gone.
    const kill = () => { try { chrome.kill(); } catch { /* already exited */ } };
    jobSignal.addEventListener('abort', kill, { once: true });
    try {
      const result = await lighthouse(url, {
        port: chrome.port,
        output: 'json',
        logLevel: 'error',
        onlyCategories: CATEGORIES,
        maxWaitForLoad: 45_000
      }, strategy === 'desktop' ? desktopConfig : undefined);
      if (!result?.lhr) throw new Error('Lighthouse returned no report');
      return toPsiShape(result.lhr);
    } finally {
      jobSignal.removeEventListener('abort', kill);
      kill();
    }
  }, { timeoutMs: AUDIT_TIMEOUT_MS, signal });

  if (strategy === 'mobile') {
    const loadingExperience = await fetchLoadingExperience(url, strategy);
    if (loadingExperience) report.loadingExperience = loadingExperience;
  }
  return report;
}

module.exports = {
  runLighthouseAudit,
  // Exposed for tests.
  _toPsiShape: toPsiShape,
  _loadingExperienceFromCrux: loadingExperienceFromCrux
};
