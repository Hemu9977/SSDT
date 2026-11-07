/**
 * Display state of the report's tool cards and AI summary.
 *
 * Shared by Hero.jsx (normal scan) and AuthenticatedScanPanel.jsx (authenticated
 * scan) so both pages decide "loading / pending / completed / failed" identically.
 *
 * Everything here is derived from structured fields the scan endpoints already
 * return (active-scan, combined-analysis, scan/:id, zap-auth/status and the
 * WebSocket payload Hero merges in). It issues no requests, invents no progress,
 * and never reads a backend `message` / `error` string for display — an `error`
 * field is only tested for presence.
 *
 *  - loading:   the check is running (or has not reported yet).
 *  - pending:   the check is waiting in a queue — the whole scan is `queued`, or
 *               the vulnerability scan is `pending` in its own queue.
 *  - completed: a usable result arrived; only then is the result rendered.
 *  - failed:    `reason: 'failed'` when the check reported failure, or
 *               `reason: 'unavailable'` when the scan ended without a result.
 */

export const TOOL_STATE = Object.freeze({
  LOADING: 'loading',
  PENDING: 'pending',
  COMPLETED: 'completed',
  FAILED: 'failed',
});

// Overall ScanResult.status values (backend/models/ScanResult.js).
const SCAN_ENDED = ['completed', 'failed', 'stopped', 'cancelled'];
const SCAN_ABORTED = ['failed', 'stopped', 'cancelled'];
// Terminal states from CLAUDE.md.
const ZAP_DONE = ['completed', 'completed_partial'];
const WEBCHECK_SETTLED = ['completed', 'completed_partial', 'completed_with_errors', 'failed'];

const completed = () => ({ state: TOOL_STATE.COMPLETED });
const failed = (reason) => ({ state: TOOL_STATE.FAILED, reason });

/** What a check with no result yet shows, given where the overall scan is. */
const awaiting = (report) => {
  if (SCAN_ENDED.includes(report?.status)) return failed('unavailable');
  if (report?.status === 'queued') return { state: TOOL_STATE.PENDING };
  return { state: TOOL_STATE.LOADING };
};

/** Real progress only: a finite number above 0, clamped to 0–100; else null. */
const realProgress = (value) => {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.min(100, Math.round(n));
};

export const getVulnerabilityState = (report) => {
  const zap = report?.zapData;
  if (zap) {
    if (ZAP_DONE.includes(zap.status)) return completed();
    if (zap.status === 'failed') return failed('failed');
    // A running/queued vulnerability scan under a scan that was stopped or
    // failed will never finish — do not keep animating it.
    if (SCAN_ABORTED.includes(report?.status)) return failed('unavailable');
    if (zap.status === 'running') {
      return { state: TOOL_STATE.LOADING, progress: realProgress(zap.progress) };
    }
    if (zap.status === 'pending') return { state: TOOL_STATE.PENDING };
  }
  if (report?.zapResult?.error || (report?.status === 'completed' && !report?.hasZapResult)) {
    return failed('unavailable');
  }
  return awaiting(report);
};

export const getPerformanceState = (report) => {
  const psi = report?.psiScores;
  if (psi?.performance != null) return completed();
  // The check answered but carried no performance score, or reported an error.
  if (psi || report?.pagespeedResult?.error) return failed('unavailable');
  return awaiting(report);
};

export const getSecurityConfigState = (report) => {
  if (report?.observatoryData?.grade) return completed();
  if (report?.observatoryData || report?.observatoryResult?.error) return failed('unavailable');
  return awaiting(report);
};

export const getThreatIntelState = (report) => {
  if (report?.hasUrlscanResult && report?.urlscanData) return completed();
  if (report?.urlscanResult?.error || (report?.status === 'completed' && !report?.hasUrlscanResult)) {
    return failed('unavailable');
  }
  return awaiting(report);
};

/** The four cards that get the loading treatment, keyed by tool. */
export const getReportToolStates = (report) => ({
  vulnerability: getVulnerabilityState(report),
  performance: getPerformanceState(report),
  securityConfig: getSecurityConfigState(report),
  threatIntel: getThreatIntelState(report),
});

/** Number of inputs the AI summary waits for: the four cards + the site checks. */
export const AI_INPUT_COUNT = 5;

/**
 * Stage of the AI summary panel.
 *  - ready:       the summary text is here.
 *  - unavailable: the scan ended without one (never animate a dead panel).
 *  - composing:   every input has settled; the summary itself is being written.
 *  - collecting:  still waiting for inputs; `settled` of `total` have arrived.
 */
export const getAiSummaryState = (report) => {
  if (report?.refinedReport) return { stage: 'ready' };
  if (SCAN_ABORTED.includes(report?.status)
      || (report?.status === 'completed' && !report?.hasRefinedReport)) {
    return { stage: 'unavailable' };
  }

  const tools = getReportToolStates(report);
  const settled = Object.values(tools)
    .filter(({ state }) => state === TOOL_STATE.COMPLETED || state === TOOL_STATE.FAILED)
    .length + (WEBCHECK_SETTLED.includes(report?.webCheckData?.status) ? 1 : 0);

  if (settled >= AI_INPUT_COUNT || report?.status === 'combining' || report?.hasRefinedReport) {
    return { stage: 'composing', settled: AI_INPUT_COUNT, total: AI_INPUT_COUNT };
  }
  return { stage: 'collecting', settled, total: AI_INPUT_COUNT };
};
