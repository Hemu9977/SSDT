/**
 * Neutral scan progress model.
 *
 * SSD is resold as a private product, so the UI must never surface which third-party
 * engine is running. Progress is reported as "Step N of 6" instead of naming the
 * scanner. This module is the single source of truth for that mapping and is shared
 * by all three progress UIs (Hero, AuthenticatedScanPanel, ScanForm).
 *
 * It deliberately ignores backend-supplied `message` / `error` strings: those are
 * plain English, bypass i18n, and name the engines — they are for server logs only.
 */

export const SCAN_STEP_COUNT = 6;

// A scanner that failed will never report success, so treat terminal failure as
// settled — otherwise the step counter freezes on a dead scanner for the rest of
// the run. Terminal states mirror the ones documented in CLAUDE.md.
const WEBCHECK_SETTLED = ['completed', 'completed_partial', 'completed_with_errors', 'failed'];
const ZAP_SETTLED = ['completed', 'completed_partial', 'failed'];

/**
 * Per-step completion, in fixed display order.
 *
 * Completion flags arrive under two different names depending on transport: the
 * WebSocket payload (notificationService.emitScanProgress) sets hasPagespeed /
 * hasObservatory / hasUrlscan, while the HTTP polling endpoints (virustotalRoutes)
 * set hasPsiResult / hasObservatoryResult / hasUrlscanResult. Hero merges WS payloads
 * into the same object, so both shapes can be present at once — hence the `||` rather
 * than `??` (an explicit `false` from one transport must not mask a `true` from the
 * other). Data presence is checked as a final fallback.
 */
export const getStepCompletion = (report) => {
  const r = report || {};
  return [
    !!(r.hasPsiResult || r.hasPagespeed || r.psiScores),
    !!(r.hasObservatoryResult || r.hasObservatory || r.observatoryData),
    !!(r.hasUrlscanResult || r.hasUrlscan || r.urlscanData),
    WEBCHECK_SETTLED.includes(r.webCheckData?.status),
    !!r.hasZapResult || ZAP_SETTLED.includes(r.zapData?.status),
    !!(r.hasRefinedReport || r.refinedReport),
  ];
};

export const getCompletedStepCount = (report) => getStepCompletion(report).filter(Boolean).length;

/**
 * 1-based index of the lowest step that has not settled yet. Using the lowest
 * incomplete step (rather than a count) keeps the number monotonic even though the
 * engines run in parallel and finish out of order.
 */
export const getCurrentStep = (report) => {
  const idx = getStepCompletion(report).findIndex((done) => !done);
  return idx === -1 ? SCAN_STEP_COUNT : idx + 1;
};

/** Localized, engine-agnostic status line for the progress bar. */
export const getScanStatusLine = (report, t) => {
  const steps = getStepCompletion(report);
  if (steps.every(Boolean)) return t('finalizingResults');
  return t('scanStepInProgress', {
    current: getCurrentStep(report),
    total: SCAN_STEP_COUNT,
  });
};
