'use strict';

/**
 * Fast-scanner orchestration for the authenticated scan flow.
 *
 * WHY THIS IS A SERVICE AND NOT A ROUTE HELPER
 * It has two callers that must behave identically: POST /api/zap-auth/scan (and its
 * GET /status/:scanId self-heal), and schedulerService.triggerAuthenticatedScan.
 * A scheduled scan has no browser polling it at all, so if this lived in the route
 * module the scheduler would have to require a route to run a scan — and, before
 * this was extracted, it simply did not run these scanners, which left every
 * scheduled authenticated scan without PageSpeed/Observatory/urlscan/WebCheck data.
 *
 * The normal flow needs no equivalent: scanWorker runs and persists the same four
 * scanners inline before it enqueues the ZAP job.
 */

const ScanResult = require('../models/ScanResult');
const { getPageSpeedReport } = require('./pagespeedService');
const { scanHost } = require('./observatoryService');
const { runUrlScan } = require('./urlscanService');
const { startAsyncWebCheckScan } = require('./webCheckService');

/**
 * Start the four fast scanners for an authenticated scan, persist their results, then
 * hand off to the completion service.
 *
 * WHY THIS EXISTS AS A FUNCTION
 * This logic used to be inline in GET /status/:scanId, which meant the fast scanners
 * only ever started when a browser happened to poll. Observed in production
 * 2026-08-24: the ZAP leg finished at 15:09:44 and the fast scanners did not start
 * until 15:23:59 — a 14-minute gap in which nothing was running, because nothing was
 * polling. A scan must not depend on a tab staying open.
 *
 * IDEMPOTENCY
 * `fastScansStartedAt` is claimed with a single atomic findOneAndUpdate. Mongo applies
 * it to one document at a time, so exactly one caller can observe the unclaimed state
 * and every other caller — a second poll, a retry, the accept-time kick-off racing the
 * first poll — returns immediately without starting anything.
 *
 * ORDERING (this is the race that was fixed)
 * WebCheck is started LAST and only after PageSpeed/Observatory/urlscan have been
 * persisted. startAsyncWebCheckScan returns immediately and runs in the background,
 * and its completion handler calls checkAndGenerateGemini. Previously all four were
 * launched together under Promise.all and persisted only after it resolved, so
 * WebCheck (~10s) could finish and trigger completion while urlscan (~20s) was still
 * running — the completion service then saw no fast-scan data at all.
 *
 * @returns {Promise<{started: boolean, reason?: string}>}
 */
async function ensureAuthFastScans(analysisId, userId) {
  // `fastScansStartedAt: null` also matches documents where the field is absent, so
  // scans created before this field existed are claimable too.
  const claimed = await ScanResult.findOneAndUpdate(
    { analysisId, fastScansStartedAt: null },
    { $set: { fastScansStartedAt: new Date() } },
    { new: false }
  );
  if (!claimed) return { started: false, reason: 'already-started' };

  console.log(`[ZAP-AUTH][${analysisId}] Starting fast scanners`);

  try {
    const hostname = new URL(claimed.target).hostname;

    // The three synchronous scanners. Individually caught: one failing must not
    // deny the other two, and the completion service only needs PageSpeed OR
    // Observatory to produce a real report.
    const [psiSettled, obsSettled, urlSettled] = await Promise.allSettled([
      claimed.pagespeedResult ? Promise.resolve(null) : getPageSpeedReport(claimed.target),
      claimed.observatoryResult ? Promise.resolve(null) : scanHost(hostname),
      claimed.urlscanResult    ? Promise.resolve(null) : runUrlScan(claimed.target)
    ]);

    const val = (r) => (r.status === 'fulfilled' ? r.value : { error: r.reason?.message });
    const updateFields = {};
    if (!claimed.pagespeedResult)  { updateFields.pagespeedResult  = val(psiSettled); console.log('[ZAP-AUTH] PageSpeed completed'); }
    if (!claimed.observatoryResult){ updateFields.observatoryResult = val(obsSettled); console.log('[ZAP-AUTH] Observatory completed'); }
    if (!claimed.urlscanResult)    { updateFields.urlscanResult     = val(urlSettled); console.log('[ZAP-AUTH] URLScan completed'); }

    // Persist BEFORE WebCheck starts. This write is what closes the race: by the
    // time WebCheck can complete and trigger the completion service, the fast-scan
    // results are already durable.
    if (Object.keys(updateFields).length > 0) {
      updateFields.updatedAt = new Date();
      await ScanResult.updateOne({ analysisId }, { $set: updateFields });
    }

    // Now WebCheck, in the background.
    const webCheckNotStarted = !claimed.webCheckResult
      || (!claimed.webCheckResult.status && !claimed.webCheckResult.error);
    if (webCheckNotStarted) {
      const webCheckInit = await startAsyncWebCheckScan(claimed.target, analysisId, userId)
        .catch(e => ({ status: 'failed', error: e.message }));
      await ScanResult.updateOne(
        { analysisId },
        { $set: { webCheckResult: webCheckInit, updatedAt: new Date() } }
      );
      console.log('[ZAP-AUTH] WebCheck started in background');
    }

    // The ZAP leg may already have finished while these were running — in which case
    // nothing else would re-trigger completion, and the scan would sit in 'combining'
    // until cleanupJob's 5-minute rescue. checkAndGenerateGemini is idempotent and
    // lock-protected, and returns immediately when the scan is not ready.
    const { checkAndGenerateGemini } = require('../services/geminiCompletionService');
    checkAndGenerateGemini(analysisId, String(userId)).catch(e =>
      console.error(`[ZAP-AUTH][${analysisId}] checkAndGenerateGemini error (post fast-scan):`, e.message)
    );

    return { started: true };
  } catch (err) {
    // Release the claim so a later poll or retry can try again — otherwise a single
    // transient failure (e.g. a bad hostname parse) would permanently prevent the
    // fast scanners from ever running for this scan.
    console.error(`[ZAP-AUTH][${analysisId}] Fast scan orchestration error:`, err.message);
    await ScanResult.updateOne({ analysisId }, { $set: { fastScansStartedAt: null } })
      .catch(e => console.error(`[ZAP-AUTH][${analysisId}] failed to release fast-scan claim:`, e.message));
    return { started: false, reason: 'error' };
  }
}

module.exports = { ensureAuthFastScans };
