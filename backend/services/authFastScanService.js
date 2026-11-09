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
const { runLighthouseAudit } = require('./inHouse/lighthouseAudit');
const { runPageCapture } = require('./inHouse/pageCapture');
const credentialVault = require('./scanCredentialVault');

/**
 * Run an in-house page check with the scan's Basic credential, scoped to the
 * target origin. Without the credential (process restart, cancelled scan) the
 * check is reported unavailable — never run unauthenticated and presented as the
 * protected page.
 */
async function basicAuthInHouse(scanId, run, signal) {
  const cred = credentialVault.get(scanId);
  if (!cred) return { error: 'credentials_unavailable' };
  const result = await run({ origin: cred.origin, username: cred.username, password: cred.password }, signal);
  if (result && typeof result === 'object') {
    result.diagnosticSource = 'in-house';
    result.fallbackReason = 'basic_auth';
  }
  return result;
}

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
// A scan in any of these states must not start (or continue) its fast scanners.
const TERMINAL_SCAN_STATES = ['stopped', 'cancelled', 'failed', 'completed'];

// analysisId → AbortController for the fast scanners running in this process. A stop
// aborts it: the in-house browser checks (which hold the single Chromium slot every
// scan queues on) end at once, and nothing further is written or started.
const fastScanControllers = new Map();

/**
 * Halt a scan's fast scanners. Called by the authenticated stop path.
 * @returns {boolean} whether anything was running here
 */
function stopAuthFastScans(analysisId) {
  const controller = fastScanControllers.get(analysisId);
  if (!controller) return false;
  controller.abort();
  fastScanControllers.delete(analysisId);
  return true;
}

async function ensureAuthFastScans(analysisId, userId) {
  // `fastScansStartedAt: null` also matches documents where the field is absent, so
  // scans created before this field existed are claimable too. A stopped scan is not
  // claimable: the accept-time kick-off can run after a very quick stop.
  const claimed = await ScanResult.findOneAndUpdate(
    { analysisId, fastScansStartedAt: null, status: { $nin: TERMINAL_SCAN_STATES } },
    { $set: { fastScansStartedAt: new Date() } },
    { new: false }
  );
  if (!claimed) return { started: false, reason: 'already-started' };

  console.log(`[ZAP-AUTH][${analysisId}] Starting fast scanners`);

  const controller = new AbortController();
  fastScanControllers.set(analysisId, controller);
  const { signal } = controller;

  try {
    const hostname = new URL(claimed.target).hostname;
    const isBasic = claimed.authScanResult && claimed.authScanResult.authMethod === 'basic';

    // The three synchronous scanners. Individually caught: one failing must not
    // deny the other two, and the completion service only needs PageSpeed OR
    // Observatory to produce a real report.
    //
    // HTTP Basic scans: the performance audit and the page capture run in-house,
    // in a browser that answers Basic challenges for the target origin only — the
    // credential is never given to a third-party service. The header grade
    // (Observatory) and the site checks (WebCheck) stay unauthenticated and
    // assess the public 401 response; the report says so.
    const [psiSettled, obsSettled, urlSettled] = await Promise.allSettled([
      claimed.pagespeedResult ? Promise.resolve(null)
        : isBasic ? basicAuthInHouse(analysisId, (basicAuth, sig) => runLighthouseAudit(claimed.target, { strategy: 'desktop', basicAuth, signal: sig }), signal)
          : getPageSpeedReport(claimed.target),
      claimed.observatoryResult ? Promise.resolve(null) : scanHost(hostname),
      claimed.urlscanResult    ? Promise.resolve(null)
        : isBasic ? basicAuthInHouse(analysisId, (basicAuth, sig) => runPageCapture(claimed.target, undefined, { basicAuth, signal: sig }), signal)
          : runUrlScan(claimed.target)
    ]);
    // The page checks are the fast scanners' only use of the credential.
    if (isBasic) credentialVault.release(analysisId, 'fast');

    // Stopped while they ran: write nothing, start nothing.
    if (signal.aborted) {
      console.log(`[ZAP-AUTH][${analysisId}] Fast scanners halted — scan was stopped`);
      return { started: false, reason: 'stopped' };
    }

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
    // startAsyncWebCheckScan also refuses a stopped scan; checking here saves the read.
    if (webCheckNotStarted && !signal.aborted) {
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
  } finally {
    if (fastScanControllers.get(analysisId) === controller) fastScanControllers.delete(analysisId);
  }
}

module.exports = { ensureAuthFastScans, stopAuthFastScans };
