/**
 * ZAP Authenticated Scanning API Routes
 * Handles login detection, credential testing, and authenticated ZAP scans.
 *
 * Base path: /api/zap-auth
 */
//zapAuthRoutes.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck');
const { claimScanSlot } = require('../services/planService');
const { v4: uuidv4 } = require('uuid');
const { detectLoginFields } = require('../services/loginDetectionService');
const { testLogin } = require('../services/loginTestService');
const {
  checkZapAuthHealth,
  startAsyncAuthScan,
  getAuthScanStatus,
  stopAuthScan
} = require('../services/zapAuthService');
const { requestContainer, releaseContainer } = require('../services/zapContainerManager');
const ScanResult = require('../models/ScanResult');
const { checkScanTarget } = require('../utils/scanTargetGuard');
const gridfsService = require('../services/gridfsService');

// The four fast scanners are no longer started from this file — that moved to
// services/authFastScanService.js. Only the WebCheck result reader is still needed
// here, to render a stored report.
const { getFullResults } = require('../services/webCheckService');
const User = require('../models/User');
const { getSanitizedAlerts, getSanitizedZapData } = require('../utils/vulnFilter');
const { lighthouseScores } = require('../utils/scoreFormat');
const { scanLimiter, loginSetupLimiter } = require('../middleware/rateLimiter');

/** Resolve plan-based vulnerability access level; defaults to most restrictive. */
async function resolveVulnAccessLevel(userId) {
  try {
    const u = await User.findById(userId).select('planType billingCycle accountType proExpiresAt organizationId');
    if (!u) return 'critical-high';
    let org = null;
    if (u.organizationId) {
      const Organization = require('../models/Organization');
      org = await Organization.findById(u.organizationId);
    }
    return u.getAccountLimits(org).vulnerabilityAccessLevel || 'critical-high';
  } catch (_) { /* non-fatal */ }
  return 'critical-high';
}

// ============================================================================
// IN-MEMORY AUTH SESSION STORE
// Stores session cookies from successful login tests, keyed by tempSessionId.
// Cookies are NEVER sent to the frontend — only the tempSessionId is returned.
// ============================================================================

const authSessions = new Map();

// Cleanup expired sessions every 5 minutes
const sessionCleanupTimer = setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, session] of authSessions) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) { // 24 hour TTL
      authSessions.delete(key);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`[ZAP-AUTH] Cleaned up ${cleaned} expired auth sessions`);
  }
}, 5 * 60 * 1000);

// A housekeeping timer must not be a reason for the process to stay alive. Without
// this, merely requiring this module keeps the event loop busy forever, which hangs
// `node --test` after the suite finishes. No effect on the server, where the HTTP
// listener holds the loop open anyway.
if (typeof sessionCleanupTimer?.unref === 'function') sessionCleanupTimer.unref();

// ============================================================================
// ROUTES
// ============================================================================

/**
 * The fast-scanner orchestration moved to services/authFastScanService.js so the
 * scheduler can run it too — a scheduled authenticated scan has no browser polling
 * GET /status/:scanId, and previously never ran these four scanners at all.
 *
 * Still re-exported from this module at the bottom of the file: that is the surface
 * backend/tests/authFastScanRace.test.js drives, i.e. the proof that the fast
 * scanners can be started without an HTTP poll.
 */
const { ensureAuthFastScans } = require('../services/authFastScanService');

/**
 * GET /api/zap-auth/health
 * Check if the zap-auth container is running and responsive.
 */
router.get('/health', async (req, res) => {
  try {
    const health = await checkZapAuthHealth();
    res.json(health);
  } catch (error) {
    res.status(503).json({ healthy: false, error: error.message });
  }
});

/**
 * POST /api/zap-auth/detect-login-fields
 * Detect login form fields on a given URL using Puppeteer.
 *
 * Body: { loginUrl: string }
 * Returns: { success, forms[], pageTitle, hasCaptcha, hasOAuth, warnings[] }
 */
router.post('/detect-login-fields', auth, loginSetupLimiter, async (req, res) => {
  try {
    const { loginUrl } = req.body;

    if (!loginUrl) {
      return res.status(400).json({ error: 'loginUrl is required' });
    }

    // A headless browser fetches whatever this points at, server-side.
    const guard = checkScanTarget(loginUrl);
    if (!guard.ok) {
      return res.status(400).json({ error: 'Invalid or refused URL', code: guard.code });
    }

    console.log(`[ZAP-AUTH] Detecting login fields for: ${loginUrl}`);
    const result = await detectLoginFields(loginUrl);
    res.json(result);
  } catch (error) {
    console.error('[ZAP-AUTH] Login detection error:', error.message);
    res.status(500).json({ error: 'Failed to detect login fields', details: error.message });
  }
});

/**
 * POST /api/zap-auth/test-login
 * Test credentials against a login form.
 * On success, stores session cookies server-side and returns a tempSessionId.
 *
 * Body: { loginUrl, username, password, usernameField, passwordField, submitButton? }
 * Returns: { success, authenticated, evidence, tempSessionId?, errorMessage? }
 */
router.post('/test-login', auth, loginSetupLimiter, async (req, res) => {
  try {
    const { loginUrl, credentials, submitButton, submitAlternates, expectedMarker } = req.body;

    if (!loginUrl || !credentials || !Array.isArray(credentials) || credentials.length === 0) {
      return res.status(400).json({ error: 'loginUrl and credentials array are required' });
    }

    // Validate that each credential has selector and value
    for (const cred of credentials) {
      if (!cred.selector || !cred.value) {
        return res.status(400).json({ error: 'Each credential must have selector and value' });
      }
    }

    const guard = checkScanTarget(loginUrl);
    if (!guard.ok) {
      return res.status(400).json({ error: 'Invalid or refused loginUrl', code: guard.code });
    }

    console.log(`[ZAP-AUTH] Testing login for: ${loginUrl} with ${credentials.length} credential fields`);

    const result = await testLogin({
      loginUrl,
      credentials,
      submitButton: submitButton || null,
      submitAlternates: submitAlternates || [],
      expectedMarker: expectedMarker || null
    });

    if (result.authenticated && result.cookies && result.cookies.length > 0) {
      // Store cookies server-side with a temporary session ID
      const tempSessionId = uuidv4();
      authSessions.set(tempSessionId, {
        cookies: result.cookies,
        loginUrl,
        // The signed-in marker lets the scan check later whether it is still
        // logged in, and the recipe lets it log back in if it is not. Both live
        // in memory for the life of the scan and are never written to disk.
        marker: result.marker,
        markerCheckableInBody: result.markerCheckableInBody,
        markerConfidence: result.markerConfidence || 'low',
        // The verdict, not the mere presence of a marker: a weak marker is
        // returned for change-detection but does not prove the sign-in.
        authConfirmed: result.authConfirmed,
        recipe: {
          loginUrl,
          credentials,
          submitButton: submitButton || null,
          submitAlternates: submitAlternates || []
        },
        createdAt: Date.now()
      });

      console.log(
        `[ZAP-AUTH] Login ${result.authConfirmed}. Session stored: ${tempSessionId} ` +
        `(marker=${result.marker ? 'yes' : 'no'}, strategy=${result.submitStrategy})`
      );

      // Return result WITHOUT cookies or the marker — only the tempSessionId.
      // The marker is text from the customer's own page and has no business
      // making a round trip through the browser.
      res.json({
        success: true,
        authenticated: true,
        authConfirmed: result.authConfirmed,
        postLoginUrl: result.postLoginUrl,
        evidence: result.evidence,
        cookieCount: result.cookies.length,
        // Tells the UI whether to offer the optional "what shows when you are
        // signed in?" field, without explaining why.
        markerFound: Boolean(result.marker),
        errorCode: result.errorCode,
        tempSessionId
      });
    } else {
      // Cannot proceed — there is no session for the scan to carry.
      //
      // This branch is also reached when the login itself worked but the site
      // issued no cookies at all, which happens on apps that keep their session
      // entirely in the browser. Reporting that as "confirmed" would show a
      // green tick on a flow that then refuses to advance, so the outcome here
      // is always a failure; only the reason differs.
      const loggedInButNoCookies =
        result.authenticated && (!result.cookies || result.cookies.length === 0);

      res.json({
        success: true,
        authenticated: false,
        authConfirmed: 'failed',
        postLoginUrl: result.postLoginUrl,
        evidence: result.evidence,
        markerFound: false,
        errorCode: loggedInButNoCookies
          ? 'NO_SESSION_COOKIES'
          : (result.errorCode || 'LOGIN_ANALYSIS_FAILED'),
        errorMessage: result.errorMessage
      });
    }
  } catch (error) {
    console.error('[ZAP-AUTH] Login test error:', error.message);
    res.status(500).json({ error: 'Failed to test login', details: error.message });
  }
});

/**
 * POST /api/zap-auth/scan
 * Start an authenticated ZAP scan.
 * Retrieves session cookies from the in-memory store using tempSessionId.
 *
 * Body: { targetUrl, loginUrl, tempSessionId }
 * Returns: { success, scanId, message }
 */
// Strict limiter is per-route: this starts a scan, while /status/:scanId below is
// polled every few seconds by the browser and must not share the same budget.
router.post('/scan', auth, planCheck, scanLimiter, async (req, res) => {
  try {
    // `triggerSource` is deliberately NOT read from the body. It steers
    // notification behaviour and the active-scan query, and a caller could
    // label their own manual scan 'scheduled'. This route is, by definition,
    // a manual start.
    const { targetUrl, loginUrl, tempSessionId, lang } = req.body;
    const triggerSource = 'manual';

    if (!targetUrl || !tempSessionId) {

      return res.status(400).json({ error: 'targetUrl and tempSessionId are required' });
    }

    const targetGuard = checkScanTarget(targetUrl);
    if (!targetGuard.ok) {
      return res.status(400).json({ error: 'Invalid or refused targetUrl', code: targetGuard.code });
    }

    // loginUrl was never validated here, yet ZAP fetches it server-side with the
    // injected session cookies — a second, unguarded door to the same place.
    if (loginUrl) {
      const loginGuard = checkScanTarget(loginUrl);
      if (!loginGuard.ok) {
        return res.status(400).json({ error: 'Invalid or refused loginUrl', code: loginGuard.code });
      }
    }

    // Retrieve stored session cookies
    const session = authSessions.get(tempSessionId);
    if (!session) {

      return res.status(400).json({
        error: 'Session expired or invalid. Please test login again.',
        code: 'SESSION_EXPIRED'
      });
    }

    const cookies = session.cookies;
    const resolvedLoginUrl = loginUrl || session.loginUrl;

    // Captured before the session entry is deleted below. Held only in this
    // request's closure for the duration of the scan — never persisted, and
    // never sent to the browser.
    const authState = {
      marker: session.marker || null,
      markerCheckableInBody: Boolean(session.markerCheckableInBody),
      markerConfidence: session.markerConfidence || 'low',
      recipe: session.recipe || null,
      authConfirmed: session.authConfirmed || 'unconfirmed',
      reloginAttempts: 0
    };

    // Generate scan ID
    const scanId = `zap-auth-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    console.log(`[ZAP-AUTH] Starting authenticated scan: ${scanId} for ${targetUrl} (Source: ${triggerSource || 'manual'})`);

    // Create skeleton record so polling shows "queued" during provisioning.
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $setOnInsert: {
          target: targetUrl,
          analysisId: scanId,
          status: 'queued',
          userId: req.user.id,
          organizationId: req.organization?._id || null,
          triggerSource: triggerSource || 'manual',
          languagePreference: lang || 'en',
          authScanResult: {
            status: 'provisioning',
            phase: 'provisioning',
            progress: 0,
            // Whether the login itself could be confirmed. The scan re-checks
            // as it runs; this is the starting point the report falls back to
            // when in-scan verification cannot apply (a single-page app serves
            // the same HTML signed in or out, so a response body proves
            // nothing either way).
            loginOutcome: authState.authConfirmed === 'confirmed' ? 'confirmed' : 'unconfirmed'
          },
          createdAt: new Date(),
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );
    console.log(`[Billing] Scan started: ${scanId}`);

    // planCheck is advisory — it reserves nothing, so concurrent starts can all pass
    // it. Authoritative check, run after the record exists because its _id is what
    // orders concurrent starters. See planService.claimScanSlot.
    if (req.organization && !(await claimScanSlot(req.organization._id, scanId))) {
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: { status: 'cancelled', updatedAt: new Date() } }
      );
      return res.status(403).json({
        success: false,
        code: 'PLAN_LIMIT_EXCEEDED',
        error: 'PLAN_LIMIT_EXCEEDED',
        message: 'Scan limit reached or subscription inactive. Please upgrade your plan.',
        limitType: 'concurrent_scans_exceed_remaining_quota'
      });
    }

    // Delete session after use (one-time use)
    authSessions.delete(tempSessionId);

    // Warm ZAP capacity up before responding, so the scale-from-zero overlaps the
    // client's first poll rather than being added to the scan. Not awaited and never
    // fatal — withZapInstance below performs the authoritative wait under the lock.
    // No-ops unless capacity management is enabled for 'auth'.
    {
      const { markZapDemand, ensureZapCapacity } = require('../services/zapCapacityManager');
      markZapDemand('auth').catch(() => {});
      ensureZapCapacity('auth', { scanId }).catch(err =>
        console.warn(`[ZapCapacity] warm-up failed for ${scanId}: ${err.message}`)
      );
    }

    // Respond immediately — provisioning + scan run in background.
    res.json({ success: true, scanId, message: 'Authenticated scan started' });

    // Start the fast scanners now, at acceptance. They used to be kicked off lazily
    // from GET /status/:scanId, which made them dependent on a browser polling: in
    // production the ZAP leg once finished 14 minutes before anything started them.
    // Starting here also means they overlap the ZAP scan instead of following it.
    //
    // Not awaited (the response is already sent) and never fatal — the ZAP leg is the
    // product, and ensureAuthFastScans claims atomically so the status-poll fallback
    // cannot start a second copy.
    ensureAuthFastScans(scanId, String(req.user.id)).catch(e =>
      console.error(`[ZAP-AUTH][${scanId}] fast-scan kick-off failed:`, e.message)
    );

    // Async: provision container → scan → release
    (async () => {
      let zapUrl;
      try {
        const container = await requestContainer(scanId, 'auth');
        zapUrl = container.zapUrl;
      } catch (err) {
        console.error(`[ZAP-AUTH] Container provisioning failed for scan ${scanId}:`, err.message);
        await ScanResult.updateOne(
          { analysisId: scanId },
          { $set: { status: 'failed', 'authScanResult.status': 'failed', 'authScanResult.error': 'Container provisioning failed', updatedAt: new Date() } }
        );
        return;
      }

      try {
        const { withZapInstance } = require('../services/zapRecycler');
        // startAsyncAuthScan is internally fire-and-forget, so releasing the lock when it
        // returns would release it seconds after acquiring. Bridge through the onComplete
        // callback instead — it fires from the background scan's .finally(), i.e. on true
        // completion. The 'already_running' early return never fires onComplete, so it is
        // resolved explicitly; without that the lock would sit until its TTL expires.
        await withZapInstance('auth', scanId, () => new Promise((resolve) => {
          startAsyncAuthScan(
            targetUrl,
            resolvedLoginUrl,
            cookies,
            scanId,
            req.user.id,
            zapUrl,
            (id) => { releaseContainer(id); resolve(); },
            authState
          )
            .then((r) => { if (r?.status === 'already_running') resolve(); })
            .catch((err) => {
              console.error(`[ZAP-AUTH] startAsyncAuthScan failed for ${scanId}:`, err.message);
              resolve();
            });
        }));
      } catch (err) {
        console.error(`[ZAP-AUTH] Pre-scan recycle failed for ${scanId}:`, err.message);
        await ScanResult.updateOne(
          { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
          {
            $set: {
              status: 'failed',
              'authScanResult.status': 'failed',
              'authScanResult.phase': 'failed',
              'authScanResult.error': err.message,
              'authScanResult.errorCode': err.name === 'ZapRecycleError' ? 'zap_recycle_failed' : 'zap_scan_failed',
              'authScanResult.failedAt': new Date(),
              failureReason: 'vulnerability_scan_failed',
              updatedAt: new Date()
            }
          }
        ).catch(e => console.error('[ZAP-AUTH] Failed to record scan failure:', e.message));
        await releaseContainer(scanId);
      }
    })();
  } catch (error) {
    console.error('[ZAP-AUTH] Scan start error:', error.message);
    // Synchronous start failed before the scan was handed off — refund the slot.

    res.status(500).json({ error: 'Failed to start authenticated scan', details: error.message });
  }
});

/**
 * GET /api/zap-auth/status/:scanId
 * Get the status and progress of an authenticated scan.
 * Orchestrates ALL scanners (PageSpeed, Observatory, URLScan, WebCheck, Gemini)
 * alongside the authenticated ZAP scan, matching the normal combined-analysis flow.
 */
router.get('/status/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;

    let scan = await ScanResult.findOne({ analysisId: scanId, userId: req.user.id });
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found or access denied' });
    }

    // --- EARLY EXIT: If scan is in a terminal state, don't trigger anything ---
    if (['stopped', 'completed', 'failed'].includes(scan.status)) {
      console.log(`🛑 Auth Scan ${scanId} is in terminal state (${scan.status}), returning early.`);
      return res.json({
        success: true,
        status: scan.status,
        analysisId: scanId,
        target: scan.target,
        // Minimal data for summary view
        hasPsiResult: !!scan.pagespeedResult,
        hasObservatoryResult: !!scan.observatoryResult,
        zapPending: false,
        webCheckPending: false,
        hasRefinedReport: !!scan.refinedReport,
        refinedReport: scan.refinedReport || null,
        createdAt: scan.createdAt,
        updatedAt: scan.updatedAt
      });
    }

    // ── STEP A: Fast scans ──
    // These are started at scan acceptance now (POST /scan). This call is a
    // fallback for scans accepted before that change shipped, and a self-heal if
    // the accept-time kick-off ever fails. ensureAuthFastScans claims atomically,
    // so calling it from every poll starts nothing twice.
    //
    // Deliberately NOT awaited. It used to be, which made a status poll block for
    // as long as the slowest scanner (urlscan polls its own API, ~20s).
    ensureAuthFastScans(scanId, String(req.user.id)).catch(e =>
      console.error(`[ZAP-AUTH][${scanId}] fast-scan orchestration error:`, e.message)
    );

    // ── Re-fetch scan to get latest auth ZAP + WebCheck progress ──
    scan = await ScanResult.findOne({ analysisId: scanId, userId: req.user.id });

    // ── Stale scan watchdog: mark stuck background scans as failed ──
    const AUTH_ZAP_STALE_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 24 hours
    const WEBCHECK_STALE_TIMEOUT_MS = 6 * 60 * 60 * 1000; // 6 hours
    const now = Date.now();

    if (scan.authScanResult?.startedAt && !['completed', 'failed'].includes(scan.authScanResult.status)) {
      const authZapAge = now - new Date(scan.authScanResult.startedAt).getTime();
      if (authZapAge > AUTH_ZAP_STALE_TIMEOUT_MS) {
        console.error(`[ZAP-AUTH] ❌ Auth ZAP scan timed out (${Math.round(authZapAge / 60000)}min). Failing entire scan.`);
        await ScanResult.updateOne(
          { analysisId: scanId },
          { $set: { 'authScanResult.status': 'failed', 'authScanResult.error': 'Scan timed out (exceeded 24 hour limit)', status: 'failed', updatedAt: new Date() } }
        );
        scan.authScanResult.status = 'failed';
        scan.status = 'failed';
      }
    }

    if (scan.webCheckResult?.startedAt && !['completed', 'completed_partial', 'completed_with_errors', 'failed'].includes(scan.webCheckResult.status)) {
      const wcAge = now - new Date(scan.webCheckResult.startedAt).getTime();
      if (wcAge > WEBCHECK_STALE_TIMEOUT_MS) {
        console.error(`[ZAP-AUTH] ❌ WebCheck scan timed out (${Math.round(wcAge / 60000)}min). Failing entire scan.`);
        await ScanResult.updateOne(
          { analysisId: scanId },
          { $set: { 'webCheckResult.status': 'failed', 'webCheckResult.error': 'Scan timed out (exceeded 6 hour limit)', status: 'failed', updatedAt: new Date() } }
        );
        scan.webCheckResult.status = 'failed';
        scan.status = 'failed';
      }
    }

    // If entire scan was failed by watchdog, return immediately
    if (scan.status === 'failed') {
      return res.json({
        status: 'failed',
        failureReason: scan.failureReason || 'internal_error',
        target: scan.target,
        analysisId: scanId
      });
    }

    // ── STEP C: Check if auth ZAP + WebCheck are done → generate Gemini report ──
    const authZapStatus = scan.authScanResult?.status;
    const authZapDone = authZapStatus === 'completed' || authZapStatus === 'failed';

    const webCheckStatus = scan.webCheckResult?.status;
    const webCheckDone = webCheckStatus === 'completed' || webCheckStatus === 'completed_partial' ||
      webCheckStatus === 'completed_with_errors' || webCheckStatus === 'failed';

    // Only the vulnerability assessment is fatal — it is the product. Without it
    // the report would read "No vulnerabilities detected" for a site that was
    // never assessed. This mirrors geminiCompletionService for the normal scan
    // flow, which CLAUDE.md requires to stay in parity.
    //
    // A failed WebCheck is NOT fatal: its report section renders N/A. Nothing is
    // billed at this point either way — quota is charged only when
    // geminiCompletionService reaches a completed report.
    if (authZapStatus === 'failed' && !scan.refinedReport) {
      console.error(`[ZAP-AUTH] ❌ Vulnerability scan failed: ${scan.authScanResult?.error || 'unknown error'}. Failing entire scan.`);
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: { status: 'failed', failureReason: 'vulnerability_scan_failed', updatedAt: new Date() } }
      );
      scan.status = 'failed';
      // Structured reason only — the raw scanner error names the engine and is
      // English-only, so it stays in the server log.
      return res.json({
        status: 'failed',
        failureReason: 'vulnerability_scan_failed',
        target: scan.target,
        analysisId: scanId
      });
    }

    if (webCheckStatus === 'failed') {
      console.warn(`[ZAP-AUTH] WebCheck failed for ${scanId} (non-fatal): ${scan.webCheckResult?.error || 'unknown error'}`);
    }

    // Copy authScanResult to zapResult so existing download/history endpoints work
    if (authZapDone && !scan.zapResult) {
      const zapResultCopy = scan.authScanResult ? { ...scan.authScanResult } : null;
      if (zapResultCopy) {
        await ScanResult.updateOne({ analysisId: scanId }, { $set: { zapResult: zapResultCopy } });
        scan.zapResult = zapResultCopy;
        console.log('[ZAP-AUTH] Copied authScanResult to zapResult for compatibility');
      }
    }

    // Hand completion to geminiCompletionService — the SINGLE place that finishes a
    // scan and charges its quota, for both the normal and the authenticated flow.
    //
    // This route used to generate the report inline. That duplicated ~80 lines of
    // geminiCompletionService, and — because it wrote `refinedReport` + `completed`
    // without calling finalizeSuccessfulScan — whichever path won the race decided
    // whether the customer was billed at all. Authenticated scans finished here were
    // delivered free.
    //
    // Fire-and-forget: generation can take minutes, and a status poll must return
    // immediately. The client polls every 3s and picks the report up on a later tick.
    if (authZapDone && webCheckDone && !scan.refinedReport) {
      setImmediate(() => {
        try {
          const { checkAndGenerateGemini } = require('../services/geminiCompletionService');
          checkAndGenerateGemini(scanId, String(req.user.id)).catch(e =>
            console.error(`[ZAP-AUTH][${scanId}] checkAndGenerateGemini error (status poll):`, e.message)
          );
        } catch (e) {
          console.error(`[ZAP-AUTH][${scanId}] Failed to load geminiCompletionService:`, e.message);
        }
      });
    }

    // ── STEP D: Build response with all scan data (progressive loading) ──
    // null per category when PageSpeed didn't return it; a genuine 0 is preserved.
    const psiScores = scan.pagespeedResult && !scan.pagespeedResult.error
      ? lighthouseScores(scan.pagespeedResult)
      : null;

    const observatoryData = scan.observatoryResult && !scan.observatoryResult.error ? {
      grade: scan.observatoryResult.grade,
      score: scan.observatoryResult.score,
      tests_passed: scan.observatoryResult.tests_passed,
      tests_failed: scan.observatoryResult.tests_failed,
      tests_quantity: scan.observatoryResult.tests_quantity
    } : null;

    // Auth ZAP data (mapped to same format as normal zapData) — plan-filtered
    const statusAccessLevel = await resolveVulnAccessLevel(req.user.id);
    let zapData = null;
    if (scan.authScanResult) {
      const s = scan.authScanResult.status;
      if (s === 'completed') {
        const rawZapData = {
          status: 'completed',
          riskCounts: scan.authScanResult.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 },
          alerts: scan.authScanResult.alerts || [],
          totalAlerts: scan.authScanResult.totalAlerts || 0,
          totalOccurrences: scan.authScanResult.totalOccurrences || 0,
          reportFiles: scan.authScanResult.reportFiles || [],
          site: scan.target
        };
        zapData = getSanitizedZapData(rawZapData, statusAccessLevel);
      } else if (s === 'running' || s === 'pending') {
        zapData = {
          status: s,
          phase: scan.authScanResult.phase || 'queued',
          progress: scan.authScanResult.progress || 0,
          message: scan.authScanResult.message || 'Authenticated ZAP scan in progress...',
          urlsFound: scan.authScanResult.urlsFound || 0,
          alertsFound: scan.authScanResult.alertsFound || 0
        };
      } else if (s === 'failed') {
        zapData = {
          status: 'failed',
          error: scan.authScanResult.error || 'Authenticated ZAP scan failed'
        };
      }
    }

    const urlscanData = scan.urlscanResult && !scan.urlscanResult.error ? {
      uuid: scan.urlscanResult.uuid,
      verdicts: scan.urlscanResult.verdicts,
      page: scan.urlscanResult.page,
      stats: scan.urlscanResult.stats,
      screenshot: scan.urlscanResult.screenshot,
      reportUrl: scan.urlscanResult.reportUrl
    } : null;

    // WebCheck data
    let webCheckData = null;
    if (scan.webCheckResult) {
      const wcs = scan.webCheckResult.status;
      if (wcs === 'completed' || wcs === 'completed_with_errors' || wcs === 'completed_partial') {
        let webCheckResults = scan.webCheckResult.fullResults;
        if (!webCheckResults && scan.webCheckResult.resultsFileId) {
          try { webCheckResults = await getFullResults(scan.webCheckResult); } catch (e) { /* ignore */ }
        }
        if (!webCheckResults) webCheckResults = scan.webCheckResult.summary || {};
        webCheckData = {
          status: wcs,
          results: webCheckResults,
          summary: scan.webCheckResult.summary || {},
          completedScans: scan.webCheckResult.completedScans || 0,
          totalScans: scan.webCheckResult.totalScans || 30,
          hasErrors: scan.webCheckResult.hasErrors || false,
          duration: scan.webCheckResult.duration || 0
        };
      } else if (wcs === 'uploading') {
        webCheckData = {
          status: 'uploading',
          progress: 100,
          uploadProgress: scan.webCheckResult.uploadProgress || 0,
          completedScans: scan.webCheckResult.completedScans || scan.webCheckResult.totalScans,
          totalScans: scan.webCheckResult.totalScans || 30,
          message: scan.webCheckResult.message || 'Uploading results...'
        };
      } else if (wcs === 'running' || wcs === 'pending') {
        webCheckData = {
          status: 'running',
          progress: scan.webCheckResult.progress || 0,
          completedScans: scan.webCheckResult.completedScans || 0,
          totalScans: scan.webCheckResult.totalScans || 30,
          message: scan.webCheckResult.message || 'WebCheck scans in progress...',
          partialResults: scan.webCheckResult.partialResults || {}
        };
      } else if (wcs === 'failed') {
        webCheckData = {
          status: 'failed',
          error: scan.webCheckResult.error || 'WebCheck scan failed'
        };
      }
    }

    // Determine overall status
    const overallStatus = scan.refinedReport ? 'completed'
      : (authZapDone ? 'combining' : 'running');

    // Auth ZAP phase/progress for the scanning UI
    const phase = scan.authScanResult?.phase || '';
    const progress = scan.authScanResult?.progress || 0;

    // One structured field the report can turn into a sentence. Deliberately
    // not derived in the browser from `authScanResult`, which carries English
    // operator strings that must never be rendered.
    const authVerified = scan.authScanResult?.authVerified;
    const authCoverage =
      authVerified === true ||
      (authVerified !== false &&
        !scan.authScanResult?.authDegraded &&
        scan.authScanResult?.loginOutcome === 'confirmed')
        ? 'confirmed'
        : 'unconfirmed';

    return res.json({
      success: true,
      scanId: scan.analysisId,
      target: scan.target,
      status: overallStatus,
      // Auth ZAP progress (for step 4 scanning UI)
      phase,
      progress,
      authCoverage,
      message: scan.authScanResult?.message || '',
      // Partial data indicators (same as combined-analysis)
      hasPsiResult: !!scan.pagespeedResult && !scan.pagespeedResult.error,
      hasObservatoryResult: !!scan.observatoryResult && !scan.observatoryResult.error,
      hasZapResult: zapData?.status === 'completed',
      zapPending: zapData?.status === 'running' || zapData?.status === 'pending',
      hasUrlscanResult: !!scan.urlscanResult && !scan.urlscanResult.error,
      hasWebCheckResult: webCheckData?.status === 'completed' || webCheckData?.status === 'completed_partial' || webCheckData?.status === 'completed_with_errors',
      webCheckPending: webCheckData?.status === 'running',
      hasRefinedReport: !!scan.refinedReport,
      // Actual data
      psiScores,
      observatoryData,
      zapData,
      urlscanData,
      webCheckData,
      refinedReport: scan.refinedReport || null,
      // Raw results for compatibility
      pagespeedResult: scan.pagespeedResult || null,
      observatoryResult: scan.observatoryResult || null,
      authScanResult: scan.authScanResult || null,
      urlscanResult: scan.urlscanResult || null,
      webCheckResult: scan.webCheckResult || null,
      // For ZapReportEnhanced and results
      analysisId: scan.analysisId,
      summary: zapData?.status === 'completed' ? {
        totalAlerts: zapData.totalAlerts,
        high: zapData.riskCounts?.High || 0,
        medium: zapData.riskCounts?.Medium || 0,
        low: zapData.riskCounts?.Low || 0,
        informational: zapData.riskCounts?.Informational || 0
      } : null,
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt
    });
  } catch (error) {
    console.error('[ZAP-AUTH] Status error:', error.message);
    res.status(500).json({ error: 'Failed to get scan status' });
  }
});

/**
 * POST /api/zap-auth/stop/:scanId
 * Stop a running authenticated scan.
 */
router.post('/stop/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const result = await stopAuthScan(scanId, req.user.id);
    res.json(result);
  } catch (error) {
    if (error.message === 'Scan not found or access denied') {
      return res.status(404).json({ error: error.message });
    }
    console.error('[ZAP-AUTH] Stop error:', error.message);
    res.status(500).json({ error: 'Failed to stop scan' });
  }
});

/**
 * GET /api/zap-auth/scans
 * Get the authenticated scan history for the current user.
 */
router.get('/scans', auth, async (req, res) => {
  try {
    const scans = await ScanResult.find({
      userId: req.user.id,
      authScanResult: { $ne: null }
    })
      .select('analysisId target status authScanResult.status authScanResult.phase authScanResult.progress authScanResult.loginUrl authScanResult.riskCounts authScanResult.totalAlerts authScanResult.completedAt createdAt')
      .sort({ createdAt: -1 })
      .limit(50);

    res.json({ scans });
  } catch (error) {
    console.error('[ZAP-AUTH] Scan history error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve scan history' });
  }
});

/**
 * GET /api/zap-auth/detailed-report/:scanId
 * Download detailed vulnerability JSON report from GridFS.
 */
router.get('/detailed-report/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;

    const scanResult = await ScanResult.findOne({
      analysisId: scanId,
      userId: req.user.id
    });

    if (!scanResult) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (!scanResult.authScanResult || !scanResult.authScanResult.reportFiles) {
      return res.status(404).json({
        error: 'Authenticated scan report not available',
        hint: 'This scan may not have completed yet'
      });
    }

    const detailedFile = scanResult.authScanResult.reportFiles.find(
      f => f.filename.includes('detailed_alerts')
    );

    if (!detailedFile) {
      return res.status(404).json({ error: 'Detailed report not found' });
    }

    // Download raw buffer, apply plan filter, then send filtered JSON
    const accessLevel = await resolveVulnAccessLevel(req.user.id);
    const rawBuf = await gridfsService.downloadFile(detailedFile.fileId, 'zap_auth_reports');
    const rawAlerts = JSON.parse(rawBuf.toString('utf-8'));
    const filteredAlerts = getSanitizedAlerts(rawAlerts, accessLevel);

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${detailedFile.filename}"`);
    res.json(filteredAlerts);
  } catch (error) {
    console.error('[ZAP-AUTH] Download error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to download report' });
    }
  }
});

/**
 * GET /api/zap-auth/detailed-report-pdf/:scanId?lang=en|ja
 * Download bilingual PDF vulnerability report.
 */
router.get('/detailed-report-pdf/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const lang = req.query.lang === 'ja' ? 'ja' : 'en';

    const { generateZapPdf } = require('../services/pdfService');

    const scanResult = await ScanResult.findOne({
      analysisId: scanId,
      userId: req.user.id
    });

    if (!scanResult) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (!scanResult.authScanResult) {
      return res.status(404).json({
        error: 'Authenticated scan report not available',
        hint: 'This scan may not have completed yet'
      });
    }

    // Map authScanResult to zapResult so the PDF generator can read it
    // The PDF generator expects scanResult.zapResult
    const scanResultForPdf = {
      ...scanResult.toObject(),
      zapResult: scanResult.authScanResult
    };

    console.log(`[ZAP-AUTH] Generating PDF (${lang.toUpperCase()}) for scan: ${scanId}`);

    const pdfAccessLevel = await resolveVulnAccessLevel(req.user.id);
    const pdfBuffer = await generateZapPdf(scanResultForPdf, lang, pdfAccessLevel);

    const filename = `zap_auth_vulnerability_report_${scanId}_${lang}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.send(pdfBuffer);

    console.log(`[ZAP-AUTH] PDF (${lang.toUpperCase()}) sent: ${filename}`);
  } catch (error) {
    console.error('[ZAP-AUTH] PDF generation error:', error);
    if (!res.headersSent) {
      if (error?.code === 'GEMINI_KEY_EXHAUSTED') {
        return res.status(429).json({
          errorCode: 'GEMINI_KEY_EXHAUSTED',
          error: 'Gemini key is exhausted'
        });
      }
      if (['EN_CONTENT_NOT_ENGLISH', 'EN_TEMPLATE_NOT_ENGLISH'].includes(error?.code)) {
        return res.status(400).json({
          errorCode: error.code,
          error: error.message
        });
      }
      res.status(500).json({
        error: 'Failed to generate PDF report',
        details: error.message
      });
    }
  }
});

// The router stays the default export — server.js does `app.use(..., require(...))`,
// and an Express router is a function, so attaching a property to it keeps every
// existing mount working unchanged. ensureAuthFastScans is attached so it can be
// driven directly in tests, i.e. proven to work without an HTTP status poll.
module.exports = router;
module.exports.ensureAuthFastScans = ensureAuthFastScans;
