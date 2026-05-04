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
const { v4: uuidv4 } = require('uuid');
const { detectLoginFields } = require('../services/loginDetectionService');
const { testLogin } = require('../services/loginTestService');
const {
  checkZapAuthHealth,
  startAsyncAuthScan,
  getAuthScanStatus,
  stopAuthScan
} = require('../services/zapAuthService');
const ScanResult = require('../models/ScanResult');
const gridfsService = require('../services/gridfsService');
const { handleScanComplete } = require('../services/notificationService');

// Additional scanner services (same as normal scan)
const { getPageSpeedReport } = require('../services/pagespeedService');
const { scanHost } = require('../services/observatoryService');
const { runUrlScan } = require('../services/urlscanService');
const { startAsyncWebCheckScan, getFullResults } = require('../services/webCheckService');
const { refineReport } = require('../services/geminiService');
const User = require('../models/User');
const { getSanitizedAlerts, getSanitizedZapData, getSanitizedZapReport } = require('../utils/vulnFilter');
const { sanitizeScanForLLM } = require('../services/geminiSanitizer');

/** Resolve plan-based vulnerability access level; defaults to most restrictive. */
async function resolveVulnAccessLevel(userId) {
  try {
    const u = await User.findById(userId).select('planType billingCycle accountType proExpiresAt');
    if (u) return u.getAccountLimits().vulnerabilityAccessLevel || 'critical-high';
  } catch (_) { /* non-fatal */ }
  return 'critical-high';
}

// In-memory lock to prevent parallel Gemini AI report calls for the same scan
const geminiInProgress = new Set();

// ============================================================================
// IN-MEMORY AUTH SESSION STORE
// Stores session cookies from successful login tests, keyed by tempSessionId.
// Cookies are NEVER sent to the frontend — only the tempSessionId is returned.
// ============================================================================

const authSessions = new Map();

// Cleanup expired sessions every 5 minutes
setInterval(() => {
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

// ============================================================================
// ROUTES
// ============================================================================

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
router.post('/detect-login-fields', auth, async (req, res) => {
  try {
    const { loginUrl } = req.body;

    if (!loginUrl) {
      return res.status(400).json({ error: 'loginUrl is required' });
    }

    // Validate URL format
    try {
      new URL(loginUrl);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
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
router.post('/test-login', auth, async (req, res) => {
  try {
    const { loginUrl, credentials, submitButton } = req.body;

    if (!loginUrl || !credentials || !Array.isArray(credentials) || credentials.length === 0) {
      return res.status(400).json({ error: 'loginUrl and credentials array are required' });
    }

    // Validate that each credential has selector and value
    for (const cred of credentials) {
      if (!cred.selector || !cred.value) {
        return res.status(400).json({ error: 'Each credential must have selector and value' });
      }
    }

    // Validate URL
    try {
      new URL(loginUrl);
    } catch {
      return res.status(400).json({ error: 'Invalid loginUrl format' });
    }

    console.log(`[ZAP-AUTH] Testing login for: ${loginUrl} with ${credentials.length} credential fields`);

    const result = await testLogin({
      loginUrl,
      credentials,
      submitButton: submitButton || null
    });

    if (result.authenticated && result.cookies && result.cookies.length > 0) {
      // Store cookies server-side with a temporary session ID
      const tempSessionId = uuidv4();
      authSessions.set(tempSessionId, {
        cookies: result.cookies,
        loginUrl,
        createdAt: Date.now()
      });

      console.log(`[ZAP-AUTH] Login successful. Session stored: ${tempSessionId}`);

      // Return result WITHOUT cookies — only the tempSessionId
      res.json({
        success: true,
        authenticated: true,
        postLoginUrl: result.postLoginUrl,
        evidence: result.evidence,
        cookieCount: result.cookies.length,
        tempSessionId
      });
    } else {
      // Login failed — no cookies to store
      res.json({
        success: true,
        authenticated: false,
        postLoginUrl: result.postLoginUrl,
        evidence: result.evidence,
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
router.post('/scan', auth, planCheck, async (req, res) => {
  try {
    const { targetUrl, loginUrl, tempSessionId, triggerSource, lang } = req.body;

    if (!targetUrl || !tempSessionId) {
      return res.status(400).json({ error: 'targetUrl and tempSessionId are required' });
    }

    // Validate target URL
    try {
      const parsed = new URL(targetUrl);
      if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
        return res.status(400).json({ error: 'Cannot scan localhost addresses' });
      }
    } catch {
      return res.status(400).json({ error: 'Invalid targetUrl format' });
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

    // Check ZAP health before starting
    const health = await checkZapAuthHealth();
    if (!health.healthy) {
      return res.status(503).json({
        error: 'ZAP authenticated scanner is not available',
        details: health.error
      });
    }

    // Generate scan ID
    const scanId = `zap-auth-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    console.log(`[ZAP-AUTH] Starting authenticated scan: ${scanId} for ${targetUrl} (Source: ${triggerSource || 'manual'})`);

    // Create a skeleton scan record immediately to store the triggerSource
    const skeletonScan = new ScanResult({
      target: targetUrl,
      analysisId: scanId,
      status: 'pending',
      userId: req.user.id,
      triggerSource: triggerSource || 'manual',
      languagePreference: lang || 'en'
    });
    await skeletonScan.save();

    // Start async auth ZAP scan
    const result = await startAsyncAuthScan(
      targetUrl,
      resolvedLoginUrl,
      cookies,
      scanId,
      req.user.id
    );

    // Delete the session after use (one-time use)
    authSessions.delete(tempSessionId);

    res.json({
      success: true,
      scanId: result.scanId,
      message: result.message
    });
  } catch (error) {
    console.error('[ZAP-AUTH] Scan start error:', error.message);
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

    // ── STEP A: Trigger fast scans (only once) ──
    const needsFastScans = !scan.pagespeedResult || !scan.observatoryResult || !scan.urlscanResult;
    const webCheckNotStarted = !scan.webCheckResult || (!scan.webCheckResult.status && !scan.webCheckResult.error);

    if (needsFastScans || webCheckNotStarted) {
      try {
        const hostname = new URL(scan.target).hostname;
        const scanPromises = [];

        // PageSpeed
        if (!scan.pagespeedResult) {
          scanPromises.push(getPageSpeedReport(scan.target).catch(e => ({ error: e.message })));
        } else {
          scanPromises.push(Promise.resolve(null));
        }

        // Observatory
        if (!scan.observatoryResult) {
          scanPromises.push(scanHost(hostname).catch(e => ({ error: e.message })));
        } else {
          scanPromises.push(Promise.resolve(null));
        }

        // URLScan
        if (!scan.urlscanResult) {
          scanPromises.push(runUrlScan(scan.target).catch(e => ({ error: e.message })));
        } else {
          scanPromises.push(Promise.resolve(null));
        }

        // WebCheck (async background scan)
        if (webCheckNotStarted) {
          scanPromises.push(startAsyncWebCheckScan(scan.target, scan.analysisId, req.user.id).catch(e => ({ status: 'failed', error: e.message })));
        } else {
          scanPromises.push(Promise.resolve(null));
        }

        const [psiResult, obsResult, urlscanResult, webCheckInitResult] = await Promise.all(scanPromises);

        const updateFields = {};

        if (psiResult && !scan.pagespeedResult) {
          updateFields.pagespeedResult = psiResult;
          scan.pagespeedResult = psiResult;
          console.log('[ZAP-AUTH] PageSpeed completed');
        }
        if (obsResult && !scan.observatoryResult) {
          updateFields.observatoryResult = obsResult;
          scan.observatoryResult = obsResult;
          console.log('[ZAP-AUTH] Observatory completed');
        }
        if (urlscanResult && !scan.urlscanResult) {
          updateFields.urlscanResult = urlscanResult;
          scan.urlscanResult = urlscanResult;
          console.log('[ZAP-AUTH] URLScan completed');
        }
        if (webCheckInitResult && webCheckNotStarted) {
          updateFields.webCheckResult = webCheckInitResult;
          scan.webCheckResult = webCheckInitResult;
          console.log('[ZAP-AUTH] WebCheck started in background');
        }

        if (Object.keys(updateFields).length > 0) {
          await ScanResult.updateOne({ analysisId: scanId }, { $set: updateFields });
        }
      } catch (fastScanError) {
        console.error('[ZAP-AUTH] Fast scan orchestration error:', fastScanError.message);
      }
    }

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
      return res.json({ status: 'failed', error: 'Background scan timed out. Please try again.', target: scan.target, analysisId: scanId });
    }

    // ── STEP C: Check if auth ZAP + WebCheck are done → generate Gemini report ──
    const authZapStatus = scan.authScanResult?.status;
    const authZapDone = authZapStatus === 'completed' || authZapStatus === 'failed';

    const webCheckStatus = scan.webCheckResult?.status;
    const webCheckDone = webCheckStatus === 'completed' || webCheckStatus === 'completed_partial' ||
      webCheckStatus === 'completed_with_errors' || webCheckStatus === 'failed';

    // If either auth ZAP or WebCheck failed entirely, fail the whole scan
    if ((authZapStatus === 'failed' || webCheckStatus === 'failed') && !scan.refinedReport) {
      const failedParts = [];
      if (authZapStatus === 'failed') failedParts.push(`Auth ZAP: ${scan.authScanResult?.error || 'unknown error'}`);
      if (webCheckStatus === 'failed') failedParts.push(`WebCheck: ${scan.webCheckResult?.error || 'unknown error'}`);
      console.error(`[ZAP-AUTH] ❌ Background scan(s) failed: ${failedParts.join(', ')}. Failing entire scan.`);
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: { status: 'failed', updatedAt: new Date() } }
      );
      scan.status = 'failed';
      return res.json({ status: 'failed', error: `Scan failed: ${failedParts.join('; ')}`, target: scan.target, analysisId: scanId });
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

    if (authZapDone && webCheckDone && !scan.refinedReport && scan.pagespeedResult && scan.observatoryResult) {
      if (geminiInProgress.has(scanId)) {
        console.log('[ZAP-AUTH] Gemini report already being generated for this scan, skipping...');
      } else {
        geminiInProgress.add(scanId);
        console.log('[ZAP-AUTH] All scans finished. Generating Gemini AI report...');
        try {
          const freshScan = await ScanResult.findOne({ analysisId: scanId, userId: req.user.id });

          // Sanitize freshScan before any data reaches Gemini — strips target URL,
          // domain, IPs, DNS records from the object graph.
          // Original freshScan is NOT mutated; DB writes still use freshScan.
          const llmSafeScan = sanitizeScanForLLM(freshScan);

          const psiReport = llmSafeScan.pagespeedResult?.error ? null : llmSafeScan.pagespeedResult;
          const observatoryReport = llmSafeScan.observatoryResult?.error ? null : llmSafeScan.observatoryResult;
          const urlscanReport = llmSafeScan.urlscanResult?.error ? null : llmSafeScan.urlscanResult;

          // Use auth ZAP data for the report — apply plan filter BEFORE sending to AI
          const authZapCompleted = freshScan.authScanResult?.status === 'completed';
          const aiAccessLevel = await resolveVulnAccessLevel(req.user.id);
          const zapReport = authZapCompleted
            ? getSanitizedZapReport(llmSafeScan.authScanResult, aiAccessLevel, llmSafeScan.target)
            : null;

          // WebCheck data — retrieve then sanitize DNS/IPs
          let webCheckReport = null;
          const freshWebCheck = freshScan.webCheckResult;
          const wcCompleted = freshWebCheck?.status === 'completed' || freshWebCheck?.status === 'completed_partial' || freshWebCheck?.status === 'completed_with_errors';
          if (wcCompleted) {
            const rawWebCheck = await getFullResults(freshWebCheck);
            if (rawWebCheck) {
              const sanitizedWC = sanitizeScanForLLM({ webCheckResult: { fullResults: rawWebCheck } });
              webCheckReport = sanitizedWC?.webCheckResult?.fullResults || rawWebCheck;
            }
          }

          const aiReport = await refineReport(
            null,
            psiReport,
            observatoryReport,
            llmSafeScan.target,   // "REDACTED"
            zapReport,
            urlscanReport,
            webCheckReport
          );

          await ScanResult.updateOne(
            { analysisId: scanId },
            { $set: { refinedReport: aiReport, status: 'completed', updatedAt: new Date() } }
          );
          scan.refinedReport = aiReport;
          scan.status = 'completed';
          console.log('[ZAP-AUTH] Gemini AI report generated!');
          // Trigger notification (email + UI popup)
          handleScanComplete(scanId, req.user.id, 'Authenticated Scan', scan.target);
        } catch (geminiError) {
          console.error('[ZAP-AUTH] Gemini report failed:', geminiError.message);
          const fallback = `AI analysis temporarily unavailable. Error: ${geminiError.message}`;
          await ScanResult.updateOne(
            { analysisId: scanId },
            { $set: { refinedReport: fallback, status: 'completed', updatedAt: new Date() } }
          );
          scan.refinedReport = fallback;
          scan.status = 'completed';
          // Trigger notification even if AI report failed
          handleScanComplete(scanId, req.user.id, 'Authenticated Scan', scan.target);
        } finally {
          geminiInProgress.delete(scanId);
        }
      }
    } else if (authZapDone && (webCheckDone || !scan.webCheckResult) && !scan.refinedReport) {
      // WebCheck may not have started or both done but missing fast scans
      if (!scan.pagespeedResult || !scan.observatoryResult) {
        const fallback = 'AI analysis could not be generated - some scan data was unavailable. Please view individual scan results below.';
        await ScanResult.updateOne(
          { analysisId: scanId },
          { $set: { refinedReport: fallback, status: 'completed', updatedAt: new Date() } }
        );
        scan.refinedReport = fallback;
        scan.status = 'completed';
        // Trigger notification for fallback completion
        handleScanComplete(scanId, req.user.id, 'Authenticated Scan', scan.target);
      }
    }

    // ── STEP D: Build response with all scan data (progressive loading) ──
    const lighthouseResult = scan.pagespeedResult?.lighthouseResult || {};
    const categories = lighthouseResult.categories || {};

    const psiScores = scan.pagespeedResult && !scan.pagespeedResult.error ? {
      performance: categories.performance?.score ? Math.round(categories.performance.score * 100) : null,
      accessibility: categories.accessibility?.score ? Math.round(categories.accessibility.score * 100) : null,
      bestPractices: categories['best-practices']?.score ? Math.round(categories['best-practices'].score * 100) : null,
      seo: categories.seo?.score ? Math.round(categories.seo.score * 100) : null
    } : null;

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

    return res.json({
      success: true,
      scanId: scan.analysisId,
      target: scan.target,
      status: overallStatus,
      // Auth ZAP progress (for step 4 scanning UI)
      phase,
      progress,
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

module.exports = router;
