//virustotalRoutes.js
const express = require('express');
const crypto = require('crypto');
const { runZapScan, stopCombinedScan } = require('../services/zapService');
const { stopWebCheckScan, getFullResults } = require('../services/webCheckService');
const gridfsService = require('../services/gridfsService');
const { generateSingleLanguagePdf } = require('../services/pdfService');
const ScanResult = require('../models/ScanResult');
const User = require('../models/User');
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck');
const { claimScanSlot } = require('../services/planService');
const { combinedScanLimiter, scanLimiter } = require('../middleware/rateLimiter');
const { getSanitizedAlerts, getSanitizedZapData } = require('../utils/vulnFilter');
const { lighthouseScores } = require('../utils/scoreFormat');
const { addScanJob } = require('../queues/scanQueue');
const { getPublisher, executeWithRetry } = require('../config/redis');
const { PDF_BUCKET, resolvePdfJobResponse, shouldReuseJob } = require('../services/pdfJobStore');

/**
 * resolveVulnAccessLevel — fetches the plan's vulnerabilityAccessLevel for req.user.
 * Falls back to 'critical-high' (most restrictive) on any error.
 */
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

const router = express.Router();

// Expose err.message in dev only — never leak internals to production clients
const devMsg = (err) => process.env.NODE_ENV !== 'production' ? err.message : undefined;

// Patterns covering all RFC-1918/loopback/link-local ranges plus cloud metadata
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,                         // 127.0.0.0/8 loopback
  /^0\./,                           // 0.0.0.0/8
  /^10\./,                          // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./,    // 172.16.0.0/12
  /^192\.168\./,                    // 192.168.0.0/16
  /^169\.254\./,                    // 169.254.0.0/16 link-local + AWS metadata
  /^::1$/,                          // IPv6 loopback
  /^fc00:/i,                        // IPv6 ULA fc00::/7
  /^fe[89ab][0-9a-f]:/i,            // IPv6 link-local fe80::/10
  /\.local$/i,                      // mDNS .local domains
];

// URL validation helper
const isValidUrl = (urlString) => {
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
    }
    const hostname = url.hostname.toLowerCase();
    if (BLOCKED_HOST_PATTERNS.some(p => p.test(hostname))) {
      return { valid: false, error: 'Localhost and private IPs are not allowed' };
    }
    return { valid: true };
  } catch (e) {
    return { valid: false, error: 'Invalid URL format' };
  }
};

// 1️⃣ Get user's scan history (Protected route)
router.get('/history', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = 'completed' } = req.query;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit)));

    // Build query - default to completed scans only
    const query = { userId: req.user.id };
    if (status !== 'all') {
      query.status = status;
    }

    // Get total count for pagination
    const total = await ScanResult.countDocuments(query);

    // Get scans with pagination and select only needed fields
    const scans = await ScanResult.find(query)
      .sort({ createdAt: -1 })
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .select('analysisId target status createdAt updatedAt');

    res.json({
      success: true,
      scans: scans,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: total,
        pages: Math.ceil(total / limitNum)
      }
    });
  } catch (err) {
    console.error('❌ History retrieval error:', err.message);
    res.status(500).json({
      error: 'Failed to retrieve scan history',
      details: devMsg(err)
    });
  }
});

// 4.4️⃣ Load a saved scan by analysisId (Protected route)
// Used to view past scans from scan history
router.get('/scan/:analysisId', auth, async (req, res) => {
  try {
    const { analysisId } = req.params;

    // Find the scan and verify ownership
    const scan = await ScanResult.findOne({
      analysisId,
      userId: req.user.id
    });

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found',
        message: 'The scan may have expired or does not exist'
      });
    }

    // Build response object similar to combined-analysis response
    const response = {
      success: true,
      isHistorical: true,
      analysisId: scan.analysisId,
      target: scan.target,
      status: scan.status,
      // Structured reason so the UI can localize it; never send the raw scanner error.
      failureReason: scan.failureReason || null,
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt
    };

    // Add PageSpeed results
    if (scan.pagespeedResult) {
      response.psiData = scan.pagespeedResult;
    }

    // Add Observatory results
    if (scan.observatoryResult) {
      response.obsData = scan.observatoryResult;
    }

    // Add urlscan results
    if (scan.urlscanResult) {
      response.urlscanData = scan.urlscanResult;
    }

    // Add ZAP results with GridFS data if available — plan-filtered
    const zapSource = scan.authScanResult || scan.zapResult;
    if (zapSource) {
      const accessLevel = await resolveVulnAccessLevel(req.user.id);
      const zs = zapSource.status;
      if (zs === 'completed' || zs === 'completed_partial') {
        const rawZapData = {
          status: zs,
          riskCounts: zapSource.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 },
          alerts: zapSource.alerts || [],
          totalAlerts: zapSource.totalAlerts || 0,
          totalOccurrences: zapSource.totalOccurrences || 0,
          reportFiles: zapSource.reportFiles || [],
          site: zapSource.site || scan.target,
          urlsFound: zapSource.urlsFound || 0
        };
        response.zapData = getSanitizedZapData(rawZapData, accessLevel);

        // Fetch detailed alerts from GridFS if available
        if (zapSource.reportFiles && Array.isArray(zapSource.reportFiles)) {
          const detailedAlertsFile = zapSource.reportFiles.find(
            f => f.filename && f.filename.includes('detailed_alerts')
          );
          if (detailedAlertsFile && detailedAlertsFile.fileId) {
            try {
              const bucket = (detailedAlertsFile.filename && detailedAlertsFile.filename.includes('zap_auth'))
                ? 'zap_auth_reports' : 'zap_reports';
              const buffer = await gridfsService.downloadFile(detailedAlertsFile.fileId, bucket);
              const rawAlerts = JSON.parse(buffer.toString('utf-8'));
              response.zapData.detailedAlerts = getSanitizedAlerts(rawAlerts, accessLevel);
            } catch (gridfsErr) {
              console.warn(`[LoadScan] Could not fetch ZAP detailed alerts: ${gridfsErr.message}`);
            }
          }
        }
      } else if (zs === 'running' || zs === 'pending') {
        response.zapData = {
          status: zs,
          phase: zapSource.phase || 'queued',
          progress: zapSource.progress || 0,
          message: zapSource.message || 'ZAP scan in progress...',
          urlsFound: zapSource.urlsFound || 0,
          alertsFound: zapSource.alertsFound || 0
        };
      } else if (zs === 'failed') {
        response.zapData = {
          status: 'failed',
          error: zapSource.error || 'ZAP scan failed'
        };
      }
    }

    // Add WebCheck results with GridFS data if available
    if (scan.webCheckResult) {
      response.webCheckData = { ...scan.webCheckResult };

      // Fetch full results from GridFS if available
      if (!scan.webCheckResult.fullResults && scan.webCheckResult.resultsFileId) {
        try {
          const fullResults = await getFullResults(scan.webCheckResult);
          if (fullResults) {
            response.webCheckData.fullResults = fullResults;
          }
        } catch (gridfsErr) {
          console.warn(`[LoadScan] Could not fetch WebCheck results: ${gridfsErr.message}`);
        }
      }
    }

    // Add AI report
    if (scan.refinedReport) {
      response.aiReport = scan.refinedReport;
    }

    // Build boolean flags matching combined-analysis flow
    const hasZap = !!zapSource && (zapSource.status === 'completed' || zapSource.status === 'completed_partial');
    const zapPending = !!zapSource && (zapSource.status === 'pending' || zapSource.status === 'running');

    const hasWebCheck = !!scan.webCheckResult && ['completed', 'completed_partial', 'completed_with_errors'].includes(scan.webCheckResult.status);
    const webCheckPending = !!scan.webCheckResult && ['pending', 'running', 'uploading'].includes(scan.webCheckResult.status);

    response.hasPsiResult = !!scan.pagespeedResult && !scan.pagespeedResult.error;
    response.hasObservatoryResult = !!scan.observatoryResult && !scan.observatoryResult.error;
    response.hasUrlscanResult = !!scan.urlscanResult && !scan.urlscanResult.error;
    response.hasZapResult = hasZap;
    response.zapPending = zapPending;
    response.hasWebCheckResult = hasWebCheck;
    response.webCheckPending = webCheckPending;
    response.hasRefinedReport = !!scan.refinedReport;

    console.log(`📜 Loaded scan: ${analysisId} for user ${req.user.id} (status: ${scan.status})`);
    res.json(response);

  } catch (err) {
    console.error('❌ Load scan error:', err.message);
    res.status(500).json({
      error: 'Failed to load scan',
      details: devMsg(err)
    });
  }
});

// 4.5️⃣ Get user's active/in-progress scan OR recently completed scan (Protected route)
// This is used to resume scans after page refresh or browser restart
// Also returns recently completed scans so user can see results after returning
router.get('/active-scan', auth, async (req, res) => {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    // The client passes the scan it was actually watching (persisted in
    // localStorage). Resolve that one directly — this endpoint otherwise answers
    // for the USER, and returning "some other recent scan" silently replaced
    // whatever the user had on screen.
    const requestedScanId = typeof req.query.scanId === 'string' ? req.query.scanId : null;
    let activeScan = requestedScanId
      ? await ScanResult.findOne({ analysisId: requestedScanId, userId: req.user.id })
      : null;

    // First, check for in-progress scans (highest priority)
    if (!activeScan) {
      activeScan = await ScanResult.findOne({
        userId: req.user.id,
        status: { $in: ['queued', 'pending', 'combining'] },
        // If a stop was requested, don't ever resume it as an "active" scan.
        // This protects against partial updates where overall status wasn't flipped to 'stopped'.
        'zapResult.status': { $nin: ['stopped', 'cancelled'] },
        'webCheckResult.status': { $nin: ['stopped', 'cancelled'] },
        createdAt: { $gte: twentyFourHoursAgo }
      }).sort({ createdAt: -1 });
    }

    // If no in-progress scan, check for a recently completed one (within the last
    // hour) so a scan that finished while the user was away is still shown.
    // Only manual scans qualify: a scheduled run happens without the user
    // watching, so surfacing it would hijack the page they are actually on.
    if (!activeScan) {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      activeScan = await ScanResult.findOne({
        userId: req.user.id,
        status: 'completed',
        triggerSource: { $ne: 'scheduled' },
        updatedAt: { $gte: oneHourAgo } // Completed within last hour
      }).sort({ updatedAt: -1 });

      // If we found a recently completed scan, mark it so frontend knows
      if (activeScan) {
        console.log(`🔄 Found recently completed scan for user ${req.user.id}: ${activeScan.analysisId}`);
      }
    }

    if (!activeScan) {
      return res.json({
        success: true,
        hasActiveScan: false,
        message: 'No active scan found'
      });
    }

    // Extract key metrics for the response (same as combined-analysis).
    // lighthouseScores() returns null per category when PageSpeed didn't return it,
    // while preserving a genuine score of 0.
    const psiScores = activeScan.pagespeedResult && !activeScan.pagespeedResult.error
      ? lighthouseScores(activeScan.pagespeedResult)
      : null;

    const observatoryData = activeScan.observatoryResult && !activeScan.observatoryResult.error ? {
      grade: activeScan.observatoryResult.grade,
      score: activeScan.observatoryResult.score,
      tests_passed: activeScan.observatoryResult.tests_passed,
      tests_failed: activeScan.observatoryResult.tests_failed,
      tests_quantity: activeScan.observatoryResult.tests_quantity
    } : null;

    // ZAP data handling — plan-filtered
    const activeScanAccessLevel = await resolveVulnAccessLevel(req.user.id);
    let zapData = null;
    if (activeScan.zapResult) {
      const zapStatus = activeScan.zapResult.status;
      if (zapStatus === 'completed') {
        const rawZapData = {
          status: 'completed',
          riskCounts: activeScan.zapResult.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 },
          alerts: activeScan.zapResult.alerts || [],
          totalAlerts: activeScan.zapResult.totalAlerts || activeScan.zapResult.alerts?.length || 0,
          totalOccurrences: activeScan.zapResult.totalOccurrences || 0,
          reportFiles: activeScan.zapResult.reportFiles || [],
          site: activeScan.zapResult.site || activeScan.target,
          urlsFound: activeScan.zapResult.urlsFound || 0
        };
        zapData = getSanitizedZapData(rawZapData, activeScanAccessLevel);
      } else if (zapStatus === 'pending' || zapStatus === 'running') {
        zapData = {
          status: zapStatus,
          phase: activeScan.zapResult.phase || 'queued',
          progress: activeScan.zapResult.progress || 0,
          message: activeScan.zapResult.message || 'ZAP scan in progress...',
          urlsFound: activeScan.zapResult.urlsFound || 0,
          alertsFound: activeScan.zapResult.alertsFound || 0
        };
      } else if (zapStatus === 'failed') {
        zapData = {
          status: 'failed',
          error: activeScan.zapResult.error || 'ZAP scan failed',
          message: activeScan.zapResult.message || 'Vulnerability scan encountered an error'
        };
      }
    }

    const urlscanData = activeScan.urlscanResult && !activeScan.urlscanResult.error ? {
      uuid: activeScan.urlscanResult.uuid,
      verdicts: activeScan.urlscanResult.verdicts,
      screenshot: activeScan.urlscanResult.screenshot,
      page: activeScan.urlscanResult.page,
      stats: activeScan.urlscanResult.stats,
      reportUrl: activeScan.urlscanResult.reportUrl
    } : null;

    // WebCheck data handling - match structure expected by frontend
    let webCheckData = null;
    if (activeScan.webCheckResult) {
      const webCheckStatus = activeScan.webCheckResult.status;

      if (webCheckStatus === 'completed' || webCheckStatus === 'completed_with_errors' || webCheckStatus === 'completed_partial') {
        // Try to get full results (handles both inline and GridFS storage)
        let webCheckResults = activeScan.webCheckResult.fullResults;
        if (!webCheckResults && activeScan.webCheckResult.resultsFileId) {
          // Results in GridFS - fetch them
          try {
            webCheckResults = await getFullResults(activeScan.webCheckResult);
          } catch (e) {
            console.warn('Failed to fetch WebCheck results from GridFS:', e.message);
          }
        }
        // Fallback to summary if full results not available
        if (!webCheckResults) {
          webCheckResults = activeScan.webCheckResult.summary || {};
        }

        webCheckData = {
          status: webCheckStatus,
          results: webCheckResults,
          summary: activeScan.webCheckResult.summary || {},
          completedScans: activeScan.webCheckResult.completedScans || 0,
          totalScans: activeScan.webCheckResult.totalScans || 30,
          hasErrors: activeScan.webCheckResult.hasErrors || false,
          duration: activeScan.webCheckResult.duration || 0
        };
      } else if (webCheckStatus === 'uploading') {
        // WebCheck scans complete, uploading large results to GridFS
        webCheckData = {
          status: 'uploading',
          progress: 100, // Scans are done
          uploadProgress: activeScan.webCheckResult.uploadProgress || 0,
          completedScans: activeScan.webCheckResult.completedScans || activeScan.webCheckResult.totalScans,
          totalScans: activeScan.webCheckResult.totalScans || 30,
          message: activeScan.webCheckResult.message || 'Uploading results to storage...'
        };
      } else if (webCheckStatus === 'running' || webCheckStatus === 'pending') {
        webCheckData = {
          status: 'running',
          progress: activeScan.webCheckResult.progress || 0,
          completedScans: activeScan.webCheckResult.completedScans || 0,
          totalScans: activeScan.webCheckResult.totalScans || 30,
          message: activeScan.webCheckResult.message || 'WebCheck scans in progress...',
          partialResults: activeScan.webCheckResult.partialResults || {}
        };
      } else if (webCheckStatus === 'failed') {
        webCheckData = {
          status: 'failed',
          error: activeScan.webCheckResult.error || 'WebCheck scan failed',
          message: activeScan.webCheckResult.message || 'WebCheck encountered an error'
        };
      }
    }

    console.log(`🔄 Active scan found for user ${req.user.id}: ${activeScan.analysisId}`);
    console.log(`   Status: ${activeScan.status}`);
    console.log(`   Has refinedReport: ${!!activeScan.refinedReport}`);
    if (activeScan.refinedReport) {
      console.log(`   refinedReport length: ${activeScan.refinedReport.length} chars`);
    }

    res.json({
      success: true,
      hasActiveScan: true,
      analysisId: activeScan.analysisId,
      target: activeScan.target,
      status: activeScan.status,
      failureReason: activeScan.failureReason || null,
      // Progress indicators
      hasPsiResult: !!activeScan.pagespeedResult,
      hasObservatoryResult: !!activeScan.observatoryResult,
      hasZapResult: !!activeScan.zapResult && (activeScan.zapResult.status === 'completed' || activeScan.zapResult.status === 'completed_partial'),
      zapPending: !!activeScan.zapResult && (activeScan.zapResult.status === 'pending' || activeScan.zapResult.status === 'running'),
      hasUrlscanResult: !!activeScan.urlscanResult && !activeScan.urlscanResult.error,
      hasRefinedReport: !!activeScan.refinedReport,
      hasWebCheckResult: !!activeScan.webCheckResult && (activeScan.webCheckResult.status === 'completed' || activeScan.webCheckResult.status === 'completed_partial' || activeScan.webCheckResult.status === 'completed_with_errors'),
      webCheckPending: !!activeScan.webCheckResult && activeScan.webCheckResult.status === 'running',
      // Summary data (for quick display)
      psiScores,
      observatoryData,
      zapData,
      urlscanData,
      webCheckData,
      // Full data (for complete display - especially for completed scans)
      pagespeedResult: activeScan.pagespeedResult || null,
      observatoryResult: activeScan.observatoryResult || null,
      zapResult: activeScan.zapResult || null,
      urlscanResult: activeScan.urlscanResult || null,
      webCheckResult: activeScan.webCheckResult || null,
      refinedReport: activeScan.refinedReport || null,
      createdAt: activeScan.createdAt,
      updatedAt: activeScan.updatedAt
    });

  } catch (err) {
    console.error('❌ Active scan retrieval error:', err.message);
    res.status(500).json({
      error: 'Failed to retrieve active scan',
      details: devMsg(err)
    });
  }
});

// 5️⃣ Combined URL Scan — creates DB record, enqueues BullMQ job, returns immediately
// Auth → Plan enforcement → Rate limiting → Handler
// scanLimiter/combinedScanLimiter are applied HERE rather than on the router
// mount: this endpoint starts real work, whereas the router's read-only status
// endpoints are polled on a timer and must not consume the same budget.
router.post('/combined-url-scan', auth, planCheck, scanLimiter, combinedScanLimiter, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      // Nothing to give back: planCheck only reads quota, it never reserves.
      return res.status(400).json({ error: 'URL is required' });
    }

    const validation = isValidUrl(url);
    if (!validation.valid) {

      return res.status(400).json({ error: validation.error });
    }

    console.log(`🔐 User ${req.user.id} submitted URL for combined scan: ${url}`);

    const analysisId = crypto.randomUUID();
    console.log(`🔑 Analysis ID: ${analysisId}`);

    // Create the DB record first so the client can immediately start polling / listening
    await new ScanResult({
      target: url,
      analysisId,
      status: 'queued',
      userId: req.user.id,
      organizationId: req.organization?._id || null
    }).save();
    console.log(`[Billing] Scan started: ${analysisId}`);

    // planCheck is advisory — it reserves nothing, so concurrent starts can all pass
    // it. This is the authoritative check, and it has to run after the record exists
    // because the record's _id is what orders concurrent starters.
    if (req.organization && !(await claimScanSlot(req.organization._id, analysisId))) {
      await ScanResult.updateOne(
        { analysisId },
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

    // Enqueue the scan job — BullMQ worker picks it up and runs all scanners
    await addScanJob(analysisId, url, req.user.id);
    console.log(`📬 Scan job enqueued for ${analysisId}`);

    // Warm ZAP capacity up at acceptance, not when the ZAP job is dequeued. scanWorker
    // runs PageSpeed, Observatory, urlscan and WebCheck before it enqueues the ZAP job,
    // so a scale-from-zero started here (4–8 min) overlaps those rather than being added
    // to the end of them — which is what keeps the cold start invisible to the user.
    //
    // Deliberately not awaited and never fatal: the authoritative capacity wait happens
    // inside withZapInstance, under the ZAP lock. This is an optimisation, so a failure
    // here must not fail a scan that would otherwise succeed. No-ops entirely unless
    // ZAP_CAPACITY_MANAGED=true and 'normal' is in ZAP_CAPACITY_KEYS.
    {
      const { markZapDemand, ensureZapCapacity } = require('../services/zapCapacityManager');
      markZapDemand('normal').catch(() => {});
      ensureZapCapacity('normal', { scanId: analysisId }).catch(err =>
        console.warn(`[ZapCapacity] warm-up failed for ${analysisId}: ${err.message}`)
      );
    }

    res.json({
      success: true,
      message: 'Scan queued — you will receive real-time updates via WebSocket',
      analysisId,
      url
    });
  } catch (err) {
    console.error('❌ Combined URL scan error:', err);
    // Nothing to refund: quota is charged at successful completion, and the
    // ScanResult created above leaves in-flight state that the watchdog clears.

    // Graceful error handling for duplicates if race condition occurs
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Scan already in progress. Please wait and try again.' });
    }
    res.status(500).json({ error: 'Failed to initiate combined scan', details: devMsg(err) });
  }
});

// 6️⃣ Combined Analysis — READ-ONLY fallback endpoint (WebSocket is primary)
// Scan triggering + Gemini generation now handled by the BullMQ worker.
// Frontend uses this only when Socket.IO updates are absent for ~15 seconds.
router.get('/combined-analysis/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: 'Analysis ID is required' });

    const scan = await ScanResult.findOne({ analysisId: id, userId: req.user.id });
    if (!scan) return res.status(404).json({ error: 'Analysis not found' });

    // Stopped / cancelled guard
    const isStopped =
      ['stopped', 'cancelled'].includes(scan.status) ||
      ['stopped', 'cancelled'].includes(scan.zapResult?.status) ||
      ['stopped', 'cancelled'].includes(scan.webCheckResult?.status);

    if (isStopped) {
      return res.json({
        status: 'stopped',
        message: 'Scan was stopped by user',
        analysisId: id,
        target: scan.target,
        pagespeedResult:   scan.pagespeedResult   || null,
        observatoryResult: scan.observatoryResult || null,
        urlscanResult:     scan.urlscanResult     || null,
        zapResult:         scan.zapResult         || null,
        webCheckResult:    scan.webCheckResult    || null,
        refinedReport:     scan.refinedReport     || null,
        createdAt: scan.createdAt,
        updatedAt: scan.updatedAt
      });
    }

    // Stale-scan watchdog (failsafe — worker should have already handled timeouts)
    const ZAP_STALE_MS    = 24 * 60 * 60 * 1000;
    const WEBCHK_STALE_MS =  6 * 60 * 60 * 1000;
    const now = Date.now();

    if (scan.zapResult?.startedAt &&
        !['completed','completed_partial','failed'].includes(scan.zapResult.status) &&
        now - new Date(scan.zapResult.startedAt).getTime() > ZAP_STALE_MS) {
      await ScanResult.updateOne(
        { analysisId: id, userId: req.user.id, status: { $nin: ['stopped','cancelled'] } },
        { $set: { 'zapResult.status': 'failed', 'zapResult.error': 'Timed out (24 h)', status: 'failed', updatedAt: new Date() } }
      );
      return res.json({ status: 'failed', error: 'ZAP scan timed out. Please try again.', target: scan.target, analysisId: id });
    }

    if (scan.webCheckResult?.startedAt &&
        !['completed','completed_partial','completed_with_errors','failed'].includes(scan.webCheckResult.status) &&
        now - new Date(scan.webCheckResult.startedAt).getTime() > WEBCHK_STALE_MS) {
      await ScanResult.updateOne(
        { analysisId: id, userId: req.user.id, status: { $nin: ['stopped','cancelled'] } },
        { $set: { 'webCheckResult.status': 'failed', 'webCheckResult.error': 'Timed out (6 h)', status: 'failed', updatedAt: new Date() } }
      );
      return res.json({ status: 'failed', error: 'WebCheck scan timed out. Please try again.', target: scan.target, analysisId: id });
    }

    // ── Build response (same shape as before so frontend code is unchanged) ──
    const psiScores = scan.pagespeedResult && !scan.pagespeedResult.error
      ? lighthouseScores(scan.pagespeedResult)
      : null;

    const observatoryData = scan.observatoryResult && !scan.observatoryResult.error ? {
      grade: scan.observatoryResult.grade, score: scan.observatoryResult.score,
      tests_passed: scan.observatoryResult.tests_passed, tests_failed: scan.observatoryResult.tests_failed,
      tests_quantity: scan.observatoryResult.tests_quantity
    } : null;

    let zapData = null;
    const zapSource = scan.authScanResult || scan.zapResult;
    if (zapSource) {
      const zs = zapSource.status;
      if (zs === 'completed' || zs === 'completed_partial') {
        zapData = {
          status: zs,
          riskCounts: zapSource.riskCounts || {},
          alerts: zapSource.alerts || [],
          totalAlerts: zapSource.totalAlerts || 0,
          totalOccurrences: zapSource.totalOccurrences || 0,
          reportFiles: zapSource.reportFiles || [],
          site: zapSource.site || scan.target,
          urlsFound: zapSource.urlsFound || 0
        };
      } else if (zs === 'pending' || zs === 'running') {
        zapData = {
          status: zs,
          phase: zapSource.phase || 'queued',
          progress: zapSource.progress || 0,
          message: zapSource.message || 'ZAP scan in progress...',
          urlsFound: zapSource.urlsFound || 0,
          alertsFound: zapSource.alertsFound || 0
        };
      } else if (zs === 'failed') {
        zapData = {
          status: 'failed',
          error: zapSource.error || 'ZAP scan failed',
          message: zapSource.message || 'Vulnerability scan encountered an error'
        };
      }
    }

    const urlscanData = scan.urlscanResult && !scan.urlscanResult.error ? {
      uuid: scan.urlscanResult.uuid, verdicts: scan.urlscanResult.verdicts,
      page: scan.urlscanResult.page, stats: scan.urlscanResult.stats,
      screenshot: scan.urlscanResult.screenshot, reportUrl: scan.urlscanResult.reportUrl
    } : null;

    let webCheckData = null;
    if (scan.webCheckResult) {
      const ws = scan.webCheckResult.status;
      if (['completed','completed_with_errors','completed_partial'].includes(ws)) {
        let webCheckResults = scan.webCheckResult.fullResults;
        if (!webCheckResults && scan.webCheckResult.resultsFileId) {
          try { webCheckResults = await getFullResults(scan.webCheckResult); } catch (_e) {}
        }
        webCheckData = { status: ws, results: webCheckResults || scan.webCheckResult.summary || {},
          summary: scan.webCheckResult.summary || {},
          completedScans: scan.webCheckResult.completedScans || 0,
          totalScans: scan.webCheckResult.totalScans || 30,
          hasErrors: scan.webCheckResult.hasErrors || false,
          duration: scan.webCheckResult.duration || 0 };
      } else if (ws === 'uploading') {
        webCheckData = { status: 'uploading', progress: 100,
          uploadProgress: scan.webCheckResult.uploadProgress || 0,
          completedScans: scan.webCheckResult.completedScans || scan.webCheckResult.totalScans,
          totalScans: scan.webCheckResult.totalScans || 30,
          message: scan.webCheckResult.message || 'Uploading results to storage...' };
      } else if (ws === 'running' || ws === 'pending') {
        webCheckData = { status: 'running', progress: scan.webCheckResult.progress || 0,
          completedScans: scan.webCheckResult.completedScans || 0,
          totalScans: scan.webCheckResult.totalScans || 30,
          message: scan.webCheckResult.message || 'WebCheck scans in progress...',
          partialResults: scan.webCheckResult.partialResults || {} };
      } else if (ws === 'failed') {
        webCheckData = { status: 'failed', error: scan.webCheckResult.error || 'WebCheck scan failed',
          message: scan.webCheckResult.message || 'WebCheck encountered an error' };
      }
    }

    // ─── Vulnerability filtering based on user's plan ──────────────────────────
    const vulnAccessLevel = await resolveVulnAccessLevel(req.user.id);

    console.log(`📤 Returning combined-analysis response:`);
    console.log(`   Status: ${scan.status}`);
    console.log(`   Vuln access level: ${vulnAccessLevel}`);
    console.log(`   Has refinedReport: ${!!scan.refinedReport}`);
    if (scan.refinedReport) {
      console.log(`   refinedReport length: ${scan.refinedReport.length} chars`);
    }

    // Apply centralized plan filter
    const filteredZapData = getSanitizedZapData(zapData, vulnAccessLevel);

    return res.json({
      success: true,
      status: scan.status,
      failureReason: scan.failureReason || null,
      analysisId: id,
      target: scan.target,
      hasPsiResult:        !!scan.pagespeedResult,
      hasObservatoryResult: !!scan.observatoryResult,
      hasZapResult: !!zapSource && (zapSource.status === 'completed' || zapSource.status === 'completed_partial'),
      zapPending: !!zapSource && (zapSource.status === 'pending' || zapSource.status === 'running'),
      hasUrlscanResult: !!scan.urlscanResult && !scan.urlscanResult.error,
      hasWebCheckResult: !!scan.webCheckResult && (scan.webCheckResult.status === 'completed' || scan.webCheckResult.status === 'completed_partial' || scan.webCheckResult.status === 'completed_with_errors'),
      webCheckPending: !!scan.webCheckResult && scan.webCheckResult.status === 'running',
      hasRefinedReport: !!scan.refinedReport,
      // Actual data (null if not yet available)
      psiScores: psiScores,
      observatoryData: observatoryData,
      zapData: filteredZapData,          // plan-filtered
      vulnAccessLevel: vulnAccessLevel,  // inform frontend of restriction
      urlscanData: urlscanData,
      webCheckData: webCheckData,
      refinedReport: scan.refinedReport || null,
      pagespeedResult: scan.pagespeedResult || null,
      observatoryResult: scan.observatoryResult || null,
      zapResult:         scan.zapResult         || null,
      urlscanResult:     scan.urlscanResult     || null,
      webCheckResult:    scan.webCheckResult    || null,
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt
    });

  } catch (err) {
    console.error('❌ Combined analysis error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve analysis', details: devMsg(err) });
  }
});


// 7️⃣ Download Complete JSON Report (All scan data combined)
router.get('/download-complete-json/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: 'Analysis ID is required' });
    }

    console.log(`📥 Downloading complete JSON report for ID: ${id}`);

    // Find the scan in database
    const scan = await ScanResult.findOne({ analysisId: id, userId: req.user.id });

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found or access denied'
      });
    }

    // Fetch full ZAP detailed alerts from GridFS, then apply plan filter
    const jsonExportAccessLevel = await resolveVulnAccessLevel(req.user.id);
    let fullZapAlerts = [];
    if (scan.zapResult?.reportFiles?.length > 0) {
      const detailedAlertsFile = scan.zapResult.reportFiles.find(
        f => f.filename && f.filename.includes('detailed_alerts')
      );

      if (detailedAlertsFile && detailedAlertsFile.fileId) {
        try {
          const zapBucket = (detailedAlertsFile.filename && detailedAlertsFile.filename.includes('zap_auth'))
            ? 'zap_auth_reports' : 'zap_reports';
          console.log(`📥 Fetching full ZAP alerts from GridFS (${zapBucket}) for JSON export: ${detailedAlertsFile.fileId}`);
          const detailedAlertsBuffer = await gridfsService.downloadFile(detailedAlertsFile.fileId, zapBucket);
          const rawAlerts = JSON.parse(detailedAlertsBuffer.toString('utf-8'));
          fullZapAlerts = getSanitizedAlerts(rawAlerts, jsonExportAccessLevel);
          console.log(`✅ Retrieved ${fullZapAlerts.length} plan-filtered ZAP alerts from GridFS`);
        } catch (gridfsError) {
          console.warn(`⚠️ Failed to fetch ZAP alerts from GridFS: ${gridfsError.message}`);
          fullZapAlerts = getSanitizedAlerts(scan.zapResult?.alerts || [], jsonExportAccessLevel);
        }
      } else {
        fullZapAlerts = getSanitizedAlerts(scan.zapResult?.alerts || [], jsonExportAccessLevel);
      }
    } else {
      fullZapAlerts = getSanitizedAlerts(scan.zapResult?.alerts || [], jsonExportAccessLevel);
    }

    // Prepare complete JSON data package with RAW OWASP ZAP structure
    const completeData = {
      metadata: {
        scanId: scan.analysisId,
        target: scan.target,
        scannedAt: scan.createdAt,
        completedAt: scan.updatedAt,
        status: scan.status,
        generatedBy: 'SSDT Security Scanner',
        version: '2.0'
      },
      pageSpeed: scan.pagespeedResult || null,
      observatory: scan.observatoryResult || null,
      urlscan: scan.urlscanResult || null,
      webCheck: {
        status: scan.webCheckResult?.status || null,
        completedScans: scan.webCheckResult?.completedScans || null,
        totalScans: scan.webCheckResult?.totalScans || null,
        duration: scan.webCheckResult?.duration || null,
        hasErrors: scan.webCheckResult?.hasErrors || false,
        results: scan.webCheckResult ? await getFullResults(scan.webCheckResult) : null,
        summary: scan.webCheckResult?.summary || null
      },
      // RAW OWASP ZAP format with full alert structure
      zap: {
        site: scan.target,
        summary: {
          riskCounts: scan.zapResult?.riskCounts || null,
          totalAlerts: scan.zapResult?.totalAlerts || null,
          totalOccurrences: scan.zapResult?.totalOccurrences || null,
          urlsFound: scan.zapResult?.urlsFound || null,
          status: scan.zapResult?.status || null,
          completedAt: scan.zapResult?.completedAt || null
        },
        // Full OWASP ZAP alerts structure with complete remediation text
        alerts: fullZapAlerts.map(alert => ({
          alert: alert.alert || alert.name,
          riskcode: alert.risk === 'High' ? 3 : alert.risk === 'Medium' ? 2 : alert.risk === 'Low' ? 1 : 0,
          risk: alert.risk,
          confidence: alert.confidence,
          riskdesc: `${alert.risk} (${alert.confidence})`,
          description: alert.description || '',
          solution: alert.solution || '',
          reference: alert.reference || '',
          cweid: alert.cweid || '',
          wascid: alert.wascid || '',
          // occurrences now carry method/param/attack/evidence + full raw
          // request/response ({ request:{header,body}, response:{header,body} }).
          instances: alert.occurrences || alert.sampleUrls?.map(url => ({ uri: url })) || [],
          count: alert.totalOccurrences || alert.occurrences?.length || 0
        })),
        reportFiles: scan.zapResult?.reportFiles || []
      },
      aiAnalysis: {
        refinedReport: scan.refinedReport || null,
        generatedAt: scan.updatedAt
      }
    };

    // Set headers for JSON download
    const filename = `scan_report_${scan.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Send JSON
    res.json(completeData);
    console.log(`✅ Complete JSON report downloaded: ${filename}`);

  } catch (err) {
    console.error('❌ Download complete JSON error:', err);
    res.status(500).json({
      error: 'Failed to download complete JSON report',
      details: devMsg(err)
    });
  }
});

// 8️⃣ Stop a combined scan and restart Docker containers (Protected route)
router.post('/stop-scan/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: 'Analysis ID is required' });
    }

    console.log(`🛑 User ${req.user.id} requested to stop combined scan: ${id}`);

    // Stop WebCheck in-memory tracking first
    const webCheckStopped = stopWebCheckScan(id);
    if (webCheckStopped) {
      console.log(`🛑 WebCheck background scan stopped for: ${id}`);
    }

    // Stop the combined scan and restart containers
    const result = await stopCombinedScan(id, req.user.id);

    res.json({
      success: true,
      message: result.message || 'Scan stopped successfully',
      scanId: id,
      containersRestarted: result.containersRestarted || { zap: false, webCheck: false },
      webCheckBackgroundStopped: webCheckStopped,
      note: 'Both ZAP and WebCheck containers have been restarted for fresh scan environment'
    });

  } catch (err) {
    console.error('❌ Stop scan error:', err);

    if (err.message.includes('not found') || err.message.includes('access denied')) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found or access denied'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Failed to stop scan',
      details: devMsg(err)
    });
  }
});

// ─── PDF job store (Redis-backed) ─────────────────────────────────────────
//
// Jobs are stored in Redis so they survive backend restarts and are visible
// across all ECS task instances (multi-container deployments).
//
// Key schema:
//   pdf:job:{jobId}    → JSON metadata  (TTL: PDF_JOB_TTL_S)
//   (the PDF bytes live in GridFS bucket 'pdf_reports'; meta.bufferFileId points to it)
//   pdf:active:{analysisId}:{lang} → jobId  (TTL: PDF_ACTIVE_TTL_S) — dedup
//
// Status lifecycle:  pending → processing → completed | failed
//
// Jobs are NOT deleted on download — TTL handles expiry after 24 hours.

const PDF_JOB_TTL_S    = 24 * 60 * 60; // 24 hours
const PDF_ACTIVE_TTL_S = 30 * 60;      // 30 minutes — dedup window
const PDF_JOB_TIMEOUT_MS = 300000; // Increase timeout to allow slow AI + translation runs to finish (5 minutes)

function timeout(ms, message) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms));
}

function _pdfMetaKey(jobId)              { return `pdf:job:${jobId}`; }
function _pdfActiveKey(analysisId, lang)  { return `pdf:active:${analysisId}:${lang}`; }

async function _getPdfMeta(jobId) {
  try {
    const raw = await executeWithRetry(() => getPublisher().get(_pdfMetaKey(jobId)));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.error(`[PDF] Redis GET meta failed for ${jobId}:`, err.message);
    return null;
  }
}

// Returns true only if the metadata was durably written. Callers MUST treat a
// false as fatal for a new job — never hand the client a jobId that points to
// nothing (that is the silent-404 bug this replaces).
async function _setPdfMeta(jobId, meta) {
  try {
    await executeWithRetry(() => getPublisher().set(_pdfMetaKey(jobId), JSON.stringify(meta), 'EX', PDF_JOB_TTL_S));
    return true;
  } catch (err) {
    console.error(`[PDF] Redis SET meta failed for ${jobId}:`, err.message);
    return false;
  }
}

// The PDF itself lives in GridFS (durable, not evictable), NOT Redis.
async function _storePdfFile(buffer, filename, meta) {
  const fileId = await gridfsService.uploadFile(
    buffer, filename,
    { jobId: meta.jobId, analysisId: meta.analysisId, lang: meta.lang, kind: 'pdf_report' },
    PDF_BUCKET
  );
  return fileId.toString();
}

async function _getPdfFile(bufferFileId) {
  if (!bufferFileId) return null;
  try {
    return await gridfsService.downloadFile(bufferFileId, PDF_BUCKET);
  } catch (err) {
    console.warn(`[PDF] GridFS download failed for file ${bufferFileId}:`, err.message);
    return null;
  }
}

/**
 * Validate that the scan has real data before attempting PDF generation.
 * Returns null if valid, or an error string listing missing fields.
 */
function _validateScanDataForPdf(scan) {
  const missing = [];
  if (!scan.pagespeedResult && !scan.observatoryResult && !scan.urlscanResult &&
      !scan.zapResult && !scan.webCheckResult) {
    missing.push('all scan results (pagespeed, observatory, urlscan, zap, webCheck)');
  }
  // At least one concrete result set must exist
  if (missing.length) {
    return `[PDF] Cannot generate report. Missing fields:\n- ${missing.join('\n- ')}`;
  }
  return null;
}

// Start async PDF generation — returns a jobId immediately, client polls for result
router.post('/pdf-job', auth, async (req, res) => {
  const { analysisId, lang = 'en' } = req.body || {};
  if (!['en', 'ja'].includes(lang)) {
    return res.status(400).json({ error: 'Invalid language. Use "en" or "ja"' });
  }
  if (!analysisId) return res.status(400).json({ error: 'analysisId is required' });

  console.log(`[PDF] Job requested  analysisId=${analysisId} lang=${lang} userId=${req.user.id}`);

  const scan = await ScanResult.findOne({ analysisId, userId: req.user.id });
  if (!scan) return res.status(404).json({ error: 'Scan not found or access denied' });

  // A scan that ended in a terminal failure never produces a report, regardless of
  // how much partial data it collected. Previously the `hasSomeData` escape hatch
  // below let a failed scan render a PDF whose vulnerability section read
  // "No vulnerabilities detected" — a clean bill of health for a site that was
  // never assessed.
  if (['failed', 'stopped', 'cancelled'].includes(scan.status)) {
    return res.status(400).json({
      errorCode: 'SCAN_NOT_COMPLETE',
      error: 'Scan did not complete; no report is available',
      status: scan.status,
      failureReason: scan.failureReason || null
    });
  }

  const hasSomeData = scan.pagespeedResult || scan.observatoryResult || scan.urlscanResult;
  if (scan.status !== 'completed' && !hasSomeData) {
    return res.status(400).json({
      errorCode: 'SCAN_NOT_COMPLETE',
      error: 'Scan is not yet complete',
      status: scan.status
    });
  }

  // ── Validate scan has real data ─────────────────────────────────────────────
  const validationError = _validateScanDataForPdf(scan);
  if (validationError) {
    console.error(validationError);
    return res.status(400).json({ error: 'Scan has no usable data for PDF generation' });
  }

  // ── Deduplication: reuse existing in-progress job ───────────────────────────
  try {
    const activeKey = _pdfActiveKey(analysisId, lang);
    const existingJobId = await executeWithRetry(() => getPublisher().get(activeKey));
    if (existingJobId) {
      const existingMeta = await _getPdfMeta(existingJobId);
      if (existingMeta && (existingMeta.status === 'pending' || existingMeta.status === 'processing' || existingMeta.status === 'completed')) {
        const isPendingOrProcessing = existingMeta.status === 'pending' || existingMeta.status === 'processing';
        const isOrphaned = isPendingOrProcessing && (Date.now() - (existingMeta.lastUpdated || existingMeta.createdAt) > PDF_JOB_TIMEOUT_MS);
        // A completed job is only reusable while its PDF file still exists in GridFS.
        const fileExists = existingMeta.status === 'completed'
          ? await gridfsService.fileExists(existingMeta.bufferFileId, PDF_BUCKET)
          : false;

        if (isOrphaned) {
          console.warn(`[PDF] Found orphaned job jobId=${existingJobId} status=${existingMeta.status} age=${Date.now() - existingMeta.createdAt}ms. Ignoring and creating new job.`);
          try {
            await _setPdfMeta(existingJobId, {
              ...existingMeta,
              status: 'failed',
              error: 'PDF generation timed out (orphaned)',
              failedAt: Date.now(),
              lastUpdated: Date.now()
            });
          } catch (_) {}
        } else if (shouldReuseJob(existingMeta, fileExists)) {
          console.log(`[PDF] Reusing existing job  jobId=${existingJobId} status=${existingMeta.status} analysisId=${analysisId} lang=${lang}`);
          return res.json({ jobId: existingJobId });
        } else {
          console.warn(`[PDF] Not reusing job jobId=${existingJobId} status=${existingMeta.status} (PDF file missing) — creating new job.`);
        }
      }
    }
  } catch (dedupErr) {
    console.warn(`[PDF] Dedup check failed (non-fatal):`, dedupErr.message);
  }

  const jobId = crypto.randomUUID();
  const nowTs = Date.now();
  const meta = {
    jobId,
    status: 'pending',
    lang,
    analysisId,
    userId: req.user.id,
    createdAt: nowTs,
    lastUpdated: nowTs
  };
  // Authoritative persistence: if we can't durably record the job, do NOT hand the
  // client a jobId that would poll forever into a 404. Fail honestly so it can retry.
  const persisted = await _setPdfMeta(jobId, meta);
  if (!persisted) {
    return res.status(503).json({ error: 'PDF service temporarily unavailable, please retry' });
  }

  // Store active-job key for deduplication
  try {
    await executeWithRetry(() => getPublisher().set(_pdfActiveKey(analysisId, lang), jobId, 'EX', PDF_ACTIVE_TTL_S));
  } catch (_) { /* dedup is best-effort */ }

  console.log(`[PDF] Job created  jobId=${jobId} lang=${lang} analysisId=${analysisId} userId=${req.user.id}`);

  // Fire-and-forget — update Redis as generation progresses.
  // The .catch() at the end ensures unhandled rejections never silently kill jobs.
  (async () => {
    try {
      console.log(`[PDF] Loading scan data  jobId=${jobId} analysisId=${analysisId}`);

      // Hydrate full WebCheck results from GridFS if needed
      if (scan.webCheckResult && !scan.webCheckResult.fullResults && scan.webCheckResult.resultsFileId) {
        const full = await getFullResults(scan.webCheckResult);
        if (full) scan.webCheckResult.fullResults = full;
      }

      console.log(`[PDF] Scan data validated  jobId=${jobId} analysisId=${analysisId}`);

      // Mark processing so polls return 202, not 404, during generation
      await _setPdfMeta(jobId, { ...meta, status: 'processing', lastUpdated: Date.now() });
      console.log(`[PDF] Job processing  jobId=${jobId} lang=${lang.toUpperCase()} analysisId=${analysisId}`);

      console.log(`[PDF] Starting Gemini analysis  jobId=${jobId} analysisId=${analysisId}`);
      const pdfAccessLevel = await resolveVulnAccessLevel(req.user.id);
      const buffer = await Promise.race([
        generateSingleLanguagePdf(scan, lang, pdfAccessLevel),
        timeout(PDF_JOB_TIMEOUT_MS, 'PDF generation timed out after 120 seconds')
      ]);
      const filename = `security_report_${lang.toUpperCase()}_${scan.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;

      console.log(`[PDF] Generating document  jobId=${jobId} analysisId=${analysisId}`);

      // Store the PDF in GridFS (durable), then flip meta to completed with the
      // file id. Order matters — the poll checks meta first, so the file must exist
      // before meta says 'completed'.
      const bufferFileId = await _storePdfFile(buffer, filename, meta);
      await _setPdfMeta(jobId, { ...meta, status: 'completed', filename, bufferFileId, completedAt: Date.now(), lastUpdated: Date.now() });
      console.log(`[PDF] PDF completed  jobId=${jobId} bytes=${buffer.length} fileId=${bufferFileId} filename=${filename} analysisId=${analysisId}`);
    } catch (err) {
      console.error(`[PDF] PDF failed  jobId=${jobId} analysisId=${analysisId} error=${err.message}`);
      console.error(`[PDF] PDF failed stack  jobId=${jobId}:`, err.stack);
      // Double-safe: wrap the Redis SET in its own try/catch so we never lose the error
      try {
        await _setPdfMeta(jobId, {
          ...meta,
          status: 'failed',
          error: err.message,
          errorCode: err.code,
          failedAt: Date.now(),
          lastUpdated: Date.now()
        });
      } catch (redisErr) {
        console.error(`[PDF] CRITICAL: Could not persist failure state  jobId=${jobId} redisError=${redisErr.message}`);
      }
    }
  })().catch(outerErr => {
    // This catches truly unexpected errors that escape even the inner try/catch
    // (e.g. if the async IIFE setup itself throws before entering the try block)
    console.error(`[PDF] UNHANDLED IIFE ERROR  jobId=${jobId} analysisId=${analysisId} error=${outerErr.message}`);
    _setPdfMeta(jobId, { ...meta, status: 'failed', error: 'Internal error during PDF generation', failedAt: Date.now(), lastUpdated: Date.now() }).catch(() => {});
  });

  res.json({ jobId });
});

// Poll PDF job status / download result
// 202 while pending or processing, 200+PDF when completed, error JSON when failed
router.get('/pdf-job/:jobId', auth, async (req, res) => {
  const { jobId } = req.params;
  console.log(`[PDF] Job status requested  jobId=${jobId} userId=${req.user.id}`);

  const meta = await _getPdfMeta(jobId);

  if (meta && meta.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }

  // For a completed job, fetch the PDF from GridFS — this both verifies the file
  // still exists and gives us the bytes to stream. Missing file → 409 'expired'.
  const buffer = meta && meta.status === 'completed' ? await _getPdfFile(meta.bufferFileId) : null;

  const decision = resolvePdfJobResponse(meta, !!buffer, Date.now(), PDF_JOB_TIMEOUT_MS);

  // Persist the orphan → failed transition when the poll detects a timed-out job.
  if (decision.kind === 'timeout' && meta) {
    console.warn(`[PDF] Job ${jobId} timed out (status=${meta.status}). Transitioning to failed.`);
    await _setPdfMeta(jobId, { ...meta, status: 'failed', error: decision.body.error, failedAt: Date.now(), lastUpdated: Date.now() });
  }

  if (decision.kind === 'not_found') console.warn(`[PDF] Job expired or not found  jobId=${jobId}`);
  if (decision.kind === 'expired')   console.warn(`[PDF] Job file missing (regenerable)  jobId=${jobId}`);

  if (decision.kind === 'completed') {
    console.log(`[PDF] Job served  jobId=${jobId} bytes=${buffer.length}`);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${meta.filename}"`);
    res.setHeader('Content-Length', buffer.length);
    return res.send(buffer);
  }

  return res.status(decision.code).json(decision.body);
});

// 🔟 Download PDF Report (Protected route) - Supports language selection
router.get('/download-pdf/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const lang = req.query.lang || 'en';

    // Validate language parameter
    if (!['en', 'ja'].includes(lang)) {
      return res.status(400).json({ error: 'Invalid language. Use "en" or "ja"' });
    }

    if (!id) {
      return res.status(400).json({ error: 'Analysis ID is required' });
    }

    console.log(`📄 PDF download requested for: ${id} (language: ${lang.toUpperCase()})`);

    // Find the scan
    const scan = await ScanResult.findOne({
      analysisId: id,
      userId: req.user.id
    });

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found or access denied'
      });
    }

    // A terminally failed scan never produces a report, however much partial data
    // it collected — otherwise the vulnerability section reads "No vulnerabilities
    // detected" for a site that was never assessed. ('partial_complete' was
    // checked here historically but is not a value in the ScanResult status enum,
    // so it never matched.)
    if (['failed', 'stopped', 'cancelled'].includes(scan.status)) {
      return res.status(400).json({
        errorCode: 'SCAN_NOT_COMPLETE',
        error: 'Scan did not complete; no report is available',
        status: scan.status,
        failureReason: scan.failureReason || null
      });
    }

    const hasSomeData = scan.pagespeedResult || scan.observatoryResult || scan.urlscanResult;
    if (scan.status !== 'completed' && !hasSomeData) {
      return res.status(400).json({
        errorCode: 'SCAN_NOT_COMPLETE',
        error: 'Scan is not yet complete. Please wait for all scans to finish.',
        status: scan.status
      });
    }
    if (scan.status !== 'completed' && hasSomeData) {
      console.log(`📄 Generating PDF with partial results for scan ${id} (status: ${scan.status})`);
    }

    // Ensure WebCheck fullResults is populated (might be in GridFS)
    if (scan.webCheckResult && !scan.webCheckResult.fullResults && scan.webCheckResult.resultsFileId) {
      console.log('📄 Fetching WebCheck results from GridFS for PDF...');
      try {
        const webCheckFullResults = await getFullResults(scan.webCheckResult);
        if (webCheckFullResults) {
          scan.webCheckResult.fullResults = webCheckFullResults;
          console.log(`📄 WebCheck results fetched: ${Object.keys(webCheckFullResults).length} scan types`);
        }
      } catch (e) {
        console.warn('⚠️ Failed to fetch WebCheck results for PDF:', e.message);
      }
    }

    // Always generate fresh PDF (no caching - data retention policy)
    const pdfAccessLevel = await resolveVulnAccessLevel(req.user.id);
    console.log(`📄 Generating ${lang.toUpperCase()} PDF report (vuln access: ${pdfAccessLevel})...`);
    const pdfBuffer = await generateSingleLanguagePdf(scan, lang, pdfAccessLevel);

    // Set headers for PDF download (include language in filename)
    const langSuffix = lang.toUpperCase();
    const filename = `security_report_${langSuffix}_${scan.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);

    // Send PDF
    res.send(pdfBuffer);
    console.log(`✅ ${lang.toUpperCase()} PDF report downloaded: ${filename}`);

  } catch (err) {
    console.error('❌ PDF generation error:', err);
    if (err?.code === 'GEMINI_KEY_EXHAUSTED') {
      return res.status(429).json({
        errorCode: 'GEMINI_KEY_EXHAUSTED',
        error: 'Gemini key is exhausted'
      });
    }
    if (['EN_CONTENT_NOT_ENGLISH', 'EN_TEMPLATE_NOT_ENGLISH'].includes(err?.code)) {
      return res.status(400).json({
        errorCode: err.code,
        error: err.message
      });
    }
    res.status(500).json({
      error: 'Failed to generate PDF report',
      details: devMsg(err)
    });
  }
});

module.exports = router;
