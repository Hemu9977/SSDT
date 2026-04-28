//virustotalRoutes.js
const express = require('express');
const crypto = require('crypto');
const { getPageSpeedReport } = require('../services/pagespeedService');
const { scanHost } = require('../services/observatoryService');
const { refineReport } = require('../services/geminiService');
const { runZapScan, startAsyncZapScan, stopCombinedScan } = require('../services/zapService');
const { runUrlScan } = require('../services/urlscanService');
const { startAsyncWebCheckScan, stopWebCheckScan, getFullResults } = require('../services/webCheckService');
const gridfsService = require('../services/gridfsService');
const { generatePdfReport, generateSingleLanguagePdf } = require('../services/pdfService');
const ScanResult = require('../models/ScanResult');
const User = require('../models/User');
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck');
const { combinedScanLimiter } = require('../middleware/rateLimiter');
const { handleScanComplete } = require('../services/notificationService');

/**
 * filterZapAlertsByPlan — filters ZAP alerts in-memory based on plan vulnerability access level.
 * NEVER modifies stored data. Operates only on the response payload.
 * @param {object|null} zapData  — the zapData object built for the response
 * @param {string} accessLevel  — 'all' | 'critical-high'
 * @returns modified copy of zapData
 */
function filterZapAlertsByPlan(zapData, accessLevel) {
  if (!zapData || accessLevel === 'all') return zapData;
  // Only 'critical-high' requires filtering
  const ALLOWED = ['High']; // ZAP does not have a 'Critical' label; High is the highest
  const filtered = {
    ...zapData,
    alerts: (zapData.alerts || []).filter(a => ALLOWED.includes(a.risk)),
    totalAlerts: undefined,  // recalculate below
    riskCounts: zapData.riskCounts
      ? {
          High:          zapData.riskCounts.High          || 0,
          Medium:        0,
          Low:           0,
          Informational: 0
        }
      : undefined,
    _filtered: true  // flag so frontend can show a note
  };
  filtered.totalAlerts = filtered.alerts.length;
  return filtered;
}

const router = express.Router();

// In-memory lock to prevent parallel Gemini AI report calls for the same scan
const geminiInProgress = new Set();

// URL validation helper
const isValidUrl = (urlString) => {
  try {
    const url = new URL(urlString);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
    }
    // Prevent localhost/internal IPs for security
    const hostname = url.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
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
      details: err.message
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

    // Check if scan is completed
    if (scan.status !== 'completed') {
      return res.status(400).json({
        error: 'Scan not completed',
        message: `Scan is currently ${scan.status}. Only completed scans can be loaded.`,
        status: scan.status
      });
    }

    // Build response object similar to combined-analysis response
    const response = {
      success: true,
      isHistorical: true,
      analysisId: scan.analysisId,
      target: scan.target,
      status: scan.status,
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

    // Add ZAP results with GridFS data if available
    if (scan.zapResult) {
      response.zapData = { ...scan.zapResult };

      // Fetch detailed alerts from GridFS if available
      if (scan.zapResult.reportFiles && Array.isArray(scan.zapResult.reportFiles)) {
        const detailedAlertsFile = scan.zapResult.reportFiles.find(
          f => f.filename && f.filename.includes('detailed_alerts')
        );
        if (detailedAlertsFile && detailedAlertsFile.fileId) {
          try {
            // Auth scan files are stored in zap_auth_reports bucket, normal in zap_reports
            const bucket = (detailedAlertsFile.filename && detailedAlertsFile.filename.includes('zap_auth'))
              ? 'zap_auth_reports' : 'zap_reports';
            const buffer = await gridfsService.downloadFile(detailedAlertsFile.fileId, bucket);
            response.zapData.detailedAlerts = JSON.parse(buffer.toString('utf-8'));
          } catch (gridfsErr) {
            console.warn(`[LoadScan] Could not fetch ZAP detailed alerts: ${gridfsErr.message}`);
          }
        }
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

    console.log(`📜 Loaded historical scan: ${analysisId} for user ${req.user.id}`);
    res.json(response);

  } catch (err) {
    console.error('❌ Load scan error:', err.message);
    res.status(500).json({
      error: 'Failed to load scan',
      details: err.message
    });
  }
});

// 4.5️⃣ Get user's active/in-progress scan OR recently completed scan (Protected route)
// This is used to resume scans after page refresh or browser restart
// Also returns recently completed scans so user can see results after returning
router.get('/active-scan', auth, async (req, res) => {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    // First, check for in-progress scans (highest priority)
    let activeScan = await ScanResult.findOne({
      userId: req.user.id,
      status: { $in: ['queued', 'pending', 'combining'] },
      // If a stop was requested, don't ever resume it as an "active" scan.
      // This protects against partial updates where overall status wasn't flipped to 'stopped'.
      'zapResult.status': { $nin: ['stopped', 'cancelled'] },
      'webCheckResult.status': { $nin: ['stopped', 'cancelled'] },
      createdAt: { $gte: twentyFourHoursAgo }
    }).sort({ createdAt: -1 });

    // If no in-progress scan, check for recently completed scan (within last hour)
    // This handles the case where scan completed while user was away
    if (!activeScan) {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      activeScan = await ScanResult.findOne({
        userId: req.user.id,
        status: 'completed',
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

    // Extract key metrics for the response (same as combined-analysis)
    const lighthouseResult = activeScan.pagespeedResult?.lighthouseResult || {};
    const categories = lighthouseResult.categories || {};

    const psiScores = activeScan.pagespeedResult && !activeScan.pagespeedResult.error ? {
      performance: categories.performance?.score ? Math.round(categories.performance.score * 100) : null,
      accessibility: categories.accessibility?.score ? Math.round(categories.accessibility.score * 100) : null,
      bestPractices: categories['best-practices']?.score ? Math.round(categories['best-practices'].score * 100) : null,
      seo: categories.seo?.score ? Math.round(categories.seo.score * 100) : null
    } : null;

    const observatoryData = activeScan.observatoryResult && !activeScan.observatoryResult.error ? {
      grade: activeScan.observatoryResult.grade,
      score: activeScan.observatoryResult.score,
      tests_passed: activeScan.observatoryResult.tests_passed,
      tests_failed: activeScan.observatoryResult.tests_failed,
      tests_quantity: activeScan.observatoryResult.tests_quantity
    } : null;

    // ZAP data handling - match structure with /combined-analysis endpoint
    let zapData = null;
    if (activeScan.zapResult) {
      const zapStatus = activeScan.zapResult.status;
      if (zapStatus === 'completed') {
        zapData = {
          status: 'completed',
          riskCounts: activeScan.zapResult.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 },
          alerts: activeScan.zapResult.alerts || [],
          totalAlerts: activeScan.zapResult.totalAlerts || activeScan.zapResult.alerts?.length || 0,
          totalOccurrences: activeScan.zapResult.totalOccurrences || 0,
          reportFiles: activeScan.zapResult.reportFiles || [],
          site: activeScan.zapResult.site || activeScan.target,
          urlsFound: activeScan.zapResult.urlsFound || 0
        };
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
      details: err.message
    });
  }
});

// 5️⃣ Combined URL Scan (PageSpeed + Observatory + ZAP + WebCheck + urlscan + Gemini)
// Auth → Plan enforcement → Rate limiting → Handler
router.post('/combined-url-scan', auth, planCheck, combinedScanLimiter, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Validate URL format and security
    const validation = isValidUrl(url);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    console.log(`🔐 User ${req.user.id} submitted URL for combined scan: ${url}`);

    // Generate unique analysis ID
    const analysisId = crypto.randomUUID();
    console.log(`🔑 Analysis ID: ${analysisId}`);

    // Create new scan record - ready to start combining immediately
    const scan = new ScanResult({
      target: url,
      analysisId: analysisId,
      status: 'combining',
      userId: req.user.id
    });
    await scan.save();
    console.log('📝 Scan record created');

    res.json({
      success: true,
      message: 'URL submitted for combined analysis',
      analysisId: analysisId,
      url: url
    });
  } catch (err) {
    console.error('❌ Combined URL scan error:', err);
    // Graceful error handling for duplicates if race condition occurs
    if (err.code === 11000) {
      return res.status(409).json({ error: "Scan already in progress. Please wait a moment and try again." });
    }
    res.status(500).json({
      error: 'Failed to initiate combined scan',
      details: err.message
    });
  }
});

// 6️⃣ Combined Analysis Polling (Protected route)
router.get('/combined-analysis/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: 'Analysis ID is required' });
    }

    console.log(`📊 Fetching combined analysis for ID: ${id}`);

    // Find the scan in database
    let scan = await ScanResult.findOne({ analysisId: id, userId: req.user.id });

    if (!scan) {
      return res.status(404).json({
        error: 'Analysis not found in database'
      });
    }

    // If the scan was explicitly stopped/cancelled, never restart work on polling.
    // This route is called repeatedly by the frontend and must be idempotent.
    if (['stopped', 'cancelled'].includes(scan.status)) {
      return res.json({
        status: scan.status,
        message: 'Scan was stopped by user',
        analysisId: id,
        target: scan.target,
        pagespeedResult: scan.pagespeedResult || null,
        observatoryResult: scan.observatoryResult || null,
        urlscanResult: scan.urlscanResult || null,
        zapResult: scan.zapResult || null,
        webCheckResult: scan.webCheckResult || null,
        refinedReport: scan.refinedReport || null,
        createdAt: scan.createdAt,
        updatedAt: scan.updatedAt
      });
    }

    // Secondary guard: if background components were stopped, do not restart them.
    if (['stopped', 'cancelled'].includes(scan.zapResult?.status) || ['stopped', 'cancelled'].includes(scan.webCheckResult?.status)) {
      return res.json({
        status: 'stopped',
        message: 'Scan was stopped by user',
        analysisId: id,
        target: scan.target,
        pagespeedResult: scan.pagespeedResult || null,
        observatoryResult: scan.observatoryResult || null,
        urlscanResult: scan.urlscanResult || null,
        zapResult: scan.zapResult || null,
        webCheckResult: scan.webCheckResult || null,
        refinedReport: scan.refinedReport || null,
        createdAt: scan.createdAt,
        updatedAt: scan.updatedAt
      });
    }

    // STEP A: Check if we need to run scans (PSI, Observatory, ZAP, urlscan, WebCheck, Gemini)
    // ONLY trigger scans if they haven't been started yet (not just checking for results)
    const needsScanning = (
      !scan.pagespeedResult ||
      !scan.observatoryResult ||
      !scan.urlscanResult ||
      !scan.refinedReport
    );

    // Check if ZAP scan needs to be started (only start once)
    const zapNotStarted = !scan.zapResult || (!scan.zapResult.status && !scan.zapResult.error);

    // Check if WebCheck scan needs to be started (only start once)
    const webCheckNotStarted = !scan.webCheckResult || (!scan.webCheckResult.status && !scan.webCheckResult.error);

    if (needsScanning || zapNotStarted || webCheckNotStarted) {
      console.log('🔄 Running PageSpeed, Observatory, ZAP, WebCheck, urlscan and Gemini analysis...');

      try {
        // Update status to combining (durable cancellation: do not overwrite stopped scans)
        const statusUpdate = await ScanResult.updateOne(
          { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
          { $set: { status: 'combining', updatedAt: new Date() } }
        );

        if (statusUpdate.modifiedCount === 0) {
          // Likely stopped in parallel by user; re-fetch and return without restarting work
          const latest = await ScanResult.findOne({ analysisId: id, userId: req.user.id });
          if (latest && ['stopped', 'cancelled'].includes(latest.status)) {
            return res.json({
              status: latest.status,
              message: 'Scan was stopped by user',
              analysisId: id,
              target: latest.target,
              pagespeedResult: latest.pagespeedResult || null,
              observatoryResult: latest.observatoryResult || null,
              urlscanResult: latest.urlscanResult || null,
              zapResult: latest.zapResult || null,
              webCheckResult: latest.webCheckResult || null,
              refinedReport: latest.refinedReport || null,
              createdAt: latest.createdAt,
              updatedAt: latest.updatedAt
            });
          }
        }

        // CRITICAL CHANGE: Run fast scans in parallel, ZAP and WebCheck run asynchronously
        // Both ZAP and WebCheck will update database independently when complete
        console.log('🚀 Fetching PageSpeed, Observatory and urlscan reports in parallel...');
        console.log('🚀 Starting ZAP and WebCheck scans asynchronously in background...');

        // Extract hostname for Observatory
        const hostname = new URL(scan.target).hostname;
        console.log(`🔍 Scanning hostname: ${hostname}`);

        // Execute fast scans in parallel, start ZAP and WebCheck asynchronously ONLY if needed
        // Both return immediately with "pending/running" status
        const scanPromises = [];

        if (!scan.pagespeedResult) {
          scanPromises.push(getPageSpeedReport(scan.target));
        } else {
          scanPromises.push(Promise.resolve(scan.pagespeedResult));
        }

        if (!scan.observatoryResult) {
          scanPromises.push(scanHost(hostname));
        } else {
          scanPromises.push(Promise.resolve(scan.observatoryResult));
        }

        if (!scan.urlscanResult) {
          scanPromises.push(runUrlScan(scan.target));
        } else {
          scanPromises.push(Promise.resolve(scan.urlscanResult));
        }

        // Always call startAsyncZapScan - it returns current DB status
        // (whether running, completed, or needs to start fresh)
        if (zapNotStarted) {
          console.log('🚀 Starting ZAP scan for the FIRST time...');
        } else {
          console.log('🔄 Checking ZAP scan status...');
        }
        scanPromises.push(startAsyncZapScan(scan.target, scan.analysisId, req.user.id));

        // Always call startAsyncWebCheckScan - it returns current DB status
        // (whether running, completed, or needs to start fresh)
        if (webCheckNotStarted) {
          console.log('🚀 Starting WebCheck scan for the FIRST time...');
        } else {
          console.log('🔄 Checking WebCheck scan status...');
        }
        scanPromises.push(startAsyncWebCheckScan(scan.target, scan.analysisId, req.user.id));

        const [psiResult, obsResult, urlscanResult, zapInitResult, webCheckInitResult] = await Promise.allSettled(scanPromises);

        // Handle PageSpeed result
        let psiReport = null;
        if (psiResult.status === 'fulfilled') {
          psiReport = psiResult.value;
          scan.pagespeedResult = psiReport;
          console.log('✅ PageSpeed report fetched successfully');
        } else {
          console.error('⚠️  PageSpeed scan failed:', psiResult.reason);
          console.error('⚠️  Error details:', psiResult.reason?.message);
          // Store error gracefully - don't fail entire scan
          scan.pagespeedResult = { error: psiResult.reason?.message || 'PageSpeed scan failed' };
        }

        // Handle Observatory result
        let observatoryReport = null;
        if (obsResult.status === 'fulfilled') {
          observatoryReport = obsResult.value;
          scan.observatoryResult = observatoryReport;
          console.log('✅ Observatory scan result:', observatoryReport);
        } else {
          console.error('⚠️  Observatory scan failed:', obsResult.reason);
          console.error('⚠️  Error details:', obsResult.reason?.message);
          // Continue even if Observatory fails - it's not critical
          scan.observatoryResult = { error: obsResult.reason?.message || 'Observatory scan failed' };
        }

        // Handle ZAP initialization result
        // ZAP scan is running in background, so we just store the initial "pending" status
        if (zapInitResult.status === 'fulfilled') {
          const zapInit = zapInitResult.value;
          scan.zapResult = zapInit; // Store pending status
          console.log('✅ ZAP scan started in background:', zapInit.status);
        } else {
          console.error('⚠️  ZAP scan failed to start:', zapInitResult.reason);
          console.error('⚠️  Error details:', zapInitResult.reason?.message);
          // Store error if ZAP failed to start
          scan.zapResult = {
            status: 'failed',
            error: zapInitResult.reason?.message || 'ZAP scan failed to start'
          };
        }

        // Handle urlscan result
        let urlscanReport = null;
        if (urlscanResult.status === 'fulfilled') {
          urlscanReport = urlscanResult.value;
          scan.urlscanResult = urlscanReport;
          console.log('✅ urlscan completed:', urlscanReport?.verdicts?.overall?.malicious ? 'MALICIOUS' : 'Clean');
        } else {
          console.error('⚠️  urlscan failed:', urlscanResult.reason);
          console.error('⚠️  Error details:', urlscanResult.reason?.message);
          // Continue even if urlscan fails - it's not critical
          scan.urlscanResult = { error: urlscanResult.reason?.message || 'urlscan failed or not available' };
        }

        // Handle WebCheck initialization result
        // WebCheck scans run in background, so we just store the initial "running" status
        if (webCheckInitResult.status === 'fulfilled') {
          const webCheckInit = webCheckInitResult.value;
          scan.webCheckResult = webCheckInit; // Store running status
          console.log('✅ WebCheck scan started in background:', webCheckInit.status);
        } else {
          console.error('⚠️  WebCheck scan failed to start:', webCheckInitResult.reason);
          console.error('⚠️  Error details:', webCheckInitResult.reason?.message);
          // Store error if WebCheck failed to start
          scan.webCheckResult = {
            status: 'failed',
            error: webCheckInitResult.reason?.message || 'WebCheck scan failed to start'
          };
        }

        // Save results so far (PSI, Observatory, urlscan complete, ZAP and WebCheck pending)
        // CRITICAL: Use $set to update only specific fields, NOT the entire document
        // This prevents overwriting zapResult/webCheckResult that background scans may have updated
        const fastUpdate = await ScanResult.updateOne(
          { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
          {
            $set: {
              status: 'combining',
              pagespeedResult: scan.pagespeedResult,
              observatoryResult: scan.observatoryResult,
              urlscanResult: scan.urlscanResult,
              // Only set initial zapResult if it was just started (not if it's already running/completed)
              ...(zapNotStarted && scan.zapResult ? { zapResult: scan.zapResult } : {}),
              // Only set initial webCheckResult if it was just started
              ...(webCheckNotStarted && scan.webCheckResult ? { webCheckResult: scan.webCheckResult } : {}),
              updatedAt: new Date()
            }
          }
        );

        if (fastUpdate.modifiedCount === 0) {
          const latest = await ScanResult.findOne({ analysisId: id, userId: req.user.id });
          if (latest && ['stopped', 'cancelled'].includes(latest.status)) {
            return res.json({
              status: latest.status,
              message: 'Scan was stopped by user',
              analysisId: id,
              target: latest.target,
              pagespeedResult: latest.pagespeedResult || null,
              observatoryResult: latest.observatoryResult || null,
              urlscanResult: latest.urlscanResult || null,
              zapResult: latest.zapResult || null,
              webCheckResult: latest.webCheckResult || null,
              refinedReport: latest.refinedReport || null,
              createdAt: latest.createdAt,
              updatedAt: latest.updatedAt
            });
          }
        }
        console.log('✅ Fast scans complete (PSI, Observatory, urlscan). ZAP and WebCheck running in background.');

        // CRITICAL: Re-fetch the scan from DB to get the latest zapResult/webCheckResult
        // Background scans may have completed while we were processing fast scans
        scan = await ScanResult.findOne({ analysisId: id, userId: req.user.id });
        if (!scan) {
          return res.status(404).json({ error: 'Scan not found after update' });
        }

        // DON'T generate Gemini report yet - wait for ZAP to complete
        // Frontend will poll and we'll check ZAP status on next request
      } catch (combineError) {
        console.error('❌ Error in combining step:', combineError);
        // Use atomic update for error case to avoid overwriting background scan progress
        await ScanResult.updateOne(
          { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
          {
            $set: {
              status: 'failed',
              updatedAt: new Date()
            }
          }
        );
        scan.status = 'failed';

        return res.status(500).json({
          error: 'Failed to complete combined analysis',
          details: combineError.message
        });
      }
    }

    // STEP C: Check if ZAP and WebCheck are complete and generate Gemini report
    // This runs on EVERY poll request until Gemini report is generated

    // Stale scan watchdog: if a background scan has been "running" too long, mark it as failed
    const ZAP_STALE_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 24 hours
    const WEBCHECK_STALE_TIMEOUT_MS = 6 * 60 * 60 * 1000; // 6 hours
    const now = Date.now();

    if (scan.zapResult?.startedAt && !['completed', 'completed_partial', 'failed'].includes(scan.zapResult.status)) {
      const zapAge = now - new Date(scan.zapResult.startedAt).getTime();
      if (zapAge > ZAP_STALE_TIMEOUT_MS) {
        console.error(`❌ ZAP scan timed out (running for ${Math.round(zapAge / 60000)}min). Failing entire scan.`);
        await ScanResult.updateOne(
          { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
          { $set: { 'zapResult.status': 'failed', 'zapResult.error': 'Scan timed out (exceeded 24 hour limit)', 'zapResult.phase': 'failed', status: 'failed', updatedAt: new Date() } }
        );
        scan.zapResult.status = 'failed';
        scan.status = 'failed';
      }
    }

    if (scan.webCheckResult?.startedAt && !['completed', 'completed_partial', 'completed_with_errors', 'failed'].includes(scan.webCheckResult.status)) {
      const wcAge = now - new Date(scan.webCheckResult.startedAt).getTime();
      if (wcAge > WEBCHECK_STALE_TIMEOUT_MS) {
        console.error(`❌ WebCheck scan timed out (running for ${Math.round(wcAge / 60000)}min). Failing entire scan.`);
        await ScanResult.updateOne(
          { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
          { $set: { 'webCheckResult.status': 'failed', 'webCheckResult.error': 'Scan timed out (exceeded 6 hour limit)', status: 'failed', updatedAt: new Date() } }
        );
        scan.webCheckResult.status = 'failed';
        scan.status = 'failed';
      }
    }

    // If entire scan was failed by watchdog, return immediately
    if (scan.status === 'failed') {
      return res.json({ status: 'failed', error: 'Background scan timed out. Please try again.', target: scan.target, analysisId: id });
    }

    const zapStatus = scan.zapResult?.status;
    const hasZapCompleted = zapStatus === 'completed' || zapStatus === 'completed_partial';
    const hasZapFailed = zapStatus === 'failed';
    const zapIsDone = hasZapCompleted || hasZapFailed;

    // Check WebCheck status
    const webCheckStatus = scan.webCheckResult?.status;
    const hasWebCheckCompleted = webCheckStatus === 'completed' || webCheckStatus === 'completed_partial' || webCheckStatus === 'completed_with_errors';
    const hasWebCheckFailed = webCheckStatus === 'failed';
    const webCheckIsDone = hasWebCheckCompleted || hasWebCheckFailed;

    // If either ZAP or WebCheck failed entirely, fail the whole scan
    if ((hasZapFailed || hasWebCheckFailed) && !scan.refinedReport) {
      const failedParts = [];
      if (hasZapFailed) failedParts.push(`ZAP: ${scan.zapResult?.error || 'unknown error'}`);
      if (hasWebCheckFailed) failedParts.push(`WebCheck: ${scan.webCheckResult?.error || 'unknown error'}`);
      console.error(`❌ Background scan(s) failed: ${failedParts.join(', ')}. Failing entire scan.`);
      await ScanResult.updateOne(
        { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
        { $set: { status: 'failed', updatedAt: new Date() } }
      );
      scan.status = 'failed';
      return res.json({ status: 'failed', error: `Scan failed: ${failedParts.join('; ')}`, target: scan.target, analysisId: id });
    }

    // If ZAP AND WebCheck are done AND we don't have Gemini report yet, generate it now
    if (zapIsDone && webCheckIsDone && !scan.refinedReport && scan.pagespeedResult && scan.observatoryResult) {
      if (geminiInProgress.has(id)) {
        console.log('🤖 Gemini report already being generated for this scan, skipping...');
      } else {
        geminiInProgress.add(id);
        console.log('🤖 ZAP and WebCheck scans finished! Generating Gemini AI report with ALL scan data...');

        // CRITICAL: Fresh refetch to ensure we have the absolute latest data
        // This prevents race conditions where background scans completed after our last read
        const freshScan = await ScanResult.findOne({ analysisId: id, userId: req.user.id });
        if (!freshScan) {
          geminiInProgress.delete(id);
          console.error('❌ Scan not found during Gemini generation');
          return res.status(404).json({ error: 'Scan not found' });
        }

        // Use fresh data for Gemini generation
        const freshZapResult = freshScan.zapResult;
        const freshWebCheckResult = freshScan.webCheckResult;

        console.log(`📊 Fresh data check - ZAP status: ${freshZapResult?.status}, WebCheck status: ${freshWebCheckResult?.status}`);
        console.log(`📊 WebCheck fullResults exists: ${!!freshWebCheckResult?.fullResults}, keys: ${freshWebCheckResult?.fullResults ? Object.keys(freshWebCheckResult.fullResults).length : 0}`);

        if (freshZapResult?.status === 'completed_partial') {
          console.log('⚠️ Note: ZAP scan completed with partial results');
        }
        if (freshWebCheckResult?.status === 'completed_partial' || freshWebCheckResult?.status === 'completed_with_errors') {
          console.log('⚠️ Note: WebCheck scan completed with partial results or errors');
        }

        try {
          // Prepare data for Gemini (with or without ZAP results depending on success)
          const psiReport = freshScan.pagespeedResult?.error ? null : freshScan.pagespeedResult;
          const observatoryReport = freshScan.observatoryResult?.error ? null : freshScan.observatoryResult;
          const urlscanReport = freshScan.urlscanResult?.error ? null : freshScan.urlscanResult;

          // Include ZAP data if scan completed (fully or partially)
          const freshZapStatus = freshZapResult?.status;
          const freshZapCompleted = freshZapStatus === 'completed' || freshZapStatus === 'completed_partial';
          const zapReport = freshZapCompleted ? {
            site: freshScan.target,
            riskCounts: freshZapResult.riskCounts,
            alerts: freshZapResult.alerts,
            totalAlerts: freshZapResult.totalAlerts,
            totalOccurrences: freshZapResult.totalOccurrences
          } : null;

          // Include WebCheck data if scan completed (fully or partially)
          const freshWebCheckStatus = freshWebCheckResult?.status;
          const freshWebCheckCompleted = freshWebCheckStatus === 'completed' || freshWebCheckStatus === 'completed_partial' || freshWebCheckStatus === 'completed_with_errors';

          // Use getFullResults to handle both inline and GridFS storage
          let webCheckReport = null;
          if (freshWebCheckCompleted) {
            webCheckReport = await getFullResults(freshWebCheckResult);
            if (!webCheckReport) {
              console.warn('⚠️ WebCheck marked complete but could not retrieve results');
            } else {
              console.log(`📊 WebCheck results retrieved: ${Object.keys(webCheckReport).length} scan types`);
            }
          }

          // Generate AI report with all available data
          const aiReport = await refineReport(
            null,
            psiReport,
            observatoryReport,
            freshScan.target,
            zapReport,
            urlscanReport,
            webCheckReport
          );

          // Use atomic update for final completion to avoid race conditions
          await ScanResult.updateOne(
            { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
            {
              $set: {
                refinedReport: aiReport,
                status: 'completed',
                updatedAt: new Date()
              }
            }
          );
          // Update local scan object for response
          scan.refinedReport = aiReport;
          scan.status = 'completed';

          // Trigger notification (email + UI popup)
          handleScanComplete(id, req.user.id, 'Combined Security Scan', scan.target);

          console.log('✅ Gemini AI report generated with all scan data!');
          console.log(`   Included ZAP data: ${zapReport ? 'Yes' : 'No (scan not completed)'}`);
          console.log(`   Included WebCheck data: ${webCheckReport ? `Yes (${Object.keys(webCheckReport).length} scan types)` : 'No (fullResults missing)'}`);
        } catch (geminiError) {
          console.error('⚠️  Gemini AI report generation failed:', geminiError.message);
          // Store fallback message using atomic update
          const fallbackReport = `AI analysis temporarily unavailable due to high demand. Please try again later.\n\nError: ${geminiError.message}`;
          await ScanResult.updateOne(
            { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
            {
              $set: {
                refinedReport: fallbackReport,
                status: 'completed',
                updatedAt: new Date()
              }
            }
          );
          // Update local scan object for response
          scan.refinedReport = fallbackReport;
          scan.status = 'completed';

          // Trigger notification (email + UI popup)
          handleScanComplete(id, req.user.id, 'Combined Security Scan', scan.target);
        } finally {
          geminiInProgress.delete(id);
        }
      }
    } else if (zapIsDone && webCheckIsDone && !scan.refinedReport) {
      // FALLBACK: Both ZAP and WebCheck done but can't generate AI report (missing PageSpeed/Observatory)
      if (!scan.pagespeedResult || !scan.observatoryResult) {
        console.log('⚠️ ZAP & WebCheck finished but cannot generate AI report - missing required scan data');
        console.log(`   PageSpeed: ${scan.pagespeedResult ? 'Available' : 'MISSING'}`);
        console.log(`   Observatory: ${scan.observatoryResult ? 'Available' : 'MISSING'}`);

        const fallbackReport = 'AI analysis could not be generated - some scan data was unavailable. Please view individual scan results below.';
        await ScanResult.updateOne(
          { analysisId: id, userId: req.user.id, status: { $nin: ['stopped', 'cancelled'] } },
          {
            $set: {
              refinedReport: fallbackReport,
              status: 'completed',
              updatedAt: new Date()
            }
          }
        );
        scan.refinedReport = fallbackReport;
        scan.status = 'completed';
        console.log('✅ Scan marked as completed (without full AI report)');

        // Trigger notification (email + UI popup)
        handleScanComplete(id, req.user.id, 'Combined Security Scan', scan.target);
      }
    } else if (!zapIsDone || !webCheckIsDone) {
      // Still waiting for ZAP or WebCheck to finish
      console.log(`⏳ Waiting for background scans: ZAP=${zapIsDone ? 'done' : 'running'}, WebCheck=${webCheckIsDone ? 'done' : 'running'}`);
    }

    // STEP D: Return results (partial or complete)
    // Extract key metrics for easy access - even for partial results
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

    // ZAP data handling - support pending/running/completed/failed states
    let zapData = null;
    if (scan.zapResult) {
      const zapStatus = scan.zapResult.status;

      if (zapStatus === 'completed') {
        // ZAP scan completed successfully
        zapData = {
          status: 'completed',
          riskCounts: scan.zapResult.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 },
          alerts: scan.zapResult.alerts || [],
          totalAlerts: scan.zapResult.totalAlerts || scan.zapResult.alerts?.length || 0,
          totalOccurrences: scan.zapResult.totalOccurrences || 0,
          reportFiles: scan.zapResult.reportFiles || [],
          site: scan.zapResult.site || scan.target
        };
      } else if (zapStatus === 'pending' || zapStatus === 'running') {
        // ZAP scan in progress - show progress info
        zapData = {
          status: zapStatus,
          phase: scan.zapResult.phase || 'queued',
          progress: scan.zapResult.progress || 0,
          message: scan.zapResult.message || 'ZAP scan in progress...',
          urlsFound: scan.zapResult.urlsFound || 0,
          alertsFound: scan.zapResult.alertsFound || 0
        };
      } else if (zapStatus === 'failed') {
        // ZAP scan failed
        zapData = {
          status: 'failed',
          error: scan.zapResult.error || 'ZAP scan failed',
          message: scan.zapResult.message || 'Vulnerability scan encountered an error'
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

    // WebCheck data handling - support running/completed/failed states
    let webCheckData = null;
    if (scan.webCheckResult) {
      const webCheckStatus = scan.webCheckResult.status;

      if (webCheckStatus === 'completed' || webCheckStatus === 'completed_with_errors' || webCheckStatus === 'completed_partial') {
        // WebCheck scans completed (possibly with some errors)
        // Try to get full results (handles both inline and GridFS storage)
        let webCheckResults = scan.webCheckResult.fullResults;
        if (!webCheckResults && scan.webCheckResult.resultsFileId) {
          // Results in GridFS - fetch them
          try {
            webCheckResults = await getFullResults(scan.webCheckResult);
          } catch (e) {
            console.warn('Failed to fetch WebCheck results from GridFS:', e.message);
          }
        }
        // Fallback to summary if full results not available
        if (!webCheckResults) {
          webCheckResults = scan.webCheckResult.summary || {};
        }

        webCheckData = {
          status: webCheckStatus,
          results: webCheckResults,
          summary: scan.webCheckResult.summary || {},
          completedScans: scan.webCheckResult.completedScans || 0,
          totalScans: scan.webCheckResult.totalScans || 30,
          hasErrors: scan.webCheckResult.hasErrors || false,
          duration: scan.webCheckResult.duration || 0
        };
      } else if (webCheckStatus === 'uploading') {
        // WebCheck scans complete, uploading large results to GridFS
        webCheckData = {
          status: 'uploading',
          progress: 100, // Scans are done
          uploadProgress: scan.webCheckResult.uploadProgress || 0,
          completedScans: scan.webCheckResult.completedScans || scan.webCheckResult.totalScans,
          totalScans: scan.webCheckResult.totalScans || 30,
          message: scan.webCheckResult.message || 'Uploading results to storage...'
        };
      } else if (webCheckStatus === 'running' || webCheckStatus === 'pending') {
        // WebCheck scan in progress - show progress info
        webCheckData = {
          status: 'running',
          progress: scan.webCheckResult.progress || 0,
          completedScans: scan.webCheckResult.completedScans || 0,
          totalScans: scan.webCheckResult.totalScans || 30,
          message: scan.webCheckResult.message || 'WebCheck scans in progress...',
          partialResults: scan.webCheckResult.partialResults || {}
        };
      } else if (webCheckStatus === 'failed') {
        // WebCheck scan failed
        webCheckData = {
          status: 'failed',
          error: scan.webCheckResult.error || 'WebCheck scan failed',
          message: scan.webCheckResult.message || 'WebCheck encountered an error'
        };
      }
    }

    // ─── Vulnerability filtering based on user's plan ──────────────────────────
    // Load user to check vulnerability access level (use req.user.id from auth middleware).
    // This is a lightweight findById — only select planType + billingCycle.
    let vulnAccessLevel = 'all';
    try {
      const scanUser = await User.findById(req.user.id).select('planType billingCycle accountType proExpiresAt');
      if (scanUser) {
        const scanLimits = scanUser.getAccountLimits();
        vulnAccessLevel = scanLimits.vulnerabilityAccessLevel || 'all';
      }
    } catch (_) { /* non-fatal — default to 'all' */ }

    // Always return all available data (progressive loading)
    console.log(`📤 Returning combined-analysis response:`);
    console.log(`   Status: ${scan.status}`);
    console.log(`   Vuln access level: ${vulnAccessLevel}`);
    console.log(`   Has refinedReport: ${!!scan.refinedReport}`);
    if (scan.refinedReport) {
      console.log(`   refinedReport length: ${scan.refinedReport.length} chars`);
    }

    // Apply filter (does nothing when accessLevel === 'all')
    const filteredZapData = filterZapAlertsByPlan(zapData, vulnAccessLevel);

    return res.json({
      success: true,
      status: scan.status,
      analysisId: id,
      target: scan.target,
      // Partial data indicators
      hasPsiResult: !!scan.pagespeedResult,
      hasObservatoryResult: !!scan.observatoryResult,
      hasZapResult: !!scan.zapResult && (scan.zapResult.status === 'completed' || scan.zapResult.status === 'completed_partial'),
      zapPending: !!scan.zapResult && (scan.zapResult.status === 'pending' || scan.zapResult.status === 'running'),
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
      zapResult: scan.zapResult || null,
      urlscanResult: scan.urlscanResult || null,
      webCheckResult: scan.webCheckResult || null,
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt
    });

  } catch (err) {
    console.error('❌ Combined analysis retrieval error:', err);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({
      error: 'Failed to retrieve combined analysis',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
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

    // Fetch full ZAP detailed alerts from GridFS (not truncated)
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
          fullZapAlerts = JSON.parse(detailedAlertsBuffer.toString('utf-8'));
          console.log(`✅ Retrieved ${fullZapAlerts.length} full ZAP alerts from GridFS`);
        } catch (gridfsError) {
          console.warn(`⚠️ Failed to fetch ZAP alerts from GridFS: ${gridfsError.message}`);
          // Fallback to truncated alerts from MongoDB
          fullZapAlerts = scan.zapResult?.alerts || [];
        }
      } else {
        fullZapAlerts = scan.zapResult?.alerts || [];
      }
    } else {
      fullZapAlerts = scan.zapResult?.alerts || [];
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
      details: err.message
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
      details: err.message
    });
  }
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

    // Check if scan is complete
    if (scan.status !== 'completed') {
      return res.status(400).json({
        error: 'Scan is not yet complete. Please wait for all scans to finish.',
        status: scan.status
      });
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
    console.log(`📄 Generating ${lang.toUpperCase()} PDF report...`);
    const pdfBuffer = await generateSingleLanguagePdf(scan, lang);

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
      details: err.message
    });
  }
});

module.exports = router;