const express = require('express');
const crypto = require('crypto');
const { runZapScan, stopCombinedScan } = require('../services/zapService');
const { stopWebCheckScan, getFullResults } = require('../services/webCheckService');
const gridfsService = require('../services/gridfsService');
const { generatePdfReport, generateSingleLanguagePdf } = require('../services/pdfService');
const ScanResult = require('../models/ScanResult');
const auth = require('../middleware/auth');
const { combinedScanLimiter } = require('../middleware/rateLimiter');
const { addScanJob } = require('../queues/scanQueue');
const { getPublisher } = require('../config/redis');

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
      details: devMsg(err)
    });
  }
});

// 5️⃣ Combined URL Scan — creates DB record, enqueues BullMQ job, returns immediately
router.post('/combined-url-scan', auth, combinedScanLimiter, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
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
      userId: req.user.id
    }).save();

    // Enqueue the scan job — BullMQ worker picks it up and runs all scanners
    await addScanJob(analysisId, url, req.user.id);
    console.log(`📬 Scan job enqueued for ${analysisId}`);

    res.json({
      success: true,
      message: 'Scan queued — you will receive real-time updates via WebSocket',
      analysisId,
      url
    });
  } catch (err) {
    console.error('❌ Combined URL scan error:', err);
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
    const lighthouseResult = scan.pagespeedResult?.lighthouseResult || {};
    const categories = lighthouseResult.categories || {};
    const psiScores = scan.pagespeedResult && !scan.pagespeedResult.error ? {
      performance:   categories.performance?.score   != null ? Math.round(categories.performance.score * 100)   : null,
      accessibility: categories.accessibility?.score  != null ? Math.round(categories.accessibility.score * 100)  : null,
      bestPractices: categories['best-practices']?.score != null ? Math.round(categories['best-practices'].score * 100) : null,
      seo:           categories.seo?.score            != null ? Math.round(categories.seo.score * 100)            : null
    } : null;

    const observatoryData = scan.observatoryResult && !scan.observatoryResult.error ? {
      grade: scan.observatoryResult.grade, score: scan.observatoryResult.score,
      tests_passed: scan.observatoryResult.tests_passed, tests_failed: scan.observatoryResult.tests_failed,
      tests_quantity: scan.observatoryResult.tests_quantity
    } : null;

    let zapData = null;
    if (scan.zapResult) {
      const zs = scan.zapResult.status;
      if (zs === 'completed' || zs === 'completed_partial') {
        zapData = { status: zs,
          riskCounts: scan.zapResult.riskCounts || {}, alerts: scan.zapResult.alerts || [],
          totalAlerts: scan.zapResult.totalAlerts || 0, totalOccurrences: scan.zapResult.totalOccurrences || 0,
          reportFiles: scan.zapResult.reportFiles || [], site: scan.zapResult.site || scan.target,
          urlsFound: scan.zapResult.urlsFound || 0 };
      } else if (zs === 'pending' || zs === 'running') {
        zapData = { status: zs, phase: scan.zapResult.phase || 'queued', progress: scan.zapResult.progress || 0,
          message: scan.zapResult.message || 'ZAP scan in progress...', urlsFound: scan.zapResult.urlsFound || 0,
          alertsFound: scan.zapResult.alertsFound || 0 };
      } else if (zs === 'failed') {
        zapData = { status: 'failed', error: scan.zapResult.error || 'ZAP scan failed',
          message: scan.zapResult.message || 'Vulnerability scan encountered an error' };
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

    return res.json({
      success: true,
      status: scan.status,
      analysisId: id,
      target: scan.target,
      hasPsiResult:        !!scan.pagespeedResult,
      hasObservatoryResult: !!scan.observatoryResult,
      hasZapResult:        !!scan.zapResult && ['completed','completed_partial'].includes(scan.zapResult.status),
      zapPending:          !!scan.zapResult && ['pending','running'].includes(scan.zapResult.status),
      hasUrlscanResult:    !!scan.urlscanResult && !scan.urlscanResult.error,
      hasWebCheckResult:   !!scan.webCheckResult && ['completed','completed_partial','completed_with_errors'].includes(scan.webCheckResult.status),
      webCheckPending:     !!scan.webCheckResult && scan.webCheckResult.status === 'running',
      hasRefinedReport:    !!scan.refinedReport,
      psiScores, observatoryData, zapData, urlscanData, webCheckData,
      refinedReport:     scan.refinedReport     || null,
      pagespeedResult:   scan.pagespeedResult   || null,
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
//   pdf:job:{jobId}  → JSON metadata  (TTL: PDF_JOB_TTL_S)
//   pdf:buf:{jobId}  → base64 PDF     (TTL: PDF_JOB_TTL_S)
//
// Status lifecycle:  pending → processing → completed | failed
//
// Jobs are NOT deleted on download — TTL handles expiry after 24 hours.

const PDF_JOB_TTL_S = 24 * 60 * 60; // 24 hours

function _pdfMetaKey(jobId) { return `pdf:job:${jobId}`; }
function _pdfBufKey(jobId)  { return `pdf:buf:${jobId}`; }

async function _getPdfMeta(jobId) {
  try {
    const raw = await getPublisher().get(_pdfMetaKey(jobId));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.error(`[PDF] Redis GET meta failed for ${jobId}:`, err.message);
    return null;
  }
}

async function _setPdfMeta(jobId, meta) {
  try {
    await getPublisher().set(_pdfMetaKey(jobId), JSON.stringify(meta), 'EX', PDF_JOB_TTL_S);
  } catch (err) {
    console.error(`[PDF] Redis SET meta failed for ${jobId}:`, err.message);
  }
}

async function _setPdfBuffer(jobId, buffer) {
  try {
    await getPublisher().set(_pdfBufKey(jobId), buffer.toString('base64'), 'EX', PDF_JOB_TTL_S);
  } catch (err) {
    console.error(`[PDF] Redis SET buffer failed for ${jobId}:`, err.message);
  }
}

async function _getPdfBuffer(jobId) {
  try {
    const raw = await getPublisher().get(_pdfBufKey(jobId));
    return raw ? Buffer.from(raw, 'base64') : null;
  } catch (err) {
    console.error(`[PDF] Redis GET buffer failed for ${jobId}:`, err.message);
    return null;
  }
}

// Start async PDF generation — returns a jobId immediately, client polls for result
router.post('/pdf-job', auth, async (req, res) => {
  const { analysisId, lang = 'en' } = req.body || {};
  if (!['en', 'ja'].includes(lang)) {
    return res.status(400).json({ error: 'Invalid language. Use "en" or "ja"' });
  }
  if (!analysisId) return res.status(400).json({ error: 'analysisId is required' });

  const scan = await ScanResult.findOne({ analysisId, userId: req.user.id });
  if (!scan) return res.status(404).json({ error: 'Scan not found or access denied' });

  const hasSomeData = scan.pagespeedResult || scan.observatoryResult || scan.urlscanResult;
  if (!['completed', 'partial_complete'].includes(scan.status) && !hasSomeData) {
    return res.status(400).json({ error: 'Scan is not yet complete', status: scan.status });
  }

  const jobId = crypto.randomUUID();
  const meta = {
    status: 'pending',
    lang,
    analysisId,
    userId: req.user.id,
    createdAt: Date.now(),
  };
  await _setPdfMeta(jobId, meta);
  console.log(`[PDF] Job created  jobId=${jobId} lang=${lang} analysisId=${analysisId}`);

  // Fire-and-forget — update Redis as generation progresses
  (async () => {
    try {
      // Hydrate full WebCheck results from GridFS if needed
      if (scan.webCheckResult && !scan.webCheckResult.fullResults && scan.webCheckResult.resultsFileId) {
        const full = await getFullResults(scan.webCheckResult);
        if (full) scan.webCheckResult.fullResults = full;
      }

      // Mark processing so polls return 202, not 404, during generation
      await _setPdfMeta(jobId, { ...meta, status: 'processing' });
      console.log(`[PDF] Job processing  jobId=${jobId} lang=${lang.toUpperCase()}`);

      const buffer = await generateSingleLanguagePdf(scan, lang);
      const filename = `security_report_${lang.toUpperCase()}_${scan.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;

      // Store buffer then update metadata (order matters — poll checks meta first)
      await _setPdfBuffer(jobId, buffer);
      await _setPdfMeta(jobId, { ...meta, status: 'completed', filename, completedAt: Date.now() });
      console.log(`[PDF] Job completed  jobId=${jobId} bytes=${buffer.length} filename=${filename}`);
    } catch (err) {
      console.error(`[PDF] Job failed  jobId=${jobId} error=${err.message}`);
      await _setPdfMeta(jobId, {
        ...meta,
        status: 'failed',
        error: err.message,
        errorCode: err.code,
        failedAt: Date.now(),
      });
    }
  })();

  res.json({ jobId });
});

// Poll PDF job status / download result
// 202 while pending or processing, 200+PDF when completed, error JSON when failed
router.get('/pdf-job/:jobId', auth, async (req, res) => {
  const { jobId } = req.params;
  console.log(`[PDF] Job status requested  jobId=${jobId} userId=${req.user.id}`);

  const meta = await _getPdfMeta(jobId);

  if (!meta) {
    console.warn(`[PDF] Job expired or not found  jobId=${jobId}`);
    return res.status(404).json({ error: 'Job not found or expired' });
  }

  if (meta.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }

  if (meta.status === 'pending' || meta.status === 'processing') {
    return res.status(202).json({ status: meta.status });
  }

  if (meta.status === 'failed') {
    const code = meta.errorCode === 'GEMINI_KEY_EXHAUSTED' ? 429 : 500;
    return res.status(code).json({ status: 'failed', errorCode: meta.errorCode, error: meta.error });
  }

  // completed — stream PDF from Redis; keep keys alive (no delete, TTL handles expiry)
  if (meta.status === 'completed') {
    const buffer = await _getPdfBuffer(jobId);
    if (!buffer) {
      // Buffer expired before metadata — treat as expired
      console.warn(`[PDF] Job buffer missing  jobId=${jobId}`);
      return res.status(404).json({ error: 'Job not found or expired' });
    }
    console.log(`[PDF] Job served  jobId=${jobId} bytes=${buffer.length}`);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${meta.filename}"`);
    res.setHeader('Content-Length', buffer.length);
    return res.send(buffer);
  }

  // Unknown status — shouldn't happen, but guard defensively
  return res.status(500).json({ status: meta.status, error: 'Unexpected job state' });
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

    // Allow PDF for completed scans and for partial_complete (ZAP failed but other data available).
    // Block only truly in-progress or terminal-failure scans with no usable data.
    const hasSomeData = scan.pagespeedResult || scan.observatoryResult || scan.urlscanResult;
    if (!['completed', 'partial_complete'].includes(scan.status) && !hasSomeData) {
      return res.status(400).json({
        error: 'Scan is not yet complete. Please wait for all scans to finish.',
        status: scan.status
      });
    }
    if (!['completed', 'partial_complete'].includes(scan.status) && hasSomeData) {
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
      details: devMsg(err)
    });
  }
});

module.exports = router;