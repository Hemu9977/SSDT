/**
 * One-time patch script: replace the combined-analysis route body
 * with a clean read-only version (scan triggering moved to BullMQ worker).
 * Run: node backend/scripts/patch_combined_analysis.js
 */
'use strict';
const fs   = require('fs');
const path = require('path');

const FILE = path.resolve(__dirname, '../routes/virustotalRoutes.js');
const src  = fs.readFileSync(FILE, 'utf8');
const lines = src.split('\n');

// Marker lines
const START_MARKER = "// 6️⃣ Combined Analysis";
const END_MARKER   = "// 7️⃣ Download Complete JSON Report";

const startIdx = lines.findIndex(l => l.includes(START_MARKER));
const endIdx   = lines.findIndex(l => l.includes(END_MARKER));

if (startIdx === -1 || endIdx === -1) {
  console.error('Could not find markers. startIdx=%d, endIdx=%d', startIdx, endIdx);
  process.exit(1);
}
console.log('Replacing lines %d–%d (%d lines)', startIdx, endIdx - 1, endIdx - startIdx);

const NEW_HANDLER = `// 6️⃣ Combined Analysis — READ-ONLY fallback endpoint (WebSocket is primary)
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

`;

const before  = lines.slice(0, startIdx);
const after   = lines.slice(endIdx);
const updated = [...before, ...NEW_HANDLER.split('\n'), ...after].join('\n');

fs.writeFileSync(FILE, updated, 'utf8');
console.log('✅ Patched successfully. New line count:', updated.split('\n').length);
