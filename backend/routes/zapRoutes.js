const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimiter');
const {
  checkZapHealth,
  runZapScanWithDB,
  getZapScanStatus
} = require('../services/zapService');
const { requestContainer, releaseContainer } = require('../services/zapContainerManager');
const ScanResult = require('../models/ScanResult');
const gridfsService = require('../services/gridfsService');
const ZapAlert = require('../models/ZapAlert');
const { handleScanComplete } = require('../services/notificationService');

/**
 * Enhanced ZAP Routes - Maximum Performance Scanner
 * Integrates comprehensive ZAP scanning with authentication and rate limiting
 */

// GET /api/zap/health
// Check if ZAP service is healthy
router.get('/health', async (req, res) => {
  try {
    const health = await checkZapHealth();

    if (health.healthy) {
      res.json({
        success: true,
        status: 'healthy',
        version: health.version,
        message: 'ZAP service is running and accessible'
      });
    } else {
      res.status(503).json({
        success: false,
        status: 'unhealthy',
        error: health.error,
        message: 'ZAP service is not available',
        troubleshooting: [
          'Ensure ZAP Docker container is running',
          'Check ZAP is accessible at http://localhost:8080',
          'Verify ZAP_API_KEY is configured correctly'
        ]
      });
    }
  } catch (error) {
    console.error('❌ Health check error:', error);
    res.status(500).json({
      success: false,
      error: 'Health check failed',
      details: error.message
    });
  }
});

// POST /api/zap/scan
// Start a comprehensive ZAP scan (Protected + Rate Limited)
router.post('/scan', auth, scanLimiter, async (req, res) => {
  try {
    const { url, quickMode = false } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'URL is required'
      });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format'
      });
    }

    console.log(`🔐 User ${req.user.id} initiated ZAP scan for: ${url}`);
    console.log(`   Mode: ${quickMode ? 'Quick' : 'Full'}`);

    // Generate scan ID
    const scanId = `zap-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const userId = req.user.id;

    // Create skeleton record immediately so polling shows "queued" during provisioning.
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $setOnInsert: {
          analysisId: scanId,
          userId,
          target: url,
          status: 'queued',
          zapResult: { status: 'provisioning', phase: 'provisioning', progress: 0, alerts: [] },
          createdAt: new Date(),
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );

    // Return immediately — provisioning + scan run in background.
    res.json({
      success: true,
      message: 'ZAP scan initiated',
      scanId,
      analysisId: scanId,
      target: url,
      scanMode: quickMode ? 'quick' : 'full',
      estimatedTime: quickMode ? '5-15 minutes' : '15-60 minutes',
      note: 'Poll /api/zap/status/:scanId for progress updates'
    });

    // Async: provision container → scan → release
    (async () => {
      let zapUrl;
      try {
        const container = await requestContainer(scanId, 'public');
        zapUrl = container.zapUrl;
      } catch (err) {
        console.error(`❌ Container provisioning failed for scan ${scanId}:`, err.message);
        await ScanResult.updateOne(
          { analysisId: scanId },
          { $set: { status: 'failed', 'zapResult.status': 'failed', 'zapResult.error': 'Container provisioning failed', updatedAt: new Date() } }
        );
        return;
      }

      try {
        const result = await runZapScanWithDB(url, userId, { quickMode, scanId, zapUrl });
        console.log(`✅ Scan completed for user ${userId}: ${result.scanId}`);
        handleScanComplete(result.scanId || scanId, userId, 'Public Scan', url);
      } catch (error) {
        console.error(`❌ Scan failed for user ${userId}:`, error.message);
      } finally {
        await releaseContainer(scanId);
      }
    })();

  } catch (error) {
    console.error('❌ ZAP scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to initiate ZAP scan',
      details: error.message
    });
  }
});

// GET /api/zap/status/:scanId
// Get ZAP scan status and results (Protected)
router.get('/status/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;

    if (!scanId) {
      return res.status(400).json({
        success: false,
        error: 'Scan ID is required'
      });
    }

    const result = await getZapScanStatus(scanId, req.user.id);

    res.json({
      success: true,
      ...result
    });

  } catch (error) {
    console.error('❌ Status retrieval error:', error);

    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found or access denied'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve scan status',
      details: error.message
    });
  }
});

// POST /api/zap/stop/:scanId
// Stop a running ZAP scan (Protected)
router.post('/stop/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;

    if (!scanId) {
      return res.status(400).json({
        success: false,
        error: 'Scan ID is required'
      });
    }

    console.log(`🛑 User ${req.user.id} requested to stop scan: ${scanId}`);

    // Import necessary modules
    const { stopZapScan } = require('../services/zapService');

    // Stop the scan and restart Docker container
    const result = await stopZapScan(scanId, req.user.id);

    res.json({
      success: true,
      message: result.message || 'Scan stopped successfully',
      scanId: scanId,
      containerRestarted: result.containerRestarted || false,
      note: 'ZAP container has been restarted for a fresh scan environment'
    });

  } catch (error) {
    console.error('❌ Stop scan error:', error);

    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found or access denied'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Failed to stop scan',
      details: error.message
    });
  }
});

// GET /api/zap/scans
// Get user's ZAP scan history (Protected)
router.get('/scans', auth, async (req, res) => {
  try {
    const ScanResult = require('../models/ScanResult');

    // Find all scans with zapResult for this user
    const scans = await ScanResult.find({
      userId: req.user.id,
      zapResult: { $exists: true }
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .select('analysisId target status zapResult createdAt updatedAt');

    res.json({
      success: true,
      count: scans.length,
      scans: scans.map(scan => ({
        scanId: scan.analysisId,
        target: scan.target,
        status: scan.status,
        zapStatus: scan.zapResult?.status,
        phase: scan.zapResult?.phase,
        urlsFound: scan.zapResult?.urlsFound,
        alerts: scan.zapResult?.alerts,
        progress: scan.zapResult?.progress,
        createdAt: scan.createdAt,
        updatedAt: scan.updatedAt
      }))
    });

  } catch (error) {
    console.error('❌ History retrieval error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve scan history',
      details: error.message
    });
  }
});

// GET /api/zap/info
// Get ZAP scanner information and capabilities
router.get('/info', (req, res) => {
  res.json({
    success: true,
    scanner: {
      name: 'OWASP ZAP Maximum Performance Scanner',
      version: '2.0',
      description: 'Comprehensive web application security scanner with maximum discovery and testing capabilities'
    },
    capabilities: {
      traditionalSpider: {
        enabled: true,
        maxDepth: 20,
        maxDuration: 120,
        description: 'Crawls static HTML links'
      },
      ajaxSpider: {
        enabled: true,
        maxDepth: 10,
        browsers: 4,
        description: 'Executes JavaScript to find dynamic content'
      },
      passiveScan: {
        enabled: true,
        description: 'Analyzes all proxied traffic automatically'
      },
      activeScan: {
        enabled: true,
        description: 'Injects payloads to find vulnerabilities'
      }
    },
    scanModes: {
      full: {
        description: 'Maximum discovery and testing',
        estimatedTime: '15-60 minutes',
        depth: 20,
        ajaxEnabled: true
      },
      quick: {
        description: 'Faster scan with reduced depth',
        estimatedTime: '5-15 minutes',
        depth: 10,
        ajaxEnabled: true
      }
    },
    rateLimit: {
      maxScansPerUser: '20 per 10 minutes',
      note: 'Rate limiting is applied to prevent API abuse'
    },
    documentation: {
      startScan: 'POST /api/zap/scan',
      checkStatus: 'GET /api/zap/status/:scanId',
      scanHistory: 'GET /api/zap/scans',
      healthCheck: 'GET /api/zap/health'
    }
  });
});

// GET /api/zap/scans/:scanId/alerts
// Get scan alerts with pagination and filtering (Protected)
router.get('/scans/:scanId/alerts', auth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const {
      page = 1,
      limit = 100,
      risk,  // Filter by risk: High, Medium, Low, Informational
      search  // Search in alert name or URL
    } = req.query;

    // Build query
    const query = { scanId };
    if (risk) {
      query.risk = risk;
    }
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { url: { $regex: search, $options: 'i' } }
      ];
    }

    // Get paginated alerts
    const skip = (page - 1) * limit;
    const alerts = await ZapAlert
      .find(query)
      .sort({ risk: -1, createdAt: -1 })  // High risk first
      .skip(skip)
      .limit(parseInt(limit));

    const total = await ZapAlert.countDocuments(query);

    res.json({
      success: true,
      data: {
        alerts,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });

  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch alerts'
    });
  }
});

// GET /api/zap/scans/:scanId/report/:format
// Download report file from GridFS (Protected)
router.get('/scans/:scanId/report/:format', auth, async (req, res) => {
  try {
    const { scanId, format } = req.params;
    const ScanResult = require('../models/ScanResult');
    const mongoose = require('mongoose'); // Issue #4 fix: Add mongoose import

    // Get scan result and verify ownership
    const scan = await ScanResult.findOne({
      analysisId: scanId,
      userId: req.user.id
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found or access denied'
      });
    }

    // Find report file ID
    const reportFile = scan.zapResult?.reportFiles?.find(
      f => f.format === format
    );

    if (!reportFile) {
      return res.status(404).json({
        success: false,
        error: `${format.toUpperCase()} report not found`
      });
    }

    // Validate ObjectId format (Issue #4 fix)
    let fileId;
    try {
      fileId = new mongoose.Types.ObjectId(reportFile.fileId);
    } catch (oidError) {
      console.error('Invalid ObjectId format:', reportFile.fileId);
      return res.status(400).json({
        success: false,
        error: 'Invalid report file reference'
      });
    }

    // Get file metadata
    const fileMetadata = await gridfsService.getFileMetadata(fileId);
    if (!fileMetadata) {
      return res.status(404).json({
        success: false,
        error: 'Report file not found in storage'
      });
    }

    // Set appropriate headers
    const contentTypes = {
      html: 'text/html',
      json: 'application/json',
      xml: 'application/xml'
    };

    res.set({
      'Content-Type': contentTypes[format] || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${fileMetadata.filename}"`,
      'Content-Length': fileMetadata.length
    });

    // Stream file to response (efficient for large files) with error handling
    const downloadStream = gridfsService.downloadFileStream(fileId);

    downloadStream.on('error', (streamError) => {
      console.error('GridFS stream error:', streamError);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          error: 'Failed to stream report file'
        });
      }
    });

    downloadStream.pipe(res);

  } catch (error) {
    console.error('Error downloading report:', error);
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        error: 'Failed to download report'
      });
    }
  }
});

// GET /api/zap/scans/:scanId/alerts/stats
// Get alert statistics (Protected)
router.get('/scans/:scanId/alerts/stats', auth, async (req, res) => {
  try {
    const { scanId } = req.params;

    const stats = await ZapAlert.aggregate([
      { $match: { scanId } },
      {
        $group: {
          _id: '$risk',
          count: { $sum: 1 }
        }
      }
    ]);

    const breakdown = {
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0
    };

    stats.forEach(stat => {
      breakdown[stat._id] = stat.count;
    });

    res.json({
      success: true,
      data: {
        breakdown,
        total: Object.values(breakdown).reduce((a, b) => a + b, 0)
      }
    });

  } catch (error) {
    console.error('Error fetching alert stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics'
    });
  }
});

// GET /api/zap/detailed-report/:scanId
// Download detailed vulnerability report with all URLs (for ZapReportEnhanced component)
router.get('/detailed-report/:scanId', auth, async (req, res) => {
  try {
    const { downloadDetailedReport } = require('../services/zapService');
    await downloadDetailedReport(req, res);
  } catch (error) {
    console.error('Download error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to download detailed report' });
    }
  }
});

// GET /api/zap/detailed-report-pdf/:scanId?lang=en|ja
// Download ZAP vulnerability report as PDF with all URLs
router.get('/detailed-report-pdf/:scanId', auth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const lang = req.query.lang === 'ja' ? 'ja' : 'en';

    // Import dependencies
    const ScanResult = require('../models/ScanResult');
    const { generateZapPdf } = require('../services/pdfService');

    // Find scan result by analysisId
    const scanResult = await ScanResult.findOne({
      analysisId: scanId,
      userId: req.user.id  // Verify ownership
    });

    if (!scanResult) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Check if ZAP result exists
    if (!scanResult.zapResult) {
      return res.status(404).json({
        error: 'ZAP report not available for this scan',
        hint: 'This scan may not have completed ZAP scanning yet'
      });
    }

    console.log(`📄 Generating ZAP PDF (${lang.toUpperCase()}) for scan: ${scanId}`);

    // Generate PDF
    const pdfBuffer = await generateZapPdf(scanResult, lang);

    // Send PDF response
    const filename = `zap_vulnerability_report_${scanId}_${lang}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.send(pdfBuffer);

    console.log(`✅ ZAP PDF (${lang.toUpperCase()}) sent successfully: ${filename}`);

  } catch (error) {
    console.error('ZAP PDF generation error:', error);
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
        error: 'Failed to generate ZAP PDF report',
        details: error.message
      });
    }
  }
});

module.exports = router;
