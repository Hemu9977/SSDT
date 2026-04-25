const express = require('express');
const router = express.Router();
const webCheckService = require('../services/webCheckService');
const ScanResult = require('../models/ScanResult');
const auth = require('../middleware/auth');
const planCheck = require('../middleware/planCheck');

// POST /api/webcheck/scan
// Body: { url: "example.com", type: "ssl" }
router.post('/scan', auth, planCheck, async (req, res) => {
    const { url, type } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    if (!type) {
        return res.status(400).json({
            error: 'Scan type is required',
            availableTypes: webCheckService.getAvailableScans()
        });
    }

    if (!webCheckService.ALLOWED_SCANS.includes(type)) {
        return res.status(400).json({
            error: `Invalid scan type: ${type}`,
            availableTypes: webCheckService.getAvailableScans()
        });
    }

    try {
        console.log(`⚡ WebCheck scan request: ${type} for ${url}`);
        const results = await webCheckService.runScan(type, url);

        res.json({
            success: true,
            scanType: type,
            targetUrl: url,
            data: results
        });
    } catch (error) {
        console.error('❌ WebCheck scan error:', error.message);
        res.status(500).json({
            error: 'WebCheck scan failed',
            details: error.message
        });
    }
});

// GET /api/webcheck/types
// Returns list of available scan types
router.get('/types', (req, res) => {
    res.json({
        scanTypes: webCheckService.getAvailableScans(),
        usage: 'POST /api/webcheck/scan with { url, type }'
    });
});

// GET /api/webcheck/health
// Check if WebCheck container is running
router.get('/health', async (req, res) => {
    const isHealthy = await webCheckService.checkHealth();

    if (isHealthy) {
        res.json({ status: 'healthy', message: 'WebCheck service is running' });
    } else {
        res.status(503).json({
            status: 'unhealthy',
            message: 'WebCheck service is not available. Start it with: docker-compose up webcheck'
        });
    }
});

// POST /api/webcheck/save-results
// Save WebCheck results to a scan record in the database
// This allows resuming scans after page refresh
router.post('/save-results', auth, async (req, res) => {
    try {
        const { scanId, results } = req.body;

        if (!scanId) {
            return res.status(400).json({ error: 'Scan ID is required' });
        }

        if (!results || typeof results !== 'object') {
            return res.status(400).json({ error: 'Results object is required' });
        }

        // Find the scan and verify ownership
        const scan = await ScanResult.findOne({
            analysisId: scanId,
            userId: req.user.id
        });

        if (!scan) {
            return res.status(404).json({ error: 'Scan not found or access denied' });
        }

        // Update the scan with WebCheck results
        scan.webCheckResult = results;
        scan.updatedAt = new Date();
        await scan.save();

        console.log(`✅ WebCheck results saved for scan: ${scanId}`);

        res.json({
            success: true,
            message: 'WebCheck results saved successfully',
            scanId: scanId
        });

    } catch (error) {
        console.error('❌ Error saving WebCheck results:', error.message);
        res.status(500).json({
            error: 'Failed to save WebCheck results',
            details: error.message
        });
    }
});

module.exports = router;
