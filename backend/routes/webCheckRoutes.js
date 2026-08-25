//webCheckRoutes.js
const express = require('express');
const router = express.Router();
const { checkScanTarget } = require('../utils/scanTargetGuard');
const webCheckService = require('../services/webCheckService');
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck');
const { consumeScan } = require('../services/planService');
const { scanLimiter } = require('../middleware/rateLimiter');

// POST /api/webcheck/scan
// Body: { url: "example.com", type: "ssl" }
// Strict limiter is per-route: the router mount now carries the generous poll
// limiter so browser status polling can't exhaust the scan-start budget.
router.post('/scan', auth, planCheck, scanLimiter, async (req, res) => {
    const { url, type } = req.body;

    if (!url) {

        return res.status(400).json({ error: 'URL is required' });
    }

    // The WebCheck container fetches this server-side, from inside the VPC.
    const guard = checkScanTarget(url);
    if (!guard.ok) {
        return res.status(400).json({ error: guard.error, code: guard.code });
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

        const limits = req.planUser.getAccountLimits(req.organization);
        await consumeScan(req.organization._id, {
            target: url,
            scansPerTarget: limits.scansPerTarget,
            targetsPerMonth: limits.targetsPerMonth
        });
        console.log(`[Billing] Scan completed - quota deducted: standalone-webcheck-${type}-${url}`);

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

// Removed: GET /types and POST /save-results. Neither had a caller anywhere in
// the repo. /save-results in particular took a client-supplied `results` object
// and wrote it straight onto the scan document with no shape validation, so the
// deletion removes an unused write path into scan records as well as dead code.

module.exports = router;
