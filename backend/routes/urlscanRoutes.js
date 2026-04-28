//urlscanRoutes.js
const express = require('express');
const { submitUrlScan, getUrlScanResult } = require('../services/urlscanService');
const ScanResult = require('../models/ScanResult');

const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck'); // ✅ ADD THIS

const router = express.Router();

/**
 * POST /api/urlscan/scan
 * Submit URL for scanning
 */
router.post('/scan', auth, requireOrg, planCheck, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        console.log(`🔐 User ${req.user.id} (Org: ${req.organization._id}) submitted URL: ${url}`);

        const submission = await submitUrlScan(url);

        res.json({
            success: true,
            message: 'URL submitted to urlscan.io',
            uuid: submission.uuid,
            apiLink: submission.api,
            visibility: submission.visibility,
            reportUrl: `https://urlscan.io/result/${submission.uuid}/`
        });

    } catch (err) {
        console.error('❌ urlscan submission error:', err.message);
        res.status(500).json({
            error: 'Failed to submit scan',
            details: err.message
        });
    }
});
module.exports = router;