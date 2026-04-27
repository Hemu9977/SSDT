const express = require('express');
const { submitUrlScan, getUrlScanResult } = require('../services/urlscanService');
const ScanResult = require('../models/ScanResult');
const auth = require('../middleware/auth');

const router = express.Router();

const devMsg = (err) => process.env.NODE_ENV !== 'production' ? err.message : undefined;

/**
 * POST /api/urlscan/scan
 * Submit URL for scanning
 */
router.post('/scan', auth, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        console.log(`🔐 User ${req.user.id} submitted URL to urlscan.io: ${url}`);

        // Submit to urlscan.io
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
            details: devMsg(err)
        });
    }
});

/**
 * GET /api/urlscan/result/:uuid
 * Get scan result by UUID
 */
router.get('/result/:uuid', auth, async (req, res) => {
    try {
        const { uuid } = req.params;

        if (!uuid) {
            return res.status(400).json({ error: 'UUID is required' });
        }

        const result = await getUrlScanResult(uuid);

        if (!result) {
            return res.status(404).json({
                status: 'pending',
                message: 'Scan not ready yet. Please try again in a few seconds.',
                uuid: uuid
            });
        }

        // Extract key information
        const verdicts = result.verdicts || {};
        const page = result.page || {};

        res.json({
            success: true,
            status: 'completed',
            uuid: uuid,
            page: {
                url: page.url,
                domain: page.domain,
                ip: page.ip,
                country: page.country,
                server: page.server
            },
            verdicts: {
                overall: verdicts.overall || {},
                urlscan: verdicts.urlscan || {},
                engines: verdicts.engines || {},
                community: verdicts.community || {}
            },
            screenshot: result.task?.screenshotURL || null,
            reportUrl: `https://urlscan.io/result/${uuid}/`
        });

    } catch (err) {
        console.error('❌ urlscan result error:', err.message);
        res.status(500).json({
            error: 'Failed to retrieve result',
            details: devMsg(err)
        });
    }
});

/**
 * GET /api/urlscan/info
 * Get service information
 */
router.get('/info', (req, res) => {
    res.json({
        success: true,
        service: {
            name: 'urlscan.io',
            description: 'Website scanner and analysis service',
            website: 'https://urlscan.io'
        },
        capabilities: {
            screenshot: true,
            domAnalysis: true,
            networkAnalysis: true,
            threatIntel: true,
            verdicts: true
        },
        endpoints: {
            submitScan: 'POST /api/urlscan/scan',
            getResult: 'GET /api/urlscan/result/:uuid'
        }
    });
});

module.exports = router;
