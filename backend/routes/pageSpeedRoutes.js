//pageSpeedRoutes.js
const express = require('express');
const router = express.Router();

const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck');

const { getPageSpeedReport } = require('../services/pagespeedService');
const { consumeScan } = require('../services/planService');

// @route   POST /api/pagespeed/analyze
// @desc    Analyze a URL with PageSpeed Insights
// @access  Private (Org + Plan enforced)
router.post('/analyze', auth, requireOrg, planCheck, async (req, res) => {
  const { url, strategy } = req.body;

  if (!url) {

    return res.status(400).json({ msg: 'URL is required' });
  }

  try {
    console.log(`⚡ PageSpeed scan by user ${req.user.id} (Org: ${req.organization._id})`);

    // `strategy` is accepted by the API for compatibility but the service does
    // not take it. This route imported `analyzeUrl`, which the service has never
    // exported, so every call threw a TypeError and answered 500.
    const report = await getPageSpeedReport(url);

    const limits = req.planUser.getAccountLimits(req.organization);
    await consumeScan(req.organization._id, {
      target: url,
      scansPerTarget: limits.scansPerTarget,
      targetsPerMonth: limits.targetsPerMonth
    });
    console.log(`[Billing] Scan completed - quota deducted: standalone-pagespeed-${url}`);

    res.json({
      success: true,
      data: report
    });

  } catch (error) {
    console.error('❌ PageSpeed error:', error.message);
    res.status(500).json({
      error: 'Failed to analyze URL'
    });
  }
});

module.exports = router;