//pageSpeedRoutes.js
const express = require('express');
const router = express.Router();

const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const planCheck = require('../middleware/planCheck');

const { analyzeUrl } = require('../services/pagespeedService');

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

    const report = await analyzeUrl(url, strategy);

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