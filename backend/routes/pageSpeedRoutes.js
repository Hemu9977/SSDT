const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { analyzeUrl } = require('../services/pagespeedService');

// @route   POST /api/pagespeed/analyze
// @desc    Analyze a URL with PageSpeed Insights
// @access  Private
router.post('/analyze', async (req, res) => {
  const { url, strategy } = req.body;

  if (!url) {
    return res.status(400).json({ msg: 'URL is required' });
  }

  try {
    const report = await analyzeUrl(url, strategy);
    res.json(report);
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;