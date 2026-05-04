//notificationRoutes.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const ScanResult = require('../models/ScanResult');

/**
 * GET /api/notifications/unread
 * Returns all scheduled scans that have completed but Haven't been "seen" by the user.
 */
router.get('/unread', auth, async (req, res) => {
  try {
    const unreadScans = await ScanResult.find({
      userId: req.user.id,
      triggerSource: 'scheduled',
      status: 'completed',
      notified: false
    })
    .select('analysisId target status scanType createdAt triggerSource')
    .sort({ createdAt: -1 });

    res.json({ unread: unreadScans });
  } catch (err) {
    console.error('❌ Error fetching unread notifications:', err);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

/**
 * POST /api/notifications/mark-read/:analysisId
 * Marks a specific scan as "notified", dismissing the persistent popup.
 */
router.post('/mark-read/:analysisId', auth, async (req, res) => {
  try {
    const { analysisId } = req.params;
    const result = await ScanResult.updateOne(
      { analysisId, userId: req.user.id },
      { $set: { notified: true } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Scan not found or access denied' });
    }

    res.json({ success: true, message: 'Notification marked as read' });
  } catch (err) {
    console.error('❌ Error marking notification as read:', err);
    res.status(500).json({ error: 'Failed to update notification status' });
  }
});

module.exports = router;
