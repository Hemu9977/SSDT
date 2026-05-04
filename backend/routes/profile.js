//profile.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const User = require('../models/User');
const ScanResult = require('../models/ScanResult');
const Organization = require('../models/Organization');
const Invite = require('../models/Invite');

const devMsg = (err) => process.env.NODE_ENV !== 'production' ? err.message : undefined;

// @route   GET /profile
// @desc    Get user profile with statistics
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -otp -otpExpires');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get scan statistics
    const totalScans = await ScanResult.countDocuments({ userId: req.user.id });
    const recentScans = await ScanResult.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('analysisId target status createdAt triggerSource');

    // Calculate scans this month
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const scansThisMonth = await ScanResult.countDocuments({
      userId: req.user.id,
      createdAt: { $gte: startOfMonth }
    });

    // Update totalScans in user model if needed
    if (user.totalScans !== totalScans) {
      user.totalScans = totalScans;
      await user.save();
    }

    // Fetch organization if user has one
    let org = null;
    let members = [];
    let pendingInvites = [];

    if (user.organizationId) {
      org = await Organization.findById(user.organizationId);
      if (org) {
        members = await User.find({ organizationId: org._id }).select('name email role');
        pendingInvites = await Invite.find({ organizationId: org._id, status: 'pending' }).select('email role token createdAt expiresAt');
      }
    }

    // Get account limits (org-aware)
    const limits = user.getAccountLimits(org);

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        bio: user.bio,
        accountType: user.accountType,
        isVerified: user.isVerified,
        totalScans: totalScans,
        scansThisMonth: scansThisMonth,
        monthlyScansUsed: org ? org.scansUsed : 0,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt,
        // isPro: true for ANY active paid plan (light, basic, pro) — org-first, then user fallback
        isPro: user.isPro(org),
        proExpiresAt: org ? org.expiresAt : user.proExpiresAt,
        // ── Service plan fields ──────────────────────────────────────────────
        organization: org ? {
          id: org._id,
          name: org.name,
          role: user.role,
          planType: org.planType,
          billingCycle: org.billingCycle,
          subscriptionStatus: org.subscriptionStatus,
          seatsAllowed: org.seatsAllowed,
          seatsUsed: org.seatsUsed,
          scanLimit: org.scanLimit,
          scansUsed: org.scansUsed,
          targetsUsed: org.targetsUsed,
          oneTimeRemainingScans: org.oneTimeRemainingScans,
          expiresAt: org.expiresAt,
          members: members,
          pendingInvites: pendingInvites
        } : null,
        planType: org ? org.planType : user.planType,
        billingCycle: org ? org.billingCycle : user.billingCycle,
        subscriptionStatus: org ? org.subscriptionStatus : user.subscriptionStatus,
        oneTimeRemainingScans: org ? (org.oneTimeRemainingScans || 0) : (user.oneTimeRemainingScans || 0),
        totalTargetsUsed: org ? (org.targetsUsed || 0) : (user.totalTargetsUsed || 0),
        // Convert Mongoose Map to plain object for JSON serialisation
        scanUsagePerTarget: user.scanUsagePerTarget
          ? Object.fromEntries(user.scanUsagePerTarget)
          : {}
      },
      limits: limits,
      recentScans: recentScans
    });
  } catch (err) {
    console.error('Profile retrieval error:', err.message);
    res.status(500).json({
      message: 'Server error',
      error: devMsg(err)
    });
  }
});

// @route   PUT /profile
// @desc    Update user profile
// @access  Private
router.put('/', auth, async (req, res) => {
  try {
    const { name, bio } = req.body;

    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Validate inputs
    if (name && name.trim().length < 3) {
      return res.status(400).json({ message: 'Name must be at least 3 characters long' });
    }

    if (bio && bio.length > 500) {
      return res.status(400).json({ message: 'Bio must not exceed 500 characters' });
    }

    // Update fields
    if (name) user.name = name.trim();
    if (bio !== undefined) user.bio = bio.trim();

    await user.save();

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        bio: user.bio,
        accountType: user.accountType
      }
    });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({
      message: 'Server error',
      error: devMsg(err)
    });
  }
});

// @route   GET /profile/stats
// @desc    Get detailed user statistics
// @access  Private
router.get('/stats', auth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Get all scans
    const allScans = await ScanResult.find({ userId }).select('status createdAt');

    // Calculate statistics
    const totalScans = allScans.length;
    const completedScans = allScans.filter(scan => scan.status === 'completed').length;
    const failedScans = allScans.filter(scan => scan.status === 'failed').length;
    const pendingScans = allScans.filter(scan => ['queued', 'pending', 'combining'].includes(scan.status)).length;

    // Calculate scans per month (last 6 months)
    const monthlyStats = {};
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    allScans.forEach(scan => {
      const monthKey = `${scan.createdAt.getFullYear()}-${String(scan.createdAt.getMonth() + 1).padStart(2, '0')}`;
      if (scan.createdAt >= sixMonthsAgo) {
        monthlyStats[monthKey] = (monthlyStats[monthKey] || 0) + 1;
      }
    });

    res.json({
      success: true,
      stats: {
        totalScans,
        completedScans,
        failedScans,
        pendingScans,
        successRate: totalScans > 0 ? ((completedScans / totalScans) * 100).toFixed(1) : 0,
        monthlyStats
      }
    });
  } catch (err) {
    console.error('Stats retrieval error:', err.message);
    res.status(500).json({
      message: 'Server error',
      error: devMsg(err)
    });
  }
});

// @route   POST /profile/upgrade-to-pro
// @desc    Upgrade to Pro account (PROTOTYPE ONLY - for testing purposes)
// @access  Private
router.post('/upgrade-to-pro', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.isPro()) {
      return res.status(400).json({
        success: false,
        message: 'You already have an active Pro account'
      });
    }

    // PROTOTYPE: Upgrade user to PRO
    user.accountType = 'pro';
    user.proExpiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year from now

    await user.save();

    res.json({
      success: true,
      message: 'Successfully upgraded to Pro!',
      user: {
        accountType: user.accountType,
        proExpiresAt: user.proExpiresAt,
        isPro: user.isPro()
      },
      note: 'This is a prototype build for testing. Payment integration will be added in production.'
    });
  } catch (err) {
    console.error('Pro upgrade error:', err.message);
    res.status(500).json({
      message: 'Server error',
      error: devMsg(err)
    });
  }
});

// @route   POST /profile/downgrade-to-free
// @desc    Downgrade to Free account (PROTOTYPE ONLY - for testing purposes)
// @access  Private
router.post('/downgrade-to-free', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.accountType === 'free') {
      return res.status(400).json({
        success: false,
        message: 'You already have a Free account'
      });
    }

    // PROTOTYPE: Downgrade user to FREE
    user.accountType = 'free';
    user.proExpiresAt = null;

    await user.save();

    res.json({
      success: true,
      message: 'Successfully downgraded to Free account',
      user: {
        accountType: user.accountType,
        proExpiresAt: user.proExpiresAt,
        isPro: user.isPro()
      },
      note: 'This is a prototype build for testing. In production, this would handle subscription cancellation.'
    });
  } catch (err) {
    console.error('Downgrade error:', err.message);
    res.status(500).json({
      message: 'Server error',
      error: devMsg(err)
    });
  }
});

module.exports = router;
