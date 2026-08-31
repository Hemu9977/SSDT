/**
 * Schedule Routes
 * CRUD API for scan scheduling management.
 * All routes require authentication.
 */
//scheduleRoutes.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const ScheduledScan = require('../models/ScheduledScan');
const User = require('../models/User');
const Organization = require('../models/Organization');
const ScanResult = require('../models/ScanResult');
const { validatePlanLimits } = require('../services/schedulerService');
const { checkScanTarget } = require('../utils/scanTargetGuard');
const { handleScheduleCreated } = require('../services/notificationService');
const { isValidTimeZone, formatInTimeZone, DEFAULT_TIME_ZONE } = require('../utils/timezone');

/**
 * POST /api/schedules
 * Create a new scheduled scan
 */
router.post('/', auth, async (req, res) => {
  // Set once the row is committed; the presentation work below the try reads it.
  let savedSchedule = null;
  const { targetUrl } = req.body;

  try {
    const { scanType, scheduleType, scheduledAt, recurring, timezone, authConfig } = req.body;

    // Validate required fields
    if (!targetUrl) {
      return res.status(400).json({ success: false, error: 'Target URL is required' });
    }

    if (!scheduleType || !['one-time', 'recurring'].includes(scheduleType)) {
      return res.status(400).json({ success: false, error: 'Schedule type must be "one-time" or "recurring"' });
    }

    // An unrecognised zone would otherwise be stored and then throw RangeError the next
    // time anything formatted it. Refuse it at the door instead.
    if (timezone !== undefined && !isValidTimeZone(timezone)) {
      return res.status(400).json({ success: false, error: 'Invalid timezone', code: 'INVALID_TIMEZONE' });
    }

    // Same guard the interactive routes apply. A schedule is just a deferred
    // scan, so it is a second door to the same server-side fetch.
    const targetGuard = checkScanTarget(targetUrl);
    if (!targetGuard.ok) {
      return res.status(400).json({ success: false, error: 'Invalid or refused URL', code: targetGuard.code });
    }
    if (authConfig && authConfig.loginUrl) {
      const loginGuard = checkScanTarget(authConfig.loginUrl);
      if (!loginGuard.ok) {
        return res.status(400).json({ success: false, error: 'Invalid or refused loginUrl', code: loginGuard.code });
      }
    }

    // Validate one-time schedule
    if (scheduleType === 'one-time') {
      if (!scheduledAt) {
        return res.status(400).json({ success: false, error: 'Scheduled date/time is required for one-time scans' });
      }
      const schedDate = new Date(scheduledAt);
      if (isNaN(schedDate.getTime())) {
        return res.status(400).json({ success: false, error: 'Invalid date/time format' });
      }
      const now = new Date();
      if (schedDate <= now) {
        return res.status(400).json({ success: false, error: 'Scheduled time must be in the future' });
      }
      // Restrict one-time schedules to within the next 1 month
      const maxAllowed = new Date(now);
      maxAllowed.setMonth(maxAllowed.getMonth() + 1);
      if (schedDate > maxAllowed) {
        return res.status(400).json({
          success: false,
          error: 'Scheduled time must be within 1 month from now'
        });
      }
    }

    // Validate recurring schedule
    if (scheduleType === 'recurring') {
      if (!recurring || !recurring.frequency) {
        return res.status(400).json({ success: false, error: 'Recurring frequency is required' });
      }
      if (!['monthly', 'twice-monthly', 'custom'].includes(recurring.frequency)) {
        return res.status(400).json({ success: false, error: 'Invalid frequency. Use "monthly", "twice-monthly", or "custom"' });
      }
      if (!recurring.days || recurring.days.length === 0) {
        return res.status(400).json({ success: false, error: 'At least one day of the month must be selected' });
      }
      // Validate days are valid (1-31)
      for (const day of recurring.days) {
        if (day < 1 || day > 31) {
          return res.status(400).json({ success: false, error: `Invalid day: ${day}. Must be between 1 and 31` });
        }
      }
      if (!recurring.time || !/^\d{2}:\d{2}$/.test(recurring.time)) {
        return res.status(400).json({ success: false, error: 'Time must be in HH:mm format' });
      }
    }

    // Get user and check plan limits
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const org = user.organizationId ? await Organization.findById(user.organizationId) : null;
    const limits = user.getAccountLimits(org);

    // TEMPORARY: Bypass plan limits for testing
    /*
    if (limits.maxSchedules <= 0) {
      return res.status(403).json({
        success: false,
        error: 'Scan scheduling is not available on your current plan. Please upgrade to Light, Basic, or Pro to access scheduling features.'
      });
    }
    */

    // Check active schedule count
    const activeCount = await ScheduledScan.countActiveForUser(req.user.id);
    /*
    if (activeCount >= limits.maxSchedules) {
      return res.status(403).json({
        success: false,
        error: `Maximum active schedules reached (${activeCount}/${limits.maxSchedules}). Please upgrade your plan or delete existing schedules.`
      });
    }
    */

    // Validate plan limits for scan execution
    user.checkAndResetMonthlyScans();
    const planValidation = await validatePlanLimits(user, targetUrl);
    if (!planValidation.valid) {
      return res.status(403).json({
        success: false,
        // Machine-readable for the UI; `error` is English and stays for logs.
        code: planValidation.code,
        error: planValidation.reason
      });
    }

    // Check for overlapping schedules (same URL within 1 hour)
    const oneHourFromSchedule = scheduleType === 'one-time'
      ? new Date(new Date(scheduledAt).getTime() + 60 * 60 * 1000)
      : null;
    const oneHourBeforeSchedule = scheduleType === 'one-time'
      ? new Date(new Date(scheduledAt).getTime() - 60 * 60 * 1000)
      : null;

    if (scheduleType === 'one-time') {
      const overlap = await ScheduledScan.findOne({
        userId: req.user.id,
        targetUrl,
        enabled: true,
        scheduleType: 'one-time',
        scheduledAt: { $gte: oneHourBeforeSchedule, $lte: oneHourFromSchedule }
      });

      if (overlap) {
        return res.status(409).json({
          success: false,
          error: 'A scan for the same URL is already scheduled within 1 hour of this time'
        });
      }
    }

    // Create schedule
    const schedule = new ScheduledScan({
      userId: req.user.id,
      targetUrl,
      scanType: scanType || 'public',
      scheduleType,
      scheduledAt: scheduleType === 'one-time' ? new Date(scheduledAt) : null,
      recurring: scheduleType === 'recurring' ? {
        frequency: recurring.frequency,
        days: recurring.days,
        time: recurring.time || '10:00'
      } : undefined,
      timezone: timezone || DEFAULT_TIME_ZONE,
      authConfig: scanType === 'authenticated' ? authConfig : undefined
    });

    // Compute next run
    schedule.computeNextRun();

    // A recurring schedule with no reachable occurrence would save with nextRun: null,
    // and getDueSchedules() only matches on nextRun - it would never run, silently.
    if (schedule.scheduleType === 'recurring' && !schedule.nextRun) {
      return res.status(400).json({
        success: false,
        error: 'No upcoming occurrence for this recurrence',
        code: 'NO_UPCOMING_OCCURRENCE'
      });
    }

    await schedule.save();
    savedSchedule = schedule;

    console.log(`📅 Schedule created: ${schedule._id} for ${targetUrl} (user: ${req.user.id})`);

  } catch (error) {
    console.error('❌ Schedule creation error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to create schedule',
      code: 'SCHEDULE_CREATE_FAILED'
    });
  }

  // Past this point the row is committed. Nothing below may turn a schedule that exists
  // into a 500 - that is exactly how a formatting TypeError made every create look like a
  // failure while the schedule sat in the database.
  const displayTime = formatInTimeZone(savedSchedule.nextRun, savedSchedule.timezone)
    || 'As soon as possible';

  // Trigger notification asynchronously (don't await so we don't block response)
  handleScheduleCreated(req.user.id, targetUrl, savedSchedule.scheduleType, displayTime);

  res.status(201).json({
    success: true,
    message: 'Scan scheduled successfully',
    schedule: {
      id: savedSchedule._id,
      targetUrl: savedSchedule.targetUrl,
      scanType: savedSchedule.scanType,
      scheduleType: savedSchedule.scheduleType,
      nextRun: savedSchedule.nextRun,
      status: savedSchedule.status
    }
  });
});

/**
 * GET /api/schedules
 * List all schedules for authenticated user
 */
router.get(
  '/',
  (req, res, next) => {
    // Health-check behavior: if called without auth, return a simple message.
    // If a token is present, proceed through normal auth + schedule listing.
    const token = req.header('x-auth-token');
    if (!token) return res.json({ message: 'Schedules working' });
    next();
  },
  auth,
  async (req, res) => {
  try {
    const schedules = await ScheduledScan.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .lean();

    // Get user plan limits for frontend display
    const user = await User.findById(req.user.id);
    const org = user && user.organizationId ? await Organization.findById(user.organizationId) : null;
    const limits = user ? user.getAccountLimits(org) : {};
    const activeCount = await ScheduledScan.countActiveForUser(req.user.id);

    // Calculate true scans this month directly from ScanResult collection
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const scansThisMonth = await ScanResult.countDocuments({
      userId: req.user.id,
      createdAt: { $gte: startOfMonth }
    });

    res.json({
      success: true,
      count: schedules.length,
      limits: {
        maxSchedules: limits.maxSchedules || 0,
        activeSchedules: activeCount,
        totalScans: limits.totalScans || 0,
        scansUsed: scansThisMonth
      },
      schedules: schedules.map(s => ({
        id: s._id,
        targetUrl: s.targetUrl,
        scanType: s.scanType,
        scheduleType: s.scheduleType,
        scheduledAt: s.scheduledAt,
        recurring: s.recurring,
        timezone: s.timezone,
        status: s.status,
        enabled: s.enabled,
        nextRun: s.nextRun,
        lastRun: s.lastRun,
        lastScanId: s.lastScanId,
        lastFailure: s.lastFailure,
        createdAt: s.createdAt,
        updatedAt: s.updatedAt
      }))
    });

  } catch (error) {
    console.error('❌ Schedule list error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch schedules' });
  }
});

/**
 * GET /api/schedules/:id
 * Get a single schedule
 */
router.get('/:id', auth, async (req, res) => {
  try {
    const schedule = await ScheduledScan.findOne({ _id: req.params.id, userId: req.user.id });
    if (!schedule) {
      return res.status(404).json({ success: false, error: 'Schedule not found' });
    }

    res.json({ success: true, schedule });

  } catch (error) {
    console.error('❌ Schedule fetch error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch schedule' });
  }
});

/**
 * PUT /api/schedules/:id
 * Update a schedule
 */
router.put('/:id', auth, async (req, res) => {
  try {
    const schedule = await ScheduledScan.findOne({ _id: req.params.id, userId: req.user.id });
    if (!schedule) {
      return res.status(404).json({ success: false, error: 'Schedule not found' });
    }

    const { targetUrl, scanType, scheduleType, scheduledAt, recurring, timezone, enabled, authConfig } = req.body;

    // Update fields if provided
    if (targetUrl !== undefined) {
      // The create route was guarded and this one was not — an update could put
      // any host back on a schedule that had passed the check once.
      const targetGuard = checkScanTarget(targetUrl);
      if (!targetGuard.ok) {
        return res.status(400).json({ success: false, error: targetGuard.error, code: targetGuard.code });
      }
      schedule.targetUrl = targetUrl;
    }
    if (scanType !== undefined) schedule.scanType = scanType;
    if (enabled !== undefined) schedule.enabled = enabled;
    if (timezone !== undefined) {
      if (!isValidTimeZone(timezone)) {
        return res.status(400).json({ success: false, error: 'Invalid timezone', code: 'INVALID_TIMEZONE' });
      }
      schedule.timezone = timezone;
    }
    if (authConfig !== undefined) {
      if (authConfig && authConfig.loginUrl) {
        const loginGuard = checkScanTarget(authConfig.loginUrl);
        if (!loginGuard.ok) {
          return res.status(400).json({ success: false, error: loginGuard.error, code: loginGuard.code });
        }
      }
      schedule.authConfig = authConfig;
    }

    if (scheduleType !== undefined) {
      schedule.scheduleType = scheduleType;
    }

    if (scheduledAt !== undefined && schedule.scheduleType === 'one-time') {
      const schedDate = new Date(scheduledAt);
      const now = new Date();
      if (isNaN(schedDate.getTime())) {
        return res.status(400).json({ success: false, error: 'Invalid date/time format' });
      }
      if (schedDate <= now) {
        return res.status(400).json({ success: false, error: 'Scheduled time must be in the future' });
      }
      const maxAllowed = new Date(now);
      maxAllowed.setMonth(maxAllowed.getMonth() + 1);
      if (schedDate > maxAllowed) {
        return res.status(400).json({
          success: false,
          error: 'Scheduled time must be within 1 month from now'
        });
      }
      schedule.scheduledAt = schedDate;
    }

    if (recurring !== undefined && schedule.scheduleType === 'recurring') {
      schedule.recurring = {
        frequency: recurring.frequency || schedule.recurring.frequency,
        days: recurring.days || schedule.recurring.days,
        time: recurring.time || schedule.recurring.time
      };
    }

    // Reset status if re-enabling or updating schedule
    if (schedule.status === 'completed' || schedule.status === 'failed') {
      schedule.status = 'scheduled';
    }

    // Recompute next run
    schedule.computeNextRun();

    await schedule.save();

    console.log(`📅 Schedule updated: ${schedule._id}`);

    res.json({
      success: true,
      message: 'Schedule updated successfully',
      schedule: {
        id: schedule._id,
        targetUrl: schedule.targetUrl,
        scanType: schedule.scanType,
        scheduleType: schedule.scheduleType,
        nextRun: schedule.nextRun,
        status: schedule.status,
        enabled: schedule.enabled
      }
    });

  } catch (error) {
    console.error('❌ Schedule update error:', error);
    res.status(500).json({ success: false, error: 'Failed to update schedule', code: 'SCHEDULE_UPDATE_FAILED' });
  }
});

/**
 * DELETE /api/schedules/:id
 * Delete a schedule
 */
router.delete('/:id', auth, async (req, res) => {
  try {
    const schedule = await ScheduledScan.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!schedule) {
      return res.status(404).json({ success: false, error: 'Schedule not found' });
    }

    console.log(`🗑️ Schedule deleted: ${schedule._id}`);

    res.json({ success: true, message: 'Schedule deleted successfully' });

  } catch (error) {
    console.error('❌ Schedule delete error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete schedule' });
  }
});

/**
 * POST /api/schedules/:id/run-now
 * Trigger immediate execution of a schedule
 */
router.post('/:id/run-now', auth, async (req, res) => {
  try {
    const schedule = await ScheduledScan.findOne({ _id: req.params.id, userId: req.user.id });
    if (!schedule) {
      return res.status(404).json({ success: false, error: 'Schedule not found' });
    }

    // Validate plan limits
    const user = await User.findById(req.user.id);
    user.checkAndResetMonthlyScans();
    const validation = await validatePlanLimits(user, schedule.targetUrl);
    if (!validation.valid) {
      return res.status(403).json({ success: false, code: validation.code, error: validation.reason });
    }

    // Set next run to now to trigger on next scheduler tick
    schedule.nextRun = new Date();
    schedule.status = 'scheduled';
    schedule.enabled = true;
    await schedule.save();

    console.log(`▶️ Run-now triggered for schedule: ${schedule._id}`);

    res.json({
      success: true,
      message: 'Scan will execute shortly',
      schedule: {
        id: schedule._id,
        targetUrl: schedule.targetUrl,
        nextRun: schedule.nextRun
      }
    });

  } catch (error) {
    console.error('❌ Run-now error:', error);
    res.status(500).json({ success: false, error: 'Failed to trigger scan' });
  }
});

module.exports = router;
