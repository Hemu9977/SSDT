// backend/routes/admin.js
// Platform-level Global Admin Dashboard API
// All routes are protected by auth + adminAuth middleware.
// Read endpoints for statistics, users, organizations, scans, and system health,
// plus mutation endpoints for user/organization lifecycle management.
console.log("✅ admin.js loaded");
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');
const User = require('../models/User');
const Organization = require('../models/Organization');
const ScanResult = require('../models/ScanResult');

const devMsg = (err) =>
  process.env.NODE_ENV !== 'production' ? err.message : undefined;

const ADMIN_CAPABLE_ROLES = ['admin', 'superadmin'];

// True if this user currently counts as an active platform administrator
// (used to make sure an action never leaves zero admins on the platform).
const isActiveAdmin = (u) => ADMIN_CAPABLE_ROLES.includes(u.systemRole) && !u.isDisabled;

// Apply auth + adminAuth to ALL routes in this router
router.use(auth, adminAuth);

// ── GET /api/admin/kpis ────────────────────────────────────────────────────────
// Aggregate platform-level KPI statistics for the dashboard overview.
router.get('/kpis', async (req, res) => {
  try {
    const [
      totalUsers,
      verifiedUsers,
      activeOrgs,
      totalOrgs,
      totalScansAggregate,
      runningScans,
      recentUsers,
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ isVerified: true }),
      Organization.countDocuments({ subscriptionStatus: 'active' }),
      Organization.countDocuments({}),
      User.aggregate([{ $group: { _id: null, total: { $sum: '$totalScans' } } }]),
      ScanResult.countDocuments({ status: { $in: ['queued', 'pending', 'combining'] } }),
      User.find({}).sort({ createdAt: -1 }).limit(5).select('name email createdAt systemRole accountType').lean(),
    ]);

    // Plan distribution
    const planDistribution = await Organization.aggregate([
      { $group: { _id: '$planType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // Same .lean()-bypasses-schema-defaults gap as GET /users — normalize here too.
    const normalizedRecentUsers = recentUsers.map((u) => ({ ...u, systemRole: u.systemRole || 'user' }));

    res.json({
      success: true,
      kpis: {
        totalUsers,
        verifiedUsers,
        activeOrgs,
        totalOrgs,
        totalScansAllTime: totalScansAggregate[0]?.total || 0,
        runningScans,
      },
      planDistribution,
      recentUsers: normalizedRecentUsers,
    });
  } catch (err) {
    console.error('❌ [admin/kpis]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch KPIs', details: devMsg(err) });
  }
});

// ── GET /api/admin/users ───────────────────────────────────────────────────────
// Paginated list of all users with optional search and filters.
router.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', role = '', systemRole = '' } = req.query;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }
    if (role) query.role = role;
    if (systemRole) query.systemRole = systemRole;

    const [total, users] = await Promise.all([
      User.countDocuments(query),
      User.find(query)
        .sort({ createdAt: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .select('name email role systemRole accountType planType isVerified isDisabled createdAt lastLoginAt organizationId totalScans')
        .populate('organizationId', 'planType subscriptionStatus')
        .lean(),
    ]);

    // .lean() returns raw MongoDB documents, bypassing Mongoose's schema-default
    // injection — documents created before systemRole existed have no such key
    // at all. Normalize here so the API contract guarantees systemRole is always
    // a string, matching the schema default (see backfillSystemRole.js for the
    // one-time data migration that fixed existing documents).
    const normalizedUsers = users.map((u) => ({ ...u, systemRole: u.systemRole || 'user', isDisabled: u.isDisabled || false }));

    res.json({
      success: true,
      users: normalizedUsers,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error('❌ [admin/users]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch users', details: devMsg(err) });
  }
});

// ── GET /api/admin/organizations ──────────────────────────────────────────────
// Paginated list of all organizations with usage statistics.
router.get('/organizations', async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', plan = '', status = '' } = req.query;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

    const query = {};
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }
    if (plan) query.planType = plan;
    if (status) query.subscriptionStatus = status;

    const [total, orgs] = await Promise.all([
      Organization.countDocuments(query),
      Organization.find(query)
        .sort({ createdAt: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .lean(),
    ]);

    // Enrich with owner info
    const orgIds = orgs.map((o) => o._id);
    const owners = await User.find({ organizationId: { $in: orgIds }, role: 'owner' })
      .select('name email organizationId')
      .lean();
    const ownerMap = {};
    owners.forEach((u) => {
      ownerMap[String(u.organizationId)] = { name: u.name, email: u.email };
    });

    const enriched = orgs.map((o) => ({
      ...o,
      isDisabled: o.isDisabled || false,
      owner: ownerMap[String(o._id)] || null,
    }));

    res.json({
      success: true,
      organizations: enriched,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error('❌ [admin/organizations]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch organizations', details: devMsg(err) });
  }
});

// ── GET /api/admin/scans ───────────────────────────────────────────────────────
// Paginated list of all scans across all users with status filter.
router.get('/scans', async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

    const query = {};
    if (status) query.status = status;

    const [total, scans] = await Promise.all([
      ScanResult.countDocuments(query),
      ScanResult.find(query)
        .sort({ createdAt: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .select('analysisId target status userId createdAt updatedAt zapResult webCheckResult')
        .lean(),
    ]);

    // Enrich with user info
    const userIds = [...new Set(scans.map((s) => String(s.userId)))];
    const users = await User.find({ _id: { $in: userIds } })
      .select('name email organizationId')
      .populate('organizationId', 'planType')
      .lean();
    const userMap = {};
    users.forEach((u) => {
      userMap[String(u._id)] = { name: u.name, email: u.email, plan: u.organizationId?.planType || 'free' };
    });

    const enriched = scans.map((s) => ({
      ...s,
      user: userMap[String(s.userId)] || null,
      duration: s.updatedAt && s.createdAt
        ? Math.round((new Date(s.updatedAt) - new Date(s.createdAt)) / 1000)
        : null,
    }));

    res.json({
      success: true,
      scans: enriched,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error('❌ [admin/scans]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch scans', details: devMsg(err) });
  }
});

// ── GET /api/admin/system-health ──────────────────────────────────────────────
// Reports the health status of all integrated services.
router.get('/system-health', async (req, res) => {
  console.log("SYSTEM HEALTH HIT");
  try {
    const mem = process.memoryUsage();
    const checks = {
      server: {
        status: 'online',
        uptimeSeconds: Math.floor(process.uptime()),
        memoryMB: Math.round(mem.heapUsed / 1048576),
        memoryTotalMB: Math.round(mem.heapTotal / 1048576),
        rssMB: Math.round(mem.rss / 1048576),
        nodeVersion: process.version,
      },
    };

    // MongoDB
    const mongoState = mongoose.connection.readyState;
    const mongoStateLabel = ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoState] ?? String(mongoState);
    checks.mongodb = {
      status: mongoState === 1 ? 'online' : 'offline',
      state: mongoStateLabel,
    };
    if (mongoState === 1) {
      try {
        const dbStats = await mongoose.connection.db.stats();
        checks.mongodb.collections = dbStats.collections;
        checks.mongodb.storageMB = Math.round((dbStats.storageSize || 0) / 1048576);
        checks.mongodb.dataFileMB = Math.round((dbStats.dataSize || 0) / 1048576);
      } catch (_) { }
    }

    // Redis
    if (process.env.REDIS_URL) {
      try {
        const { getPublisher } = require('../config/redis');
        const pub = getPublisher();
        if (pub && pub.status === 'ready') {
          let latencyMs = null;
          try {
            const start = Date.now();
            await pub.ping();
            latencyMs = Date.now() - start;
          } catch (_) { }
          checks.redis = { status: 'online', latencyMs };
        } else {
          checks.redis = { status: 'offline', state: pub ? pub.status : 'unavailable' };
        }
      } catch (e) {
        checks.redis = { status: 'offline', error: e.message };
      }
    } else {
      checks.redis = { status: 'not_configured' };
    }

    // WebCheck container
    try {
      const { checkHealth } = require('../services/webCheckService');
      const start = Date.now();
      const ok = await checkHealth();
      checks.webcheck = { status: ok ? 'online' : 'offline', latencyMs: Date.now() - start };
    } catch (e) {
      checks.webcheck = { status: 'offline', error: e.message };
    }

    // ZAP (standard scanner on port 8080)
    try {
      const axios = require('axios');
      const zapUrl = process.env.ZAP_API_URL || 'http://127.0.0.1:8080';
      const start = Date.now();
      const resp = await axios.get(`${zapUrl}/JSON/core/view/version/`, { timeout: 3000 });
      checks.zap = {
        status: resp.data?.version ? 'online' : 'offline',
        version: resp.data?.version,
        latencyMs: Date.now() - start,
      };
    } catch (e) {
      checks.zap = { status: 'offline', error: e.message };
    }

    // ZAP Auth scanner (port 8081)
    try {
      const axios = require('axios');
      const start = Date.now();
      const resp = await axios.get('http://127.0.0.1:8081/JSON/core/view/version/', { timeout: 3000 });
      checks.zapAuth = {
        status: resp.data?.version ? 'online' : 'offline',
        version: resp.data?.version,
        latencyMs: Date.now() - start,
      };
    } catch (e) {
      checks.zapAuth = { status: 'offline', error: e.message };
    }

    // Gemini API (check key presence only — don't make API call to avoid quota)
    checks.gemini = {
      status: process.env.GEMINI_API_KEY ? 'configured' : 'not_configured',
    };

    // Google PageSpeed Insights
    checks.pagespeed = {
      status: process.env.PSI_API_KEY ? 'configured' : 'not_configured',
    };

    // urlscan.io
    checks.urlscan = {
      status: process.env.URLSCAN_API_KEY ? 'configured' : 'not_configured',
    };

    // BullMQ (check if queue can be reached via Redis)
    try {
      const { getScanQueue } = require('../queues/scanQueue');
      const queue = getScanQueue ? getScanQueue() : null;
      if (queue) {
        const counts = await queue.getJobCounts('waiting', 'active', 'completed', 'failed');
        checks.bullmq = { status: 'online', ...counts };
      } else {
        checks.bullmq = { status: 'unavailable' };
      }
    } catch (e) {
      checks.bullmq = { status: checks.redis.status === 'online' ? 'unavailable' : 'offline', error: e.message };
    }


    res.json({ success: true, checks, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('❌ [admin/system-health]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch system health', details: devMsg(err) });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// GET /api/admin/analytics — Executive analytics
//
// Every number here is traceable to a real, currently-stored field. Two hard
// constraints from the schema shape what's included:
//   1. There is no invoice/transaction table anywhere — Stripe webhooks only
//      ever write planType/subscriptionStatus/expiresAt, never amount_paid.
//      So there is no "revenue" figure to report. `estimatedRecurringValue`
//      is explicitly an ESTIMATE: (count of orgs with subscriptionStatus
//      'active' on each plan) × (that plan's published list price, normalized
//      to a monthly figure). It does not reflect discounts, proration, failed
//      payments, or refunds — none of which are recorded anywhere.
//   2. ScanResult.createdAt has a 7-day TTL index (see models/ScanResult.js) —
//      MongoDB physically deletes scan documents after 7 days, so scan
//      activity can only ever be reported as a 7-day rolling window, never a
//      monthly/quarterly trend.
// ════════════════════════════════════════════════════════════════════════════

// Published list prices (¥), matching the pricing table in CLAUDE.md and the
// PLANS constant in frontend/src/pages/Profile.jsx exactly. Monthly-equivalent
// is annual ÷ 12, used only to make monthly and annual subscribers comparable
// on one chart — it is not a discount calculation.
const PLAN_PRICES = {
  light: { monthly: 30000, annual: 300000 },
  basic: { monthly: 50000, annual: 500000 },
  pro:   { monthly: 100000, annual: 1000000 },
};
const monthlyEquivalent = (planType, billingCycle) => {
  const p = PLAN_PRICES[planType];
  if (!p) return 0; // trial1/trial2 are one-time purchases, not recurring — excluded by design
  return billingCycle === 'annual' ? Math.round(p.annual / 12) : p.monthly;
};

// Produces a continuous [{ date: 'YYYY-MM-DD', count }] series for the last N
// days (inclusive of today), filling in zero for days with no matching docs —
// so a trend line never silently skips a day with no activity.
const fillDailySeries = (rawCounts, days) => {
  const map = new Map(rawCounts.map((r) => [r._id, r.count]));
  const series = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setUTCHours(0, 0, 0, 0);
    d.setUTCDate(d.getUTCDate() - i);
    const key = d.toISOString().slice(0, 10);
    series.push({ date: key, count: map.get(key) || 0 });
  }
  return series;
};

router.get('/analytics', async (req, res) => {
  try {
    const now = new Date();
    const since30 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const since7 = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const dayFormat = { $dateToString: { format: '%Y-%m-%d', date: '$createdAt', timezone: 'UTC' } };

    const [
      userGrowthRaw,
      orgGrowthRaw,
      planDistribution,
      subscriptionStatusDistribution,
      activeOrgsForValue,
      scanActivityRaw,
      topOrgsByUsage,
    ] = await Promise.all([
      User.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: dayFormat, count: { $sum: 1 } } },
      ]),
      Organization.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: dayFormat, count: { $sum: 1 } } },
      ]),
      Organization.aggregate([
        { $group: { _id: '$planType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Organization.aggregate([
        { $group: { _id: '$subscriptionStatus', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Organization.find({ subscriptionStatus: 'active' })
        .select('planType billingCycle')
        .lean(),
      ScanResult.aggregate([
        { $match: { createdAt: { $gte: since7 } } },
        { $group: { _id: { day: dayFormat, status: '$status' }, count: { $sum: 1 } } },
      ]),
      Organization.find({ scansUsed: { $gt: 0 } })
        .sort({ scansUsed: -1 })
        .limit(8)
        .select('name planType scansUsed scanLimit seatsUsed seatsAllowed')
        .lean(),
    ]);

    // ── Estimated recurring value (see disclaimer in the comment block above) ──
    let estimatedRecurringValueTotal = 0;
    const estimatedRecurringValueByPlan = {};
    for (const org of activeOrgsForValue) {
      const value = monthlyEquivalent(org.planType, org.billingCycle);
      estimatedRecurringValueTotal += value;
      if (value > 0) {
        estimatedRecurringValueByPlan[org.planType] = (estimatedRecurringValueByPlan[org.planType] || 0) + value;
      }
    }

    // ── Reshape scan activity into one row per day with a column per status ──
    const scanStatusKeys = ['queued', 'pending', 'combining', 'completed', 'failed', 'stopped', 'cancelled'];
    const scanByDay = new Map();
    for (const row of scanActivityRaw) {
      const { day, status } = row._id;
      if (!scanByDay.has(day)) {
        const base = { date: day, total: 0 };
        scanStatusKeys.forEach((k) => { base[k] = 0; });
        scanByDay.set(day, base);
      }
      const entry = scanByDay.get(day);
      entry[status] = (entry[status] || 0) + row.count;
      entry.total += row.count;
    }
    const scanActivity = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setUTCHours(0, 0, 0, 0);
      d.setUTCDate(d.getUTCDate() - i);
      const key = d.toISOString().slice(0, 10);
      const base = { date: key, total: 0 };
      scanStatusKeys.forEach((k) => { base[k] = 0; });
      scanActivity.push(scanByDay.get(key) || base);
    }

    res.json({
      success: true,
      userGrowth: fillDailySeries(userGrowthRaw, 30),
      organizationGrowth: fillDailySeries(orgGrowthRaw, 30),
      planDistribution,
      subscriptionStatusDistribution,
      estimatedRecurringValue: {
        total: estimatedRecurringValueTotal,
        byPlan: estimatedRecurringValueByPlan,
        activeOrgCount: activeOrgsForValue.length,
      },
      scanActivity,
      topOrgsByUsage,
    });
  } catch (err) {
    console.error('❌ [admin/analytics]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch analytics', details: devMsg(err) });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// MUTATION ENDPOINTS — user & organization lifecycle management
// ════════════════════════════════════════════════════════════════════════════

// ── PATCH /api/admin/users/:id ─────────────────────────────────────────────────
// Partial update — only the fields present in the body are changed.
// Body: { systemRole?: 'user'|'admin'|'superadmin', isDisabled?: boolean }
router.patch('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ success: false, error: 'User not found' });

    const { systemRole, isDisabled } = req.body;
    const isSelf = String(target._id) === String(req.adminUser._id);

    const assertNotLastAdmin = async () => {
      const otherAdmins = await User.countDocuments({
        _id: { $ne: target._id },
        systemRole: { $in: ADMIN_CAPABLE_ROLES },
        isDisabled: { $ne: true },
      });
      return otherAdmins > 0;
    };

    if (systemRole !== undefined) {
      if (!['user', 'admin', 'superadmin'].includes(systemRole)) {
        return res.status(400).json({ success: false, error: 'Invalid systemRole' });
      }
      if (isSelf) {
        return res.status(403).json({ success: false, error: 'You cannot change your own system role' });
      }
      const willLoseAdmin = isActiveAdmin(target) && !ADMIN_CAPABLE_ROLES.includes(systemRole);
      if (willLoseAdmin && !(await assertNotLastAdmin())) {
        return res.status(409).json({ success: false, error: 'Cannot remove the last remaining administrator' });
      }
      target.systemRole = systemRole;
    }

    if (isDisabled !== undefined) {
      if (typeof isDisabled !== 'boolean') {
        return res.status(400).json({ success: false, error: 'isDisabled must be a boolean' });
      }
      if (isSelf && isDisabled) {
        return res.status(403).json({ success: false, error: 'You cannot disable your own account' });
      }
      if (isDisabled && isActiveAdmin(target) && !(await assertNotLastAdmin())) {
        return res.status(409).json({ success: false, error: 'Cannot disable the last remaining administrator' });
      }
      target.isDisabled = isDisabled;
    }

    await target.save();

    res.json({
      success: true,
      user: {
        _id: target._id,
        name: target.name,
        email: target.email,
        systemRole: target.systemRole,
        isDisabled: target.isDisabled,
      },
    });
  } catch (err) {
    console.error('❌ [admin/users PATCH]', err.message);
    res.status(500).json({ success: false, error: 'Failed to update user', details: devMsg(err) });
  }
});

// ── DELETE /api/admin/users/:id/organization ──────────────────────────────────
// Remove a user from their organization without deleting the account.
router.delete('/users/:id/organization', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ success: false, error: 'User not found' });
    if (!target.organizationId) {
      return res.status(400).json({ success: false, error: 'User does not belong to an organization' });
    }
    if (target.role === 'owner') {
      return res.status(409).json({ success: false, error: 'Cannot remove an organization owner this way — delete the organization instead' });
    }

    const orgId = target.organizationId;
    target.organizationId = null;
    await target.save();

    // Recount seats from DB for accuracy (same pattern as orgRoutes.js accept-invite).
    const actualSeats = await User.countDocuments({ organizationId: orgId });
    await Organization.updateOne({ _id: orgId }, { $set: { seatsUsed: actualSeats } });

    res.json({ success: true });
  } catch (err) {
    console.error('❌ [admin/users/:id/organization DELETE]', err.message);
    res.status(500).json({ success: false, error: 'Failed to remove user from organization', details: devMsg(err) });
  }
});

// ── DELETE /api/admin/users/:id ────────────────────────────────────────────────
// Permanently deletes a user account.
router.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ success: false, error: 'User not found' });

    if (String(target._id) === String(req.adminUser._id)) {
      return res.status(403).json({ success: false, error: 'You cannot delete your own account' });
    }
    if (target.role === 'owner' && target.organizationId) {
      return res.status(409).json({ success: false, error: 'Cannot delete an organization owner — delete the organization instead' });
    }
    if (isActiveAdmin(target)) {
      const otherAdmins = await User.countDocuments({
        _id: { $ne: target._id },
        systemRole: { $in: ADMIN_CAPABLE_ROLES },
        isDisabled: { $ne: true },
      });
      if (otherAdmins === 0) {
        return res.status(409).json({ success: false, error: 'Cannot delete the last remaining administrator' });
      }
    }

    const orgId = target.organizationId;
    await User.deleteOne({ _id: target._id });

    if (orgId) {
      const actualSeats = await User.countDocuments({ organizationId: orgId });
      await Organization.updateOne({ _id: orgId }, { $set: { seatsUsed: actualSeats } });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ [admin/users DELETE]', err.message);
    res.status(500).json({ success: false, error: 'Failed to delete user', details: devMsg(err) });
  }
});

// ── PATCH /api/admin/organizations/:id ────────────────────────────────────────
// Enable/disable an organization — disabling blocks login for all its members.
// Body: { isDisabled: boolean }
router.patch('/organizations/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid organization id' });
    }

    const org = await Organization.findById(id);
    if (!org) return res.status(404).json({ success: false, error: 'Organization not found' });

    const { isDisabled } = req.body;
    if (isDisabled !== undefined) {
      if (typeof isDisabled !== 'boolean') {
        return res.status(400).json({ success: false, error: 'isDisabled must be a boolean' });
      }
      org.isDisabled = isDisabled;
    }

    await org.save();
    res.json({ success: true, organization: { _id: org._id, name: org.name, isDisabled: org.isDisabled } });
  } catch (err) {
    console.error('❌ [admin/organizations PATCH]', err.message);
    res.status(500).json({ success: false, error: 'Failed to update organization', details: devMsg(err) });
  }
});

// ── POST /api/admin/organizations/:id/cancel-subscription ────────────────────
// Cancels the organization's Stripe subscription at the end of the current
// billing period. Mirrors POST /api/stripe/cancel-subscription exactly, just
// scoped by organization id instead of the caller's own account. DB plan
// fields are intentionally NOT touched here — per the existing architecture,
// the Stripe webhook is the only writer of plan/subscription state.
router.post('/organizations/:id/cancel-subscription', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid organization id' });
    }

    const org = await Organization.findById(id);
    if (!org) return res.status(404).json({ success: false, error: 'Organization not found' });
    if (!org.stripeSubscriptionId) {
      return res.status(400).json({ success: false, error: 'This organization has no active subscription' });
    }

    const subscription = await stripe.subscriptions.update(org.stripeSubscriptionId, {
      cancel_at_period_end: true,
    });

    console.log(`🚫 [admin] Subscription cancel_at_period_end set for org ${org._id} by ${req.adminUser.email}`);

    res.json({
      success: true,
      cancelAt: subscription.cancel_at ? new Date(subscription.cancel_at * 1000) : null,
    });
  } catch (err) {
    console.error('❌ [admin/organizations/:id/cancel-subscription]', err.message);
    res.status(500).json({ success: false, error: 'Failed to cancel subscription', details: devMsg(err) });
  }
});

// ── DELETE /api/admin/organizations/:id ───────────────────────────────────────
// Permanently deletes an organization. Members are detached (organizationId
// cleared) rather than deleted — their accounts survive as standalone users.
// Any active Stripe subscription is set to cancel at period end so billing
// doesn't continue against a deleted organization.
router.delete('/organizations/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid organization id' });
    }

    const org = await Organization.findById(id);
    if (!org) return res.status(404).json({ success: false, error: 'Organization not found' });

    if (org.stripeSubscriptionId) {
      try {
        await stripe.subscriptions.update(org.stripeSubscriptionId, { cancel_at_period_end: true });
      } catch (stripeErr) {
        console.warn(`⚠️ [admin] Failed to cancel Stripe subscription for org ${org._id} during deletion:`, stripeErr.message);
      }
    }

    const { modifiedCount } = await User.updateMany(
      { organizationId: org._id },
      { $set: { organizationId: null } }
    );
    await Organization.deleteOne({ _id: org._id });

    console.log(`🗑️ [admin] Organization ${org._id} deleted by ${req.adminUser.email}, ${modifiedCount} member(s) detached`);

    res.json({ success: true, membersDetached: modifiedCount });
  } catch (err) {
    console.error('❌ [admin/organizations DELETE]', err.message);
    res.status(500).json({ success: false, error: 'Failed to delete organization', details: devMsg(err) });
  }
});

module.exports = router;
