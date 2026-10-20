// backend/routes/admin.js
// Platform-level Global Admin Dashboard API
// All routes are protected by auth + adminAuth middleware.
// Read endpoints for statistics, users, organizations, scans, system health and
// the admin audit log, plus mutation endpoints for user/organization lifecycle
// management. Every mutation is recorded in AdminAuditLog (services/adminAudit.js).
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const stripe = require('../config/stripe');
const auth = require('../middleware/auth');
const { invalidatePrincipal, invalidateAllPrincipals, isRecentAuth } = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');
const User = require('../models/User');
const Organization = require('../models/Organization');
const ScanResult = require('../models/ScanResult');
const ScheduledScan = require('../models/ScheduledScan');
const Invite = require('../models/Invite');
const AdminAuditLog = require('../models/AdminAuditLog');
const { applySubscription, isCancellationScheduled, periodEndOf } = require('../services/subscriptionLifecycle');
const { entitlementFilter } = require('../utils/entitlement');
const { subscriptionState, isCancellable } = require('../utils/subscriptionState');
const { RECENT_AUTH_MAX_AGE_MS } = require('../utils/sessionPolicy');
const { scansUsedThisMonth, startOfUtcMonth } = require('../utils/monthlyUsage');
const { beginAdminAction, finishAdminAction, recordDenied } = require('../services/adminAudit');

const devMsg = (err) =>
  process.env.NODE_ENV !== 'production' ? err.message : undefined;

const ADMIN_CAPABLE_ROLES = ['admin', 'superadmin'];

// Search boxes feed straight into $regex. Without escaping, a stray '(' is a
// 500 and a crafted pattern is a ReDoS against the event loop — admin-only,
// but neither is an acceptable failure mode.
const escapeRegex = (str) => String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// True if this user currently counts as an active platform administrator
// (used to make sure an action never leaves zero admins on the platform).
const isActiveAdmin = (u) => ADMIN_CAPABLE_ROLES.includes(u.systemRole) && !u.isDisabled;

// Privilege hierarchy. `adminAuth` lets both 'admin' and 'superadmin' through,
// so without this a plain admin could promote anyone to superadmin, or demote,
// disable and delete existing superadmins — i.e. the three-role enum would
// describe a hierarchy that nothing actually enforced.
// Rule: only a superadmin may grant/revoke administrator roles, act on an
// account that already holds one, lock out an organization that contains one,
// cancel a customer's billing, or delete an organization. Admins manage
// ordinary users only.
const holdsAdminRole = (u) => ADMIN_CAPABLE_ROLES.includes(u.systemRole);
const isSuperadmin = (req) => req.adminUser && req.adminUser.systemRole === 'superadmin';

// Soft-deleted organizations are kept for recovery and history but are gone from
// every admin listing and count. `null` also matches documents without the field.
const NOT_DELETED = { deletedAt: null };

// Scan statuses the dashboard can filter on (ScanResult.status enum).
const SCAN_STATUSES = ['queued', 'pending', 'combining', 'completed', 'failed', 'stopped', 'cancelled'];
const IN_FLIGHT_SCAN_STATUSES = ['queued', 'pending', 'combining'];
const PLAN_FILTERS = ['light', 'basic', 'pro', 'trial1', 'trial2', 'free'];
const ORG_ROLES = ['owner', 'admin', 'member'];
const SYSTEM_ROLES = ['user', 'admin', 'superadmin'];
// Stripe statuses after which a subscription bills no one (matches
// services/subscriptionLifecycle.js).
const STRIPE_ENDED = ['canceled', 'incomplete_expired'];

// Query strings arrive as strings, arrays (?a=1&a=2) or not at all. Only a
// plain string is a usable filter value.
const qstr = (v) => (typeof v === 'string' ? v.trim() : '');

// Page/limit parsing that cannot produce NaN (which 500'd the list endpoints).
const pageParams = (query) => {
  const page = Number.parseInt(qstr(query.page), 10);
  const limit = Number.parseInt(qstr(query.limit), 10);
  const pageNum = Number.isFinite(page) && page > 0 ? page : 1;
  const limitNum = Number.isFinite(limit) && limit > 0 ? Math.min(100, limit) : 20;
  return { pageNum, limitNum, skip: (pageNum - 1) * limitNum };
};

const paginationOf = ({ pageNum, limitNum }, total) => ({
  page: pageNum,
  limit: limitNum,
  total,
  pages: Math.max(1, Math.ceil(total / limitNum)),
});

const badFilter = (res) =>
  res.status(400).json({ success: false, code: 'ADMIN_INVALID_PAYLOAD', error: 'Invalid filter value' });

// Revoking access must also cut the realtime channel: the Socket.IO handshake
// is only checked at connect time, so an already-open socket would otherwise
// keep streaming scan progress and results to a just-disabled user.
// Lazily required (like the health-check probes below) to keep this route file
// free of a load-time dependency on the socket layer.
const cutRealtime = (userId) => {
  try {
    require('../services/notificationService').disconnectUser(userId);
  } catch (err) {
    console.error('⚠️ [admin] realtime disconnect failed:', err.message);
  }
};

// Disabling an organization blocks every one of its members at the auth layer,
// exactly as if each had been disabled individually. Without this guard,
// disabling the org that happens to contain the last administrator locks
// everyone out of the admin panel — recoverable only via scripts/grantSystemRole.js
// or a direct DB edit. The user-level paths already refuse to remove the last
// administrator; this applies the same rule to the org-level switch.
const adminsRemainAfterOrgDisable = async (orgId) => {
  const alreadyDisabled = await Organization.find(
    { isDisabled: true, _id: { $ne: orgId } }, { _id: 1 }
  ).lean();
  const blockedOrgIds = [orgId, ...alreadyDisabled.map((o) => o._id)];

  const reachable = await User.countDocuments({
    systemRole: { $in: ADMIN_CAPABLE_ROLES },
    isDisabled: { $ne: true },
    $or: [
      { organizationId: null },
      { organizationId: { $exists: false } },
      { organizationId: { $nin: blockedOrgIds } },
    ],
  });
  return reachable > 0;
};

// Superadmins who could still sign in and act: enabled, and not in a disabled
// organization (nor in `blockedOrgId`, the one about to be disabled). Only a
// superadmin can grant admin rights, cancel billing, delete organizations or
// read the audit log, so no action may leave the platform without one — the
// generic last-admin guards count plain admins too and do not prevent that.
// Recovery would otherwise need a script run against production.
const reachableSuperadmins = async ({ excludeUserId = null, blockedOrgId = null } = {}) => {
  const disabledOrgs = await Organization.find({ isDisabled: true }, { _id: 1 }).lean();
  const blocked = disabledOrgs.map((o) => o._id);
  if (blockedOrgId) blocked.push(blockedOrgId);
  const query = {
    systemRole: 'superadmin',
    isDisabled: { $ne: true },
    $or: [
      { organizationId: null },
      { organizationId: { $exists: false } },
      { organizationId: { $nin: blocked } },
    ],
  };
  if (excludeUserId) query._id = { $ne: excludeUserId };
  return User.countDocuments(query);
};

/** True when `target` is an enabled superadmin and nobody else could take over. */
const isLastSuperadmin = async (target) =>
  target.systemRole === 'superadmin' && !target.isDisabled &&
  (await reachableSuperadmins({ excludeUserId: target._id })) === 0;

const lastSuperadmin = (res) =>
  res.status(409).json({
    success: false,
    code: 'ADMIN_LAST_SUPERADMIN',
    error: 'This would leave no superadmin able to sign in',
  });

const superadminRequired = (res) =>
  res.status(403).json({
    success: false,
    code: 'ADMIN_SUPERADMIN_REQUIRED',
    error: 'Only a superadmin can perform this action',
  });

const reauthRequired = (res) =>
  res.status(403).json({
    success: false,
    code: 'ADMIN_REAUTH_REQUIRED',
    error: 'Recent sign-in required for this action',
  });

// An audit row could not be written, so the action was refused (fail closed).
const auditUnavailable = (res) =>
  res.status(503).json({
    success: false,
    code: 'ADMIN_AUDIT_FAILED',
    error: 'Action refused: the audit record could not be written',
  });

// Destructive actions need a sign-in within RECENT_AUTH_MAX_AGE_MS. Checked
// after the permission checks, so a caller who may not act at all is told so
// (and the attempt audited) rather than being sent to sign in again.
const hasRecentAuth = (req) => isRecentAuth(req, RECENT_AUTH_MAX_AGE_MS);

// A Stripe "no such subscription" means nothing is billing; anything else is a
// real failure the caller must not proceed past.
const isStripeMissing = (err) =>
  !!err && (err.code === 'resource_missing' || err.statusCode === 404);

// Run independent dashboard queries. A failed one becomes `null` and is named in
// `unavailable`, so one failure neither blanks the whole tab nor shows up as a
// plausible 0 — the UI renders null as "unavailable". If every query failed the
// database is down, and the caller answers with an error instead.
async function settleMetrics(tasks) {
  const names = Object.keys(tasks);
  const settled = await Promise.allSettled(names.map((n) => tasks[n]()));
  const values = {};
  const unavailable = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') {
      values[names[i]] = r.value;
    } else {
      values[names[i]] = null;
      unavailable.push(names[i]);
      console.error(`❌ [admin] metric ${names[i]} failed:`, r.reason && r.reason.message);
    }
  });
  return { values, unavailable, allFailed: unavailable.length === names.length };
}

// The plan an organization is on right now, for plan distributions: its stored
// plan while that plan grants access (active, trialing, cancelling — paid until
// the period ends — or a legacy one-time org), 'lapsed' when a plan is still
// stored but no longer grants access (expired, past_due, canceled … before the
// reconcile sweep clears it), and null (Free) when there is no plan. Grouping by
// the stored planType alone counted lapsed customers as paying ones.
const PLAN_IN_EFFECT_STATES = ['active', 'trialing', 'cancelling', 'onetime'];
const planBucket = (org, now) => {
  if (!org.planType) return null;
  return PLAN_IN_EFFECT_STATES.includes(subscriptionState(org, now)) ? org.planType : 'lapsed';
};
const planDistributionOf = (orgs, now) => {
  const counts = new Map();
  for (const org of orgs) {
    const key = planBucket(org, now);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].map(([_id, count]) => ({ _id, count })).sort((a, b) => b.count - a.count);
};
const PLAN_STATE_FIELDS = 'planType billingCycle subscriptionStatus expiresAt cancelAtPeriodEnd';

// Apply auth + adminAuth to ALL routes in this router
router.use(auth, adminAuth);

// ── GET /api/admin/kpis ────────────────────────────────────────────────────────
// Aggregate platform-level KPI statistics for the dashboard overview. Each
// figure is queried independently; one that fails is null (see settleMetrics).
router.get('/kpis', async (req, res) => {
  try {
    const now = new Date();
    const { values: v, unavailable, allFailed } = await settleMetrics({
      totalUsers: () => User.countDocuments({}),
      verifiedUsers: () => User.countDocuments({ isVerified: true }),
      // Paid access right now, by the same rule that grants it
      // (utils/entitlement.js) — not the raw 'active' status, which outlives the
      // paid period until the reconcile sweep catches up.
      activeOrgs: () => Organization.countDocuments({ ...NOT_DELETED, ...entitlementFilter(now) }),
      totalOrgs: () => Organization.countDocuments(NOT_DELETED),
      // Lifetime completed scans. Organization.totalScansAllTime is incremented
      // on every billing path (planService) and never expires; ScanResult keeps
      // only 7 days. Soft-deleted organizations are included: their scans ran.
      // Users without an organization cannot start scans (planCheck), so this
      // covers every completed scan since the counter was introduced. No
      // organizations at all is a genuine 0.
      totalScansAllTime: async () => {
        const agg = await Organization.aggregate([{ $group: { _id: null, total: { $sum: '$totalScansAllTime' } } }]);
        return agg.length ? agg[0].total || 0 : 0;
      },
      runningScans: () => ScanResult.countDocuments({ status: { $in: IN_FLIGHT_SCAN_STATUSES } }),
      // .lean() bypasses schema defaults — normalize like GET /users.
      recentUsers: async () => (await User.find({}).sort({ createdAt: -1 }).limit(5)
        .select('name email createdAt systemRole').lean())
        .map((u) => ({ ...u, systemRole: u.systemRole || 'user' })),
      planDistribution: async () => planDistributionOf(
        await Organization.find(NOT_DELETED).select(PLAN_STATE_FIELDS).lean(), now),
    });
    if (allFailed) throw new Error('every KPI query failed');

    res.json({
      success: true,
      kpis: {
        totalUsers: v.totalUsers,
        verifiedUsers: v.verifiedUsers,
        // `activeOrgs` kept as the field name the UI already reads.
        activeOrgs: v.activeOrgs,
        totalOrgs: v.totalOrgs,
        totalScansAllTime: v.totalScansAllTime,
        runningScans: v.runningScans,
      },
      planDistribution: v.planDistribution,
      recentUsers: v.recentUsers,
      unavailable,
      generatedAt: now.toISOString(),
    });
  } catch (err) {
    console.error('❌ [admin/kpis]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch KPIs', details: devMsg(err) });
  }
});

// ── GET /api/admin/users ───────────────────────────────────────────────────────
// Paginated list of all users with optional search and filters.
router.get('/users', async (req, res) => {
  try {
    const paging = pageParams(req.query);
    const search = qstr(req.query.search);
    const role = qstr(req.query.role);
    const systemRole = qstr(req.query.systemRole);
    if (role && !ORG_ROLES.includes(role)) return badFilter(res);
    if (systemRole && !SYSTEM_ROLES.includes(systemRole)) return badFilter(res);

    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: escapeRegex(search), $options: 'i' } },
        { email: { $regex: escapeRegex(search), $options: 'i' } },
      ];
    }
    if (role) query.role = role;
    if (systemRole === 'user') {
      // Documents created before systemRole existed have no such key at all.
      query.systemRole = { $in: ['user', null] };
    } else if (systemRole) {
      query.systemRole = systemRole;
    }

    const [total, users] = await Promise.all([
      User.countDocuments(query),
      User.find(query)
        .sort({ createdAt: -1 })
        .skip(paging.skip)
        .limit(paging.limitNum)
        .select('name email role systemRole isVerified isDisabled createdAt lastLoginAt organizationId')
        .populate('organizationId', 'name planType billingCycle subscriptionStatus expiresAt cancelAtPeriodEnd')
        .lean(),
    ]);

    const now = new Date();
    // .lean() returns raw MongoDB documents, bypassing Mongoose's schema-default
    // injection — documents created before systemRole existed have no such key
    // at all. Normalize here so the API contract guarantees systemRole is always
    // a string, matching the schema default (see backfillSystemRole.js for the
    // one-time data migration that fixed existing documents).
    const normalizedUsers = users.map(({ organizationId: org, ...u }) => ({
      ...u,
      systemRole: u.systemRole || 'user',
      isDisabled: u.isDisabled || false,
      lastLoginAt: u.lastLoginAt || null,
      organizationId: org ? org._id : null,
      // The plan shown for a user is their organization's, with its real state
      // (a lapsed subscription reads as expired, not as a paid plan).
      organization: org ? {
        _id: org._id,
        name: org.name,
        planType: org.planType || null,
        subscriptionState: subscriptionState(org, now),
      } : null,
    }));

    res.json({
      success: true,
      users: normalizedUsers,
      pagination: paginationOf(paging, total),
    });
  } catch (err) {
    console.error('❌ [admin/users]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch users', details: devMsg(err) });
  }
});

// ── GET /api/admin/organizations ──────────────────────────────────────────────
// Paginated list of all organizations with usage statistics.
router.get('/organizations', async (req, res) => {
  try {
    const paging = pageParams(req.query);
    const search = qstr(req.query.search);
    const plan = qstr(req.query.plan);
    const status = qstr(req.query.status);
    if (plan && !PLAN_FILTERS.includes(plan)) return badFilter(res);
    if (status && !/^[a-z_]+$/.test(status)) return badFilter(res);

    const query = { ...NOT_DELETED };
    if (search) {
      query.name = { $regex: escapeRegex(search), $options: 'i' };
    }
    if (plan === 'free') query.planType = null;
    else if (plan) query.planType = plan;
    if (status) query.subscriptionStatus = status;

    const [total, orgs] = await Promise.all([
      Organization.countDocuments(query),
      Organization.find(query)
        .sort({ createdAt: -1 })
        .skip(paging.skip)
        .limit(paging.limitNum)
        // Explicit projection, matching every other list query in this file.
        // Without it the whole document went to the browser, including
        // stripeCustomerId / stripeSubscriptionId / stripeCheckoutSessionId,
        // none of which the organizations table renders.
        .select('name planType billingCycle subscriptionStatus isDisabled ' +
                'seatsAllowed seatsUsed scanLimit scansUsed targetsUsed ' +
                'oneTimeRemainingScans expiresAt lastScanReset createdAt ' +
                'cancelAtPeriodEnd stripeSubscriptionId')
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

    const now = new Date();
    // stripeSubscriptionId is destructured OUT rather than spread: the table
    // only needs to know whether a cancellable subscription exists, so send a
    // boolean instead of the Stripe identifier.
    const enriched = orgs.map(({ stripeSubscriptionId, ...o }) => ({
      ...o,
      isDisabled: o.isDisabled || false,
      // The stored scansUsed is reset only when the org next scans, so it can
      // be last month's figure; this is the current UTC billing month's.
      scansUsedThisMonth: scansUsedThisMonth(o, now),
      owner: ownerMap[String(o._id)] || null,
      hasSubscription: Boolean(stripeSubscriptionId),
      subscriptionState: subscriptionState(o, now),
      cancellable: isCancellable({ ...o, stripeSubscriptionId }, now),
    }));

    res.json({
      success: true,
      organizations: enriched,
      pagination: paginationOf(paging, total),
    });
  } catch (err) {
    console.error('❌ [admin/organizations]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch organizations', details: devMsg(err) });
  }
});

// ── GET /api/admin/scans ───────────────────────────────────────────────────────
// Paginated list of all scans across all users with status filter.
// Scans exist for 7 days (ScanResult TTL). Failed/stopped scans keep their
// lightweight record for that period; their heavy artifacts are purged hourly
// (jobs/cleanupJob.js).
router.get('/scans', async (req, res) => {
  try {
    const paging = pageParams(req.query);
    const status = qstr(req.query.status);
    if (status && !SCAN_STATUSES.includes(status)) return badFilter(res);

    const query = {};
    if (status) query.status = status;

    const [total, scans] = await Promise.all([
      ScanResult.countDocuments(query),
      ScanResult.find(query)
        .sort({ createdAt: -1 })
        .skip(paging.skip)
        .limit(paging.limitNum)
        // zapResult and webCheckResult are deliberately NOT selected. They are
        // untyped Object columns holding entire scan payloads (ZAP alert arrays,
        // WebCheck results); this handler never reads them and AdminScans.jsx
        // never renders them, so selecting them shipped every customer's full
        // vulnerability detail to the browser — up to 100 rows per request.
        .select('analysisId target status failureReason userId createdAt updatedAt')
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

    const now = Date.now();
    const enriched = scans.map((s) => {
      const inProgress = IN_FLIGHT_SCAN_STATUSES.includes(s.status);
      const created = s.createdAt ? new Date(s.createdAt).getTime() : null;
      const updated = s.updatedAt ? new Date(s.updatedAt).getTime() : null;
      return {
        ...s,
        user: userMap[String(s.userId)] || null,
        inProgress,
        // Finished scans: time to their last update (there is no separate
        // completion timestamp). Running scans: time elapsed so far — the old
        // updatedAt-based figure showed "time since the last progress write".
        duration: !inProgress && created && updated ? Math.max(0, Math.round((updated - created) / 1000)) : null,
        elapsed: inProgress && created ? Math.max(0, Math.round((now - created) / 1000)) : null,
      };
    });

    res.json({
      success: true,
      scans: enriched,
      pagination: paginationOf(paging, total),
    });
  } catch (err) {
    console.error('❌ [admin/scans]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch scans', details: devMsg(err) });
  }
});

// ── GET /api/admin/system-health ──────────────────────────────────────────────
// Health of the services Fortexa runs on in production. The service list,
// check methods, timeouts and status meanings live in config/healthInventory.js;
// the checks themselves in services/systemHealth.js (read-only, time-boxed,
// concurrent, sanitized, briefly cached). `?service=<id>` re-checks one
// inventory service now — the only thing a caller can choose.
const systemHealth = require('../services/systemHealth');
const { SERVICE_IDS: HEALTH_SERVICE_IDS } = require('../config/healthInventory');

router.get('/system-health', async (req, res) => {
  try {
    const { service } = req.query;
    if (service !== undefined && typeof service !== 'string') return badFilter(res);
    const retry = qstr(service);
    if (retry && !HEALTH_SERVICE_IDS.includes(retry)) return badFilter(res);
    const report = await systemHealth.getReport({ retry: retry || null });
    res.json({ success: true, ...report });
  } catch (err) {
    console.error('❌ [admin/system-health]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch system health', details: devMsg(err) });
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
//      is explicitly an ESTIMATE: (count of organizations whose subscription
//      grants paid access right now, by utils/entitlement.js, on each plan) ×
//      (that plan's published list price, normalized to a monthly figure). It
//      does not reflect discounts, proration, failed payments, or refunds —
//      none of which are recorded anywhere.
//   2. ScanResult.createdAt has a 7-day TTL index (see models/ScanResult.js) —
//      MongoDB physically deletes scan documents after 7 days, so scan
//      activity can only ever be reported as a 7-day rolling window, never a
//      monthly/quarterly trend.
// ════════════════════════════════════════════════════════════════════════════

// Prices come from the plan catalog. monthlyEquivalent returns 0 for trial1/trial2:
// they are one-time purchases, not recurring revenue, and are excluded by design.
const { monthlyEquivalent } = require('../config/planCatalog');

// Produces a continuous [{ date: 'YYYY-MM-DD', count }] series for the last N
// days (inclusive of today), filling in zero for days with no matching docs —
// so a trend line never silently skips a day with no activity.
const fillDailySeries = (rawCounts, days, startOfToday) => {
  const map = new Map(rawCounts.map((r) => [r._id, r.count]));
  const series = [];
  for (let i = days - 1; i >= 0; i--) {
    const key = new Date(startOfToday.getTime() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    series.push({ date: key, count: map.get(key) || 0 });
  }
  return series;
};

router.get('/analytics', async (req, res) => {
  try {
    const now = new Date();
    // Day boundaries are UTC: the 30-day window starts at 00:00 UTC 29 days ago,
    // so every bucket in the series is a whole day (the old rolling 30×24 h
    // window cut the first day short).
    const startOfToday = new Date(now);
    startOfToday.setUTCHours(0, 0, 0, 0);
    const since30 = new Date(startOfToday.getTime() - 29 * 24 * 60 * 60 * 1000);
    const since7 = new Date(startOfToday.getTime() - 6 * 24 * 60 * 60 * 1000);
    const monthStart = startOfUtcMonth(now);
    const dayFormat = { $dateToString: { format: '%Y-%m-%d', date: '$createdAt', timezone: 'UTC' } };

    // Independent queries; a failed one leaves its sections null (settleMetrics).
    const { values: q, unavailable: failedQueries, allFailed } = await settleMetrics({
      userGrowthRaw: () => User.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: dayFormat, count: { $sum: 1 } } },
      ]),
      // Registrations that happened, including organizations deleted since.
      orgGrowthRaw: () => Organization.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: dayFormat, count: { $sum: 1 } } },
      ]),
      orgsForState: () => Organization.find(NOT_DELETED).select(PLAN_STATE_FIELDS).lean(),
      activeOrgsForValue: () => Organization.find({ ...NOT_DELETED, ...entitlementFilter(now) })
        .select('planType billingCycle')
        .lean(),
      scanActivityRaw: () => ScanResult.aggregate([
        { $match: { createdAt: { $gte: since7 } } },
        { $group: { _id: { day: dayFormat, status: '$status' }, count: { $sum: 1 } } },
      ]),
      // Usage this UTC billing month. planService resets scansUsed only when an
      // org next scans, so an org whose counters were last reset in an earlier
      // month has used 0 this month whatever the stored figure says.
      topOrgsByUsage: () => Organization.find({ ...NOT_DELETED, scansUsed: { $gt: 0 }, lastScanReset: { $gte: monthStart } })
        .sort({ scansUsed: -1 })
        .limit(8)
        .select('name planType scansUsed scanLimit seatsUsed seatsAllowed lastScanReset')
        .lean(),
    });
    if (allFailed) throw new Error('every analytics query failed');

    // ── Subscription health: the computed state, not the raw Stripe status ──
    let subscriptionStatusDistribution = null;
    if (q.orgsForState) {
      const stateCounts = {};
      for (const org of q.orgsForState) {
        const state = subscriptionState(org, now);
        stateCounts[state] = (stateCounts[state] || 0) + 1;
      }
      subscriptionStatusDistribution = Object.entries(stateCounts)
        .map(([_id, count]) => ({ _id, count }))
        .sort((a, b) => b.count - a.count);
    }

    // ── Estimated recurring value (see disclaimer in the comment block above) ──
    let estimatedRecurringValue = null;
    if (q.activeOrgsForValue) {
      let total = 0;
      const byPlan = {};
      for (const org of q.activeOrgsForValue) {
        const value = monthlyEquivalent(org.planType, org.billingCycle);
        total += value;
        if (value > 0) byPlan[org.planType] = (byPlan[org.planType] || 0) + value;
      }
      estimatedRecurringValue = { total, byPlan, activeOrgCount: q.activeOrgsForValue.length };
    }

    // ── Reshape scan activity into one row per day with a column per status ──
    let scanActivity = null;
    if (q.scanActivityRaw) {
      const scanByDay = new Map();
      for (const row of q.scanActivityRaw) {
        const { day, status } = row._id;
        if (!scanByDay.has(day)) {
          const base = { date: day, total: 0 };
          SCAN_STATUSES.forEach((k) => { base[k] = 0; });
          scanByDay.set(day, base);
        }
        const entry = scanByDay.get(day);
        entry[status] = (entry[status] || 0) + row.count;
        entry.total += row.count;
      }
      scanActivity = [];
      for (let i = 6; i >= 0; i--) {
        const key = new Date(startOfToday.getTime() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        const base = { date: key, total: 0 };
        SCAN_STATUSES.forEach((k) => { base[k] = 0; });
        scanActivity.push(scanByDay.get(key) || base);
      }
    }

    // Response field → the query it depends on, so the UI can mark exactly
    // which sections could not be loaded.
    const DEPENDS = {
      userGrowth: 'userGrowthRaw',
      organizationGrowth: 'orgGrowthRaw',
      planDistribution: 'orgsForState',
      subscriptionStatusDistribution: 'orgsForState',
      estimatedRecurringValue: 'activeOrgsForValue',
      scanActivity: 'scanActivityRaw',
      topOrgsByUsage: 'topOrgsByUsage',
    };
    const unavailable = Object.keys(DEPENDS).filter((k) => failedQueries.includes(DEPENDS[k]));

    res.json({
      success: true,
      userGrowth: q.userGrowthRaw ? fillDailySeries(q.userGrowthRaw, 30, startOfToday) : null,
      organizationGrowth: q.orgGrowthRaw ? fillDailySeries(q.orgGrowthRaw, 30, startOfToday) : null,
      planDistribution: q.orgsForState ? planDistributionOf(q.orgsForState, now) : null,
      subscriptionStatusDistribution,
      estimatedRecurringValue,
      scanActivity,
      topOrgsByUsage: q.topOrgsByUsage
        ? q.topOrgsByUsage.map(({ lastScanReset, ...o }) => ({ ...o, scansUsedThisMonth: scansUsedThisMonth({ ...o, lastScanReset }, now) }))
        : null,
      unavailable,
      generatedAt: now.toISOString(),
    });
  } catch (err) {
    console.error('❌ [admin/analytics]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch analytics', details: devMsg(err) });
  }
});

// ── GET /api/admin/audit-log ───────────────────────────────────────────────────
// Read-only history of admin actions. Superadmin only: it shows what every
// administrator did, which is the superadmin's oversight job.
router.get('/audit-log', async (req, res) => {
  try {
    if (!isSuperadmin(req)) return superadminRequired(res);
    const paging = pageParams(req.query);
    const action = qstr(req.query.action);
    const targetId = qstr(req.query.targetId);
    if (action && !AdminAuditLog.ACTIONS.includes(action)) return badFilter(res);
    if (targetId && !mongoose.Types.ObjectId.isValid(targetId)) return badFilter(res);

    const query = {};
    if (action) query.action = action;
    if (targetId) query.targetId = targetId;

    const [total, entries] = await Promise.all([
      AdminAuditLog.countDocuments(query),
      AdminAuditLog.find(query)
        .sort({ createdAt: -1 })
        .skip(paging.skip)
        .limit(paging.limitNum)
        .select('actorType actorEmail actorRole operator ticket action targetType targetId targetLabel result errorCode createdAt completedAt')
        .lean(),
    ]);

    res.json({ success: true, entries, pagination: paginationOf(paging, total) });
  } catch (err) {
    console.error('❌ [admin/audit-log]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_FETCH_FAILED', error: 'Failed to fetch audit log', details: devMsg(err) });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// MUTATION ENDPOINTS — user & organization lifecycle management
//
// Pattern for every mutation: validate → permission checks (denials recorded) →
// beginAdminAction (a pending audit row; if it cannot be written the action is
// refused) → mutate → finishAdminAction with the outcome.
// ════════════════════════════════════════════════════════════════════════════

// ── PATCH /api/admin/users/:id ─────────────────────────────────────────────────
// Exactly one change per request.
// Body: { systemRole: 'user'|'admin'|'superadmin' }  or  { isDisabled: boolean }
router.patch('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ID', error: 'Invalid user id' });
    }

    const { systemRole, isDisabled } = req.body || {};
    if ((systemRole === undefined) === (isDisabled === undefined)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_PAYLOAD', error: 'Send exactly one of systemRole or isDisabled' });
    }
    if (systemRole !== undefined && !SYSTEM_ROLES.includes(systemRole)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ROLE', error: 'Invalid systemRole' });
    }
    if (isDisabled !== undefined && typeof isDisabled !== 'boolean') {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_PAYLOAD', error: 'isDisabled must be a boolean' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ success: false, code: 'ADMIN_USER_NOT_FOUND', error: 'User not found' });

    const isSelf = String(target._id) === String(req.adminUser._id);
    const action = systemRole !== undefined
      ? 'user.role_change'
      : (isDisabled ? 'user.disable' : 'user.enable');
    const auditTarget = { action, targetType: 'user', targetId: target._id, targetLabel: target.email };

    const assertNotLastAdmin = async () => {
      const otherAdmins = await User.countDocuments({
        _id: { $ne: target._id },
        systemRole: { $in: ADMIN_CAPABLE_ROLES },
        isDisabled: { $ne: true },
      });
      return otherAdmins > 0;
    };

    if (systemRole !== undefined) {
      if (isSelf) {
        return res.status(403).json({ success: false, code: 'ADMIN_SELF_ROLE', error: 'You cannot change your own system role' });
      }
      // Granting OR revoking an admin role is a superadmin-only action.
      if (req.adminUser.systemRole !== 'superadmin' &&
          (holdsAdminRole(target) || ADMIN_CAPABLE_ROLES.includes(systemRole))) {
        await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
        return superadminRequired(res);
      }
      // Changing who holds admin rights is destructive enough to need a fresh sign-in.
      if (!hasRecentAuth(req)) return reauthRequired(res);
      const willLoseAdmin = isActiveAdmin(target) && !ADMIN_CAPABLE_ROLES.includes(systemRole);
      if (willLoseAdmin && !(await assertNotLastAdmin())) {
        return res.status(409).json({ success: false, code: 'ADMIN_LAST_ADMIN', error: 'Cannot remove the last remaining administrator' });
      }
      if (systemRole !== 'superadmin' && (await isLastSuperadmin(target))) return lastSuperadmin(res);
    } else {
      if (isSelf && isDisabled) {
        return res.status(403).json({ success: false, code: 'ADMIN_SELF_DISABLE', error: 'You cannot disable your own account' });
      }
      if (req.adminUser.systemRole !== 'superadmin' && holdsAdminRole(target)) {
        await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
        return superadminRequired(res);
      }
      if (isDisabled && isActiveAdmin(target) && !(await assertNotLastAdmin())) {
        return res.status(409).json({ success: false, code: 'ADMIN_LAST_ADMIN', error: 'Cannot disable the last remaining administrator' });
      }
      if (isDisabled && (await isLastSuperadmin(target))) return lastSuperadmin(res);
    }

    const before = systemRole !== undefined
      ? { systemRole: target.systemRole || 'user' }
      : { isDisabled: Boolean(target.isDisabled) };
    let audit;
    try {
      audit = await beginAdminAction(req, { ...auditTarget, before });
    } catch (_) {
      return auditUnavailable(res);
    }

    try {
      if (systemRole !== undefined) target.systemRole = systemRole;
      else target.isDisabled = isDisabled;
      await target.save();
    } catch (err) {
      await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_ACTION_FAILED' });
      throw err;
    }

    // Make the change effective on the target's very next request rather than
    // waiting out the auth-middleware cache TTL.
    invalidatePrincipal(target._id);
    if (target.isDisabled) cutRealtime(target._id);

    await finishAdminAction(audit, {
      result: 'success',
      after: systemRole !== undefined ? { systemRole: target.systemRole } : { isDisabled: target.isDisabled },
    });

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
    res.status(500).json({ success: false, code: 'ADMIN_ACTION_FAILED', error: 'Failed to update user', details: devMsg(err) });
  }
});

// ── DELETE /api/admin/users/:id/organization ──────────────────────────────────
// Remove a user from their organization without deleting the account.
router.delete('/users/:id/organization', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ID', error: 'Invalid user id' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ success: false, code: 'ADMIN_USER_NOT_FOUND', error: 'User not found' });
    if (!target.organizationId) {
      return res.status(400).json({ success: false, code: 'ADMIN_NO_ORG', error: 'User does not belong to an organization' });
    }
    const auditTarget = { action: 'user.remove_from_org', targetType: 'user', targetId: target._id, targetLabel: target.email };
    if (req.adminUser.systemRole !== 'superadmin' && holdsAdminRole(target)) {
      await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
      return superadminRequired(res);
    }
    if (target.role === 'owner') {
      return res.status(409).json({ success: false, code: 'ADMIN_OWNER_PROTECTED', error: 'Cannot remove an organization owner this way — delete the organization instead' });
    }

    const orgId = target.organizationId;
    let audit;
    try {
      audit = await beginAdminAction(req, { ...auditTarget, before: { organizationId: orgId, role: target.role } });
    } catch (_) {
      return auditUnavailable(res);
    }

    try {
      target.organizationId = null;
      await target.save();
    } catch (err) {
      await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_ACTION_FAILED' });
      throw err;
    }

    // Recount seats from DB for accuracy (same pattern as orgRoutes.js accept-invite).
    const actualSeats = await User.countDocuments({ organizationId: orgId });
    await Organization.updateOne({ _id: orgId }, { $set: { seatsUsed: actualSeats } });
    invalidatePrincipal(target._id);

    await finishAdminAction(audit, { result: 'success', after: { organizationId: null } });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ [admin/users/:id/organization DELETE]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_ACTION_FAILED', error: 'Failed to remove user from organization', details: devMsg(err) });
  }
});

// ── DELETE /api/admin/users/:id ────────────────────────────────────────────────
// Permanently deletes a user account. Superadmin only (it cannot be undone;
// plain admins disable instead), recent sign-in required.
router.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ID', error: 'Invalid user id' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ success: false, code: 'ADMIN_USER_NOT_FOUND', error: 'User not found' });

    if (String(target._id) === String(req.adminUser._id)) {
      return res.status(403).json({ success: false, code: 'ADMIN_SELF_DELETE', error: 'You cannot delete your own account' });
    }
    const auditTarget = { action: 'user.delete', targetType: 'user', targetId: target._id, targetLabel: target.email };
    if (!isSuperadmin(req)) {
      await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
      return superadminRequired(res);
    }
    if (target.role === 'owner' && target.organizationId) {
      return res.status(409).json({ success: false, code: 'ADMIN_OWNER_PROTECTED', error: 'Cannot delete an organization owner — delete the organization instead' });
    }
    if (!hasRecentAuth(req)) return reauthRequired(res);
    if (isActiveAdmin(target)) {
      const otherAdmins = await User.countDocuments({
        _id: { $ne: target._id },
        systemRole: { $in: ADMIN_CAPABLE_ROLES },
        isDisabled: { $ne: true },
      });
      if (otherAdmins === 0) {
        return res.status(409).json({ success: false, code: 'ADMIN_LAST_ADMIN', error: 'Cannot delete the last remaining administrator' });
      }
    }
    if (await isLastSuperadmin(target)) return lastSuperadmin(res);

    const orgId = target.organizationId;
    let audit;
    try {
      audit = await beginAdminAction(req, {
        ...auditTarget,
        before: {
          name: target.name,
          email: target.email,
          systemRole: target.systemRole || 'user',
          role: target.role,
          organizationId: orgId || null,
          createdAt: target.createdAt,
        },
      });
    } catch (_) {
      return auditUnavailable(res);
    }

    try {
      await User.deleteOne({ _id: target._id });
    } catch (err) {
      await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_ACTION_FAILED' });
      throw err;
    }
    invalidatePrincipal(target._id);
    cutRealtime(target._id);

    if (orgId) {
      const actualSeats = await User.countDocuments({ organizationId: orgId });
      await Organization.updateOne({ _id: orgId }, { $set: { seatsUsed: actualSeats } });
    }

    await finishAdminAction(audit, { result: 'success', after: { deleted: true } });
    res.json({ success: true });
  } catch (err) {
    console.error('❌ [admin/users DELETE]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_ACTION_FAILED', error: 'Failed to delete user', details: devMsg(err) });
  }
});

// ── PATCH /api/admin/organizations/:id ────────────────────────────────────────
// Enable/disable an organization — disabling blocks login for all its members.
// Body: { isDisabled: boolean }
router.patch('/organizations/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ID', error: 'Invalid organization id' });
    }
    const { isDisabled } = req.body || {};
    if (typeof isDisabled !== 'boolean') {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_PAYLOAD', error: 'isDisabled must be a boolean' });
    }

    const org = await Organization.findById(id);
    if (!org || org.deletedAt) return res.status(404).json({ success: false, code: 'ADMIN_ORG_NOT_FOUND', error: 'Organization not found' });

    const auditTarget = {
      action: isDisabled ? 'org.disable' : 'org.enable',
      targetType: 'organization',
      targetId: org._id,
      targetLabel: org.name,
    };

    if (isDisabled) {
      // Disabling your own organization locks you out mid-session.
      if (req.adminUser.organizationId && String(req.adminUser.organizationId) === String(org._id)) {
        return res.status(403).json({ success: false, code: 'ADMIN_SELF_ORG', error: 'You cannot disable your own organization' });
      }
      // Disabling an org locks out every member. A plain admin may not do that
      // to an organization containing an administrator — it would bypass the
      // rule that only a superadmin acts on admin accounts.
      if (!isSuperadmin(req)) {
        const adminMembers = await User.countDocuments({
          organizationId: org._id,
          systemRole: { $in: ADMIN_CAPABLE_ROLES },
        });
        if (adminMembers > 0) {
          await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
          return superadminRequired(res);
        }
      }
      if (!(await adminsRemainAfterOrgDisable(org._id))) {
        return res.status(409).json({
          success: false,
          code: 'ADMIN_LAST_ADMIN_ORG',
          error: 'Disabling this organization would leave no reachable administrator',
        });
      }
      if ((await reachableSuperadmins()) > 0 && (await reachableSuperadmins({ blockedOrgId: org._id })) === 0) {
        return lastSuperadmin(res);
      }
    }

    let audit;
    try {
      audit = await beginAdminAction(req, { ...auditTarget, before: { isDisabled: Boolean(org.isDisabled) } });
    } catch (_) {
      return auditUnavailable(res);
    }

    try {
      org.isDisabled = isDisabled;
      await org.save();
    } catch (err) {
      await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_ACTION_FAILED' });
      throw err;
    }
    // An org-level lock changes access for every member, and the auth cache is
    // keyed by user — clear all of it rather than trying to enumerate members.
    invalidateAllPrincipals();
    if (org.isDisabled) {
      const members = await User.find({ organizationId: org._id }, { _id: 1 }).lean();
      members.forEach((m) => cutRealtime(m._id));
    }
    await finishAdminAction(audit, { result: 'success', after: { isDisabled: org.isDisabled } });
    res.json({ success: true, organization: { _id: org._id, name: org.name, isDisabled: org.isDisabled } });
  } catch (err) {
    console.error('❌ [admin/organizations PATCH]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_ACTION_FAILED', error: 'Failed to update organization', details: devMsg(err) });
  }
});

/**
 * Make sure subscription `org.stripeSubscriptionId` will not bill again after
 * its current period, and record that on the org. Mirrors
 * POST /api/stripe/cancel-subscription: no refund, access continues to the end
 * of the paid period. Throws on any Stripe failure other than "no such
 * subscription" (which means nothing is billing).
 *
 * @returns {Promise<{outcome: 'scheduled'|'already_scheduled'|'already_ended', cancelAt: Date|null, synced: boolean}>}
 */
async function ensureCancelledAtPeriodEnd(org) {
  let sub;
  try {
    sub = await stripe.subscriptions.retrieve(org.stripeSubscriptionId);
  } catch (err) {
    if (!isStripeMissing(err)) throw err;
    sub = { id: org.stripeSubscriptionId, object: 'subscription', status: 'canceled' };
  }

  let outcome;
  if (STRIPE_ENDED.includes(sub.status)) {
    outcome = 'already_ended';
  } else if (isCancellationScheduled(sub)) {
    outcome = 'already_scheduled';
  } else {
    sub = await stripe.subscriptions.update(org.stripeSubscriptionId, { cancel_at_period_end: true });
    outcome = 'scheduled';
  }

  // Stripe is now right. Writing it onto the org is a convenience — the
  // customer.subscription.updated webhook and the 5-minute sweep reconcile the
  // same state — so a failure here is reported, not fatal.
  let synced = true;
  try {
    await applySubscription(org, sub);
  } catch (err) {
    synced = false;
    console.error(`❌ [admin] Stripe updated but org ${org._id} could not be synced (webhook will reconcile):`, err.message);
  }

  const cancelAt = outcome === 'already_ended'
    ? null
    : (sub.cancel_at ? new Date(sub.cancel_at * 1000) : periodEndOf(sub));
  return { outcome, cancelAt, synced };
}

// ── POST /api/admin/organizations/:id/cancel-subscription ────────────────────
// Cancels the organization's Stripe subscription at the end of the current
// billing period. Superadmin only, recent sign-in required. The plan keeps
// working until the period ends; the downgrade to Free happens when Stripe ends
// the subscription (services/subscriptionLifecycle.js).
router.post('/organizations/:id/cancel-subscription', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ID', error: 'Invalid organization id' });
    }

    const org = await Organization.findById(id);
    if (!org || org.deletedAt) return res.status(404).json({ success: false, code: 'ADMIN_ORG_NOT_FOUND', error: 'Organization not found' });

    const auditTarget = { action: 'org.cancel_subscription', targetType: 'organization', targetId: org._id, targetLabel: org.name };
    if (!isSuperadmin(req)) {
      await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
      return superadminRequired(res);
    }
    if (!org.stripeSubscriptionId) {
      return res.status(400).json({ success: false, code: 'ADMIN_NO_SUBSCRIPTION', error: 'This organization has no active subscription' });
    }
    if (!hasRecentAuth(req)) return reauthRequired(res);
    // Already scheduled to end — nothing to do, and no second Stripe call.
    if (org.cancelAtPeriodEnd) {
      return res.json({ success: true, alreadyScheduled: true, cancelAt: org.expiresAt });
    }

    let audit;
    try {
      audit = await beginAdminAction(req, {
        ...auditTarget,
        before: { subscriptionState: subscriptionState(org), expiresAt: org.expiresAt },
      });
    } catch (_) {
      return auditUnavailable(res);
    }

    let result;
    try {
      result = await ensureCancelledAtPeriodEnd(org);
    } catch (err) {
      console.error(`❌ [admin] Stripe cancel failed for org ${org._id}:`, err.message);
      await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_STRIPE_FAILED' });
      return res.status(502).json({ success: false, code: 'ADMIN_STRIPE_FAILED', error: 'Stripe could not cancel the subscription' });
    }

    console.log(`🚫 [admin] Subscription cancel (${result.outcome}) for org ${org._id} by admin ${req.adminUser._id}`);
    await finishAdminAction(audit, {
      result: 'success',
      after: { stripe: result.outcome, cancelAt: result.cancelAt, dbSynced: result.synced },
    });

    res.json({
      success: true,
      outcome: result.outcome,
      cancelAt: result.cancelAt,
      synced: result.synced,
    });
  } catch (err) {
    console.error('❌ [admin/organizations/:id/cancel-subscription]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_ACTION_FAILED', error: 'Failed to cancel subscription', details: devMsg(err) });
  }
});

// ── DELETE /api/admin/organizations/:id ───────────────────────────────────────
// Soft-deletes an organization. Superadmin only, recent sign-in required.
//
// Order matters:
//   1. Stripe first. If the organization still has a live subscription it is set
//      to end at period end; if Stripe refuses, NOTHING else happens (deleting
//      the org would leave a customer billed for an account that is gone, and no
//      webhook could ever find the org again).
//   2. The org is marked deleted AND disabled in one write, so its members are
//      locked out even if a later step fails.
//   3. Members are detached (their accounts survive as standalone users with no
//      plan), their schedules disabled, pending invites expired — the same
//      clean-up as a downgrade to Free.
// The document, its purchased credits and lifetime counters are kept: the
// deletion is recoverable from the audit row (which lists the members).
// Repeating the call on an org whose clean-up failed resumes it.
router.delete('/organizations/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, code: 'ADMIN_INVALID_ID', error: 'Invalid organization id' });
    }

    const org = await Organization.findById(id);
    if (!org) return res.status(404).json({ success: false, code: 'ADMIN_ORG_NOT_FOUND', error: 'Organization not found' });

    const auditTarget = { action: 'org.delete', targetType: 'organization', targetId: org._id, targetLabel: org.name };
    if (!isSuperadmin(req)) {
      await recordDenied(req, { ...auditTarget, errorCode: 'ADMIN_SUPERADMIN_REQUIRED' });
      return superadminRequired(res);
    }
    if (!hasRecentAuth(req)) return reauthRequired(res);

    const resuming = Boolean(org.deletedAt);
    const members = await User.find({ organizationId: org._id }, { _id: 1, email: 1, role: 1 }).lean();
    const memberIds = members.map((m) => m._id);

    let audit;
    try {
      audit = await beginAdminAction(req, {
        ...auditTarget,
        before: {
          resuming,
          planType: org.planType,
          subscriptionState: subscriptionState(org),
          hasSubscription: Boolean(org.stripeSubscriptionId),
          members: members.map((m) => ({ _id: m._id, email: m.email, role: m.role })),
          creditsRemaining: (org.scanCredits || []).reduce((n, c) => n + (c.scansRemaining || 0), 0),
        },
      });
    } catch (_) {
      return auditUnavailable(res);
    }

    // 1. Stripe — fail closed.
    let stripeOutcome = 'none';
    if (!resuming && org.stripeSubscriptionId && !STRIPE_ENDED.includes(org.subscriptionStatus)) {
      try {
        stripeOutcome = (await ensureCancelledAtPeriodEnd(org)).outcome;
      } catch (err) {
        console.error(`❌ [admin] Stripe cancel failed — org ${org._id} NOT deleted:`, err.message);
        await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_STRIPE_FAILED' });
        return res.status(502).json({
          success: false,
          code: 'ADMIN_STRIPE_FAILED',
          error: 'Stripe could not cancel the subscription; the organization was not deleted',
        });
      }
    }

    // 2. Mark deleted + disabled (members are blocked from here on).
    const now = new Date();
    if (!resuming) {
      const marked = await Organization.updateOne(
        { _id: org._id, deletedAt: null },
        { $set: { deletedAt: now, deletedBy: req.adminUser._id, isDisabled: true } }
      );
      if (!marked.matchedCount) {
        await finishAdminAction(audit, { result: 'failure', errorCode: 'ADMIN_ORG_NOT_FOUND' });
        return res.status(404).json({ success: false, code: 'ADMIN_ORG_NOT_FOUND', error: 'Organization not found' });
      }
    }
    invalidateAllPrincipals();

    // 3. Detach members and clean up. Each step is idempotent.
    const effects = await Promise.allSettled([
      User.updateMany(
        { organizationId: org._id },
        {
          $set: {
            organizationId: null,
            role: 'owner',
            accountType: 'free',
            planType: null,
            billingCycle: null,
            subscriptionStatus: null,
            stripeSubscriptionId: null,
          },
        }
      ),
      ScheduledScan.updateMany({ userId: { $in: memberIds }, enabled: true }, { $set: { enabled: false } }),
      Invite.updateMany({ organizationId: org._id, status: 'pending' }, { $set: { status: 'expired', expiresAt: now } }),
    ]);
    invalidateAllPrincipals();
    memberIds.forEach(cutRealtime);

    const failedSteps = ['members', 'schedules', 'invites'].filter((_, i) => effects[i].status === 'rejected');
    if (failedSteps.length) {
      effects.forEach((r, i) => {
        if (r.status === 'rejected') console.error(`❌ [admin] org ${org._id} delete step ${i} failed:`, r.reason && r.reason.message);
      });
      await finishAdminAction(audit, {
        result: 'failure',
        errorCode: 'ADMIN_DELETE_INCOMPLETE',
        after: { deletedAt: now, stripe: stripeOutcome, failedSteps },
      });
      return res.status(500).json({
        success: false,
        code: 'ADMIN_DELETE_INCOMPLETE',
        error: 'Organization deleted and locked, but clean-up did not finish; repeat the request to resume',
      });
    }

    console.log(`🗑️ [admin] Organization ${org._id} soft-deleted by admin ${req.adminUser._id}, ${memberIds.length} member(s) detached`);
    await finishAdminAction(audit, {
      result: 'success',
      after: { deletedAt: org.deletedAt || now, stripe: stripeOutcome, membersDetached: memberIds.length },
    });

    res.json({ success: true, membersDetached: memberIds.length, stripe: stripeOutcome });
  } catch (err) {
    console.error('❌ [admin/organizations DELETE]', err.message);
    res.status(500).json({ success: false, code: 'ADMIN_ACTION_FAILED', error: 'Failed to delete organization', details: devMsg(err) });
  }
});

module.exports = router;
