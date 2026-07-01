/**
 * backend/middleware/planCheck.js
 *
 * Plan enforcement middleware — inserted between `auth` and scan route handler.
 * NEVER trusts frontend. All checks are server-side against DB state.
 *
 * Enforces:
 *  - Monthly scan quota
 *  - Monthly target quota
 *  - Per-target scan quota (annual plans)
 *  - One-time / trial remaining scans
 *
 * After passing, increments usage counters (atomic via Organization.updateOne()).
 * Attaches req.planUser (loaded user doc) for downstream use.
 */

const User = require('../models/User');
const Organization = require('../models/Organization');
const { checkScanQuota } = require('../services/planService');

module.exports = async function planCheck(req, res, next) {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(401).json({ success: false, code: 'USER_NOT_FOUND', error: 'UNAUTHORIZED', message: 'User account not found' });
    }

    if (!user.organizationId) {
      // 🟡 Stripe payment in progress
      if (user.stripePending === true) {
        return res.status(403).json({
          success: false,
          code: 'ORG_CREATING',
          error: 'ORG_CREATING',
          message: 'Your organization is being created. Please wait a few seconds.',
          retry: true
        });
      }

      return res.status(403).json({
        success: false,
        code: 'NO_ORGANIZATION',
        error: 'ORG_REQUIRED',
        message: 'You must join an organization via invite or create one via payment.',
        redirect: '/pricing'
      });
    }

    // Resolve plan limits from the org (target caps come from the plan matrix).
    const org = await Organization.findById(user.organizationId);
    const limits = user.getAccountLimits(org);

    // Scan target — routes use either `url` (normal/zap/webcheck/pagespeed) or
    // `targetUrl` (authenticated scan).
    const target = (req.body && (req.body.url || req.body.targetUrl)) || null;

    const result = await checkScanQuota(user.organizationId, {
      target,
      scansPerTarget: limits.scansPerTarget,
      targetsPerMonth: limits.targetsPerMonth
    });

    if (!result) {
      return res.status(403).json({
        success: false,
        code: 'PLAN_LIMIT_EXCEEDED',
        error: 'PLAN_LIMIT_EXCEEDED',
        message: 'Scan limit reached or subscription inactive. Please upgrade your plan.',
        limitType: 'monthly_scans_targets_or_inactive'
      });
    }

    req.organization = result;
    req.planUser = user;

    next();
  } catch (err) {
    console.error('❌ [planCheck] Error:', err.message);
    res.status(500).json({ success: false, code: 'PLAN_CHECK_ERROR', error: 'PLAN_CHECK_ERROR', message: 'Failed to verify plan limits' });
  }
};
