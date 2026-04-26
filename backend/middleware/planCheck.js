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
const { consumeScan } = require('../services/planService');

module.exports = async function planCheck(req, res, next) {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(401).json({ success: false, code: 'USER_NOT_FOUND', error: 'UNAUTHORIZED', message: 'User account not found' });
    }

    if (!user.organizationId) {
      return res.status(403).json({ success: false, code: 'NO_ORGANIZATION', error: 'PLAN_LIMIT_EXCEEDED', message: 'No organization found for user. Please purchase a plan.' });
    }

    const result = await consumeScan(user.organizationId);

    if (!result) {
      return res.status(403).json({
        success: false,
        code: 'PLAN_LIMIT_EXCEEDED',
        error: 'PLAN_LIMIT_EXCEEDED',
        message: 'Scan limit reached or subscription inactive. Please upgrade your plan.',
        limitType: 'monthly_scans_or_inactive'
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
