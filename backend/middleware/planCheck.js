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
 * After passing, increments usage counters (atomic via User.save()).
 * Attaches req.planUser (loaded user doc) for downstream use.
 */

const User = require('../models/User');

/**
 * Main middleware.
 * Expects:
 *  - req.user.id  (set by auth middleware)
 *  - req.body.url (the target being scanned)
 */
module.exports = async function planCheck(req, res, next) {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(401).json({ code: 'USER_NOT_FOUND', message: 'User account not found' });
    }

    // --- 1. Reset monthly counters if calendar month has rolled over ---
    const wasReset = user.checkAndResetMonthlyScans();
    // (save happens after all checks to keep it one round-trip)

    const limits = user.getAccountLimits();
    const url = (req.body.url || '').trim();

    // Normalize URL for target-tracking (strip trailing slash, lowercase scheme)
    const normalizedTarget = normalizeUrl(url);

    // --- 2. One-time / trial plan: check remaining slots ---
    if (user.billingCycle === 'onetime') {
      if (user.oneTimeRemainingScans <= 0) {
        return res.status(403).json({
          code: 'PLAN_LIMIT_EXCEEDED',
          message: 'Your one-time plan has no remaining scans. Please purchase a new plan to continue.',
          limitType: 'onetime_exhausted'
        });
      }
    }

    // --- 3. Monthly scan quota ---
    if (limits.scansPerMonth !== -1 && user.monthlyScansUsed >= limits.scansPerMonth) {
      return res.status(403).json({
        code: 'PLAN_LIMIT_EXCEEDED',
        message: `Monthly scan limit reached (${user.monthlyScansUsed}/${limits.scansPerMonth}). Upgrade your plan for more scans.`,
        limitType: 'monthly_scans',
        used: user.monthlyScansUsed,
        limit: limits.scansPerMonth
      });
    }

    // --- 4. Monthly target quota ---
    if (limits.targetsPerMonth !== -1) {
      const isNewTarget = !user.targetsUsed.includes(normalizedTarget);
      if (isNewTarget && user.totalTargetsUsed >= limits.targetsPerMonth) {
        return res.status(403).json({
          code: 'PLAN_LIMIT_EXCEEDED',
          message: `Monthly target limit reached (${user.totalTargetsUsed}/${limits.targetsPerMonth} targets). Upgrade your plan to scan more targets.`,
          limitType: 'monthly_targets',
          used: user.totalTargetsUsed,
          limit: limits.targetsPerMonth
        });
      }
    }

    // --- 5. Per-target scan quota (annual plans only) ---
    if (limits.scansPerTarget !== null) {
      const perTargetUsed = user.scanUsagePerTarget.get(normalizedTarget) || 0;
      if (perTargetUsed >= limits.scansPerTarget) {
        return res.status(403).json({
          code: 'PLAN_LIMIT_EXCEEDED',
          message: `Scan limit for this target reached (${perTargetUsed}/${limits.scansPerTarget} scans on ${normalizedTarget}). Upgrade or wait for monthly reset.`,
          limitType: 'per_target',
          target: normalizedTarget,
          used: perTargetUsed,
          limit: limits.scansPerTarget
        });
      }
    }

    // ─── All checks passed — increment counters ───────────────────────────────

    // Monthly scans
    user.monthlyScansUsed = (user.monthlyScansUsed || 0) + 1;

    // Target tracking
    const isNewTargetForIncrement = !user.targetsUsed.includes(normalizedTarget);
    if (isNewTargetForIncrement) {
      user.targetsUsed.push(normalizedTarget);
      user.totalTargetsUsed = (user.totalTargetsUsed || 0) + 1;
    }

    // Per-target counter
    const prevPerTarget = user.scanUsagePerTarget.get(normalizedTarget) || 0;
    user.scanUsagePerTarget.set(normalizedTarget, prevPerTarget + 1);

    // One-time / trial deduction
    if (user.billingCycle === 'onetime') {
      user.oneTimeRemainingScans = Math.max(0, (user.oneTimeRemainingScans || 0) - 1);
    }

    // Total lifetime
    user.totalScans = (user.totalScans || 0) + 1;

    // Save all mutations in one write
    await user.save();

    // Attach loaded user for downstream route handlers (avoids a second DB call)
    req.planUser = user;

    next();
  } catch (err) {
    console.error('❌ [planCheck] Error:', err.message);
    res.status(500).json({ code: 'PLAN_CHECK_ERROR', message: 'Failed to verify plan limits' });
  }
};

/**
 * Normalize a URL string for consistent target-key storage.
 * E.g. "HTTPS://Example.com/" → "https://example.com"
 */
function normalizeUrl(raw) {
  try {
    const u = new URL(raw);
    // Keep origin only (scheme + host + port). Strip path / query / fragment.
    return u.origin.toLowerCase();
  } catch (_) {
    return raw.toLowerCase().replace(/\/+$/, '');
  }
}
