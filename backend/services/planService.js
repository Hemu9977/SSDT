const crypto = require('crypto');
const Organization = require('../models/Organization');

/**
 * Normalize a scan target to its lowercase hostname so the same site under
 * different paths/schemes counts as one target.
 * @returns {string|null}
 */
function normalizeTarget(target) {
  if (!target || typeof target !== 'string') return null;
  try {
    const u = new URL(target.includes('://') ? target : `https://${target}`);
    return u.hostname.toLowerCase();
  } catch {
    const t = target.trim().toLowerCase();
    return t || null;
  }
}

// Hash so the map key never contains '.'/'$' (illegal in Mongo dotted paths).
function targetKey(normalizedTarget) {
  return crypto.createHash('sha1').update(normalizedTarget).digest('hex');
}

function mapGet(map, key) {
  if (!map) return 0;
  if (map instanceof Map) return map.get(key) || 0;
  return map[key] || 0;
}

function mapSize(map) {
  if (!map) return 0;
  if (map instanceof Map) return map.size;
  return Object.keys(map).length;
}

/**
 * Atomically consume one scan slot for an organization, enforcing:
 *   - active subscription (or one-time scans remaining)
 *   - monthly scan cap (scanLimit)
 *   - max distinct targets / month (targetsPerMonth; -1 = unlimited)
 *   - max scans per target / month (scansPerTarget; null = unlimited)
 *
 * @param {string} orgId
 * @param {object} [opts]
 * @param {string} [opts.target]          scan target (url or hostname)
 * @param {number|null} [opts.scansPerTarget]
 * @param {number|null} [opts.targetsPerMonth]
 * @returns {Promise<object|null>} updated org on success, null if any limit hit / inactive
 */
async function consumeScan(orgId, opts = {}) {
  const { target = null, scansPerTarget = null, targetsPerMonth = null } = opts;

  const org = await Organization.findById(orgId);

  if (!org || (org.billingCycle !== "onetime" && org.subscriptionStatus !== "active" && org.subscriptionStatus !== "trialing")) {
    return null;
  }

  const now = new Date();

  // 🔁 Monthly reset FIRST — UTC, so the cycle is timezone-independent
  const lastReset = org.lastScanReset || new Date(0);
  const isNewMonth =
    now.getUTCMonth() !== lastReset.getUTCMonth() ||
    now.getUTCFullYear() !== lastReset.getUTCFullYear();

  if (isNewMonth && org.billingCycle !== "onetime") {
    await Organization.updateOne(
      { _id: orgId },
      {
        $set: {
          scansUsed: 0,
          targetsUsed: 0,
          targetScanCounts: {},
          lastScanReset: now
        }
      }
    );
    // Reflect the reset in the in-memory doc used for the checks below.
    org.scansUsed = 0;
    org.targetsUsed = 0;
    org.targetScanCounts = new Map();
    org.lastScanReset = now;
  }

  // 🔥 ONE-TIME PLAN — bounded by oneTimeRemainingScans; target caps don't apply.
  if (org.billingCycle === "onetime") {
    return Organization.findOneAndUpdate(
      { _id: orgId, oneTimeRemainingScans: { $gt: 0 } },
      { $inc: { oneTimeRemainingScans: -1 } },
      { new: true }
    );
  }

  // 🔥 SUBSCRIPTION PLAN — enforce target caps (read-then-write; the per-user
  // 1-scan-per-minute combined limiter makes a same-org race effectively impossible).
  const norm = normalizeTarget(target);
  const inc = { scansUsed: 1, targetsUsed: 1 };

  if (norm) {
    const key = targetKey(norm);
    const counts = org.targetScanCounts;
    const thisTargetCount = mapGet(counts, key);
    const isNewTarget = thisTargetCount === 0;

    // Max distinct targets per month (skip when unlimited: -1 / null)
    if (isNewTarget && targetsPerMonth != null && targetsPerMonth >= 0 && mapSize(counts) >= targetsPerMonth) {
      return null;
    }
    // Max scans per target per month (skip when unlimited: null)
    if (scansPerTarget != null && thisTargetCount >= scansPerTarget) {
      return null;
    }

    inc[`targetScanCounts.${key}`] = 1;
  }

  // Atomic monthly scan-cap increment. The target counter only advances when the
  // scan is actually granted (same $inc), so counts never drift from scansUsed.
  return Organization.findOneAndUpdate(
    { _id: orgId, scansUsed: { $lt: org.scanLimit } },
    { $inc: inc },
    { new: true }
  );
}

/**
 * Reverse a single consumeScan() increment. Call this when a scan was charged at
 * the gate (planCheck) but failed to start (invalid input, duplicate, handler
 * error) so the user is not billed a slot for work that never ran.
 *
 * Mirrors consumeScan exactly:
 *   onetime      → +1 oneTimeRemainingScans
 *   subscription → -1 scansUsed, -1 targetsUsed (guarded so they never go negative)
 *
 * @param {string} orgId
 * @param {string} billingCycle  the org's billingCycle ('onetime' | 'monthly' | 'annual')
 * @param {string} [target]      the scan target, so its per-target counter is also reversed
 */
async function refundScan(orgId, billingCycle, target = null) {
  if (!orgId) return;
  try {
    if (billingCycle === 'onetime') {
      await Organization.updateOne({ _id: orgId }, { $inc: { oneTimeRemainingScans: 1 } });
    } else {
      // Guard against underflow: only decrement counters that are still positive.
      await Organization.updateOne(
        { _id: orgId, scansUsed: { $gt: 0 } },
        { $inc: { scansUsed: -1 } }
      );
      await Organization.updateOne(
        { _id: orgId, targetsUsed: { $gt: 0 } },
        { $inc: { targetsUsed: -1 } }
      );
      const norm = normalizeTarget(target);
      if (norm) {
        const key = targetKey(norm);
        await Organization.updateOne(
          { _id: orgId, [`targetScanCounts.${key}`]: { $gt: 0 } },
          { $inc: { [`targetScanCounts.${key}`]: -1 } }
        );
      }
    }
  } catch (err) {
    console.error('⚠️  [planService] refundScan failed:', err.message);
  }
}

module.exports = { consumeScan, refundScan };
