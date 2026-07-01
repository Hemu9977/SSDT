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
 * Check if the organization has quota to run a scan without consuming it.
 * Performs monthly reset if needed.
 *
 * @param {string} orgId
 * @param {object} [opts]
 * @returns {Promise<object|null>} updated org on success, null if any limit hit / inactive
 */
async function checkScanQuota(orgId, opts = {}) {
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
    org.scansUsed = 0;
    org.targetsUsed = 0;
    org.targetScanCounts = new Map();
    org.lastScanReset = now;
  }

  // 🔥 ONE-TIME PLAN
  if (org.billingCycle === "onetime") {
    return org.oneTimeRemainingScans > 0 ? org : null;
  }

  // 🔥 SUBSCRIPTION PLAN
  if (org.scansUsed >= org.scanLimit) {
    return null;
  }

  const norm = normalizeTarget(target);

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
  }

  return org;
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
    org.scansUsed = 0;
    org.targetsUsed = 0;
    org.targetScanCounts = new Map();
    org.lastScanReset = now;
  }

  if (org.billingCycle === "onetime") {
    return Organization.findOneAndUpdate(
      { _id: orgId, oneTimeRemainingScans: { $gt: 0 } },
      { $inc: { oneTimeRemainingScans: -1 } },
      { new: true }
    );
  }

  const norm = normalizeTarget(target);
  const inc = { scansUsed: 1, targetsUsed: 1 };

  if (norm) {
    const key = targetKey(norm);
    const counts = org.targetScanCounts;
    const thisTargetCount = mapGet(counts, key);
    const isNewTarget = thisTargetCount === 0;

    if (isNewTarget && targetsPerMonth != null && targetsPerMonth >= 0 && mapSize(counts) >= targetsPerMonth) {
      return null;
    }
    if (scansPerTarget != null && thisTargetCount >= scansPerTarget) {
      return null;
    }

    inc[`targetScanCounts.${key}`] = 1;
  }

  return Organization.findOneAndUpdate(
    { _id: orgId, scansUsed: { $lt: org.scanLimit } },
    { $inc: inc },
    { new: true }
  );
}

/**
 * Called when a scan successfully completes. 
 * Fetches the ScanResult, checks limits, and deducts the quota atomically.
 */
async function finalizeSuccessfulScan(scanId) {
  const ScanResult = require('../models/ScanResult');
  const User = require('../models/User');

  try {
    const scan = await ScanResult.findOne({ analysisId: scanId });
    if (!scan) return;
    
    // Ensure we only charge once
    if (scan.quotaConsumed) return;

    // Strict success check: do not bill if the scan is not fully completed or if any required phase failed
    if (scan.status !== 'completed' && scan.status !== 'success') {
      console.log(`[Billing] Scan ${scanId} is not in a terminal success state (${scan.status}), skipping deduction.`);
      return;
    }
    
    if (scan.zapResult && scan.zapResult.status === 'failed') {
      console.log(`[Billing] Scan ${scanId} had a failed ZAP phase, skipping deduction.`);
      return;
    }
    
    if (scan.webCheckResult && scan.webCheckResult.status === 'failed') {
      console.log(`[Billing] Scan ${scanId} had a failed WebCheck phase, skipping deduction.`);
      return;
    }
    
    if (scan.authScanResult && scan.authScanResult.status === 'failed') {
      console.log(`[Billing] Scan ${scanId} had a failed Auth Scan phase, skipping deduction.`);
      return;
    }

    const user = await User.findById(scan.userId);
    if (!user || !user.organizationId) return;

    const org = await Organization.findById(user.organizationId);
    if (!org) return;

    const limits = user.getAccountLimits(org);

    // Charge the quota
    const result = await consumeScan(user.organizationId, {
      target: scan.target,
      scansPerTarget: limits.scansPerTarget,
      targetsPerMonth: limits.targetsPerMonth
    });

    if (result) {
      // Mark as consumed
      await ScanResult.updateOne(
        { analysisId: scanId, quotaConsumed: false },
        { $set: { quotaConsumed: true } }
      );
      console.log(`[Billing] Scan completed - quota deducted: ${scanId}`);
    }
  } catch (err) {
    console.error(`⚠️ [Billing] Failed to finalize scan ${scanId}:`, err.message);
  }
}

/**
 * Reverse a single consumeScan() increment. (Legacy support, may not be needed anymore)
 */
async function refundScan(orgId, billingCycle, target = null) {
  if (!orgId) return;
  try {
    if (billingCycle === 'onetime') {
      await Organization.updateOne({ _id: orgId }, { $inc: { oneTimeRemainingScans: 1 } });
    } else {
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

module.exports = { checkScanQuota, consumeScan, finalizeSuccessfulScan, refundScan };
