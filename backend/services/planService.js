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

function hasActiveSubscription(org) {
  return org.subscriptionStatus === 'active' || org.subscriptionStatus === 'trialing';
}

function subscriptionHasCapacity(org) {
  return hasActiveSubscription(org) && org.scanLimit > 0 && org.scansUsed < org.scanLimit;
}

function hasLiveCredit(org, now = new Date()) {
  return (org.scanCredits || []).some(c => c.scansRemaining > 0 && c.expiresAt && c.expiresAt > now);
}

// Back-compat for legacy one-time orgs created before scanCredits existed: their
// balance lives only in the oneTimeRemainingScans scalar. Without this, every
// unmigrated trial customer gets PLAN_LIMIT_EXCEEDED the moment this deploys,
// making scripts/migrateOneTimeCredits.js a hard prerequisite of the release.
// Honouring the scalar makes that migration ordinary cleanup instead.
//
// Gated on there being NO batches at all — not merely no *live* ones — because:
//   • once migrated, the batch is authoritative and the scalar is just a mirror,
//     so counting both would let the same scan be spent twice;
//   • if every batch has expired, the scalar still reads high (nothing decrements
//     it on expiry, see Organization.js), so trusting it would resurrect expired
//     credits.
// Residual gap, resolved by running the migration: an unmigrated org that buys a
// new one-time plan gets a batch for the new purchase only, and its old scalar
// remainder becomes unreachable.
function hasLegacyOneTimeBalance(org) {
  return org.billingCycle === 'onetime'
    && (org.scanCredits || []).length === 0
    && (org.oneTimeRemainingScans || 0) > 0;
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
  const now = new Date();

  if (!org || (!hasActiveSubscription(org) && !hasLiveCredit(org, now) && !hasLegacyOneTimeBalance(org))) {
    return null;
  }

  // 🔁 Monthly reset FIRST — UTC, so the cycle is timezone-independent.
  // Unconditional: an org can hold a subscription AND credits at once, so
  // the subscription's monthly counters must still roll over regardless of
  // billingCycle. Credit batches are unaffected — they expire on their own
  // expiresAt, not on the monthly boundary.
  const lastReset = org.lastScanReset || new Date(0);
  const isNewMonth =
    now.getUTCMonth() !== lastReset.getUTCMonth() ||
    now.getUTCFullYear() !== lastReset.getUTCFullYear();

  if (isNewMonth) {
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

  // 🔥 SUBSCRIPTION PATH — tried first. Per-target caps apply here only.
  if (subscriptionHasCapacity(org)) {
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

  // 🔥 CREDIT FALLBACK — only reached once the monthly allowance is
  // exhausted (or there's no active subscription at all). Bypasses
  // per-target caps entirely by design.
  if (hasLiveCredit(org, now)) {
    return org;
  }

  // Legacy pre-scanCredits balance (see hasLegacyOneTimeBalance).
  if (hasLegacyOneTimeBalance(org)) {
    return org;
  }

  return null;
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
  const now = new Date();

  if (!org || (!hasActiveSubscription(org) && !hasLiveCredit(org, now) && !hasLegacyOneTimeBalance(org))) {
    return null;
  }

  const lastReset = org.lastScanReset || new Date(0);
  const isNewMonth =
    now.getUTCMonth() !== lastReset.getUTCMonth() ||
    now.getUTCFullYear() !== lastReset.getUTCFullYear();

  if (isNewMonth) {
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

  // ── 1. Try the subscription slot first ──────────────────────────────────
  if (subscriptionHasCapacity(org)) {
    const norm = normalizeTarget(target);
    const inc = { scansUsed: 1, targetsUsed: 1, totalScansAllTime: 1 };

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

    const sub = await Organization.findOneAndUpdate(
      { _id: orgId, subscriptionStatus: { $in: ['active', 'trialing'] }, scansUsed: { $lt: org.scanLimit } },
      { $inc: inc },
      { new: true }
    );
    if (sub) return sub;
    // Lost a race for the last subscription slot — fall through to credits,
    // which mirrors "monthly allowance exhausted" becoming true concurrently.
  }

  // ── 2. Credit fallback — bypasses target caps, still records
  //      targetScanCounts for reporting purposes only ─────────────────────
  // ── 3. Legacy pre-scanCredits balance — decrement the bare scalar. Guarded
  //      on $gt: 0 so concurrent scans can't drive it negative ─────────────
  if (hasLegacyOneTimeBalance(org)) {
    const legacy = await Organization.findOneAndUpdate(
      { _id: orgId, billingCycle: 'onetime', oneTimeRemainingScans: { $gt: 0 } },
      { $inc: { oneTimeRemainingScans: -1, totalScansAllTime: 1 } },
      { new: true }
    );
    if (legacy) return legacy;
  }

  return consumeFromCreditBatch(orgId, target);
}

async function consumeFromCreditBatch(orgId, target, attempt = 0) {
  const MAX_ATTEMPTS = 5;
  if (attempt >= MAX_ATTEMPTS) return null;

  const now = new Date();
  const org = await Organization.findById(orgId);
  if (!org) return null;

  const liveBatches = (org.scanCredits || [])
    .filter(c => c.scansRemaining > 0 && c.expiresAt && c.expiresAt > now)
    .sort((a, b) => a.expiresAt - b.expiresAt);
  if (liveBatches.length === 0) return null;

  const batch = liveBatches[0];
  const norm = normalizeTarget(target);
  const inc = { 'scanCredits.$.scansRemaining': -1, oneTimeRemainingScans: -1, totalScansAllTime: 1 };
  if (norm) {
    const key = targetKey(norm);
    inc[`targetScanCounts.${key}`] = 1; // bookkeeping only — not gated
    inc.targetsUsed = 1;
  }

  const result = await Organization.findOneAndUpdate(
    { _id: orgId, scanCredits: { $elemMatch: { _id: batch._id, scansRemaining: { $gt: 0 } } } },
    { $inc: inc },
    { new: true }
  );

  if (result) return result;
  // Lost the race for this specific batch — retry against the next-soonest.
  return consumeFromCreditBatch(orgId, target, attempt + 1);
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
