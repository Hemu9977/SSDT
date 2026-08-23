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
 * Total scans the org could still pay for right now: unused subscription
 * allowance plus every live credit. Used by claimScanSlot to decide how many
 * concurrent scans may be in flight at once.
 */
function availableCapacity(org, now = new Date()) {
  let capacity = 0;

  if (hasActiveSubscription(org) && org.scanLimit > 0) {
    capacity += Math.max(0, org.scanLimit - (org.scansUsed || 0));
  }

  const creditBalance = (org.scanCredits || [])
    .filter(c => c.scansRemaining > 0 && c.expiresAt && c.expiresAt > now)
    .reduce((sum, c) => sum + c.scansRemaining, 0);

  if (creditBalance > 0) {
    capacity += creditBalance;
  } else if (hasLegacyOneTimeBalance(org)) {
    // Mirrors consumeScan: the bare scalar only counts when no batches exist.
    capacity += org.oneTimeRemainingScans || 0;
  }

  return capacity;
}

// Statuses in which a scan is still running and has therefore not yet been billed.
const IN_FLIGHT_STATUSES = ['queued', 'pending', 'combining'];

/**
 * Decide whether a freshly-created scan is allowed to run, accounting for the
 * org's other in-flight scans. Call this immediately AFTER saving the ScanResult.
 *
 * Why this exists: quota is charged at successful completion, so checkScanQuota at
 * scan start reserves nothing. Two scans begun with one slot left both passed the
 * check and both completed, and the customer got one free (HANDOFF.md §6.1).
 *
 * Why it is not a reservation counter: a counter has to be released on every
 * failure path, and a leaked reservation locks a paying customer out of their own
 * plan — strictly worse than the over-delivery it fixes. Instead the answer is
 * derived from documents that already exist, so there is nothing to leak: the
 * stale-scan watchdog moving a wedged scan to `failed` frees its slot for free.
 *
 * How it is race-free: `rank` counts only in-flight scans with a LOWER `_id`.
 * ObjectIds are unique and monotonic, so concurrent starters get distinct ranks
 * and exactly `capacity` of them clear the bar — no over-admission, and (unlike a
 * plain "count them all" check) no mutual rejection either.
 *
 * @param {string} orgId
 * @param {string} analysisId  the scan that was just created
 * @returns {Promise<boolean>} true if the scan may proceed
 */
async function claimScanSlot(orgId, analysisId) {
  const ScanResult = require('../models/ScanResult');

  try {
    if (!orgId) return true; // no org → nothing to meter against; planCheck already 403s

    const scan = await ScanResult.findOne({ analysisId }, { _id: 1, organizationId: 1 });
    if (!scan) return true; // caller order bug, not the customer's problem — let it run

    const org = await Organization.findById(orgId);
    if (!org) return true;

    const capacity = availableCapacity(org);

    const rank = await ScanResult.countDocuments({
      organizationId: orgId,
      status: { $in: IN_FLIGHT_STATUSES },
      _id: { $lt: scan._id }
    });

    if (rank < capacity) return true;

    console.warn(
      `[Billing] Scan ${analysisId} refused: ${rank} scan(s) already in flight ahead of it ` +
      `for org ${orgId}, capacity ${capacity}.`
    );
    return false;
  } catch (err) {
    // Fail OPEN, matching middleware/auth.js: a Mongo blip must not stop every
    // customer from scanning. The completion-time charge still enforces the cap.
    console.error(`⚠️  [planService] claimScanSlot failed for ${analysisId}:`, err.message);
    return true;
  }
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
    if (sub) return tagSource(sub, 'subscription');
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
    if (legacy) return tagSource(legacy, 'legacy');
  }

  return consumeFromCreditBatch(orgId, target);
}

/**
 * Record which pool paid for a scan, for support and for the completion log.
 * Non-persisted: it is a plain property on the returned document, never a schema
 * field on Organization.
 */
function tagSource(org, source) {
  if (org) org.__quotaSource = source;
  return org;
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

  if (result) return tagSource(result, 'credit');
  // Lost the race for this specific batch — retry against the next-soonest.
  return consumeFromCreditBatch(orgId, target, attempt + 1);
}

/**
 * Called when a scan successfully completes.
 * Fetches the ScanResult, checks limits, and deducts the quota atomically.
 *
 * ⚠️ This must stay the ONLY caller of consumeScan() in the orchestrated pipeline.
 * `backend/tests/billingInvariants.test.js` asserts that, because a second billing
 * site is exactly how auth scans ended up billed or not depending on which completion
 * path won the race.
 */
async function finalizeSuccessfulScan(scanId) {
  const ScanResult = require('../models/ScanResult');
  const User = require('../models/User');

  try {
    const scan = await ScanResult.findOne({ analysisId: scanId });
    if (!scan) return;

    // Cheap fast path only — the real guard is the atomic claim further down.
    // Several components can reach finalize for the same scan, so a plain read
    // here decides nothing on its own.
    if (scan.quotaConsumed) return;

    // A scan is billable exactly when it reached `completed`, which the pipeline
    // allows only when the vulnerability assessment produced results. Keep the
    // phase guards below in step with that rule — a guard stricter than the
    // completion policy means a report the customer already has, for free.
    if (scan.status !== 'completed' && scan.status !== 'success') {
      console.log(`[Billing] Scan ${scanId} is not in a terminal success state (${scan.status}), skipping deduction.`);
      return;
    }

    // The vulnerability assessment IS the product: without it the report would tell
    // the customer their site is clean when nothing was checked. geminiCompletionService
    // already refuses to complete such a scan, so these are belt-and-braces.
    if (scan.zapResult && scan.zapResult.status === 'failed') {
      console.log(`[Billing] Scan ${scanId} had a failed vulnerability phase, skipping deduction.`);
      return;
    }

    if (scan.authScanResult && scan.authScanResult.status === 'failed') {
      console.log(`[Billing] Scan ${scanId} had a failed authenticated phase, skipping deduction.`);
      return;
    }

    // NOTE: a failed WebCheck is deliberately NOT checked here.
    //
    // geminiCompletionService treats it as non-fatal by design — the scan completes,
    // the AI report is generated, and the WebCheck section renders N/A. This function
    // used to refuse the charge anyway, so every scan with a failed WebCheck was
    // delivered in full and never billed. Billing must follow the completion policy,
    // not contradict it; if a failed WebCheck should void the sale, the scan has to
    // stop completing, and that decision belongs in geminiCompletionService.

    const user = await User.findById(scan.userId);
    if (!user || !user.organizationId) return;

    const org = await Organization.findById(user.organizationId);
    if (!org) return;

    const limits = user.getAccountLimits(org);

    // ── Claim BEFORE charging ──────────────────────────────────────────────────
    // Previously the flag was read at the top of this function and written after
    // consumeScan, several awaits later. Two finalize calls for the same scan could
    // both pass the read and both charge the org. findOneAndUpdate is atomic in the
    // server, so exactly one caller sees the un-consumed document and proceeds.
    const claimed = await ScanResult.findOneAndUpdate(
      { analysisId: scanId, quotaConsumed: false },
      { $set: { quotaConsumed: true } }
    );
    if (!claimed) {
      console.log(`[Billing] Scan ${scanId} already claimed by another finalize call — not charging again.`);
      return;
    }

    // Charge the quota
    const result = await consumeScan(user.organizationId, {
      target: scan.target,
      scansPerTarget: limits.scansPerTarget,
      targetsPerMonth: limits.targetsPerMonth
    });

    if (!result) {
      // Could not charge — release the claim so a retry (or the cleanup watchdog)
      // can charge it later. Leaving it set would deliver the scan for free and
      // hide the fact that it was never billed.
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: { quotaConsumed: false } }
      );
      console.warn(`[Billing] consumeScan declined for ${scanId} — claim released.`);
      return;
    }

    if (result.__quotaSource) {
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: { quotaSource: result.__quotaSource } }
      ).catch(() => { /* bookkeeping only — never fail a settled charge over it */ });
    }

    console.log(`[Billing] Scan completed - quota deducted: ${scanId} (source=${result.__quotaSource || 'unknown'})`);
  } catch (err) {
    console.error(`⚠️ [Billing] Failed to finalize scan ${scanId}:`, err.message);
  }
}

/**
 * Reverse a single consumeScan() increment.
 *
 * ⚠️ Currently has NO callers anywhere in the repo — kept because it is the only
 * refund primitive that exists, and a Stripe refund/chargeback handler will need
 * one. Note it does not know which credit batch a scan was charged to, so it would
 * have to take `quotaSource`/batch id before it is safe to use on a credit-funded
 * scan (it blindly $incs the oneTimeRemainingScans mirror today).
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

module.exports = {
  checkScanQuota,
  claimScanSlot,
  consumeScan,
  finalizeSuccessfulScan,
  refundScan,
  // exported for tests
  availableCapacity,
  IN_FLIGHT_STATUSES
};
