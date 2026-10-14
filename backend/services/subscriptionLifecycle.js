/**
 * backend/services/subscriptionLifecycle.js
 *
 * The only writer of an Organization's SUBSCRIPTION state after checkout, and the
 * only path that downgrades an org to Free.
 *
 * Lifecycle being implemented:
 *   1. Customer cancels → Stripe `cancel_at_period_end: true`. Status stays
 *      `active`; we record `cancelAtPeriodEnd` and the end date. Auto-pay is off.
 *   2. Until that date the plan keeps working (utils/entitlement.js).
 *   3. At that date Stripe moves the subscription to `canceled` and we downgrade
 *      the org so it behaves exactly like one that never bought a plan.
 *
 * Rules every function here follows:
 *   - Fetch on event. Callers pass only a subscription id; the current state is
 *     read from Stripe. Webhook ordering, duplicates and payload shape therefore
 *     cannot put stale data into the database.
 *   - Match by subscription id. Plan state is written only to the org whose
 *     `stripeSubscriptionId` equals the subscription's id, and the write itself is
 *     conditional on it, so an event about an old subscription can never touch an
 *     org that has since bought a new one. There is deliberately no fallback
 *     through the paying user's stripeCustomerId.
 *   - Stripe decides. Nothing here downgrades on our own stored date; access is
 *     already cut at that date by utils/entitlement.js, and this module only
 *     repairs the stored state once Stripe confirms it.
 */

const Organization = require('../models/Organization');
const User = require('../models/User');
const ScheduledScan = require('../models/ScheduledScan');
const Invite = require('../models/Invite');
const { needsReconcile, isSubscriptionEntitled } = require('../utils/entitlement');

// Statuses after which a subscription can never become active again.
const ENDED_STATUSES = ['canceled', 'incomplete_expired'];

// Statuses the sweep re-reads once their stored period has passed. Not-entitled
// states such as `unpaid` or `paused` are left to their webhooks: they grant no
// access, so there is nothing to cut off.
const SWEEP_STATUSES = ['active', 'trialing', 'past_due'];
const SWEEP_BATCH = 100;

const RECONCILE_TIMEOUT_MS = 3000;

function idOf(ref) {
  if (!ref) return null;
  return typeof ref === 'string' ? ref : (ref.id || null);
}

function fromUnix(seconds) {
  return typeof seconds === 'number' && Number.isFinite(seconds) ? new Date(seconds * 1000) : null;
}

/**
 * End of the subscription's current billing period.
 * Since API 2025-03-31.basil the period lives on each subscription item; with
 * several items the subscription renews at the earliest of them. Older payloads
 * (a webhook endpoint pinned to an older version) carry it at the top level.
 */
function periodEndOf(sub) {
  const items = (sub && sub.items && Array.isArray(sub.items.data)) ? sub.items.data : [];
  const ends = items
    .map(i => i && i.current_period_end)
    .filter(v => typeof v === 'number' && Number.isFinite(v));
  if (ends.length) return fromUnix(Math.min(...ends));
  return fromUnix(sub && sub.current_period_end);
}

/**
 * Subscription id referenced by a Stripe subscription or invoice object.
 * Invoices moved theirs to `parent.subscription_details.subscription` in basil;
 * either location may hold an id string or an expanded object.
 */
function subscriptionIdOf(obj) {
  if (!obj) return null;
  if (obj.object === 'subscription') return obj.id || null;
  const fromParent = obj.parent && obj.parent.subscription_details
    ? idOf(obj.parent.subscription_details.subscription)
    : null;
  return fromParent || idOf(obj.subscription);
}

/**
 * True while the org is attached to a Stripe subscription that has not ended —
 * including past_due/unpaid ones Stripe is still trying to charge. Such an org
 * must not start a second subscription (it would be billed twice), and a one-time
 * purchase must be added as a top-up rather than replace the subscription.
 */
function hasLiveSubscription(org) {
  return !!(org && org.stripeSubscriptionId && !ENDED_STATUSES.includes(org.subscriptionStatus));
}

/** True when a subscription is set to end rather than renew. */
function isCancellationScheduled(sub) {
  return !!(sub && (sub.cancel_at_period_end || sub.cancel_at));
}

/**
 * Downgrade an org whose subscription `subscriptionId` has ended, so it behaves
 * exactly like an org that never bought a plan. Purchased scan credits are kept:
 * they were paid for separately and expire on their own dates.
 *
 * @returns {Promise<boolean>} true if this call performed the downgrade
 */
async function downgradeOrgToFree(orgId, subscriptionId) {
  const now = new Date();

  // Conditional on the ended subscription still being the org's subscription:
  // if a newer plan replaced it, or another path already downgraded, this
  // matches nothing and none of the side effects below run.
  const res = await Organization.updateOne(
    { _id: orgId, stripeSubscriptionId: subscriptionId },
    {
      $set: {
        planType: null,
        billingCycle: null,
        subscriptionStatus: 'canceled',
        stripeSubscriptionId: null,
        expiresAt: null,
        cancelAtPeriodEnd: false,
        scanLimit: 0,
        scansUsed: 0,
        targetsUsed: 0,
        targetScanCounts: {},
        seatsAllowed: 1,
        lastScanReset: now
      }
    }
  );
  if (!res || !res.matchedCount) return false;

  // Members: no paid plan may survive on a legacy User field either, or a code
  // path that resolves limits from the user instead of the org would hand out
  // paid limits. Existing members stay in the org; seatsAllowed = 1 stops new
  // invites, and pending ones are expired so they cannot be accepted.
  const members = await User.find({ organizationId: orgId }).select('_id');
  const memberIds = members.map(m => m._id);

  const effects = await Promise.allSettled([
    User.updateMany(
      { organizationId: orgId },
      {
        $set: {
          accountType: 'free',
          planType: null,
          billingCycle: null,
          subscriptionStatus: null,
          stripeSubscriptionId: null
        }
      }
    ),
    // A never-purchased account has no running schedules. Disabled rather than
    // deleted, so the customer can switch them back on after buying a plan.
    ScheduledScan.updateMany(
      { userId: { $in: memberIds }, enabled: true },
      { $set: { enabled: false } }
    ),
    Invite.updateMany(
      { organizationId: orgId, status: 'pending' },
      { $set: { status: 'expired', expiresAt: now } }
    )
  ]);

  effects.forEach((r, i) => {
    if (r.status === 'rejected') {
      const what = ['member plan fields', 'schedules', 'pending invites'][i];
      console.error(`❌ [subscription] Org ${orgId} downgraded but resetting ${what} failed:`, r.reason && r.reason.message);
    }
  });

  console.log(`🚫 [subscription] Org ${orgId} downgraded to Free (subscription ${subscriptionId} ended).`);
  return true;
}

/**
 * Write a subscription's current Stripe state onto its org.
 *
 * @param {object} org  must carry _id and stripeSubscriptionId
 * @param {object} sub  a Stripe subscription, freshly retrieved
 * @returns {Promise<{applied: boolean, downgraded?: boolean, reason?: string}>}
 */
async function applySubscription(org, sub) {
  if (!org || !sub || !sub.id) return { applied: false, reason: 'missing' };
  if (org.stripeSubscriptionId !== sub.id) return { applied: false, reason: 'not_current_subscription' };

  if (ENDED_STATUSES.includes(sub.status)) {
    const downgraded = await downgradeOrgToFree(org._id, sub.id);
    return { applied: downgraded, downgraded };
  }

  const scheduled = isCancellationScheduled(sub);
  const set = {
    subscriptionStatus: sub.status,
    cancelAtPeriodEnd: scheduled
  };
  const end = (scheduled && fromUnix(sub.cancel_at)) || periodEndOf(sub);
  if (end) set.expiresAt = end;

  const res = await Organization.updateOne(
    { _id: org._id, stripeSubscriptionId: sub.id },
    { $set: set }
  );
  return { applied: !!(res && res.matchedCount) };
}

/**
 * Retrieve subscription `subscriptionId` from Stripe and apply it to its org.
 * Throws on a Stripe or database error so a webhook caller returns 500 and
 * Stripe retries.
 */
async function reconcileById(subscriptionId) {
  if (!subscriptionId) return { applied: false, reason: 'no_subscription_id' };

  // Required here, not at the top: constructing the client throws without
  // STRIPE_SECRET_KEY, and planCheck/profile load this module on every request path.
  const stripe = require('../config/stripe');

  let sub;
  try {
    sub = await stripe.subscriptions.retrieve(subscriptionId);
  } catch (err) {
    if (err && (err.code === 'resource_missing' || err.statusCode === 404)) {
      // Stripe has no such subscription, so it cannot be billing anyone.
      sub = { id: subscriptionId, object: 'subscription', status: 'canceled' };
    } else {
      throw err;
    }
  }

  const org = await Organization.findOne({ stripeSubscriptionId: subscriptionId });
  if (!org) return { applied: false, reason: 'no_org' };

  return applySubscription(org, sub);
}

/**
 * Re-read the org's subscription from Stripe and return the refreshed org.
 * Never throws and never waits longer than RECONCILE_TIMEOUT_MS: on failure the
 * stale org is returned and the computed entitlement (utils/entitlement.js)
 * decides access on its own.
 */
async function refreshFromStripe(org) {
  let timer;
  try {
    await Promise.race([
      reconcileById(org.stripeSubscriptionId),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('reconcile timed out')), RECONCILE_TIMEOUT_MS);
      })
    ]);
    return (await Organization.findById(org._id)) || org;
  } catch (err) {
    console.warn(`⚠️  [subscription] On-demand reconcile failed for org ${org._id}:`, err.message);
    return org;
  } finally {
    clearTimeout(timer);
  }
}

/** Refresh from Stripe only if the org's stored paid period has passed. */
async function refreshIfExpired(org, now = new Date()) {
  if (!org || !needsReconcile(org, now)) return org;
  return refreshFromStripe(org);
}

/**
 * Refresh before a purchase decision: also when the org holds a live but
 * non-paying subscription (past_due, unpaid…), which may in fact have ended in
 * Stripe without our webhook arriving — that must not block a new purchase.
 */
async function refreshForPurchase(org, now = new Date()) {
  if (!org) return org;
  if (needsReconcile(org, now) || (hasLiveSubscription(org) && !isSubscriptionEntitled(org, now))) {
    return refreshFromStripe(org);
  }
  return org;
}

/**
 * Safety net for missed webhooks: re-read from Stripe every subscription whose
 * stored period has passed (or was never recorded). Access was already cut by
 * the computed entitlement; this repairs the stored state.
 */
async function sweepSubscriptions(now = new Date()) {
  const due = await Organization.find({
    stripeSubscriptionId: { $type: 'string' },
    subscriptionStatus: { $in: SWEEP_STATUSES },
    $or: [{ expiresAt: { $lte: now } }, { expiresAt: null }]
  })
    .select('_id stripeSubscriptionId')
    .limit(SWEEP_BATCH);

  let reconciled = 0;
  for (const org of due) {
    try {
      await reconcileById(org.stripeSubscriptionId);
      reconciled++;
    } catch (err) {
      console.error(`❌ [subscription] Sweep could not reconcile org ${org._id}:`, err.message);
    }
  }
  if (due.length) {
    console.log(`🧹 [subscription] Sweep reconciled ${reconciled}/${due.length} expired subscription(s).`);
  }
  return { due: due.length, reconciled };
}

module.exports = {
  periodEndOf,
  subscriptionIdOf,
  isCancellationScheduled,
  hasLiveSubscription,
  applySubscription,
  reconcileById,
  refreshIfExpired,
  refreshForPurchase,
  downgradeOrgToFree,
  sweepSubscriptions,
  ENDED_STATUSES,
};
