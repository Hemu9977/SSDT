/**
 * backend/utils/entitlement.js
 *
 * Whether an organization's SUBSCRIPTION currently grants paid access.
 * Pure and dependency-free: models/User.js, services/planService.js and the
 * routes all require it, so it must not require any of them back.
 *
 * Entitlement is computed at request time rather than stored, so a plan ends at
 * the exact instant its paid period does — even if Stripe's
 * `customer.subscription.deleted` webhook is late or never arrives. The stored
 * plan fields are repaired separately, and only from Stripe
 * (services/subscriptionLifecycle.js).
 *
 * Purchased scan credits are a separate pool and are not decided here.
 */

const ENTITLED_STATUSES = ['active', 'trialing'];

// A renewing subscription's period end moves forward at the renewal instant and
// Stripe normally tells us within seconds. The grace covers a late or missed
// renewal event so a paying customer is never locked out; reconciliation repairs
// expiresAt long before it runs out. A subscription that is set to cancel gets
// no grace — nothing can renew it.
const RENEWAL_GRACE_MS = 24 * 60 * 60 * 1000;

function toMs(date) {
  if (date == null) return null;
  const ms = date instanceof Date ? date.getTime() : new Date(date).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function hasEntitledStatus(org) {
  return !!org && ENTITLED_STATUSES.includes(org.subscriptionStatus);
}

/**
 * @param {object} org  Organization document or plain object
 * @param {Date}   [now]
 * @returns {boolean}
 */
function isSubscriptionEntitled(org, now = new Date()) {
  if (!hasEntitledStatus(org)) return false;

  // Legacy one-time orgs carry status 'active' without being a subscription.
  // Their scans live in credit batches with their own expiry, so their existing
  // status-only behaviour is kept unchanged.
  if (org.billingCycle === 'onetime') return true;

  const end = toMs(org.expiresAt);
  // Legacy rows written before expiresAt was reliable: trust the status until the
  // sweep fills the date in from Stripe.
  if (end == null) return true;

  const t = toMs(now);
  if (org.cancelAtPeriodEnd) return t < end;
  return t < end + RENEWAL_GRACE_MS;
}

/**
 * True when the stored state says "paid" but the paid period has passed, so the
 * stored fields should be re-read from Stripe.
 */
function needsReconcile(org, now = new Date()) {
  if (!hasEntitledStatus(org) || !org.stripeSubscriptionId) return false;
  const end = toMs(org.expiresAt);
  return end != null && toMs(now) >= end;
}

/**
 * isSubscriptionEntitled() as a MongoDB filter, for atomic updates that must not
 * charge a subscription which has ended between the read and the write.
 * Keep the two in step — the tests check them against each other.
 */
function entitlementFilter(now = new Date()) {
  const t = toMs(now);
  return {
    subscriptionStatus: { $in: ENTITLED_STATUSES },
    $or: [
      { billingCycle: 'onetime' },
      { expiresAt: null },
      { cancelAtPeriodEnd: true, expiresAt: { $gt: new Date(t) } },
      { cancelAtPeriodEnd: { $ne: true }, expiresAt: { $gt: new Date(t - RENEWAL_GRACE_MS) } }
    ]
  };
}

module.exports = {
  ENTITLED_STATUSES,
  RENEWAL_GRACE_MS,
  isSubscriptionEntitled,
  needsReconcile,
  entitlementFilter,
};
