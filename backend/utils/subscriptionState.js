/**
 * backend/utils/subscriptionState.js
 *
 * One display state per organization, derived from the stored fields with the
 * same rules that grant access (utils/entitlement.js). The admin dashboard shows
 * this instead of the raw `subscriptionStatus`, which stays 'active' after a
 * paid period has ended until the reconcile sweep catches up.
 *
 * Pure and dependency-free apart from entitlement.js.
 */
const { isSubscriptionEntitled, ENTITLED_STATUSES } = require('./entitlement');

const STATES = [
  'none',        // never purchased, or downgraded to Free
  'onetime',     // legacy one-time (trial) org: access comes from credits
  'active',      // paid and renewing
  'trialing',    // Stripe trial period
  'cancelling',  // paid, set to end at expiresAt
  'expired',     // status still says paid, but the paid period has passed
  'past_due',
  'unpaid',
  'canceled',
  'incomplete',
  'incomplete_expired',
  'paused',
];

/**
 * @param {object} org  Organization document or plain object
 * @param {Date}   [now]
 * @returns {string} one of STATES
 */
function subscriptionState(org, now = new Date()) {
  if (!org) return 'none';
  const status = org.subscriptionStatus || null;

  if (org.billingCycle === 'onetime' && org.planType) return 'onetime';
  if (!org.planType && !status) return 'none';

  if (ENTITLED_STATUSES.includes(status)) {
    if (!isSubscriptionEntitled(org, now)) return 'expired';
    if (org.cancelAtPeriodEnd) return 'cancelling';
    return status; // 'active' | 'trialing'
  }

  if (status && STATES.includes(status)) return status;
  return org.planType ? 'expired' : 'none';
}

/** True when the admin "Cancel subscription" action is meaningful for this org. */
function isCancellable(org, now = new Date()) {
  return !!(org && org.stripeSubscriptionId)
    && ['active', 'trialing', 'past_due', 'unpaid'].includes(subscriptionState(org, now));
}

module.exports = { subscriptionState, isCancellable, SUBSCRIPTION_STATES: STATES };
