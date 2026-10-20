'use strict';

/**
 * M6 — the admin dashboard's subscription state follows the entitlement rules
 * (utils/entitlement.js) instead of the raw stored Stripe status.
 *
 * Run with: node --test backend/tests/subscriptionState.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { subscriptionState, isCancellable } = require('../utils/subscriptionState');
const { isSubscriptionEntitled } = require('../utils/entitlement');

const NOW = new Date('2026-10-20T00:00:00Z');
const days = (n) => new Date(NOW.getTime() + n * 86400000);
const sub = (over) => ({ planType: 'basic', billingCycle: 'monthly', stripeSubscriptionId: 'sub_1', ...over });

test('each stored combination maps to the state an operator should see', () => {
  const cases = [
    [{}, 'none'],
    [{ planType: null, subscriptionStatus: 'canceled' }, 'canceled'],
    [sub({ subscriptionStatus: 'active', expiresAt: days(10) }), 'active'],
    [sub({ subscriptionStatus: 'trialing', expiresAt: days(10) }), 'trialing'],
    [sub({ subscriptionStatus: 'active', expiresAt: days(10), cancelAtPeriodEnd: true }), 'cancelling'],
    // Stored as active, but the paid period (plus the 24 h renewal grace) is over.
    [sub({ subscriptionStatus: 'active', expiresAt: days(-2) }), 'expired'],
    // A cancelling subscription gets no grace.
    [sub({ subscriptionStatus: 'active', expiresAt: days(-0.01), cancelAtPeriodEnd: true }), 'expired'],
    [sub({ subscriptionStatus: 'past_due', expiresAt: days(3) }), 'past_due'],
    [sub({ subscriptionStatus: 'unpaid' }), 'unpaid'],
    [{ planType: 'trial2', billingCycle: 'onetime' }, 'onetime'],
  ];
  for (const [org, expected] of cases) {
    assert.equal(subscriptionState(org, NOW), expected, JSON.stringify(org));
  }
});

test('"active"/"trialing"/"cancelling" are exactly the entitled states', () => {
  const samples = [
    sub({ subscriptionStatus: 'active', expiresAt: days(10) }),
    sub({ subscriptionStatus: 'active', expiresAt: days(-2) }),
    sub({ subscriptionStatus: 'active', expiresAt: days(10), cancelAtPeriodEnd: true }),
    sub({ subscriptionStatus: 'trialing', expiresAt: days(1) }),
    sub({ subscriptionStatus: 'past_due', expiresAt: days(3) }),
  ];
  for (const org of samples) {
    const entitled = ['active', 'trialing', 'cancelling'].includes(subscriptionState(org, NOW));
    assert.equal(entitled, isSubscriptionEntitled(org, NOW), JSON.stringify(org));
  }
});

test('cancellable only for a live subscription that is not already ending', () => {
  assert.equal(isCancellable(sub({ subscriptionStatus: 'active', expiresAt: days(10) }), NOW), true);
  assert.equal(isCancellable(sub({ subscriptionStatus: 'past_due', expiresAt: days(3) }), NOW), true);
  assert.equal(isCancellable(sub({ subscriptionStatus: 'active', expiresAt: days(10), cancelAtPeriodEnd: true }), NOW), false);
  assert.equal(isCancellable(sub({ subscriptionStatus: 'canceled' }), NOW), false);
  assert.equal(isCancellable({ planType: 'basic', subscriptionStatus: 'active', expiresAt: days(10) }, NOW), false, 'no Stripe id');
});
