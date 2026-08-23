/**
 * backend/config/planCatalog.js
 *
 * THE commercial definition of every purchasable plan: what it costs, how many
 * seats it comes with, and how much scanning it buys.
 *
 * Before this file the same numbers were hand-copied into five places —
 * `PLAN_LIMITS` (models/User.js), `PLAN_CONFIGS` and `ONETIME_SCANS`
 * (routes/stripeRoutes.js), `PLAN_PRICES` (routes/admin.js), and two tables in the
 * frontend. They happened to agree; nothing made them agree, and a price change
 * had to land in five diffs to be correct.
 *
 * The frontend cannot import this file, so it keeps its own copy in
 * `frontend/src/config/planCatalog.js` — a public pricing endpoint would put a
 * network round-trip in front of the signed-out landing page. The two are held in
 * step by a test in `frontend/src/__tests__/appInvariants.test.js`, which reads
 * this file off disk and compares every number.
 *
 * NOT here, and deliberately:
 *   • The free / no-plan tier. It is not purchasable and has no price; it lives
 *     with the other quota shapes in models/User.js.
 *   • The consumption-tax rate. It is configured on a Stripe Tax Rate object
 *     (STRIPE_TAX_RATE_ID) that this code cannot read — see stripeRoutes.js.
 *
 * All prices are Japanese yen, TAX-EXCLUSIVE, matching the Stripe Price objects.
 */

const PLAN_CATALOG = {
  light: {
    seats: 1,
    scans: 3,
    targets: 3,
    vulnerabilityAccessLevel: 'critical-high',
    maxSchedules: 1,
    price: { monthly: 30000, annual: 300000 }
  },
  basic: {
    seats: 3,
    scans: 5,
    targets: 5,
    vulnerabilityAccessLevel: 'all',
    maxSchedules: 3,
    price: { monthly: 50000, annual: 500000 }
  },
  pro: {
    seats: 5,
    scans: 10,
    targets: 10,
    vulnerabilityAccessLevel: 'all',
    maxSchedules: 10,
    price: { monthly: 100000, annual: 1000000 }
  },
  trial1: {
    seats: 1,
    scans: 1,
    targets: 1,
    vulnerabilityAccessLevel: 'critical-high',
    maxSchedules: 0,
    price: { onetime: 20000 }
  },
  trial2: {
    seats: 1,
    scans: 2,
    targets: 1,
    vulnerabilityAccessLevel: 'all',
    maxSchedules: 0,
    price: { onetime: 30000 }
  }
};

/** Plan types sold as a recurring subscription. */
const RECURRING_PLANS = Object.keys(PLAN_CATALOG).filter(
  p => PLAN_CATALOG[p].price.monthly != null || PLAN_CATALOG[p].price.annual != null
);

/** Plan types sold as a single purchase (scan credits, no subscription). */
const ONETIME_PLANS = Object.keys(PLAN_CATALOG).filter(
  p => PLAN_CATALOG[p].price.onetime != null
);

/**
 * Scans granted per one-time purchase, keyed `${planType}_onetime` to match the
 * Stripe price keys. Replaces the hand-written ONETIME_SCANS table.
 */
const ONETIME_SCANS = ONETIME_PLANS.reduce((acc, plan) => {
  acc[`${plan}_onetime`] = PLAN_CATALOG[plan].scans;
  return acc;
}, {});

/**
 * Seats and monthly scan allowance written onto the Organization when a
 * subscription checkout completes. One-time plans carry no monthly allowance —
 * their scans arrive as a credit batch — so their scanLimit is 0.
 */
const PLAN_PROVISIONING = Object.keys(PLAN_CATALOG).reduce((acc, plan) => {
  const isRecurring = RECURRING_PLANS.includes(plan);
  acc[plan] = {
    seatsAllowed: PLAN_CATALOG[plan].seats,
    scanLimit: isRecurring ? PLAN_CATALOG[plan].scans : 0
  };
  return acc;
}, {});

/**
 * Monthly-equivalent revenue for a subscription, in yen. One-time plans return 0:
 * they are not recurring revenue and are excluded from MRR by design.
 */
function monthlyEquivalent(planType, billingCycle) {
  const plan = PLAN_CATALOG[planType];
  if (!plan) return 0;
  if (billingCycle === 'annual' && plan.price.annual != null) {
    return Math.round(plan.price.annual / 12);
  }
  return plan.price.monthly || 0;
}

module.exports = {
  PLAN_CATALOG,
  RECURRING_PLANS,
  ONETIME_PLANS,
  ONETIME_SCANS,
  PLAN_PROVISIONING,
  monthlyEquivalent
};
