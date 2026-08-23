// frontend/src/config/planCatalog.js
//
// The commercial numbers for every purchasable plan: price, seats, scan
// allowance, severity tier. Both the signed-out landing page (MarketingHome) and
// the Profile plan chooser read this — before it existed they each carried their
// own copy, alongside three more in the backend.
//
// This deliberately mirrors backend/config/planCatalog.js rather than fetching
// it: a pricing endpoint would put a network round-trip (and a loading state) in
// front of the first thing a signed-out visitor sees. The two files are held in
// step by a test in src/__tests__/appInvariants.test.js, which reads the backend
// file off disk and compares every number — so a change here fails CI until the
// backend agrees, and vice versa.
//
// Prices are Japanese yen, TAX-EXCLUSIVE. The tax-inclusive figure shown on the
// cards is derived at render time — see TAX_RATE in pages/Profile.jsx.

export const PLAN_CATALOG = {
  light: {
    seats: 1,
    scans: 3,
    severity: 'critical-high',
    price: { monthly: 30000, annual: 300000 },
  },
  basic: {
    seats: 3,
    scans: 5,
    severity: 'all',
    price: { monthly: 50000, annual: 500000 },
  },
  pro: {
    seats: 5,
    scans: 10,
    severity: 'all',
    price: { monthly: 100000, annual: 1000000 },
  },
  trial1: {
    seats: 1,
    scans: 1,
    severity: 'critical-high',
    price: { onetime: 20000 },
  },
  trial2: {
    seats: 1,
    scans: 2,
    severity: 'all',
    price: { onetime: 30000 },
  },
};

// Display order for the plan cards — least to most capable. Keyed separately from
// PLAN_CATALOG so object key order is never load-bearing.
export const SUBSCRIPTION_PLAN_ORDER = ['light', 'basic', 'pro'];
export const ONETIME_PLAN_ORDER = ['trial1', 'trial2'];

/** Translation keys for plan display names. */
export const PLAN_NAMES = {
  light: 'planLight',
  basic: 'planBasic',
  pro: 'planPro',
  trial1: 'planTrial1',
  trial2: 'planTrial2',
};

/** `30000` → `'¥30,000'`. Grouping is the same in both locales. */
export const formatYen = (amount) => `¥${Math.round(amount).toLocaleString('en-US')}`;

/**
 * Build the plan-card rows for one billing cycle.
 * Shape matches what both PlanCard consumers already expected.
 */
export const plansForCycle = (billingCycle) => {
  const order = billingCycle === 'onetime' ? ONETIME_PLAN_ORDER : SUBSCRIPTION_PLAN_ORDER;
  const period = billingCycle === 'annual' ? 'periodYear' : billingCycle === 'monthly' ? 'periodMonth' : '';

  return order.map((planType) => {
    const plan = PLAN_CATALOG[planType];
    return {
      planType,
      billingCycle,
      price: formatYen(plan.price[billingCycle]),
      period,
      accounts: plan.seats,
      totalScans: plan.scans,
      severity: plan.severity,
    };
  });
};

/** All three cycles at once — the shape Profile.jsx's chooser indexes by cycle. */
export const PLANS = {
  monthly: plansForCycle('monthly'),
  annual: plansForCycle('annual'),
  onetime: plansForCycle('onetime'),
};
