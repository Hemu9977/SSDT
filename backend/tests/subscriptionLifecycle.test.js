'use strict';

/**
 * Subscription lifecycle tests: cancel → paid until the period ends → Free.
 *
 * These EXECUTE the real code — utils/entitlement.js, services/subscriptionLifecycle.js,
 * the real Stripe webhook and cancel handlers in routes/stripeRoutes.js, planCheck, and
 * planService's admission/charging — against an in-memory model layer and a stubbed
 * Stripe client. No database, no network.
 *
 * The real mongoose models are loaded (so instance methods such as
 * User#getAccountLimits are the production ones) and only their static query
 * methods are replaced by the store below.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const mongoose = require('mongoose');

const BACKEND = path.join(__dirname, '..');

// The webhook takes its unsigned dev path (JSON body, no signature) in tests.
delete process.env.STRIPE_WEBHOOK_SECRET;
if (process.env.NODE_ENV === 'production') process.env.NODE_ENV = 'test';
// Checkout configuration, read once when routes/stripeRoutes.js loads.
process.env.STRIPE_TAX_RATE_ID = 'txr_test';
process.env.STRIPE_PRICE_LIGHT_MONTHLY = 'price_light_monthly_test';
process.env.STRIPE_PRICE_TRIAL1 = 'price_trial1_test';
delete process.env.STRIPE_PRICE_PRO_ANNUAL; // a plan whose price is not configured

// ─── Stripe stub ─────────────────────────────────────────────────────────────
const stripeState = {
  subs: new Map(),        // id → subscription object (the "truth" in Stripe)
  retrieveError: null,    // when set, every retrieve throws it
  updateError: null,
  retrieveCalls: 0,
  updateCalls: 0,
  sessions: new Map(),    // checkout session id → session
  createdSessions: [],    // params of every checkout.sessions.create call
};
const clone = (o) => JSON.parse(JSON.stringify(o));
const sec = (ms) => Math.floor(ms / 1000);

function stripeNotFound() {
  const e = new Error('No such subscription');
  e.code = 'resource_missing';
  e.statusCode = 404;
  return e;
}

const stripeStub = {
  subscriptions: {
    retrieve: async (id) => {
      stripeState.retrieveCalls++;
      if (stripeState.retrieveError) throw stripeState.retrieveError;
      const s = stripeState.subs.get(id);
      if (!s) throw stripeNotFound();
      return clone(s);
    },
    update: async (id, params) => {
      stripeState.updateCalls++;
      if (stripeState.updateError) throw stripeState.updateError;
      const s = stripeState.subs.get(id);
      if (!s) throw stripeNotFound();
      if (params.cancel_at_period_end) {
        s.cancel_at_period_end = true;
        // Stripe reports the scheduled end as cancel_at = current period end.
        s.cancel_at = Math.min(...s.items.data.map(i => i.current_period_end));
      }
      return clone(s);
    },
  },
  checkout: {
    sessions: {
      retrieve: async (id) => clone(stripeState.sessions.get(id)),
      create: async (params) => {
        stripeState.createdSessions.push(params);
        return { id: `cs_new_${stripeState.createdSessions.length}`, url: 'https://checkout.stripe.test/x' };
      },
    },
  },
  customers: {
    retrieve: async (id) => ({ id, deleted: false }),
    create: async () => ({ id: 'cus_new' }),
  },
};
require.cache[path.join(BACKEND, 'config/stripe.js')] = {
  id: 'stripe', filename: 'stripe', loaded: true, exports: stripeStub,
};

// ─── In-memory store with just enough MongoDB filter semantics ───────────────
const db = { orgs: [], users: [], schedules: [], invites: [], scans: [], events: new Set(), claims: new Map() };
const DAY = 24 * 60 * 60 * 1000;

const isOp = (c) => c && typeof c === 'object' && !(c instanceof Date) && !Array.isArray(c)
  && !(c instanceof mongoose.Types.ObjectId) && Object.keys(c).some(k => k.startsWith('$'));
const num = (v) => (v instanceof Date ? v.getTime() : v);
function eq(a, b) {
  if (a == null || b == null) return a == null && b == null;
  if (a instanceof Date || b instanceof Date) return new Date(a).getTime() === new Date(b).getTime();
  return String(a) === String(b);
}

function matchValue(v, cond) {
  if (cond === null) return v == null;
  if (!isOp(cond)) return v != null && eq(v, cond);
  return Object.entries(cond).every(([op, arg]) => {
    switch (op) {
      case '$in': return arg.some(a => (a === null ? v == null : v != null && eq(v, a)));
      case '$ne': return arg === null ? v != null : !(v != null && eq(v, arg));
      case '$gt': return v != null && num(v) > num(arg);
      case '$gte': return v != null && num(v) >= num(arg);
      case '$lt': return v != null && num(v) < num(arg);
      case '$lte': return v != null && num(v) <= num(arg);
      case '$type': return arg === 'string' ? typeof v === 'string' : false;
      case '$exists': return arg ? v !== undefined : v === undefined;
      case '$elemMatch': return Array.isArray(v) && v.some(e => matches(e, arg));
      default: throw new Error(`matcher: unsupported operator ${op}`);
    }
  });
}

function matches(doc, filter) {
  return Object.entries(filter || {}).every(([k, cond]) => {
    if (k === '$or') return cond.some(f => matches(doc, f));
    if (k === '$and') return cond.every(f => matches(doc, f));
    return matchValue(doc[k], cond);
  });
}

function applyUpdate(doc, update, filter) {
  for (const [k, v] of Object.entries(update.$set || {})) doc[k] = v;
  for (const [k, v] of Object.entries(update.$push || {})) {
    doc[k] = [...(doc[k] || []), ...(v.$each || [v])];
    if (v.$sort && v.$sort.expiresAt) doc[k].sort((a, b) => a.expiresAt - b.expiresAt);
  }
  for (const [k, v] of Object.entries(update.$inc || {})) {
    if (k.startsWith('targetScanCounts.')) continue; // reporting map — not under test
    if (k.startsWith('scanCredits.$.')) {
      const field = k.slice('scanCredits.$.'.length);
      const el = doc.scanCredits.find(e => matches(e, filter.scanCredits.$elemMatch));
      el[field] += v;
      continue;
    }
    doc[k] = (doc[k] || 0) + v;
  }
}

// Chainable, awaitable stand-in for a mongoose Query.
function q(result) {
  const o = {
    select() { return o; },
    lean() { return o; },
    sort() { return o; },
    limit(n) { if (Array.isArray(result)) result = result.slice(0, n); return o; },
    then(a, b) { return Promise.resolve(result).then(a, b); },
  };
  return o;
}

function collectionStatics(name) {
  const rows = () => db[name];
  return {
    findById: (id) => q(rows().find(d => eq(d._id, id)) || null),
    findOne: (f) => q(rows().find(d => matches(d, f)) || null),
    find: (f) => q(rows().filter(d => matches(d, f))),
    countDocuments: async (f) => rows().filter(d => matches(d, f)).length,
    updateOne: async (f, u) => {
      const d = rows().find(x => matches(x, f));
      if (d) applyUpdate(d, u, f);
      return { matchedCount: d ? 1 : 0, modifiedCount: d ? 1 : 0 };
    },
    updateMany: async (f, u) => {
      const ds = rows().filter(x => matches(x, f));
      ds.forEach(d => applyUpdate(d, u, f));
      return { matchedCount: ds.length, modifiedCount: ds.length };
    },
    findOneAndUpdate: async (f, u) => {
      const d = rows().find(x => matches(x, f));
      if (!d) return null;
      applyUpdate(d, u, f);
      return d;
    },
  };
}

const Organization = require(path.join(BACKEND, 'models/Organization.js'));
const User = require(path.join(BACKEND, 'models/User.js'));
const ScheduledScan = require(path.join(BACKEND, 'models/ScheduledScan.js'));
const Invite = require(path.join(BACKEND, 'models/Invite.js'));
const ScanResult = require(path.join(BACKEND, 'models/ScanResult.js'));
const StripeEvent = require(path.join(BACKEND, 'models/StripeEvent.js'));

Object.assign(Organization, collectionStatics('orgs'));
Object.assign(User, collectionStatics('users'));
Object.assign(ScheduledScan, collectionStatics('schedules'));
Object.assign(Invite, collectionStatics('invites'));
Object.assign(ScanResult, collectionStatics('scans'), {
  // The quota claim: atomic test-and-set that returns the PRE-update document.
  findOneAndUpdate: async (f, u) => {
    const d = db.scans.find(x => matches(x, f));
    if (!d) return null;
    const before = { ...d };
    applyUpdate(d, u, f);
    return before;
  },
});
// Saving a document (new Organization, user.save()) just records it in the store;
// the store's objects are mutated in place, so there is nothing else to write.
Organization.prototype.save = async function () { if (!db.orgs.includes(this)) db.orgs.push(this); return this; };
User.prototype.save = async function () { if (!db.users.includes(this)) db.users.push(this); return this; };

Object.assign(StripeEvent, {
  findOne: (f) => q(db.claims.get(f.eventId) || null),
  create: async ({ eventId }) => {
    if (db.events.has(eventId)) { const e = new Error('dup'); e.code = 11000; throw e; }
    db.events.add(eventId);
    db.claims.set(eventId, { eventId, expiresAt: new Date(Date.now() + 7 * DAY) });
  },
  deleteOne: async ({ eventId }) => { db.events.delete(eventId); db.claims.delete(eventId); },
});

// ─── Code under test (loaded after the stubs) ────────────────────────────────
const entitlement = require(path.join(BACKEND, 'utils/entitlement.js'));
const { isSubscriptionEntitled, entitlementFilter, needsReconcile, RENEWAL_GRACE_MS } = entitlement;
const lifecycle = require(path.join(BACKEND, 'services/subscriptionLifecycle.js'));
const planService = require(path.join(BACKEND, 'services/planService.js'));
const planCheck = require(path.join(BACKEND, 'middleware/planCheck.js'));
const stripeRouter = require(path.join(BACKEND, 'routes/stripeRoutes.js'));

function handlerFor(router, routePath, method) {
  const layer = router.stack.find(l => l.route && l.route.path === routePath && l.route.methods[method]);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle; // skip the auth middleware
}
const { webhookHandler } = stripeRouter;
const cancelHandler = handlerFor(stripeRouter, '/cancel-subscription', 'post');
const checkoutHandler = handlerFor(stripeRouter, '/create-checkout-session', 'post');
const syncHandler = handlerFor(stripeRouter, '/sync-checkout-session', 'post');

function mockRes() {
  const r = {
    statusCode: 200, body: null,
    status(c) { r.statusCode = c; return r; },
    json(b) { r.body = b; return r; },
  };
  return r;
}

let eventSeq = 0;
async function deliver(event) {
  const res = mockRes();
  await webhookHandler({ headers: {}, body: Buffer.from(JSON.stringify(event)) }, res);
  return res;
}
const subEvent = (type, subId, id) => ({
  id: id || `evt_${++eventSeq}`, type,
  data: { object: { id: subId, object: 'subscription', status: 'active' } },
});
const invoiceEvent = (type, subId, { legacy = false, id } = {}) => ({
  id: id || `evt_${++eventSeq}`, type,
  data: {
    object: legacy
      ? { id: `in_${eventSeq}`, object: 'invoice', subscription: subId }
      : { id: `in_${eventSeq}`, object: 'invoice', parent: { type: 'subscription_details', subscription_details: { subscription: subId } } },
  },
});

async function cancelAs(user) {
  const res = mockRes();
  await cancelHandler({ user: { id: String(user._id) } }, res);
  return res;
}

// ─── Fixtures ────────────────────────────────────────────────────────────────
const HOUR = 60 * 60 * 1000;
const oid = () => new mongoose.Types.ObjectId();

function stripeSub(id, { status = 'active', periodEndMs, cancel = false } = {}) {
  const sub = {
    id, object: 'subscription', status,
    cancel_at_period_end: cancel,
    cancel_at: cancel ? sec(periodEndMs) : null,
    items: { object: 'list', data: [{ id: `si_${id}`, current_period_end: sec(periodEndMs) }] },
  };
  stripeState.subs.set(id, sub);
  return sub;
}

/**
 * One org on Pro monthly with an owner, a member, a schedule each, a pending
 * invite and (optionally) a purchased credit batch; plus its Stripe subscription.
 */
function seed({
  subId = 'sub_A', status = 'active', periodEndMs = Date.now() + 10 * DAY,
  cancel = false, credits = [], scanLimit = 10, scansUsed = 2,
} = {}) {
  db.orgs.length = 0; db.users.length = 0; db.schedules.length = 0;
  db.invites.length = 0; db.scans.length = 0; db.events.clear(); db.claims.clear();
  stripeState.subs.clear(); stripeState.sessions.clear(); stripeState.createdSessions.length = 0;
  stripeState.retrieveError = null; stripeState.updateError = null;
  stripeState.retrieveCalls = 0; stripeState.updateCalls = 0;

  const orgId = oid();
  const owner = new User({
    name: 'Owner', email: 'owner@example.test', organizationId: orgId, role: 'owner',
    stripeCustomerId: 'cus_A', accountType: 'paid',
  });
  const member = new User({
    name: 'Member', email: 'member@example.test', organizationId: orgId, role: 'member',
    accountType: 'paid',
    // Legacy user-level plan fields that must not survive a downgrade.
    planType: 'pro', billingCycle: 'monthly', subscriptionStatus: 'active', stripeSubscriptionId: subId,
  });
  db.users.push(owner, member);

  const org = {
    _id: orgId, name: 'Acme', ownerId: owner._id,
    planType: 'pro', billingCycle: 'monthly',
    subscriptionStatus: status, cancelAtPeriodEnd: cancel,
    stripeSubscriptionId: subId,
    expiresAt: new Date(sec(periodEndMs) * 1000),
    scanLimit, scansUsed, targetsUsed: 1, targetScanCounts: new Map(),
    seatsAllowed: 5, seatsUsed: 2,
    scanCredits: credits, oneTimeRemainingScans: credits.reduce((s, c) => s + c.scansRemaining, 0),
    totalScansAllTime: 0, lastScanReset: new Date(),
  };
  // handleCheckoutComplete saves the org document it loaded.
  Object.defineProperty(org, 'save', { value: async () => org, enumerable: false });
  db.orgs.push(org);

  db.schedules.push(
    { _id: oid(), userId: owner._id, enabled: true },
    { _id: oid(), userId: member._id, enabled: true },
  );
  db.invites.push({ _id: oid(), organizationId: orgId, status: 'pending', expiresAt: new Date(Date.now() + 7 * DAY) });

  stripeSub(subId, { status, periodEndMs, cancel });
  return { org, owner, member };
}

const liveCredit = (n = 1) => ({
  _id: oid(), source: 'trial1_onetime', scansTotal: n, scansRemaining: n,
  purchasedAt: new Date(), expiresAt: new Date(Date.now() + 60 * DAY),
  vulnerabilityAccessLevel: 'critical-high', source_type: 'stripe',
});

function assertFree(org) {
  assert.equal(org.planType, null);
  assert.equal(org.billingCycle, null);
  assert.equal(org.subscriptionStatus, 'canceled');
  assert.equal(org.stripeSubscriptionId, null);
  assert.equal(org.expiresAt, null);
  assert.equal(org.cancelAtPeriodEnd, false);
  assert.equal(org.scanLimit, 0);
  assert.equal(org.scansUsed, 0);
  assert.equal(org.seatsAllowed, 1);
  assert.equal(isSubscriptionEntitled(org), false);
}

// ═══ Entitlement: computed from status AND paid period ════════════════════════

test('cancelling org: entitled 1ms before the period end, not at it (no grace)', () => {
  const end = new Date('2026-11-01T00:00:00Z');
  const org = { subscriptionStatus: 'active', billingCycle: 'monthly', cancelAtPeriodEnd: true, expiresAt: end };
  assert.equal(isSubscriptionEntitled(org, new Date(end.getTime() - 1)), true);
  assert.equal(isSubscriptionEntitled(org, end), false);
});

test('renewing org: covered for a late renewal webhook up to the grace, not beyond', () => {
  const end = new Date('2026-11-01T00:00:00Z');
  const org = { subscriptionStatus: 'active', billingCycle: 'monthly', cancelAtPeriodEnd: false, expiresAt: end };
  assert.equal(isSubscriptionEntitled(org, new Date(end.getTime() + RENEWAL_GRACE_MS - 1)), true);
  assert.equal(isSubscriptionEntitled(org, new Date(end.getTime() + RENEWAL_GRACE_MS)), false);
});

test('non-paying statuses are never entitled, even inside the period', () => {
  const future = new Date(Date.now() + DAY);
  for (const status of ['past_due', 'unpaid', 'canceled', 'incomplete', 'incomplete_expired', 'paused', null]) {
    assert.equal(
      isSubscriptionEntitled({ subscriptionStatus: status, billingCycle: 'monthly', expiresAt: future }),
      false, status
    );
  }
});

test('legacy one-time orgs keep their status-only behaviour', () => {
  const org = { subscriptionStatus: 'active', billingCycle: 'onetime', expiresAt: new Date(Date.now() - 100 * DAY) };
  assert.equal(isSubscriptionEntitled(org), true);
  assert.equal(needsReconcile(org), false); // no subscription id → nothing to ask Stripe
});

test('entitlementFilter (atomic charge) agrees with isSubscriptionEntitled on every case', () => {
  const now = new Date('2026-11-01T12:00:00Z');
  const offsets = [null, -2 * RENEWAL_GRACE_MS, -RENEWAL_GRACE_MS, -RENEWAL_GRACE_MS + 1, -1, 0, 1, DAY];
  let cases = 0;
  for (const subscriptionStatus of ['active', 'trialing', 'past_due', 'canceled', 'unpaid', null]) {
    for (const billingCycle of ['monthly', 'annual', 'onetime', null]) {
      for (const cancelAtPeriodEnd of [true, false, undefined]) {
        for (const off of offsets) {
          const org = {
            subscriptionStatus, billingCycle, cancelAtPeriodEnd,
            expiresAt: off === null ? null : new Date(now.getTime() + off),
          };
          assert.equal(
            matches(org, entitlementFilter(now)), isSubscriptionEntitled(org, now),
            JSON.stringify(org)
          );
          cases++;
        }
      }
    }
  }
  assert.ok(cases > 500);
});

test('getAccountLimits gives FREE limits to a non-entitled org that still has planType set', () => {
  const user = new User({ name: 'u', email: 'u@example.test' });
  const base = { planType: 'pro', billingCycle: 'annual', scanCredits: [] };
  const free = { scansPerMonth: 20, targetsPerMonth: -1, scansPerTarget: null, vulnerabilityAccessLevel: 'critical-high', maxSchedules: 2 };

  const paid = user.getAccountLimits({ ...base, subscriptionStatus: 'active', expiresAt: new Date(Date.now() + DAY) });
  assert.equal(paid.vulnerabilityAccessLevel, 'all');
  assert.equal(paid.scansPerTarget, 10);

  for (const org of [
    { ...base, subscriptionStatus: 'past_due', expiresAt: new Date(Date.now() + DAY) },
    { ...base, subscriptionStatus: 'unpaid', expiresAt: new Date(Date.now() + DAY) },
    { ...base, subscriptionStatus: 'active', cancelAtPeriodEnd: true, expiresAt: new Date(Date.now() - 1) },
    { ...base, subscriptionStatus: 'active', cancelAtPeriodEnd: false, expiresAt: new Date(Date.now() - RENEWAL_GRACE_MS - 1) },
  ]) {
    const l = user.getAccountLimits(org);
    for (const [k, v] of Object.entries(free)) assert.equal(l[k], v, `${org.subscriptionStatus}: ${k}`);
    assert.equal(user.isPro(org), false);
  }
});

// ═══ Stripe API shapes ════════════════════════════════════════════════════════

test('periodEndOf reads basil+ items (earliest wins) and the legacy top-level field', () => {
  const { periodEndOf } = lifecycle;
  assert.equal(
    periodEndOf({ items: { data: [{ current_period_end: 2000 }, { current_period_end: 1000 }] } }).getTime(),
    1000 * 1000
  );
  assert.equal(periodEndOf({ current_period_end: 1500 }).getTime(), 1500 * 1000);
  assert.equal(periodEndOf({ items: { data: [] } }), null);
  assert.equal(periodEndOf({}), null);
});

test('subscriptionIdOf handles subscriptions, both invoice shapes and expanded objects', () => {
  const { subscriptionIdOf } = lifecycle;
  assert.equal(subscriptionIdOf({ object: 'subscription', id: 'sub_1' }), 'sub_1');
  assert.equal(subscriptionIdOf({ object: 'invoice', parent: { subscription_details: { subscription: 'sub_2' } } }), 'sub_2');
  assert.equal(subscriptionIdOf({ object: 'invoice', parent: { subscription_details: { subscription: { id: 'sub_3' } } } }), 'sub_3');
  assert.equal(subscriptionIdOf({ object: 'invoice', subscription: 'sub_4' }), 'sub_4');
  assert.equal(subscriptionIdOf({ object: 'invoice', subscription: { id: 'sub_5' } }), 'sub_5');
  assert.equal(subscriptionIdOf({ object: 'invoice', parent: null, subscription: null }), null);
  assert.equal(subscriptionIdOf({ object: 'checkout.session', subscription: 'sub_6' }), 'sub_6');
});

// ═══ Cancelling ═══════════════════════════════════════════════════════════════

test('owner cancels: auto-pay off, plan still works, end date recorded', async () => {
  const periodEndMs = Date.now() + 10 * DAY;
  const { org, owner } = seed({ periodEndMs });

  const res = await cancelAs(owner);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);
  assert.equal(stripeState.subs.get('sub_A').cancel_at_period_end, true);
  assert.equal(org.cancelAtPeriodEnd, true);
  assert.equal(org.expiresAt.getTime(), sec(periodEndMs) * 1000);
  assert.equal(new Date(res.body.cancelAt).getTime(), sec(periodEndMs) * 1000);
  // Paid until the end: nothing about the plan changed yet.
  assert.equal(org.planType, 'pro');
  assert.equal(org.subscriptionStatus, 'active');
  assert.equal(isSubscriptionEntitled(org), true);
});

test('a member cannot cancel the org subscription', async () => {
  const { org, member } = seed();
  const res = await cancelAs(member);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'INSUFFICIENT_ROLE');
  assert.equal(stripeState.updateCalls, 0);
  assert.equal(org.cancelAtPeriodEnd, false);
});

test('cancelling twice is idempotent and calls Stripe once', async () => {
  const { owner } = seed();
  await cancelAs(owner);
  const again = await cancelAs(owner);
  assert.equal(again.statusCode, 200);
  assert.equal(again.body.alreadyScheduled, true);
  assert.equal(stripeState.updateCalls, 1);
});

test('cancel without a subscription → NO_SUBSCRIPTION; Stripe failure → CANCEL_FAILED, nothing written', async () => {
  const { org, owner } = seed();
  org.stripeSubscriptionId = null;
  let res = await cancelAs(owner);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'NO_SUBSCRIPTION');

  seed();
  stripeState.updateError = new Error('Stripe down');
  res = await cancelAs(db.users[0]);
  assert.equal(res.statusCode, 500);
  assert.equal(res.body.code, 'CANCEL_FAILED');
  assert.equal(db.orgs[0].cancelAtPeriodEnd, false);
});

// ═══ Webhooks ═════════════════════════════════════════════════════════════════

test('subscription ended → org becomes Free like a never-purchased account; credits survive', async () => {
  const credit = liveCredit(2);
  const { org, owner, member } = seed({ cancel: true, credits: [credit] });
  // The paying user has since left the org — the old customer→user lookup would miss it.
  owner.organizationId = null;
  stripeState.subs.get('sub_A').status = 'canceled';

  const res = await deliver(subEvent('customer.subscription.deleted', 'sub_A'));

  assert.equal(res.statusCode, 200);
  assertFree(org);
  assert.equal(org.scanCredits[0].scansRemaining, 2, 'purchased credits are kept');
  assert.equal(member.accountType, 'free');
  assert.equal(member.planType, null);
  assert.equal(member.subscriptionStatus, null);
  assert.equal(member.stripeSubscriptionId, null);
  assert.equal(db.schedules.find(s => eq(s.userId, member._id)).enabled, false);
  assert.equal(db.invites[0].status, 'expired');

  // Same view a never-purchased org gets: free limits, credit severity only.
  const limits = member.getAccountLimits(org);
  assert.equal(limits.scansPerMonth, 20);
  assert.equal(limits.vulnerabilityAccessLevel, 'critical-high');
});

test('a duplicate delivery of the same event is processed once', async () => {
  seed();
  const ev = invoiceEvent('invoice.paid', 'sub_A', { id: 'evt_dup' });
  const first = await deliver(ev);
  const second = await deliver(ev);
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(stripeState.retrieveCalls, 1);
});

test('late events after the end cannot resurrect the plan', async () => {
  const { org } = seed({ cancel: true });
  stripeState.subs.get('sub_A').status = 'canceled';
  await deliver(subEvent('customer.subscription.deleted', 'sub_A'));
  assertFree(org);

  // An older "active" update and a late invoice arrive afterwards — even if Stripe
  // returned stale data, no org owns sub_A any more.
  stripeState.subs.get('sub_A').status = 'active';
  const r1 = await deliver(subEvent('customer.subscription.updated', 'sub_A'));
  const r2 = await deliver(invoiceEvent('invoice.paid', 'sub_A'));
  assert.equal(r1.statusCode, 200);
  assert.equal(r2.statusCode, 200);
  assertFree(org);
});

test('an event about an OLD subscription never touches the org’s newer plan', async () => {
  const { org } = seed({ subId: 'sub_NEW' });
  stripeSub('sub_OLD', { status: 'canceled', periodEndMs: Date.now() - DAY });
  const before = JSON.stringify(org);

  for (const ev of [
    subEvent('customer.subscription.deleted', 'sub_OLD'),
    subEvent('customer.subscription.updated', 'sub_OLD'),
    invoiceEvent('invoice.payment_failed', 'sub_OLD'),
  ]) {
    assert.equal((await deliver(ev)).statusCode, 200);
  }
  assert.equal(JSON.stringify(org), before);
  assert.equal(isSubscriptionEntitled(org), true);
});

test('writes are conditional: a stale org snapshot cannot overwrite or downgrade a newer plan', async () => {
  // A caller read the org while it was on sub_OLD; a new checkout then replaced it
  // with sub_NEW before the caller's write landed.
  const { org, member } = seed({ subId: 'sub_NEW' });
  const staleSnapshot = { _id: org._id, stripeSubscriptionId: 'sub_OLD' };
  const before = JSON.stringify(org);

  const r = await lifecycle.applySubscription(staleSnapshot, stripeSub('sub_OLD', { status: 'canceled', periodEndMs: Date.now() - DAY }));
  assert.equal(r.applied, false);
  assert.equal(await lifecycle.downgradeOrgToFree(org._id, 'sub_OLD'), false);

  assert.equal(JSON.stringify(org), before);
  assert.equal(member.accountType, 'paid', 'no member side effects');
  assert.equal(db.schedules.every(s => s.enabled), true, 'no schedule side effects');
  assert.equal(db.invites[0].status, 'pending');
});

test('an update that arrives before checkout completes is acknowledged without writing', async () => {
  const { org } = seed();
  org.stripeSubscriptionId = null; // checkout.session.completed not processed yet
  stripeSub('sub_EARLY', { periodEndMs: Date.now() + 30 * DAY });
  const before = JSON.stringify(org);
  const res = await deliver(subEvent('customer.subscription.updated', 'sub_EARLY'));
  assert.equal(res.statusCode, 200);
  assert.equal(JSON.stringify(org), before);
});

test('Stripe unreachable during a webhook → 500 and the claim is released so the retry works', async () => {
  const { org } = seed({ cancel: true });
  stripeState.subs.get('sub_A').status = 'canceled';
  stripeState.retrieveError = Object.assign(new Error('connect ETIMEDOUT'), { type: 'StripeConnectionError' });

  const ev = subEvent('customer.subscription.deleted', 'sub_A', 'evt_retry');
  const failed = await deliver(ev);
  assert.equal(failed.statusCode, 500);
  assert.equal(db.events.has('evt_retry'), false, 'claim released');
  assert.equal(org.planType, 'pro', 'nothing written');

  stripeState.retrieveError = null;
  const retried = await deliver(ev);
  assert.equal(retried.statusCode, 200);
  assertFree(org);
});

test('a subscription Stripe no longer has (resource_missing) is treated as ended', async () => {
  const { org } = seed();
  stripeState.subs.delete('sub_A');
  await deliver(subEvent('customer.subscription.deleted', 'sub_A'));
  assertFree(org);
});

test('renewal (invoice.paid, both payload shapes) advances the period end from Stripe', async () => {
  const { org } = seed({ periodEndMs: Date.now() - HOUR });
  const next = Date.now() + 30 * DAY;
  stripeState.subs.get('sub_A').items.data[0].current_period_end = sec(next);

  await deliver(invoiceEvent('invoice.paid', 'sub_A'));
  assert.equal(org.expiresAt.getTime(), sec(next) * 1000);

  const after = Date.now() + 60 * DAY;
  stripeState.subs.get('sub_A').items.data[0].current_period_end = sec(after);
  await deliver(invoiceEvent('invoice.paid', 'sub_A', { legacy: true }));
  assert.equal(org.expiresAt.getTime(), sec(after) * 1000);
});

test('payment failure → past_due (no access, plan kept) → paid again → finally ended → Free', async () => {
  const { org } = seed();
  const sub = stripeState.subs.get('sub_A');

  sub.status = 'past_due';
  await deliver(invoiceEvent('invoice.payment_failed', 'sub_A'));
  assert.equal(org.subscriptionStatus, 'past_due');
  assert.equal(org.planType, 'pro', 'plan kept while Stripe retries');
  assert.equal(isSubscriptionEntitled(org), false);

  sub.status = 'active';
  await deliver(invoiceEvent('invoice.paid', 'sub_A'));
  assert.equal(isSubscriptionEntitled(org), true);

  sub.status = 'canceled';
  await deliver(subEvent('customer.subscription.deleted', 'sub_A'));
  assertFree(org);
});

test('one-time (top-up) invoices are ignored', async () => {
  const { org } = seed();
  const before = JSON.stringify(org);
  const res = await deliver({ id: 'evt_onetime', type: 'invoice.paid', data: { object: { id: 'in_1', object: 'invoice', parent: null } } });
  assert.equal(res.statusCode, 200);
  assert.equal(stripeState.retrieveCalls, 0);
  assert.equal(JSON.stringify(org), before);
});

// ═══ Missed webhook: access still ends on time; Stripe repairs the record ═════

async function runPlanCheck(user) {
  const res = mockRes();
  let nextCalled = false;
  await planCheck({ user: { id: String(user._id) }, body: { url: 'https://example.com' } }, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

test('cancelled plan past its end with Stripe unreachable: scanning is refused', async () => {
  const { member } = seed({ cancel: true, periodEndMs: Date.now() - 60 * 1000 });
  stripeState.retrieveError = new Error('Stripe down');
  const { res, nextCalled } = await runPlanCheck(member);
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'PLAN_LIMIT_EXCEEDED');
});

test('cancelled plan before its end: scanning still works, Stripe not consulted', async () => {
  const { member } = seed({ cancel: true, periodEndMs: Date.now() + HOUR });
  const { nextCalled } = await runPlanCheck(member);
  assert.equal(nextCalled, true);
  assert.equal(stripeState.retrieveCalls, 0);
});

test('renewing plan just past its stored end with Stripe unreachable: still allowed (grace)', async () => {
  const { member } = seed({ periodEndMs: Date.now() - HOUR });
  stripeState.retrieveError = new Error('Stripe down');
  const { nextCalled } = await runPlanCheck(member);
  assert.equal(nextCalled, true);
});

test('on-demand reconcile: a missed deletion is repaired on the next request', async () => {
  const { org, member } = seed({ cancel: true, periodEndMs: Date.now() - 60 * 1000 });
  stripeState.subs.get('sub_A').status = 'canceled';
  const { res } = await runPlanCheck(member);
  assert.equal(res.statusCode, 403);
  assertFree(org);
});

test('sweep: ended subscriptions are downgraded, renewed ones healed, current ones untouched', async () => {
  seed({ subId: 'sub_ENDED', cancel: true, periodEndMs: Date.now() - HOUR });
  const ended = db.orgs[0];
  stripeState.subs.get('sub_ENDED').status = 'canceled';

  const renewed = { ...ended, _id: oid(), stripeSubscriptionId: 'sub_RENEWED', cancelAtPeriodEnd: false, planType: 'light' };
  const nextEnd = Date.now() + 30 * DAY;
  stripeSub('sub_RENEWED', { periodEndMs: nextEnd });

  const current = { ...ended, _id: oid(), stripeSubscriptionId: 'sub_CURRENT', cancelAtPeriodEnd: false, expiresAt: new Date(Date.now() + DAY) };
  stripeSub('sub_CURRENT', { periodEndMs: Date.now() + DAY });
  db.orgs.push(renewed, current);
  const currentBefore = JSON.stringify(current);

  const result = await lifecycle.sweepSubscriptions();

  assert.equal(result.due, 2);
  assertFree(ended);
  assert.equal(renewed.planType, 'light');
  assert.equal(renewed.expiresAt.getTime(), sec(nextEnd) * 1000);
  assert.equal(JSON.stringify(current), currentBefore);
  assert.equal(stripeState.retrieveCalls, 2, 'only due subscriptions are read');
});

// ═══ A scan that straddles the end of the paid period ═════════════════════════

function addScan(org, user, analysisId) {
  db.scans.push({
    _id: new mongoose.Types.ObjectId().toHexString(), analysisId,
    organizationId: org._id, userId: user._id, target: 'https://example.com',
    status: 'queued', quotaConsumed: false,
  });
  return db.scans[db.scans.length - 1];
}

test('admitted by the subscription, completed after it ended: settled there, no credit spent', async () => {
  const { org, member } = seed({ cancel: true, periodEndMs: Date.now() + 1000, credits: [liveCredit(1)] });
  const scan = addScan(org, member, 'scan-boundary');

  assert.equal(await planService.claimScanSlot(org._id, 'scan-boundary'), true);
  assert.equal(scan.admittedBy, 'subscription');

  // The period ends and Stripe's deletion is processed while the scan runs.
  stripeState.subs.get('sub_A').status = 'canceled';
  await deliver(subEvent('customer.subscription.deleted', 'sub_A'));
  assertFree(org);

  scan.status = 'completed';
  await planService.finalizeSuccessfulScan('scan-boundary');

  assert.equal(scan.quotaConsumed, true);
  assert.equal(scan.quotaSource, 'subscription');
  assert.equal(org.scanCredits[0].scansRemaining, 1, 'purchased credit untouched');
  assert.equal(org.totalScansAllTime, 1);
});

test('admitted after the end: funded by a credit if the org has one', async () => {
  const { org, member } = seed({ cancel: true, periodEndMs: Date.now() - 1000, credits: [liveCredit(1)] });
  const scan = addScan(org, member, 'scan-after');

  assert.equal(await planService.claimScanSlot(org._id, 'scan-after'), true);
  assert.equal(scan.admittedBy, 'credit');

  scan.status = 'completed';
  await planService.finalizeSuccessfulScan('scan-after');
  assert.equal(scan.quotaSource, 'credit');
  assert.equal(org.scanCredits[0].scansRemaining, 0);
});

test('admitted after the end with no credits: refused', async () => {
  const { org, member } = seed({ cancel: true, periodEndMs: Date.now() - 1000 });
  addScan(org, member, 'scan-refused');
  assert.equal(await planService.claimScanSlot(org._id, 'scan-refused'), false);
});

// ═══ Checkout: production safety ══════════════════════════════════════════════

async function startCheckout(user, planType, billingCycle) {
  const res = mockRes();
  await checkoutHandler({ user: { id: String(user._id) }, body: { planType, billingCycle } }, res);
  return res;
}

async function syncAs(user, sessionId) {
  const res = mockRes();
  await syncHandler({ user: { id: String(user._id) }, body: { sessionId } }, res);
  return res;
}

function checkoutSession(id, buyer, { planType, billingCycle, subscription = null }) {
  const session = {
    id, object: 'checkout.session', status: 'complete',
    mode: billingCycle === 'onetime' ? 'payment' : 'subscription',
    payment_status: 'paid', subscription,
    metadata: { userId: String(buyer._id), planType, billingCycle },
  };
  stripeState.sessions.set(id, session);
  return session;
}
const checkoutEvent = (session, id) => ({
  id: id || `evt_${++eventSeq}`, type: 'checkout.session.completed', data: { object: session },
});

test('an org whose subscription is past_due cannot start a second one (no double billing)', async () => {
  const { owner } = seed({ status: 'past_due' });
  const res = await startCheckout(owner, 'light', 'monthly');
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, 'ALREADY_SUBSCRIBED');
  assert.equal(stripeState.createdSessions.length, 0);
});

test('a subscription that ended without its webhook does not block buying a new plan', async () => {
  const { org, owner } = seed({ status: 'past_due' });
  stripeState.subs.get('sub_A').status = 'canceled'; // Stripe gave up; webhook lost

  const res = await startCheckout(owner, 'light', 'monthly');

  assert.equal(res.statusCode, 200);
  assert.equal(stripeState.createdSessions.length, 1);
  assert.equal(stripeState.createdSessions[0].mode, 'subscription');
  assert.deepEqual(stripeState.createdSessions[0].line_items[0].tax_rates, ['txr_test']);
  assertFree(org);
});

test('unknown plans are rejected and unconfigured plans are not sent to Stripe', async () => {
  const { org, owner } = seed();
  org.stripeSubscriptionId = null; org.subscriptionStatus = 'canceled';

  let res = await startCheckout(owner, 'enterprise', 'monthly');
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'INVALID_PLAN');

  res = await startCheckout(owner, 'pro', 'annual'); // STRIPE_PRICE_PRO_ANNUAL unset
  assert.equal(res.statusCode, 503);
  assert.equal(res.body.code, 'PLAN_NOT_CONFIGURED');
  assert.equal(stripeState.createdSessions.length, 0);
});

test('a trial bought while past_due is a top-up: the live subscription stays attached', async () => {
  const { org, owner } = seed({ status: 'past_due' });
  const session = checkoutSession('cs_topup', owner, { planType: 'trial1', billingCycle: 'onetime' });

  const res = await deliver(checkoutEvent(session));

  assert.equal(res.statusCode, 200);
  assert.equal(org.stripeSubscriptionId, 'sub_A', 'still attached — Stripe is still billing it');
  assert.equal(org.planType, 'pro');
  assert.equal(org.subscriptionStatus, 'past_due');
  assert.equal(org.scanCredits.length, 1);
  assert.equal(org.scanCredits[0].stripeCheckoutSessionId, 'cs_topup');
});

test('webhook and post-redirect sync racing on one checkout create exactly one org', async () => {
  seed();
  const buyer = new User({ name: 'Buyer', email: 'buyer@example.test' });
  db.users.push(buyer);
  const orgsBefore = db.orgs.length;
  stripeSub('sub_BUYER', { periodEndMs: Date.now() + 30 * DAY });
  const session = checkoutSession('cs_race', buyer, { planType: 'light', billingCycle: 'monthly', subscription: 'sub_BUYER' });
  const event = checkoutEvent(session, 'evt_race');

  const [hook, sync] = await Promise.all([deliver(event), syncAs(buyer, 'cs_race')]);

  // One of them applied it; the other was told to come back later.
  assert.equal(db.orgs.length, orgsBefore + 1);
  assert.ok([200, 500].includes(hook.statusCode));
  assert.ok([200, 409].includes(sync.statusCode));
  if (sync.statusCode === 409) assert.equal(sync.body.code, 'CHECKOUT_PROCESSING');

  // Stripe's retry (if the webhook lost) and a second sync are both no-ops.
  assert.equal((await deliver(event)).statusCode, 200);
  assert.equal((await syncAs(buyer, 'cs_race')).statusCode, 200);
  assert.equal(db.orgs.length, orgsBefore + 1);

  const org = db.orgs[db.orgs.length - 1];
  assert.equal(String(buyer.organizationId), String(org._id));
  assert.equal(org.stripeSubscriptionId, 'sub_BUYER');
  assert.equal(org.expiresAt.getTime(), sec(Date.now() + 30 * DAY) * 1000);
  assert.equal(isSubscriptionEntitled(org), true);
});

test('a checkout claim abandoned by a crashed worker is taken over', async () => {
  seed();
  const buyer = new User({ name: 'Buyer', email: 'buyer2@example.test' });
  db.users.push(buyer);
  const session = checkoutSession('cs_crashed', buyer, { planType: 'trial1', billingCycle: 'onetime' });
  // Claimed 10 minutes ago and never finished.
  db.events.add('checkout:cs_crashed');
  db.claims.set('checkout:cs_crashed', { eventId: 'checkout:cs_crashed', expiresAt: new Date(Date.now() + 7 * DAY - 10 * 60 * 1000) });

  const res = await deliver(checkoutEvent(session));

  assert.equal(res.statusCode, 200);
  const org = db.orgs.find(o => String(o._id) === String(buyer.organizationId));
  assert.ok(org, 'purchase applied');
  assert.equal(org.scanCredits.length, 1);
});
