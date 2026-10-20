'use strict';

/**
 * Behavioural tests for the admin API (routes/admin.js).
 *
 * These EXECUTE the real route handlers, the real audit service
 * (services/adminAudit.js) and the real subscription lifecycle against an
 * in-memory model layer (tests/support/fakeMongo.js) and a stubbed Stripe.
 * No database, network or credentials.
 *
 * Covers the audit findings fixed in this change: H1 (superadmin-only billing
 * and org deletion), H2 (persistent audit, fail closed), H3 (Stripe failure
 * stops an org deletion), M1 (org disable hierarchy), M4 (recent sign-in for
 * destructive actions), M5/M6 (KPI sources), M7 (health states), L2 (pagination).
 *
 * Run with: node --test backend/tests/adminRoutes.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { makeModel, stubModule, handlerFor, invoke, norm } = require('./support/fakeMongo');

const BACKEND = path.join(__dirname, '..');

// ─── Fake model layer ────────────────────────────────────────────────────────
const Organization = makeModel('Organization', {
  defaults: () => ({
    planType: null, billingCycle: null, subscriptionStatus: null, cancelAtPeriodEnd: false,
    isDisabled: false, deletedAt: null, deletedBy: null, seatsAllowed: 1, seatsUsed: 1,
    scanLimit: 0, scansUsed: 0, totalScansAllTime: 0, stripeSubscriptionId: null,
    expiresAt: null, scanCredits: [], createdAt: new Date(),
  }),
});
const User = makeModel('User', {
  defaults: () => ({
    systemRole: 'user', role: 'owner', isDisabled: false, isVerified: true,
    organizationId: null, lastLoginAt: null, createdAt: new Date(),
    password: 'BCRYPT-HASH', otp: '123456',
  }),
  refs: { organizationId: () => Organization },
});
const ScanResult = makeModel('ScanResult', { defaults: () => ({ createdAt: new Date(), updatedAt: new Date() }) });
const ScheduledScan = makeModel('ScheduledScan', { defaults: () => ({ enabled: true }) });
const Invite = makeModel('Invite', { defaults: () => ({ status: 'pending' }) });
const AdminAuditLog = makeModel('AdminAuditLog');
AdminAuditLog.ACTIONS = [
  'user.disable', 'user.enable', 'user.role_change', 'user.remove_from_org', 'user.delete',
  'org.disable', 'org.enable', 'org.cancel_subscription', 'org.delete',
];

stubModule(BACKEND, 'models/User.js', User);
stubModule(BACKEND, 'models/Organization.js', Organization);
stubModule(BACKEND, 'models/ScanResult.js', ScanResult);
stubModule(BACKEND, 'models/ScheduledScan.js', ScheduledScan);
stubModule(BACKEND, 'models/Invite.js', Invite);
stubModule(BACKEND, 'models/AdminAuditLog.js', AdminAuditLog);

// ─── Stripe stub ─────────────────────────────────────────────────────────────
const stripeState = { subs: {}, retrieveError: null, updateError: null, calls: [] };
const stripeErr = (code, statusCode) => Object.assign(new Error(`stripe ${code}`), { code, statusCode });
stubModule(BACKEND, 'config/stripe.js', {
  subscriptions: {
    async retrieve(id) {
      stripeState.calls.push(['retrieve', id]);
      if (stripeState.retrieveError) throw stripeState.retrieveError;
      if (!stripeState.subs[id]) throw stripeErr('resource_missing', 404);
      return { ...stripeState.subs[id] };
    },
    async update(id, params) {
      stripeState.calls.push(['update', id, params]);
      if (stripeState.updateError) throw stripeState.updateError;
      const sub = stripeState.subs[id];
      Object.assign(sub, params, params.cancel_at_period_end ? { cancel_at: sub.current_period_end } : {});
      return { ...sub };
    },
  },
});

// Realtime + health dependencies.
const disconnected = [];
stubModule(BACKEND, 'services/notificationService.js', { disconnectUser: (id) => disconnected.push(String(id)) });
const geminiStub = { mode: 'VERTEX_WIF', verified: true };
stubModule(BACKEND, 'services/geminiService.js', {
  GEMINI_AUTH_MODE: () => geminiStub.mode,
  getCredentialStatus: () => ({ verified: geminiStub.verified, checkedAt: null }),
});
stubModule(BACKEND, 'services/webCheckService.js', { checkHealth: async () => false });
const capacityStub = { managed: true, desired: 0, running: 0, pending: 0 };
stubModule(BACKEND, 'services/zapCapacityManager.js', {
  isManagedKey: () => capacityStub.managed,
  describeCapacity: async () => ({ desiredCount: capacityStub.desired, runningCount: capacityStub.running, pendingCount: capacityStub.pending }),
});

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
// Nothing listens on port 1: the ZAP API probes fail fast with ECONNREFUSED.
process.env.ZAP_API_URL = 'http://127.0.0.1:1';
process.env.ZAP_AUTH_API_URL = 'http://127.0.0.1:1';
delete process.env.REDIS_URL;

const router = require(path.join(BACKEND, 'routes/admin.js'));

// ─── Helpers ─────────────────────────────────────────────────────────────────
const NOW_S = () => Math.floor(Date.now() / 1000);
const DAY = 86400000;

function reset() {
  [Organization, User, ScanResult, ScheduledScan, Invite, AdminAuditLog].forEach((m) => m._reset());
  stripeState.subs = {}; stripeState.retrieveError = null; stripeState.updateError = null; stripeState.calls = [];
  disconnected.length = 0;
  geminiStub.mode = 'VERTEX_WIF'; geminiStub.verified = true;
  Object.assign(capacityStub, { managed: true, desired: 0, running: 0, pending: 0 });
}

function actor(systemRole, { signedInMinutesAgo = 1 } = {}) {
  const u = User._insert({ email: `${systemRole}@example.com`, name: systemRole, systemRole });
  return { adminUser: { ...u }, tokenIssuedAt: NOW_S() - signedInMinutesAgo * 60 };
}

const call = (method, routePath, req) => invoke(handlerFor(router, method, routePath), req);

function paidOrg(over = {}) {
  const org = Organization._insert({
    name: 'Paid Co', planType: 'basic', billingCycle: 'monthly', subscriptionStatus: 'active',
    expiresAt: new Date(Date.now() + 20 * DAY), stripeSubscriptionId: 'sub_live', ...over,
  });
  stripeState.subs[org.stripeSubscriptionId] = {
    id: org.stripeSubscriptionId, object: 'subscription', status: 'active',
    cancel_at_period_end: false, cancel_at: null,
    current_period_end: Math.floor((Date.now() + 20 * DAY) / 1000),
    items: { data: [{ current_period_end: Math.floor((Date.now() + 20 * DAY) / 1000) }] },
  };
  return org;
}

const auditRows = () => AdminAuditLog._store.map((r) => norm(r));

// ═════════════════════════════════════════════════════════════════════════════
// H1 — billing and deletion are superadmin-only, enforced by the server
// ═════════════════════════════════════════════════════════════════════════════

test('a plain admin cannot cancel a subscription: 403, Stripe untouched, attempt audited as denied', async () => {
  reset();
  const org = paidOrg();
  const res = await call('post', '/organizations/:id/cancel-subscription', { ...actor('admin'), params: { id: String(org._id) } });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'ADMIN_SUPERADMIN_REQUIRED');
  assert.deepEqual(stripeState.calls, [], 'Stripe must not be called');
  const [row] = auditRows();
  assert.equal(row.action, 'org.cancel_subscription');
  assert.equal(row.result, 'denied');
});

test('a plain admin cannot delete an organization: 403 and the org is untouched', async () => {
  reset();
  const org = paidOrg();
  const res = await call('delete', '/organizations/:id', { ...actor('admin'), params: { id: String(org._id) } });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'ADMIN_SUPERADMIN_REQUIRED');
  assert.equal(Organization._get(org._id).deletedAt, null);
  assert.equal(stripeState.calls.length, 0);
});

// ═════════════════════════════════════════════════════════════════════════════
// H3 + soft delete
// ═════════════════════════════════════════════════════════════════════════════

test('org deletion stops when Stripe refuses the cancellation (nothing deleted, failure audited)', async () => {
  reset();
  const org = paidOrg();
  const member = User._insert({ email: 'm@example.com', role: 'member', organizationId: org._id });
  stripeState.updateError = stripeErr('api_connection_error', 500);

  const res = await call('delete', '/organizations/:id', { ...actor('superadmin'), params: { id: String(org._id) } });

  assert.equal(res.status, 502);
  assert.equal(res.body.code, 'ADMIN_STRIPE_FAILED');
  const stored = Organization._get(org._id);
  assert.equal(stored.deletedAt, null, 'org must not be marked deleted');
  assert.equal(stored.isDisabled, false, 'org must not be locked');
  assert.equal(String(User._get(member._id).organizationId), String(org._id), 'members stay attached');
  const row = auditRows().find((r) => r.action === 'org.delete');
  assert.equal(row.result, 'failure');
  assert.equal(row.errorCode, 'ADMIN_STRIPE_FAILED');
});

test('org deletion: Stripe set to end, org soft-deleted and locked, members detached, invites expired, schedules off', async () => {
  reset();
  const org = paidOrg({ scanCredits: [{ source: 'stripe', scansTotal: 2, scansRemaining: 2, expiresAt: new Date(Date.now() + DAY) }] });
  const owner = User._insert({ email: 'own@example.com', role: 'owner', organizationId: org._id });
  const member = User._insert({ email: 'mem@example.com', role: 'member', organizationId: org._id, planType: 'basic' });
  Invite._insert({ organizationId: org._id, status: 'pending' });
  ScheduledScan._insert({ userId: member._id, enabled: true });

  const res = await call('delete', '/organizations/:id', { ...actor('superadmin'), params: { id: String(org._id) } });

  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.body.membersDetached, 2);
  assert.equal(res.body.stripe, 'scheduled');
  assert.deepEqual(stripeState.calls.find((c) => c[0] === 'update')[2], { cancel_at_period_end: true });

  const stored = Organization._get(org._id);
  assert.ok(stored.deletedAt instanceof Date, 'soft-deleted, not removed');
  assert.equal(stored.isDisabled, true);
  assert.equal(stored.scanCredits.length, 1, 'purchased credits are kept for recovery');
  for (const u of [owner, member]) {
    const s = User._get(u._id);
    assert.equal(s.organizationId, null);
    assert.equal(s.role, 'owner');
    assert.equal(s.planType, null);
  }
  assert.equal(Invite._store[0].status, 'expired');
  assert.equal(ScheduledScan._store[0].enabled, false);

  const row = auditRows().find((r) => r.action === 'org.delete');
  assert.equal(row.result, 'success');
  assert.equal(row.before.members.length, 2, 'audit row lists the detached members for recovery');
  assert.equal(row.before.creditsRemaining, 2);
});

test('org deletion proceeds when Stripe has no such subscription (nothing is billing)', async () => {
  reset();
  const org = paidOrg();
  delete stripeState.subs[org.stripeSubscriptionId];
  const res = await call('delete', '/organizations/:id', { ...actor('superadmin'), params: { id: String(org._id) } });
  assert.equal(res.status, 200);
  assert.equal(res.body.stripe, 'already_ended');
  assert.ok(Organization._get(org._id).deletedAt);
});

test('a deleted organization disappears from the list and the counts', async () => {
  reset();
  Organization._insert({ name: 'Kept' });
  Organization._insert({ name: 'Gone', deletedAt: new Date() });
  const list = await call('get', '/organizations', { ...actor('admin') });
  assert.deepEqual(list.body.organizations.map((o) => o.name), ['Kept']);
  assert.equal(list.body.pagination.total, 1);
});

// ═════════════════════════════════════════════════════════════════════════════
// Cancel subscription paths
// ═════════════════════════════════════════════════════════════════════════════

test('cancel subscription: Stripe failure → 502, org unchanged, failure audited', async () => {
  reset();
  const org = paidOrg();
  stripeState.updateError = stripeErr('rate_limit', 429);
  const res = await call('post', '/organizations/:id/cancel-subscription', { ...actor('superadmin'), params: { id: String(org._id) } });
  assert.equal(res.status, 502);
  assert.equal(res.body.code, 'ADMIN_STRIPE_FAILED');
  assert.equal(Organization._get(org._id).cancelAtPeriodEnd, false);
  assert.equal(auditRows().find((r) => r.result !== 'denied').result, 'failure');
});

test('cancel subscription: success records cancelAtPeriodEnd and the audit outcome', async () => {
  reset();
  const org = paidOrg();
  const res = await call('post', '/organizations/:id/cancel-subscription', { ...actor('superadmin'), params: { id: String(org._id) } });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.body.outcome, 'scheduled');
  assert.equal(res.body.synced, true);
  assert.equal(Organization._get(org._id).cancelAtPeriodEnd, true);
  const row = auditRows()[0];
  assert.equal(row.result, 'success');
  assert.equal(row.after.stripe, 'scheduled');
});

test('cancel subscription: Stripe succeeds but the org write fails → 200 with synced:false (webhook reconciles)', async () => {
  reset();
  const org = paidOrg();
  Organization._failures.add('updateOne');
  const res = await call('post', '/organizations/:id/cancel-subscription', { ...actor('superadmin'), params: { id: String(org._id) } });
  Organization._failures.clear();
  assert.equal(res.status, 200);
  assert.equal(res.body.synced, false);
  assert.equal(auditRows()[0].after.dbSynced, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// M4 — destructive actions need a recent sign-in
// ═════════════════════════════════════════════════════════════════════════════

test('destructive actions need a sign-in within 15 minutes; reversible ones do not', async () => {
  reset();
  const stale = actor('superadmin', { signedInMinutesAgo: 60 });
  const org = paidOrg();
  const target = User._insert({ email: 't@example.com' });

  for (const [method, route, params, body] of [
    ['delete', '/organizations/:id', { id: String(org._id) }],
    ['post', '/organizations/:id/cancel-subscription', { id: String(org._id) }],
    ['delete', '/users/:id', { id: String(target._id) }],
    ['patch', '/users/:id', { id: String(target._id) }, { systemRole: 'admin' }],
  ]) {
    const res = await call(method, route, { ...stale, params, body });
    assert.equal(res.status, 403, `${method} ${route}`);
    assert.equal(res.body.code, 'ADMIN_REAUTH_REQUIRED', `${method} ${route}`);
  }
  assert.equal(stripeState.calls.length, 0);

  const disable = await call('patch', '/users/:id', { ...stale, params: { id: String(target._id) }, body: { isDisabled: true } });
  assert.equal(disable.status, 200, 'disable/enable is reversible and stays available');
});

// ═════════════════════════════════════════════════════════════════════════════
// M1 — org disable hierarchy
// ═════════════════════════════════════════════════════════════════════════════

test('a plain admin cannot disable an organization that contains an administrator', async () => {
  reset();
  const org = Organization._insert({ name: 'Has Admin' });
  User._insert({ email: 'sa2@example.com', systemRole: 'superadmin', organizationId: org._id });
  User._insert({ email: 'sa-elsewhere@example.com', systemRole: 'superadmin' });

  const asAdmin = await call('patch', '/organizations/:id', { ...actor('admin'), params: { id: String(org._id) }, body: { isDisabled: true } });
  assert.equal(asAdmin.status, 403);
  assert.equal(asAdmin.body.code, 'ADMIN_SUPERADMIN_REQUIRED');
  assert.equal(Organization._get(org._id).isDisabled, false);

  const asSuper = await call('patch', '/organizations/:id', { ...actor('superadmin'), params: { id: String(org._id) }, body: { isDisabled: true } });
  assert.equal(asSuper.status, 200);
  assert.equal(Organization._get(org._id).isDisabled, true);
});

test('a plain admin may still disable an ordinary organization', async () => {
  reset();
  const org = Organization._insert({ name: 'Ordinary' });
  User._insert({ email: 'cust@example.com', organizationId: org._id });
  const res = await call('patch', '/organizations/:id', { ...actor('admin'), params: { id: String(org._id) }, body: { isDisabled: true } });
  assert.equal(res.status, 200);
  assert.equal(Organization._get(org._id).isDisabled, true);
  const row = auditRows().find((r) => r.action === 'org.disable');
  assert.deepEqual([row.result, row.before.isDisabled, row.after.isDisabled], ['success', false, true]);
});

// ═════════════════════════════════════════════════════════════════════════════
// H2 — audit records, fail closed
// ═════════════════════════════════════════════════════════════════════════════

test('disabling a user persists, is audited with before/after, and cuts the realtime channel', async () => {
  reset();
  const target = User._insert({ email: 'cust@example.com' });
  const res = await call('patch', '/users/:id', { ...actor('admin'), params: { id: String(target._id) }, body: { isDisabled: true } });
  assert.equal(res.status, 200);
  assert.equal(User._get(target._id).isDisabled, true, 'persisted');
  assert.ok(disconnected.includes(String(target._id)));
  const row = auditRows()[0];
  assert.equal(row.action, 'user.disable');
  assert.equal(row.targetLabel, 'cust@example.com');
  assert.deepEqual([row.result, row.before, row.after], ['success', { isDisabled: false }, { isDisabled: true }]);
  assert.ok(row.completedAt);
  assert.equal(JSON.stringify(row).includes('BCRYPT-HASH'), false, 'no secrets in audit rows');
});

test('if the audit record cannot be written, the action is refused (fail closed)', async () => {
  reset();
  const target = User._insert({ email: 'cust@example.com' });
  AdminAuditLog._failures.add('create');
  const res = await call('patch', '/users/:id', { ...actor('admin'), params: { id: String(target._id) }, body: { isDisabled: true } });
  AdminAuditLog._failures.clear();
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'ADMIN_AUDIT_FAILED');
  assert.equal(User._get(target._id).isDisabled, false, 'unaudited change must not happen');
});

test('PATCH /users/:id accepts exactly one change', async () => {
  reset();
  const target = User._insert({ email: 'cust@example.com' });
  for (const body of [{}, { isDisabled: true, systemRole: 'user' }, { isDisabled: 'yes' }]) {
    const res = await call('patch', '/users/:id', { ...actor('superadmin'), params: { id: String(target._id) }, body });
    assert.equal(res.status, 400, JSON.stringify(body));
  }
});

test('the audit log is superadmin-only', async () => {
  reset();
  const denied = await call('get', '/audit-log', { ...actor('admin') });
  assert.equal(denied.status, 403);
  const ok = await call('get', '/audit-log', { ...actor('superadmin') });
  assert.equal(ok.status, 200);
  assert.ok(Array.isArray(ok.body.entries));
});

// ═════════════════════════════════════════════════════════════════════════════
// M5 / M6 — KPI sources
// ═════════════════════════════════════════════════════════════════════════════

test('KPIs: all-time scans come from org counters; active = entitled now; deleted orgs excluded', async () => {
  reset();
  Organization._insert({ name: 'Paid', planType: 'pro', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() + 5 * DAY), totalScansAllTime: 10 });
  Organization._insert({ name: 'Lapsed', planType: 'basic', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() - 3 * DAY), totalScansAllTime: 4 });
  Organization._insert({ name: 'Deleted', planType: 'pro', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() + 5 * DAY), deletedAt: new Date(), totalScansAllTime: 6 });
  // Stale per-user counter (the old, wrong source) must not matter.
  User._insert({ email: 'u@example.com', totalScans: 999 });
  ScanResult._insert({ status: 'pending' }, { status: 'completed' });

  const res = await call('get', '/kpis', { ...actor('admin') });
  assert.equal(res.status, 200);
  assert.equal(res.body.kpis.totalScansAllTime, 20, 'sum of Organization.totalScansAllTime incl. deleted orgs');
  assert.equal(res.body.kpis.activeOrgs, 1, 'lapsed and deleted orgs are not active');
  assert.equal(res.body.kpis.totalOrgs, 2, 'deleted org excluded');
  assert.equal(res.body.kpis.runningScans, 1);
});

// ═════════════════════════════════════════════════════════════════════════════
// Lists: projections, subscription state, pagination, filters (L2)
// ═════════════════════════════════════════════════════════════════════════════

test('users list: no secrets, real last login (null when none), org plan with its real state', async () => {
  reset();
  const org = Organization._insert({ name: 'Lapsed Co', planType: 'basic', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() - 3 * DAY) });
  User._insert({ email: 'never@example.com', organizationId: org._id, lastLoginAt: null });

  const res = await call('get', '/users', { ...actor('admin'), query: { search: 'never' } });
  assert.equal(res.status, 200);
  const [u] = res.body.users;
  assert.equal(u.lastLoginAt, null);
  assert.equal(u.organization.name, 'Lapsed Co');
  assert.equal(u.organization.subscriptionState, 'expired');
  for (const secret of ['password', 'otp', 'otpExpires', 'resetPasswordToken']) {
    assert.equal(secret in u, false, `${secret} leaked`);
  }
});

test('organizations list: no Stripe ids; cancellable only for live, not-ending subscriptions', async () => {
  reset();
  paidOrg({ name: 'Live' });
  paidOrg({ name: 'Ending', stripeSubscriptionId: 'sub_end', cancelAtPeriodEnd: true });
  Organization._insert({ name: 'Free' });
  const res = await call('get', '/organizations', { ...actor('admin') });
  const byName = Object.fromEntries(res.body.organizations.map((o) => [o.name, o]));
  assert.equal(JSON.stringify(res.body).includes('sub_live'), false, 'Stripe id leaked');
  assert.deepEqual(
    [byName.Live.cancellable, byName.Ending.cancellable, byName.Free.cancellable],
    [true, false, false]
  );
  assert.deepEqual(
    [byName.Live.subscriptionState, byName.Ending.subscriptionState, byName.Free.subscriptionState],
    ['active', 'cancelling', 'none']
  );
});

test('non-numeric page/limit fall back to defaults instead of a 500; bad filters are 400', async () => {
  reset();
  User._insert({ email: 'a@example.com' });
  const res = await call('get', '/users', { ...actor('admin'), query: { page: 'abc', limit: 'NaN' } });
  assert.equal(res.status, 200);
  assert.equal(res.body.pagination.page, 1);
  assert.equal(res.body.pagination.limit, 20);

  assert.equal((await call('get', '/scans', { ...actor('admin'), query: { status: 'bogus' } })).status, 400);
  assert.equal((await call('get', '/organizations', { ...actor('admin'), query: { plan: 'gold' } })).status, 400);
  assert.equal((await call('get', '/users', { ...actor('admin'), query: { systemRole: 'root' } })).status, 400);
});

test('scans: running scans report elapsed time, finished scans a duration; failure reason is returned', async () => {
  reset();
  const owner = User._insert({ email: 'o@example.com' });
  const t0 = new Date(Date.now() - 10 * 60000);
  ScanResult._insert(
    { analysisId: 'run', userId: owner._id, target: 'https://a.example', status: 'pending', createdAt: t0, updatedAt: new Date(Date.now() - 9 * 60000) },
    { analysisId: 'bad', userId: owner._id, target: 'https://b.example', status: 'failed', failureReason: 'internal_error', createdAt: t0, updatedAt: new Date(t0.getTime() + 120000) },
  );
  const res = await call('get', '/scans', { ...actor('admin') });
  const byId = Object.fromEntries(res.body.scans.map((s) => [s.analysisId, s]));
  assert.equal(byId.run.inProgress, true);
  assert.ok(byId.run.elapsed >= 599 && byId.run.elapsed <= 605, `elapsed ${byId.run.elapsed}`);
  assert.equal(byId.run.duration, null);
  assert.equal(byId.bad.duration, 120);
  assert.equal(byId.bad.failureReason, 'internal_error');
  assert.equal('zapResult' in byId.bad, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// System Health route (checks themselves: tests/systemHealth.test.js)
// ═════════════════════════════════════════════════════════════════════════════

const systemHealth = require(path.join(BACKEND, 'services/systemHealth.js'));
const { INVENTORY, EXCLUDED } = require(path.join(BACKEND, 'config/healthInventory.js'));

/** Replace every check with a recorder for the duration of `fn`. */
async function withStubbedChecks(fn) {
  const saved = { ...systemHealth.CHECKS };
  const ran = [];
  for (const id of Object.keys(saved)) {
    systemHealth.CHECKS[id] = async () => { ran.push(id); return { status: 'healthy' }; };
  }
  systemHealth.clearCache();
  try {
    return await fn(ran);
  } finally {
    Object.assign(systemHealth.CHECKS, saved);
    systemHealth.clearCache();
  }
}

test('health route: reports exactly the inventory, never an excluded service, with a server-computed summary', async () => {
  reset();
  await withStubbedChecks(async () => {
    const res = await call('get', '/system-health', { ...actor('admin') });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.services.map((s) => s.id), INVENTORY.map((s) => s.id));
    const ids = new Set(res.body.services.map((s) => s.id));
    EXCLUDED.forEach((x) => assert.equal(ids.has(x.id), false, `${x.id} must not be shown`));
    assert.equal(res.body.summary.total, INVENTORY.length);
    assert.equal(res.body.summary.overall, 'healthy');
    assert.ok(res.body.generatedAt && res.body.refreshIntervalSec > 0);
  });
});

test('health route: ?service= re-checks one inventory service and rejects anything else', async () => {
  reset();
  await withStubbedChecks(async (ran) => {
    await call('get', '/system-health', { ...actor('admin') });
    ran.length = 0;
    // Within the cache window nothing re-runs…
    await call('get', '/system-health', { ...actor('admin') });
    assert.deepEqual(ran, []);
    // …but a retry of one service is not served from the full-report cache.
    // (FORCE_MIN_INTERVAL_MS still applies; advance past it by clearing.)
    systemHealth.clearCache();
    const ok = await call('get', '/system-health', { ...actor('admin'), query: { service: 'mongodb' } });
    assert.equal(ok.status, 200);
    assert.ok(ran.includes('mongodb'));

    for (const bad of ['arn:aws:ecs:ap-northeast-1:1:service/x', '../../etc', 'cdn', ['mongodb', 'redis']]) {
      const res = await call('get', '/system-health', { ...actor('admin'), query: { service: bad } });
      assert.equal(res.status, 400, `service=${JSON.stringify(bad)}`);
      assert.equal(res.body.code, 'ADMIN_INVALID_PAYLOAD');
    }
  });
});

test('health route is registered behind auth + adminAuth', () => {
  const auth = require(path.join(BACKEND, 'middleware/auth.js'));
  const adminAuth = require(path.join(BACKEND, 'middleware/adminAuth.js'));
  const idx = (pred) => router.stack.findIndex(pred);
  const authAt = idx((l) => !l.route && l.handle === auth);
  const adminAt = idx((l) => !l.route && l.handle === adminAuth);
  const routeAt = idx((l) => l.route && l.route.path === '/system-health');
  assert.ok(authAt >= 0 && adminAt > authAt && routeAt > adminAt, `${authAt} ${adminAt} ${routeAt}`);
});

// ═════════════════════════════════════════════════════════════════════════════
// Live data: plans in effect (N7), current-month usage (N6), partial failure
// is null, never zero (N8)
// ═════════════════════════════════════════════════════════════════════════════

test('plan distribution counts a lapsed plan as lapsed, a cancelling one as its plan, no plan as Free', async () => {
  reset();
  Organization._insert({ name: 'Paid', planType: 'pro', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() + 5 * DAY) });
  Organization._insert({ name: 'Cancelling', planType: 'pro', billingCycle: 'monthly', subscriptionStatus: 'active', cancelAtPeriodEnd: true, expiresAt: new Date(Date.now() + 5 * DAY) });
  Organization._insert({ name: 'Expired', planType: 'basic', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() - 3 * DAY) });
  Organization._insert({ name: 'PastDue', planType: 'light', billingCycle: 'monthly', subscriptionStatus: 'past_due', expiresAt: new Date(Date.now() + 5 * DAY) });
  Organization._insert({ name: 'Trial', planType: 'trial1', billingCycle: 'onetime', subscriptionStatus: 'active' });
  Organization._insert({ name: 'Free' });
  Organization._insert({ name: 'Gone', planType: 'pro', billingCycle: 'monthly', subscriptionStatus: 'active', expiresAt: new Date(Date.now() + 5 * DAY), deletedAt: new Date() });

  const asMap = (rows) => Object.fromEntries(rows.map((r) => [String(r._id), r.count]));
  const expected = { pro: 2, lapsed: 2, trial1: 1, null: 1 };
  const kpis = await call('get', '/kpis', { ...actor('admin') });
  assert.deepEqual(asMap(kpis.body.planDistribution), expected);
  const analytics = await call('get', '/analytics', { ...actor('admin') });
  assert.deepEqual(asMap(analytics.body.planDistribution), expected);
  assert.equal(analytics.body.estimatedRecurringValue.activeOrgCount, 3, 'pro ×2 + legacy one-time trial');
});

test('usage is this UTC month: a counter last reset in an earlier month reads 0 and leaves the top list', async () => {
  reset();
  const now = new Date();
  const lastMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 15));
  Organization._insert({ name: 'Stale', planType: 'pro', scansUsed: 9, scanLimit: 10, lastScanReset: lastMonth });
  Organization._insert({ name: 'Current', planType: 'basic', scansUsed: 2, scanLimit: 5, lastScanReset: now });

  const orgs = await call('get', '/organizations', { ...actor('admin') });
  const byName = Object.fromEntries(orgs.body.organizations.map((o) => [o.name, o]));
  assert.equal(byName.Stale.scansUsedThisMonth, 0);
  assert.equal(byName.Current.scansUsedThisMonth, 2);

  const analytics = await call('get', '/analytics', { ...actor('admin') });
  assert.deepEqual(analytics.body.topOrgsByUsage.map((o) => [o.name, o.scansUsedThisMonth]), [['Current', 2]]);
  assert.equal('lastScanReset' in analytics.body.topOrgsByUsage[0], false);
});

test('KPIs: a failed query is null and named in `unavailable`; the rest are real; zero stays zero', async () => {
  reset();
  User._failures.add('countDocuments');
  const res = await call('get', '/kpis', { ...actor('admin') });
  assert.equal(res.status, 200);
  assert.equal(res.body.kpis.totalUsers, null);
  assert.equal(res.body.kpis.verifiedUsers, null);
  assert.deepEqual(res.body.unavailable.sort(), ['totalUsers', 'verifiedUsers']);
  // No organizations exist: these are genuine zeros, not failures.
  assert.equal(res.body.kpis.totalOrgs, 0);
  assert.equal(res.body.kpis.totalScansAllTime, 0);
  assert.equal(res.body.kpis.runningScans, 0);
});

test('KPIs/analytics: when every query fails the request fails instead of returning a page of nulls', async () => {
  reset();
  const adminReq = actor('admin');
  [User, Organization, ScanResult].forEach((m) => m._failures.add('*'));
  assert.equal((await call('get', '/kpis', adminReq)).status, 500);
  assert.equal((await call('get', '/analytics', adminReq)).status, 500);
});

test('analytics: one failed source blanks only its sections', async () => {
  reset();
  ScanResult._failures.add('aggregate');
  const res = await call('get', '/analytics', { ...actor('admin') });
  assert.equal(res.status, 200);
  assert.equal(res.body.scanActivity, null);
  assert.deepEqual(res.body.unavailable, ['scanActivity']);
  assert.equal(res.body.userGrowth.length, 30, 'other sections still real');
  assert.ok(res.body.userGrowth.every((d) => typeof d.count === 'number'));
});

// ═════════════════════════════════════════════════════════════════════════════
// N4 — the platform is never left without a superadmin; N9 — user deletion is
// superadmin-only
// ═════════════════════════════════════════════════════════════════════════════

test('a superadmin cannot disable their own organization', async () => {
  reset();
  const org = Organization._insert({ name: 'Home' });
  const me = actor('superadmin');
  User._get(me.adminUser._id).organizationId = org._id;
  me.adminUser.organizationId = org._id;
  User._insert({ email: 'other-sa@example.com', systemRole: 'superadmin' });

  const res = await call('patch', '/organizations/:id', { ...me, params: { id: String(org._id) }, body: { isDisabled: true } });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'ADMIN_SELF_ORG');
  assert.equal(Organization._get(org._id).isDisabled, false);
});

test('disabling the organization holding every reachable superadmin is refused, even with plain admins elsewhere', async () => {
  reset();
  const org = Organization._insert({ name: 'Founders' });
  User._insert({ email: 'sa-a@example.com', systemRole: 'superadmin', organizationId: org._id });
  const me = actor('superadmin');
  User._insert({ email: 'plain@example.com', systemRole: 'admin' });

  // The caller is a second reachable superadmin, so this is allowed.
  const ok = await call('patch', '/organizations/:id', { ...me, params: { id: String(org._id) }, body: { isDisabled: true } });
  assert.equal(ok.status, 200);

  // Remove the caller from the count (their account disabled out of band; the
  // auth layer would normally stop them, this isolates the guard). Now the
  // organization holds the only reachable superadmin, and the plain admin
  // elsewhere must not satisfy the check.
  Organization._get(org._id).isDisabled = false;
  User._get(me.adminUser._id).isDisabled = true;
  const blocked = await call('patch', '/organizations/:id', { ...me, params: { id: String(org._id) }, body: { isDisabled: true } });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.body.code, 'ADMIN_LAST_SUPERADMIN');
  assert.equal(Organization._get(org._id).isDisabled, false);
});

test('the last reachable superadmin cannot be demoted, disabled or deleted (plain admins do not count)', async () => {
  reset();
  const disabledOrg = Organization._insert({ name: 'Locked', isDisabled: true });
  const target = User._insert({ email: 'only-sa@example.com', systemRole: 'superadmin' });
  // Another superadmin exists but cannot sign in: their organization is disabled.
  User._insert({ email: 'stranded-sa@example.com', systemRole: 'superadmin', organizationId: disabledOrg._id });
  User._insert({ email: 'plain@example.com', systemRole: 'admin' });
  // The caller's own account is disabled so it does not count as a remaining
  // superadmin (the auth layer would normally stop them; this isolates the guard).
  const me = actor('superadmin');
  User._get(me.adminUser._id).isDisabled = true;

  for (const [method, route, body] of [
    ['patch', '/users/:id', { systemRole: 'admin' }],
    ['patch', '/users/:id', { isDisabled: true }],
    ['delete', '/users/:id', undefined],
  ]) {
    const res = await call(method, route, { ...me, params: { id: String(target._id) }, body });
    assert.equal(res.status, 409, `${method} ${JSON.stringify(body)}`);
    assert.equal(res.body.code, 'ADMIN_LAST_SUPERADMIN', `${method} ${JSON.stringify(body)}`);
  }
  const after = User._get(target._id);
  assert.deepEqual([after.systemRole, after.isDisabled], ['superadmin', false]);

  // With a second reachable superadmin the same demotion goes through.
  User._insert({ email: 'second-sa@example.com', systemRole: 'superadmin' });
  const ok = await call('patch', '/users/:id', { ...me, params: { id: String(target._id) }, body: { systemRole: 'admin' } });
  assert.equal(ok.status, 200);
});

test('a plain admin cannot delete even an ordinary user: 403 and the attempt is audited', async () => {
  reset();
  const target = User._insert({ email: 'cust@example.com' });
  const res = await call('delete', '/users/:id', { ...actor('admin'), params: { id: String(target._id) } });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'ADMIN_SUPERADMIN_REQUIRED');
  assert.ok(User._get(target._id), 'the account must still exist');
  const row = auditRows().find((r) => r.action === 'user.delete');
  assert.deepEqual([row.result, row.errorCode], ['denied', 'ADMIN_SUPERADMIN_REQUIRED']);

  const asSuper = await call('delete', '/users/:id', { ...actor('superadmin'), params: { id: String(target._id) } });
  assert.equal(asSuper.status, 200);
  assert.equal(User._get(target._id), undefined);
});

test('the audit log shows script-made changes with operator and ticket', async () => {
  reset();
  AdminAuditLog._insert({
    actorType: 'script', operator: 'Ops Person', ticket: 'CHG-1', action: 'user.role_change',
    targetType: 'user', targetId: User._insert({ email: 'x@example.com' })._id, targetLabel: 'x@example.com',
    result: 'success', createdAt: new Date(),
  });
  const res = await call('get', '/audit-log', { ...actor('superadmin') });
  assert.equal(res.status, 200);
  const [e] = res.body.entries;
  assert.deepEqual([e.actorType, e.operator, e.ticket], ['script', 'Ops Person', 'CHG-1']);
});
