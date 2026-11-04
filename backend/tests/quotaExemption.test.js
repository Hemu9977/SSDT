'use strict';

/**
 * Superadmins scan without plan restrictions (utils/quotaExemption.js).
 *
 * Executes the real User.getAccountLimits, planCheck middleware and scan-start
 * rate limiters — no database (model statics are replaced per test), no server.
 * Billing (claimScanSlot / finalizeSuccessfulScan) is covered in
 * billingInvariants.test.js.
 *
 * Run with: node --test backend/tests/quotaExemption.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');

process.env.RATE_LIMIT_ENABLED = 'true';
process.env.SCAN_RATE_LIMIT_MAX = '2';
process.env.COMBINED_SCAN_RATE_LIMIT_MAX = '1';

const User = require(path.join(BACKEND, 'models/User.js'));
const Organization = require(path.join(BACKEND, 'models/Organization.js'));
const planCheck = require(path.join(BACKEND, 'middleware/planCheck.js'));
const { scanLimiter, combinedScanLimiter } = require(path.join(BACKEND, 'middleware/rateLimiter.js'));
const { isQuotaExempt } = require(path.join(BACKEND, 'utils/quotaExemption.js'));

const exhaustedOrg = () => new Organization({
  name: 'Acme', planType: 'light', billingCycle: 'monthly', subscriptionStatus: 'active',
  expiresAt: new Date(Date.now() + 86400000), scanLimit: 3, scansUsed: 3,
});

function runPlanCheck(user, org, body = { url: 'https://example.com' }) {
  User.findById = async () => user;
  Organization.findById = async () => org;
  let status = null; let payload = null; let nextCalled = false;
  const req = { user: { id: String(user._id) }, body };
  const res = {
    status(code) { status = code; return this; },
    json(b) { payload = b; return this; },
  };
  return Promise.resolve(planCheck(req, res, () => { nextCalled = true; }))
    .then(() => ({ req, status, payload, nextCalled }));
}

// ─── who is exempt ───────────────────────────────────────────────────────────

test('only systemRole superadmin is exempt', () => {
  assert.equal(isQuotaExempt({ systemRole: 'superadmin' }), true);
  assert.equal(isQuotaExempt({ systemRole: 'admin' }), false);
  assert.equal(isQuotaExempt({ systemRole: 'user' }), false);
  assert.equal(isQuotaExempt({ role: 'owner' }), false, 'an org owner is a customer');
  assert.equal(isQuotaExempt(null), false);
});

// ─── getAccountLimits ────────────────────────────────────────────────────────

test('a superadmin gets unlimited limits and every severity, whatever the org', () => {
  const u = new User({ name: 'S', email: 's@x.io', systemRole: 'superadmin' });
  for (const org of [null, exhaustedOrg()]) {
    const l = u.getAccountLimits(org);
    assert.equal(l.scansPerMonth, -1);
    assert.equal(l.targetsPerMonth, -1);
    assert.equal(l.scansPerTarget, null);
    assert.equal(l.maxSchedules, -1);
    assert.equal(l.vulnerabilityAccessLevel, 'all');
  }
});

test('an admin still gets the org plan limits', () => {
  const u = new User({ name: 'A', email: 'a@x.io', systemRole: 'admin' });
  const l = u.getAccountLimits(exhaustedOrg());
  assert.equal(l.scansPerMonth, 3);
  assert.equal(l.vulnerabilityAccessLevel, 'critical-high');
});

// ─── planCheck ───────────────────────────────────────────────────────────────

test('planCheck admits a superadmin whose org quota is exhausted', async () => {
  const org = exhaustedOrg();
  const u = new User({ name: 'S', email: 's@x.io', systemRole: 'superadmin', organizationId: org._id });
  const r = await runPlanCheck(u, org);
  assert.equal(r.nextCalled, true);
  assert.equal(r.status, null);
  assert.equal(r.req.quotaExempt, true);
  assert.equal(r.req.organization, org);
});

test('planCheck admits a superadmin with no organization', async () => {
  const u = new User({ name: 'S', email: 's@x.io', systemRole: 'superadmin' });
  const r = await runPlanCheck(u, null);
  assert.equal(r.nextCalled, true);
  assert.equal(r.req.organization, null);
});

test('planCheck still refuses an ordinary user with no organization', async () => {
  const u = new User({ name: 'U', email: 'u@x.io' });
  const r = await runPlanCheck(u, null);
  assert.equal(r.nextCalled, false);
  assert.equal(r.status, 403);
  assert.equal(r.payload.code, 'NO_ORGANIZATION');
  assert.equal(r.req.quotaExempt, undefined);
});

// ─── scan-start rate limiters ────────────────────────────────────────────────

/** Send one request through a limiter; returns { passed, status, body }. */
async function hit(limiter, req) {
  let passed = false; let body = null;
  const res = {
    statusCode: 200,
    setHeader() {}, getHeader() {}, append() {},
    status(c) { this.statusCode = c; return this; },
    json(b) { body = b; return this; }, send() { return this; },
  };
  await limiter(req, res, () => { passed = true; });
  return { passed, status: res.statusCode, body };
}

async function passes(limiter, reqFactory, n) {
  let ok = 0;
  for (let i = 0; i < n; i++) if ((await hit(limiter, reqFactory())).passed) ok++;
  return ok;
}

const fakeReq = (id, extra = {}) => ({
  ip: '203.0.113.7', method: 'POST', path: '/scan', headers: {}, app: { get() {} },
  authUserId: id, ...extra,
});
const superReq = (id, extra = {}) => fakeReq(id, { quotaExempt: true, ...extra });

// One of the external scanners accepts one request per minute, so even an
// unlimited account must not start many scans at the same moment.
test('a superadmin may start only one scan per minute', async () => {
  assert.equal(await passes(scanLimiter, () => superReq('super-1'), 5), 1);

  const refused = await hit(scanLimiter, superReq('super-1'));
  assert.equal(refused.status, 429);
  assert.equal(refused.body.errorCode, 'SCAN_RATE_LIMITED', 'the client maps this code to its message');
});

test("a superadmin's one-per-minute budget is shared across scan routes", async () => {
  // e.g. a normal scan, then an authenticated scan in the same minute
  assert.equal((await hit(scanLimiter, superReq('super-2', { path: '/combined-url-scan' }))).passed, true);
  assert.equal((await hit(scanLimiter, superReq('super-2', { path: '/zap-auth/scan' }))).passed, false);
});

test('the combined-scan limiter applies to superadmins too', async () => {
  assert.equal(await passes(combinedScanLimiter, () => superReq('super-3'), 3), 1);
});

test('ordinary users keep their plan-sized scan budget', async () => {
  // SCAN_RATE_LIMIT_MAX is 2 in this file — not the superadmin's 1.
  assert.equal(await passes(scanLimiter, () => fakeReq('user-1'), 5), 2);
  assert.equal(await passes(combinedScanLimiter, () => fakeReq('user-1'), 3), 1);
});
