'use strict';

/**
 * Session rules, executed against the real middleware and login handlers with an
 * in-memory model layer (tests/support/fakeMongo.js):
 *   - M3: when the account check cannot reach the database, reads are allowed
 *     (fail open) but writes are refused (fail closed).
 *   - M4: admin tokens live 8 h, customer tokens 7 d; administrators never get
 *     the 24-hour post-reset OTP bypass; isRecentAuth measures token age.
 *   - L10: every successful sign-in records lastLoginAt; a password check alone
 *     (OTP still pending) does not.
 *
 * Run with: node --test backend/tests/sessionRules.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { makeModel, stubModule, handlerFor, invoke } = require('./support/fakeMongo');

const BACKEND = path.join(__dirname, '..');

const Organization = makeModel('Organization', { defaults: () => ({ isDisabled: false }) });
const User = makeModel('User', {
  defaults: () => ({
    systemRole: 'user', isDisabled: false, isVerified: true, organizationId: null,
    lastLoginAt: null, passwordResetAt: null, tokensValidFrom: null, preferredLanguage: 'en',
  }),
});
stubModule(BACKEND, 'models/User.js', User);
stubModule(BACKEND, 'models/Organization.js', Organization);

const sentOtps = [];
stubModule(BACKEND, 'services/emailService.js', {
  generateOTP: () => '246810',
  sendOTPEmail: async (to, otp) => { sentOtps.push({ to, otp }); },
  sendResetPasswordEmail: async () => {},
});

process.env.JWT_SECRET = 'test-secret';
process.env.RATE_LIMIT_ENABLED = 'false';

const auth = require(path.join(BACKEND, 'middleware/auth.js'));
const { isRecentAuth } = auth;
const authRouter = require(path.join(BACKEND, 'routes/auth.js'));

const PASSWORD = 'Correct-Horse-1';
let HASH;
test.before(async () => { HASH = await bcrypt.hash(PASSWORD, 4); });

function reset() {
  User._reset(); Organization._reset(); sentOtps.length = 0;
  auth.invalidateAllPrincipals();
}

async function runAuth(method, token) {
  let status = null; let body = null; let nextCalled = false;
  const req = {
    method, path: '/x',
    header: (h) => (h.toLowerCase() === 'x-auth-token' ? token : undefined),
  };
  const res = { status(c) { status = c; return this; }, json(b) { body = b; return this; } };
  await auth(req, res, () => { nextCalled = true; });
  return { status, body, nextCalled, req };
}

const lifetimeSeconds = (token) => { const d = jwt.decode(token); return d.exp - d.iat; };

// ── M3 ──────────────────────────────────────────────────────────────────────

test('account check unavailable: reads fail open, writes fail closed with AUTH_UNAVAILABLE', async () => {
  reset();
  const u = User._insert({ email: 'a@example.com' });
  const token = jwt.sign({ user: { id: String(u._id) } }, 'test-secret', { expiresIn: '1h' });
  User._failures.add('findOne');

  const read = await runAuth('GET', token);
  assert.equal(read.nextCalled, true, 'GET must still be served');

  for (const m of ['POST', 'PATCH', 'PUT', 'DELETE']) {
    auth.invalidateAllPrincipals();
    const write = await runAuth(m, token);
    assert.equal(write.nextCalled, false, `${m} must be refused`);
    assert.equal(write.status, 503);
    assert.equal(write.body.code, 'AUTH_UNAVAILABLE');
  }
});

test('auth records the token issue time and 401s carry a code', async () => {
  reset();
  const u = User._insert({ email: 'a@example.com' });
  const token = jwt.sign({ user: { id: String(u._id) } }, 'test-secret', { expiresIn: '1h' });
  const ok = await runAuth('GET', token);
  assert.equal(typeof ok.req.tokenIssuedAt, 'number');

  const missing = await runAuth('GET', undefined);
  assert.deepEqual([missing.status, missing.body.code], [401, 'UNAUTHORIZED']);
  const bad = await runAuth('GET', 'not-a-jwt');
  assert.deepEqual([bad.status, bad.body.code], [401, 'UNAUTHORIZED']);
});

test('isRecentAuth compares token age with the limit', () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(isRecentAuth({ tokenIssuedAt: now - 60 }, 15 * 60000), true);
  assert.equal(isRecentAuth({ tokenIssuedAt: now - 16 * 60 }, 15 * 60000), false);
  assert.equal(isRecentAuth({}, 15 * 60000), false);
});

// ── M4 + L10: login paths ───────────────────────────────────────────────────

const login = (body) => invoke(handlerFor(authRouter, 'post', '/login'), { body });
const verifyOtp = (body) => invoke(handlerFor(authRouter, 'post', '/verify-otp'), { body });

test('post-reset login without OTP: customer gets a 7-day token and lastLoginAt is recorded', async () => {
  reset();
  const u = User._insert({ email: 'cust@example.com', password: HASH, passwordResetAt: new Date() });
  const res = await login({ email: 'cust@example.com', password: PASSWORD });
  assert.equal(res.body.code, 'AUTH_LOGIN_SUCCESS');
  assert.equal(lifetimeSeconds(res.body.token), 7 * 24 * 3600);
  assert.ok(User._get(u._id).lastLoginAt instanceof Date, 'the old bypass path never recorded the login');
});

test('administrators never get the post-reset OTP bypass', async () => {
  reset();
  const u = User._insert({ email: 'boss@example.com', password: HASH, systemRole: 'superadmin', passwordResetAt: new Date() });
  const res = await login({ email: 'boss@example.com', password: PASSWORD });
  assert.equal(res.body.code, 'AUTH_OTP_SENT');
  assert.equal(res.body.token, undefined, 'no token before the second factor');
  assert.equal(sentOtps.length, 1);
  assert.equal(User._get(u._id).lastLoginAt, null, 'a password check alone is not a sign-in');
});

test('OTP sign-in: admin token lives 8 hours, customer token 7 days, both record lastLoginAt', async () => {
  for (const [systemRole, seconds] of [['admin', 8 * 3600], ['user', 7 * 24 * 3600]]) {
    reset();
    const u = User._insert({ email: `${systemRole}@example.com`, password: HASH, systemRole });
    await login({ email: `${systemRole}@example.com`, password: PASSWORD });
    const res = await verifyOtp({ email: `${systemRole}@example.com`, otp: '246810' });
    assert.equal(res.body.code, 'AUTH_LOGIN_SUCCESS', JSON.stringify(res.body));
    assert.equal(lifetimeSeconds(res.body.token), seconds, systemRole);
    assert.ok(User._get(u._id).lastLoginAt instanceof Date, systemRole);
  }
});

test('the User model no longer defaults lastLoginAt to the creation time', () => {
  const src = require('node:fs').readFileSync(path.join(BACKEND, 'models/User.js'), 'utf8');
  const block = src.slice(src.indexOf('lastLoginAt: {'), src.indexOf('lastLoginAt: {') + 80);
  assert.match(block, /default: null/);
});
