'use strict';

/**
 * Sign-in hardening, executed against the real auth routes with an in-memory
 * model layer (tests/support/fakeMongo.js) and a stubbed Google verifier:
 *   - N2: a platform administrator who signs in with Google must still enter
 *     the emailed code; customers are unchanged.
 *   - N5: each emailed code allows OTP_MAX_ATTEMPTS guesses, counted per
 *     account and atomically (parallel guesses share the budget); only an HMAC
 *     of the code is stored; a code stored before hashing still verifies.
 *
 * Run with: node --test backend/tests/adminSignIn.test.js
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
let nextCode = '246810';
stubModule(BACKEND, 'services/emailService.js', {
  generateOTP: () => nextCode,
  sendOTPEmail: async (to, otp) => { sentOtps.push({ to, otp }); },
  sendResetPasswordEmail: async () => {},
});
const googleIdentity = { email: 'boss@aevus.jp', googleId: 'g-1', name: 'Boss' };
stubModule(BACKEND, 'utils/googleAuth.js', { verifyGoogleCredential: async () => ({ ...googleIdentity }) });

process.env.JWT_SECRET = 'test-secret';
process.env.RATE_LIMIT_ENABLED = 'false';

const authRouter = require(path.join(BACKEND, 'routes/auth.js'));
const { hashOtp, OTP_MAX_ATTEMPTS } = require(path.join(BACKEND, 'utils/otp.js'));

// /google answers customers from a jwt.sign callback, i.e. after the handler's
// promise settles, so wait for the response itself rather than the handler.
const google = (body) => new Promise((resolve, reject) => {
  let status = 200;
  const res = {
    status(c) { status = c; return this; },
    json(b) { resolve({ status, body: b }); return this; },
  };
  Promise.resolve(handlerFor(authRouter, 'post', '/google')({ body, ip: '127.0.0.1', get: () => 'node-test' }, res, () => {}))
    .catch(reject);
});
const login = (body) => invoke(handlerFor(authRouter, 'post', '/login'), { body });
const verifyOtp = (body) => invoke(handlerFor(authRouter, 'post', '/verify-otp'), { body });

const PASSWORD = 'Correct-Horse-1';
let HASH;
test.before(async () => { HASH = await bcrypt.hash(PASSWORD, 4); });

function reset() {
  User._reset(); Organization._reset(); sentOtps.length = 0; nextCode = '246810';
}
const lifetimeSeconds = (token) => { const d = jwt.decode(token); return d.exp - d.iat; };

// ── N2: Google sign-in ──────────────────────────────────────────────────────

test('admin signing in with Google gets no token until the emailed code is entered', async () => {
  for (const systemRole of ['admin', 'superadmin']) {
    reset();
    const u = User._insert({ email: 'boss@aevus.jp', password: HASH, systemRole, googleId: 'g-1' });
    const res = await google({ googleAccessToken: 'tok' });
    assert.equal(res.status, 200);
    assert.equal(res.body.code, 'AUTH_OTP_SENT', systemRole);
    assert.equal(res.body.token, undefined, `${systemRole}: Google alone must not yield a session`);
    assert.equal(sentOtps.length, 1);
    assert.equal(User._get(u._id).lastLoginAt, null, 'not signed in yet');

    const done = await verifyOtp({ email: 'boss@aevus.jp', otp: sentOtps[0].otp });
    assert.equal(done.body.code, 'AUTH_LOGIN_SUCCESS');
    assert.equal(lifetimeSeconds(done.body.token), 8 * 3600, 'admin token lifetime');
  }
});

test('a customer signing in with Google still gets a token directly', async () => {
  reset();
  User._insert({ email: 'boss@aevus.jp', password: HASH, googleId: 'g-1' });
  const res = await google({ googleAccessToken: 'tok' });
  assert.equal(res.body.code, 'AUTH_GOOGLE_SUCCESS');
  assert.ok(res.body.token);
  assert.equal(sentOtps.length, 0);
});

// ── N5: OTP storage and attempt limit ───────────────────────────────────────

test('only an HMAC of the code is stored, bound to the account', async () => {
  reset();
  const u = User._insert({ email: 'a@example.com', password: HASH });
  await login({ email: 'a@example.com', password: PASSWORD });
  const stored = User._get(u._id);
  assert.equal(stored.otp, undefined, 'plaintext code must not be stored');
  assert.equal(stored.otpHash, hashOtp(u._id, '246810'));
  assert.notEqual(stored.otpHash, hashOtp('someone-else', '246810'), 'the hash is per account');
  assert.equal(stored.otpAttempts, 0);
});

test(`after ${OTP_MAX_ATTEMPTS} wrong guesses even the right code is refused`, async () => {
  reset();
  User._insert({ email: 'a@example.com', password: HASH });
  await login({ email: 'a@example.com', password: PASSWORD });

  for (let i = 0; i < OTP_MAX_ATTEMPTS - 1; i++) {
    const r = await verifyOtp({ email: 'a@example.com', otp: '000000' });
    assert.equal(r.body.code, 'AUTH_OTP_INVALID', `guess ${i + 1}`);
  }
  const last = await verifyOtp({ email: 'a@example.com', otp: '000000' });
  assert.equal(last.status, 429);
  assert.equal(last.body.code, 'AUTH_OTP_LOCKED');

  const right = await verifyOtp({ email: 'a@example.com', otp: '246810' });
  assert.notEqual(right.body.code, 'AUTH_LOGIN_SUCCESS', 'the spent code must be dead');
  assert.equal(right.body.token, undefined);
});

test('parallel guesses share one budget', async () => {
  reset();
  User._insert({ email: 'a@example.com', password: HASH });
  await login({ email: 'a@example.com', password: PASSWORD });

  const results = await Promise.all(
    Array.from({ length: 20 }, () => verifyOtp({ email: 'a@example.com', otp: '111111' }))
  );
  const invalid = results.filter((r) => r.body.code === 'AUTH_OTP_INVALID').length;
  assert.ok(invalid <= OTP_MAX_ATTEMPTS - 1, `${invalid} guesses were evaluated`);
  assert.equal(results.some((r) => r.body.token), false);
});

test('a new code gets a fresh budget; the right code then signs in and clears the code', async () => {
  reset();
  const u = User._insert({ email: 'a@example.com', password: HASH });
  await login({ email: 'a@example.com', password: PASSWORD });
  for (let i = 0; i < OTP_MAX_ATTEMPTS; i++) await verifyOtp({ email: 'a@example.com', otp: '000000' });

  nextCode = '135790';
  await login({ email: 'a@example.com', password: PASSWORD });
  const ok = await verifyOtp({ email: 'a@example.com', otp: '135790' });
  assert.equal(ok.body.code, 'AUTH_LOGIN_SUCCESS');
  const stored = User._get(u._id);
  assert.equal(stored.otpHash, undefined);
  assert.equal(stored.otpAttempts, undefined);

  const replay = await verifyOtp({ email: 'a@example.com', otp: '135790' });
  assert.equal(replay.body.code, 'AUTH_OTP_INVALID', 'a code works once');
});

test('a code stored in plaintext before the change still verifies until it expires', async () => {
  reset();
  User._insert({ email: 'old@example.com', password: HASH, otp: '424242', otpExpires: new Date(Date.now() + 60000) });
  const ok = await verifyOtp({ email: 'old@example.com', otp: '424242' });
  assert.equal(ok.body.code, 'AUTH_LOGIN_SUCCESS');

  reset();
  User._insert({ email: 'old@example.com', password: HASH, otp: '424242', otpExpires: new Date(Date.now() - 1000) });
  const expired = await verifyOtp({ email: 'old@example.com', otp: '424242' });
  assert.equal(expired.body.code, 'AUTH_OTP_INVALID');
});

test('the profile endpoint never returns code material', () => {
  const src = require('node:fs').readFileSync(path.join(BACKEND, 'routes/auth.js'), 'utf8');
  const me = src.slice(src.indexOf("router.get('/me'"));
  for (const f of ['-password', '-otp', '-otpHash', '-otpAttempts', '-resetPasswordToken']) {
    assert.ok(me.includes(f), `/me must exclude ${f}`);
  }
});
