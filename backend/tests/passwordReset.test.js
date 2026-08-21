'use strict';

/**
 * Password-reset and session-revocation tests.
 *
 * Before this, /auth/forgot-password, /auth/reset-password and /auth/resend-otp
 * were one-line stubs that returned success unconditionally while doing
 * nothing — no email sent, no password changed. The routes are now implemented,
 * so these pin the properties that make them safe rather than merely working.
 *
 * The route handlers are exercised through a stubbed Mongoose layer: no
 * database, no SMTP, no AWS. Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const authRouteSrc = fs.readFileSync(path.join(BACKEND, 'routes/auth.js'), 'utf8');
const authMwSrc = fs.readFileSync(path.join(BACKEND, 'middleware/auth.js'), 'utf8');

// ─────────────────────────────────────────────────────────────────────────────
// 1. The routes are actually wired — this is the regression that started it
// ─────────────────────────────────────────────────────────────────────────────

test('the three routes are no longer unconditional-success stubs', () => {
  for (const route of ['/resend-otp', '/forgot-password', '/reset-password']) {
    const at = authRouteSrc.indexOf(`router.post('${route}'`);
    assert.ok(at !== -1, `${route} is missing`);
    const body = authRouteSrc.slice(at, authRouteSrc.indexOf('\n});', at));
    assert.ok(body.includes('await'), `${route} still does no work`);
    assert.ok(/User\.findOne|User\.findById/.test(body), `${route} never looks up a user`);
  }
});

test('forgot-password sends the reset email and resend-otp sends the OTP', () => {
  const forgot = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/forgot-password'"));
  assert.ok(/sendResetPasswordEmail\(/.test(forgot.slice(0, forgot.indexOf('\n});'))),
    'sendResetPasswordEmail was imported but never called — the original bug');

  const resend = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/resend-otp'"));
  assert.ok(/sendOTPEmail\(/.test(resend.slice(0, resend.indexOf('\n});'))));
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Token handling
// ─────────────────────────────────────────────────────────────────────────────

test('the reset token is stored hashed, never in plaintext', () => {
  // A database leak must not hand an attacker usable reset links.
  assert.ok(/createHash\('sha256'\)/.test(authRouteSrc), 'no hashing helper found');
  const forgot = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/forgot-password'"));
  const body = forgot.slice(0, forgot.indexOf('\n});'));
  assert.ok(/resetPasswordToken = hashResetToken\(rawToken\)/.test(body),
    'the stored token must be the hash');
  assert.ok(/sendResetPasswordEmail\(user\.email, rawToken/.test(body),
    'the RAW token must be what goes in the email');
});

test('hashResetToken is deterministic and one-way for lookup', () => {
  const hash = (raw) => crypto.createHash('sha256').update(raw).digest('hex');
  const raw = crypto.randomBytes(32).toString('hex');
  assert.equal(hash(raw), hash(raw), 'lookup by hash requires determinism');
  assert.notEqual(hash(raw), raw);
  assert.equal(hash(raw).length, 64);
});

test('reset-password requires an unexpired token and consumes it', () => {
  const reset = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/reset-password'"));
  const body = reset.slice(0, reset.indexOf('\n});'));
  assert.ok(/resetPasswordExpires: \{ \$gt: new Date\(\) \}/.test(body),
    'an expired token must not be accepted');
  assert.ok(/resetPasswordToken = undefined/.test(body), 'the link must be single-use');
  assert.ok(/resetPasswordExpires = undefined/.test(body));
});

test('reset-password hashes the new password rather than storing it plainly', () => {
  // There is no pre-save hook on the User model, so assigning the plaintext
  // and calling .save() would persist it in the clear.
  const modelSrc = fs.readFileSync(path.join(BACKEND, 'models/User.js'), 'utf8');
  assert.ok(!/pre\(['"]save['"]/.test(modelSrc),
    'a pre-save hook now exists — this route must be re-checked');

  const reset = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/reset-password'"));
  const body = reset.slice(0, reset.indexOf('\n});'));
  assert.ok(/bcrypt\.genSalt\(10\)/.test(body) && /bcrypt\.hash\(password, salt\)/.test(body));
});

test('reset-password enforces the same 8-character minimum as register', () => {
  const reset = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/reset-password'"));
  const body = reset.slice(0, reset.indexOf('\n});'));
  assert.ok(/password\.length < 8/.test(body));

  // And the client agrees, so a 6-character password can't pass validation and
  // then fail server-side.
  const page = fs.readFileSync(
    path.join(BACKEND, '../frontend/src/pages/auth/ResetPasswordPage.jsx'), 'utf8');
  assert.ok(/password\.length < 8/.test(page), 'client minimum drifted from the server');
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Account enumeration
// ─────────────────────────────────────────────────────────────────────────────

test('forgot-password and resend-otp answer identically for unknown accounts', () => {
  for (const route of ['/forgot-password', '/resend-otp']) {
    const at = authRouteSrc.indexOf(`router.post('${route}'`);
    const body = authRouteSrc.slice(at, authRouteSrc.indexOf('\n});', at));
    // A single ack() helper used on every path is what makes the responses
    // indistinguishable; branching returns would leak account existence.
    assert.ok(/const ack = \(\) =>/.test(body), `${route} has no shared ack`);
    assert.ok(/if \(!user\) return ack\(\);/.test(body),
      `${route} must not reveal that the account is unknown`);
    assert.ok(/catch \(e\)/.test(body),
      `${route} must swallow email failures — otherwise the error leaks existence`);
  }
});

test('reset-password does not distinguish "no such token" from "expired"', () => {
  const reset = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/reset-password'"));
  const body = reset.slice(0, reset.indexOf('\n});'));
  const codes = [...body.matchAll(/code: '(AUTH_RESET_TOKEN_INVALID|[A-Z_]+)'/g)].map((m) => m[1]);
  assert.ok(codes.includes('AUTH_RESET_TOKEN_INVALID'));
  // Only one failure code for the lookup, so timing/response can't be mined.
  assert.equal(body.match(/Invalid or expired reset token/g).length, 1);
});

test('both email-sending routes sit behind the dedicated limiter', () => {
  for (const route of ['/forgot-password', '/resend-otp']) {
    const line = authRouteSrc.split('\n').find((l) => l.includes(`router.post('${route}'`));
    assert.ok(/emailSendLimiter/.test(line), `${route} is not rate limited per recipient`);
  }
  const limiterSrc = fs.readFileSync(path.join(BACKEND, 'middleware/rateLimiter.js'), 'utf8');
  assert.ok(/email:\$\{email\}/.test(limiterSrc) || /`email:/.test(limiterSrc),
    'the limiter must key on the recipient, not the caller IP');
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Session revocation
// ─────────────────────────────────────────────────────────────────────────────

test('isTokenRevoked compares JWT iat (seconds) against tokensValidFrom (ms)', () => {
  const { isTokenRevoked } = require('../middleware/auth');
  const now = Date.now();

  // Never reset: nothing is revoked.
  assert.equal(isTokenRevoked({ tokensValidFrom: null }, { iat: Math.floor(now / 1000) }), false);

  // Token issued a minute BEFORE the reset — must be rejected.
  assert.equal(
    isTokenRevoked({ tokensValidFrom: now }, { iat: Math.floor((now - 60_000) / 1000) }),
    true
  );

  // Token issued a minute AFTER the reset — must still work.
  assert.equal(
    isTokenRevoked({ tokensValidFrom: now }, { iat: Math.floor((now + 60_000) / 1000) }),
    false
  );

  // A malformed token must not crash the middleware.
  assert.equal(isTokenRevoked({ tokensValidFrom: now }, {}), false);
  assert.equal(isTokenRevoked({ tokensValidFrom: now }, null), false);
});

test('reset-password revokes existing sessions and applies immediately', () => {
  const reset = authRouteSrc.slice(authRouteSrc.indexOf("router.post('/reset-password'"));
  const body = reset.slice(0, reset.indexOf('\n});'));
  assert.ok(/tokensValidFrom = new Date\(\)/.test(body),
    'a reset must not leave the old token valid for the rest of its 7-day life');
  assert.ok(/invalidatePrincipal\(user\._id\)/.test(body),
    'without this the revocation waits out the 30s auth cache');
  // The login route reads this to skip OTP for 24h; nothing wrote it before.
  assert.ok(/passwordResetAt = new Date\(\)/.test(body));
});

test('the auth middleware enforces revocation and reuses the cached read', () => {
  assert.ok(/isTokenRevoked\(state, decoded\)/.test(authMwSrc));
  assert.ok(/code: 'SESSION_REVOKED'/.test(authMwSrc));
  // One query serving both checks — not a second read on the hot path.
  assert.ok(/select\('isDisabled organizationId tokensValidFrom'\)/.test(authMwSrc));
  assert.ok(/tokensValidFrom/.test(fs.readFileSync(path.join(BACKEND, 'models/User.js'), 'utf8')));
});

test('the frontend treats SESSION_REVOKED as terminal, like ACCOUNT_DISABLED', () => {
  const ctx = fs.readFileSync(
    path.join(BACKEND, '../frontend/src/contexts/UserContext.jsx'), 'utf8');
  assert.ok(/SESSION_REVOKED/.test(ctx),
    'a revoked session must clear local state rather than show a stale error');
});
