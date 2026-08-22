'use strict';

/**
 * Password-reset, OTP-resend and session-revocation tests.
 *
 * These EXECUTE the real route handlers. An earlier version of this file
 * asserted that the source text matched certain regexes, which proves a string
 * is present and nothing about what the code does — too weak for auth code.
 * The handlers are pulled off the Express router stack and invoked directly
 * with a stubbed model/email layer: no database, no SMTP, no AWS, no server.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');

// ─── Stub the model and email layers before the router requires them ─────────
const state = {
  user: null,          // what User.findOne resolves to
  lastQuery: null,     // the filter it was called with
  saved: null,         // snapshot of the doc at save() time
  otpEmails: [],
  resetEmails: [],
  emailThrows: false,
};

function makeUser(over = {}) {
  const u = {
    _id: 'user-1',
    email: 'target@example.com',
    password: 'OLD-BCRYPT-HASH',
    preferredLanguage: 'en',
    isDisabled: false,
    organizationId: null,
    save: async function () { state.saved = { ...this }; },
    ...over,
  };
  return u;
}

require.cache[path.join(BACKEND, 'models/User.js')] = {
  id: 'u', filename: 'u', loaded: true,
  exports: {
    findOne: async (q) => { state.lastQuery = q; return state.user; },
    findById: () => ({ select: () => ({ lean: async () => null }) }),
  },
};
require.cache[path.join(BACKEND, 'models/Organization.js')] = {
  id: 'o', filename: 'o', loaded: true,
  exports: { findById: () => ({ select: () => ({ lean: async () => null }) }) },
};
require.cache[path.join(BACKEND, 'services/emailService.js')] = {
  id: 'e', filename: 'e', loaded: true,
  exports: {
    generateOTP: () => '654321',
    sendOTPEmail: async (to, otp, lang) => {
      if (state.emailThrows) throw new Error('SES unavailable');
      state.otpEmails.push({ to, otp, lang });
    },
    sendResetPasswordEmail: async (to, token, lang) => {
      if (state.emailThrows) throw new Error('SES unavailable');
      state.resetEmails.push({ to, token, lang });
    },
  },
};

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.RATE_LIMIT_ENABLED = 'false';   // limiter becomes a pass-through

const router = require(path.join(BACKEND, 'routes/auth.js'));

/** Pull the terminal handler for a route off the router stack. */
function handlerFor(routePath) {
  const layer = router.stack.find((l) => l.route && l.route.path === routePath);
  assert.ok(layer, `route ${routePath} not registered`);
  return layer.route.stack[layer.route.stack.length - 1].handle;
}

/** Invoke a handler and capture what it responded with. */
async function call(routePath, body) {
  let status = 200;
  let payload = null;
  const res = {
    status(c) { status = c; return this; },
    json(b) { payload = b; return this; },
  };
  await handlerFor(routePath)({ body, headers: {}, ip: '127.0.0.1' }, res, () => {});
  return { status, body: payload };
}

function reset() {
  state.user = null;
  state.lastQuery = null;
  state.saved = null;
  state.otpEmails = [];
  state.resetEmails = [];
  state.emailThrows = false;
}

const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');

// ─────────────────────────────────────────────────────────────────────────────
// forgot-password
// ─────────────────────────────────────────────────────────────────────────────

test('forgot-password emails the RAW token but stores only its hash', async () => {
  reset();
  state.user = makeUser();
  const res = await call('/forgot-password', { email: 'target@example.com' });

  assert.equal(res.status, 200);
  assert.equal(state.resetEmails.length, 1, 'no reset email was sent');

  const emailed = state.resetEmails[0].token;
  assert.match(emailed, /^[0-9a-f]{64}$/, 'expected a 32-byte hex token');
  assert.equal(state.saved.resetPasswordToken, sha256(emailed),
    'the stored value must be the hash of the emailed token');
  assert.notEqual(state.saved.resetPasswordToken, emailed,
    'a database leak must not yield usable reset links');
});

test('forgot-password sets an expiry that matches the 1 hour the email promises', async () => {
  reset();
  state.user = makeUser();
  const before = Date.now();
  await call('/forgot-password', { email: 'target@example.com' });
  const ttl = state.saved.resetPasswordExpires.getTime() - before;
  assert.ok(ttl > 59 * 60 * 1000 && ttl <= 60 * 60 * 1000 + 1000, `ttl was ${ttl}ms`);
});

test('forgot-password answers identically for a known and an unknown address', async () => {
  reset();
  state.user = makeUser();
  const known = await call('/forgot-password', { email: 'target@example.com' });

  reset();
  state.user = null;                       // no such account
  const unknown = await call('/forgot-password', { email: 'nobody@example.com' });

  assert.deepEqual(unknown, known, 'the response reveals whether the account exists');
  assert.equal(state.resetEmails.length, 0, 'no email should be sent for an unknown address');
});

test('forgot-password still answers normally when the mail transport fails', async () => {
  reset();
  state.user = makeUser();
  state.emailThrows = true;                // SES down
  const res = await call('/forgot-password', { email: 'target@example.com' });
  assert.equal(res.status, 200, 'a send failure must not change the response');
  assert.equal(res.body.code, 'AUTH_RESET_EMAIL_SENT');
});

test('forgot-password does not issue a token for a disabled account', async () => {
  reset();
  state.user = makeUser({ isDisabled: true });
  const res = await call('/forgot-password', { email: 'target@example.com' });
  assert.equal(res.status, 200, 'still indistinguishable from the normal path');
  assert.equal(state.resetEmails.length, 0);
  assert.equal(state.saved, null, 'no reset token should be minted');
});

test('forgot-password rejects a malformed address before doing any work', async () => {
  reset();
  const res = await call('/forgot-password', { email: 'not-an-email' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'AUTH_EMAIL_INVALID');
  assert.equal(state.resetEmails.length, 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// reset-password
// ─────────────────────────────────────────────────────────────────────────────

test('reset-password looks the token up by hash, never by the raw value', async () => {
  reset();
  state.user = makeUser();
  await call('/reset-password', { token: 'raw-token-abc', password: 'longenough1' });

  assert.equal(state.lastQuery.resetPasswordToken, sha256('raw-token-abc'));
  assert.ok(state.lastQuery.resetPasswordExpires.$gt instanceof Date,
    'an expired token must not be accepted');
});

test('reset-password bcrypt-hashes the new password', async () => {
  reset();
  state.user = makeUser();
  await call('/reset-password', { token: 't', password: 'longenough1' });

  assert.notEqual(state.saved.password, 'longenough1', 'password stored in plaintext');
  assert.notEqual(state.saved.password, 'OLD-BCRYPT-HASH', 'password was not changed');
  assert.match(state.saved.password, /^\$2[aby]\$/, 'not a bcrypt hash');
});

test('reset-password consumes the token and stamps both timestamps', async () => {
  reset();
  state.user = makeUser();
  const res = await call('/reset-password', { token: 't', password: 'longenough1' });

  assert.equal(res.status, 200);
  assert.equal(state.saved.resetPasswordToken, undefined, 'link must be single-use');
  assert.equal(state.saved.resetPasswordExpires, undefined);
  // Login reads passwordResetAt to skip OTP for 24h; nothing wrote it before.
  assert.ok(state.saved.passwordResetAt instanceof Date);
  // And every token issued before now stops working.
  assert.ok(state.saved.tokensValidFrom instanceof Date);
});

test('reset-password rejects an unknown or expired token with one indistinguishable code', async () => {
  reset();
  state.user = null;                       // findOne matched nothing
  const res = await call('/reset-password', { token: 'whatever', password: 'longenough1' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'AUTH_RESET_TOKEN_INVALID');
});

test('reset-password validates input before touching the database', async () => {
  for (const body of [{ password: 'longenough1' }, { token: '', password: 'longenough1' }]) {
    reset();
    const res = await call('/reset-password', body);
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'AUTH_RESET_TOKEN_INVALID');
    assert.equal(state.lastQuery, null, 'an empty token must never reach the query');
  }

  reset();
  const short = await call('/reset-password', { token: 't', password: 'short' });
  assert.equal(short.status, 400);
  assert.equal(short.body.code, 'AUTH_PASSWORD_TOO_SHORT');
  assert.equal(state.saved, null);
});

// ─────────────────────────────────────────────────────────────────────────────
// resend-otp
// ─────────────────────────────────────────────────────────────────────────────

test('resend-otp regenerates and sends a code', async () => {
  reset();
  state.user = makeUser({ otp: 'OLD', otpExpires: new Date(0) });
  const before = Date.now();
  const res = await call('/resend-otp', { email: 'target@example.com' });

  assert.equal(res.status, 200);
  assert.equal(state.otpEmails.length, 1, 'the stub route never sent anything');
  assert.equal(state.saved.otp, '654321');
  assert.equal(state.otpEmails[0].otp, '654321', 'emailed code must match the stored one');
  const ttl = state.saved.otpExpires.getTime() - before;
  assert.ok(ttl > 9 * 60 * 1000 && ttl <= 10 * 60 * 1000 + 1000, `ttl was ${ttl}ms`);
});

test('resend-otp answers identically for an unknown address and sends nothing', async () => {
  reset();
  state.user = makeUser();
  const known = await call('/resend-otp', { email: 'target@example.com' });

  reset();
  state.user = null;
  const unknown = await call('/resend-otp', { email: 'nobody@example.com' });

  assert.deepEqual(unknown, known);
  assert.equal(state.otpEmails.length, 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// Session revocation
// ─────────────────────────────────────────────────────────────────────────────

test('isTokenRevoked does not lock out a token minted in the same second as the reset', () => {
  const { isTokenRevoked } = require(path.join(BACKEND, 'middleware/auth.js'));
  const S = 1_700_000_000;

  // The regression: jwt.sign floors iat to the second, so comparing
  // iat*1000 against a millisecond-precision cut-off rejected the very token
  // the reset was supposed to enable.
  for (const offsetMs of [0, 1, 500, 750, 999]) {
    assert.equal(
      isTokenRevoked({ tokensValidFrom: S * 1000 + offsetMs }, { iat: S }),
      false,
      `a token minted in the same second as a reset at .${offsetMs}ms was revoked`
    );
  }

  // Genuinely older tokens must still die.
  assert.equal(isTokenRevoked({ tokensValidFrom: S * 1000 + 750 }, { iat: S - 1 }), true);
  assert.equal(isTokenRevoked({ tokensValidFrom: S * 1000 + 750 }, { iat: S - 3600 }), true);
  // Later tokens and never-reset accounts are untouched.
  assert.equal(isTokenRevoked({ tokensValidFrom: S * 1000 + 750 }, { iat: S + 1 }), false);
  assert.equal(isTokenRevoked({ tokensValidFrom: null }, { iat: S }), false);
  // Malformed input must not throw.
  assert.equal(isTokenRevoked({ tokensValidFrom: S * 1000 }, {}), false);
  assert.equal(isTokenRevoked({ tokensValidFrom: S * 1000 }, null), false);
});

test('reset-password revocation takes effect immediately, not after the cache TTL', () => {
  const src = fs.readFileSync(path.join(BACKEND, 'routes/auth.js'), 'utf8');
  const at = src.indexOf("router.post('/reset-password'");
  const body = src.slice(at, src.indexOf('\n});', at));
  assert.match(body, /invalidatePrincipal\(user\._id\)/,
    'without this the revocation waits out the 30s auth cache');
});

// ─────────────────────────────────────────────────────────────────────────────
// Structural guards that cannot be expressed behaviourally
// ─────────────────────────────────────────────────────────────────────────────

test('the User model still has no pre-save hook', () => {
  // If one is ever added, /reset-password would double-hash the password —
  // it hashes explicitly because today nothing else does.
  const model = fs.readFileSync(path.join(BACKEND, 'models/User.js'), 'utf8');
  assert.ok(!/pre\(['"]save['"]/.test(model),
    'a pre-save hook now exists — the reset route must be re-checked for double hashing');
});

test('both email-sending routes sit behind the recipient-keyed limiter', () => {
  // Two handlers on the layer means limiter + route; one means unprotected.
  for (const p of ['/forgot-password', '/resend-otp']) {
    const layer = router.stack.find((l) => l.route && l.route.path === p);
    assert.equal(layer.route.stack.length, 2, `${p} is missing its limiter`);
  }
  const limiter = fs.readFileSync(path.join(BACKEND, 'middleware/rateLimiter.js'), 'utf8');
  assert.match(limiter, /email:\$\{email\}/,
    'the limiter must key on the recipient so one address cannot be mail-bombed');
});
