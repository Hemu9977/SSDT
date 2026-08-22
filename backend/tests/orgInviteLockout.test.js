'use strict';

/**
 * accept-invite must honour the account-disabled lockout.
 *
 * This route verifies its OWN JWT rather than going through middleware/auth,
 * and it mints a fresh token on success — so it is the one place where a
 * disabled user could have walked straight back in. It also mutates
 * organizationId, which is exactly the state the auth middleware caches, so it
 * has to invalidate that cache too.
 *
 * Previously covered only by a static "every jwt.sign is preceded by a block
 * check" census, which proves ordering in the source and nothing about
 * behaviour. This executes the handler.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.RATE_LIMIT_ENABLED = 'false';

const state = { invite: null, org: null, user: null, blocked: false, invalidated: [] };

// ─── Stub every model the route touches, plus the auth middleware's check ────
const q = (get) => ({ select: () => q(get), lean: async () => get(), then: (r) => Promise.resolve(get()).then(r) });

require.cache[path.join(BACKEND, 'models/Invite.js')] = {
  id: 'i', filename: 'i', loaded: true,
  exports: {
    findOne: async () => state.invite,
    findOneAndUpdate: async () => state.invite,
    updateOne: async () => ({ modifiedCount: 1 }),
  },
};
require.cache[path.join(BACKEND, 'models/Organization.js')] = {
  id: 'o', filename: 'o', loaded: true,
  exports: {
    findById: (...a) => q(() => state.org),
    updateOne: async () => ({ modifiedCount: 1 }),
    find: () => q(() => []),
  },
};
require.cache[path.join(BACKEND, 'models/User.js')] = {
  id: 'u', filename: 'u', loaded: true,
  exports: {
    findOne: async () => state.user,
    findById: (...a) => q(() => state.user),
    countDocuments: async () => 1,
  },
};
// The route imports the real middleware for isPrincipalBlocked/invalidatePrincipal.
require.cache[path.join(BACKEND, 'middleware/auth.js')] = {
  id: 'a', filename: 'a', loaded: true,
  exports: Object.assign(
    function auth(req, res, next) { next(); },
    {
      isPrincipalBlocked: async () => state.blocked,
      invalidatePrincipal: (id) => state.invalidated.push(String(id)),
      invalidateAllPrincipals: () => {},
      identifyUser: (req, res, next) => next(),
    }
  ),
};

const router = require(path.join(BACKEND, 'routes/orgRoutes.js'));

function handlerFor(routePath) {
  const layer = router.stack.find((l) => l.route && l.route.path === routePath);
  assert.ok(layer, `route ${routePath} not registered`);
  return layer.route.stack[layer.route.stack.length - 1].handle;
}

async function acceptInvite({ token, body }) {
  let status = 200;
  let payload = null;
  const res = {
    status(c) { status = c; return this; },
    json(b) { payload = b; return this; },
  };
  const req = {
    body,
    headers: {},
    ip: '127.0.0.1',
    header: (h) => (h === 'Authorization' && token ? `Bearer ${token}` : undefined),
  };
  await handlerFor('/accept-invite')(req, res, () => {});
  return { status, body: payload };
}

function reset() {
  state.invite = {
    _id: 'inv-1',
    email: 'invitee@example.com',
    organizationId: 'org-1',
    role: 'member',
    status: 'pending',
    expiresAt: new Date(Date.now() + 86400000),
  };
  state.org = { _id: 'org-1', name: 'Acme', seatsUsed: 1, seatsAllowed: 5 };
  state.user = {
    _id: 'user-1', id: 'user-1',
    email: 'invitee@example.com',
    organizationId: null,
    role: 'member',
    systemRole: 'user',
    save: async () => {},
  };
  state.blocked = false;
  state.invalidated = [];
}

const tokenFor = (id) => jwt.sign({ user: { id } }, process.env.JWT_SECRET, { expiresIn: '7d' });

// ─────────────────────────────────────────────────────────────────────────────

test('a disabled user cannot consume an invite or be issued a token', async () => {
  reset();
  state.blocked = true;                       // admin has disabled this account

  const res = await acceptInvite({ token: tokenFor('user-1'), body: { token: 'invite-tok' } });

  assert.equal(res.status, 403, 'a locked-out account was let through');
  assert.equal(res.body.code, 'ACCOUNT_DISABLED');
  assert.ok(!res.body.token, 'a fresh JWT was minted for a disabled account');
});

test('an active user accepting an invite is issued a token', async () => {
  reset();
  const res = await acceptInvite({ token: tokenFor('user-1'), body: { token: 'invite-tok' } });

  assert.equal(res.status, 200, `unexpected ${res.status}: ${JSON.stringify(res.body)}`);
  assert.ok(res.body.token, 'no token returned on the happy path');
  // Same shape every other login path returns, so the client can route on role.
  assert.equal(res.body.user.systemRole, 'user');
});

test('joining an organization invalidates the cached auth state', async () => {
  reset();
  await acceptInvite({ token: tokenFor('user-1'), body: { token: 'invite-tok' } });

  // organizationId is part of what the auth middleware caches for up to 30s.
  // Without this the user could keep the pre-join verdict, and if the org they
  // joined is disabled they would not be blocked until the TTL lapsed.
  assert.ok(state.invalidated.includes('user-1'),
    'invalidatePrincipal was not called for the joining user');
});

test('the route still gates on the invite being addressed to this user', async () => {
  reset();
  state.user.email = 'someone-else@example.com';   // logged in as the wrong person

  const res = await acceptInvite({ token: tokenFor('user-1'), body: { token: 'invite-tok' } });

  assert.equal(res.status, 403);
  assert.ok(!res.body.token, 'a token was issued to the wrong recipient');
});

test('accept-invite is the only jwt.sign outside routes/auth.js', () => {
  // If a new token-issuing path appears elsewhere it needs its own block check;
  // this keeps that decision deliberate rather than accidental.
  const files = [];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === '.git' || e.name === 'tests') continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) files.push(p);
    }
  })(BACKEND);

  const issuers = files.filter((f) => /jwt\.sign\(/.test(fs.readFileSync(f, 'utf8')))
    .map((f) => path.relative(BACKEND, f).replace(/\\/g, '/'));

  assert.deepEqual(issuers.sort(), ['routes/auth.js', 'routes/orgRoutes.js']);
});
