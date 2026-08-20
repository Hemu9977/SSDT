'use strict';

/**
 * Static invariants for the admin API and auth middleware.
 *
 * These began as throwaway verification scripts in a scratch directory during
 * the admin-dashboard review. That directory was wiped mid-task and took every
 * assertion with it, which is the reason they now live in the repo: a check
 * that only exists while one session is open cannot stop a regression later.
 *
 * They are deliberately static/behavioural — no database, no network, no
 * server — so they run anywhere `npm test` runs, with no credentials.
 *
 * Run with: node --test backend/tests/adminApiInvariants.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const REPO = path.join(BACKEND, '..');
const read = (p) => fs.readFileSync(p, 'utf8');
const adminSrc = read(path.join(BACKEND, 'routes/admin.js'));

// ─────────────────────────────────────────────────────────────────────────────
// 1. Query projections — over-fetching regressions
// ─────────────────────────────────────────────────────────────────────────────

test('GET /scans does not select the heavy scan payload columns', () => {
  const handler = adminSrc.slice(adminSrc.indexOf("router.get('/scans'"));
  const body = handler.slice(0, handler.indexOf('\n});'));
  const select = body.match(/\.select\('([^']+)'\)/);
  assert.ok(select, 'expected an explicit projection');
  for (const heavy of ['zapResult', 'webCheckResult']) {
    assert.ok(!select[1].includes(heavy),
      `${heavy} is an untyped Object column holding a whole scan payload and is ` +
      `never rendered by AdminScans.jsx — selecting it ships it to the browser`);
  }
});

test('every list query in admin.js has an explicit projection', () => {
  const lines = adminSrc.split('\n');
  const unprojected = [];
  lines.forEach((line, i) => {
    // Only list queries. findById/findOne feed mutation handlers that need a
    // full document to call .save(), so they are correctly unprojected.
    if (!/\b(User|Organization|ScanResult)\.find\(/.test(line)) return;
    // Scan forward to the end of the chain rather than a fixed line count —
    // an explanatory comment between .limit() and .select() is normal here.
    const chainEnd = lines.slice(i).findIndex((l) => /\.lean\(\)|;\s*$/.test(l));
    const window = lines.slice(i, i + (chainEnd === -1 ? 12 : chainEnd + 1)).join(' ');
    const projected = /\.select\(/.test(window) || /,\s*\{[^}]*:\s*1/.test(window);
    if (!projected) unprojected.push(`${i + 1}: ${line.trim()}`);
  });
  assert.deepEqual(unprojected, [], `unprojected list queries:\n  ${unprojected.join('\n  ')}`);
});

test('no Stripe identifier is sent to the browser by the organizations list', () => {
  const handler = adminSrc.slice(adminSrc.indexOf("router.get('/organizations'"));
  const body = handler.slice(0, handler.indexOf('\n});'));
  assert.ok(/hasSubscription: Boolean\(stripeSubscriptionId\)/.test(body),
    'expected a derived boolean rather than the raw identifier');
  assert.ok(/\(\{ stripeSubscriptionId, \.\.\.o \}\)/.test(body),
    'stripeSubscriptionId must be destructured out, not spread into the response');
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Search input reaches $regex escaped
// ─────────────────────────────────────────────────────────────────────────────

test('escapeRegex neutralises regex metacharacters without breaking literal search', () => {
  const line = adminSrc.split('\n').find((l) => l.startsWith('const escapeRegex'));
  assert.ok(line, 'escapeRegex helper is missing');
  const escapeRegex = new Function(`${line}; return escapeRegex;`)();
  const BS = String.fromCharCode(92);

  assert.equal(escapeRegex('a.b'), `a${BS}.b`);
  assert.equal(escapeRegex('a(b'), `a${BS}(b`);
  assert.equal(escapeRegex(BS), BS + BS);
  assert.equal(escapeRegex('plain text'), 'plain text');

  // An unbalanced paren used to reach RegExp raw and 500 the endpoint.
  assert.doesNotThrow(() => new RegExp(escapeRegex('(')));
  assert.doesNotThrow(() => new RegExp(escapeRegex(BS)));

  // Escaping must not break ordinary substring search.
  assert.ok(new RegExp(escapeRegex('a.b'), 'i').test('xxa.bxx'));
  assert.ok(!new RegExp(escapeRegex('a.b'), 'i').test('axb'));

  // A catastrophic-backtracking payload becomes an inert literal.
  const started = Date.now();
  new RegExp(escapeRegex('(a+)+$')).test('a'.repeat(60) + 'X');
  assert.ok(Date.now() - started < 100, 'ReDoS payload was not neutralised');
});

test('both admin search filters escape their input before $regex', () => {
  const regexUses = adminSrc.match(/\$regex:\s*([A-Za-z(]+)/g) || [];
  assert.ok(regexUses.length > 0, 'expected at least one $regex use');
  for (const use of regexUses) {
    assert.ok(use.includes('escapeRegex'), `unescaped user input reaches $regex: ${use}`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Privilege hierarchy — an admin must never be able to mint admin rights
// ─────────────────────────────────────────────────────────────────────────────

test('only a superadmin can grant, revoke, or act on an administrator', () => {
  const rolesLine = adminSrc.split('\n').find((l) => l.startsWith('const ADMIN_CAPABLE_ROLES'));
  const holdsLine = adminSrc.split('\n').find((l) => l.startsWith('const holdsAdminRole'));
  assert.ok(rolesLine && holdsLine, 'hierarchy helpers are missing');

  const holdsAdminRole = new Function(`${rolesLine}\n${holdsLine}\nreturn holdsAdminRole;`)();
  const ADMIN_CAPABLE_ROLES = new Function(`${rolesLine}\nreturn ADMIN_CAPABLE_ROLES;`)();

  // Mirrors the guards as written in PATCH /users/:id and the delete handlers.
  const roleBlocked = (caller, target, newRole) =>
    caller.systemRole !== 'superadmin' &&
    (holdsAdminRole(target) || ADMIN_CAPABLE_ROLES.includes(newRole));
  const actBlocked = (caller, target) =>
    caller.systemRole !== 'superadmin' && holdsAdminRole(target);

  const SA = { systemRole: 'superadmin' };
  const AD = { systemRole: 'admin' };
  const US = { systemRole: 'user' };

  assert.equal(roleBlocked(AD, US, 'admin'), true, 'admin must not promote to admin');
  assert.equal(roleBlocked(AD, US, 'superadmin'), true, 'admin must not promote to superadmin');
  assert.equal(roleBlocked(AD, SA, 'user'), true, 'admin must not demote a superadmin');
  assert.equal(roleBlocked(AD, AD, 'user'), true, 'admin must not demote another admin');
  assert.equal(roleBlocked(AD, US, 'user'), false, 'admin may still manage ordinary users');
  assert.equal(roleBlocked(SA, US, 'superadmin'), false);
  assert.equal(actBlocked(AD, SA), true, 'admin must not disable/delete a superadmin');
  assert.equal(actBlocked(AD, US), false);
  assert.equal(actBlocked(SA, AD), false);

  // Exhaustive: no admin-initiated role change may ever yield admin rights.
  let escalations = 0;
  for (const target of [US, AD, SA]) {
    for (const newRole of ['user', 'admin', 'superadmin']) {
      if (!roleBlocked(AD, target, newRole) && ADMIN_CAPABLE_ROLES.includes(newRole)) escalations++;
    }
  }
  assert.equal(escalations, 0, 'an admin has a path to create admin rights');
});

test('disabling an organization cannot orphan the platform', () => {
  const handler = adminSrc.slice(adminSrc.indexOf("router.patch('/organizations/:id'"));
  const body = handler.slice(0, handler.indexOf('\n});'));
  assert.ok(/adminsRemainAfterOrgDisable/.test(body), 'org disable is not gated');
  assert.ok(/ADMIN_LAST_ADMIN_ORG/.test(body), 'refusal must carry a translatable code');

  const helper = adminSrc.slice(adminSrc.indexOf('const adminsRemainAfterOrgDisable'));
  const helperBody = helper.slice(0, helper.indexOf('\n};'));
  assert.ok(/systemRole: \{ \$in: ADMIN_CAPABLE_ROLES \}/.test(helperBody));
  assert.ok(/isDisabled: \{ \$ne: true \}/.test(helperBody));
  assert.ok(/\$nin: blockedOrgIds/.test(helperBody),
    'must exclude the target org AND already-disabled orgs');
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Error responses are machine-readable (so the UI can translate them)
// ─────────────────────────────────────────────────────────────────────────────

test('every admin error response carries a code', () => {
  const offenders = adminSrc
    .split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /error: '/.test(l) && !/code: '/.test(l))
    // A multi-line response object may carry its code on the previous line.
    .filter(([n]) => !/code: '/.test(adminSrc.split('\n')[n - 2] || ''));
  assert.deepEqual(offenders.map(([n, l]) => `${n}: ${l.trim()}`), []);
});

test('every backend error code has a UI mapping and a translation in both locales', () => {
  const backend = adminSrc
    + read(path.join(BACKEND, 'middleware/adminAuth.js'))
    + read(path.join(BACKEND, 'middleware/auth.js'));
  const emitted = [...new Set([...backend.matchAll(/code:\s*'([A-Z_]+)'/g)].map((m) => m[1]))];
  assert.ok(emitted.length > 10, `expected a real set of codes, saw ${emitted.length}`);

  const labels = read(path.join(REPO, 'frontend/src/pages/Admin/adminLabels.js'));
  const errBlock = labels.slice(labels.indexOf('const ERROR_KEYS'));
  const mapped = Object.fromEntries(
    [...errBlock.matchAll(/([A-Z_]+):\s*'([A-Za-z0-9_]+)'/g)].map((m) => [m[1], m[2]])
  );

  const unmapped = emitted.filter((c) => !(c in mapped));
  assert.deepEqual(unmapped, [], `codes with no UI mapping: ${unmapped.join(', ')}`);

  const en = read(path.join(REPO, 'frontend/src/locales/en.js'));
  const ja = read(path.join(REPO, 'frontend/src/locales/ja.js'));
  for (const key of new Set(Object.values(mapped))) {
    assert.ok(en.includes(`${key}:`), `${key} missing from en.js`);
    assert.ok(ja.includes(`${key}:`), `${key} missing from ja.js`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Token issuance and the account-disabled lockout
// ─────────────────────────────────────────────────────────────────────────────

function backendJsFiles() {
  const out = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name.endsWith('.js')) out.push(p);
    }
  })(BACKEND);
  return out;
}

test('every jwt.sign is preceded by an account-blocked check', () => {
  const GATE = /isAccountBlocked|isPrincipalBlocked/;
  const ungated = [];
  for (const file of backendJsFiles()) {
    const lines = read(file).split('\n');
    lines.forEach((line, i) => {
      if (!/jwt\.sign\(/.test(line)) return;
      const before = lines.slice(0, i + 1).join('\n');
      if (!GATE.test(before)) ungated.push(`${path.relative(BACKEND, file)}:${i + 1}`);
    });
  }
  assert.deepEqual(ungated, [], `token issued without a block check: ${ungated.join(', ')}`);
});

test('every independent jwt.verify also checks disabled state', () => {
  const middleware = path.join('middleware', 'auth.js');
  const ungated = [];
  for (const file of backendJsFiles()) {
    const rel = path.relative(BACKEND, file);
    if (rel === middleware) continue; // this IS the enforcement point
    const src = read(file);
    if (!/jwt\.verify\(/.test(src)) continue;
    if (!/isDisabled|isPrincipalBlocked|isAccountBlocked/.test(src)) ungated.push(rel);
  }
  assert.deepEqual(ungated, [],
    `these verify a JWT without the disabled check, bypassing the lockout: ${ungated.join(', ')}`);
});

test('the admin mount keys its rate limiter per user, not per IP', () => {
  const server = read(path.join(BACKEND, 'server.js'));
  const mount = server.split('\n').find((l) => /app\.use\('\/api\/admin'/.test(l)) || '';
  assert.ok(/identifyUser/.test(mount),
    'without identifyUser the limiter falls back to req.ip and every admin ' +
    'behind one egress IP shares a single quota');
});

test('auth middleware exports its cache invalidators and is async', () => {
  const src = read(path.join(BACKEND, 'middleware/auth.js'));
  assert.ok(/async function auth\(/.test(src), 'auth must be async to await the check');
  assert.ok(/module\.exports\.invalidatePrincipal/.test(src));
  assert.ok(/module\.exports\.invalidateAllPrincipals/.test(src));
  assert.ok(/module\.exports\.isPrincipalBlocked/.test(src),
    'the socket handshake reuses this rather than reimplementing the rule');
  assert.ok(/for \(const \[key, entry\] of principalCache\)/.test(src),
    'expired cache entries must be swept or the Map grows for the life of the task');
});

test('every handler that revokes access also invalidates the cache and cuts realtime', () => {
  const mutations = adminSrc.split(/router\.(?=(?:patch|delete|post)\()/).slice(1);
  const missing = [];
  for (const block of mutations) {
    const signature = block.slice(0, block.indexOf('\n'));
    const touchesCachedState =
      /\.isDisabled\s*=/.test(block) ||
      /organizationId\s*=\s*null/.test(block) ||
      /User\.deleteOne|Organization\.deleteOne/.test(block);
    if (!touchesCachedState) continue;
    if (!/invalidatePrincipal|invalidateAllPrincipals/.test(block)) {
      missing.push(`no cache invalidation: ${signature}`);
    }
  }
  assert.deepEqual(missing, []);

  const notif = read(path.join(BACKEND, 'services/notificationService.js'));
  assert.ok(/io\.use\(async \(socket, next\)/.test(notif), 'socket handshake must be async');
  assert.ok(/isPrincipalBlocked/.test(notif), 'handshake must apply the disabled check');
  assert.ok(/function disconnectUser/.test(notif), 'live sockets must be evictable');
});
