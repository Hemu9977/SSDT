'use strict';

/**
 * N3 — platform roles are granted only by scripts/grantSystemRole.js, which
 * refuses unverified/disabled accounts and the removal of the last superadmin,
 * writes an audit row before the change (fail closed), ends the account's old
 * sessions, and never touches a password. scripts/adminRoster.js reads only.
 * The two unsafe scripts it replaced must stay gone.
 *
 * Run with: node --test backend/tests/grantSystemRole.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeModel, norm } = require('./support/fakeMongo');

const BACKEND = path.join(__dirname, '..');
const { planGrant, applyGrant, parseArgs } = require(path.join(BACKEND, 'scripts/grantSystemRole.js'));
const { buildRoster } = require(path.join(BACKEND, 'scripts/adminRoster.js'));

const Organization = makeModel('Organization', { defaults: () => ({ isDisabled: false }) });
const User = makeModel('User', {
  defaults: () => ({ systemRole: 'user', isDisabled: false, isVerified: true, organizationId: null, password: 'BCRYPT-HASH' }),
});
const AdminAuditLog = makeModel('AdminAuditLog');

function reset() { [Organization, User, AdminAuditLog].forEach((m) => m._reset()); }
const grant = async (email, role, opts = {}) => {
  const plan = await planGrant({ User, Organization, email, role });
  if (!plan.ok || plan.noChange) return { plan };
  const auditId = await applyGrant({ User, AdminAuditLog, plan, operator: 'Ops', ticket: 'CHG-7', ...opts });
  return { plan, auditId };
};

test('grants superadmin to a verified account: audited, sessions ended, password untouched', async () => {
  reset();
  const u = User._insert({ email: 'fortexa@aevus.jp' });
  const { plan, auditId } = await grant('  Fortexa@Aevus.JP ', 'superadmin');
  assert.equal(plan.ok, true);

  const after = User._get(u._id);
  assert.equal(after.systemRole, 'superadmin');
  assert.ok(after.tokensValidFrom instanceof Date, 'existing sessions must end');
  assert.equal(after.password, 'BCRYPT-HASH', 'the script never sets or copies a password');

  const row = norm(AdminAuditLog._get(auditId));
  assert.deepEqual(
    [row.actorType, row.operator, row.ticket, row.action, row.result, row.before.systemRole, row.after.systemRole],
    ['script', 'Ops', 'CHG-7', 'user.role_change', 'success', 'user', 'superadmin']
  );
});

test('dry run (plan only) writes nothing', async () => {
  reset();
  const u = User._insert({ email: 'a@example.com' });
  const plan = await planGrant({ User, Organization, email: 'a@example.com', role: 'admin' });
  assert.equal(plan.ok, true);
  assert.equal(User._get(u._id).systemRole, 'user');
  assert.equal(AdminAuditLog._store.length, 0);
});

test('refuses unknown, unverified, disabled and org-disabled accounts, and bad roles', async () => {
  reset();
  const org = Organization._insert({ isDisabled: true });
  User._insert({ email: 'unverified@example.com', isVerified: false });
  User._insert({ email: 'disabled@example.com', isDisabled: true });
  User._insert({ email: 'inlocked@example.com', organizationId: org._id });
  for (const [email, role, reason] of [
    ['nobody@example.com', 'admin', 'not_found'],
    ['unverified@example.com', 'superadmin', 'not_verified'],
    ['disabled@example.com', 'admin', 'disabled'],
    ['inlocked@example.com', 'admin', 'org_disabled'],
    ['unverified@example.com', 'root', 'invalid_role'],
  ]) {
    const plan = await planGrant({ User, Organization, email, role });
    assert.deepEqual([plan.ok, plan.reason], [false, reason], email);
  }
  assert.equal(AdminAuditLog._store.length, 0);
});

test('refuses to remove the last reachable superadmin; plain admins do not count', async () => {
  reset();
  const locked = Organization._insert({ isDisabled: true });
  User._insert({ email: 'sa@example.com', systemRole: 'superadmin' });
  User._insert({ email: 'stranded@example.com', systemRole: 'superadmin', organizationId: locked._id });
  User._insert({ email: 'plain@example.com', systemRole: 'admin' });

  const plan = await planGrant({ User, Organization, email: 'sa@example.com', role: 'admin' });
  assert.deepEqual([plan.ok, plan.reason], [false, 'last_superadmin']);

  User._insert({ email: 'sa2@example.com', systemRole: 'superadmin' });
  const ok = await planGrant({ User, Organization, email: 'sa@example.com', role: 'admin' });
  assert.equal(ok.ok, true);
});

test('if the audit row cannot be written, the role is not changed', async () => {
  reset();
  const u = User._insert({ email: 'a@example.com' });
  AdminAuditLog._failures.add('create');
  await assert.rejects(grant('a@example.com', 'admin'));
  assert.equal(User._get(u._id).systemRole, 'user');
});

test('operator and ticket are required to apply', async () => {
  reset();
  User._insert({ email: 'a@example.com' });
  const plan = await planGrant({ User, Organization, email: 'a@example.com', role: 'admin' });
  await assert.rejects(applyGrant({ User, AdminAuditLog, plan, operator: null, ticket: 'X' }));
  const args = parseArgs(['a@example.com', 'admin', '--operator', 'Ops', '--ticket', 'CHG-1']);
  assert.deepEqual([args.apply, args.operator, args.ticket, ...args.positional], [false, 'Ops', 'CHG-1', 'a@example.com', 'admin']);
});

test('no change when the account already holds the role', async () => {
  reset();
  User._insert({ email: 'a@example.com', systemRole: 'admin' });
  const { plan } = await grant('a@example.com', 'admin');
  assert.equal(plan.noChange, true);
  assert.equal(AdminAuditLog._store.length, 0);
});

test('roster reports reachable holders and one account, without credential fields', async () => {
  reset();
  const locked = Organization._insert({ isDisabled: true });
  User._insert({ email: 'sa@example.com', systemRole: 'superadmin', googleId: 'g-1' });
  User._insert({ email: 'stranded@example.com', systemRole: 'superadmin', organizationId: locked._id });
  User._insert({ email: 'plain@example.com', systemRole: 'admin', isDisabled: true });
  User._insert({ email: 'fortexa@aevus.jp', isVerified: false });

  const roster = await buildRoster({ User, Organization, checkEmail: 'fortexa@aevus.jp' });
  assert.deepEqual(roster.counts, { superadmin: 1, admin: 0, totalHolders: 3 });
  assert.deepEqual(
    [roster.checked.email, roster.checked.systemRole, roster.checked.isVerified, roster.checked.canSignIn],
    ['fortexa@aevus.jp', 'user', false, true]
  );
  const text = JSON.stringify(roster);
  assert.equal(/BCRYPT|password|otp/i.test(text), false, 'no credential material in the output');
});

test('the unsafe scripts stay deleted, and no script copies a password hash', () => {
  const dir = path.join(BACKEND, 'scripts');
  assert.equal(fs.existsSync(path.join(dir, 'transferAdmin.js')), false);
  assert.equal(fs.existsSync(path.join(dir, 'makeAdmin.js')), false);
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.js'))) {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.equal(/\$set:\s*\{[^}]*password\s*:/.test(src), false, `${f} writes a password`);
  }
});
