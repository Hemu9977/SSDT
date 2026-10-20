// backend/scripts/grantSystemRole.js
//
// The only supported way to grant or remove a platform role (user | admin |
// superadmin) outside the dashboard — in particular to create a superadmin,
// which the dashboard cannot do. Replaces makeAdmin.js and transferAdmin.js.
//
// Usage:
//   node scripts/grantSystemRole.js <email> <user|admin|superadmin> --operator "<name>" --ticket <id>          (dry run)
//   node scripts/grantSystemRole.js <email> <user|admin|superadmin> --operator "<name>" --ticket <id> --apply  (writes)
//
// Rules:
//   - Dry run unless --apply. It prints the target database host first.
//   - The account must already exist, have a verified email, and not be disabled
//     (nor be in a disabled organization). Accounts are never created here, and
//     no password is ever set or copied.
//   - Refuses to remove the last reachable superadmin or the last administrator.
//   - Writes an AdminAuditLog row (actorType 'script', operator, ticket) BEFORE
//     the change; if that row cannot be written, nothing changes.
//   - Stamps tokensValidFrom, ending the account's existing sessions, so its next
//     sign-in gets a token with the new role's lifetime (8 h for administrators).
//
// Run it where the production secrets already are (a one-off ECS task using the
// backend task definition with a command override), not with a production
// MONGO_URI copied into a laptop's .env.

const ROLES = ['user', 'admin', 'superadmin'];
const ADMIN_ROLES = ['admin', 'superadmin'];

const normalizeEmail = (e) => String(e || '').toLowerCase().trim();

async function disabledOrgIds(Organization) {
  const rows = await Organization.find({ isDisabled: true }, { _id: 1 }).lean();
  return rows.map((o) => o._id);
}

async function countReachable(User, Organization, roles, excludeUserId) {
  const blocked = await disabledOrgIds(Organization);
  return User.countDocuments({
    _id: { $ne: excludeUserId },
    systemRole: { $in: roles },
    isDisabled: { $ne: true },
    $or: [
      { organizationId: null },
      { organizationId: { $exists: false } },
      { organizationId: { $nin: blocked } },
    ],
  });
}

/**
 * Work out what a grant would do, without writing anything.
 * @returns {Promise<{ok: false, reason: string} | {ok: true, user: object, from: string, to: string, noChange: boolean}>}
 */
async function planGrant({ User, Organization, email, role }) {
  if (!ROLES.includes(role)) return { ok: false, reason: 'invalid_role' };
  const user = await User.findOne({ email: normalizeEmail(email) })
    .select('email name systemRole isVerified isDisabled organizationId')
    .lean();
  if (!user) return { ok: false, reason: 'not_found' };

  const from = user.systemRole || 'user';
  if (from === role) return { ok: true, user, from, to: role, noChange: true };

  if (ADMIN_ROLES.includes(role)) {
    if (!user.isVerified) return { ok: false, reason: 'not_verified' };
    if (user.isDisabled) return { ok: false, reason: 'disabled' };
    if (user.organizationId) {
      const org = await Organization.findById(user.organizationId).select('isDisabled').lean();
      if (org && org.isDisabled) return { ok: false, reason: 'org_disabled' };
    }
  }

  if (from === 'superadmin' && role !== 'superadmin' &&
      (await countReachable(User, Organization, ['superadmin'], user._id)) === 0) {
    return { ok: false, reason: 'last_superadmin' };
  }
  if (ADMIN_ROLES.includes(from) && !ADMIN_ROLES.includes(role) &&
      (await countReachable(User, Organization, ADMIN_ROLES, user._id)) === 0) {
    return { ok: false, reason: 'last_admin' };
  }

  return { ok: true, user, from, to: role, noChange: false };
}

/** Apply a plan from planGrant(): audit row first (fail closed), then the change. */
async function applyGrant({ User, AdminAuditLog, plan, operator, ticket, now = new Date() }) {
  if (!operator || !ticket) throw new Error('operator and ticket are required');
  const { user, from, to } = plan;

  const entry = await AdminAuditLog.create({
    actorType: 'script',
    operator,
    ticket,
    action: 'user.role_change',
    targetType: 'user',
    targetId: user._id,
    targetLabel: user.email,
    before: { systemRole: from },
    result: 'pending',
  });

  try {
    // Conditional on the role we planned from, so a concurrent change is not overwritten.
    const fromFilter = from === 'user' ? { $in: ['user', null] } : from;
    const res = await User.updateOne(
      { _id: user._id, systemRole: fromFilter },
      { $set: { systemRole: to, tokensValidFrom: now } }
    );
    if (!res.matchedCount) throw new Error('the account changed since it was read; nothing was written');
  } catch (err) {
    await AdminAuditLog.updateOne(
      { _id: entry._id },
      { $set: { result: 'failure', errorCode: 'ADMIN_ACTION_FAILED', completedAt: new Date() } }
    );
    throw err;
  }

  await AdminAuditLog.updateOne(
    { _id: entry._id },
    { $set: { result: 'success', after: { systemRole: to }, completedAt: new Date() } }
  );
  return entry._id;
}

const REASONS = {
  invalid_role: 'role must be one of: user, admin, superadmin',
  not_found: 'no account with that email (accounts are never created by this script)',
  not_verified: 'the account has not verified its email address',
  disabled: 'the account is disabled',
  org_disabled: "the account's organization is disabled",
  last_superadmin: 'this is the last superadmin who can still sign in',
  last_admin: 'this is the last administrator who can still sign in',
};

function parseArgs(argv) {
  const args = { apply: false, operator: null, ticket: null, positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') args.apply = true;
    else if (a === '--operator') args.operator = argv[++i] || null;
    else if (a === '--ticket') args.ticket = argv[++i] || null;
    else args.positional.push(a);
  }
  return args;
}

async function main() {
  // Loaded here, not at module scope: tests import the functions below.
  require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
  const mongoose = require('mongoose');
  const User = require('../models/User');
  const Organization = require('../models/Organization');
  const AdminAuditLog = require('../models/AdminAuditLog');

  const { apply, operator, ticket, positional: [email, role] } = parseArgs(process.argv.slice(2));
  if (!email || !role || !operator || !ticket) {
    console.error('Usage: node scripts/grantSystemRole.js <email> <user|admin|superadmin> --operator "<name>" --ticket <id> [--apply]');
    process.exitCode = 1;
    return;
  }

  await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
  try {
    console.log(`Database: ${mongoose.connection.host} / ${mongoose.connection.name}`);
    const plan = await planGrant({ User, Organization, email, role });
    if (!plan.ok) {
      console.error(`Refused: ${REASONS[plan.reason] || plan.reason}`);
      process.exitCode = 2;
      return;
    }
    if (plan.noChange) {
      console.log(`${plan.user.email} already has systemRole ${plan.to}. Nothing to do.`);
      return;
    }
    console.log(`${plan.user.email}: systemRole ${plan.from} → ${plan.to} (operator: ${operator}, ticket: ${ticket})`);
    console.log('Existing sessions of this account will end.');
    if (!apply) {
      console.log('Dry run: nothing written. Re-run with --apply to make the change.');
      return;
    }
    const auditId = await applyGrant({ User, AdminAuditLog, plan, operator, ticket });
    console.log(`Done. Audit record ${auditId}.`);
  } catch (err) {
    console.error('Error:', err.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

if (require.main === module) main();

module.exports = { planGrant, applyGrant, parseArgs, ROLES };
