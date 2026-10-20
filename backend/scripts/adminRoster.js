// backend/scripts/adminRoster.js
//
// READ-ONLY. Lists who holds a platform role and, optionally, the state of one
// account — the check to run before granting a role with grantSystemRole.js.
// Writes nothing. Prints no password hashes, codes or tokens.
//
// Usage:
//   node scripts/adminRoster.js                       (all admin / superadmin holders)
//   node scripts/adminRoster.js --check <email>       (plus one account's state)
//
// As with grantSystemRole.js, run it as a one-off ECS task against production
// rather than copying the production MONGO_URI to a laptop.

const ADMIN_ROLES = ['admin', 'superadmin'];

/** Shape one account for display: state only, never credential material. */
async function describeAccount(user, Organization) {
  let orgDisabled = false;
  if (user.organizationId) {
    const org = await Organization.findById(user.organizationId).select('isDisabled').lean();
    orgDisabled = Boolean(org && org.isDisabled);
  }
  return {
    email: user.email,
    systemRole: user.systemRole || 'user',
    isVerified: Boolean(user.isVerified),
    isDisabled: Boolean(user.isDisabled),
    orgDisabled,
    canSignIn: !user.isDisabled && !orgDisabled,
    googleLinked: Boolean(user.googleId),
    lastLoginAt: user.lastLoginAt || null,
  };
}

const FIELDS = 'email systemRole isVerified isDisabled organizationId googleId lastLoginAt';

async function buildRoster({ User, Organization, checkEmail = null }) {
  const holders = await User.find({ systemRole: { $in: ADMIN_ROLES } }).select(FIELDS).lean();
  const admins = [];
  for (const u of holders) admins.push(await describeAccount(u, Organization));

  let checked = null;
  if (checkEmail) {
    const u = await User.findOne({ email: String(checkEmail).toLowerCase().trim() }).select(FIELDS).lean();
    checked = u ? await describeAccount(u, Organization) : { email: checkEmail, exists: false };
  }

  const reachable = (role) => admins.filter((a) => a.systemRole === role && a.canSignIn).length;
  return {
    counts: { superadmin: reachable('superadmin'), admin: reachable('admin'), totalHolders: admins.length },
    admins,
    checked,
  };
}

async function main() {
  // Loaded here, not at module scope: tests import the functions below.
  require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
  const mongoose = require('mongoose');
  const User = require('../models/User');
  const Organization = require('../models/Organization');

  const argv = process.argv.slice(2);
  const i = argv.indexOf('--check');
  const checkEmail = i >= 0 ? argv[i + 1] : null;

  await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
  try {
    console.log(`Database: ${mongoose.connection.host} / ${mongoose.connection.name} (read-only)`);
    const roster = await buildRoster({ User, Organization, checkEmail });
    console.log(JSON.stringify(roster, null, 2));
  } catch (err) {
    console.error('Error:', err.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

if (require.main === module) main();

module.exports = { buildRoster };
