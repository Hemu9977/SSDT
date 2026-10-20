// backend/scripts/backfillLastLoginAt.js
// One-time data fix for User.lastLoginAt.
//
// The field used to default to Date.now, so every account that never signed in
// carried a "last login" equal to its creation time, and the admin dashboard
// showed it as a real sign-in. The default is now null and every login path
// writes the field. This script clears the values that were only ever the
// default: lastLoginAt within TOLERANCE_MS of createdAt (both were stamped at
// document creation). A real first login happens after OTP or Google sign-in,
// seconds or more later.
//
// Accounts whose login was never recorded by the old 24-hour post-reset path
// cannot be repaired — their last real sign-in is simply unknown.
//
// Dry run by default — it only reads and reports counts. With --apply it writes.
// Run against the intended database only; it uses MONGODB_URI / MONGO_URI.
//
// Usage: node scripts/backfillLastLoginAt.js [--apply]

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const mongoose = require('mongoose');
const User = require('../models/User');

const APPLY = process.argv.includes('--apply');
const TOLERANCE_MS = 2000;

async function run() {
  try {
    console.log(`🔌 Connecting to MongoDB... (${APPLY ? 'APPLY' : 'dry run'})`);
    await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
    console.log('✅ Connected.\n');

    // Server-side comparison of the two fields; returns ids only.
    const defaulted = await User.aggregate([
      { $match: { lastLoginAt: { $type: 'date' }, createdAt: { $type: 'date' } } },
      { $project: { gap: { $abs: { $subtract: ['$lastLoginAt', '$createdAt'] } } } },
      { $match: { gap: { $lte: TOLERANCE_MS } } },
      { $project: { _id: 1 } },
    ]);

    const total = await User.countDocuments({});
    console.log(`Users: ${total}`);
    console.log(`lastLoginAt equal to creation time (never signed in): ${defaulted.length}`);

    if (!APPLY) {
      console.log('\nDry run — nothing written. Re-run with --apply to clear these values.');
      return;
    }

    const res = await User.updateMany(
      { _id: { $in: defaulted.map((u) => u._id) } },
      { $set: { lastLoginAt: null } }
    );
    console.log(`\n✅ Cleared lastLoginAt on ${res.modifiedCount} user(s).`);
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

run();
