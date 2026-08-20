// backend/scripts/backfillSystemRole.js
// One-time migration: sets systemRole = 'user' on any User document that
// predates the systemRole schema field. Mongoose schema defaults are only
// applied when a document is hydrated by the ODM — they are never written
// back into documents that already exist in MongoDB, and .lean() queries
// (used by the admin API for performance) bypass Mongoose's default
// injection entirely. Without this backfill, those documents return
// `systemRole: undefined` over the API.
//
// Usage: node scripts/backfillSystemRole.js

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const mongoose = require('mongoose');

async function run() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
    console.log('✅ Connected.');

    const users = mongoose.connection.db.collection('users');
    const before = await users.countDocuments({ systemRole: { $exists: false } });
    console.log(`📋 Users missing systemRole: ${before}`);

    if (before === 0) {
      console.log('✅ Nothing to backfill.');
      return;
    }

    const result = await users.updateMany(
      { systemRole: { $exists: false } },
      { $set: { systemRole: 'user' } }
    );

    console.log(`✅ Backfilled ${result.modifiedCount} user document(s) with systemRole: 'user'.`);
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

run();
