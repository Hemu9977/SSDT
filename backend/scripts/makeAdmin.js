// backend/scripts/makeAdmin.js
// Usage: node scripts/makeAdmin.js <email> [superadmin]
// Grants platform-level admin (or superadmin) access to a user by email.
// This is independent from organization-level roles (owner/admin/member).
//
// Examples:
//   node scripts/makeAdmin.js admin@example.com
//   node scripts/makeAdmin.js admin@example.com superadmin

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const mongoose = require('mongoose');
const User = require('../models/User');

const [email, roleArg] = process.argv.slice(2);
const role = roleArg === 'superadmin' ? 'superadmin' : 'admin';

if (!email) {
  console.error('❌ Usage: node scripts/makeAdmin.js <email> [superadmin]');
  process.exit(1);
}

async function run() {
  try {
    console.log(`🔌 Connecting to MongoDB...`);
    await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
    console.log('✅ Connected.');

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      console.error(`❌ User with email "${email}" not found.`);
      process.exit(1);
    }

    const oldRole = user.systemRole;
    user.systemRole = role;
    await user.save();

    console.log(`✅ Successfully updated "${email}"`);
    console.log(`   systemRole: ${oldRole} → ${role}`);
    console.log(`\n💡 This user can now access /admin in the dashboard.`);
  } catch (err) {
    console.error('❌ Error:', err.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

run();
