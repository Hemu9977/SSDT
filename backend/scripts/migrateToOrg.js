const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const User = require('../models/User');
const Organization = require('../models/Organization');
const ScanResult = require('../models/ScanResult');

async function migrate() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to DB');

    const users = await User.find({ organizationId: null });
    console.log(`Found ${users.length} users to migrate`);

    const PLAN_LIMITS = {
      light: 3,
      basic: 5,
      pro: 10
    };

    const PLAN_SEATS = {
      light: 1,
      basic: 3,
      pro: 5
    };

    for (let user of users) {
      if (user.organizationId) {
        console.log(`Skipping user ${user.email} - already migrated`);
        continue;
      }
      
      let limit = 0;
      let seats = 1;
      
      if (user.planType && PLAN_LIMITS[user.planType]) {
        limit = PLAN_LIMITS[user.planType];
        seats = PLAN_SEATS[user.planType];
      }

      if (user.billingCycle === 'onetime') {
        seats = 1;
      }

      const org = new Organization({
        name: `${user.name}'s Organization`,
        ownerId: user._id,
        planType: user.planType,
        billingCycle: user.billingCycle,
        subscriptionStatus: user.subscriptionStatus,
        seatsAllowed: seats,
        seatsUsed: 1,
        scanLimit: limit,
        scansUsed: 0,
        oneTimeRemainingScans: user.oneTimeRemainingScans || 0,
        stripeSubscriptionId: user.stripeSubscriptionId,
        expiresAt: user.proExpiresAt,
        lastScanReset: user.lastResetDate,
        createdAt: user.createdAt
      });

      await org.save();

      user.organizationId = org._id;
      user.role = 'owner';
      await user.save();

      console.log(`Migrated user ${user.email} -> Org ${org._id}`);
      
      // Optional: Backfill ScanResults
      await ScanResult.updateMany(
        { userId: user._id, organizationId: { $exists: false } },
        { $set: { organizationId: org._id } }
      );
    }

    console.log('Migration complete');
    process.exit(0);
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
}

migrate();
