const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const Organization = require('../models/Organization');

// Backfills a scanCredits batch for legacy pure-trial orgs (billingCycle
// 'onetime', oneTimeRemainingScans > 0) so they keep working under the new
// subscription-first/credit-fallback quota logic, which reads live
// scanCredits batches rather than the bare oneTimeRemainingScans scalar.
//
// Defaults to a dry run. Pass --apply to actually write.
// Idempotent: orgs that already have a scanCredits batch are skipped, so
// re-running after --apply finds zero candidates.
async function migrate({ dryRun = true } = {}) {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to DB');

    const candidates = await Organization.find({
      billingCycle: 'onetime',
      oneTimeRemainingScans: { $gt: 0 },
      $or: [{ scanCredits: { $exists: false } }, { scanCredits: { $size: 0 } }]
    });

    console.log(`Found ${candidates.length} legacy one-time orgs to migrate.`);

    if (dryRun) {
      candidates.forEach(o => {
        console.log(`  [dry-run] Org ${o._id}: ${o.oneTimeRemainingScans} scans, expiresAt=${o.expiresAt}`);
      });
      console.log('Dry run complete. Re-run with --apply to write changes.');
      process.exit(0);
    }

    for (const org of candidates) {
      const batch = {
        source: `${org.planType || 'trial1'}_onetime`,
        scansTotal: org.oneTimeRemainingScans,
        scansRemaining: org.oneTimeRemainingScans,
        purchasedAt: org.createdAt || new Date(),
        expiresAt: org.expiresAt || new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
        stripeCheckoutSessionId: org.stripeCheckoutSessionId || null,
        vulnerabilityAccessLevel: org.planType === 'trial2' ? 'all' : 'critical-high',
        source_type: 'migration'
      };

      await Organization.updateOne({ _id: org._id }, { $push: { scanCredits: batch } });
      console.log(`  Migrated Org ${org._id}: +${batch.scansRemaining} scans, expires ${batch.expiresAt}`);
    }

    console.log('Migration complete.');
    process.exit(0);
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
}

const dryRun = !process.argv.includes('--apply');
migrate({ dryRun });
