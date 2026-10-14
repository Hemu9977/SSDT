// backend/scripts/backfillSubscriptionIds.js
// Pre-deploy check for the subscription lifecycle (services/subscriptionLifecycle.js).
//
// Every subscription webhook now finds its organization by
// Organization.stripeSubscriptionId — the old fallback through the paying user's
// stripeCustomerId is gone, because it let stale events overwrite newer plans.
// So every org on a recurring plan must carry its subscription id, or Stripe's
// renewals and cancellations will never reach it. This script:
//
//   1. reports subscription ids shared by more than one org (they would also stop
//      the new unique index on stripeSubscriptionId from building);
//   2. finds recurring orgs with no stripeSubscriptionId and looks the subscription
//      up through the owner's Stripe customer;
//   3. finds orgs whose stored period has passed or was never recorded;
//   4. reports legacy User-level stripeSubscriptionIds whose org has none.
//
// Dry run by default — it only reads. With --apply it writes the ids it found
// (only where exactly one live subscription matches and no other org uses it) and
// re-reads every affected subscription from Stripe through reconcileById.
//
// Usage: node scripts/backfillSubscriptionIds.js [--apply]

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const mongoose = require('mongoose');
const Organization = require('../models/Organization');
const User = require('../models/User');
const { reconcileById, ENDED_STATUSES } = require('../services/subscriptionLifecycle');

const APPLY = process.argv.includes('--apply');
const RECURRING = ['monthly', 'annual'];
const PAID_STATUSES = ['active', 'trialing', 'past_due'];

async function run() {
  const stripe = require('../config/stripe');
  let problems = 0;

  try {
    console.log(`🔌 Connecting to MongoDB... (${APPLY ? 'APPLY' : 'dry run'})`);
    await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
    console.log('✅ Connected.\n');

    // ── 1. Duplicate subscription ids ──────────────────────────────────────────
    const dupes = await Organization.aggregate([
      { $match: { stripeSubscriptionId: { $type: 'string' } } },
      { $group: { _id: '$stripeSubscriptionId', orgs: { $push: '$_id' }, n: { $sum: 1 } } },
      { $match: { n: { $gt: 1 } } }
    ]);
    console.log(`📋 Subscription ids shared by several orgs: ${dupes.length}`);
    for (const d of dupes) {
      problems++;
      console.log(`   ⚠️  ${d._id} → orgs ${d.orgs.join(', ')} (resolve by hand; not touched)`);
    }

    // ── 2. Recurring orgs without a subscription id ────────────────────────────
    const missing = await Organization.find({
      billingCycle: { $in: RECURRING },
      subscriptionStatus: { $in: PAID_STATUSES },
      $or: [{ stripeSubscriptionId: null }, { stripeSubscriptionId: { $exists: false } }]
    }).select('_id name ownerId planType billingCycle subscriptionStatus');
    console.log(`\n📋 Recurring orgs with no stripeSubscriptionId: ${missing.length}`);

    for (const org of missing) {
      const owner = await User.findById(org.ownerId).select('email stripeCustomerId');
      if (!owner || !owner.stripeCustomerId) {
        problems++;
        console.log(`   ⚠️  org ${org._id} (${org.name}): owner has no Stripe customer — cannot resolve`);
        continue;
      }
      const subs = await stripe.subscriptions.list({ customer: owner.stripeCustomerId, status: 'all', limit: 20 });
      const live = subs.data.filter(s => !ENDED_STATUSES.includes(s.status));
      if (live.length !== 1) {
        problems++;
        console.log(`   ⚠️  org ${org._id} (${org.name}): ${live.length} live subscriptions for ${owner.stripeCustomerId} — resolve by hand`);
        continue;
      }
      const subId = live[0].id;
      const taken = await Organization.findOne({ stripeSubscriptionId: subId, _id: { $ne: org._id } }).select('_id');
      if (taken) {
        problems++;
        console.log(`   ⚠️  org ${org._id}: ${subId} already belongs to org ${taken._id} — resolve by hand`);
        continue;
      }
      console.log(`   ${APPLY ? '✏️ ' : '→ '} org ${org._id} (${org.name}) ← ${subId} (${live[0].status})`);
      if (APPLY) {
        await Organization.updateOne({ _id: org._id, stripeSubscriptionId: null }, { $set: { stripeSubscriptionId: subId } });
        const r = await reconcileById(subId);
        console.log(`      reconciled: ${r.applied ? (r.downgraded ? 'downgraded to Free' : 'state applied') : r.reason}`);
      }
    }

    // ── 3. Orgs whose stored period has passed or is unknown ───────────────────
    const stale = await Organization.find({
      stripeSubscriptionId: { $type: 'string' },
      subscriptionStatus: { $in: PAID_STATUSES },
      $or: [{ expiresAt: { $lte: new Date() } }, { expiresAt: null }]
    }).select('_id name stripeSubscriptionId expiresAt');
    console.log(`\n📋 Subscribed orgs with a passed or missing period end: ${stale.length}`);
    for (const org of stale) {
      console.log(`   ${APPLY ? '🔄' : '→ '} org ${org._id} (${org.name}) ${org.stripeSubscriptionId} expiresAt=${org.expiresAt ? org.expiresAt.toISOString() : 'null'}`);
      if (APPLY) {
        const r = await reconcileById(org.stripeSubscriptionId);
        console.log(`      reconciled: ${r.applied ? (r.downgraded ? 'downgraded to Free' : 'state applied') : r.reason}`);
      }
    }

    // ── 4. Legacy user-level subscription ids ──────────────────────────────────
    const legacyUsers = await User.find({ stripeSubscriptionId: { $type: 'string' } })
      .select('_id email organizationId stripeSubscriptionId');
    let orphaned = 0;
    for (const u of legacyUsers) {
      const org = u.organizationId ? await Organization.findById(u.organizationId).select('stripeSubscriptionId') : null;
      if (!org || org.stripeSubscriptionId !== u.stripeSubscriptionId) {
        orphaned++;
        problems++;
        console.log(`   ⚠️  user ${u._id} holds ${u.stripeSubscriptionId}, which no org of theirs tracks — check it in Stripe`);
      }
    }
    console.log(`\n📋 Legacy user-level subscription ids not tracked by an org: ${orphaned}`);

    console.log(`\n${problems ? `⚠️  ${problems} item(s) need a manual look.` : '✅ No manual follow-up needed.'}`);
    if (!APPLY) console.log('ℹ️  Dry run — nothing was written. Re-run with --apply to write.');
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

run();
