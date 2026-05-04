const Organization = require('../models/Organization');

async function consumeScan(orgId) {
  const org = await Organization.findById(orgId);

  if (!org || (org.billingCycle !== "onetime" && org.subscriptionStatus !== "active" && org.subscriptionStatus !== "trialing")) {
    return null;
  }

  const now = new Date();

  // 🔁 Monthly reset FIRST — UTC, so the cycle is timezone-independent
  const lastReset = org.lastScanReset || new Date(0);
  const isNewMonth =
    now.getUTCMonth() !== lastReset.getUTCMonth() ||
    now.getUTCFullYear() !== lastReset.getUTCFullYear();

  if (isNewMonth && org.billingCycle !== "onetime") {
    await Organization.updateOne(
      { _id: orgId },
      {
        $set: {
          scansUsed: 0,
          targetsUsed: 0,
          lastScanReset: now
        }
      }
    );
  }

  // 🔥 ONE-TIME PLAN
  if (org.billingCycle === "onetime") {
    return Organization.findOneAndUpdate(
      { _id: orgId, oneTimeRemainingScans: { $gt: 0 } },
      { $inc: { oneTimeRemainingScans: -1 } },
      { new: true }
    );
  }

  // 🔥 SUBSCRIPTION PLAN
  return Organization.findOneAndUpdate(
    { _id: orgId, scansUsed: { $lt: org.scanLimit } },
    { $inc: { scansUsed: 1, targetsUsed: 1 } },
    { new: true }
  );
}

module.exports = { consumeScan };
