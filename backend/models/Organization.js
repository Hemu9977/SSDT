const mongoose = require('mongoose');

const OrganizationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  planType: {
    type: String,
    enum: ['light', 'basic', 'pro', 'trial1', 'trial2', null],
    default: null
  },
  billingCycle: {
    type: String,
    enum: ['monthly', 'annual', 'onetime', null],
    default: null
  },
  subscriptionStatus: {
    type: String,
    enum: ['active', 'canceled', 'past_due', 'trialing', null],
    default: null
  },
  // Platform-level admin lock — blocks login for all members of this org.
  // Independent from subscriptionStatus (which reflects billing state, not access).
  isDisabled: { type: Boolean, default: false },
  seatsAllowed: { type: Number, default: 1 },
  seatsUsed: { type: Number, default: 1 },
  scanLimit: { type: Number, default: 0 },
  scansUsed: { type: Number, default: 0 },
  targetsUsed: { type: Number, default: 0 },
  // Per-target scan counts for the current month. Keyed by a sha1 hash of the
  // normalized target hostname (hashing avoids '.'/'$' which are illegal in
  // MongoDB map keys / dotted update paths). Map size = distinct targets used;
  // each value = scans against that target. Reset monthly alongside scansUsed.
  targetScanCounts: { type: Map, of: Number, default: {} },
  // Denormalized mirror of sum(scanCredits[].scansRemaining) for live batches,
  // updated in the same atomic op as the array. Drifts upward when a batch
  // merely expires (nothing decrements it on expiry) — quota logic and
  // display must derive from live scanCredits batches, never trust this
  // scalar alone as the source of truth for "can we spend a credit".
  oneTimeRemainingScans: { type: Number, default: 0 },
  // Purchased one-off scan credit batches — one per completed Stripe one-time
  // checkout. Kept sorted by expiresAt ascending ($push + $sort on insert) so
  // the atomic positional-$ decrement in consumeScan() always burns the
  // soonest-expiring live batch first.
  scanCredits: {
    type: [{
      source: { type: String, required: true },
      scansTotal: { type: Number, required: true },
      scansRemaining: { type: Number, required: true, min: 0 },
      purchasedAt: { type: Date, default: Date.now },
      expiresAt: { type: Date, required: true },
      stripeCheckoutSessionId: { type: String, default: null },
      vulnerabilityAccessLevel: { type: String, default: 'critical-high' },
      source_type: { type: String, enum: ['stripe', 'migration'], default: 'stripe' }
    }],
    default: []
  },
  // Real lifetime scan counter (ScanResult has a 7-day TTL so it cannot serve
  // this purpose). Incremented atomically inside consumeScan().
  totalScansAllTime: { type: Number, default: 0 },
  stripeSubscriptionId: { type: String, default: null },
  stripeCheckoutSessionId: { type: String, default: null },
  expiresAt: { type: Date, default: null },
  lastScanReset: { type: Date, default: Date.now },
  // Indexed for the admin analytics growth-trend aggregation.
  createdAt: { type: Date, default: Date.now, index: true }
});

module.exports = mongoose.model('Organization', OrganizationSchema);
