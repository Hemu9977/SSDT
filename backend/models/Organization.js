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
  oneTimeRemainingScans: { type: Number, default: 0 },
  stripeSubscriptionId: { type: String, default: null },
  stripeCheckoutSessionId: { type: String, default: null },
  expiresAt: { type: Date, default: null },
  lastScanReset: { type: Date, default: Date.now },
  // Indexed for the admin analytics growth-trend aggregation.
  createdAt: { type: Date, default: Date.now, index: true }
});

module.exports = mongoose.model('Organization', OrganizationSchema);
