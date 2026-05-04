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
  seatsAllowed: { type: Number, default: 1 },
  seatsUsed: { type: Number, default: 1 },
  scanLimit: { type: Number, default: 0 },
  scansUsed: { type: Number, default: 0 },
  targetsUsed: { type: Number, default: 0 },
  oneTimeRemainingScans: { type: Number, default: 0 },
  stripeSubscriptionId: { type: String, default: null },
  expiresAt: { type: Date, default: null },
  lastScanReset: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Organization', OrganizationSchema);
