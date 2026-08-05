const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    // Password is required only if googleId is not present
    required: function () { return !this.googleId; },
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  otp: {
    type: String,
  },
  otpExpires: {
    type: Date,
  },
  resetPasswordToken: {
    type: String,
  },
  resetPasswordExpires: {
    type: Date,
  },

  // ─── ORGANIZATION (NEW) ──────────────────────────────────────────────────────
  organizationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    default: null
  },
  role: {
    type: String,
    enum: ['owner', 'admin', 'member'],
    default: 'owner'
  },

  // ─── LEGACY (keep — existing code reads accountType and proExpiresAt) ───────
  accountType: {
    type: String,
    enum: ['free', 'pro', 'paid'],   // 'paid' covers all non-pro subscription plans
    default: 'free'
  },
  proExpiresAt: {
    type: Date,
    default: null
  },

  // ─── SERVICE PLAN FIELDS ─────────────────────────────────────────────────────
  // planType drives all limit logic. null = free / no plan purchased.
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
  // For stripe subscription management
  stripeCustomerId: {
    type: String,
    default: null
  },
  stripeSubscriptionId: {
    type: String,
    default: null
  },
  subscriptionStatus: {
    type: String,
    enum: ['active', 'canceled', 'past_due', 'trialing', null],
    default: null
  },
  stripePending: {
    type: Boolean,
    default: false
  },
  // Target-level scan tracking (annual plans: scans per target per month)
  // Stored as a plain object: { 'https://example.com': 2, ... }
  scanUsagePerTarget: {
    type: Map,
    of: Number,
    default: {}
  },
  // @deprecated - Use Organization.targetsUsed instead for team-level accuracy
  totalTargetsUsed: {
    type: Number,
    default: 0
  },
  // One-time / trial plan remaining scan slots
  oneTimeRemainingScans: {
    type: Number,
    default: 0
  },
  // ─────────────────────────────────────────────────────────────────────────────

  // Profile information
  bio: {
    type: String,
    default: '',
    maxlength: 500
  },
  // Account statistics
  totalScans: {
    type: Number,
    default: 0
  },
  lastResetDate: {
    type: Date,
    default: Date.now
  },
  targetsUsed: [{
    type: String
  }],
  // Account creation date
  createdAt: {
    type: Date,
    default: Date.now
  },
  // Last login tracking
  lastLoginAt: {
    type: Date,
    default: Date.now
  },
  // Track password reset timestamp for skipping OTP
  passwordResetAt: {
    type: Date,
    default: null
  }
});

// ─── METHOD: Check if user has ANY active paid plan ─────────────────────────
// Returns true for light, basic, pro — any plan with active org subscription.
// Also supports legacy accountType='pro' for backward compatibility.
UserSchema.methods.isPro = function (org = null) {
  // Use organization plan if available, otherwise fallback to user plan
  const source = org || this;

  // Primary check: any paid plan that is currently active
  if (source.planType && source.subscriptionStatus === 'active') return true;
  // One-time plans: active if remaining scans > 0
  if (source.billingCycle === 'onetime' && source.oneTimeRemainingScans > 0) return true;
  // Legacy check: accountType 'pro' and not expired (only if checking user directly)
  if (!org) {
    const isLegacyPro = this.accountType === 'pro' && (this.proExpiresAt && this.proExpiresAt > new Date());
    return isLegacyPro;
  }
  return false;
};

// ─── METHOD: Reset monthly usage counters when the calendar month rolls over ──
UserSchema.methods.checkAndResetMonthlyScans = function () {
  const now = new Date();
  const lastReset = new Date(this.lastResetDate);

  if (now.getUTCMonth() !== lastReset.getUTCMonth() || now.getUTCFullYear() !== lastReset.getUTCFullYear()) {
    this.totalTargetsUsed = 0;
    this.scanUsagePerTarget = new Map();
    this.lastResetDate = now;
    return true; // caller must save
  }
  return false;
};

// ─── PLAN DEFINITIONS (single source of truth) ───────────────────────────────
const PLAN_LIMITS = {
  // Monthly plans
  light_monthly: { scansPerMonth: 3, targetsPerMonth: 3, scansPerTarget: null, vulnerabilityAccessLevel: 'critical-high', maxSchedules: 1 },
  basic_monthly: { scansPerMonth: 5, targetsPerMonth: 5, scansPerTarget: null, vulnerabilityAccessLevel: 'all', maxSchedules: 3 },
  pro_monthly: { scansPerMonth: 10, targetsPerMonth: 10, scansPerTarget: null, vulnerabilityAccessLevel: 'all', maxSchedules: 10 },
  // Annual plans (same quota counts but enforced per-target per month)
  light_annual: { scansPerMonth: 3, targetsPerMonth: 3, scansPerTarget: 3, vulnerabilityAccessLevel: 'critical-high', maxSchedules: 1 },
  basic_annual: { scansPerMonth: 5, targetsPerMonth: 5, scansPerTarget: 5, vulnerabilityAccessLevel: 'all', maxSchedules: 3 },
  pro_annual: { scansPerMonth: 10, targetsPerMonth: 10, scansPerTarget: 10, vulnerabilityAccessLevel: 'all', maxSchedules: 10 },
  // One-time / trial
  trial1_onetime: { scansPerMonth: 1, targetsPerMonth: 1, scansPerTarget: 1, vulnerabilityAccessLevel: 'critical-high', maxSchedules: 0 },
  trial2_onetime: { scansPerMonth: 2, targetsPerMonth: 1, scansPerTarget: 2, vulnerabilityAccessLevel: 'all', maxSchedules: 0 },
  // Free / no plan — also the fallback for an org whose paid plan was nulled on
  // cancellation. Vulnerability access defaults to the MOST RESTRICTIVE level
  // (matches vulnFilter.DEFAULT_LEVEL) so a downgraded/expired account never sees
  // more severities than the lowest paid tier (Light).
  free: { scansPerMonth: 20, targetsPerMonth: -1, scansPerTarget: null, vulnerabilityAccessLevel: 'critical-high', maxSchedules: 2 },
};

// ─── METHOD: Get account limits (SINGLE SOURCE OF TRUTH) ─────────────────────
UserSchema.methods.getAccountLimits = function (org = null) {
  // Use organization plan if available, otherwise fallback to user plan
  const source = org || this;

  // Derive key
  let key = 'free';
  if (source.planType && source.billingCycle) {
    key = `${source.planType}_${source.billingCycle}`;
  }

  let limits = PLAN_LIMITS[key] || PLAN_LIMITS['free'];

  // Credit-only override: while a subscription is active, the subscription's
  // vulnerabilityAccessLevel always wins. Only when there is NO active
  // subscription does a purchased credit's own severity level apply — taken
  // from the soonest-expiring live batch (the one that will fund the next
  // scan), not from PLAN_LIMITS['free'].
  const hasActiveSub = source && (source.subscriptionStatus === 'active' || source.subscriptionStatus === 'trialing');
  if (!hasActiveSub && org && Array.isArray(org.scanCredits)) {
    const now = new Date();
    const liveBatches = org.scanCredits
      .filter(c => c.scansRemaining > 0 && c.expiresAt && c.expiresAt > now)
      .sort((a, b) => a.expiresAt - b.expiresAt);
    if (liveBatches.length > 0) {
      limits = { ...limits, vulnerabilityAccessLevel: liveBatches[0].vulnerabilityAccessLevel || limits.vulnerabilityAccessLevel };
    }
  }

  return {
    scansPerMonth: limits.scansPerMonth,
    targetsPerMonth: limits.targetsPerMonth,
    scansPerTarget: limits.scansPerTarget,
    vulnerabilityAccessLevel: limits.vulnerabilityAccessLevel,
    maxSchedules: limits.maxSchedules,
    // Legacy fields kept for backward-compat with existing profile/schedule code
    scansPerDay: limits.scansPerMonth === -1 ? -1 : Math.ceil(limits.scansPerMonth / 30),
    // All paid plans (light, basic, pro) get the higher file size and priority queue
    maxFileSize: this.isPro(org) ? 100 * 1024 * 1024 : 32 * 1024 * 1024,
    priorityQueue: this.isPro(org)
  };
};

module.exports = mongoose.model('User', UserSchema);