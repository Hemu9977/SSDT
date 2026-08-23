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

  // ─── SYSTEM ROLE (PLATFORM-LEVEL) ───────────────────────────────────────────
  // Independent from org-level role (owner/admin/member).
  // Controls access to the global admin dashboard.
  systemRole: {
    type: String,
    enum: ['user', 'admin', 'superadmin'],
    default: 'user'
  },
  // Platform-level admin lock — independent from org/subscription state.
  // Blocks login when true; does not invalidate already-issued JWTs (7-day expiry).
  isDisabled: {
    type: Boolean,
    default: false
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
  // Language used for transactional emails (OTP, scan notifications, etc).
  // Mirrors the frontend's UI language choice (LanguageContext), synced via PUT /profile.
  preferredLanguage: {
    type: String,
    enum: ['en', 'ja'],
    default: 'ja'
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
  // Account creation date — indexed for the admin analytics growth-trend
  // aggregation (30-day date-range $match + $group by day).
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
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
  },

  // ─── SESSION REVOCATION ─────────────────────────────────────────────────────
  // JWTs are stateless and live for 7 days, so changing a password would
  // otherwise leave every already-issued token working — a reset would not
  // actually lock out whoever compromised the account. Any token whose `iat`
  // predates this timestamp is rejected by middleware/auth.js.
  // Null means "never revoked"; it is only set by the password-reset route.
  tokensValidFrom: {
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

// ─── PLAN DEFINITIONS ────────────────────────────────────────────────────────
// The commercial numbers (seats, scans, targets, severity, schedules) come from
// config/planCatalog.js, which is also what Stripe provisioning and the admin
// revenue figures read. This table only shapes them into quota keys.
//
// The one rule that lives here rather than in the catalog: MONTHLY plans have no
// per-target cap (the cap is the global scansPerMonth), while ANNUAL plans cap
// scans per target. That is a billing-cycle behaviour, not a property of the plan.
const { PLAN_CATALOG, RECURRING_PLANS, ONETIME_PLANS } = require('../config/planCatalog');

const PLAN_LIMITS = {};

for (const plan of RECURRING_PLANS) {
  const c = PLAN_CATALOG[plan];
  const shared = {
    scansPerMonth: c.scans,
    targetsPerMonth: c.targets,
    vulnerabilityAccessLevel: c.vulnerabilityAccessLevel,
    maxSchedules: c.maxSchedules
  };
  PLAN_LIMITS[`${plan}_monthly`] = { ...shared, scansPerTarget: null };
  PLAN_LIMITS[`${plan}_annual`] = { ...shared, scansPerTarget: c.scans };
}

for (const plan of ONETIME_PLANS) {
  const c = PLAN_CATALOG[plan];
  PLAN_LIMITS[`${plan}_onetime`] = {
    scansPerMonth: c.scans,
    targetsPerMonth: c.targets,
    scansPerTarget: c.scans,
    vulnerabilityAccessLevel: c.vulnerabilityAccessLevel,
    maxSchedules: c.maxSchedules
  };
}

// Free / no plan — not purchasable, so it has no catalog entry. Also the fallback
// for an org whose paid plan was nulled on cancellation. Vulnerability access
// defaults to the MOST RESTRICTIVE level (matches vulnFilter.DEFAULT_LEVEL) so a
// downgraded/expired account never sees more severities than the lowest paid tier.
PLAN_LIMITS.free = {
  scansPerMonth: 20,
  targetsPerMonth: -1,
  scansPerTarget: null,
  vulnerabilityAccessLevel: 'critical-high',
  maxSchedules: 2
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