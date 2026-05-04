const mongoose = require('mongoose');

const scheduledScanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  targetUrl: {
    type: String,
    required: true,
    trim: true
  },
  scanType: {
    type: String,
    enum: ['public', 'authenticated'],
    default: 'public'
  },
  scheduleType: {
    type: String,
    enum: ['one-time', 'recurring'],
    required: true
  },
  // For one-time schedules
  scheduledAt: {
    type: Date,
    default: null
  },
  // For recurring schedules
  recurring: {
    frequency: {
      type: String,
      enum: ['monthly', 'twice-monthly', 'custom'],
      default: null
    },
    days: {
      type: [Number], // Day-of-month array, e.g. [1, 15]
      default: []
    },
    time: {
      type: String, // "HH:mm" format
      default: '10:00'
    }
  },
  timezone: {
    type: String,
    default: 'Asia/Kolkata'
  },
  status: {
    type: String,
    enum: ['scheduled', 'running', 'completed', 'failed'],
    default: 'scheduled'
  },
  lastRun: {
    type: Date,
    default: null
  },
  nextRun: {
    type: Date,
    default: null,
    index: true
  },
  lastFailure: {
    reason: { type: String, default: null },
    details: { type: String, default: null },
    failureType: { type: String, default: null }, // target_unreachable, auth_failure, timeout, invalid_url, internal_error
    timestamp: { type: Date, default: null }
  },
  lastScanId: {
    type: String,
    default: null
  },
  enabled: {
    type: Boolean,
    default: true
  },
  // For authenticated scans
  authConfig: {
    loginUrl: { type: String, default: null },
    credentials: [{
      selector: { type: String, required: true },
      value: { type: String, required: true },
      inputType: { type: String, default: 'text' }
    }],
    submitButton: { type: String, default: null }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Compound indexes for efficient queries
scheduledScanSchema.index({ nextRun: 1, enabled: 1, status: 1 });
scheduledScanSchema.index({ userId: 1, status: 1 });

scheduledScanSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

/**
 * Compute the next run date based on recurring configuration.
 * For one-time schedules, nextRun = scheduledAt.
 * For recurring, finds the next occurrence after `now`.
 */
scheduledScanSchema.methods.computeNextRun = function () {
  const now = new Date();

  if (this.scheduleType === 'one-time') {
    this.nextRun = this.scheduledAt;
    return this.nextRun;
  }

  // Recurring schedule
  if (!this.recurring || !this.recurring.days || this.recurring.days.length === 0) {
    return null;
  }

  const [hours, minutes] = (this.recurring.time || '10:00').split(':').map(Number);
  const sortedDays = [...this.recurring.days].sort((a, b) => a - b);

  // Try to find next run in current month and subsequent months
  for (let monthOffset = 0; monthOffset <= 2; monthOffset++) {
    const candidateMonth = new Date(now.getFullYear(), now.getMonth() + monthOffset, 1);

    for (const day of sortedDays) {
      const candidate = new Date(
        candidateMonth.getFullYear(),
        candidateMonth.getMonth(),
        day,
        hours,
        minutes,
        0
      );

      // Skip if day doesn't exist in this month (e.g., Feb 31)
      if (candidate.getMonth() !== candidateMonth.getMonth()) continue;

      // Must be in the future
      if (candidate > now) {
        this.nextRun = candidate;
        return this.nextRun;
      }
    }
  }

  return null;
};

/**
 * Static: Get all schedules due for execution
 */
scheduledScanSchema.statics.getDueSchedules = function () {
  const now = new Date();
  return this.find({
    enabled: true,
    status: 'scheduled',
    nextRun: { $lte: now }
  }).populate('userId', 'name email accountType targetsUsed organizationId');
};

/**
 * Static: Count active schedules for a user
 */
scheduledScanSchema.statics.countActiveForUser = function (userId) {
  return this.countDocuments({
    userId,
    enabled: true,
    $or: [
      { scheduleType: 'recurring' },
      { scheduleType: 'one-time', status: 'scheduled' }
    ]
  });
};

module.exports = mongoose.model('ScheduledScan', scheduledScanSchema);
