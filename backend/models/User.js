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
    // CHANGED: Password is now required only if googleId is not present
    required: function() { return !this.googleId; },
  },
  googleId: { // NEW: To store Google unique ID
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
  // Account type - defaults to 'free'
  accountType: {
    type: String,
    enum: ['free', 'pro'],
    default: 'free'
  },
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
  monthlyScansUsed: {
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
  // Pro features (for future implementation)
  proExpiresAt: {
    type: Date,
    default: null
  },
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

// Method to check if user is Pro
UserSchema.methods.isPro = function() {
  return this.accountType === 'pro' && (!this.proExpiresAt || this.proExpiresAt > new Date());
};

// Method to check and reset monthly scans if a new month has started
UserSchema.methods.checkAndResetMonthlyScans = function() {
  const now = new Date();
  const lastReset = new Date(this.lastResetDate);
  
  if (now.getMonth() !== lastReset.getMonth() || now.getFullYear() !== lastReset.getFullYear()) {
    this.monthlyScansUsed = 0;
    this.lastResetDate = now;
    // Don't save here, caller should save if needed or it will be saved with other updates
    return true;
  }
  return false;
};

// Method to get account limits
UserSchema.methods.getAccountLimits = function() {
  if (this.isPro()) {
    return {
      scansPerMonth: 500,
      scansPerDay: -1,
      maxSchedules: 50,
      maxFileSize: 100 * 1024 * 1024,
      priorityQueue: true
    };
  } else {
    return {
      scansPerMonth: 20,
      scansPerDay: 5,
      maxSchedules: 2,
      maxFileSize: 32 * 1024 * 1024,
      priorityQueue: false
    };
  }
};

module.exports = mongoose.model('User', UserSchema);