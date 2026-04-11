const mongoose = require('mongoose');

const scanResultSchema = new mongoose.Schema({
  target: {
    type: String,
    required: true,
    trim: true
  },
  analysisId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  // Legacy field (kept for backwards compatibility)
  result: {
    type: Object,
    default: null
  },
  pagespeedResult: {
    type: Object,
    default: null
  },
  observatoryResult: {
    type: Object,
    default: null
  },
  // 👇 ADD THIS FIELD
  zapResult: {
    type: Object,
    default: null
  },
  // Authenticated ZAP scan result (separate from public ZAP scan)
  authScanResult: {
    type: Object,
    default: null
  },
  // urlscan.io result
  urlscanResult: {
    type: Object,
    default: null
  },
  // WebCheck 30 scan types result
  webCheckResult: {
    type: Object,
    default: null
  },
  refinedReport: {
    type: String,
    default: null
  },
  status: {
    type: String,
    enum: ['queued', 'pending', 'combining', 'completed', 'failed', 'stopped'],
    default: 'queued'
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  triggerSource: {
    type: String,
    enum: ['manual', 'scheduled'],
    default: 'manual'
  },
  notified: {
    type: Boolean,
    default: false
  },
  languagePreference: {
    type: String,
    default: 'en'
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: { expires: 604800 } // TTL: 7 days (604800 seconds)
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

scanResultSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

scanResultSchema.methods.isComplete = function () {
  return this.status === 'completed';
};

scanResultSchema.statics.getRecentScans = function (userId, limit = 10) {
  return this.find({ userId })
    .sort({ createdAt: -1 })
    .limit(limit);
};

module.exports = mongoose.model('ScanResult', scanResultSchema);