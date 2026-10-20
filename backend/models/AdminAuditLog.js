// backend/models/AdminAuditLog.js
// Durable record of every sensitive platform-admin action (routes/admin.js).
//
// Written in two steps by services/adminAudit.js: a `pending` row BEFORE the
// mutation runs (if that write fails, the mutation is refused, so nothing can
// change unaudited), then the outcome. A row left `pending` therefore means the
// action was attempted and the process died before it could record the result.
//
// No TTL: this is the accountability record. It holds account ids and an email
// snapshot (so a deleted account's actions stay attributable), never passwords,
// tokens, OTPs or Stripe secrets.
const mongoose = require('mongoose');

const ACTIONS = [
  'user.disable',
  'user.enable',
  'user.role_change',
  'user.remove_from_org',
  'user.delete',
  'org.disable',
  'org.enable',
  'org.cancel_subscription',
  'org.delete',
];

// Who acted: an administrator through the dashboard ('admin'), or an operator
// running an approved maintenance script such as scripts/grantSystemRole.js
// ('script'), identified by name and change ticket instead of an account.
const isAdminActor = function () { return this.actorType !== 'script'; };

const AdminAuditLogSchema = new mongoose.Schema({
  actorType: { type: String, enum: ['admin', 'script'], default: 'admin' },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: isAdminActor, index: true },
  actorEmail: { type: String, default: null },
  actorRole: { type: String, enum: ['admin', 'superadmin'], required: isAdminActor },
  // Script runs only.
  operator: { type: String, default: null },
  ticket: { type: String, default: null },
  action: { type: String, enum: ACTIONS, required: true, index: true },
  targetType: { type: String, enum: ['user', 'organization'], required: true },
  targetId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  // Human-readable snapshot of the target at the time (email or org name).
  targetLabel: { type: String, default: null },
  // Only the fields the action changes, before and after.
  before: { type: mongoose.Schema.Types.Mixed, default: null },
  after: { type: mongoose.Schema.Types.Mixed, default: null },
  result: {
    type: String,
    enum: ['pending', 'success', 'failure', 'denied'],
    required: true,
    index: true,
  },
  // Stable machine code for a failure or denial (e.g. ADMIN_STRIPE_FAILED).
  errorCode: { type: String, default: null },
  ip: { type: String, default: null },
  userAgent: { type: String, default: null },
  createdAt: { type: Date, default: Date.now, index: true },
  completedAt: { type: Date, default: null },
});

AdminAuditLogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('AdminAuditLog', AdminAuditLogSchema);
module.exports.ACTIONS = ACTIONS;
