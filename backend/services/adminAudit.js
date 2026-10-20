// backend/services/adminAudit.js
// The only writer of AdminAuditLog. See models/AdminAuditLog.js for the contract.
const AdminAuditLog = require('../models/AdminAuditLog');

class AdminAuditError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AdminAuditError';
    this.code = 'ADMIN_AUDIT_FAILED';
  }
}

function actorOf(req) {
  const a = req.adminUser || {};
  return {
    actorId: a._id,
    actorEmail: a.email || null,
    actorRole: a.systemRole,
    ip: req.ip || null,
    userAgent: (req.get && req.get('user-agent')) || null,
  };
}

/**
 * Record that an action is about to run. MUST be awaited before the mutation:
 * if it throws, the caller refuses the action (fail closed).
 * @returns {Promise<object>} handle for finishAdminAction
 */
async function beginAdminAction(req, { action, targetType, targetId, targetLabel = null, before = null }) {
  try {
    const entry = await AdminAuditLog.create({
      ...actorOf(req),
      action,
      targetType,
      targetId,
      targetLabel,
      before,
      result: 'pending',
    });
    return entry;
  } catch (err) {
    console.error(`❌ [adminAudit] could not record ${action} on ${targetType} ${targetId}:`, err.message);
    throw new AdminAuditError(err.message);
  }
}

/**
 * Record the outcome. Never throws: the action has already happened (or failed),
 * and losing the outcome must not turn a completed change into an error response.
 * A row left `pending` is the visible trace of that rare case.
 */
async function finishAdminAction(entry, { result, after = null, errorCode = null }) {
  if (!entry || !entry._id) return;
  try {
    await AdminAuditLog.updateOne(
      { _id: entry._id },
      { $set: { result, after, errorCode, completedAt: new Date() } }
    );
  } catch (err) {
    console.error(`❌ [adminAudit] could not record outcome of ${entry._id} (${result}):`, err.message);
  }
}

/** Record a refused attempt (e.g. a plain admin trying a superadmin action). Best effort. */
async function recordDenied(req, { action, targetType, targetId, targetLabel = null, errorCode }) {
  try {
    await AdminAuditLog.create({
      ...actorOf(req),
      action,
      targetType,
      targetId,
      targetLabel,
      result: 'denied',
      errorCode,
      completedAt: new Date(),
    });
  } catch (err) {
    console.error(`❌ [adminAudit] could not record denied ${action}:`, err.message);
  }
}

module.exports = { beginAdminAction, finishAdminAction, recordDenied, AdminAuditError };
