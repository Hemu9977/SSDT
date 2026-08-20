// backend/middleware/adminAuth.js
// Platform-level admin authorization middleware.
// Must always be used AFTER the `auth` middleware.
// Independent from organization-level roles (owner/admin/member).

const User = require('../models/User');

module.exports = async function adminAuth(req, res, next) {
  try {
    if (!req.user || !req.user.id) {
      console.log('⚠️ [adminAuth] No authenticated user on request');
      return res.status(401).json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'No token, authorization denied'
      });
    }

    // Fetch the user with systemRole from DB; never trust JWT payload alone for role
    const user = await User.findById(req.user.id).select('systemRole email name isDisabled');
    if (!user) {
      console.log('⚠️ [adminAuth] User not found:', req.user.id);
      return res.status(401).json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'User account not found'
      });
    }

    if (user.isDisabled) {
      console.log(`🚫 [adminAuth] Disabled admin account blocked: ${user.email}`);
      return res.status(403).json({
        success: false,
        error: 'ACCOUNT_DISABLED',
        code: 'ACCOUNT_DISABLED',
        message: 'This account has been disabled'
      });
    }

    const allowedRoles = ['admin', 'superadmin'];
    if (!allowedRoles.includes(user.systemRole)) {
      console.log(`🚫 [adminAuth] Access denied for user ${user.email} (systemRole: ${user.systemRole})`);
      return res.status(403).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Access denied. Administrator privileges required.'
      });
    }

    // Attach the full admin user info for downstream handlers.
    // Deliberately no success log — this runs on every admin request and would
    // write the admin's email address into the logs continuously. Denials below
    // are still logged, which is the part worth auditing.
    req.adminUser = user;
    next();
  } catch (err) {
    console.error('❌ [adminAuth] Error:', err.message);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'Authorization check failed'
    });
  }
};
