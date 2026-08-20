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
    const user = await User.findById(req.user.id).select('systemRole email name');
    if (!user) {
      console.log('⚠️ [adminAuth] User not found:', req.user.id);
      return res.status(401).json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'User account not found'
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

    // Attach the full admin user info for downstream handlers
    req.adminUser = user;
    console.log(`✅ [adminAuth] Admin access granted to ${user.email} (systemRole: ${user.systemRole})`);
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
