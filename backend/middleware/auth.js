// backend/middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  // Support both Authorization: Bearer <token> (standard) and x-auth-token (legacy)
  let token = null;

  const authHeader = req.header('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim(); // Extract token after "Bearer "
  } else {
    token = req.header('x-auth-token'); // Legacy fallback
  }

  // Check if no token
  if (!token) {
    console.log('⚠️ Auth: No token provided for', req.path);
    return res.status(401).json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'No token, authorization denied'
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    console.log('✅ Auth: Token verified for user', decoded.user.id, 'on', req.path);
    next();
  } catch (err) {
    console.log('❌ Auth: Invalid token for', req.path, '-', err.message);
    res.status(401).json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Token is not valid',
      details: err.message
    });
  }
};
