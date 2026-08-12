// backend/middleware/auth.js
const jwt = require('jsonwebtoken');

/**
 * Read the bearer token from either header form.
 * Supports Authorization: Bearer <token> (standard) and x-auth-token (legacy).
 */
function readToken(req) {
  const authHeader = req.header('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  return req.header('x-auth-token') || null;
}

/**
 * Enforcing auth. Rejects the request when the token is missing or invalid.
 */
function auth(req, res, next) {
  const token = readToken(req);

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
}

/**
 * Non-enforcing identification, for middleware that must run BEFORE the
 * per-route `auth` — chiefly the rate limiters, which are mounted on the path in
 * server.js and therefore execute before any route handler.
 *
 * Sets `req.authUserId` when a valid token is present and does nothing otherwise.
 * It NEVER rejects: `auth` still performs the real enforcement on each route.
 *
 * Without this, limiter keyGenerators fell through to `req.ip`, so every user
 * behind the same egress IP (or the same CDN edge) shared one quota — which is
 * what made a second PDF download fail after the first one used up the window.
 */
function identifyUser(req, _res, next) {
  const token = readToken(req);
  if (!token) return next();

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded?.user?.id) req.authUserId = String(decoded.user.id);
  } catch {
    // Invalid/expired token — stay anonymous and let `auth` produce the 401.
  }
  next();
}

module.exports = auth;
module.exports.identifyUser = identifyUser;
