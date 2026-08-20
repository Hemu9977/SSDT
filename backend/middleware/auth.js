// backend/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Organization = require('../models/Organization');

// ── Account-disabled enforcement ─────────────────────────────────────────────
// A JWT is valid for 7 days, so checking `isDisabled` only at login would let a
// disabled user keep full access for up to a week after an admin locks them out.
// The flag is therefore re-checked on every authenticated request.
//
// A naive DB read per request would put two extra queries on the hot path of
// every API call, so results are cached briefly. Admin mutations call
// `invalidatePrincipal` / `invalidateAllPrincipals` below, which makes a
// disable take effect immediately; the TTL is only a backstop for state changed
// out-of-band (a direct DB edit, or another instance in a multi-task ECS
// deployment, where each task holds its own cache).
const DISABLED_CACHE_TTL_MS = 30 * 1000;
const principalCache = new Map(); // userId -> { blocked: boolean, expires: number }

async function isPrincipalBlocked(userId) {
  const cached = principalCache.get(userId);
  if (cached && cached.expires > Date.now()) return cached.blocked;

  const user = await User.findById(userId).select('isDisabled organizationId').lean();

  let blocked;
  if (!user) {
    blocked = true;                 // account deleted — the token outlives it
  } else if (user.isDisabled) {
    blocked = true;
  } else if (user.organizationId) {
    const org = await Organization.findById(user.organizationId).select('isDisabled').lean();
    blocked = Boolean(org && org.isDisabled);
  } else {
    blocked = false;
  }

  principalCache.set(userId, { blocked, expires: Date.now() + DISABLED_CACHE_TTL_MS });
  return blocked;
}

/** Drop one user's cached state so an admin action applies on the next request. */
function invalidatePrincipal(userId) {
  principalCache.delete(String(userId));
}

/** Drop every cached entry — used when an org-wide flag changes. */
function invalidateAllPrincipals() {
  principalCache.clear();
}

// An expired entry is otherwise only replaced when that same user comes back,
// so on a busy platform the Map would grow for the whole life of the task and
// never shrink. Sweep it periodically; unref() so the timer never by itself
// keeps the process alive (matters for the worker entrypoints and for tests).
const CACHE_SWEEP_INTERVAL_MS = 5 * 60 * 1000;
const sweepTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of principalCache) {
    if (entry.expires <= now) principalCache.delete(key);
  }
}, CACHE_SWEEP_INTERVAL_MS);
if (typeof sweepTimer.unref === 'function') sweepTimer.unref();

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
async function auth(req, res, next) {
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

    // Cryptographically valid tokens can still belong to a locked-out account.
    // On an unexpected DB error we fail OPEN and log: the token itself is still
    // valid, this is a secondary control, and a transient Mongo blip must not
    // lock every user out of the platform at once.
    try {
      if (await isPrincipalBlocked(decoded.user.id)) {
        console.log('🚫 Auth: Disabled account attempted access —', decoded.user.id, 'on', req.path);
        return res.status(403).json({
          success: false,
          error: 'ACCOUNT_DISABLED',
          code: 'ACCOUNT_DISABLED',
          message: 'This account has been disabled'
        });
      }
    } catch (dbErr) {
      console.error('⚠️ Auth: disabled-state check failed, allowing request:', dbErr.message);
    }

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
// Exported so non-Express entry points that verify their own JWTs (the
// Socket.IO handshake) enforce exactly the same rule instead of reimplementing it.
module.exports.isPrincipalBlocked = isPrincipalBlocked;
module.exports.invalidatePrincipal = invalidatePrincipal;
module.exports.invalidateAllPrincipals = invalidateAllPrincipals;
