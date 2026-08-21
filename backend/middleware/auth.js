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
// userId -> { blocked: boolean, tokensValidFrom: number|null, expires: number }
const principalCache = new Map();

/**
 * Resolve a principal's current state. Returns both the disabled verdict and
 * the token cut-off, so the two checks share one cached read rather than
 * adding a second query to the hot path of every authenticated request.
 */
async function getPrincipalState(userId) {
  const cached = principalCache.get(userId);
  if (cached && cached.expires > Date.now()) return cached;

  const user = await User.findById(userId)
    .select('isDisabled organizationId tokensValidFrom')
    .lean();

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

  const state = {
    blocked,
    // Null means "never revoked". Set only by the password-reset route.
    tokensValidFrom: user && user.tokensValidFrom ? new Date(user.tokensValidFrom).getTime() : null,
    expires: Date.now() + DISABLED_CACHE_TTL_MS,
  };
  principalCache.set(userId, state);
  return state;
}

async function isPrincipalBlocked(userId) {
  return (await getPrincipalState(userId)).blocked;
}

/**
 * True when this token predates a password reset and must no longer be honoured.
 * `iat` is in seconds; tokensValidFrom is in milliseconds.
 */
function isTokenRevoked(state, decoded) {
  if (!state.tokensValidFrom || !decoded || !decoded.iat) return false;
  return decoded.iat * 1000 < state.tokensValidFrom;
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
      const state = await getPrincipalState(decoded.user.id);

      if (state.blocked) {
        console.log('🚫 Auth: Disabled account attempted access —', decoded.user.id, 'on', req.path);
        return res.status(403).json({
          success: false,
          error: 'ACCOUNT_DISABLED',
          code: 'ACCOUNT_DISABLED',
          message: 'This account has been disabled'
        });
      }

      // A password reset revokes every token issued before it. Without this a
      // reset would not lock out whoever held the old session — the stolen
      // token would keep working for the rest of its 7-day life.
      if (isTokenRevoked(state, decoded)) {
        console.log('🚫 Auth: Revoked (pre-reset) token rejected —', decoded.user.id, 'on', req.path);
        return res.status(403).json({
          success: false,
          error: 'SESSION_REVOKED',
          code: 'SESSION_REVOKED',
          message: 'This session has ended. Please sign in again.'
        });
      }
    } catch (dbErr) {
      console.error('⚠️ Auth: principal-state check failed, allowing request:', dbErr.message);
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
module.exports.getPrincipalState = getPrincipalState;
module.exports.isTokenRevoked = isTokenRevoked;
module.exports.invalidatePrincipal = invalidatePrincipal;
module.exports.invalidateAllPrincipals = invalidateAllPrincipals;
