const rateLimit = require('express-rate-limit');
// Normalises an IPv6 address to its /56 subnet. A single IPv6 client can present
// a different address on every request, so keying on the raw value makes IP-based
// limiting useless (and express-rate-limit v8 rejects it outright).
const { ipKeyGenerator } = require('express-rate-limit');

// Check if rate limiting is enabled (can be disabled in development)
const isRateLimitEnabled = process.env.RATE_LIMIT_ENABLED !== 'false';

if (!isRateLimitEnabled) {
  console.warn('⚠️  RATE LIMITING IS DISABLED - Only use this in development!');
}

// Helper function to parse env variable as integer with fallback
const getEnvInt = (key, defaultValue) => {
  const value = process.env[key];
  return value ? parseInt(value, 10) : defaultValue;
};

// General API rate limiter configuration
const API_RATE_LIMIT_MAX = getEnvInt('API_RATE_LIMIT_MAX', 100);
const API_RATE_LIMIT_WINDOW_MS = getEnvInt('API_RATE_LIMIT_WINDOW_MS', 900000); // 15 minutes

// Auth rate limiter configuration
const AUTH_RATE_LIMIT_MAX = getEnvInt('AUTH_RATE_LIMIT_MAX', 20);
const AUTH_RATE_LIMIT_WINDOW_MS = getEnvInt('AUTH_RATE_LIMIT_WINDOW_MS', 900000); // 15 minutes

// Scan rate limiter configuration
const SCAN_RATE_LIMIT_MAX = getEnvInt('SCAN_RATE_LIMIT_MAX', 20);
const SCAN_RATE_LIMIT_WINDOW_MS = getEnvInt('SCAN_RATE_LIMIT_WINDOW_MS', 600000); // 10 minutes

// Combined scan rate limiter configuration
const COMBINED_SCAN_RATE_LIMIT_MAX = getEnvInt('COMBINED_SCAN_RATE_LIMIT_MAX', 1);
const COMBINED_SCAN_RATE_LIMIT_WINDOW_MS = getEnvInt('COMBINED_SCAN_RATE_LIMIT_WINDOW_MS', 60000); // 1 minute

// Poll rate limiter configuration.
// Read-only status endpoints (PDF job status, active scan, combined analysis) are
// polled on a timer by the browser and must NOT share the scan-starting budget.
// A single PDF download alone can issue dozens of polls.
const POLL_RATE_LIMIT_MAX = getEnvInt('POLL_RATE_LIMIT_MAX', 600);
const POLL_RATE_LIMIT_WINDOW_MS = getEnvInt('POLL_RATE_LIMIT_WINDOW_MS', 600000); // 10 minutes

/**
 * Identify the caller for rate-limiting purposes.
 *
 * `req.authUserId` is set by the non-enforcing `identifyUser` middleware
 * (middleware/auth.js), which server.js runs immediately before these limiters.
 * `req.user` is only populated later, by the per-route `auth` middleware, so
 * relying on it here silently degraded every limiter to per-IP — meaning all
 * users behind one NAT or CDN edge shared a single bucket.
 */
const limitKey = (req) => req.authUserId || req.user?.id || ipKeyGenerator(req.ip);

// Log rate limit configuration on startup
console.log('📊 Rate Limit Configuration:');
console.log(`   - Enabled: ${isRateLimitEnabled}`);
console.log(`   - API: ${API_RATE_LIMIT_MAX} requests per ${API_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Auth: ${AUTH_RATE_LIMIT_MAX} requests per ${AUTH_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Scan: ${SCAN_RATE_LIMIT_MAX} requests per ${SCAN_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Combined: ${COMBINED_SCAN_RATE_LIMIT_MAX} requests per ${COMBINED_SCAN_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Poll: ${POLL_RATE_LIMIT_MAX} requests per ${POLL_RATE_LIMIT_WINDOW_MS / 1000}s`);

// Create a pass-through middleware when rate limiting is disabled
const createBypassMiddleware = () => (req, res, next) => next();

// General API rate limiter (100 requests per 15 minutes by default).
// Keyed on the authenticated user (see limitKey); falls back to IP only for
// genuinely anonymous callers.
const apiLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: API_RATE_LIMIT_WINDOW_MS,
  max: API_RATE_LIMIT_MAX,
  message: {
    error: 'Too many requests, please try again later.',
    retryAfter: `${Math.ceil(API_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limitKey,
  handler: (req, res) => {
    const identifier = req.authUserId ? `User ${req.authUserId}` : `IP ${req.ip}`;
    console.log(`⚠️  Rate limit exceeded for ${identifier} on ${req.path}`);
    res.status(429).json({
      error: 'Too many requests, please try again later.',
      retryAfter: `${Math.ceil(API_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
    });
  }
}) : createBypassMiddleware();

// Strict rate limiter for authentication endpoints (20 requests per 15 minutes by default)
// Routes that cause an email to be SENT to an address the caller supplies.
// These need a tighter, differently-keyed budget than the rest of /auth: keyed
// on the target address so one victim cannot be mail-bombed, and separate from
// authLimiter so burning it does not also block legitimate logins from the
// same IP (they share one 20-per-15-minute bucket otherwise).
const EMAIL_SEND_WINDOW_MS = parseInt(process.env.EMAIL_SEND_WINDOW_MS || '900000', 10);
const EMAIL_SEND_MAX       = parseInt(process.env.EMAIL_SEND_MAX || '5', 10);

const emailSendLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: EMAIL_SEND_WINDOW_MS,
  max: EMAIL_SEND_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  // Key on the recipient, falling back to IP when no email was supplied.
  keyGenerator: (req) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return email ? `email:${email}` : ipKeyGenerator(req.ip);
  },
  handler: (req, res) => {
    console.log(`🚨 Email-send rate limit exceeded on ${req.path}`);
    // Deliberately the same shape the routes return on success — this endpoint
    // must not become an account-enumeration or existence oracle.
    res.status(429).json({
      code: 'TOO_MANY_REQUESTS',
      message: 'Too many requests. Please try again later.'
    });
  }
}) : createBypassMiddleware();

const authLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX,
  message: {
    message: 'Too many authentication attempts from this IP, please try again later.',
    retryAfter: `${Math.ceil(AUTH_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  // Login/registration is deliberately IP-keyed (there is no user yet).
  keyGenerator: (req) => ipKeyGenerator(req.ip),
  handler: (req, res) => {
    console.log(`🚨 Auth rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      message: 'Too many authentication attempts. Please try again later.',
      retryAfter: `${Math.ceil(AUTH_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
    });
  }
}) : createBypassMiddleware();

// Moderate rate limiter for scan-STARTING routes (20 requests per 10 minutes by
// default). Read-only polling must use pollLimiter instead — see below.
const scanLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: SCAN_RATE_LIMIT_WINDOW_MS,
  max: SCAN_RATE_LIMIT_MAX,
  message: {
    error: 'Too many scan requests, please try again later.',
    retryAfter: `${Math.ceil(SCAN_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limitKey,
  handler: (req, res) => {
    const identifier = req.authUserId ? `User ${req.authUserId}` : `IP ${req.ip}`;
    console.log(`⚠️  Scan rate limit exceeded for ${identifier} on ${req.path}`);
    res.status(429).json({
      error: 'Too many scan requests. Please slow down and try again later.',
      retryAfter: `${Math.ceil(SCAN_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
    });
  }
}) : createBypassMiddleware();

// Strict rate limiter for combined scans (1 scan per minute by default)
// This respects external API limits: Mozilla Observatory (1/min), PageSpeed, Gemini
const combinedScanLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: COMBINED_SCAN_RATE_LIMIT_WINDOW_MS,
  max: COMBINED_SCAN_RATE_LIMIT_MAX,
  message: {
    error: 'Please wait before starting another scan.',
    retryAfter: `${Math.ceil(COMBINED_SCAN_RATE_LIMIT_WINDOW_MS / 1000)} seconds`
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limitKey,
  handler: (req, res) => {
    const identifier = req.authUserId ? `User ${req.authUserId}` : `IP ${req.ip}`;
    const retryAfterSeconds = Math.ceil(COMBINED_SCAN_RATE_LIMIT_WINDOW_MS / 1000);
    console.log(`⚠️  Combined scan rate limit exceeded for ${identifier} on ${req.path}`);
    res.status(429).json({
      // Never name the underlying scan engines: reports are resold and clients
      // must not learn which third-party scanners are in use.
      error: `You can only start one scan per ${retryAfterSeconds} second${retryAfterSeconds > 1 ? 's' : ''}.`,
      errorCode: 'SCAN_RATE_LIMITED',
      retryAfter: `${retryAfterSeconds} second${retryAfterSeconds > 1 ? 's' : ''}`,
      retryAfterSeconds: retryAfterSeconds
    });
  }
}) : createBypassMiddleware();

// Generous limiter for read-only status polling (600 requests per 10 minutes by
// default). The browser polls PDF-job status, active-scan and combined-analysis
// on a timer; sharing the scan-starting budget meant one PDF download exhausted
// it and the next download was rejected.
const pollLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: POLL_RATE_LIMIT_WINDOW_MS,
  max: POLL_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limitKey,
  handler: (req, res) => {
    const identifier = req.authUserId ? `User ${req.authUserId}` : `IP ${req.ip}`;
    console.log(`⚠️  Poll rate limit exceeded for ${identifier} on ${req.path}`);
    res.status(429).json({
      errorCode: 'POLL_RATE_LIMITED',
      error: 'Too many status requests. Please slow down and try again later.',
      retryAfter: `${Math.ceil(POLL_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
    });
  }
}) : createBypassMiddleware();

module.exports = {
  apiLimiter,
  authLimiter,
  emailSendLimiter,
  scanLimiter,
  combinedScanLimiter,
  pollLimiter
};
