const rateLimit = require('express-rate-limit');

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

// Log rate limit configuration on startup
console.log('📊 Rate Limit Configuration:');
console.log(`   - Enabled: ${isRateLimitEnabled}`);
console.log(`   - API: ${API_RATE_LIMIT_MAX} requests per ${API_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Auth: ${AUTH_RATE_LIMIT_MAX} requests per ${AUTH_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Scan: ${SCAN_RATE_LIMIT_MAX} requests per ${SCAN_RATE_LIMIT_WINDOW_MS / 1000}s`);
console.log(`   - Combined: ${COMBINED_SCAN_RATE_LIMIT_MAX} requests per ${COMBINED_SCAN_RATE_LIMIT_WINDOW_MS / 1000}s`);

// Create a pass-through middleware when rate limiting is disabled
const createBypassMiddleware = () => (req, res, next) => next();

// General API rate limiter (100 requests per 15 minutes by default)
// Uses user-based limiting for authenticated routes, falls back to IP for unauthenticated
const apiLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: API_RATE_LIMIT_WINDOW_MS,
  max: API_RATE_LIMIT_MAX,
  message: {
    error: 'Too many requests, please try again later.',
    retryAfter: `${Math.ceil(API_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.user?.id || req.ip;
  },
  handler: (req, res) => {
    const identifier = req.user?.id ? `User ${req.user.id}` : `IP ${req.ip}`;
    console.log(`⚠️  Rate limit exceeded for ${identifier} on ${req.path}`);
    res.status(429).json({
      error: 'Too many requests, please try again later.',
      retryAfter: `${Math.ceil(API_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
    });
  }
}) : createBypassMiddleware();

// Strict rate limiter for authentication endpoints (20 requests per 15 minutes by default)
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
  keyGenerator: (req) => {
    return req.ip;
  },
  handler: (req, res) => {
    console.log(`🚨 Auth rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      message: 'Too many authentication attempts. Please try again later.',
      retryAfter: `${Math.ceil(AUTH_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
    });
  }
}) : createBypassMiddleware();

// Moderate rate limiter for file/URL scanning (20 requests per 10 minutes by default)
// Uses user-based limiting for better per-user tracking
const scanLimiter = isRateLimitEnabled ? rateLimit({
  windowMs: SCAN_RATE_LIMIT_WINDOW_MS,
  max: SCAN_RATE_LIMIT_MAX,
  message: {
    error: 'Too many scan requests, please try again later.',
    retryAfter: `${Math.ceil(SCAN_RATE_LIMIT_WINDOW_MS / 60000)} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.user?.id || req.ip;
  },
  handler: (req, res) => {
    const identifier = req.user?.id ? `User ${req.user.id}` : `IP ${req.ip}`;
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
  keyGenerator: (req) => {
    return req.user?.id || req.ip;
  },
  handler: (req, res) => {
    const identifier = req.user?.id ? `User ${req.user.id}` : `IP ${req.ip}`;
    const retryAfterSeconds = Math.ceil(COMBINED_SCAN_RATE_LIMIT_WINDOW_MS / 1000);
    console.log(`⚠️  Combined scan rate limit exceeded for ${identifier} on ${req.path}`);
    res.status(429).json({
      error: `You can only perform one combined scan per ${retryAfterSeconds} second${retryAfterSeconds > 1 ? 's' : ''}. This helps us respect API limits from Mozilla Observatory, PageSpeed, and Gemini.`,
      retryAfter: `${retryAfterSeconds} second${retryAfterSeconds > 1 ? 's' : ''}`,
      retryAfterSeconds: retryAfterSeconds
    });
  }
}) : createBypassMiddleware();

module.exports = {
  apiLimiter,
  authLimiter,
  scanLimiter,
  combinedScanLimiter
};