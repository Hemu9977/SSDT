/**
 * backend/utils/otp.js
 *
 * Emailed one-time codes. The code itself is never stored: the user document
 * holds an HMAC of it (keyed by OTP_SECRET, else JWT_SECRET, and bound to the
 * user id), so a database read does not reveal a usable code. Each issued code
 * may be tried OTP_MAX_ATTEMPTS times; routes/auth.js reserves an attempt
 * atomically before comparing, so parallel guesses share that budget.
 */

const crypto = require('crypto');

const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function otpKey() {
  const key = process.env.OTP_SECRET || process.env.JWT_SECRET;
  if (!key) throw new Error('OTP_SECRET / JWT_SECRET is not set');
  return key;
}

function hashOtp(userId, code) {
  return crypto.createHmac('sha256', otpKey()).update(`otp:${String(userId)}:${String(code)}`).digest('hex');
}

const sameString = (a, b) => {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
};

/**
 * Put a fresh code on `user` (the caller saves). Clears any earlier code,
 * including a plaintext one written before codes were hashed.
 * @returns {string} the code, to be emailed
 */
function issueOtp(user, code, now = Date.now()) {
  user.otpHash = hashOtp(user._id, code);
  user.otpExpires = new Date(now + OTP_TTL_MS);
  user.otpAttempts = 0;
  user.otp = undefined;
  return code;
}

/** True when the user has an unexpired code outstanding. */
function hasLiveOtp(user, now = Date.now()) {
  return Boolean((user.otpHash || user.otp) && user.otpExpires && new Date(user.otpExpires).getTime() >= now);
}

/** Constant-time check of `code` against the stored hash (or a legacy plaintext code). */
function otpMatches(user, code) {
  if (user.otpHash) return sameString(user.otpHash, hashOtp(user._id, code));
  if (user.otp) return sameString(user.otp, code);
  return false;
}

/** Fields that end an outstanding code, for an update's $unset. */
const OTP_CLEAR = { otp: '', otpHash: '', otpExpires: '', otpAttempts: '' };

module.exports = { OTP_TTL_MS, OTP_MAX_ATTEMPTS, hashOtp, issueOtp, hasLiveOtp, otpMatches, OTP_CLEAR };
