// backend/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Organization = require('../models/Organization');
const auth = require('../middleware/auth');
const { invalidatePrincipal } = require('../middleware/auth');
const { emailSendLimiter } = require('../middleware/rateLimiter');
const { generateOTP, sendOTPEmail, sendResetPasswordEmail } = require('../services/emailService');
const crypto = require('crypto');
const { verifyGoogleCredential } = require('../utils/googleAuth');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// An account is blocked when the user was disabled by a platform admin, or when
// the organization they belong to was disabled. Checked on every login path.
// NOTE: this gates token ISSUANCE only. `auth` additionally re-checks the flag
// on each request so an already-issued JWT stops working immediately.
async function isAccountBlocked(user) {
  if (user.isDisabled) return true;
  if (user.organizationId) {
    const org = await Organization.findById(user.organizationId).select('isDisabled').lean();
    if (org && org.isDisabled) return true;
  }
  return false;
}

const DISABLED_MESSAGE = 'This account has been disabled. Please contact your administrator.';

// Explicit OPTIONS handler — belt-and-suspenders in case the global preflight
// handler in server.js is bypassed (e.g. a future middleware ordering change).
// CORS headers are already set by app.use(cors(corsOptions)) upstream.
router.options('/google', (req, res) => res.sendStatus(204));

// @route   POST /auth/google
// @desc    Login or Register with Google
router.post('/google', async (req, res) => {
  const { token, googleAccessToken } = req.body;

  try {
    let name, email, googleId, picture;

    if (!googleAccessToken && !token) {
      return res.status(400).json({ code: 'AUTH_NO_TOKEN', message: 'No token provided' });
    }

    ({ name, email, googleId, picture } = await verifyGoogleCredential({ token, googleAccessToken }));

    console.log(`Processing Google Login for user`);

    // Check if user exists
    let user = await User.findOne({ email: email.toLowerCase() });

    if (user) {
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }
    } else {
      console.log('Creating new user from Google');
      const randomPassword = crypto.randomBytes(32).toString('hex');
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(randomPassword, salt);

      user = new User({
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
        googleId,
        isVerified: true,
        accountType: 'free'
      });
      await user.save();
    }

    if (await isAccountBlocked(user)) {
      return res.status(403).json({ code: 'ACCOUNT_DISABLED', message: DISABLED_MESSAGE });
    }

    if (!user.isVerified) user.isVerified = true;
    user.lastLoginAt = new Date();
    await user.save();

    const payload = { user: { id: user.id } };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '7d' },
      (err, jwtToken) => {
        if (err) throw err;
        res.json({
          code: 'AUTH_GOOGLE_SUCCESS', message: 'Google login successful',
          token: jwtToken,
          user: { id: user.id, email: user.email, isVerified: user.isVerified, systemRole: user.systemRole || 'user' }
        });
      }
    );
  } catch (err) {
    console.error('Google Auth Error:', err.message);
    res.status(500).json({ code: 'AUTH_GOOGLE_FAILED', message: 'Google authentication failed' });
  }
});

// Existing Register Route
router.post('/register', async (req, res) => {
  const { name, email, password, language } = req.body;
  if (!name || typeof name !== 'string' || name.trim().length < 1) {
    return res.status(400).json({ code: 'AUTH_NAME_REQUIRED', message: 'Name is required' });
  }
  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ code: 'AUTH_EMAIL_INVALID', message: 'Valid email is required' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ code: 'AUTH_PASSWORD_TOO_SHORT', message: 'Password must be at least 8 characters' });
  }
  try {
    let user = await User.findOne({ email: email.toLowerCase() });
    if (user) return res.status(400).json({ code: 'AUTH_USER_EXISTS', message: 'User already exists' });

    user = new User({ name, email: email.toLowerCase(), password });
    // Seed the email language from the UI language the visitor registered under
    // (frontend's LanguageContext); falls back to the schema default otherwise.
    if (['en', 'ja'].includes(language)) user.preferredLanguage = language;
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    await user.save();

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    // Attempt email, but don't fail registration if email fails
    try { await sendOTPEmail(user.email, otp, user.preferredLanguage); } catch(e) { console.error("Email failed", e); }
    
    res.status(201).json({ code: 'AUTH_REGISTERED', message: 'User registered', user: { id: user.id, email: user.email }});
  } catch (err) {
    res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' });
  }
});

// Existing Login Route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ code: 'AUTH_EMAIL_INVALID', message: 'Valid email is required' });
  }
  if (!password) {
    return res.status(400).json({ code: 'AUTH_PASSWORD_REQUIRED', message: 'Password is required' });
  }
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ code: 'AUTH_INVALID_CREDENTIALS', message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ code: 'AUTH_INVALID_CREDENTIALS', message: 'Invalid credentials' });

    if (await isAccountBlocked(user)) {
      return res.status(403).json({ code: 'ACCOUNT_DISABLED', message: DISABLED_MESSAGE });
    }

    const recentlyReset = user.passwordResetAt && (new Date() - user.passwordResetAt) < (86400000);
    if (recentlyReset) {
       const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '7d' });
       return res.json({ code: 'AUTH_LOGIN_SUCCESS', message: 'Login successful', token, user: { id: user.id, email: user.email, isVerified: true, systemRole: user.systemRole || 'user' } });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 600000);
    await user.save();
    try { await sendOTPEmail(user.email, otp, user.preferredLanguage); } catch(e) { console.error(e); }
    res.json({ code: 'AUTH_OTP_SENT', message: 'Check email for OTP', user: { id: user.id, email: user.email }});
  } catch (err) {
    res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' });
  }
});

// Existing Verify OTP Route
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ code: 'AUTH_EMAIL_INVALID', message: 'Valid email is required' });
  }
  if (!otp || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ code: 'AUTH_OTP_FORMAT', message: 'OTP must be a 6-digit number' });
  }
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ code: 'AUTH_OTP_INVALID', message: 'Invalid or expired OTP' });
    }
    if (await isAccountBlocked(user)) {
      return res.status(403).json({ code: 'ACCOUNT_DISABLED', message: DISABLED_MESSAGE });
    }

    user.otp = undefined;
    user.otpExpires = undefined;
    user.isVerified = true;
    user.lastLoginAt = new Date();
    await user.save();

    const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ code: 'AUTH_LOGIN_SUCCESS', message: 'Login successful', token, user: { id: user.id, email: user.email, isVerified: true, systemRole: user.systemRole || 'user' }});
  } catch (err) {
    res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' });
  }
});

// ─── PASSWORD RESET / OTP RESEND ─────────────────────────────────────────────
// These three were stubs that returned success unconditionally while doing
// nothing — no email sent, no password changed — even though the bilingual
// templates and sendResetPasswordEmail() already existed and were imported.
//
// Two invariants apply to all three:
//   1. The response is IDENTICAL whether or not the account exists. Otherwise
//      an unauthenticated caller can enumerate registered addresses.
//   2. Email sending is wrapped in try/catch (as /register does), so a mail
//      failure never changes the HTTP response — which would leak the same
//      thing by another route.
// Both are additionally behind emailSendLimiter, keyed on the target address.

/** The stored value is a hash: a database leak must not yield usable links. */
const hashResetToken = (raw) => crypto.createHash('sha256').update(raw).digest('hex');

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;  // 1 hour — matches the email copy
const OTP_TTL_MS         = 10 * 60 * 1000;  // matches /register

router.post('/resend-otp', emailSendLimiter, async (req, res) => {
  const { email } = req.body;
  // Same response shape on every path below.
  const ack = () => res.json({ code: 'AUTH_OTP_SENT', message: 'OTP sent' });

  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ code: 'AUTH_EMAIL_INVALID', message: 'Valid email is required' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return ack();
    if (await isAccountBlocked(user)) return ack();

    user.otp = generateOTP();
    user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
    await user.save();

    try {
      await sendOTPEmail(user.email, user.otp, user.preferredLanguage);
    } catch (e) {
      console.error('[resend-otp] email failed:', e.message);
    }
    return ack();
  } catch (err) {
    console.error('[resend-otp]', err.message);
    return res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' });
  }
});

router.post('/forgot-password', emailSendLimiter, async (req, res) => {
  const { email } = req.body;
  const ack = () => res.json({ code: 'AUTH_RESET_EMAIL_SENT', message: 'Reset email sent' });

  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ code: 'AUTH_EMAIL_INVALID', message: 'Valid email is required' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return ack();
    if (await isAccountBlocked(user)) return ack();

    // The raw token goes in the email; only its hash is persisted.
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = hashResetToken(rawToken);
    user.resetPasswordExpires = new Date(Date.now() + RESET_TOKEN_TTL_MS);
    await user.save();

    try {
      await sendResetPasswordEmail(user.email, rawToken, user.preferredLanguage);
    } catch (e) {
      console.error('[forgot-password] email failed:', e.message);
    }
    return ack();
  } catch (err) {
    console.error('[forgot-password]', err.message);
    return res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  if (!token || typeof token !== 'string') {
    return res.status(400).json({ code: 'AUTH_RESET_TOKEN_INVALID', message: 'Reset token is required' });
  }
  // Same minimum the register route enforces.
  if (!password || password.length < 8) {
    return res.status(400).json({ code: 'AUTH_PASSWORD_TOO_SHORT', message: 'Password must be at least 8 characters' });
  }

  try {
    const user = await User.findOne({
      resetPasswordToken: hashResetToken(token),
      resetPasswordExpires: { $gt: new Date() },
    });
    // One code for "no such token" and "expired" alike — distinguishing them
    // would tell an attacker which tokens once existed.
    if (!user) {
      return res.status(400).json({ code: 'AUTH_RESET_TOKEN_INVALID', message: 'Invalid or expired reset token' });
    }

    // No pre-save hook hashes this field — /register and /google both hash
    // manually, and assigning plaintext here would store it in the clear.
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Single-use.
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // The login route already reads this to skip OTP for 24h; nothing wrote it
    // until now.
    user.passwordResetAt = new Date();

    // Revoke every token issued before this moment, so a reset actually locks
    // out whoever held the old session rather than leaving it valid for 7 days.
    user.tokensValidFrom = new Date();

    await user.save();
    invalidatePrincipal(user._id);   // apply on the very next request

    return res.json({ code: 'AUTH_PASSWORD_RESET', message: 'Password reset' });
  } catch (err) {
    console.error('[reset-password]', err.message);
    return res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' });
  }
});
router.get('/me', auth, async (req, res) => {
    try { const user = await User.findById(req.user.id).select('-password'); res.json(user); } 
    catch(err) { res.status(500).json({ code: 'SERVER_ERROR', message: 'Server error' }); }
});

module.exports = router;