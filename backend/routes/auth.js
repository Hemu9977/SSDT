// backend/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');
const crypto = require('crypto');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { generateOTP, sendOTPEmail, sendResetPasswordEmail } = require('../services/emailService');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

console.log("✅ AUTH ROUTES LOADED - Google Login Enabled");

// GOOGLE LOGIN
router.post('/google', async (req, res) => {
  const { token, googleAccessToken } = req.body;

  try {
    let email, googleId, name;

    if (googleAccessToken) {
      const response = await axios.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        {
          headers: { Authorization: `Bearer ${googleAccessToken}` }
        }
      );

      email = response.data.email;
      googleId = response.data.sub;
      name = response.data.name || email.split('@')[0];

    } else if (token) {
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID
      });

      const payload = ticket.getPayload();
      email = payload.email;
      googleId = payload.sub;
      name = payload.name || email.split('@')[0];

    } else {
      return res.status(400).json({ message: 'No token provided' });
    }

    let user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      user = new User({
        name,
        email: email.toLowerCase(),
        googleId,
        isVerified: true,
        accountType: 'free'
      });
      await user.save();
    } else {
      if (!user.googleId) {
        user.googleId = googleId;
      }
      user.lastLoginAt = new Date();
      await user.save();
    }

    const jwtToken = jwt.sign(
      { user: { id: user.id } },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Google login successful',
      token: jwtToken,
      user: {
        id: user.id,
        email: user.email,
        isVerified: user.isVerified
      }
    });

  } catch (err) {
    console.error('Google Auth Error:', err.message);
    res.status(500).json({
      message: 'Google authentication failed'
    });
  }
});

// REGISTER
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email: email.toLowerCase() });

    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const otp = generateOTP();

    user = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      accountType: 'free',
      otp,
      otpExpires: new Date(Date.now() + 600000)
    });

    await user.save();

    try {
      await sendOTPEmail(user.email, otp);
    } catch (e) {
      console.error('Failed to send OTP email during registration:', e);
    }

    res.status(201).json({
      message: 'Registration successful. Check your email for the OTP.'
    });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const recentlyReset =
      user.passwordResetAt &&
      (new Date() - user.passwordResetAt) < 86400000;

    if (recentlyReset) {
      const token = jwt.sign(
        { user: { id: user.id } },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          email: user.email,
          isVerified: true
        }
      });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 600000);

    await user.save();

    try {
      await sendOTPEmail(user.email, otp);
    } catch (e) {
      console.error(e);
    }

    res.json({
      message: 'Check email for OTP',
      user: {
        id: user.id,
        email: user.email
      }
    });

  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// VERIFY OTP
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({
        message: 'Invalid or expired OTP'
      });
    }

    user.otp = undefined;
    user.otpExpires = undefined;
    user.isVerified = true;
    user.lastLoginAt = new Date();

    await user.save();

    const token = jwt.sign(
      { user: { id: user.id } },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        isVerified: true
      }
    });

  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

router.post('/resend-otp', async (req, res) => {
  res.json({ message: "OTP sent" });
});

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.json({ message: "If that email exists, a reset link has been sent." });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
    await user.save();

    try {
      await sendResetPasswordEmail(user.email, resetToken);
    } catch (e) {
      console.error('Failed to send reset email:', e);
    }

    res.json({ message: "If that email exists, a reset link has been sent." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ message: 'Token and new password required' });

  try {
    const user = await User.findOne({ 
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.passwordResetAt = new Date();
    await user.save();

    res.json({ message: "Password successfully reset. You can now log in." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;