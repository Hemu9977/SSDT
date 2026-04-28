// backend/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { generateOTP, sendOTPEmail, sendResetPasswordEmail } = require('../services/emailService');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

console.log("✅ AUTH ROUTES LOADED - Google Login Enabled");

// GOOGLE LOGIN
router.post('/google', async (req, res) => {
  const { token, googleAccessToken } = req.body;

  try {
    let email, googleId;

    if (googleAccessToken) {
      const response = await axios.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        {
          headers: { Authorization: `Bearer ${googleAccessToken}` }
        }
      );

      email = response.data.email;
      googleId = response.data.sub;

    } else if (token) {
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID
      });

      const payload = ticket.getPayload();
      email = payload.email;
      googleId = payload.sub;

    } else {
      return res.status(400).json({ message: 'No token provided' });
    }

    let user = await User.findOne({ email: email.toLowerCase() });

    // BLOCK NEW GOOGLE SIGNUPS
    if (!user) {
      return res.status(403).json({
        error: 'ORG_REQUIRED',
        message: 'You must join an organization via invite or create one via payment.',
        redirect: '/pricing'
      });
    }

    if (!user.organizationId) {
      return res.status(403).json({
        error: 'ORG_REQUIRED',
        message: 'You must join an organization via invite or create one via payment.',
        redirect: '/pricing'
      });
    }

    if (!user.googleId) {
      user.googleId = googleId;
    }

    user.lastLoginAt = new Date();
    await user.save();

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

// DISABLE DIRECT REGISTRATION
router.post('/register', async (req, res) => {
  return res.status(403).json({
    error: 'ORG_REQUIRED',
    message: 'You must join an organization via invite or create one via payment.',
    redirect: '/pricing'
  });
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
  res.json({ message: "Reset email sent" });
});

router.post('/reset-password', async (req, res) => {
  res.json({ message: "Password reset" });
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