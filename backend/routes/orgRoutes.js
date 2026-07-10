/**
 * backend/routes/orgRoutes.js
 *
 * Organization invite flow — complete, production-grade implementation.
 *
 * Routes:
 *   POST /api/org/invite              - Send invite (owner/admin only)
 *   GET  /api/org/invite/:token       - Validate invite token (public)
 *   POST /api/org/accept-invite       - Accept invite (logged-in OR new user)
 *   DELETE /api/org/invite/:token     - Cancel/revoke invite (owner/admin only)
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { getFrontendBaseUrl } = require('../utils/frontendUrl');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');
const requireOrg = require('../middleware/requireOrg');
const Organization = require('../models/Organization');
const Invite = require('../models/Invite');
const User = require('../models/User');
const { sendInviteEmail } = require('../services/emailService');

// ─── POST /api/org/invite ─────────────────────────────────────────────────────
// Send an invite. Only owners or admins can invite. Fires email delivery.
router.post('/invite', auth, async (req, res) => {
  try {
    const { email, role = 'member' } = req.body;

    if (!email) return res.status(400).json({ error: 'Email is required' });

    const allowedRoles = ['admin', 'member'];
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Role must be "admin" or "member"' });
    }

    const inviter = await User.findById(req.user.id);
    if (!inviter || !inviter.organizationId) {
      return res.status(400).json({ error: 'User does not belong to an organization' });
    }

    // Only owners and admins can invite
    if (!['owner', 'admin'].includes(inviter.role)) {
      return res.status(403).json({ error: 'Only owners or admins can invite members' });
    }

    // Only owners can invite admins
    if (role === 'admin' && inviter.role !== 'owner') {
      return res.status(403).json({ error: 'Only owners can invite admins' });
    }

    const org = await Organization.findById(inviter.organizationId);
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    // Check seat availability including pending invites
    const pendingInvitesCount = await Invite.countDocuments({ 
      organizationId: org._id, 
      status: 'pending' 
    });
    if (org.seatsUsed + pendingInvitesCount >= org.seatsAllowed) {
      return res.status(403).json({ error: 'Seat limit reached for this organization. Upgrade your plan to add more members.' });
    }

    // Block if email already belongs to an org member
    const existingMember = await User.findOne({ email: email.toLowerCase(), organizationId: org._id });
    if (existingMember) {
      return res.status(400).json({ error: 'This user is already a member of your organization' });
    }

    // Cancel any pre-existing pending invite for this email + org (re-invite replaces old)
    await Invite.deleteOne({ email: email.toLowerCase(), organizationId: org._id, status: 'pending' });

    // Generate token and expiry
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    const invite = new Invite({
      email: email.toLowerCase(),
      organizationId: org._id,
      role,
      token,
      expiresAt
    });
    await invite.save();

    // Send invite email — non-blocking (don't fail invite creation if email fails)
    try {
      await sendInviteEmail(email.toLowerCase(), {
        orgName: org.name,
        inviterName: inviter.name,
        role,
        token
      });
    } catch (emailErr) {
      console.error('⚠️  Invite created but email delivery failed:', emailErr.message);
      // Still return success — token is valid, inviter can share link manually
      return res.json({
        success: true,
        message: 'Invite created. Email delivery failed — share the link manually.',
        joinLink: `${getFrontendBaseUrl()}/join?token=${token}`,
        emailDelivered: false
      });
    }

    res.json({
      success: true,
      message: `Invite sent to ${email}`,
      joinLink: `${getFrontendBaseUrl()}/join?token=${token}`,
      emailDelivered: true
    });
  } catch (err) {
    console.error('Invite error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── GET /api/org/invite/:token ───────────────────────────────────────────────
// Public route — validate a token and return org/role info for the join page.
router.get('/invite/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const invite = await Invite.findOne({ token });

    if (!invite) {
      return res.status(404).json({ error: 'Invalid invite link. It may have already been used or does not exist.' });
    }

    if (invite.status === 'accepted') {
      return res.status(400).json({ error: 'This invite has already been accepted.' });
    }

    if (new Date() > invite.expiresAt) {
      // Mark expired if not already
      if (invite.status === 'pending') {
        invite.status = 'expired';
        await invite.save();
      }
      return res.status(400).json({ error: 'This invite has expired. Ask your team admin for a new invite.' });
    }

    const org = await Organization.findById(invite.organizationId).select('name planType seatsAllowed seatsUsed');
    if (!org) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    res.json({
      success: true,
      invite: {
        email: invite.email,
        role: invite.role,
        orgName: org.name,
        orgPlan: org.planType,
        expiresAt: invite.expiresAt
      }
    });
  } catch (err) {
    console.error('Invite validate error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── POST /api/org/accept-invite ─────────────────────────────────────────────
// Accepts an invite. Supports two flows:
//   1. Logged-in user:  { token }  — header: x-auth-token
//   2. New user:        { token, name, password }  — no auth header required
router.post('/accept-invite', async (req, res) => {
  try {
    const { token, name, password } = req.body;
    if (!token) return res.status(400).json({ error: 'Invite token is required' });

    // ── Validate and atomically accept invite ──────────────────────────────
    const invite = await Invite.findOneAndUpdate(
      { token, status: 'pending', expiresAt: { $gt: new Date() } },
      { status: 'accepted' },
      { new: true }
    );
    if (!invite) {
      return res.status(400).json({ error: 'Invalid, expired, or already accepted invite token' });
    }

    const org = await Organization.findById(invite.organizationId);
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    // ── Resolve user (logged-in or new registration) ──────────────────────
    let user = null;

    // Check for auth token in headers (logged-in flow)
    const authHeader = req.header('Authorization') || '';
    const legacyToken = req.header('x-auth-token') || '';
    const rawJwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : legacyToken;

    if (rawJwt) {
      try {
        const decoded = jwt.verify(rawJwt, process.env.JWT_SECRET);
        user = await User.findById(decoded.user.id);
      } catch (_) {
        // Token invalid — fall through to new-user registration path
      }
    }

    if (!user) {
      // ── New user registration path ─────────────────────────────────────
      if (!name || !password) {
        return res.status(400).json({
          error: 'Please provide your name and password to create an account',
          requiresRegistration: true
        });
      }

      // Check if email already exists (user registered separately)
      const existingByEmail = await User.findOne({ email: invite.email });
      if (existingByEmail) {
        // User exists but didn't use auth token — tell frontend to log in first
        return res.status(409).json({
          error: 'An account with this email already exists. Please log in to accept the invite.',
          requiresLogin: true,
          email: invite.email
        });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      user = new User({
        name: name.trim(),
        email: invite.email,
        password: hashedPassword,
        isVerified: true, // Email is confirmed via invite
        accountType: 'free',
        lastLoginAt: new Date()
      });
      await user.save();
    }

    // ── Guard: invite is scoped to one email ──────────────────────────────
    // The new-user path creates the account with invite.email so it always
    // matches; this primarily protects the logged-in path, where a different
    // authenticated user must not be able to consume an invite (and its seat)
    // that was addressed to someone else.
    if ((user.email || '').toLowerCase() !== invite.email.toLowerCase()) {
      // The invite was atomically flipped to 'accepted' above; since this caller
      // is not the intended recipient, release it back to 'pending' so the real
      // invitee can still use it.
      await Invite.updateOne({ _id: invite._id, status: 'accepted' }, { $set: { status: 'pending' } });
      return res.status(403).json({
        error: 'This invite was sent to a different email address. Log in with the invited email to accept it.',
        invitedEmail: invite.email
      });
    }

    // ── Guard: user already in an org ─────────────────────────────────────
    if (user.organizationId && user.organizationId.toString() === org._id.toString()) {
      return res.status(400).json({ error: 'You are already a member of this organization' });
    }
    if (user.organizationId && user.organizationId.toString() !== org._id.toString()) {
      return res.status(400).json({ error: 'You already belong to a different organization. Contact support to transfer.' });
    }

    // ── Seat check ────────────────────────────────────────────────────────
    if (org.seatsUsed >= org.seatsAllowed) {
      return res.status(403).json({ error: 'This organization has no available seats' });
    }

    // ── Assign user to org ────────────────────────────────────────────────
    user.organizationId = org._id;
    user.role = invite.role;
    await user.save();

    // ── Mark invite accepted ──────────────────────────────────────────────
    // Invite is already marked accepted atomically above

    // ── Update seatsUsed (recount from DB for accuracy) ──────────────────
    const actualSeats = await User.countDocuments({ organizationId: org._id });
    await Organization.updateOne({ _id: org._id }, { $set: { seatsUsed: actualSeats } });

    // ── Issue JWT so frontend can log user in immediately ─────────────────
    const jwtToken = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      message: `Welcome to ${org.name}!`,
      token: jwtToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        organizationId: org._id
      }
    });
  } catch (err) {
    console.error('Accept invite error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── DELETE /api/org/invite/:token ───────────────────────────────────────────
// Cancel a pending invite. Only owners and admins can do this.
router.delete('/invite/:token', auth, async (req, res) => {
  try {
    const { token } = req.params;

    const inviter = await User.findById(req.user.id);
    if (!inviter || !['owner', 'admin'].includes(inviter.role)) {
      return res.status(403).json({ error: 'Only owners or admins can cancel invites' });
    }

    const invite = await Invite.findOne({ token, organizationId: inviter.organizationId });
    if (!invite) return res.status(404).json({ error: 'Invite not found' });
    if (invite.status !== 'pending') return res.status(400).json({ error: 'This invite is no longer active' });

    await Invite.deleteOne({ _id: invite._id });
    res.json({ success: true, message: 'Invite cancelled' });
  } catch (err) {
    console.error('Cancel invite error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
