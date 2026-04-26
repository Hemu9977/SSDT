const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const auth = require('../middleware/auth');
const Organization = require('../models/Organization');
const Invite = require('../models/Invite');
const User = require('../models/User');

// @route   POST /api/org/invite
// @desc    Invite user to organization
router.post('/invite', auth, async (req, res) => {
  try {
    const { email, role } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await User.findById(req.user.id);
    if (!user || !user.organizationId) {
      return res.status(400).json({ error: 'User does not belong to an organization' });
    }

    if (!["owner", "admin"].includes(user.role)) {
      return res.status(403).json({ error: 'Unauthorized: Only owners or admins can invite members' });
    }

    const org = await Organization.findById(user.organizationId);
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    if (org.seatsUsed >= org.seatsAllowed) {
      return res.status(403).json({ error: 'Seat limit reached for this organization' });
    }

    // Check if invite exists
    const existingInvite = await Invite.findOne({ email, organizationId: org._id, status: 'pending' });
    if (existingInvite) {
      return res.status(400).json({ error: 'An invite is already pending for this email' });
    }

    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    const invite = new Invite({
      email,
      organizationId: org._id,
      role: role || 'member',
      token,
      expiresAt
    });

    await invite.save();

    res.json({ success: true, message: 'Invite sent', token });
  } catch (err) {
    console.error('Invite error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// @route   POST /api/org/accept-invite
// @desc    Accept an organization invite
router.post('/accept-invite', auth, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    const invite = await Invite.findOne({ token, status: 'pending' });
    if (!invite) return res.status(400).json({ error: 'Invalid or expired invite' });

    if (new Date() > invite.expiresAt) {
      invite.status = 'expired';
      await invite.save();
      return res.status(400).json({ error: 'Invite expired' });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const org = await Organization.findById(invite.organizationId);
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    if (org.seatsUsed >= org.seatsAllowed) {
      return res.status(403).json({ error: 'Organization has no available seats' });
    }

    // Assign user to org
    user.organizationId = org._id;
    user.role = invite.role;
    await user.save();

    invite.status = 'accepted';
    await invite.save();

    const actualSeats = await User.countDocuments({ 
      organizationId: org._id
    });
    await Organization.updateOne(
      { _id: org._id },
      { $set: { seatsUsed: actualSeats } }
    );

    res.json({ success: true, message: 'Successfully joined organization' });
  } catch (err) {
    console.error('Accept invite error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
