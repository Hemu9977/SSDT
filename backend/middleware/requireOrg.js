// middleware/requireOrg.js
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'User not found'
      });
    }

    if (!user.organizationId) {
      return res.status(403).json({
        error: 'ORG_REQUIRED',
        message: 'You must join an organization via invite or create one via payment.',
        redirect: '/pricing'
      });
    }

    req.orgUser = user; // ✅ attach for later use
    next();

  } catch (err) {
    console.error('❌ requireOrg error:', err.message);
    res.status(500).json({
      error: 'SERVER_ERROR',
      message: 'Failed to verify organization'
    });
  }
};