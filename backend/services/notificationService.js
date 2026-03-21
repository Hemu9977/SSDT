/**
 * Notification Service
 * Handles real-time Socket.IO notifications and scan completion orchestration.
 * 
 * - initializeSocket(httpServer): Sets up Socket.IO with JWT auth
 * - emitScanCompleted(userId, payload): Sends event to specific user room
 * - handleScanComplete(scanId, userId, scanType, targetUrl): Orchestrates email + socket
 */

const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendScanCompletionEmail } = require('./emailService');

let io = null;

/**
 * Initialize Socket.IO server with JWT-based authentication.
 * Each authenticated user joins a private room keyed by their userId.
 */
function initializeSocket(httpServer) {
  io = new Server(httpServer, {
    cors: {
      origin: [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:3002'
      ],
      credentials: true
    }
  });

  // Authenticate Socket.IO connections using JWT from handshake
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
      return next(new Error('Authentication required'));
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.user?.id || decoded.id;
      if (!socket.userId) {
        return next(new Error('Invalid token payload'));
      }
      next();
    } catch (err) {
      return next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    const userId = socket.userId;
    // Join the user to their private room
    socket.join(`user_${userId}`);
    console.log(`🔌 Socket connected: user ${userId} (socket ${socket.id})`);

    socket.on('disconnect', (reason) => {
      console.log(`🔌 Socket disconnected: user ${userId} (${reason})`);
    });
  });

  console.log('✅ Socket.IO notification service initialized');
  return io;
}

/**
 * Emit a scan_completed event to a specific user's room.
 */
function emitScanCompleted(userId, payload) {
  if (!io) {
    console.warn('⚠️ Socket.IO not initialized, cannot emit scan_completed');
    return;
  }

  io.to(`user_${userId}`).emit('scan_completed', payload);
  console.log(`📢 Emitted scan_completed to user ${userId}:`, payload.scanId);
}

/**
 * Orchestrate all notifications when a scan completes.
 * 1. Lookup user details (name, email)
 * 2. Send email notification
 * 3. Emit Socket.IO event for UI popup
 */
async function handleScanComplete(scanId, userId, scanType, targetUrl) {
  const completedAt = new Date().toISOString();
  const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
  const dashboardLink = `${clientUrl}/scan/${scanId}`;

  const payload = {
    scanId,
    scanType,
    targetUrl,
    completedAt
  };

  // 1. Emit Socket.IO event (instant, non-blocking)
  emitScanCompleted(userId, payload);

  // 2. Send email notification (async, don't block on failure)
  try {
    const user = await User.findById(userId).select('name email');
    if (user && user.email) {
      await sendScanCompletionEmail(user.email, user.name || 'User', {
        scanType,
        targetUrl,
        scanId,
        completedAt,
        dashboardLink
      });
      console.log(`📧 Scan completion email sent to ${user.email}`);
    } else {
      console.warn(`⚠️ Could not find user ${userId} for email notification`);
    }
  } catch (emailError) {
    // Log but don't throw — email failure should not break the flow
    console.error('❌ Failed to send scan completion email:', emailError.message);
  }
}

/**
 * Get the Socket.IO instance (for external use if needed).
 */
function getIO() {
  return io;
}

module.exports = {
  initializeSocket,
  emitScanCompleted,
  handleScanComplete,
  getIO
};
