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
const { sendScanCompletionEmail, sendScanTriggeredEmail, sendScanFailedEmail, sendScheduleConfirmationEmail } = require('./emailService');

let io = null;

/**
 * Initialize Socket.IO server with JWT-based authentication.
 * Each authenticated user joins a private room keyed by their userId.
 */
function initializeSocket(httpServer) {
  io = new Server(httpServer, {
    cors: {
      origin: [
        process.env.FRONTEND_URL || 'http://localhost:3000',
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
  const clientUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
  let dashboardLink = `${clientUrl}/scan/${scanId}`;

  // 0. Fetch scan result to check triggerSource
  const ScanResult = require('../models/ScanResult');
  const scan = await ScanResult.findOne({ analysisId: scanId });
  const isScheduled = scan && scan.triggerSource === 'scheduled';

  // If scheduled, append ?lang=en to force English report as requested
  if (isScheduled) {
    dashboardLink += '?lang=en';
  }

  const payload = {
    scanId,
    scanType,
    targetUrl,
    completedAt,
    triggerSource: scan ? scan.triggerSource : 'manual',
    isScheduled
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
      console.log(`📧 Scan completion email sent to ${user.email} (Link: ${dashboardLink})`);
    } else {
      console.warn(`⚠️ Could not find user ${userId} for email notification`);
    }
  } catch (emailError) {
    // Log but don't throw — email failure should not break the flow
    console.error('❌ Failed to send scan completion email:', emailError.message);
  }
}

/**
 * Handle a scheduled scan getting triggered
 * Sends an email notification to let the user know the scan has started.
 */
async function handleScheduledScanTriggered(userId, scanType, targetUrl, scheduledFor, startedAt) {
  try {
    const user = await User.findById(userId).select('name email');
    if (user && user.email) {
      await sendScanTriggeredEmail(user.email, user.name || 'User', {
        scanType,
        targetUrl,
        scheduledFor,
        startedAt
      });
      console.log(`📧 Scan triggered email sent to ${user.email}`);
    }
  } catch (err) {
    console.error('❌ Failed to send scan triggered email:', err.message);
  }
}

/**
 * Handle a scheduled scan failure
 * Sends an email notification describing the failure.
 */
async function handleScanFailed(scanId, userId, scanType, targetUrl, failureReason) {
  try {
    const user = await User.findById(userId).select('name email');
    if (user && user.email) {
      await sendScanFailedEmail(user.email, user.name || 'User', {
        scanType,
        targetUrl,
        scanId,
        failureReason
      });
      console.log(`📧 Scan failed email sent to ${user.email}`);
    }
  } catch (err) {
    console.error('❌ Failed to send scan failure email:', err.message);
  }
}

/**
 * Emit a scan_started event to a specific user's room.
 */
function emitScanStarted(userId, payload) {
  if (!io) return;
  io.to(`user_${userId}`).emit('scan_started', payload);
  console.log(`📢 Emitted scan_started to user ${userId}:`, payload.scanId);
}

/**
 * Get the Socket.IO instance (for external use if needed).
 */
function getIO() {
  return io;
}

/**
 * Handle a scan being successfully scheduled
 */
async function handleScheduleCreated(userId, targetUrl, scheduleType, displayTime) {
  try {
    const user = await User.findById(userId).select('name email');
    if (user && user.email) {
      await sendScheduleConfirmationEmail(user.email, user.name || 'User', {
        scanType: 'Security Scan',
        targetUrl,
        scheduleType,
        displayTime
      });
    }
    
    // Also emit a socket event if needed for instant UI feedback
    if (io) {
      io.to(`user_${userId}`).emit('schedule_created', {
        targetUrl,
        scheduleType,
        displayTime,
        timestamp: new Date()
      });
    }
  } catch (err) {
    console.error('❌ Failed to handle schedule created notification:', err.message);
  }
}

module.exports = {
  initializeSocket,
  emitScanCompleted,
  emitScanStarted,
  handleScanComplete,
  handleScheduledScanTriggered,
  handleScanFailed,
  handleScheduleCreated,
  getIO
};
