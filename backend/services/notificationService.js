/**
 * Notification Service
 * Handles real-time Socket.IO notifications and scan completion orchestration.
 *
 * - initializeSocket(httpServer): Sets up Socket.IO with JWT auth
 * - initializeScanProgressSubscriber(redisSubscriber): Subscribes to Redis pub/sub
 *   and forwards `scan_progress` events to the correct Socket.IO user room.
 * - emitScanCompleted(userId, payload): Sends scan_completed event to user room
 * - emitScanProgress(scanId, userId, data): Sends scan:update event to user room
 * - handleScanComplete(scanId, userId, scanType, targetUrl): Orchestrates email + socket
 */

const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendScanCompletionEmail, sendScanTriggeredEmail, sendScanFailedEmail, sendScheduleConfirmationEmail } = require('./emailService');
const { CHANNEL } = require('./scanProgressService');
const { getPublisher } = require('../config/redis');

let io = null;

/**
 * Derive a progress integer from the current DB scan state.
 * Used when replaying state to a late-joining socket client.
 */
function _deriveProgress(scan) {
  if (scan.status === 'completed') return 100;
  if (scan.status === 'failed')    return 0;
  if (scan.refinedReport)          return 95;
  const zapDone  = ['completed', 'completed_partial', 'failed'].includes(scan.zapResult?.status);
  const wchkDone = ['completed', 'completed_partial', 'completed_with_errors', 'failed'].includes(scan.webCheckResult?.status);
  if (zapDone && wchkDone)  return 85;
  if (zapDone || wchkDone)  return 70;
  if (scan.pagespeedResult) return 40;
  return 15;
}

/**
 * Initialize Socket.IO server with JWT-based authentication.
 * Each authenticated user joins a private room keyed by their userId.
 */
function initializeSocket(httpServer) {
  const socketOriginsSet = new Set(
    (process.env.FRONTEND_URL || 'http://localhost:3000')
      .split(',').map(o => o.trim()).filter(Boolean)
  );
  if (process.env.NODE_ENV !== 'production') {
    ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002']
      .forEach(o => socketOriginsSet.add(o));
  }

  io = new Server(httpServer, {
    cors: {
      origin(origin, callback) {
        if (!origin || socketOriginsSet.has(origin)) return callback(null, true);
        callback(new Error('Not allowed by CORS'));
      },
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
    // Join the user's private notification room
    socket.join(`user_${userId}`);
    console.log(`🔌 Socket connected: user ${userId} (socket ${socket.id})`);

    // Allow client to subscribe to a specific scan's progress updates.
    // Client emits: socket.emit('join:scan', { scanId })
    // Security: verify the scan belongs to this user before joining the room.
    // After joining, immediately replay the current scan state so late-connecting
    // clients don't wait blind for the next event.
    socket.on('join:scan', async ({ scanId } = {}) => {
      if (!scanId || typeof scanId !== 'string') return;
      try {
        const ScanResult = require('../models/ScanResult');
        const scan = await ScanResult.findOne(
          { analysisId: scanId, userId },
          {
            target: 1,
            status: 1, updatedAt: 1,
            pagespeedResult: 1, observatoryResult: 1, urlscanResult: 1,
            zapResult: 1, webCheckResult: 1, refinedReport: 1
          }
        );
        if (!scan) return;

        socket.join(`scan:${scanId}`);
        console.log(`🔌 Socket ${socket.id} joined scan room scan:${scanId}`);

        // Replay current state immediately — prefer Redis state snapshot (single source
        // of truth for live progress), but fall back to DB-derived values.
        let redisState = null;
        try {
          const raw = await getPublisher().get(`scan:${scanId}`);
          if (raw) redisState = JSON.parse(raw);
        } catch (e) {
          // best-effort only
        }

        if (redisState && redisState.userId === String(userId)) {
          socket.emit('scan:update', {
            scanId,
            target: scan.target,
            status: redisState.status,
            progress: redisState.progress,
            message: redisState.message,
            error: redisState.error,
            modules: redisState.modules,
            updatedAt: redisState.updatedAt
          });
          return;
        }

        socket.emit('scan:update', {
          scanId,
          target:           scan.target,
          status:           scan.status,
          progress:         _deriveProgress(scan),
          hasPagespeed:     !!(scan.pagespeedResult && !scan.pagespeedResult.error),
          hasObservatory:   !!(scan.observatoryResult && !scan.observatoryResult.error),
          hasUrlscan:       !!(scan.urlscanResult && !scan.urlscanResult.error),
          zapStatus:        scan.zapResult?.status   || null,
          webCheckStatus:   scan.webCheckResult?.status || null,
          hasAiReport:      !!scan.refinedReport,
          updatedAt:        scan.updatedAt
        });
      } catch (err) {
        console.error('[Socket] join:scan error:', err.message);
      }
    });

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
 * Emit a real-time scan:update event to the user's room AND the scan-specific room.
 * Called directly (in-process) or indirectly via Redis pub/sub (worker process).
 *
 * @param {string} scanId
 * @param {string} userId
 * @param {object} data - { status, progress, message, ...partial results }
 */
function emitScanProgress(scanId, userId, data) {
  if (!io) return;
  const payload = { scanId, ...data };

  // ── Shape payload for frontend & prevent huge payloads from disconnecting Socket.io (max 1MB) ──
  if (payload.pagespeedResult) {
    const categories = payload.pagespeedResult.lighthouseResult?.categories || {};
    payload.psiScores = !payload.pagespeedResult.error ? {
      performance:   categories.performance?.score   != null ? Math.round(categories.performance.score * 100)   : null,
      accessibility: categories.accessibility?.score  != null ? Math.round(categories.accessibility.score * 100)  : null,
      bestPractices: categories['best-practices']?.score != null ? Math.round(categories['best-practices'].score * 100) : null,
      seo:           categories.seo?.score            != null ? Math.round(categories.seo.score * 100)            : null
    } : null;
    payload.hasPagespeed = !payload.pagespeedResult.error;
    delete payload.pagespeedResult;
  }
  
  if (payload.observatoryResult) {
    payload.observatoryData = !payload.observatoryResult.error ? {
      grade: payload.observatoryResult.grade, score: payload.observatoryResult.score,
      tests_passed: payload.observatoryResult.tests_passed, tests_failed: payload.observatoryResult.tests_failed,
      tests_quantity: payload.observatoryResult.tests_quantity
    } : null;
    payload.hasObservatory = !payload.observatoryResult.error;
    delete payload.observatoryResult;
  }

  if (payload.urlscanResult) {
    payload.urlscanData = !payload.urlscanResult.error ? {
      uuid: payload.urlscanResult.uuid, verdicts: payload.urlscanResult.verdicts,
      page: payload.urlscanResult.page, stats: payload.urlscanResult.stats,
      screenshot: payload.urlscanResult.screenshot, reportUrl: payload.urlscanResult.reportUrl
    } : null;
    payload.hasUrlscan = !payload.urlscanResult.error;
    delete payload.urlscanResult;
  }

  if (payload.zapResult) {
    const zs = payload.zapResult.status;
    if (zs === 'completed' || zs === 'completed_partial') {
      payload.zapData = { status: zs, riskCounts: payload.zapResult.riskCounts || {}, alerts: payload.zapResult.alerts || [], totalAlerts: payload.zapResult.totalAlerts || 0, totalOccurrences: payload.zapResult.totalOccurrences || 0, reportFiles: payload.zapResult.reportFiles || [], site: payload.zapResult.site, urlsFound: payload.zapResult.urlsFound || 0 };
    } else if (zs === 'pending' || zs === 'running') {
      payload.zapData = { status: zs, phase: payload.zapResult.phase || 'queued', progress: payload.zapResult.progress || 0, message: payload.zapResult.message || 'ZAP scan in progress...', urlsFound: payload.zapResult.urlsFound || 0, alertsFound: payload.zapResult.alertsFound || 0 };
    } else if (zs === 'failed') {
      payload.zapData = { status: 'failed', error: payload.zapResult.error || 'ZAP scan failed', message: payload.zapResult.message || 'Vulnerability scan encountered an error' };
    }
    payload.zapStatus = zs;
    delete payload.zapResult;
  }

  if (payload.webCheckResult) {
    const ws = payload.webCheckResult.status;
    if (['completed','completed_with_errors','completed_partial'].includes(ws)) {
      payload.webCheckData = { status: ws, results: payload.webCheckResult.summary || {}, summary: payload.webCheckResult.summary || {}, completedScans: payload.webCheckResult.completedScans || 0, totalScans: payload.webCheckResult.totalScans || 30, hasErrors: payload.webCheckResult.hasErrors || false, duration: payload.webCheckResult.duration || 0 };
    } else if (ws === 'uploading') {
      payload.webCheckData = { status: 'uploading', progress: 100, uploadProgress: payload.webCheckResult.uploadProgress || 0, completedScans: payload.webCheckResult.completedScans || payload.webCheckResult.totalScans, totalScans: payload.webCheckResult.totalScans || 30, message: payload.webCheckResult.message || 'Uploading results to storage...' };
    } else if (ws === 'running' || ws === 'pending') {
      payload.webCheckData = { status: 'running', progress: payload.webCheckResult.progress || 0, completedScans: payload.webCheckResult.completedScans || 0, totalScans: payload.webCheckResult.totalScans || 30, message: payload.webCheckResult.message || 'WebCheck scans in progress...', partialResults: payload.webCheckResult.partialResults || {} };
    } else if (ws === 'failed') {
      payload.webCheckData = { status: 'failed', error: payload.webCheckResult.error || 'WebCheck scan failed', message: payload.webCheckResult.message || 'WebCheck encountered an error' };
    }
    payload.webCheckStatus = ws;
    delete payload.webCheckResult;
  }

  // Ensure timestamp is always present on the payload
  payload.timestamp = payload.timestamp || Date.now();

  // Deliver to both rooms so the client can listen on either
  io.to(`user_${userId}`).emit('scan:update', payload);
  io.to(`scan:${scanId}`).emit('scan:update', payload);
  console.log(`[Socket] Progress event sent... (timestamp: ${payload.timestamp})`);
}

/**
 * Subscribe to the Redis `scan_progress` pub/sub channel and forward each
 * message to Socket.IO.  Call this once during server startup after both
 * Socket.IO and Redis are ready.
 *
 * @param {Redis} subscriber - A dedicated ioredis client in subscribe mode
 */
function initializeScanProgressSubscriber(subscriber) {
  const doSubscribe = () => {
    subscriber.subscribe(CHANNEL, (err) => {
      if (err) {
        console.error('[NotificationService] Failed to subscribe to scan_progress:', err.message);
      } else {
        console.log('[Redis] Subscriber resubscribed...');
      }
    });
  };

  // Subscribe immediately if ready, or when it becomes ready
  subscriber.on('ready', () => {
    console.log('[NotificationService] Subscriber ready event received. Subscribing...');
    doSubscribe();
  });

  if (subscriber.status === 'ready') {
    doSubscribe();
  }

  subscriber.on('message', (_channel, raw) => {
    try {
      const data = JSON.parse(raw);
      const { scanId, userId, ...rest } = data;
      if (scanId && userId) {
        emitScanProgress(scanId, userId, rest);
      }
    } catch (e) {
      console.error('[NotificationService] Bad scan_progress message:', e.message);
    }
  });
}

/**
 * Orchestrate all notifications when a scan completes.
 * 1. Lookup user details (name, email)
 * 2. Send email notification
 * 3. Emit Socket.IO event for UI popup
 */
async function handleScanComplete(scanId, userId, scanType, targetUrl) {
  const completedAt = new Date().toISOString();
  const clientUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').split(',')[0].trim();
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
    const user = await User.findById(userId).select('name email preferredLanguage');
    if (user && user.email) {
      await sendScanCompletionEmail(user.email, user.name || 'User', {
        scanType,
        targetUrl,
        scanId,
        completedAt,
        dashboardLink
      }, user.preferredLanguage);
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
    const user = await User.findById(userId).select('name email preferredLanguage');
    if (user && user.email) {
      await sendScanTriggeredEmail(user.email, user.name || 'User', {
        scanType,
        targetUrl,
        scheduledFor,
        startedAt
      }, user.preferredLanguage);
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
    const user = await User.findById(userId).select('name email preferredLanguage');
    if (user && user.email) {
      await sendScanFailedEmail(user.email, user.name || 'User', {
        scanType,
        targetUrl,
        scanId,
        failureReason
      }, user.preferredLanguage);
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
    const user = await User.findById(userId).select('name email preferredLanguage');
    if (user && user.email) {
      await sendScheduleConfirmationEmail(user.email, user.name || 'User', {
        scanType: 'Security Scan',
        targetUrl,
        scheduleType,
        displayTime
      }, user.preferredLanguage);
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
  initializeScanProgressSubscriber,
  emitScanCompleted,
  emitScanProgress,
  emitScanStarted,
  handleScanComplete,
  handleScheduledScanTriggered,
  handleScanFailed,
  handleScheduleCreated,
  getIO
};
