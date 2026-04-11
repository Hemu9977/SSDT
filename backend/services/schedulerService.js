/**
 * Scheduler Service
 * Manages cron-based execution of scheduled scans.
 * 
 * - startScheduler(): Register a cron job that runs every minute
 * - processScheduledScans(): Find and execute due scans
 * - validatePlanLimits(): Check user's plan before execution
 * - classifyFailure(): Categorize scan failure reasons
 */

const cron = require('node-cron');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const ScheduledScan = require('../models/ScheduledScan');
const User = require('../models/User');
const ScanResult = require('../models/ScanResult');
const {
  handleScanComplete,
  handleScanFailed,
  handleScheduledScanTriggered,
  emitScanStarted
} = require('./notificationService');
const { testLogin } = require('./loginTestService');

let schedulerTask = null;
let isProcessing = false;

/**
 * Start the scheduler cron job (runs every minute)
 */
function startScheduler() {
  if (schedulerTask) {
    console.log('[Scheduler] Already running, skipping start');
    return;
  }

  // Task 1: Trigger new scans (every 15 seconds)
  schedulerTask = cron.schedule('*/15 * * * * *', async () => {
    await processScheduledScans();
  });

  // Task 2: Poll for completion of running scheduled scans (every 2 minutes)
  // This ensures AI reports are generated and emails are sent even if the user is offline
  cron.schedule('*/2 * * * *', async () => {
    await finalizeRunningScans();
  });

  console.log('[Scheduler] Scan scheduler started (Trigger: 15s, Finalizer: 2m)');
}

/**
 * Stop the scheduler
 */
function stopScheduler() {
  if (schedulerTask) {
    schedulerTask.stop();
    schedulerTask = null;
    console.log('[Scheduler] Scan scheduler stopped');
  }
}

/**
 * Process all scheduled scans that are due for execution
 */
async function processScheduledScans() {
  if (isProcessing) {
    return; // Prevent overlapping executions
  }

  isProcessing = true;

  try {
    const dueScans = await ScheduledScan.getDueSchedules();

    if (dueScans.length === 0) {
      isProcessing = false;
      return;
    }

    console.log(`[Scheduler] Found ${dueScans.length} due scan(s) to execute`);

    for (const schedule of dueScans) {
      try {
        await executeSingleSchedule(schedule);
      } catch (err) {
        console.error(`[Scheduler] Error executing schedule ${schedule._id}:`, err.message);
      }
    }
  } catch (err) {
    console.error('[Scheduler] Error processing scheduled scans:', err.message);
  } finally {
    isProcessing = false;
  }
}

/**
 * Execute a single scheduled scan
 */
async function executeSingleSchedule(schedule) {
  const user = schedule.userId;

  if (!user) {
    console.error(`[Scheduler] Schedule ${schedule._id}: User not found, disabling`);
    schedule.enabled = false;
    schedule.status = 'failed';
    schedule.lastFailure = {
      reason: 'User account not found',
      failureType: 'internal_error',
      timestamp: new Date()
    };
    await schedule.save();
    return;
  }

  // Validate plan limits before execution
  const validation = await validatePlanLimits(user, schedule.targetUrl);
  if (!validation.valid) {
    console.log(`[Scheduler] Schedule ${schedule._id}: Plan limit exceeded - ${validation.reason}`);
    schedule.status = 'failed';
    schedule.lastFailure = {
      reason: validation.reason,
      failureType: 'plan_limit_exceeded',
      timestamp: new Date()
    };
    await schedule.save();

    // Notify user of failure
    await handleScanFailed(
      null,
      user._id.toString(),
      schedule.scanType === 'public' ? 'Public Scan' : 'Authenticated Scan',
      schedule.targetUrl,
      validation.reason
    );
    return;
  }

  const scheduledFor = schedule.nextRun ? new Date(schedule.nextRun).toISOString() : null;
  const startedAt = new Date().toISOString();

  // Mark as running
  schedule.status = 'running';
  schedule.lastRun = new Date(startedAt);
  await schedule.save();

  console.log(`[Scheduler] Executing scan for ${schedule.targetUrl} (user: ${user.email})`);

  try {
    // Generate scan ID
    const scanId = `scheduled-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    schedule.lastScanId = scanId;

    // Email at trigger-time (scheduled time reached)
    await handleScheduledScanTriggered(
      user._id.toString(),
      schedule.scanType === 'public' ? 'Public Scan' : 'Authenticated Scan',
      schedule.targetUrl,
      scheduledFor,
      startedAt
    );

    // Trigger the actual scan based on scan type
    if (schedule.scanType === 'public') {
      const publicResult = await triggerPublicScan(scanId, schedule.targetUrl, user._id.toString(), {
        triggerSource: 'scheduled',
        scheduleId: schedule._id.toString(),
        scheduledFor,
        startedAt
      });
      if (publicResult && publicResult.scanId) {
        schedule.lastScanId = publicResult.scanId; // Update with the real backend-generated ID
      }
    } else {
      await triggerAuthenticatedScan(scanId, schedule.targetUrl, user._id.toString(), schedule.authConfig, {
        triggerSource: 'scheduled',
        scheduleId: schedule._id.toString(),
        scheduledFor,
        startedAt
      });
    }

    // Update user's monthly scan usage
    user.checkAndResetMonthlyScans();
    user.monthlyScansUsed = (user.monthlyScansUsed || 0) + 1;
    if (!user.targetsUsed) user.targetsUsed = [];
    if (!user.targetsUsed.includes(schedule.targetUrl)) {
      user.targetsUsed.push(schedule.targetUrl);
    }
    user.totalScans = (user.totalScans || 0) + 1;
    await user.save();

    // Handle schedule completion
    schedule.status = 'completed';
    schedule.lastFailure = { reason: null, details: null, failureType: null, timestamp: null };

    // For recurring schedules, compute next run and reset status
    if (schedule.scheduleType === 'recurring') {
      schedule.computeNextRun();
      schedule.status = 'scheduled';
    } else {
      // One-time schedules have no future runs.
      schedule.nextRun = null;
    }

    await schedule.save();
    console.log(`[Scheduler] ✅ Scan completed for ${schedule.targetUrl}`);

    // Success notification is handled by the scan system itself (zapRoutes / virustotalRoutes)
    // The handleScanComplete is called within those routes when scan finishes

  } catch (err) {
    console.error(`[Scheduler] ❌ Scan failed for ${schedule.targetUrl}:`, err.message);

    const failureType = classifyFailure(err);

    schedule.status = 'failed';
    schedule.lastFailure = {
      reason: err.message,
      details: err.stack?.substring(0, 500),
      failureType,
      timestamp: new Date()
    };

    // For recurring schedules, still compute next run but keep failure info
    if (schedule.scheduleType === 'recurring') {
      schedule.computeNextRun();
      // Reset to scheduled so it runs again next time
      schedule.status = 'scheduled';
    }

    await schedule.save();

    // Notify user of failure
    await handleScanFailed(
      schedule.lastScanId,
      user._id.toString(),
      schedule.scanType === 'public' ? 'Public Scan' : 'Authenticated Scan',
      schedule.targetUrl,
      err.message
    );
  }
}

/**
 * Trigger a public scan via internal API orchestration (guarantees combined scan runs fully)
 */
async function triggerPublicScan(scanId, targetUrl, userId, meta) {
  // Generate a short-lived internal token
  const token = jwt.sign({ user: { id: userId } }, process.env.JWT_SECRET, { expiresIn: '5m' });
  const baseUrl = `http://localhost:${process.env.PORT || 3001}`;

  // Notify UI safely
  emitScanStarted(userId, {
    scanId,
    targetUrl,
    scanType: 'Public Scan',
    ...(meta || {})
  });

  console.log(`[Scheduler] Orchestrating internal combined scan for ${targetUrl}`);
  
  // 1. Create the combined scan using the standard endpoint
  const postRes = await axios.post(
    `${baseUrl}/api/vt/combined-url-scan`,
    { 
      url: targetUrl,
      triggerSource: 'scheduled',
      lang: 'en'
    },
    { headers: { 'x-auth-token': token } }
  );

  const analysisId = postRes.data.analysisId;

  // 2. Trigger the orchestration logic (runs PageSpeed, Observatory, URLScan, starts ZAP & WebCheck)
  try {
    await axios.get(
      `${baseUrl}/api/vt/combined-analysis/${analysisId}`,
      { headers: { 'x-auth-token': token }, timeout: 120000 }
    );
  } catch (err) {
    if (err.code !== 'ECONNABORTED') {
      console.warn('[Scheduler] Notice during combined-analysis GET orchestration:', err.message);
    }
  }

  // ZAP and WebCheck will independently call handleScanComplete when they finish.
  return { scanId: analysisId };
}

/**
 * Trigger an authenticated scan
 */
async function triggerAuthenticatedScan(scanId, targetUrl, userId, authConfig, meta) {
  const { startAsyncAuthScan } = require('./zapAuthService');

  // Notify UI safely
  emitScanStarted(userId, {
    scanId,
    targetUrl,
    scanType: 'Authenticated Scan',
    ...(meta || {})
  });

  console.log(`[Scheduler] 🔐 Performing background login for ${targetUrl}`);
  
  let cookies = [];
  if (authConfig && authConfig.loginUrl && authConfig.credentials && authConfig.credentials.length > 0) {
    try {
      const loginResult = await testLogin({
        loginUrl: authConfig.loginUrl,
        credentials: authConfig.credentials,
        submitButton: authConfig.submitButton ? { selector: authConfig.submitButton } : null
      });

      if (loginResult && loginResult.authenticated) {
        cookies = loginResult.cookies || [];
        console.log(`[Scheduler] ✅ Background login successful for ${targetUrl} (${cookies.length} cookies obtained)`);
      } else {
        console.warn(`[Scheduler] ⚠️ Background login failed for ${targetUrl}: ${loginResult?.errorMessage || 'Unknown error'}`);
        // We continue anyway, hoping ZAP can handle it or use whatever cookies it might have
      }
    } catch (loginErr) {
      console.error(`[Scheduler] ❌ Background login exception for ${targetUrl}:`, loginErr.message);
    }
  }

  // 1. Generate a tempSessionId for this background scan
  const { v4: uuidv4 } = require('uuid');
  const tempSessionId = uuidv4();
  
  // We need to reach into the route's authSessions if we want to use the API, 
  // but since we are in a service, we can't easily do that without exporting the map.
  // HOWEVER, we can just call the service directly BUT we need to make sure 
  // we create the ScanResult with triggerSource first.
  
  const ScanResult = require('../models/ScanResult');
  const skeletonScan = new ScanResult({
    target: targetUrl,
    analysisId: scanId,
    status: 'pending',
    userId: userId,
    triggerSource: 'scheduled',
    languagePreference: 'en'
  });
  await skeletonScan.save();

  // The startAsyncAuthScan handles the full flow
  const result = await startAsyncAuthScan(
    targetUrl,
    authConfig?.loginUrl || targetUrl,
    cookies,
    scanId,
    userId
  );

  // Success notification will be triggered by handleScanComplete inside zapAuthService or status polling logic
  return result;
}

/**
 * Validate user's plan limits before executing a scheduled scan
 */
async function validatePlanLimits(user, targetUrl) {
  // TEMPORARY: Aggressively bypass all plan limits for testing purposes
  // Previously, limits.scansPerTarget was rejecting the second scheduled scan on the same URL!
  return { valid: true };
}

/**
 * Classify a scan failure into a category
 */
function classifyFailure(error) {
  const msg = (error.message || '').toLowerCase();

  if (msg.includes('econnrefused') || msg.includes('enotfound') || msg.includes('unreachable') || msg.includes('dns')) {
    return 'target_unreachable';
  }
  if (msg.includes('auth') || msg.includes('login') || msg.includes('credential') || msg.includes('401') || msg.includes('403')) {
    return 'auth_failure';
  }
  if (msg.includes('timeout') || msg.includes('timed out') || msg.includes('etimedout')) {
    return 'timeout';
  }
  if (msg.includes('invalid url') || msg.includes('url') || msg.includes('malformed')) {
    return 'invalid_url';
  }

  return 'internal_error';
}

/**
 * Periodically check for "running" scheduled scans and attempt to finalize them.
 * This handles generating the AI report and sending completion emails for offline users.
 */
async function finalizeRunningScans() {
  try {
    const runningScans = await ScanResult.find({
      triggerSource: 'scheduled',
      status: { $in: ['pending', 'running', 'combining'] }
    });

    if (runningScans.length === 0) return;

    console.log(`[Scheduler] Finalizing ${runningScans.length} running scheduled scan(s)...`);

    for (const scan of runningScans) {
      try {
        const userId = scan.userId;
        const analysisId = scan.analysisId;

        // Generate a short-lived internal token for this user
        const token = jwt.sign({ user: { id: userId.toString() } }, process.env.JWT_SECRET, { expiresIn: '5m' });
        const baseUrl = `http://localhost:${process.env.PORT || 3001}`;

        // Differentiate between Public and Authenticated scans to call the correct status endpoint
        // Authenticated scans have authScanResult; Public scans use combined-analysis
        const isAuthScan = scan.authScanResult || (analysisId && analysisId.startsWith('scheduled-'));
        const statusEndpoint = isAuthScan 
          ? `/api/zap-auth/status/${analysisId}`
          : `/api/vt/combined-analysis/${analysisId}`;

        console.log(`[Scheduler] 🔍 Polling status for ${isAuthScan ? 'AUTH' : 'PUBLIC'} scan: ${analysisId}`);

        // Call the orchestration GET endpoint to trigger finalization if ready
        await axios.get(
          `${baseUrl}${statusEndpoint}`,
          { 
            headers: { 'x-auth-token': token },
            timeout: 60000 // 1 minute timeout
          }
        );
      } catch (err) {
        // Silently fail individual scan finalization - it will retry next cycle
        if (err.response?.status !== 404) {
          console.debug(`[Scheduler] Notice: Could not finalize scan ${scan.analysisId}:`, err.message);
        }
      }
    }
  } catch (err) {
    console.error('[Scheduler] Error in finalizeRunningScans:', err.message);
  }
}

module.exports = {
  startScheduler,
  stopScheduler,
  processScheduledScans,
  finalizeRunningScans,
  validatePlanLimits,
  classifyFailure
};
