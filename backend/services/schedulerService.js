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
  handleScanFailed,
  handleScheduledScanTriggered,
  emitScanStarted
} = require('./notificationService');
const { testLogin } = require('./loginTestService');

const { getPageSpeedReport } = require('./pagespeedService');
const { scanHost } = require('./observatoryService');
const { runUrlScan } = require('./urlscanService');
const { startAsyncZapScan } = require('./zapService');
const { startAsyncWebCheckScan } = require('./webCheckService');

const { checkScanQuota, claimScanSlot } = require('./planService');

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
 * Mark a schedule failed because the org has no capacity, and tell the user.
 * Shared by the advisory pre-check and the authoritative claimScanSlot refusal so
 * both produce the same schedule state and the same notification.
 */
async function failScheduleOnPlanLimit(schedule, user) {
  console.log(`[Scheduler] Schedule ${schedule._id}: Plan limit exceeded or inactive`);
  schedule.status = 'failed';
  schedule.lastFailure = {
    reason: 'Scan limit reached or subscription inactive',
    failureType: 'plan_limit_exceeded',
    timestamp: new Date()
  };
  await schedule.save();

  await handleScanFailed(
    null,
    user._id.toString(),
    schedule.scanType === 'public' ? 'Public Scan' : 'Authenticated Scan',
    schedule.targetUrl,
    'Scan limit reached or subscription inactive'
  );
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

  // Validate plan limits before execution. Advisory only — the authoritative check
  // is claimScanSlot inside the trigger functions, which can also refuse.
  const limits = user.getAccountLimits ? user.getAccountLimits() : {};
  const result = await checkScanQuota(user.organizationId, {
    target: schedule.targetUrl,
    scansPerTarget: limits.scansPerTarget,
    targetsPerMonth: limits.targetsPerMonth
  });
  if (!result) {
    await failScheduleOnPlanLimit(schedule, user);
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
    const triggerMeta = {
      triggerSource: 'scheduled',
      scheduleId: schedule._id.toString(),
      scheduledFor,
      startedAt
    };

    let triggerResult;
    if (schedule.scanType === 'public') {
      triggerResult = await triggerPublicScan(
        scanId, schedule.targetUrl, user._id.toString(), triggerMeta, user.organizationId
      );
      if (triggerResult && triggerResult.scanId) {
        schedule.lastScanId = triggerResult.scanId; // Update with the real backend-generated ID
      }
    } else {
      triggerResult = await triggerAuthenticatedScan(
        scanId, schedule.targetUrl, user._id.toString(), schedule.authConfig, triggerMeta, user.organizationId
      );
    }

    // The org ran out of capacity between the advisory check above and the claim —
    // e.g. a manual scan started in between. Treat it exactly like the pre-check.
    if (triggerResult && triggerResult.refused) {
      await failScheduleOnPlanLimit(schedule, user);
      return;
    }

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

    if (schedule.scheduleType === 'recurring') {
      schedule.computeNextRun();
      schedule.status = 'scheduled';
    }

    await schedule.save();

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
async function triggerPublicScan(scanId, targetUrl, userId, meta, organizationId = null) {
  console.log(`[Scheduler] Orchestrating internal combined scan for ${targetUrl}`);

  const scan = new ScanResult({
    target: targetUrl,
    analysisId: scanId,
    status: 'combining',
    userId: userId,
    organizationId: organizationId || null,
    triggerSource: 'scheduled',
    languagePreference: 'en'
  });
  await scan.save();

  // Authoritative quota check — see planService.claimScanSlot. The checkScanQuota
  // call in executeSchedule is advisory and reserves nothing, so a schedule firing
  // alongside in-flight manual scans could otherwise overshoot the plan.
  // Runs before emitScanStarted so a refused scan never announces itself.
  if (organizationId && !(await claimScanSlot(organizationId, scanId))) {
    await ScanResult.updateOne(
      { analysisId: scanId },
      { $set: { status: 'cancelled', updatedAt: new Date() } }
    );
    return { scanId, refused: true };
  }

  emitScanStarted(userId, {
    scanId,
    targetUrl,
    scanType: 'Public Scan',
    ...(meta || {})
  });

  // Warm ZAP capacity up now rather than when the ZAP job is dequeued. The four
  // scanners below run first and take minutes of their own, so an EC2 boot and image
  // pull started here overlaps them instead of being added to the end. No-ops unless
  // capacity management is enabled for 'normal'.
  {
    const { markZapDemand, ensureZapCapacity } = require('./zapCapacityManager');
    markZapDemand('normal').catch(() => {});
    ensureZapCapacity('normal', { scanId }).catch(err =>
      console.warn(`[Scheduler] ZAP capacity warm-up failed for ${scanId}: ${err.message}`)
    );
  }

  try {
    const hostname = new URL(targetUrl).hostname;

    const scanPromises = [
      getPageSpeedReport(targetUrl),
      scanHost(hostname),
      runUrlScan(targetUrl),
      startAsyncZapScan(targetUrl, scanId, userId),
      startAsyncWebCheckScan(targetUrl, scanId, userId)
    ];

    const [psiResult, obsResult, urlscanResult, zapInitResult, webCheckInitResult] = await Promise.allSettled(scanPromises);

    const pagespeedResult = psiResult.status === 'fulfilled' ? psiResult.value : { error: psiResult.reason?.message };
    const observatoryResult = obsResult.status === 'fulfilled' ? obsResult.value : { error: obsResult.reason?.message };
    const urlscanData = urlscanResult.status === 'fulfilled' ? urlscanResult.value : { error: urlscanResult.reason?.message };
    const zapResult = zapInitResult.status === 'fulfilled' ? zapInitResult.value : { status: 'failed', error: zapInitResult.reason?.message };
    const webCheckResult = webCheckInitResult.status === 'fulfilled' ? webCheckInitResult.value : { status: 'failed', error: webCheckInitResult.reason?.message };

    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          pagespeedResult,
          observatoryResult,
          urlscanResult: urlscanData,
          zapResult,
          webCheckResult,
          updatedAt: new Date()
        }
      }
    );

  } catch (err) {
    console.error('[Scheduler] Error orchestrating public scan:', err.message);
    await ScanResult.updateOne({ analysisId: scanId }, { $set: { status: 'failed', updatedAt: new Date() } });
  }

  return { scanId };
}

/**
 * Trigger an authenticated scan
 */
async function triggerAuthenticatedScan(scanId, targetUrl, userId, authConfig, meta, organizationId = null) {
  const { startAsyncAuthScan } = require('./zapAuthService');

  // Unlike triggerPublicScan, the start event is emitted before the slot claim: the
  // background login below runs first and the ScanResult (which the claim needs) only
  // exists after it. A refusal still reaches the user, as a scan-failed notification.

  emitScanStarted(userId, {
    scanId,
    targetUrl,
    scanType: 'Authenticated Scan',
    ...(meta || {})
  });

  console.log(`[Scheduler] 🔐 Performing background login for ${targetUrl}`);
  
  let cookies = [];
  let authState = null;
  let loginOutcome = 'not_configured';

  if (authConfig && authConfig.loginUrl && authConfig.credentials && authConfig.credentials.length > 0) {
    try {
      const loginResult = await testLogin({
        loginUrl: authConfig.loginUrl,
        credentials: authConfig.credentials,
        submitButton: authConfig.submitButton ? { selector: authConfig.submitButton } : null,
        expectedMarker: authConfig.signedInMarker || null
      });

      if (loginResult && loginResult.authenticated) {
        cookies = loginResult.cookies || [];
        loginOutcome = loginResult.authConfirmed || 'unconfirmed';
        authState = {
          marker: loginResult.marker || null,
          markerCheckableInBody: Boolean(loginResult.markerCheckableInBody),
          recipe: {
            loginUrl: authConfig.loginUrl,
            credentials: authConfig.credentials,
            submitButton: authConfig.submitButton ? { selector: authConfig.submitButton } : null
          },
          reloginAttempts: 0
        };
        console.log(`[Scheduler] ✅ Background login ${loginOutcome} for ${targetUrl} (${cookies.length} cookies)`);
      } else {
        loginOutcome = 'failed';
        console.warn(`[Scheduler] ⚠️ Background login failed for ${targetUrl}: ${loginResult?.errorCode || 'unknown'}`);
      }
    } catch (loginErr) {
      loginOutcome = 'failed';
      console.error(`[Scheduler] ❌ Background login exception for ${targetUrl}:`, loginErr.message);
    }
  }

  const { v4: uuidv4 } = require('uuid');
  const tempSessionId = uuidv4();
  
  const ScanResult = require('../models/ScanResult');
  const skeletonScan = new ScanResult({
    target: targetUrl,
    analysisId: scanId,
    status: 'pending',
    userId: userId,
    organizationId: organizationId || null,
    triggerSource: 'scheduled',
    languagePreference: 'en',
    // Mirrors the skeleton POST /api/zap-auth/scan writes. Two things depend on it:
    // the UI can show "queued" instead of an empty panel, and — the reason it was
    // added — zapCapacityManager.hasActiveZapScans('auth') can see that this scan
    // owes ZAP work. Without it a scheduled auth scan waiting on zap:lock:auth is
    // invisible to the idle scale-in guard, which can then take the instance away
    // from under it. It is also what distinguishes an auth scan from a normal one
    // before either has produced a result.
    //
    // The sign-in fields record what the background login actually achieved. A
    // failed login used to leave `cookies` empty and let the scan run anyway,
    // producing a report of the publicly visible pages that was
    // indistinguishable from an authenticated one. It still runs — a public scan
    // beats no scan — but it is now labelled as one.
    authScanResult: {
      status: 'provisioning',
      phase: 'provisioning',
      progress: 0,
      loginOutcome,
      authVerified: loginOutcome === 'confirmed' ? true : (loginOutcome === 'failed' ? false : null),
      authDegraded: loginOutcome === 'failed',
      authDegradedReason: loginOutcome === 'failed' ? 'scheduled_login_failed' : null
    }
  });
  await skeletonScan.save();

  // Authoritative quota check — see triggerPublicScan for the rationale.
  if (organizationId && !(await claimScanSlot(organizationId, scanId))) {
    await ScanResult.updateOne(
      { analysisId: scanId },
      { $set: { status: 'cancelled', updatedAt: new Date() } }
    );
    return { scanId, refused: true };
  }

  // Route the scan through withZapInstance, exactly as POST /api/zap-auth/start does.
  //
  // Before this, a scheduled authenticated scan called startAsyncAuthScan directly: no
  // zap:lock:auth, no pre-scan recycle, no readiness wait. A schedule firing alongside a
  // route-initiated auth scan therefore ran concurrently against the same ZAP daemon,
  // where newSession is global and wipes the other scan's sites tree, contexts and
  // alerts mid-flight. The only guard was the duplicate check in zapAuthService, which
  // is keyed on analysisId — it catches a repeat of the *same* scan, not a different
  // concurrent one. Under scale-to-zero the same gap would additionally fire the scan at
  // a Service Connect alias with no endpoints behind it.
  //
  // Detached on purpose. withZapInstance holds the lock until onComplete fires — i.e.
  // for the whole scan, up to three hours — while triggerAuthenticatedScan is awaited by
  // the 15-second cron tick behind an isProcessing guard. Awaiting it here would stall
  // the scheduler for the length of the scan.
  const { withZapInstance } = require('./zapRecycler');
  const { markZapDemand, ensureZapCapacity } = require('./zapCapacityManager');
  const { ensureAuthFastScans } = require('./authFastScanService');

  // Warm up ahead of the lock so the EC2 boot and image pull overlap the login work
  // and the queue wait rather than adding to them. No-ops unless capacity management
  // is enabled for 'auth'.
  markZapDemand('auth').catch(() => {});
  ensureZapCapacity('auth', { scanId }).catch(err =>
    console.warn(`[Scheduler] auth capacity warm-up failed for ${scanId}: ${err.message}`)
  );

  // Start the fast scanners now, alongside the ZAP leg.
  //
  // A scheduled authenticated scan ran NONE of these before: the four scanners were
  // driven only from GET /api/zap-auth/status/:scanId, and nothing polls that for a
  // scan the scheduler started. The scan therefore reached 'combining' with no
  // PageSpeed, Observatory, urlscan or WebCheck data and could never satisfy the
  // completion service's readiness gate — it sat there until it was failed as
  // 'scan_data_unavailable' (and before that gate existed, completed with a
  // placeholder report and was billed for it).
  //
  // Not awaited: these take minutes and must overlap the ZAP scan, not delay the
  // 15-second scheduler tick. Never fatal — ensureAuthFastScans catches internally
  // and releases its claim so a later call can retry.
  ensureAuthFastScans(scanId, String(userId)).catch(e =>
    console.error(`[Scheduler] fast-scan kick-off failed for ${scanId}: ${e.message}`)
  );

  withZapInstance('auth', scanId, () => new Promise((resolve) => {
    startAsyncAuthScan(
      targetUrl,
      authConfig?.loginUrl || targetUrl,
      cookies,
      scanId,
      userId,
      undefined,        // zapUrl — fall back to ZAP_AUTH_API_URL
      () => resolve(),  // onComplete fires from the background scan's .finally()
      authState         // marker + login recipe, so the scan can re-check and re-login
    )
      // 'already_running' never fires onComplete, so resolve explicitly or the lock
      // sits until its TTL expires.
      .then((r) => { if (r?.status === 'already_running') resolve(); })
      .catch((err) => {
        console.error(`[Scheduler] startAsyncAuthScan failed for ${scanId}: ${err.message}`);
        resolve();
      });
  })).catch(async (err) => {
    console.error(`[Scheduler] auth scan could not start for ${scanId}: ${err.message}`);
    // errorCode is machine-readable so the UI can render a localized explanation;
    // the English message stays server-side only (CLAUDE.md).
    const recycleCodes = ['ECS_ACCESS_DENIED', 'PLACEMENT_FAILED', 'REPLACEMENT_DIED',
                          'API_NOT_READY', 'NOT_FRESH', 'LOCK_TIMEOUT', 'TIMEOUT',
                          'CAPACITY_TIMEOUT', 'CAPACITY_TASK_DIED', 'CAPACITY_API_NOT_READY',
                          'CAPACITY_SCALE_OUT_FAILED', 'SERVICE_NOT_FOUND'];
    await ScanResult.updateOne(
      { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
      {
        $set: {
          status: 'failed',
          'authScanResult.status': 'failed',
          'authScanResult.phase': 'failed',
          'authScanResult.error': err.message,
          'authScanResult.errorCode': recycleCodes.includes(err.code) ? 'zap_recycle_failed' : 'zap_scan_failed',
          'authScanResult.failedAt': new Date(),
          failureReason: 'vulnerability_scan_failed',
          updatedAt: new Date()
        }
      }
    ).catch(e => console.error(`[Scheduler] Failed to record auth scan failure for ${scanId}:`, e.message));
  });

  return { scanId };
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
        // Timeout check logic
        const ZAP_STALE_TIMEOUT_MS = 24 * 60 * 60 * 1000;
        const now = Date.now();
        if (scan.zapResult?.startedAt && !['completed', 'completed_partial', 'failed'].includes(scan.zapResult.status)) {
          const zapAge = now - new Date(scan.zapResult.startedAt).getTime();
          if (zapAge > ZAP_STALE_TIMEOUT_MS) {
            await ScanResult.updateOne({ _id: scan._id }, { $set: { 'zapResult.status': 'failed', status: 'failed' } });
            continue;
          }
        }

        const isZAPComplete = !scan.zapResult || ['completed', 'completed_partial', 'failed'].includes(scan.zapResult.status);
        const isWebCheckComplete = !scan.webCheckResult || ['completed', 'completed_partial', 'completed_with_errors', 'failed'].includes(scan.webCheckResult.status);

        if (isZAPComplete && isWebCheckComplete && !scan.refinedReport) {
          // Delegate to the completion service rather than generating inline.
          //
          // This block used to call refineReport itself and write
          // `refinedReport` + `status: completed` directly. Three things were wrong
          // with that: it never called finalizeSuccessfulScan, so a scheduled scan
          // finished here was delivered free; it raced checkAndGenerateGemini, which
          // then short-circuited on the refinedReport it found; and it passed raw
          // alerts to the LLM without the plan's severity filter and without loading
          // WebCheck full results from GridFS.
          //
          // checkAndGenerateGemini is idempotent and lock-protected, so calling it
          // from this poller is safe. If the scan is not actually ready it returns
          // without doing anything and the next poll retries.
          console.log(`[Scheduler] Handing ${scan.analysisId} to the completion service`);
          const { checkAndGenerateGemini } = require('./geminiCompletionService');
          await checkAndGenerateGemini(scan.analysisId, String(scan.userId)).catch(e =>
            console.error(`[Scheduler] checkAndGenerateGemini failed for ${scan.analysisId}:`, e.message)
          );
        }
      } catch (err) {
        console.error(`[Scheduler] Error finalizing scan ${scan.analysisId}:`, err.message);
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
  classifyFailure
};
