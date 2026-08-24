/**
 * Scheduled cleanup job for scan data
 * Runs periodically to clean up:
 * - Failed/stopped scans that weren't cleaned up immediately
 * - Orphaned GridFS files
 * - Orphaned ZapAlert documents
 */

const cleanupService = require('../services/cleanupService');
const ScanResult = require('../models/ScanResult');
const { publishScanProgress } = require('../services/scanProgressService');

// Cleanup interval: 1 hour (in milliseconds)
const CLEANUP_INTERVAL = 60 * 60 * 1000;
// Fast-rescue interval: check for combining-stuck scans every 5 minutes.
// The full cleanup (GridFS/ZapAlert orphan checks) is expensive; this only
// re-triggers Gemini for scans that are ready but stuck — cheap DB read.
const FAST_RESCUE_INTERVAL = 5 * 60 * 1000;

// Capacity idle check: every 2 minutes. Cheap (Redis + one countDocuments + one
// DescribeServices) and frequent enough that the ASG comes down promptly after the
// idle window elapses, without being so frequent that it churns the ECS API.
const CAPACITY_CHECK_INTERVAL = 2 * 60 * 1000;

// Stuck-scan watchdog thresholds
//
// 45 min, raised from 30. A scan can now legitimately sit in 'queued' for a
// scale-from-zero (up to ZAP_CAPACITY_WAIT_MS = 10 min) on top of the existing
// ZAP_LOCK_WAIT_MS (30 min) wait behind another scan. At 30 min the watchdog would
// fail scans that are merely waiting. This is the only watchdog threshold the
// capacity work changes — ZAP_STALE_MS (24 h) and WEBCHK_STALE_MS (6 h) already
// dwarf any cold start, and COMBINING_STUCK_MS applies after ZAP is done.
const QUEUED_STALE_MS  = 45 * 60 * 1000;         // 45 min — job never picked up
const ZAP_STALE_MS     = 24 * 60 * 60 * 1000;    // 24 h
const WEBCHK_STALE_MS  =  6 * 60 * 60 * 1000;    // 6 h
// If both background scans are done but refinedReport is still null after this
// threshold, re-trigger Gemini rather than waiting the full 24-hour watchdog.
const COMBINING_STUCK_MS = 15 * 60 * 1000;        // 15 min

// Track if cleanup is already running to prevent overlap
let isCleanupRunning = false;
let cleanupIntervalId = null;
let fastRescueIntervalId = null;
let capacityIntervalId = null;
let isCapacityCheckRunning = false;

/**
 * Run the cleanup tasks
 */
async function runCleanup() {
    if (isCleanupRunning) {
        console.log('[CleanupJob] Cleanup already in progress, skipping...');
        return;
    }

    isCleanupRunning = true;
    console.log('[CleanupJob] Starting scheduled cleanup...');
    const startTime = Date.now();

    try {
        // 0. Watchdog: fail scans that are stuck in queued/combining
        // This ensures scans never remain "running" forever even if no client is polling.
        try {
            const now = Date.now();
            const candidates = await ScanResult.find(
                { status: { $in: ['queued', 'combining'] } },
                { analysisId: 1, userId: 1, target: 1, status: 1, createdAt: 1, updatedAt: 1, zapResult: 1, webCheckResult: 1 }
            ).lean();

            let watchdogFailed = 0;
            for (const scan of candidates) {
                const createdAt = scan.createdAt ? new Date(scan.createdAt).getTime() : 0;
                const updatedAt = scan.updatedAt ? new Date(scan.updatedAt).getTime() : createdAt;

                // A) queued too long: worker never picked it up
                if (scan.status === 'queued' && createdAt && (now - createdAt) > QUEUED_STALE_MS) {
                    await ScanResult.updateOne(
                        { analysisId: scan.analysisId, status: 'queued' },
                        { $set: { status: 'failed', error: 'Timed out waiting for worker (queued too long)', updatedAt: new Date() } }
                    );
                    publishScanProgress(scan.analysisId, scan.userId, {
                        status: 'failed',
                        progress: 0,
                        error: 'Scan timed out waiting for worker. Please try again.'
                    }).catch(() => {});
                    watchdogFailed++;
                    continue;
                }

                // B) ZAP stale
                const zapStartedAt = scan.zapResult?.startedAt ? new Date(scan.zapResult.startedAt).getTime() : null;
                const zapStatus = scan.zapResult?.status;
                const zapTerminal = ['completed', 'completed_partial', 'failed'].includes(zapStatus);
                if (zapStartedAt && !zapTerminal && (now - zapStartedAt) > ZAP_STALE_MS) {
                    await ScanResult.updateOne(
                        { analysisId: scan.analysisId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
                        { $set: { status: 'failed', 'zapResult.status': 'failed', 'zapResult.error': 'Timed out (24 h)', updatedAt: new Date() } }
                    );
                    publishScanProgress(scan.analysisId, scan.userId, {
                        status: 'failed',
                        progress: 0,
                        error: 'ZAP scan timed out. Please try again.'
                    }).catch(() => {});
                    watchdogFailed++;
                    continue;
                }

                // C) WebCheck stale
                const webStartedAt = scan.webCheckResult?.startedAt ? new Date(scan.webCheckResult.startedAt).getTime() : null;
                const webStatus = scan.webCheckResult?.status;
                const webTerminal = ['completed', 'completed_partial', 'completed_with_errors', 'failed'].includes(webStatus);
                if (webStartedAt && !webTerminal && (now - webStartedAt) > WEBCHK_STALE_MS) {
                    await ScanResult.updateOne(
                        { analysisId: scan.analysisId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
                        { $set: { status: 'failed', 'webCheckResult.status': 'failed', 'webCheckResult.error': 'Timed out (6 h)', updatedAt: new Date() } }
                    );
                    publishScanProgress(scan.analysisId, scan.userId, {
                        status: 'failed',
                        progress: 0,
                        error: 'WebCheck scan timed out. Please try again.'
                    }).catch(() => {});
                    watchdogFailed++;
                    continue;
                }

                // D) Global safety: if nothing has updated for a very long time, fail it.
                // (Prevents eternal combining if modules never set startedAt.)
                if (updatedAt && (now - updatedAt) > ZAP_STALE_MS) {
                    await ScanResult.updateOne(
                        { analysisId: scan.analysisId, status: { $in: ['queued', 'combining'] } },
                        { $set: { status: 'failed', error: 'Timed out (no progress updates)', updatedAt: new Date() } }
                    );
                    publishScanProgress(scan.analysisId, scan.userId, {
                        status: 'failed',
                        progress: 0,
                        error: 'Scan timed out due to no progress updates. Please try again.'
                    }).catch(() => {});
                    watchdogFailed++;
                }
            }

            if (watchdogFailed > 0) {
                console.warn(`[CleanupJob] Watchdog marked ${watchdogFailed} scans as failed`);
            }
        } catch (watchdogErr) {
            console.error('[CleanupJob] Watchdog error:', watchdogErr.message);
        }

        // E) Combining-stuck recovery: both background scans finished but Gemini
        //    never completed (likely an auth hang or process crash during generation).
        //    Re-trigger checkAndGenerateGemini — it is idempotent and lock-protected.
        try {
            const now = Date.now();
            const ZAP_TERMINAL    = ['completed', 'failed'];
            const WEBCHK_TERMINAL = ['completed', 'completed_partial', 'completed_with_errors', 'failed'];

            const stuckCombining = await ScanResult.find(
                {
                    status: 'combining',
                    refinedReport: null,
                    updatedAt: { $lt: new Date(now - COMBINING_STUCK_MS) }
                },
                { analysisId: 1, userId: 1, zapResult: 1, webCheckResult: 1, updatedAt: 1 }
            ).lean();

            let retriggered = 0;
            for (const scan of stuckCombining) {
                const zapDone    = ZAP_TERMINAL.includes(scan.zapResult?.status);
                const webChkDone = WEBCHK_TERMINAL.includes(scan.webCheckResult?.status);

                if (!zapDone || !webChkDone) continue; // background scans still running

                const stuckFor = Math.round((now - new Date(scan.updatedAt).getTime()) / 60000);
                console.warn(`[CleanupJob] Combining-stuck scan detected: ${scan.analysisId} (${stuckFor} min, zapStatus=${scan.zapResult?.status} webCheckStatus=${scan.webCheckResult?.status}) — re-triggering Gemini`);

                try {
                    const { checkAndGenerateGemini } = require('../services/geminiCompletionService');
                    checkAndGenerateGemini(scan.analysisId, String(scan.userId)).catch(e =>
                        console.error(`[CleanupJob] Re-triggered Gemini error for ${scan.analysisId}:`, e.message)
                    );
                    retriggered++;
                } catch (loadErr) {
                    console.error(`[CleanupJob] Could not load geminiCompletionService for ${scan.analysisId}:`, loadErr.message);
                }
            }

            if (retriggered > 0) {
                console.log(`[CleanupJob] Re-triggered Gemini for ${retriggered} stuck-combining scan(s)`);
            }
        } catch (stuckErr) {
            console.error('[CleanupJob] Combining-stuck recovery error:', stuckErr.message);
        }

        // 1. Clean up failed/stopped scans
        const failedScans = await ScanResult.find({
            status: { $in: ['failed', 'stopped'] }
        }, { analysisId: 1, userId: 1 }).lean();

        console.log(`[CleanupJob] Found ${failedScans.length} failed/stopped scans to clean up`);

        for (const scan of failedScans) {
            try {
                await cleanupService.cleanupFailedScan(scan.analysisId, scan.userId);
            } catch (err) {
                console.error(`[CleanupJob] Failed to cleanup scan ${scan.analysisId}:`, err.message);
            }
        }

        // 2. Clean up orphaned GridFS files (files older than 7 days without parent scan)
        await cleanupService.cleanupOrphanedGridFSFiles();

        // 3. Clean up orphaned ZapAlert documents
        await cleanupService.cleanupOrphanedZapAlerts();

        // 4. Clean up generated PDF reports older than 24h. These live in GridFS
        //    (bucket 'pdf_reports') and are no longer TTL-managed by Redis, so bound
        //    their lifetime here to match the PDF-job metadata TTL.
        try {
            const gridfsService = require('../services/gridfsService');
            const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
            const deleted = await gridfsService.deleteFilesOlderThan('pdf_reports', cutoff);
            if (deleted) console.log(`[CleanupJob] Deleted ${deleted} expired PDF report file(s) from GridFS`);
        } catch (pdfErr) {
            console.warn('[CleanupJob] PDF report cleanup failed (non-fatal):', pdfErr.message);
        }

        const duration = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`[CleanupJob] Cleanup completed in ${duration}s`);

    } catch (error) {
        console.error('[CleanupJob] Cleanup job error:', error.message);
    } finally {
        isCleanupRunning = false;
    }
}

/**
 * Fast combining-stuck rescue: re-trigger Gemini for any scan where both
 * background scans finished but refinedReport is still null after 15 min.
 * Runs every 5 min so stuck scans are rescued within ~5 min rather than ~75 min.
 */
let isFastRescueRunning = false;
async function runFastRescue() {
    if (isFastRescueRunning) return;
    isFastRescueRunning = true;
    try {
        const now = Date.now();
        const ZAP_TERMINAL    = ['completed', 'failed'];
        const WEBCHK_TERMINAL = ['completed', 'completed_partial', 'completed_with_errors', 'failed'];

        const stuckCombining = await ScanResult.find(
            {
                status: 'combining',
                refinedReport: null,
                updatedAt: { $lt: new Date(now - COMBINING_STUCK_MS) }
            },
            { analysisId: 1, userId: 1, zapResult: 1, webCheckResult: 1, updatedAt: 1 }
        ).lean();

        let retriggered = 0;
        for (const scan of stuckCombining) {
            const zapDone    = ZAP_TERMINAL.includes(scan.zapResult?.status);
            const webChkDone = WEBCHK_TERMINAL.includes(scan.webCheckResult?.status);
            if (!zapDone || !webChkDone) continue;

            const stuckFor = Math.round((now - new Date(scan.updatedAt).getTime()) / 60000);
            console.warn(`[FastRescue] Stuck scan: ${scan.analysisId} (${stuckFor} min) — re-triggering Gemini`);
            try {
                const { checkAndGenerateGemini } = require('../services/geminiCompletionService');
                checkAndGenerateGemini(scan.analysisId, String(scan.userId)).catch(e =>
                    console.error(`[FastRescue] Gemini re-trigger error for ${scan.analysisId}:`, e.message)
                );
                retriggered++;
            } catch (loadErr) {
                console.error(`[FastRescue] Could not load geminiCompletionService:`, loadErr.message);
            }
        }
        if (retriggered > 0) {
            console.log(`[FastRescue] Re-triggered Gemini for ${retriggered} scan(s)`);
        }
    } catch (err) {
        console.error('[FastRescue] Error:', err.message);
    } finally {
        isFastRescueRunning = false;
    }
}

/**
 * Start the cleanup job scheduler
 */
/**
 * Scale idle ZAP capacity back to zero.
 *
 * Lives here rather than in schedulerService because schedulerService.startScheduler()
 * is exported but never called anywhere in the codebase — its cron jobs do not run in
 * the current deployment. startCleanupJob IS called (server.js), so this is the only
 * reliable timer in the process.
 *
 * Every guard inside releaseZapCapacityIfIdle is a veto and any error means "leave
 * capacity up", so the worst case here is spending a few more cents, never killing a
 * scan. A no-op unless ZAP_CAPACITY_MANAGED=true.
 */
async function runCapacityCheck() {
    if (isCapacityCheckRunning) return;
    isCapacityCheckRunning = true;
    try {
        const { releaseIdleCapacity } = require('../services/zapCapacityManager');
        const results = await releaseIdleCapacity();
        for (const r of results) {
            if (r.scaledDown) {
                console.log(`[CleanupJob] ZAP capacity scaled down: instance=${r.key}`);
            }
        }
    } catch (err) {
        console.error('[CleanupJob] Capacity check error:', err.message);
    } finally {
        isCapacityCheckRunning = false;
    }
}

function startCleanupJob() {
    console.log(`[CleanupJob] Starting cleanup scheduler (interval: ${CLEANUP_INTERVAL / 1000 / 60} minutes)`);

    // Run immediately on startup (after a short delay to allow DB connection)
    setTimeout(() => {
        console.log('[CleanupJob] Running initial cleanup...');
        runCleanup();
    }, 10000); // 10 second delay

    // Schedule periodic cleanup
    cleanupIntervalId = setInterval(runCleanup, CLEANUP_INTERVAL);

    // Fast rescue: poll every 5 min for stuck-combining scans
    fastRescueIntervalId = setInterval(runFastRescue, FAST_RESCUE_INTERVAL);

    // Idle ZAP capacity scale-in: poll every 2 min
    capacityIntervalId = setInterval(runCapacityCheck, CAPACITY_CHECK_INTERVAL);

    console.log('[CleanupJob] Cleanup job scheduled');
}

/**
 * Stop the cleanup job scheduler
 */
function stopCleanupJob() {
    if (cleanupIntervalId) {
        clearInterval(cleanupIntervalId);
        cleanupIntervalId = null;
        console.log('[CleanupJob] Cleanup job stopped');
    }
    if (capacityIntervalId) {
        clearInterval(capacityIntervalId);
        capacityIntervalId = null;
        console.log('[CleanupJob] Capacity check stopped');
    }
    if (fastRescueIntervalId) {
        clearInterval(fastRescueIntervalId);
        fastRescueIntervalId = null;
        console.log('[CleanupJob] Fast rescue job stopped');
    }
}

module.exports = {
    startCleanupJob,
    stopCleanupJob,
    runCleanup,
    runCapacityCheck
};
