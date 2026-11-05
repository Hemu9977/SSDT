const mongoose = require('mongoose');
const gridfsService = require('./gridfsService');
const ScanResult = require('../models/ScanResult');
const ZapAlert = require('../models/ZapAlert');

const WEBCHECK_BUCKET = 'webcheck_results';
const ZAP_BUCKET = 'zap_reports';
const ZAP_AUTH_BUCKET = 'zap_auth_reports';

// Authenticated scans store their reports in their own bucket (zapAuthService),
// named zap_auth_*; the readers pick the bucket the same way.
const zapBucketFor = (file) =>
    (file.filename || '').includes('zap_auth') ? ZAP_AUTH_BUCKET : ZAP_BUCKET;

/**
 * Delete a scan's heavy artifacts: its GridFS report files (WebCheck + ZAP) and
 * its ZapAlert documents. Leaves the ScanResult document itself alone.
 * @returns {Promise<{gridfsFiles: number, zapAlerts: number}>}
 */
async function deleteScanArtifacts(scan) {
    const deletedItems = {
        gridfsFiles: 0,
        zapAlerts: 0
    };

    // 1. Delete WebCheck GridFS files
    if (scan.webCheckResult?.resultsFileId) {
        try {
            await gridfsService.deleteFile(scan.webCheckResult.resultsFileId, WEBCHECK_BUCKET);
            deletedItems.gridfsFiles++;
            console.log(`[Cleanup] Deleted WebCheck GridFS file: ${scan.webCheckResult.resultsFileId}`);
        } catch (err) {
            console.warn(`[Cleanup] Failed to delete WebCheck file: ${err.message}`);
        }
    }

    // 2. Delete ZAP GridFS files (can be multiple). An authenticated scan lists
    //    the same files in both zapResult and authScanResult, so dedupe by id.
    const zapFiles = new Map();
    for (const file of [...(scan.zapResult?.reportFiles || []), ...(scan.authScanResult?.reportFiles || [])]) {
        if (file?.fileId) zapFiles.set(String(file.fileId), file);
    }
    for (const [fileId, file] of zapFiles) {
        const bucket = zapBucketFor(file);
        try {
            await gridfsService.deleteFile(fileId, bucket);
            deletedItems.gridfsFiles++;
            console.log(`[Cleanup] Deleted ZAP GridFS file: ${fileId} (${bucket})`);
        } catch (err) {
            console.warn(`[Cleanup] Failed to delete ZAP file ${fileId} from ${bucket}: ${err.message}`);
        }
    }

    // Also check for single reportFileId (older format)
    if (scan.zapResult?.reportFileId) {
        try {
            await gridfsService.deleteFile(scan.zapResult.reportFileId, ZAP_BUCKET);
            deletedItems.gridfsFiles++;
            console.log(`[Cleanup] Deleted ZAP GridFS file: ${scan.zapResult.reportFileId}`);
        } catch (err) {
            console.warn(`[Cleanup] Failed to delete ZAP file: ${err.message}`);
        }
    }

    // 3. Delete ZapAlert documents
    const zapAlertResult = await ZapAlert.deleteMany({ scanId: scan.analysisId });
    deletedItems.zapAlerts = zapAlertResult.deletedCount;
    if (deletedItems.zapAlerts > 0) {
        console.log(`[Cleanup] Deleted ${deletedItems.zapAlerts} ZapAlert documents`);
    }

    return deletedItems;
}

// Small diagnostic fields kept on a failed scan after its artifacts are purged.
// Whitelisted (not blacklisted) so no unexpected heavy field survives.
const KEEP_ZAP = ['status', 'error', 'errorCode', 'failureReason', 'message', 'startedAt', 'completedAt'];
const KEEP_WEBCHECK = ['status', 'error', 'completedScans', 'totalScans', 'hasErrors', 'duration'];
const KEEP_AUTH = ['status', 'error', 'errorCode', 'failureReason', 'loginVerified'];

const pick = (obj, keys) => {
    if (!obj || typeof obj !== 'object') return obj ?? null;
    const out = {};
    for (const k of keys) if (obj[k] !== undefined) out[k] = obj[k];
    return out;
};

/**
 * Retention for failed/stopped scans (run hourly by jobs/cleanupJob.js).
 *
 * Deletes the heavy artifacts — GridFS files, ZAP alerts, full result payloads —
 * but KEEPS the ScanResult document with its status, target, user, failureReason
 * and timestamps. The document is then removed by the same 7-day TTL as every
 * other scan, so a failure stays diagnosable (admin Scans tab, the customer's
 * history) for as long as a success does. Idempotent via artifactsPurgedAt.
 */
async function purgeFailedScanArtifacts(analysisId) {
    const scan = await ScanResult.findOne({ analysisId });
    if (!scan) return { success: true, skipped: 'not_found' };
    if (!['failed', 'stopped'].includes(scan.status)) return { success: true, skipped: 'not_failed' };
    if (scan.artifactsPurgedAt) return { success: true, skipped: 'already_purged' };

    try {
        const deleted = await deleteScanArtifacts(scan);
        await ScanResult.updateOne(
            { analysisId, status: { $in: ['failed', 'stopped'] } },
            {
                $set: {
                    zapResult: pick(scan.zapResult, KEEP_ZAP),
                    webCheckResult: pick(scan.webCheckResult, KEEP_WEBCHECK),
                    authScanResult: pick(scan.authScanResult, KEEP_AUTH),
                    pagespeedResult: null,
                    observatoryResult: null,
                    urlscanResult: null,
                    refinedReport: null,
                    artifactsPurgedAt: new Date()
                }
            }
        );
        console.log(`🧹 [Cleanup] Purged artifacts of ${scan.status} scan ${analysisId} (record kept until TTL):`, deleted);
        return { success: true, deleted };
    } catch (error) {
        console.error(`❌ [Cleanup] Error purging artifacts of scan ${analysisId}:`, error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Clean up all data associated with a failed scan
 * @param {string} analysisId - The scan's analysis ID
 * @param {string} userId - The user's ID (optional, for verification)
 */
async function cleanupFailedScan(analysisId, userId = null) {
    console.log(`🗑️ [Cleanup] Starting cleanup for scan: ${analysisId}`);

    try {
        // Find the scan
        const query = { analysisId };
        if (userId) query.userId = userId;

        const scan = await ScanResult.findOne(query);

        if (!scan) {
            console.log(`[Cleanup] Scan ${analysisId} not found, skipping`);
            return { success: true, message: 'Scan not found' };
        }

        const deletedItems = await deleteScanArtifacts(scan);
        deletedItems.scanResult = false;

        // 4. Delete the ScanResult document
        await ScanResult.deleteOne({ analysisId });
        deletedItems.scanResult = true;
        console.log(`[Cleanup] Deleted ScanResult document: ${analysisId}`);

        console.log(`✅ [Cleanup] Completed cleanup for scan ${analysisId}:`, deletedItems);
        return { success: true, deleted: deletedItems };

    } catch (error) {
        console.error(`❌ [Cleanup] Error cleaning up scan ${analysisId}:`, error.message);
        return { success: false, error: error.message };
    }
}

// Buckets swept for orphans, and the metadata key linking a file to its scan.
// Normal and authenticated ZAP reports are both uploaded with { scanId }, so
// they are swept by the same rule.
const ORPHAN_SWEEP = [
    { bucket: ZAP_BUCKET, label: 'zap', scanIdOf: (m) => m?.analysisId || m?.scanId },
    { bucket: ZAP_AUTH_BUCKET, label: 'zapAuth', scanIdOf: (m) => m?.analysisId || m?.scanId },
    { bucket: WEBCHECK_BUCKET, label: 'webcheck', scanIdOf: (m) => m?.analysisId }
];

/**
 * Clean up orphaned GridFS files that no longer have a parent ScanResult
 * Should be run periodically (e.g., daily via cron job)
 */
async function cleanupOrphanedGridFSFiles() {
    console.log('🧹 [Cleanup] Starting orphaned GridFS cleanup...');

    const stats = { errors: [] };
    for (const { label } of ORPHAN_SWEEP) {
        stats[`${label}FilesChecked`] = 0;
        stats[`${label}FilesDeleted`] = 0;
    }

    try {
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

        for (const { bucket: bucketName, label, scanIdOf } of ORPHAN_SWEEP) {
            const bucket = gridfsService.initialize(bucketName);
            const files = await bucket.find({ uploadDate: { $lt: sevenDaysAgo } }).toArray();
            stats[`${label}FilesChecked`] = files.length;

            for (const file of files) {
                const analysisId = scanIdOf(file.metadata);
                if (!analysisId) continue;
                const scanExists = await ScanResult.exists({ analysisId });
                if (scanExists) continue;
                try {
                    await gridfsService.deleteFile(file._id, bucketName);
                    stats[`${label}FilesDeleted`]++;
                    console.log(`[Cleanup] Deleted orphaned ${bucketName} file: ${file._id} (analysisId: ${analysisId})`);
                } catch (err) {
                    stats.errors.push(`${bucketName} ${file._id}: ${err.message}`);
                }
            }
        }

        console.log('✅ [Cleanup] Orphaned GridFS cleanup complete:', stats);
        return { success: true, stats };

    } catch (error) {
        console.error('❌ [Cleanup] Error during orphaned file cleanup:', error.message);
        return { success: false, error: error.message, stats };
    }
}

/**
 * Clean up orphaned ZapAlert documents that no longer have a parent ScanResult
 */
async function cleanupOrphanedZapAlerts() {
    console.log('🧹 [Cleanup] Starting orphaned ZapAlert cleanup...');

    try {
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

        // Find all unique scanIds in ZapAlerts older than 7 days
        const oldAlerts = await ZapAlert.aggregate([
            { $match: { createdAt: { $lt: sevenDaysAgo } } },
            { $group: { _id: '$scanId' } }
        ]);

        let deletedCount = 0;
        for (const { _id: scanId } of oldAlerts) {
            const scanExists = await ScanResult.exists({ analysisId: scanId });
            if (!scanExists) {
                const result = await ZapAlert.deleteMany({ scanId });
                deletedCount += result.deletedCount;
                console.log(`[Cleanup] Deleted ${result.deletedCount} orphaned ZapAlerts for scanId: ${scanId}`);
            }
        }

        console.log(`✅ [Cleanup] Deleted ${deletedCount} orphaned ZapAlert documents`);
        return { success: true, deletedCount };

    } catch (error) {
        console.error('❌ [Cleanup] Error during ZapAlert cleanup:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Comprehensive cleanup - deletes everything for a scan
 * Use this for complete manual cleanup
 * @param {string} analysisId - Optional: specific scan to delete. If null, deletes all.
 */
async function fullCleanup(analysisId = null) {
    console.log('🧹 [Cleanup] Starting full cleanup...');

    const stats = {
        scansDeleted: 0,
        gridfsFilesDeleted: 0,
        zapAlertsDeleted: 0
    };

    try {
        if (analysisId) {
            // Clean single scan
            const result = await cleanupFailedScan(analysisId);
            if (result.success && result.deleted) {
                stats.scansDeleted = result.deleted.scanResult ? 1 : 0;
                stats.gridfsFilesDeleted = result.deleted.gridfsFiles;
                stats.zapAlertsDeleted = result.deleted.zapAlerts;
            }
        } else {
            // Clean all scans - get all scan IDs first
            const allScans = await ScanResult.find({}, { analysisId: 1 }).lean();

            for (const scan of allScans) {
                const result = await cleanupFailedScan(scan.analysisId);
                if (result.success && result.deleted) {
                    stats.scansDeleted += result.deleted.scanResult ? 1 : 0;
                    stats.gridfsFilesDeleted += result.deleted.gridfsFiles;
                    stats.zapAlertsDeleted += result.deleted.zapAlerts;
                }
            }

            // Also clean orphaned files (in case some weren't linked properly)
            await cleanupOrphanedGridFSFiles();
            await cleanupOrphanedZapAlerts();
        }

        console.log('✅ [Cleanup] Full cleanup complete:', stats);
        return { success: true, stats };

    } catch (error) {
        console.error('❌ [Cleanup] Error during full cleanup:', error.message);
        return { success: false, error: error.message, stats };
    }
}

module.exports = {
    cleanupFailedScan,
    purgeFailedScanArtifacts,
    deleteScanArtifacts,
    cleanupOrphanedGridFSFiles,
    cleanupOrphanedZapAlerts,
    fullCleanup
};
