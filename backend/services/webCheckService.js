const axios = require('axios');
const ScanResult = require('../models/ScanResult');
const gridfsService = require('./gridfsService');

// Internal Docker URL or localhost for native development
const WEBCHECK_BASE_URL = process.env.WEBCHECK_URI || 'http://localhost:3002';

// GridFS bucket name for WebCheck results
const WEBCHECK_BUCKET = 'webcheck_results';

// All available scan types
// Note: 'screenshot' is commented out - using urlscan screenshot instead
const ALLOWED_SCANS = [
    'ssl', 'dns', 'headers', 'cookies', 'firewall', 'ports',
    // 'screenshot', // Using urlscan screenshot instead
    'tech-stack', 'hsts', 'security-txt', 'block-lists',
    'social-tags', 'linked-pages', 'robots-txt', 'sitemap', 'status',
    'redirects', 'mail-config', 'trace-route', 'http-security', 'get-ip',
    'dns-server', 'dnssec', 'txt-records', 'carbon', 'archives',
    'legacy-rank', 'whois', 'tls', 'quality'
];

// Track active WebCheck scans to prevent duplicates
const activeWebCheckScans = new Map();

/**
 * Run a WebCheck scan
 * @param {string} scanType - Type of scan (e.g., 'ssl', 'dns')
 * @param {string} url - Target URL to scan
 * @returns {Promise<object>} Scan results
 */
const runScan = async (scanType, url) => {
    if (!ALLOWED_SCANS.includes(scanType)) {
        throw new Error(`Invalid scan type: ${scanType}. Allowed: ${ALLOWED_SCANS.join(', ')}`);
    }

    try {
        console.log(`[WebCheck] Running ${scanType} scan for: ${url}`);

        const response = await axios.get(`${WEBCHECK_BASE_URL}/api/${scanType}`, {
            params: { url },
            timeout: 120000 // 120 second timeout for heavy scans
        });

        return response.data;
    } catch (error) {
        console.error(`[WebCheck] ${scanType} scan error:`, error.message);

        if (error.code === 'ECONNREFUSED') {
            throw new Error('WebCheck service is not available. Ensure the container is running.');
        }

        throw new Error(`Failed to run ${scanType} scan: ${error.message}`);
    }
};

/**
 * Get list of available scan types
 * @returns {string[]} Array of scan type names
 */
const getAvailableScans = () => ALLOWED_SCANS;

/**
 * Check if WebCheck service is healthy
 * @returns {Promise<boolean>}
 */
const checkHealth = async () => {
    try {
        const response = await axios.get(`${WEBCHECK_BASE_URL}/health`, { timeout: 5000 });
        return response.data.status === 'healthy';
    } catch (error) {
        console.error('[WebCheck] Health check failed:', error.message);
        return false;
    }
};

/**
 * Run ALL WebCheck scans in parallel for a URL
 * @param {string} url - Target URL to scan
 * @returns {Promise<object>} Object with all scan results keyed by scan type
 */
const runAllScans = async (url) => {
    console.log(`[WebCheck] Running ALL ${ALLOWED_SCANS.length} scans for: ${url}`);

    const results = await Promise.allSettled(
        ALLOWED_SCANS.map(async (scanType) => {
            try {
                const data = await runScan(scanType, url);
                return { type: scanType, success: true, data };
            } catch (error) {
                return { type: scanType, success: false, error: error.message };
            }
        })
    );

    // Collect results into an object keyed by scan type
    const scanResults = {};
    results.forEach((result, index) => {
        const type = ALLOWED_SCANS[index];
        if (result.status === 'fulfilled' && result.value.success) {
            scanResults[type] = result.value.data;
        } else {
            scanResults[type] = {
                error: result.reason?.message || result.value?.error || 'Scan failed'
            };
        }
    });

    console.log(`[WebCheck] Completed ${Object.keys(scanResults).length} scans`);
    return scanResults;
};

/**
 * Extract a lightweight summary from WebCheck results for MongoDB storage
 * Full results are stored in GridFS
 * @param {object} results - Full WebCheck results
 * @returns {object} - Lightweight summary
 */
const extractWebCheckSummary = (results) => {
    const summary = {};

    // SSL/TLS info (keep essential fields)
    if (results.ssl && !results.ssl.error) {
        summary.ssl = {
            valid: results.ssl.valid,
            issuer: results.ssl.issuer,
            expires: results.ssl.expires,
            protocol: results.ssl.protocol
        };
    }

    // TLS grade from Observatory
    if (results.tls && !results.tls.error) {
        summary.tls = {
            grade: results.tls.tlsInfo?.grade || results.tls.grade,
            score: results.tls.tlsInfo?.score || results.tls.score
        };
    }

    // Headers security summary
    if (results.headers && !results.headers.error) {
        summary.headers = {
            hasHSTS: !!results.headers['strict-transport-security'],
            hasCSP: !!results.headers['content-security-policy'],
            hasXFrameOptions: !!results.headers['x-frame-options'],
            hasXContentType: !!results.headers['x-content-type-options']
        };
    }

    // HSTS status
    if (results.hsts && !results.hsts.error) {
        summary.hsts = {
            enabled: results.hsts.enabled || results.hsts.preloaded || false,
            maxAge: results.hsts.maxAge
        };
    }

    // Firewall/WAF detection
    if (results.firewall && !results.firewall.error) {
        summary.firewall = {
            detected: results.firewall.detected || results.firewall.hasWaf || false,
            name: results.firewall.name || results.firewall.wafName
        };
    }

    // Tech stack (limit to first 10)
    if (results['tech-stack'] && !results['tech-stack'].error) {
        const techs = results['tech-stack'].technologies || results['tech-stack'];
        summary.techStack = Array.isArray(techs) ? techs.slice(0, 10) : [];
    }

    // DNS basic info
    if (results.dns && !results.dns.error) {
        summary.dns = {
            hasA: !!results.dns.A?.length,
            hasAAAA: !!results.dns.AAAA?.length,
            hasMX: !!results.dns.MX?.length
        };
    }

    // WHOIS basic info
    if (results.whois && !results.whois.error) {
        summary.whois = {
            registrar: results.whois.registrar,
            createdDate: results.whois.createdDate,
            expiresDate: results.whois.expiresDate
        };
    }

    // Quality score if available
    if (results.quality && !results.quality.error) {
        summary.quality = {
            score: results.quality.score,
            grade: results.quality.grade
        };
    }

    // Count errors
    summary.errorCount = Object.values(results).filter(r => r && r.error).length;
    summary.successCount = Object.values(results).filter(r => r && !r.error).length;

    return summary;
};

/**
 * Start WebCheck scans asynchronously (runs in background, saves to MongoDB)
 * Similar pattern to ZAP async scanning
 * @param {string} url - Target URL to scan
 * @param {string} analysisId - The scan's analysis ID for database lookup
 * @param {string} userId - User ID for ownership verification
 * @returns {Promise<object>} Initial status with pending state
 */
const startAsyncWebCheckScan = async (url, analysisId, userId) => {
    console.log(`[WebCheck] 🚀 Starting async WebCheck scan for: ${url}`);
    console.log(`[WebCheck] Analysis ID: ${analysisId}`);

    // CHECK DATABASE FIRST - this is the source of truth for production
    // This prevents duplicate scans even if backend restarts
    try {
        const existingScan = await ScanResult.findOne({ analysisId, userId });

        // --- EARLY EXIT: If scan is in a terminal state, don't trigger anything ---
        if (existingScan && ['stopped', 'completed', 'failed'].includes(existingScan.status)) {
            console.log(`🛑 [WebCheck] Scan ${analysisId} is in terminal state (${existingScan.status}), refusing to start.`);
            return existingScan.webCheckResult || { status: existingScan.status };
        }

        if (existingScan?.webCheckResult) {
            const status = existingScan.webCheckResult.status;

            // If scan is already running or completed, don't start another
            if (status === 'running') {
                console.log(`[WebCheck] ⏭️ Scan already running in DB for ${analysisId}`);
                return {
                    status: 'running',
                    message: 'WebCheck scan already in progress',
                    progress: existingScan.webCheckResult.progress || 0,
                    analysisId
                };
            }

            if (status === 'completed' || status === 'completed_with_errors') {
                console.log(`[WebCheck] ⏭️ Scan already completed in DB for ${analysisId}`);
                return existingScan.webCheckResult;
            }
        }
    } catch (dbError) {
        console.error('[WebCheck] Failed to check existing scan:', dbError.message);
        // Continue anyway - better to risk duplicate than fail completely
    }

    // Also check in-memory Map (for same-request race conditions)
    if (activeWebCheckScans.has(analysisId)) {
        console.log(`[WebCheck] ⏭️ Scan already in memory for ${analysisId}`);
        return {
            status: 'running',
            message: 'WebCheck scan already in progress',
            analysisId
        };
    }

    // Mark scan as active in memory (for cancellation support)
    activeWebCheckScans.set(analysisId, {
        url,
        userId,
        startTime: Date.now(),
        completed: 0,
        total: ALLOWED_SCANS.length
    });

    // Initialize WebCheck result in database with running status
    // Use atomic findOneAndUpdate to prevent race conditions
    // NOTE: Must set entire webCheckResult object (not nested paths) because
    // MongoDB can't create nested fields inside a null value
    try {
        const result = await ScanResult.findOneAndUpdate(
            {
                analysisId,
                userId,
                // Only update if not already running (atomic check)
                $or: [
                    { webCheckResult: null },
                    { webCheckResult: { $exists: false } },
                    { 'webCheckResult.status': { $exists: false } },
                    { 'webCheckResult.status': { $nin: ['running', 'completed', 'completed_with_errors'] } }
                ]
            },
            {
                // Set entire object to avoid "Cannot create field in null" error
                $set: {
                    webCheckResult: {
                        status: 'running',
                        progress: 0,
                        completedScans: 0,
                        totalScans: ALLOWED_SCANS.length,
                        message: 'Starting WebCheck scans...',
                        startedAt: new Date()
                    }
                }
            },
            { new: true }
        );

        // If no document was updated, scan was already started by another request
        if (!result) {
            console.log(`[WebCheck] ⏭️ Another request already started scan for ${analysisId}`);
            // DON'T delete from Map - another request is running the scan and needs the Map entry
            // activeWebCheckScans.delete(analysisId); // REMOVED - caused race condition bug

            // Fetch current status
            const current = await ScanResult.findOne({ analysisId, userId });
            return current?.webCheckResult || { status: 'running', analysisId };
        }
    } catch (dbError) {
        console.error('[WebCheck] Failed to initialize DB record:', dbError.message);
    }

    // Run scans asynchronously (don't await - runs in background)
    runWebCheckInBackground(url, analysisId, userId).catch(err => {
        console.error(`[WebCheck] Background scan error for ${analysisId}:`, err.message);
    });

    // Return immediately with pending status
    return {
        status: 'running',
        message: 'WebCheck scan started in background',
        progress: 0,
        totalScans: ALLOWED_SCANS.length,
        analysisId
    };
};

/**
 * Run WebCheck scans in background and update MongoDB progressively
 * @param {string} url - Target URL
 * @param {string} analysisId - Analysis ID for DB updates
 * @param {string} userId - User ID for ownership
 */
const runWebCheckInBackground = async (url, analysisId, userId) => {
    console.log(`[WebCheck] 🔄 Background scan started for: ${url}`);
    const startTime = Date.now();

    const results = {};
    let completedCount = 0;
    let hasErrors = false;

    // Run scans in batches to avoid overwhelming the WebCheck service
    // Process 5 scans at a time
    const BATCH_SIZE = 5;
    const batches = [];
    for (let i = 0; i < ALLOWED_SCANS.length; i += BATCH_SIZE) {
        batches.push(ALLOWED_SCANS.slice(i, i + BATCH_SIZE));
    }

    for (const batch of batches) {
        // Check if scan was cancelled (in memory or in database)
        const currentScan = await ScanResult.findOne({ analysisId, userId });
        const isStoppedInDb = currentScan && ['stopped', 'failed'].includes(currentScan.status);

        if (!activeWebCheckScans.has(analysisId) || isStoppedInDb) {
            console.log(`[WebCheck] ⏹️ Scan was cancelled or stopped for ${analysisId}`);
            activeWebCheckScans.delete(analysisId); // Cleanup memory Map if it was stopped in DB
            return;
        }

        // Run batch of scans in parallel with per-scan timeout
        const batchPromises = batch.map(async (scanType) => {
            try {
                // Add a hard timeout of 150 seconds per scan
                // This ensures hanging scans don't block the entire batch indefinitely
                const scanPromise = runScan(scanType, url);
                const timeoutPromise = new Promise((_, reject) => {
                    setTimeout(() => reject(new Error(`${scanType} scan timeout after 150s`)), 150000);
                });

                const data = await Promise.race([scanPromise, timeoutPromise]);
                return { type: scanType, success: true, data };
            } catch (error) {
                console.warn(`[WebCheck] ${scanType} scan failed:`, error.message);
                return { type: scanType, success: false, error: error.message };
            }
        });

        const batchResults = await Promise.allSettled(batchPromises);

        // Process batch results
        for (const result of batchResults) {
            completedCount++;
            const scanResult = result.status === 'fulfilled' ? result.value : {
                type: 'unknown',
                success: false,
                error: result.reason?.message || 'Scan failed'
            };

            if (scanResult.success) {
                results[scanResult.type] = scanResult.data;
            } else {
                results[scanResult.type] = { error: scanResult.error };
                hasErrors = true;
            }
        }

        // Update progress in database after each batch
        // Don't store partialResults - they can exceed MongoDB 16MB limit
        const progress = Math.round((completedCount / ALLOWED_SCANS.length) * 100);
        try {
            await ScanResult.findOneAndUpdate(
                { analysisId, userId },
                {
                    $set: {
                        webCheckResult: {
                            status: 'running',
                            progress,
                            completedScans: completedCount,
                            totalScans: ALLOWED_SCANS.length,
                            message: `Completed ${completedCount}/${ALLOWED_SCANS.length} scans...`,
                            // Only store lightweight partial summary during progress
                            partialSummary: extractWebCheckSummary(results),
                            startedAt: new Date(startTime)
                        }
                    }
                }
            );
            console.log(`[WebCheck] 📊 Progress: ${progress}% (${completedCount}/${ALLOWED_SCANS.length})`);
        } catch (dbError) {
            console.error('[WebCheck] Failed to update progress:', dbError.message);
        }

        // Update active scan tracker
        const activeScan = activeWebCheckScans.get(analysisId);
        if (activeScan) {
            activeScan.completed = completedCount;
        }
    }

    // All scans complete - save final results
    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[WebCheck] ✅ All scans complete for ${url} in ${duration}s`);

    // Truncate large data arrays to prevent bloat
    // Archives (Wayback Machine) can have tens of thousands of entries for old domains
    if (results.archives && Array.isArray(results.archives) && results.archives.length > 20) {
        const originalCount = results.archives.length;
        results.archives = results.archives.slice(0, 20);
        console.log(`[WebCheck] ✂️ Truncated archives from ${originalCount} to 20 entries`);
    }

    // Log size of each scan type to identify bloat
    console.log(`[WebCheck] 📊 Size breakdown by scan type:`);
    const scanSizes = [];
    for (const [scanType, data] of Object.entries(results)) {
        const scanJson = JSON.stringify(data);
        const scanSize = Buffer.byteLength(scanJson, 'utf-8');
        const scanSizeMB = (scanSize / (1024 * 1024)).toFixed(3);
        scanSizes.push({ type: scanType, size: scanSize, sizeMB: scanSizeMB });
    }
    // Sort by size descending and log all
    scanSizes.sort((a, b) => b.size - a.size);
    scanSizes.forEach((s, i) => {
        console.log(`   ${i + 1}. ${s.type}: ${s.sizeMB}MB`);
    });

    // Convert results to JSON
    const resultsJson = JSON.stringify(results, null, 2);
    const resultsSize = Buffer.byteLength(resultsJson, 'utf-8');
    const resultsSizeMB = (resultsSize / (1024 * 1024)).toFixed(2);
    console.log(`[WebCheck] 📊 Total results size: ${resultsSizeMB}MB`);

    // Extract summary for MongoDB (lightweight data only)
    const summary = extractWebCheckSummary(results);

    // Decide storage strategy based on size
    // MongoDB doc limit is 16MB, but we use 10MB as safe threshold
    const GRIDFS_THRESHOLD = 10 * 1024 * 1024; // 10MB
    let resultsFileId = null;
    let fullResults = null;

    if (resultsSize > GRIDFS_THRESHOLD) {
        // Large data - use GridFS
        console.log(`[WebCheck] 📤 Data exceeds ${GRIDFS_THRESHOLD / (1024 * 1024)}MB, using GridFS...`);

        // Update status to show uploading in progress
        try {
            await ScanResult.findOneAndUpdate(
                { analysisId, userId },
                {
                    $set: {
                        'webCheckResult.status': 'uploading',
                        'webCheckResult.uploadProgress': 0,
                        'webCheckResult.message': `Uploading ${resultsSizeMB}MB to storage...`
                    }
                }
            );
        } catch (e) {
            console.warn('[WebCheck] Failed to update uploading status:', e.message);
        }

        // Progress callback to update database with upload progress
        const onUploadProgress = async ({ percent, uploadedMB, totalMB, elapsed }) => {
            try {
                await ScanResult.findOneAndUpdate(
                    { analysisId, userId },
                    {
                        $set: {
                            'webCheckResult.uploadProgress': percent,
                            'webCheckResult.message': `Uploading: ${uploadedMB}MB / ${totalMB}MB (${percent}%) - ${elapsed}s`
                        }
                    }
                );
            } catch (e) {
                // Ignore update errors to not slow down upload
            }
        };

        try {
            resultsFileId = await gridfsService.uploadFile(
                resultsJson,
                `webcheck_results_${analysisId}.json`,
                { analysisId, userId, contentType: 'application/json' },
                WEBCHECK_BUCKET,
                600000, // timeout
                onUploadProgress // progress callback
            );
            console.log(`[WebCheck] 📦 Full results stored in GridFS: ${resultsFileId}`);
        } catch (gridfsError) {
            console.error('[WebCheck] ❌ Failed to store results in GridFS:', gridfsError.message);
            // Fallback: save full results directly (may fail if > 16MB)
            fullResults = results;
        }
    } else {
        // Small data - save directly to MongoDB (no GridFS needed)
        console.log(`[WebCheck] 💾 Data under threshold, saving directly to MongoDB`);
        fullResults = results;
    }

    // Save to database
    try {
        await ScanResult.findOneAndUpdate(
            { analysisId, userId },
            {
                $set: {
                    webCheckResult: {
                        status: hasErrors ? 'completed_with_errors' : 'completed',
                        progress: 100,
                        completedScans: ALLOWED_SCANS.length,
                        totalScans: ALLOWED_SCANS.length,
                        message: 'WebCheck scan completed',
                        summary, // Lightweight summary for display
                        fullResults, // Full results (if small enough)
                        resultsFileId, // GridFS reference (if large)
                        hasErrors,
                        duration: parseFloat(duration),
                        completedAt: new Date()
                    }
                }
            }
        );
        console.log(`[WebCheck] 💾 Results saved to database for ${analysisId}`);
    } catch (dbError) {
        console.error('[WebCheck] Failed to save results:', dbError.message);
    }

    // Remove from active scans
    activeWebCheckScans.delete(analysisId);
};

/**
 * Stop an active WebCheck scan
 * @param {string} analysisId - The analysis ID to stop
 * @returns {boolean} Whether the scan was stopped
 */
const stopWebCheckScan = (analysisId) => {
    if (activeWebCheckScans.has(analysisId)) {
        console.log(`[WebCheck] 🛑 Stopping scan for ${analysisId}`);
        activeWebCheckScans.delete(analysisId);
        return true;
    }
    return false;
};

/**
 * Check if a WebCheck scan is active
 * @param {string} analysisId - The analysis ID to check
 * @returns {object|null} Active scan info or null
 */
const getActiveScanStatus = (analysisId) => {
    return activeWebCheckScans.get(analysisId) || null;
};

/**
 * Short-lived in-memory cache for GridFS results.
 * Prevents redundant downloads when the same scan is requested multiple times
 * in quick succession (e.g., React StrictMode double-invoke, page refresh).
 * Cache entries expire after 60 seconds.
 */
const _gridfsCache = new Map();
const GRIDFS_CACHE_TTL_MS = 60 * 1000;

/**
 * Retrieve full WebCheck results
 * Checks inline fullResults first, then in-memory cache, then GridFS if needed
 * @param {object} webCheckResult - The webCheckResult object from ScanResult
 * @returns {Promise<object|null>} Full results or null if not found
 */
const getFullResults = async (webCheckResult) => {
    if (!webCheckResult) {
        console.log('[WebCheck] getFullResults: No webCheckResult provided');
        return null;
    }

    console.log(`[WebCheck] getFullResults: status=${webCheckResult.status}, hasFullResults=${!!webCheckResult.fullResults}, hasResultsFileId=${!!webCheckResult.resultsFileId}`);

    // Check for inline results first (most common case without screenshots)
    if (webCheckResult.fullResults) {
        const keys = Object.keys(webCheckResult.fullResults);
        console.log(`[WebCheck] getFullResults: Found inline fullResults with ${keys.length} scan types`);
        return webCheckResult.fullResults;
    }

    // Fall back to GridFS for large results
    if (webCheckResult.resultsFileId) {
        const fileId = webCheckResult.resultsFileId.toString();

        // Check in-memory cache first
        const cached = _gridfsCache.get(fileId);
        if (cached && (Date.now() - cached.timestamp < GRIDFS_CACHE_TTL_MS)) {
            console.log(`[WebCheck] getFullResults: Cache HIT for fileId=${fileId} (${Object.keys(cached.data).length} scan types)`);
            return cached.data;
        }

        console.log(`[WebCheck] getFullResults: Fetching from GridFS, fileId=${fileId}`);
        try {
            const buffer = await gridfsService.downloadFile(webCheckResult.resultsFileId, WEBCHECK_BUCKET);
            const results = JSON.parse(buffer.toString('utf-8'));
            const keys = Object.keys(results);
            console.log(`[WebCheck] getFullResults: Retrieved ${keys.length} scan types from GridFS`);

            // Cache the result
            _gridfsCache.set(fileId, { data: results, timestamp: Date.now() });

            // Clean up expired entries periodically
            if (_gridfsCache.size > 10) {
                const now = Date.now();
                for (const [key, val] of _gridfsCache) {
                    if (now - val.timestamp > GRIDFS_CACHE_TTL_MS) _gridfsCache.delete(key);
                }
            }

            return results;
        } catch (error) {
            console.error('[WebCheck] Failed to retrieve results from GridFS:', error.message);
            return null;
        }
    }

    console.log('[WebCheck] getFullResults: No fullResults or resultsFileId found');
    return null;
};

module.exports = {
    runScan,
    runAllScans,
    getAvailableScans,
    checkHealth,
    startAsyncWebCheckScan,
    stopWebCheckScan,
    getActiveScanStatus,
    getFullResults,
    ALLOWED_SCANS
};
