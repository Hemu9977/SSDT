// Enhanced ZAP Service with URL-Specific Vulnerability Tracking
// File: backend/services/zapService.js

const axios = require('axios');
const ScanResult = require('../models/ScanResult');
const ZapAlert = require('../models/ZapAlert');
const gridfsService = require('./gridfsService');
const cleanupService = require('./cleanupService');

// ============================================================================
// ZAP API CONFIGURATION
// ============================================================================

const ZAP_URL = process.env.ZAP_API_URL || 'http://127.0.0.1:8080';
const ZAP_API_KEY = process.env.ZAP_API_KEY || 'ssdt-secure-zap-2025';

// Create HTTP agent with keep-alive to prevent socket hang up errors
const http = require('http');
const httpAgent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 10,
  timeout: 120000
});

const zapApi = axios.create({
  baseURL: ZAP_URL,
  timeout: 120000, // Increased timeout to 2 minutes
  httpAgent: httpAgent,
  headers: {
    'X-Zap-Api-Key': ZAP_API_KEY,
    'Content-Type': 'application/json',
    'Connection': 'keep-alive'
  },
  params: {
    apikey: ZAP_API_KEY
  },
  // Retry on network errors
  maxRedirects: 5
});

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ============================================================================
// RETRY LOGIC WITH EXPONENTIAL BACKOFF
// ============================================================================

/**
 * Execute a ZAP API call with retry logic and exponential backoff
 * @param {Function} apiCall - Async function that makes the API call
 * @param {number} maxRetries - Maximum number of retries (default: 3)
 * @param {number} baseDelay - Base delay in ms (default: 1000)
 * @param {string} operationName - Name of the operation for logging
 * @returns {Promise<any>} - Result of the API call
 */
async function zapApiWithRetry(apiCall, maxRetries = 3, baseDelay = 1000, operationName = 'ZAP API call') {
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await apiCall();
    } catch (error) {
      lastError = error;
      const isRetryable = error.code === 'ECONNRESET' ||
                          error.code === 'ETIMEDOUT' ||
                          error.code === 'ENOTFOUND' ||
                          error.message?.includes('socket hang up') ||
                          error.message?.includes('ECONNREFUSED') ||
                          error.message?.includes('timeout');

      if (!isRetryable || attempt === maxRetries) {
        console.error(`❌ ${operationName} failed after ${attempt} attempt(s): ${error.message}`);
        throw error;
      }

      const delay = baseDelay * Math.pow(2, attempt - 1); // Exponential backoff: 1s, 2s, 4s
      console.warn(`⚠️ ${operationName} failed (attempt ${attempt}/${maxRetries}): ${error.message}. Retrying in ${delay}ms...`);
      await sleep(delay);
    }
  }

  throw lastError;
}

// ============================================================================
// URL-SPECIFIC VULNERABILITY TRACKING
// ============================================================================

/**
 * Structure for URL-specific alerts:
 * {
 *   "Missing Anti-clickjacking Header": {
 *     risk: "Medium",
 *     description: "...",
 *     solution: "...",
 *     occurrences: [
 *       { url: "https://example.com/page1", instances: 1 },
 *       { url: "https://example.com/page2", instances: 1 }
 *     ],
 *     totalCount: 2
 *   }
 * }
 */

function groupAlertsByUrl(alerts) {
  const grouped = {};

  alerts.forEach(alert => {
    const key = alert.alert; // Use alert name as key

    if (!grouped[key]) {
      grouped[key] = {
        alert: alert.alert,
        risk: alert.risk,
        confidence: alert.confidence,
        description: alert.description,
        solution: alert.solution,
        reference: alert.reference,
        cweid: alert.cweid,
        wascid: alert.wascid,
        occurrences: [],
        totalCount: 0
      };
    }

    // Add URL-specific occurrence
    if (alert.instances && alert.instances.length > 0) {
      alert.instances.forEach(instance => {
        grouped[key].occurrences.push({
          url: instance.uri || alert.url,
          method: instance.method,
          param: instance.param,
          attack: instance.attack,
          evidence: instance.evidence
        });
        grouped[key].totalCount++;
      });
    } else {
      // Fallback: alert without detailed instances
      grouped[key].occurrences.push({
        url: alert.url,
        instances: 1
      });
      grouped[key].totalCount++;
    }
  });

  return Object.values(grouped);
}

/**
 * Create TWO versions of the alert data:
 * 1. Summary version (for MongoDB document) - compact, under 16MB
 * 2. Detailed version (for GridFS) - complete with all URLs
 */
function createDualVersionAlerts(alerts) {
  const grouped = groupAlertsByUrl(alerts);

  // SUMMARY VERSION: Top 5 URLs per alert type
  const summaryAlerts = grouped.map(alert => ({
    alert: alert.alert,
    risk: alert.risk,
    confidence: alert.confidence,
    description: alert.description ? alert.description.substring(0, 200) + '...' : '',
    solution: alert.solution ? alert.solution.substring(0, 150) + '...' : '',
    totalOccurrences: alert.totalCount,
    sampleUrls: alert.occurrences.slice(0, 5).map(occ => occ.url), // Top 5 URLs only
    hasMoreUrls: alert.occurrences.length > 5
  }));

  // DETAILED VERSION: All URLs, all data
  const detailedAlerts = grouped.map(alert => ({
    alert: alert.alert,
    risk: alert.risk,
    confidence: alert.confidence,
    description: alert.description,
    solution: alert.solution,
    reference: alert.reference,
    cweid: alert.cweid,
    wascid: alert.wascid,
    totalOccurrences: alert.totalCount,
    occurrences: alert.occurrences // ALL URLs with full details
  }));

  return { summaryAlerts, detailedAlerts };
}

// ============================================================================
// SIMPLIFIED ZAP SCAN (For scan orchestration routes - returns simple structure)
// ============================================================================

/**
 * Simplified ZAP scan that returns old structure for backward compatibility
 * This is called from the scan orchestration routes during combined scan
 *
 * Returns: { site, riskCounts, alerts, totalAlerts, totalOccurrences, reportFiles }
 */
async function runZapScanWithUrlTracking(options) {
  const {
    target,
    scanId,
    maxUrls = 1000,
    timeout = 600000, // 10 minutes
    onProgress = null
  } = options;

  console.log(`🔍 Starting simplified ZAP scan: ${target}`);

  try {
    // Configure file exclusions BEFORE scanning
    console.log('⚙️ Configuring file type exclusions...');
    const exclusionPatterns = [
      '.*\\.webm.*', '.*\\.mp4.*', '.*\\.mov.*', '.*\\.avi.*',
      '.*\\.mkv.*', '.*\\.flv.*', '.*\\.wmv.*', '.*\\.m4v.*',
      '.*\\.zip$', '.*\\.tar$', '.*\\.gz$', '.*\\.rar$',
      '.*\\.7z$', '.*\\.iso$', '.*\\.dmg$', '.*\\.bz2$',
      '.*\\.pdf$', '.*\\.woff$', '.*\\.woff2$', '.*\\.ttf$'
    ];

    for (const pattern of exclusionPatterns) {
      try {
        await zapApi.get('/JSON/core/action/excludeFromProxy/', {
          params: { regex: pattern }
        });
      } catch (excludeError) {
        // Ignore exclusion errors
      }
    }

    // Step 1: Spider the target
    if (onProgress) onProgress({ stage: 'spider', progress: 0 });

    const spiderResponse = await zapApi.get('/JSON/spider/action/scan/', {
      params: {
        url: target,
        maxChildren: maxUrls,
        recurse: true,
        contextName: '',
        subtreeOnly: false
      }
    });

    const spiderScanId = spiderResponse.data.scan;
    console.log(`🕷️ Spider scan started: ${spiderScanId}`);

    // Wait for spider to complete with timeout
    let spiderProgress = 0;
    let spiderTimeout = 0;
    const maxSpiderWait = 120; // 2 minutes max

    while (spiderProgress < 100 && spiderTimeout < maxSpiderWait) {
      await sleep(2000);

      const statusResponse = await zapApi.get('/JSON/spider/view/status/', {
        params: { scanId: spiderScanId }
      });

      spiderProgress = parseInt(statusResponse.data.status);
      if (onProgress) onProgress({ stage: 'spider', progress: spiderProgress });
      console.log(`🕷️ Spider progress: ${spiderProgress}%`);
      spiderTimeout += 2;
    }

    if (spiderProgress < 100) {
      console.warn(`⚠️ Spider timeout after ${spiderTimeout}s`);
    }

    // Enable passive scanning
    await zapApi.get('/JSON/pscan/action/enableAllScanners/');

    // Wait briefly for passive scan
    let passiveScanTimeout = 0;
    const maxPassiveWait = 30; // 30 seconds max

    while (passiveScanTimeout < maxPassiveWait) {
      await sleep(2000);

      try {
        const recordsResponse = await zapApi.get('/JSON/pscan/view/recordsToScan/');
        const recordsToScan = parseInt(recordsResponse.data.recordsToScan || 0);

        if (recordsToScan === 0) {
          console.log('✅ Passive scan complete');
          break;
        }
        passiveScanTimeout += 2;
      } catch (pscanError) {
        break;
      }
    }

    // Configure active scanner with limits
    try {
      await zapApi.get('/JSON/ascan/action/setOptionMaxScanDurationInMins/', {
        params: { Integer: 20 }
      });
      await zapApi.get('/JSON/ascan/action/setOptionMaxRuleDurationInMins/', {
        params: { Integer: 7 }
      });
    } catch (configError) {
      console.warn('⚠️ Could not configure active scanner');
    }

    // Step 2: Active scan
    if (onProgress) onProgress({ stage: 'scan', progress: 0 });

    const scanResponse = await zapApi.get('/JSON/ascan/action/scan/', {
      params: {
        url: target,
        recurse: true,
        inScopeOnly: false,
        scanPolicyName: '',
        method: '',
        postData: ''
      }
    });

    const activeScanId = scanResponse.data.scan;
    console.log(`⚡ Active scan started: ${activeScanId}`);

    // Wait for active scan to complete with stuck detection
    let scanProgress = 0;
    let lastProgress = 0;
    let stuckCount = 0;
    const maxStuckIterations = 15; // 75 seconds
    const activeScanStartTime = Date.now();
    const maxActiveScanTime = 25 * 60 * 1000; // 25 minutes max

    while (scanProgress < 100) {
      await sleep(5000);

      // Check timeout
      if (Date.now() - activeScanStartTime > maxActiveScanTime) {
        console.warn('⚠️ Active scan timeout, stopping...');
        try {
          await zapApi.get('/JSON/ascan/action/stop/', {
            params: { scanId: activeScanId }
          });
        } catch (stopError) {
          // Ignore stop errors
        }
        break;
      }

      const statusResponse = await zapApi.get('/JSON/ascan/view/status/', {
        params: { scanId: activeScanId }
      });

      scanProgress = parseInt(statusResponse.data.status);

      // Stuck detection
      if (scanProgress === lastProgress) {
        stuckCount++;
        if (stuckCount >= maxStuckIterations) {
          console.warn(`⚠️ Scan stuck at ${scanProgress}%, stopping...`);
          try {
            await zapApi.get('/JSON/ascan/action/stop/', {
              params: { scanId: activeScanId }
            });
          } catch (stopError) {
            // Ignore stop errors
          }
          break;
        }
      } else {
        stuckCount = 0;
      }
      lastProgress = scanProgress;

      if (onProgress) onProgress({ stage: 'scan', progress: scanProgress });
      console.log(`⚡ Scan progress: ${scanProgress}% | Stuck: ${stuckCount}`);
    }

    // Step 3: Retrieve alerts with URL details
    console.log('📊 Retrieving alerts...');

    const alertsResponse = await zapApi.get('/JSON/core/view/alerts/', {
      params: {
        baseurl: target,
        start: 0,
        count: 10000 // Get all alerts
      }
    });

    const rawAlerts = alertsResponse.data.alerts || [];
    console.log(`📊 Retrieved ${rawAlerts.length} raw alerts`);

    // Step 4: Generate HTML report (for GridFS storage)
    const htmlReportResponse = await zapApi.get('/OTHER/core/other/htmlreport/', {
      responseType: 'arraybuffer'
    });

    // Step 5: Process alerts into dual versions
    const { summaryAlerts, detailedAlerts } = createDualVersionAlerts(rawAlerts);

    console.log(`📊 Grouped into ${summaryAlerts.length} unique alert types`);
    console.log(`📊 Summary version size: ${JSON.stringify(summaryAlerts).length} bytes`);
    console.log(`📊 Detailed version size: ${JSON.stringify(detailedAlerts).length} bytes`);

    // Step 6: Calculate risk counts
    const riskCounts = summaryAlerts.reduce((acc, alert) => {
      acc[alert.risk] = (acc[alert.risk] || 0) + 1;
      return acc;
    }, { High: 0, Medium: 0, Low: 0, Informational: 0 });

    // Step 7: Store detailed report in GridFS
    const htmlBuffer = Buffer.from(htmlReportResponse.data);
    const htmlFileId = await gridfsService.uploadFile(
      htmlBuffer,
      `zap_report_${scanId}.html`,
      { scanId, contentType: 'text/html' }
    );

    // Store detailed alerts JSON in GridFS (for future download)
    const detailedAlertsBuffer = Buffer.from(JSON.stringify(detailedAlerts, null, 2), 'utf-8');
    const detailedAlertsFileId = await gridfsService.uploadFile(
      detailedAlertsBuffer,
      `zap_detailed_alerts_${scanId}.json`,
      { scanId, contentType: 'application/json' }
    );

    console.log(`✅ HTML report stored in GridFS: ${htmlFileId}`);
    console.log(`✅ Detailed alerts stored in GridFS: ${detailedAlertsFileId}`);

    // Step 8: Return data for MongoDB (compact version)
    return {
      scanId,
      site: target, // For backward compatibility with scan orchestration routes
      target,
      alerts: summaryAlerts, // COMPACT VERSION for MongoDB
      riskCounts,
      totalAlerts: summaryAlerts.length,
      totalOccurrences: summaryAlerts.reduce((sum, a) => sum + a.totalOccurrences, 0),
      reportFiles: [
        {
          fileId: htmlFileId.toString(), // GridFS returns ObjectId, convert to string
          filename: `zap_report_${scanId}.html`,
          contentType: 'text/html',
          format: 'html', // For zapRoutes download endpoint
          size: htmlBuffer.length
        },
        {
          fileId: detailedAlertsFileId.toString(), // GridFS returns ObjectId, convert to string
          filename: `zap_detailed_alerts_${scanId}.json`,
          contentType: 'application/json',
          format: 'json', // For zapRoutes download endpoint
          size: detailedAlertsBuffer.length,
          description: 'Full alert details with all affected URLs'
        }
      ],
      completedAt: new Date()
    };

  } catch (error) {
    console.error('❌ ZAP scan failed:', error.message);
    throw error;
  }
}

// ============================================================================
// FRONTEND API: Download Detailed Report
// ============================================================================

/**
 * Express route to download detailed alert report
 * Usage: GET /api/zap/detailed-report/:scanId
 */
async function downloadDetailedReport(req, res) {
  try {
    const { scanId } = req.params;

    // Find scan result by analysisId (scanId in the route)
    const scanResult = await ScanResult.findOne({ analysisId: scanId });
    if (!scanResult) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Check if zapResult exists
    if (!scanResult.zapResult || !scanResult.zapResult.reportFiles) {
      return res.status(404).json({
        error: 'ZAP report not available for this scan',
        hint: 'This scan may not have completed ZAP scanning yet'
      });
    }

    // Find detailed alerts file
    const detailedFile = scanResult.zapResult.reportFiles.find(
      f => f.filename.includes('detailed_alerts')
    );

    if (!detailedFile) {
      return res.status(404).json({
        error: 'Detailed report not found',
        hint: 'The detailed alert report may not have been generated for this scan'
      });
    }

    // Stream from GridFS using correct method name
    const stream = gridfsService.downloadFileStream(detailedFile.fileId);

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${detailedFile.filename}"`);

    stream.on('error', (streamError) => {
      console.error('GridFS stream error:', streamError);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Failed to stream report file' });
      }
    });

    stream.pipe(res);

  } catch (error) {
    console.error('Download error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to download report' });
    }
  }
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

/**
 * Check if ZAP service is healthy and accessible
 */
async function checkZapHealth() {
  try {
    console.log(`🔍 Checking ZAP health at: ${ZAP_URL}`);
    const response = await zapApi.get('/JSON/core/view/version/');

    return {
      healthy: true,
      version: response.data.version,
      url: ZAP_URL
    };
  } catch (error) {
    console.error('❌ ZAP health check failed:', error.message);
    return {
      healthy: false,
      error: error.message,
      url: ZAP_URL
    };
  }
}

// ============================================================================
// MAIN SCAN WORKFLOW WITH DATABASE INTEGRATION
// ============================================================================

/**
 * Run ZAP scan and store results in database
 * This is the main entry point called from the API routes
 */
async function runZapScanWithDB(targetUrl, userId, options = {}) {
  const { scanId } = options;

  console.log(`🚀 Starting ZAP comprehensive scan for user ${userId}: ${targetUrl}`);
  console.log(`   Scan ID: ${scanId}`);
  console.log(`   Mode: Enterprise Comprehensive (up to 12 hours, 20,000 URLs)`);

  let scanResult = null;

  try {
    // Create initial scan result in database with status "scanning"
    scanResult = new ScanResult({
      analysisId: scanId,
      userId: userId,
      target: targetUrl,
      status: 'scanning',
      zapResult: {
        status: 'initializing',
        phase: 'starting',
        progress: 0,
        urlsFound: 0,
        alerts: []
      }
    });
    await scanResult.save();
    console.log(`✅ Initial scan result created in database: ${scanId}`);

    // Update helper function to update database as scan progresses
    const updateProgress = async (phase, progress, additionalData = {}) => {
      try {
        await ScanResult.updateOne(
          { analysisId: scanId },
          {
            $set: {
              'zapResult.phase': phase,
              'zapResult.progress': progress,
              'zapResult.lastUpdate': new Date(),
              ...Object.keys(additionalData).reduce((acc, key) => {
                acc[`zapResult.${key}`] = additionalData[key];
                return acc;
              }, {})
            }
          }
        );
        console.log(`📊 Progress: ${phase} - ${progress}%`);
      } catch (updateError) {
        console.error('Failed to update progress:', updateError.message);
      }
    };

    // Phase 1: Configure file exclusions BEFORE scanning
    await updateProgress('configuring', 3);
    console.log('⚙️ Configuring file type exclusions...');

    const exclusionPatterns = [
      // Videos (prevent infinite loops and timeouts)
      '.*\\.webm.*', '.*\\.mp4.*', '.*\\.mov.*', '.*\\.avi.*',
      '.*\\.mkv.*', '.*\\.flv.*', '.*\\.wmv.*', '.*\\.m4v.*',
      // Archives (prevent database bloat)
      '.*\\.zip$', '.*\\.tar$', '.*\\.gz$', '.*\\.rar$',
      '.*\\.7z$', '.*\\.iso$', '.*\\.dmg$', '.*\\.bz2$',
      // Executables (not scannable)
      '.*\\.exe$', '.*\\.msi$', '.*\\.app$',
      '.*\\.deb$', '.*\\.rpm$', '.*\\.pkg$',
      // Large media files
      '.*\\.pdf$', '.*\\.doc$', '.*\\.docx$', '.*\\.ppt$', '.*\\.pptx$',
      // Images (large files)
      '.*\\.png\\?.*size=large.*', '.*\\.jpg\\?.*size=large.*',
      // Fonts
      '.*\\.woff$', '.*\\.woff2$', '.*\\.ttf$', '.*\\.eot$'
    ];

    let excludedCount = 0;
    for (const pattern of exclusionPatterns) {
      try {
        await zapApi.get('/JSON/core/action/excludeFromProxy/', {
          params: { regex: pattern }
        });
        excludedCount++;
      } catch (excludeError) {
        console.warn(`⚠️ Failed to exclude pattern ${pattern}:`, excludeError.message);
      }
    }
    console.log(`✅ Configured ${excludedCount}/${exclusionPatterns.length} exclusion patterns`);

    // Phase 1.5: Create ZAP context for domain scoping
    // This prevents ZAP from crawling external domains (CDNs, analytics, social media, etc.)
    await updateProgress('configuring', 4, { message: 'Setting up domain scope...' });
    console.log('🔒 Configuring domain scope to filter external URLs...');

    const contextName = `scan_${scanId}`;
    let contextCreated = false;

    try {
      // Extract domain from target URL
      const targetUrlObj = new URL(targetUrl);
      const targetDomain = targetUrlObj.hostname;
      const targetDomainEscaped = targetDomain.replace(/\./g, '\\.');

      // Create a new context for this scan
      await zapApi.get('/JSON/context/action/newContext/', {
        params: { contextName }
      });
      console.log(`✅ Created ZAP context: ${contextName}`);

      // Include only the target domain and its subdomains
      const includePatterns = [
        `https?://${targetDomainEscaped}.*`,           // Main domain
        `https?://.*\\.${targetDomainEscaped}.*`       // Subdomains
      ];

      for (const pattern of includePatterns) {
        try {
          await zapApi.get('/JSON/context/action/includeInContext/', {
            params: { contextName, regex: pattern }
          });
          console.log(`   ✓ Include: ${pattern}`);
        } catch (err) {
          console.warn(`   ⚠️ Failed to add include pattern: ${err.message}`);
        }
      }

      // Exclude common external domains that ZAP tends to crawl
      const excludeDomains = [
        // Analytics & Tracking
        '.*google-analytics\\.com.*',
        '.*googletagmanager\\.com.*',
        '.*doubleclick\\.net.*',
        '.*facebook\\.com.*',
        '.*facebook\\.net.*',
        '.*twitter\\.com.*',
        '.*linkedin\\.com.*',
        '.*hotjar\\.com.*',
        '.*mixpanel\\.com.*',
        '.*segment\\.io.*',
        '.*amplitude\\.com.*',
        // CDNs
        '.*cdn\\.jsdelivr\\.net.*',
        '.*cdnjs\\.cloudflare\\.com.*',
        '.*unpkg\\.com.*',
        '.*cloudflare\\.com.*',
        '.*fastly\\.net.*',
        '.*akamaihd\\.net.*',
        '.*akamai\\.net.*',
        '.*cloudfront\\.net.*',
        // Fonts & Icons
        '.*fonts\\.googleapis\\.com.*',
        '.*fonts\\.gstatic\\.com.*',
        '.*use\\.fontawesome\\.com.*',
        '.*use\\.typekit\\.net.*',
        // Google Services
        '.*google\\.com.*',
        '.*gstatic\\.com.*',
        '.*googleapis\\.com.*',
        '.*googlesyndication\\.com.*',
        '.*googleadservices\\.com.*',
        // Social Media Embeds
        '.*instagram\\.com.*',
        '.*youtube\\.com.*',
        '.*youtu\\.be.*',
        '.*vimeo\\.com.*',
        '.*tiktok\\.com.*',
        // Other Common Third Parties
        '.*jquery\\.com.*',
        '.*bootstrapcdn\\.com.*',
        '.*gravatar\\.com.*',
        '.*wp\\.com.*',
        '.*wordpress\\.com.*',
        '.*stripe\\.com.*',
        '.*paypal\\.com.*',
        '.*recaptcha\\.net.*',
        '.*hcaptcha\\.com.*',
        // Auth Endpoints to prevent logout issues
        '.*logout.*',
        '.*signout.*',
        '.*sign-out.*',
        '.*/auth/logout.*'
      ];

      for (const pattern of excludeDomains) {
        try {
          await zapApi.get('/JSON/context/action/excludeFromContext/', {
            params: { contextName, regex: pattern }
          });
        } catch (err) {
          // Silently continue - some patterns may fail
        }
      }
      console.log(`✅ Excluded ${excludeDomains.length} external domain patterns`);

      // Set context in scope
      await zapApi.get('/JSON/context/action/setContextInScope/', {
        params: { contextName, booleanInScope: 'true' }
      });

      contextCreated = true;
      console.log(`✅ Domain scope configured: Only crawling ${targetDomain}`);

    } catch (contextError) {
      console.warn('⚠️ Failed to create ZAP context:', contextError.message);
      console.warn('⚠️ Scan will proceed without domain scoping (may crawl external URLs)');
    }

    // Phase 2: Access the URL
    await updateProgress('accessing', 5);
    await zapApi.get('/JSON/core/action/accessUrl/', {
      params: { url: targetUrl }
    });
    await sleep(2000);

    // Phase 2: Spider (Traditional crawling)
    await updateProgress('spidering', 10);
    console.log('🕷️ Starting traditional spider...');
    if (contextCreated) {
      console.log(`🔒 Spider will use context: ${contextName} (domain-scoped)`);
    }

    // ENTERPRISE SPIDER CONFIG - comprehensive scanning for paid clients
    const spiderConfig = {
      maxDepth: 30,           // Deep crawling for maximum coverage
      maxDuration: 600,       // 600 minutes = 10 hours maximum
      maxChildren: 20000      // Support up to 20,000 URLs for enterprise reports
    };

    const spiderResponse = await zapApi.get('/JSON/spider/action/scan/', {
      params: {
        url: targetUrl,
        maxChildren: spiderConfig.maxChildren,
        recurse: true,
        contextName: contextCreated ? contextName : '',  // Use context if created
        subtreeOnly: contextCreated  // Only scan subtree if context is set
      }
    });

    const spiderScanId = spiderResponse.data.scan;
    console.log(`🕷️ Spider scan ID: ${spiderScanId}`);

    // Wait for spider to complete with timeout protection
    let spiderProgress = 0;
    let spiderIterations = 0;
    const maxSpiderIterations = Math.ceil(spiderConfig.maxDuration * 60 / 3); // Based on maxDuration in minutes

    while (spiderProgress < 100 && spiderIterations < maxSpiderIterations) {
      await sleep(3000);
      spiderIterations++;

      const statusResponse = await zapApi.get('/JSON/spider/view/status/', {
        params: { scanId: spiderScanId }
      });

      spiderProgress = parseInt(statusResponse.data.status);

      // Get current URL count during spider
      let currentUrlCount = 0;
      try {
        const spiderUrlsResponse = await zapApi.get('/JSON/spider/view/results/', {
          params: { scanId: spiderScanId }
        });
        currentUrlCount = spiderUrlsResponse.data.results?.length || 0;
      } catch (err) {
        console.warn('⚠️ Could not get spider URL count');
      }

      const uiProgress = 10 + Math.floor(spiderProgress * 0.2); // 10% to 30%
      await updateProgress('spidering', uiProgress, {
        message: `Crawling pages: ${currentUrlCount} URLs found (${spiderProgress}%)`,
        urlsFound: currentUrlCount
      });
    }

    if (spiderProgress < 100) {
      console.warn(`⚠️ Spider timeout after ${spiderIterations * 3}s`);
    }

    // Get URLs found by spider
    const spiderResults = await zapApi.get('/JSON/spider/view/results/', {
      params: { scanId: spiderScanId }
    });
    const spiderUrls = spiderResults.data.results?.length || 0;
    console.log(`🕷️ Spider complete: ${spiderUrls} URLs found`);

    // Phase 2.5: AJAX Spider (for JavaScript-heavy sites)
    await updateProgress('ajax_spider', 32, { message: 'Configuring AJAX spider...' });
    console.log('🌐 Configuring AJAX spider for JavaScript content...');

    try {
      // Configure AJAX Spider for maximum discovery
      const ajaxConfig = {
        maxDuration: spiderConfig.maxDuration || 5, // Use same duration as traditional spider
        maxCrawlDepth: 10, // Deep crawling
        numberOfBrowsers: 4, // Parallel browsers for speed
        clickDefaultElems: true, // Click buttons, links etc
        clickElemsOnce: false, // Click elements multiple times for different states
        randomInputs: true // Try random inputs in forms
      };

      // Apply AJAX spider configuration
      await zapApi.get('/JSON/ajaxSpider/action/setOptionMaxDuration/', {
        params: { Integer: ajaxConfig.maxDuration }
      });
      await zapApi.get('/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/', {
        params: { Integer: ajaxConfig.maxCrawlDepth }
      });
      await zapApi.get('/JSON/ajaxSpider/action/setOptionNumberOfBrowsers/', {
        params: { Integer: ajaxConfig.numberOfBrowsers }
      });
      await zapApi.get('/JSON/ajaxSpider/action/setOptionBrowserId/', {
        params: { String: 'firefox-headless' }
      });
      await zapApi.get('/JSON/ajaxSpider/action/setOptionClickDefaultElems/', {
        params: { Boolean: ajaxConfig.clickDefaultElems }
      });
      await zapApi.get('/JSON/ajaxSpider/action/setOptionClickElemsOnce/', {
        params: { Boolean: ajaxConfig.clickElemsOnce }
      });
      await zapApi.get('/JSON/ajaxSpider/action/setOptionRandomInputs/', {
        params: { Boolean: ajaxConfig.randomInputs }
      });

      console.log('✅ AJAX Spider configured for maximum discovery');
      if (contextCreated) {
        console.log(`🔒 AJAX Spider will use context: ${contextName} (domain-scoped)`);
      }
      await updateProgress('ajax_spider', 32, { message: 'Starting AJAX spider...' });

      const ajaxSpiderResponse = await zapApi.get('/JSON/ajaxSpider/action/scan/', {
        params: {
          url: targetUrl,
          inScope: contextCreated ? 'true' : '',     // Only scan in-scope URLs
          contextName: contextCreated ? contextName : '',
          subtreeOnly: contextCreated ? 'true' : ''
        }
      });

      console.log(`🌐 AJAX Spider started${contextCreated ? ' (domain-scoped)' : ''}`);

      // Wait for AJAX spider to complete with timeout
      let ajaxSpiderProgress = 'running';
      let ajaxSpiderIterations = 0;
      const maxAjaxSpiderIterations = Math.ceil(spiderConfig.maxDuration * 60 / 5);

      while (ajaxSpiderProgress === 'running' && ajaxSpiderIterations < maxAjaxSpiderIterations) {
        await sleep(5000);
        ajaxSpiderIterations++;

        try {
          const ajaxStatusResponse = await zapApi.get('/JSON/ajaxSpider/view/status/');
          ajaxSpiderProgress = ajaxStatusResponse.data.status;

          // Get current URL count during AJAX spider
          let currentUrlCount = 0;
          try {
            const ajaxUrlsResponse = await zapApi.get('/JSON/ajaxSpider/view/results/', {
              params: { start: 0, count: 10000 }
            });
            currentUrlCount = ajaxUrlsResponse.data.results?.length || 0;
          } catch (err) {
            // Fallback to numberOfResults API
            try {
              const countResponse = await zapApi.get('/JSON/ajaxSpider/view/numberOfResults/');
              currentUrlCount = countResponse.data.numberOfResults || 0;
            } catch (countErr) {
              console.warn('⚠️ Could not get AJAX spider URL count');
            }
          }

          console.log(`🌐 AJAX Spider: ${ajaxSpiderProgress} | URLs: ${currentUrlCount}`);

          // Update progress with URL count
          const ajaxProgress = Math.min(32 + Math.floor((ajaxSpiderIterations / maxAjaxSpiderIterations) * 3), 34);
          await updateProgress('ajax_spider', ajaxProgress, {
            message: `AJAX Spider: ${currentUrlCount} URLs found`,
            urlsFound: currentUrlCount
          });

          if (ajaxSpiderProgress === 'stopped') {
            break;
          }
        } catch (ajaxError) {
          console.warn('⚠️ AJAX spider status check failed:', ajaxError.message);
          break;
        }
      }

      // Get AJAX spider results
      try {
        const ajaxResultsResponse = await zapApi.get('/JSON/ajaxSpider/view/results/', {
          params: { start: 0, count: 1000 }
        });
        const ajaxUrls = ajaxResultsResponse.data.results?.length || 0;
        console.log(`🌐 AJAX Spider complete: ${ajaxUrls} additional URLs found`);
      } catch (ajaxResultsError) {
        console.warn('⚠️ Could not fetch AJAX spider results:', ajaxResultsError.message);
      }
    } catch (ajaxSpiderError) {
      console.warn('⚠️ AJAX Spider failed:', ajaxSpiderError.message);
      // Continue even if AJAX spider fails
    }

    // Phase 3: Get total URLs discovered so far
    await updateProgress('discovery', 35);
    let urlsFound = 0;
    try {
      const urlsResponse = await zapApi.get('/JSON/core/view/urls/', {
        params: { baseurl: targetUrl }
      });
      urlsFound = urlsResponse.data.urls?.length || 0;
      console.log(`📊 Total URLs in sitemap: ${urlsFound}`);
      await updateProgress('discovery', 40, { urlsFound });
    } catch (urlError) {
      console.warn('⚠️ Could not fetch URL count:', urlError.message);
      urlsFound = spiderUrls; // Fallback to spider count
    }

    // Phase 4: Passive Scan (wait for passive scanning to complete)
    await updateProgress('passive_scan', 45, {
      message: 'Analyzing discovered pages for vulnerabilities...'
    });
    console.log('🔍 Waiting for passive scan to complete...');

    // Enable passive scanning
    await zapApi.get('/JSON/pscan/action/enableAllScanners/');

    // Wait for passive scan with timeout
    let passiveScanTimeout = 0;
    const maxPassiveScanWait = 60; // seconds

    while (passiveScanTimeout < maxPassiveScanWait) {
      await sleep(2000);

      try {
        const recordsResponse = await zapApi.get('/JSON/pscan/view/recordsToScan/');
        const recordsToScan = parseInt(recordsResponse.data.recordsToScan || 0);

        console.log(`🔍 Passive scan: ${recordsToScan} records remaining`);

        if (recordsToScan === 0) {
          console.log('✅ Passive scan complete');
          break;
        }

        passiveScanTimeout += 2;
        const progress = 45 + Math.min(15, Math.floor((passiveScanTimeout / maxPassiveScanWait) * 15));
        await updateProgress('passive_scan', progress, {
          message: `Processing ${recordsToScan} records...`
        });
      } catch (pscanError) {
        console.warn('⚠️ Passive scan check error:', pscanError.message);
        break;
      }
    }

    // Phase 5: Configure Active Scanner (set timeouts and limits)
    console.log('⚙️ Configuring active scanner...');
    const maxActiveScanDuration = 720; // 720 minutes = 12 hours for comprehensive enterprise scan

    try {
      await zapApi.get('/JSON/ascan/action/setOptionMaxScanDurationInMins/', {
        params: { Integer: maxActiveScanDuration }
      });
      await zapApi.get('/JSON/ascan/action/setOptionMaxRuleDurationInMins/', {
        params: { Integer: Math.floor(maxActiveScanDuration / 3) }
      });
      await zapApi.get('/JSON/ascan/action/setOptionThreadPerHost/', {
        params: { Integer: 10 }
      });
      await zapApi.get('/JSON/ascan/action/setOptionDelayInMs/', {
        params: { Integer: 0 }
      });
      console.log(`✅ Active scanner configured (max ${maxActiveScanDuration} min)`);
    } catch (configError) {
      console.warn('⚠️ Could not configure active scanner:', configError.message);
    }

    // Phase 6: Active Scan
    await updateProgress('active_scan', 60, {
      message: 'Starting active vulnerability testing...'
    });
    console.log('⚡ Starting active scan...');
    if (contextCreated) {
      console.log(`🔒 Active scan will use context: ${contextName} (domain-scoped)`);
    }

    const activeScanResponse = await zapApi.get('/JSON/ascan/action/scan/', {
      params: {
        url: targetUrl,
        recurse: true,
        inScopeOnly: contextCreated,  // Only scan in-scope URLs when context is set
        scanPolicyName: '',
        method: '',
        postData: '',
        contextName: contextCreated ? contextName : ''
      }
    });

    const activeScanId = activeScanResponse.data.scan;
    console.log(`⚡ Active scan ID: ${activeScanId}`);

    // Wait for active scan to complete with stuck detection
    let scanProgress = 0;
    let lastProgress = 0;
    let stuckCount = 0;
    const maxStuckIterations = 60; // 300 seconds = 5 minutes (for comprehensive 12-hour scans)
    const activeScanStartTime = Date.now();
    const maxActiveScanTime = (maxActiveScanDuration + 30) * 60 * 1000; // Add 30 min buffer for cleanup

    while (scanProgress < 100) {
      await sleep(5000);

      // Check timeout
      if (Date.now() - activeScanStartTime > maxActiveScanTime) {
        console.warn('⚠️ Active scan timeout exceeded, stopping scan...');
        try {
          await zapApi.get('/JSON/ascan/action/stop/', {
            params: { scanId: activeScanId }
          });
        } catch (stopError) {
          console.error('Failed to stop scan:', stopError.message);
        }
        break;
      }

      const statusResponse = await zapApi.get('/JSON/ascan/view/status/', {
        params: { scanId: activeScanId }
      });

      scanProgress = parseInt(statusResponse.data.status);
      const uiProgress = 60 + Math.floor(scanProgress * 0.3); // 60% to 90%

      // Stuck detection
      if (scanProgress === lastProgress) {
        stuckCount++;
        if (stuckCount >= maxStuckIterations) {
          console.warn(`⚠️ Scan stuck at ${scanProgress}% for ${stuckCount * 5} seconds, stopping...`);
          try {
            await zapApi.get('/JSON/ascan/action/stop/', {
              params: { scanId: activeScanId }
            });
          } catch (stopError) {
            console.error('Failed to stop scan:', stopError.message);
          }
          break;
        }
      } else {
        stuckCount = 0; // Reset if progress changed
      }
      lastProgress = scanProgress;

      // Get current alert count
      let currentAlerts = 0;
      try {
        const alertsCountResponse = await zapApi.get('/JSON/core/view/numberOfAlerts/');
        currentAlerts = parseInt(alertsCountResponse.data.numberOfAlerts || 0);
      } catch (alertError) {
        console.warn('⚠️ Could not fetch alert count');
      }

      await updateProgress('active_scan', uiProgress, {
        message: `Testing for vulnerabilities: ${scanProgress}%`,
        alertsFound: currentAlerts
      });

      console.log(`⚡ Active scan progress: ${scanProgress}% | Alerts: ${currentAlerts} | Stuck: ${stuckCount}`);
    }

    console.log('✅ Active scan complete');

    // Phase 6: Retrieve and process alerts
    await updateProgress('processing', 92, { message: 'Collecting vulnerability data...' });
    console.log('📊 Retrieving alerts...');

    const alertsResponse = await zapApi.get('/JSON/core/view/alerts/', {
      params: {
        baseurl: targetUrl,
        start: 0,
        count: 10000
      }
    });

    const rawAlerts = alertsResponse.data.alerts || [];
    console.log(`📊 Retrieved ${rawAlerts.length} raw alerts`);

    // Generate HTML report
    const htmlReportResponse = await zapApi.get('/OTHER/core/other/htmlreport/', {
      responseType: 'arraybuffer'
    });

    // Process alerts into dual versions
    const { summaryAlerts, detailedAlerts } = createDualVersionAlerts(rawAlerts);

    console.log(`📊 Grouped into ${summaryAlerts.length} unique alert types`);

    // Calculate risk counts
    const riskCounts = summaryAlerts.reduce((acc, alert) => {
      acc[alert.risk] = (acc[alert.risk] || 0) + 1;
      return acc;
    }, { High: 0, Medium: 0, Low: 0, Informational: 0 });

    // Store reports in GridFS
    await updateProgress('saving', 95, { message: 'Saving reports...' });

    const htmlBuffer = Buffer.from(htmlReportResponse.data);
    const htmlFileId = await gridfsService.uploadFile(
      htmlBuffer,
      `zap_report_${scanId}.html`,
      { scanId, contentType: 'text/html' }
    );

    const detailedAlertsBuffer = Buffer.from(JSON.stringify(detailedAlerts, null, 2), 'utf-8');
    const detailedAlertsFileId = await gridfsService.uploadFile(
      detailedAlertsBuffer,
      `zap_detailed_alerts_${scanId}.json`,
      { scanId, contentType: 'application/json' }
    );

    console.log(`✅ Reports stored in GridFS`);

    // Update final scan result
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          status: 'completed',
          'zapResult.status': 'completed',
          'zapResult.phase': 'completed',
          'zapResult.progress': 100,
          'zapResult.urlsFound': urlsFound,
          'zapResult.alerts': summaryAlerts,
          'zapResult.riskCounts': riskCounts,
          'zapResult.totalAlerts': summaryAlerts.length,
          'zapResult.totalOccurrences': summaryAlerts.reduce((sum, a) => sum + a.totalOccurrences, 0),
          'zapResult.reportFiles': [
            {
              fileId: htmlFileId.toString(),
              filename: `zap_report_${scanId}.html`,
              contentType: 'text/html',
              format: 'html',
              size: htmlBuffer.length
            },
            {
              fileId: detailedAlertsFileId.toString(),
              filename: `zap_detailed_alerts_${scanId}.json`,
              contentType: 'application/json',
              format: 'json',
              size: detailedAlertsBuffer.length,
              description: 'Full alert details with all affected URLs'
            }
          ],
          'zapResult.completedAt': new Date(),
          updatedAt: new Date()
        }
      }
    );

    console.log(`✅ Scan complete: ${scanId}`);
    console.log(`   URLs found: ${urlsFound}`);
    console.log(`   Alert types: ${summaryAlerts.length}`);
    console.log(`   Total occurrences: ${summaryAlerts.reduce((sum, a) => sum + a.totalOccurrences, 0)}`);
    console.log(`   Risk breakdown: High=${riskCounts.High}, Medium=${riskCounts.Medium}, Low=${riskCounts.Low}, Info=${riskCounts.Informational}`);

    // Cleanup: Remove the ZAP context to avoid accumulation
    if (contextCreated) {
      try {
        await zapApi.get('/JSON/context/action/removeContext/', {
          params: { contextName }
        });
        console.log(`🧹 Cleaned up ZAP context: ${contextName}`);
      } catch (cleanupError) {
        console.warn('⚠️ Could not cleanup ZAP context:', cleanupError.message);
      }
    }

    return {
      success: true,
      scanId: scanId,
      urlsFound: urlsFound,
      alerts: summaryAlerts.length,
      riskCounts: riskCounts
    };

  } catch (error) {
    console.error('❌ ZAP scan failed:', error.message);

    // Clean up failed scan immediately (no partial data)
    if (scanResult) {
      try {
        await cleanupService.cleanupFailedScan(scanId, scanResult.userId);
        console.log(`🗑️ Cleaned up failed scan: ${scanId}`);
      } catch (cleanupError) {
        console.error('Failed to cleanup scan:', cleanupError.message);
      }
    }

    throw error;
  }
}

// ============================================================================
// GET SCAN STATUS
// ============================================================================

/**
 * Get the status of a ZAP scan
 */
async function getZapScanStatus(scanId, userId) {
  try {
    const scanResult = await ScanResult.findOne({
      analysisId: scanId,
      userId: userId
    });

    if (!scanResult) {
      throw new Error('Scan not found or access denied');
    }

    return {
      scanId: scanResult.analysisId,
      target: scanResult.target,
      status: scanResult.status,
      zapResult: scanResult.zapResult,
      createdAt: scanResult.createdAt,
      updatedAt: scanResult.updatedAt
    };
  } catch (error) {
    console.error('❌ Failed to get scan status:', error.message);
    throw error;
  }
}

// ============================================================================
// ASYNC ZAP SCAN FOR COMBINED SCANS
// ============================================================================

/**
 * Start ZAP scan asynchronously and update database when complete
 * This function returns immediately with a "pending" status
 * The actual scan runs in the background and updates the database when done
 *
 * Used by combined scan flow to allow ZAP to run without blocking other scans
 *
 * ALWAYS runs comprehensive 12-hour scan for industry-standard security testing
 */
async function startAsyncZapScan(targetUrl, scanId, userId) {
  console.log(`🚀 Starting ASYNC ZAP scan for: ${targetUrl}`);
  console.log(`   Scan ID: ${scanId}`);
  console.log(`   User: ${userId}`);
  console.log(`   Mode: Full Comprehensive (up to 12 hours)`);

  try {
    // CHECK DATABASE FIRST - this is the source of truth for production
    // This prevents duplicate scans even if backend restarts
    const existingScan = await ScanResult.findOne({ analysisId: scanId, userId });

    if (existingScan?.zapResult) {
      const status = existingScan.zapResult.status;

      // If scan is already running, return current status
      if (status === 'running' || status === 'pending') {
        console.log(`[ZAP] ⏭️ Scan already running in DB for ${scanId}`);
        return {
          status: existingScan.zapResult.status,
          phase: existingScan.zapResult.phase || 'running',
          progress: existingScan.zapResult.progress || 0,
          message: 'ZAP scan already in progress',
          startedAt: existingScan.zapResult.startedAt
        };
      }

      // If scan is completed, return completed result
      if (status === 'completed' || status === 'completed_partial' || status === 'failed') {
        console.log(`[ZAP] ⏭️ Scan already completed in DB for ${scanId}`);
        return existingScan.zapResult;
      }
    }

    // Initialize ZAP result in database with "pending" status
    // Use full object to avoid MongoDB nested field creation errors when zapResult is null
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          zapResult: {
            status: 'pending',
            phase: 'queued',
            progress: 0,
            startedAt: new Date(),
            message: 'ZAP comprehensive scan queued (up to 12 hours)...'
          },
          updatedAt: new Date()
        }
      },
      { upsert: false }
    );

    console.log(`✅ ZAP scan marked as pending in database`);

    // Start the actual scan in the background (fire and forget)
    // This runs independently and updates the database when complete
    runAsyncZapScanBackground(targetUrl, scanId, userId)
      .then(() => {
        console.log(`✅ Background ZAP scan completed: ${scanId}`);
      })
      .catch((error) => {
        console.error(`❌ Background ZAP scan failed: ${scanId}`, error.message);
      });

    // Return immediately with pending status
    return {
      status: 'pending',
      phase: 'queued',
      progress: 0,
      message: 'ZAP comprehensive security scan started (up to 12 hours). Results will appear when ready.',
      startedAt: new Date()
    };

  } catch (error) {
    console.error('❌ Failed to start async ZAP scan:', error.message);
    return {
      status: 'failed',
      error: error.message,
      message: 'Failed to start ZAP scan'
    };
  }
}

/**
 * Background ZAP scan process - updates database as it progresses
 * This is the actual scan logic that runs independently
 *
 * COMPREHENSIVE SCAN MODE - up to 12 hours
 */
async function runAsyncZapScanBackground(targetUrl, scanId, userId) {
  console.log(`🔍 [BACKGROUND] Starting ZAP scan: ${scanId}`);

  try {
    // Update helper function with retry logic for long-running scans
    const updateProgress = async (phase, progress, additionalData = {}, maxRetries = 3) => {
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          // First, get the current zapResult to merge with new data
          const currentScan = await ScanResult.findOne({ analysisId: scanId });
          const currentZapResult = currentScan?.zapResult || {};

          // Merge current data with updates
          const updatedZapResult = {
            ...currentZapResult,
            status: 'running',
            phase: phase,
            progress: progress,
            lastUpdate: new Date(),
            ...additionalData
          };

          await ScanResult.updateOne(
            { analysisId: scanId },
            {
              $set: {
                zapResult: updatedZapResult,
                updatedAt: new Date()
              }
            }
          );
          console.log(`📊 [BACKGROUND] ZAP Progress: ${phase} - ${progress}%`);
          return; // Success
        } catch (updateError) {
          console.error(`Failed to update ZAP progress (attempt ${attempt}/${maxRetries}):`, updateError.message);
          if (attempt === maxRetries) {
            console.error('❌ All retry attempts failed. Progress update lost.');
          } else {
            await sleep(5000); // Wait 5s before retry
          }
        }
      }
    };

    // Phase 1: Configure file exclusions
    await updateProgress('configuring', 3, { message: 'Configuring file exclusions...' });
    console.log('⚙️ [BACKGROUND] Configuring file type exclusions...');

    const exclusionPatterns = [
      // Videos (prevent infinite loops and timeouts)
      '.*\\.webm.*', '.*\\.mp4.*', '.*\\.mov.*', '.*\\.avi.*',
      '.*\\.mkv.*', '.*\\.flv.*', '.*\\.wmv.*', '.*\\.m4v.*',
      // Archives (prevent database bloat)
      '.*\\.zip$', '.*\\.tar$', '.*\\.gz$', '.*\\.rar$',
      '.*\\.7z$', '.*\\.iso$', '.*\\.dmg$', '.*\\.bz2$',
      // Executables (not scannable)
      '.*\\.exe$', '.*\\.msi$', '.*\\.app$',
      '.*\\.deb$', '.*\\.rpm$', '.*\\.pkg$',
      // Large media files
      '.*\\.pdf$', '.*\\.doc$', '.*\\.docx$', '.*\\.ppt$', '.*\\.pptx$',
      // Images (large files)
      '.*\\.png\\?.*size=large.*', '.*\\.jpg\\?.*size=large.*',
      // Fonts
      '.*\\.woff$', '.*\\.woff2$', '.*\\.ttf$', '.*\\.eot$'
    ];

    let excludedCount = 0;
    for (const pattern of exclusionPatterns) {
      try {
        await zapApi.get('/JSON/core/action/excludeFromProxy/', {
          params: { regex: pattern }
        });
        excludedCount++;
      } catch (excludeError) {
        console.warn(`⚠️ Failed to exclude pattern ${pattern}:`, excludeError.message);
      }
    }
    console.log(`✅ [BACKGROUND] Configured ${excludedCount}/${exclusionPatterns.length} exclusion patterns`);

    // Phase 1.5: Create ZAP context for domain scoping
    // This prevents ZAP from crawling external domains (CDNs, analytics, social media, etc.)
    await updateProgress('configuring', 4, { message: 'Setting up domain scope...' });
    console.log('🔒 [BACKGROUND] Configuring domain scope to filter external URLs...');

    const contextName = `scan_${scanId}`;
    let contextCreated = false;

    try {
      // Extract domain from target URL
      const targetUrlObj = new URL(targetUrl);
      const targetDomain = targetUrlObj.hostname;
      const targetDomainEscaped = targetDomain.replace(/\./g, '\\.');

      // Create a new context for this scan
      await zapApi.get('/JSON/context/action/newContext/', {
        params: { contextName }
      });
      console.log(`✅ [BACKGROUND] Created ZAP context: ${contextName}`);

      // Include only the target domain and its subdomains
      const includePatterns = [
        `https?://${targetDomainEscaped}.*`,           // Main domain
        `https?://.*\\.${targetDomainEscaped}.*`       // Subdomains
      ];

      for (const pattern of includePatterns) {
        try {
          await zapApi.get('/JSON/context/action/includeInContext/', {
            params: { contextName, regex: pattern }
          });
          console.log(`   ✓ [BACKGROUND] Include: ${pattern}`);
        } catch (err) {
          console.warn(`   ⚠️ [BACKGROUND] Failed to add include pattern: ${err.message}`);
        }
      }

      // Exclude common external domains that ZAP tends to crawl
      const excludeDomains = [
        // Analytics & Tracking
        '.*google-analytics\\.com.*',
        '.*googletagmanager\\.com.*',
        '.*doubleclick\\.net.*',
        '.*facebook\\.com.*',
        '.*facebook\\.net.*',
        '.*twitter\\.com.*',
        '.*linkedin\\.com.*',
        '.*hotjar\\.com.*',
        '.*mixpanel\\.com.*',
        '.*segment\\.io.*',
        '.*amplitude\\.com.*',
        // CDNs
        '.*cdn\\.jsdelivr\\.net.*',
        '.*cdnjs\\.cloudflare\\.com.*',
        '.*unpkg\\.com.*',
        '.*cloudflare\\.com.*',
        '.*fastly\\.net.*',
        '.*akamaihd\\.net.*',
        '.*akamai\\.net.*',
        '.*cloudfront\\.net.*',
        // Fonts & Icons
        '.*fonts\\.googleapis\\.com.*',
        '.*fonts\\.gstatic\\.com.*',
        '.*use\\.fontawesome\\.com.*',
        '.*use\\.typekit\\.net.*',
        // Google Services
        '.*google\\.com.*',
        '.*gstatic\\.com.*',
        '.*googleapis\\.com.*',
        '.*googlesyndication\\.com.*',
        '.*googleadservices\\.com.*',
        // Social Media Embeds
        '.*instagram\\.com.*',
        '.*youtube\\.com.*',
        '.*youtu\\.be.*',
        '.*vimeo\\.com.*',
        '.*tiktok\\.com.*',
        // Other Common Third Parties
        '.*jquery\\.com.*',
        '.*bootstrapcdn\\.com.*',
        '.*gravatar\\.com.*',
        '.*wp\\.com.*',
        '.*wordpress\\.com.*',
        '.*stripe\\.com.*',
        '.*paypal\\.com.*',
        '.*recaptcha\\.net.*',
        '.*hcaptcha\\.com.*',
        // Auth Endpoints to prevent logout issues
        '.*logout.*',
        '.*signout.*',
        '.*sign-out.*',
        '.*/auth/logout.*'
      ];

      for (const pattern of excludeDomains) {
        try {
          await zapApi.get('/JSON/context/action/excludeFromContext/', {
            params: { contextName, regex: pattern }
          });
        } catch (err) {
          // Silently continue - some patterns may fail
        }
      }
      console.log(`✅ [BACKGROUND] Excluded ${excludeDomains.length} external domain patterns`);

      // Set context in scope
      await zapApi.get('/JSON/context/action/setContextInScope/', {
        params: { contextName, booleanInScope: 'true' }
      });

      contextCreated = true;
      console.log(`✅ [BACKGROUND] Domain scope configured: Only crawling ${targetDomain}`);

    } catch (contextError) {
      console.warn('⚠️ [BACKGROUND] Failed to create ZAP context:', contextError.message);
      console.warn('⚠️ [BACKGROUND] Scan will proceed without domain scoping');
    }

    // Phase 2: Access the URL
    await updateProgress('accessing', 5, { message: 'Accessing target URL...' });
    await zapApi.get('/JSON/core/action/accessUrl/', {
      params: { url: targetUrl }
    });
    await sleep(2000);

    // Phase 3: Spider (Traditional crawling)
    await updateProgress('spidering', 10, { message: 'Crawling website...' });
    console.log('🕷️ [BACKGROUND] Starting traditional spider...');
    if (contextCreated) {
      console.log(`🔒 [BACKGROUND] Spider will use context: ${contextName} (domain-scoped)`);
    }

    // ENTERPRISE SPIDER CONFIG - comprehensive scanning for paid enterprise clients
    const spiderConfig = {
      maxDepth: 30,           // Deep crawling for maximum coverage of large enterprise sites
      maxDuration: 600,       // 600 minutes = 10 hours maximum spider time
      maxChildren: 20000      // Support up to 20,000 URLs for enterprise comprehensive reports
    };

    const spiderResponse = await zapApi.get('/JSON/spider/action/scan/', {
      params: {
        url: targetUrl,
        maxChildren: spiderConfig.maxChildren,
        recurse: true,
        contextName: contextCreated ? contextName : '',  // Use context if created
        subtreeOnly: contextCreated  // Only scan subtree if context is set
      }
    });

    const spiderScanId = spiderResponse.data.scan;
    console.log(`🕷️ [BACKGROUND] Spider scan ID: ${spiderScanId}`);

    // Wait for spider to complete with timeout protection
    let spiderProgress = 0;
    let spiderIterations = 0;
    const maxSpiderIterations = Math.ceil(spiderConfig.maxDuration * 60 / 3); // Based on maxDuration in minutes

    while (spiderProgress < 100 && spiderIterations < maxSpiderIterations) {
      await sleep(3000);
      spiderIterations++;

      const statusResponse = await zapApi.get('/JSON/spider/view/status/', {
        params: { scanId: spiderScanId }
      });

      spiderProgress = parseInt(statusResponse.data.status);

      // Get current URL count during spider
      let currentUrlCount = 0;
      try {
        const spiderUrlsResponse = await zapApi.get('/JSON/spider/view/results/', {
          params: { scanId: spiderScanId }
        });
        currentUrlCount = spiderUrlsResponse.data.results?.length || 0;
      } catch (err) {
        console.warn('⚠️ Could not get spider URL count');
      }

      const uiProgress = 10 + Math.floor(spiderProgress * 0.2); // 10% to 30%
      await updateProgress('spidering', uiProgress, {
        message: `Crawling pages: ${currentUrlCount} URLs found (${spiderProgress}%)`,
        urlsFound: currentUrlCount
      });
    }

    if (spiderProgress < 100) {
      console.warn(`⚠️ [BACKGROUND] Spider timeout after ${spiderIterations * 3}s`);
    }

    // Get URLs found by spider
    const spiderResults = await zapApi.get('/JSON/spider/view/results/', {
      params: { scanId: spiderScanId }
    });
    const spiderUrls = spiderResults.data.results?.length || 0;
    console.log(`🕷️ [BACKGROUND] Spider complete: ${spiderUrls} URLs found`);

    // Phase 3.5: AJAX Spider (for JavaScript-heavy sites)
    await updateProgress('ajax_spider', 32, { message: 'Crawling with AJAX spider...' });
    console.log('🌐 [BACKGROUND] Starting AJAX spider for JavaScript content...');
    if (contextCreated) {
      console.log(`🔒 [BACKGROUND] AJAX Spider will use context: ${contextName} (domain-scoped)`);
    }

    try {
      const ajaxSpiderResponse = await zapApi.get('/JSON/ajaxSpider/action/scan/', {
        params: {
          url: targetUrl,
          inScope: contextCreated ? 'true' : '',     // Only scan in-scope URLs
          contextName: contextCreated ? contextName : '',
          subtreeOnly: contextCreated ? 'true' : ''
        }
      });

      console.log(`🌐 [BACKGROUND] AJAX Spider started${contextCreated ? ' (domain-scoped)' : ''}`);

      // Wait for AJAX spider to complete with timeout
      let ajaxSpiderProgress = 'running';
      let ajaxSpiderIterations = 0;
      const maxAjaxSpiderIterations = Math.ceil(spiderConfig.maxDuration * 60 / 5); // Based on maxDuration

      while (ajaxSpiderProgress === 'running' && ajaxSpiderIterations < maxAjaxSpiderIterations) {
        await sleep(5000);
        ajaxSpiderIterations++;

        try {
          const ajaxStatusResponse = await zapApi.get('/JSON/ajaxSpider/view/status/');
          ajaxSpiderProgress = ajaxStatusResponse.data.status;

          // Get current URL count during AJAX spider
          let currentUrlCount = 0;
          try {
            const ajaxUrlsResponse = await zapApi.get('/JSON/ajaxSpider/view/results/', {
              params: { start: 0, count: 10000 }
            });
            currentUrlCount = ajaxUrlsResponse.data.results?.length || 0;
          } catch (err) {
            // Fallback to numberOfResults API
            try {
              const countResponse = await zapApi.get('/JSON/ajaxSpider/view/numberOfResults/');
              currentUrlCount = countResponse.data.numberOfResults || 0;
            } catch (countErr) {
              // Silently continue
            }
          }

          console.log(`🌐 [BACKGROUND] AJAX Spider: ${ajaxSpiderProgress} | URLs: ${currentUrlCount}`);

          // Update progress with URL count
          const ajaxProgress = Math.min(32 + Math.floor((ajaxSpiderIterations / maxAjaxSpiderIterations) * 3), 34);
          await updateProgress('ajax_spider', ajaxProgress, {
            message: `AJAX Spider: ${currentUrlCount} URLs found`,
            urlsFound: spiderUrls + currentUrlCount  // Combined count
          });

          if (ajaxSpiderProgress === 'stopped') {
            break;
          }
        } catch (ajaxError) {
          console.warn('⚠️ [BACKGROUND] AJAX spider status check failed:', ajaxError.message);
          break;
        }
      }

      // Get AJAX spider results
      try {
        const ajaxResultsResponse = await zapApi.get('/JSON/ajaxSpider/view/results/', {
          params: { start: 0, count: 10000 }
        });
        const ajaxUrls = ajaxResultsResponse.data.results?.length || 0;
        console.log(`🌐 [BACKGROUND] AJAX Spider complete: ${ajaxUrls} additional URLs found`);
      } catch (ajaxResultsError) {
        console.warn('⚠️ Could not fetch AJAX spider results:', ajaxResultsError.message);
      }
    } catch (ajaxSpiderError) {
      console.warn('⚠️ [BACKGROUND] AJAX Spider failed:', ajaxSpiderError.message);
      // Continue even if AJAX spider fails
    }

    // Phase 4: Get total URLs discovered
    await updateProgress('discovery', 35, { message: 'Analyzing discovered pages...' });
    let urlsFound = 0;
    try {
      const urlsResponse = await zapApi.get('/JSON/core/view/urls/', {
        params: { baseurl: targetUrl }
      });
      urlsFound = urlsResponse.data.urls?.length || 0;
      console.log(`📊 [BACKGROUND] Total URLs in sitemap: ${urlsFound}`);
      await updateProgress('discovery', 40, { urlsFound, message: `Found ${urlsFound} URLs` });
    } catch (urlError) {
      console.warn('⚠️ Could not fetch URL count:', urlError.message);
      urlsFound = spiderUrls;
    }

    // Phase 5: Passive Scan
    await updateProgress('passive_scan', 45, {
      message: 'Analyzing for vulnerabilities...'
    });
    console.log('🔍 [BACKGROUND] Waiting for passive scan to complete...');

    // Enable passive scanning
    await zapApi.get('/JSON/pscan/action/enableAllScanners/');

    // Wait for passive scan with timeout
    let passiveScanTimeout = 0;
    const maxPassiveScanWait = 120; // 2 minutes for comprehensive passive scan

    while (passiveScanTimeout < maxPassiveScanWait) {
      await sleep(2000);

      try {
        const recordsResponse = await zapApi.get('/JSON/pscan/view/recordsToScan/');
        const recordsToScan = parseInt(recordsResponse.data.recordsToScan || 0);

        console.log(`🔍 [BACKGROUND] Passive scan: ${recordsToScan} records remaining`);

        if (recordsToScan === 0) {
          console.log('✅ [BACKGROUND] Passive scan complete');
          break;
        }

        passiveScanTimeout += 2;
        const progress = 45 + Math.min(15, Math.floor((passiveScanTimeout / maxPassiveScanWait) * 15));
        await updateProgress('passive_scan', progress, {
          message: `Processing ${recordsToScan} records...`
        });
      } catch (pscanError) {
        console.warn('⚠️ Passive scan check error:', pscanError.message);
        break;
      }
    }

    // Phase 6: Configure Active Scanner
    console.log('⚙️ [BACKGROUND] Configuring active scanner...');
    const maxActiveScanDuration = 720; // 12 hours maximum - industry standard comprehensive scan

    try {
      await zapApi.get('/JSON/ascan/action/setOptionMaxScanDurationInMins/', {
        params: { Integer: maxActiveScanDuration }
      });
      await zapApi.get('/JSON/ascan/action/setOptionMaxRuleDurationInMins/', {
        params: { Integer: Math.floor(maxActiveScanDuration / 3) }
      });
      await zapApi.get('/JSON/ascan/action/setOptionThreadPerHost/', {
        params: { Integer: 10 }
      });
      await zapApi.get('/JSON/ascan/action/setOptionDelayInMs/', {
        params: { Integer: 0 }
      });
      console.log(`✅ [BACKGROUND] Active scanner configured (max ${maxActiveScanDuration} min)`);
    } catch (configError) {
      console.warn('⚠️ Could not configure active scanner:', configError.message);
    }

    // Phase 7: Active Scan
    await updateProgress('active_scan', 60, {
      message: 'Testing for vulnerabilities...'
    });
    console.log('⚡ [BACKGROUND] Starting active scan...');
    if (contextCreated) {
      console.log(`🔒 [BACKGROUND] Active scan will use context: ${contextName} (domain-scoped)`);
    }

    const activeScanResponse = await zapApi.get('/JSON/ascan/action/scan/', {
      params: {
        url: targetUrl,
        recurse: true,
        inScopeOnly: contextCreated,  // Only scan in-scope URLs when context is set
        scanPolicyName: '',
        method: '',
        postData: '',
        contextName: contextCreated ? contextName : ''
      }
    });

    const activeScanId = activeScanResponse.data.scan;
    console.log(`⚡ [BACKGROUND] Active scan ID: ${activeScanId}`);

    // Wait for active scan to complete with stuck detection
    let scanProgress = 0;
    let lastProgress = 0;
    let stuckCount = 0;
    const maxStuckIterations = 60; // 300 seconds = 5 minutes (for comprehensive 12-hour scans)
    const activeScanStartTime = Date.now();
    const maxActiveScanTime = (maxActiveScanDuration + 30) * 60 * 1000; // Add 30 min buffer for cleanup
    let connectionFailureCount = 0;
    const maxConnectionFailures = 5; // After 5 consecutive connection failures, save partial results

    while (scanProgress < 100) {
      await sleep(5000);

      // Check timeout
      if (Date.now() - activeScanStartTime > maxActiveScanTime) {
        console.warn('⚠️ [BACKGROUND] Active scan timeout exceeded, stopping scan...');
        try {
          await zapApi.get('/JSON/ascan/action/stop/', {
            params: { scanId: activeScanId }
          });
        } catch (stopError) {
          console.error('Failed to stop scan:', stopError.message);
        }
        break;
      }

      // Use retry logic for scan status check
      let statusResponse;
      try {
        statusResponse = await zapApiWithRetry(
          () => zapApi.get('/JSON/ascan/view/status/', { params: { scanId: activeScanId } }),
          3, 2000, 'Active scan status check'
        );
        connectionFailureCount = 0; // Reset on success
      } catch (statusError) {
        connectionFailureCount++;
        console.error(`❌ [BACKGROUND] Connection failure ${connectionFailureCount}/${maxConnectionFailures}: ${statusError.message}`);

        if (connectionFailureCount >= maxConnectionFailures) {
          console.warn('⚠️ [BACKGROUND] Too many connection failures, saving partial results...');
          break; // Exit loop to save partial results
        }
        continue; // Try again on next iteration
      }

      scanProgress = parseInt(statusResponse.data.status);
      const uiProgress = 60 + Math.floor(scanProgress * 0.3); // 60% to 90%

      // Stuck detection
      if (scanProgress === lastProgress) {
        stuckCount++;
        if (stuckCount >= maxStuckIterations) {
          console.warn(`⚠️ [BACKGROUND] Scan stuck at ${scanProgress}% for ${stuckCount * 5} seconds, stopping...`);
          try {
            await zapApi.get('/JSON/ascan/action/stop/', {
              params: { scanId: activeScanId }
            });
          } catch (stopError) {
            console.error('Failed to stop scan:', stopError.message);
          }
          break;
        }
      } else {
        stuckCount = 0;
      }
      lastProgress = scanProgress;

      // Get current alert count
      let currentAlerts = 0;
      try {
        const alertsCountResponse = await zapApi.get('/JSON/core/view/numberOfAlerts/');
        currentAlerts = parseInt(alertsCountResponse.data.numberOfAlerts || 0);
      } catch (alertError) {
        console.warn('⚠️ Could not fetch alert count');
      }

      await updateProgress('active_scan', uiProgress, {
        message: `Testing: ${scanProgress}%`,
        alertsFound: currentAlerts
      });

      console.log(`⚡ [BACKGROUND] Active scan: ${scanProgress}% | Alerts: ${currentAlerts} | Stuck: ${stuckCount}`);
    }

    console.log('✅ [BACKGROUND] Active scan complete');

    // Phase 8: Retrieve and process alerts with retry logic
    await updateProgress('processing', 92, { message: 'Collecting vulnerability data...' });
    console.log('📊 [BACKGROUND] Retrieving alerts...');

    let rawAlerts = [];
    let htmlReportResponse = null;
    let partialResults = false;

    try {
      const alertsResponse = await zapApiWithRetry(
        () => zapApi.get('/JSON/core/view/alerts/', {
          params: { baseurl: targetUrl, start: 0, count: 10000 }
        }),
        3, 2000, 'Alerts retrieval'
      );
      rawAlerts = alertsResponse.data.alerts || [];
      console.log(`📊 [BACKGROUND] Retrieved ${rawAlerts.length} raw alerts`);
    } catch (alertsError) {
      console.error('❌ [BACKGROUND] Failed to retrieve alerts:', alertsError.message);
      partialResults = true;
      // Continue with empty alerts - we'll still save what we have
    }

    // Generate HTML report with retry
    try {
      htmlReportResponse = await zapApiWithRetry(
        () => zapApi.get('/OTHER/core/other/htmlreport/', { responseType: 'arraybuffer' }),
        3, 2000, 'HTML report generation'
      );
    } catch (reportError) {
      console.error('❌ [BACKGROUND] Failed to generate HTML report:', reportError.message);
      partialResults = true;
      // Continue without HTML report
    }

    // Process alerts into dual versions
    const { summaryAlerts, detailedAlerts } = createDualVersionAlerts(rawAlerts);

    console.log(`📊 [BACKGROUND] Grouped into ${summaryAlerts.length} unique alert types`);

    // Calculate risk counts
    const riskCounts = summaryAlerts.reduce((acc, alert) => {
      acc[alert.risk] = (acc[alert.risk] || 0) + 1;
      return acc;
    }, { High: 0, Medium: 0, Low: 0, Informational: 0 });

    // Store reports in GridFS
    await updateProgress('saving', 95, { message: 'Saving reports...' });

    let htmlBuffer = null;
    let htmlFileId = null;
    let detailedAlertsFileId = null;
    const reportFiles = [];

    // Store HTML report if available
    if (htmlReportResponse && htmlReportResponse.data) {
      try {
        htmlBuffer = Buffer.from(htmlReportResponse.data);
        htmlFileId = await gridfsService.uploadFile(
          htmlBuffer,
          `zap_report_${scanId}.html`,
          { scanId, contentType: 'text/html' }
        );
        reportFiles.push({
          fileId: htmlFileId.toString(),
          filename: `zap_report_${scanId}.html`,
          contentType: 'text/html',
          format: 'html',
          size: htmlBuffer.length
        });
      } catch (uploadError) {
        console.error('❌ [BACKGROUND] Failed to store HTML report:', uploadError.message);
        partialResults = true;
      }
    }

    // Store detailed alerts
    try {
      const detailedAlertsBuffer = Buffer.from(JSON.stringify(detailedAlerts, null, 2), 'utf-8');
      detailedAlertsFileId = await gridfsService.uploadFile(
        detailedAlertsBuffer,
        `zap_detailed_alerts_${scanId}.json`,
        { scanId, contentType: 'application/json' }
      );
      reportFiles.push({
        fileId: detailedAlertsFileId.toString(),
        filename: `zap_detailed_alerts_${scanId}.json`,
        contentType: 'application/json',
        format: 'json',
        size: detailedAlertsBuffer.length,
        description: 'Full alert details with all affected URLs'
      });
    } catch (uploadError) {
      console.error('❌ [BACKGROUND] Failed to store detailed alerts:', uploadError.message);
      partialResults = true;
    }

    console.log(`✅ [BACKGROUND] Reports stored in GridFS (partial: ${partialResults})`);

    // Determine final status based on partial results
    const finalStatus = partialResults ? 'completed_partial' : 'completed';
    const statusMessage = partialResults
      ? `Scan completed with partial results. Found ${summaryAlerts.length} vulnerability types. Some data may be missing due to connection issues.`
      : `Scan complete! Found ${summaryAlerts.length} vulnerability types.`;

    // Update final scan result with retry logic (critical operation)
    let finalUpdateSuccess = false;
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        await ScanResult.updateOne(
          { analysisId: scanId },
          {
            $set: {
              'zapResult.status': finalStatus,
              'zapResult.phase': 'completed',
              'zapResult.progress': 100,
              'zapResult.urlsFound': urlsFound,
              'zapResult.alerts': summaryAlerts,
              'zapResult.riskCounts': riskCounts,
              'zapResult.totalAlerts': summaryAlerts.length,
              'zapResult.totalOccurrences': summaryAlerts.reduce((sum, a) => sum + a.totalOccurrences, 0),
              'zapResult.reportFiles': reportFiles,
              'zapResult.partialResults': partialResults,
              'zapResult.completedAt': new Date(),
              'zapResult.message': statusMessage,
              updatedAt: new Date()
            }
          }
    );
        finalUpdateSuccess = true;
        break; // Success
      } catch (finalUpdateError) {
        console.error(`❌ Failed to save final results (attempt ${attempt}/5):`, finalUpdateError.message);
        if (attempt < 5) {
          await sleep(10000); // Wait 10s before critical retry
        }
      }
    }

    if (!finalUpdateSuccess) {
      throw new Error('Failed to save scan results after 5 attempts - database connection issue');
    }

    console.log(`✅ [BACKGROUND] ZAP scan complete: ${scanId}`);
    console.log(`   URLs found: ${urlsFound}`);
    console.log(`   Alert types: ${summaryAlerts.length}`);
    console.log(`   Total occurrences: ${summaryAlerts.reduce((sum, a) => sum + a.totalOccurrences, 0)}`);
    console.log(`   Risk breakdown: High=${riskCounts.High}, Medium=${riskCounts.Medium}, Low=${riskCounts.Low}, Info=${riskCounts.Informational}`);

    // Cleanup: Remove the ZAP context to avoid accumulation
    if (contextCreated) {
      try {
        await zapApi.get('/JSON/context/action/removeContext/', {
          params: { contextName }
        });
        console.log(`🧹 [BACKGROUND] Cleaned up ZAP context: ${contextName}`);
      } catch (cleanupError) {
        console.warn('⚠️ [BACKGROUND] Could not cleanup ZAP context:', cleanupError.message);
      }
    }

  } catch (error) {
    console.error('❌ [BACKGROUND] ZAP scan failed:', error.message);

    // Update scan result with error
    try {
      await ScanResult.updateOne(
        { analysisId: scanId },
        {
          $set: {
            'zapResult.status': 'failed',
            'zapResult.phase': 'failed',
            'zapResult.error': error.message,
            'zapResult.failedAt': new Date(),
            'zapResult.message': `Scan failed: ${error.message}`,
            updatedAt: new Date()
          }
        }
      );
    } catch (updateError) {
      console.error('Failed to update scan result with error:', updateError.message);
    }

    throw error;
  }
}

/**
 * Stop a running ZAP scan and restart the Docker container for a fresh instance
 * @param {string} scanId - Scan ID to stop
 * @param {string} userId - User ID requesting the stop
 * @returns {Promise<Object>} Result of stop operation
 */
async function stopZapScan(scanId, userId) {
  try {
    // Verify the scan exists and belongs to the user
    const scan = await ScanResult.findOne({
      analysisId: scanId,
      userId: userId
    });

    if (!scan) {
      throw new Error('Scan not found or access denied');
    }

    // Check if scan is still running
    if (scan.status === 'completed' || scan.status === 'failed') {
      return { message: 'Scan already completed or failed', status: scan.status };
    }

    console.log(`🛑 Stopping ZAP scan: ${scanId}`);

    // Stop all active ZAP scans (spider, ajax spider, active scan)
    try {
      // Stop spider scans
      const spiderScansResponse = await zapApi.get('/JSON/spider/view/scans/');
      const spiderScans = spiderScansResponse.data.scans || [];
      for (const spiderScan of spiderScans) {
        if (spiderScan.state === 'RUNNING') {
          await zapApi.get('/JSON/spider/action/stop/', {
            params: { scanId: spiderScan.id }
          });
          console.log(`🛑 Stopped spider scan: ${spiderScan.id}`);
        }
      }
    } catch (err) {
      console.warn('⚠️ Could not stop spider scans:', err.message);
    }

    try {
      // Stop AJAX spider
      const ajaxStatusResponse = await zapApi.get('/JSON/ajaxSpider/view/status/');
      if (ajaxStatusResponse.data.status === 'running') {
        await zapApi.get('/JSON/ajaxSpider/action/stop/');
        console.log('🛑 Stopped AJAX spider');
      }
    } catch (err) {
      console.warn('⚠️ Could not stop AJAX spider:', err.message);
    }

    try {
      // Stop active scans
      const activeScansResponse = await zapApi.get('/JSON/ascan/view/scans/');
      const activeScans = activeScansResponse.data.scans || [];
      for (const activeScan of activeScans) {
        if (activeScan.state === 'RUNNING') {
          await zapApi.get('/JSON/ascan/action/stop/', {
            params: { scanId: activeScan.id }
          });
          console.log(`🛑 Stopped active scan: ${activeScan.id}`);
        }
      }
    } catch (err) {
      console.warn('⚠️ Could not stop active scans:', err.message);
    }

    // Update database to mark scan as stopped
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          status: 'stopped',
          'zapResult.status': 'stopped',
          'zapResult.phase': 'stopped',
          'zapResult.message': 'Scan stopped by user - restarting ZAP container...',
          stoppedAt: new Date(),
          updatedAt: new Date()
        }
      }
    );

    console.log(`✅ ZAP scan stopped successfully: ${scanId}`);

    // Restart Docker container for fresh ZAP instance
    console.log('🔄 Restarting ZAP Docker container for fresh instance...');
    await restartZapContainer();

    return { message: 'Scan stopped and ZAP container restarted successfully', scanId, containerRestarted: true };

  } catch (error) {
    console.error('❌ Error stopping ZAP scan:', error.message);
    throw error;
  }
}

/**
 * Restart the ZAP Docker container to get a fresh instance
 * @returns {Promise<Object>} Result of restart operation
 */
async function restartZapContainer() {
  const { exec } = require('child_process');
  const util = require('util');
  const execPromise = util.promisify(exec);

  const containerName = 'zap-scanner';

  try {
    console.log(`🔄 Restarting Docker container: ${containerName}`);

    // Restart the ZAP container
    await execPromise(`docker restart ${containerName}`);
    console.log(`✅ Docker container ${containerName} restart initiated`);

    // Wait for container to be healthy (max 90 seconds)
    console.log('⏳ Waiting for ZAP container to be ready...');
    let healthy = false;
    let attempts = 0;
    const maxAttempts = 30; // 30 attempts * 3 seconds = 90 seconds max

    while (!healthy && attempts < maxAttempts) {
      await sleep(3000); // Wait 3 seconds between checks
      attempts++;

      try {
        // Check if ZAP API is responding
        const healthCheck = await zapApi.get('/JSON/core/view/version/', {
          timeout: 5000 // 5 second timeout for health check
        });

        if (healthCheck.data && healthCheck.data.version) {
          healthy = true;
          console.log(`✅ ZAP container is healthy (v${healthCheck.data.version}) after ${attempts * 3} seconds`);
        }
      } catch (healthError) {
        console.log(`⏳ Waiting for ZAP... (attempt ${attempts}/${maxAttempts})`);
      }
    }

    if (!healthy) {
      console.warn('⚠️ ZAP container may not be fully ready yet. It should become available shortly.');
      return { success: true, warning: 'Container restarted but health check timed out', containerName };
    }

    return { success: true, containerName, message: 'Container restarted and healthy' };

  } catch (error) {
    console.error('❌ Failed to restart ZAP container:', error.message);

    // Don't throw - the scan was still stopped, just container restart failed
    return {
      success: false,
      error: error.message,
      containerName,
      message: 'Scan stopped but container restart failed. You may need to restart manually.'
    };
  }
}

/**
 * Restart the WebCheck Docker container to stop pending requests
 * @returns {Promise<Object>} Result of restart operation
 */
async function restartWebCheckContainer() {
  const { exec } = require('child_process');
  const util = require('util');
  const execPromise = util.promisify(exec);

  const containerName = 'ssdt-webcheck';

  try {
    console.log(`🔄 Restarting Docker container: ${containerName}`);

    // Restart the WebCheck container
    await execPromise(`docker restart ${containerName}`);
    console.log(`✅ Docker container ${containerName} restart initiated`);

    // Wait for container to be healthy (max 60 seconds)
    console.log('⏳ Waiting for WebCheck container to be ready...');
    let healthy = false;
    let attempts = 0;
    const maxAttempts = 20; // 20 attempts * 3 seconds = 60 seconds max

    while (!healthy && attempts < maxAttempts) {
      await sleep(3000); // Wait 3 seconds between checks
      attempts++;

      try {
        // Check if WebCheck API is responding
        const healthCheck = await axios.get('http://localhost:3002/health', {
          timeout: 5000 // 5 second timeout for health check
        });

        if (healthCheck.data && healthCheck.data.status === 'healthy') {
          healthy = true;
          console.log(`✅ WebCheck container is healthy after ${attempts * 3} seconds`);
        }
      } catch (healthError) {
        console.log(`⏳ Waiting for WebCheck... (attempt ${attempts}/${maxAttempts})`);
      }
    }

    if (!healthy) {
      console.warn('⚠️ WebCheck container may not be fully ready yet. It should become available shortly.');
      return { success: true, warning: 'Container restarted but health check timed out', containerName };
    }

    return { success: true, containerName, message: 'Container restarted and healthy' };

  } catch (error) {
    console.error('❌ Failed to restart WebCheck container:', error.message);

    return {
      success: false,
      error: error.message,
      containerName,
      message: 'Container restart failed. You may need to restart manually.'
    };
  }
}

/**
 * Stop a combined scan and restart all Docker containers for fresh instances
 * This stops ZAP scans, restarts ZAP container, and restarts WebCheck container
 * @param {string} scanId - Scan ID to stop
 * @param {string} userId - User ID requesting the stop
 * @returns {Promise<Object>} Result of stop operation
 */
async function stopCombinedScan(scanId, userId) {
  try {
    // Verify the scan exists and belongs to the user
    const scan = await ScanResult.findOne({
      analysisId: scanId,
      userId: userId
    });

    if (!scan) {
      throw new Error('Scan not found or access denied');
    }

    // Check if scan is still running
    if (scan.status === 'completed' || scan.status === 'failed') {
      return { message: 'Scan already completed or failed', status: scan.status };
    }

    console.log(`🛑 Stopping combined scan: ${scanId}`);

    // Stop all active ZAP scans (spider, ajax spider, active scan)
    try {
      // Stop spider scans
      const spiderScansResponse = await zapApi.get('/JSON/spider/view/scans/');
      const spiderScans = spiderScansResponse.data.scans || [];
      for (const spiderScan of spiderScans) {
        if (spiderScan.state === 'RUNNING') {
          await zapApi.get('/JSON/spider/action/stop/', {
            params: { scanId: spiderScan.id }
          });
          console.log(`🛑 Stopped spider scan: ${spiderScan.id}`);
        }
      }
    } catch (err) {
      console.warn('⚠️ Could not stop spider scans:', err.message);
    }

    try {
      // Stop AJAX spider
      const ajaxStatusResponse = await zapApi.get('/JSON/ajaxSpider/view/status/');
      if (ajaxStatusResponse.data.status === 'running') {
        await zapApi.get('/JSON/ajaxSpider/action/stop/');
        console.log('🛑 Stopped AJAX spider');
      }
    } catch (err) {
      console.warn('⚠️ Could not stop AJAX spider:', err.message);
    }

    try {
      // Stop active scans
      const activeScansResponse = await zapApi.get('/JSON/ascan/view/scans/');
      const activeScans = activeScansResponse.data.scans || [];
      for (const activeScan of activeScans) {
        if (activeScan.state === 'RUNNING') {
          await zapApi.get('/JSON/ascan/action/stop/', {
            params: { scanId: activeScan.id }
          });
          console.log(`🛑 Stopped active scan: ${activeScan.id}`);
        }
      }
    } catch (err) {
      console.warn('⚠️ Could not stop active scans:', err.message);
    }

    // Update database to mark scan as stopped
    // Use full object replacement to avoid MongoDB nested field errors when zapResult is null
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          status: 'stopped',
          zapResult: {
            status: 'stopped',
            phase: 'stopped',
            message: 'Scan stopped by user - restarting containers...',
            stoppedAt: new Date()
          },
          stoppedAt: new Date(),
          updatedAt: new Date()
        }
      }
    );

    console.log(`✅ Scan stopped in database: ${scanId}`);

    // Restart both Docker containers in parallel for fresh instances
    console.log('🔄 Restarting ZAP and WebCheck Docker containers for fresh instances...');

    const [zapRestartResult, webCheckRestartResult] = await Promise.allSettled([
      restartZapContainer(),
      restartWebCheckContainer()
    ]);

    const zapRestarted = zapRestartResult.status === 'fulfilled' && zapRestartResult.value.success;
    const webCheckRestarted = webCheckRestartResult.status === 'fulfilled' && webCheckRestartResult.value.success;

    console.log(`✅ Container restart results:`);
    console.log(`   ZAP: ${zapRestarted ? 'Success' : 'Failed'}`);
    console.log(`   WebCheck: ${webCheckRestarted ? 'Success' : 'Failed'}`);

    return {
      message: 'Scan stopped and containers restarted successfully',
      scanId,
      containersRestarted: {
        zap: zapRestarted,
        webCheck: webCheckRestarted
      },
      zapRestartResult: zapRestartResult.status === 'fulfilled' ? zapRestartResult.value : { error: zapRestartResult.reason?.message },
      webCheckRestartResult: webCheckRestartResult.status === 'fulfilled' ? webCheckRestartResult.value : { error: webCheckRestartResult.reason?.message }
    };

  } catch (error) {
    console.error('❌ Error stopping combined scan:', error.message);
    throw error;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  checkZapHealth,
  runZapScanWithDB,
  getZapScanStatus,
  runZapScanWithUrlTracking,
  downloadDetailedReport,
  groupAlertsByUrl,
  createDualVersionAlerts,
  startAsyncZapScan, // For combined scan async flow
  runZapScan: runZapScanWithUrlTracking, // Backward compatibility alias
  stopZapScan, // Stop running ZAP scan and restart ZAP container
  stopCombinedScan, // Stop combined scan and restart ALL containers (ZAP + WebCheck)
  restartZapContainer, // Restart ZAP Docker container for fresh instance
  restartWebCheckContainer // Restart WebCheck Docker container for fresh instance
};
