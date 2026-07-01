/**
 * ZAP Authenticated Scanning Service
 * Connects to the zap-auth container on port 8081 and runs authenticated scans.
 * Uses cookie-based authentication via ZAP's Replacer API.
 *
 * DO NOT confuse with zapService.js (public scans on port 8080).
 */

const axios = require('axios');
const http = require('http');
const ScanResult = require('../models/ScanResult');
const gridfsService = require('./gridfsService');
const { finalizeSuccessfulScan } = require('./planService');

// ============================================================================
// ZAP AUTH API CONFIGURATION
// ============================================================================

const ZAP_AUTH_URL = process.env.ZAP_AUTH_API_URL || 'http://127.0.0.1:8081';
const ZAP_AUTH_API_KEY = process.env.ZAP_AUTH_API_KEY; // Optional when ZAP runs with api.disablekey=true

const httpAgent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 10,
  timeout: 120000
});

// Factory: create a per-scan ZAP auth client.
// In AWS mode, each auth scan gets its own Fargate container (port 8080 internal).
// In local mode, the default ZAP_AUTH_URL points at the docker-compose mapped port 8081.
// The Host header is forced to 'localhost:8080' because ZAP's API validation is
// Host-header-sensitive — ZAP always listens on port 8080 internally.
function createZapAuthClient(zapUrl) {
  const headers = {
    'Content-Type': 'application/json',
    'Connection': 'keep-alive',
    'Host': 'localhost:8080',
    ...(ZAP_AUTH_API_KEY ? { 'X-Zap-Api-Key': ZAP_AUTH_API_KEY } : {})
  };

  return axios.create({
    baseURL: zapUrl,
    timeout: 120000,
    httpAgent: httpAgent,
    headers,
    params: ZAP_AUTH_API_KEY ? { apikey: ZAP_AUTH_API_KEY } : {},
    maxRedirects: 5
  });
}

// Module-level client used only by checkZapAuthHealth() (not by scans).
const zapAuthApi = createZapAuthClient(ZAP_AUTH_URL);

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ============================================================================
// RETRY LOGIC
// ============================================================================

async function zapAuthApiWithRetry(apiCall, maxRetries = 3, baseDelay = 1000, operationName = 'ZAP Auth API call') {
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
        console.error(`[ZAP-AUTH] ${operationName} failed after ${attempt} attempt(s): ${error.message}`);
        throw error;
      }

      const delay = baseDelay * Math.pow(2, attempt - 1);
      console.warn(`[ZAP-AUTH] ${operationName} failed (attempt ${attempt}/${maxRetries}): ${error.message}. Retrying in ${delay}ms...`);
      await sleep(delay);
    }
  }

  throw lastError;
}

// ============================================================================
// ALERT PROCESSING (duplicated from zapService.js to avoid modifying it)
// ============================================================================

function groupAlertsByUrl(alerts) {
  const grouped = {};

  alerts.forEach(alert => {
    const key = alert.alert;

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

    // ZAP's /JSON/core/view/alerts/ returns a FLAT list — one entry per
    // occurrence, each addressable to its raw HTTP request/response via
    // `messageId`. Handle both flat and nested (`instances`) shapes. We capture
    // method/param/attack/evidence/messageId here (previously only `url` survived
    // because the flat shape has no `.instances`).
    if (alert.instances && alert.instances.length > 0) {
      alert.instances.forEach(instance => {
        grouped[key].occurrences.push({
          url: instance.uri || alert.url,
          method: instance.method || alert.method,
          param: instance.param || alert.param,
          attack: instance.attack || alert.attack,
          evidence: instance.evidence || alert.evidence,
          messageId: instance.messageId || alert.messageId
        });
        grouped[key].totalCount++;
      });
    } else {
      grouped[key].occurrences.push({
        url: alert.url,
        method: alert.method,
        param: alert.param,
        attack: alert.attack,
        evidence: alert.evidence,
        messageId: alert.messageId
      });
      grouped[key].totalCount++;
    }
  });

  return Object.values(grouped);
}

/**
 * Fetch the raw HTTP request/response for a single ZAP message.
 * Best-effort: returns null on any failure (never throws).
 * @param {import('axios').AxiosInstance} client - ZAP auth API client
 * @param {string|number} messageId
 * @returns {Promise<{request:{header:string,body:string},response:{header:string,body:string}}|null>}
 */
async function fetchZapMessage(client, messageId) {
  if (!client || messageId === undefined || messageId === null || messageId === '') return null;
  try {
    const res = await client.get('/JSON/core/view/message/', { params: { id: messageId } });
    const m = (res && res.data && res.data.message) ? res.data.message : (res ? res.data : null);
    if (!m) return null;
    return {
      request: { header: m.requestHeader || '', body: m.requestBody || '' },
      response: { header: m.responseHeader || '', body: m.responseBody || '' }
    };
  } catch (err) {
    console.warn(`⚠️ Failed to fetch ZAP message ${messageId}: ${err.message}`);
    return null;
  }
}

/**
 * Enrich grouped-alert occurrences with raw HTTP request/response, fetching each
 * unique messageId once (deduped, concurrency-capped). Mutates in place.
 * Best-effort: individual failures are skipped and never throw.
 * @param {Array} grouped - output of groupAlertsByUrl()
 * @param {import('axios').AxiosInstance} client - ZAP auth API client
 */
async function enrichOccurrencesWithMessages(grouped, client) {
  if (!client || !Array.isArray(grouped) || grouped.length === 0) return;

  const uniqueIds = new Set();
  for (const alert of grouped) {
    for (const occ of (alert.occurrences || [])) {
      if (occ && occ.messageId !== undefined && occ.messageId !== null && occ.messageId !== '') {
        uniqueIds.add(String(occ.messageId));
      }
    }
  }
  if (uniqueIds.size === 0) return;

  const ids = Array.from(uniqueIds);
  const messageMap = new Map();
  const CONCURRENCY = 5;

  let cursor = 0;
  async function worker() {
    while (cursor < ids.length) {
      const id = ids[cursor++];
      const msg = await fetchZapMessage(client, id);
      if (msg) messageMap.set(id, msg);
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(CONCURRENCY, ids.length); i++) workers.push(worker());
  await Promise.all(workers);

  for (const alert of grouped) {
    for (const occ of (alert.occurrences || [])) {
      if (occ && occ.messageId !== undefined && occ.messageId !== null) {
        const msg = messageMap.get(String(occ.messageId));
        if (msg) {
          occ.request = msg.request;
          occ.response = msg.response;
        }
      }
    }
  }
  console.log(`📩 Enriched ZAP auth occurrences with raw request/response for ${messageMap.size}/${ids.length} unique messages`);
}

async function createDualVersionAlerts(alerts, client = null) {
  const grouped = groupAlertsByUrl(alerts);

  // Best-effort: attach raw HTTP request/response to each occurrence.
  if (client) {
    await enrichOccurrencesWithMessages(grouped, client);
  }

  const summaryAlerts = grouped.map(alert => ({
    alert: alert.alert,
    risk: alert.risk,
    confidence: alert.confidence,
    description: alert.description ? alert.description.substring(0, 200) + '...' : '',
    solution: alert.solution ? alert.solution.substring(0, 150) + '...' : '',
    totalOccurrences: alert.totalCount,
    sampleUrls: alert.occurrences.slice(0, 5).map(occ => occ.url),
    hasMoreUrls: alert.occurrences.length > 5
  }));

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
    occurrences: alert.occurrences
  }));

  return { summaryAlerts, detailedAlerts };
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

async function checkZapAuthHealth() {
  try {
    console.log(`[ZAP-AUTH] Checking health at: ${ZAP_AUTH_URL}`);
    const response = await zapAuthApi.get('/JSON/core/view/version/');

    return {
      healthy: true,
      version: response.data.version,
      url: ZAP_AUTH_URL
    };
  } catch (error) {
    console.error('[ZAP-AUTH] Health check failed:', error.message);
    return {
      healthy: false,
      error: error.message,
      url: ZAP_AUTH_URL
    };
  }
}

// ============================================================================
// AUTHENTICATION CONTEXT CONFIGURATION
// ============================================================================

/**
 * Configure ZAP authentication context with session cookies.
 * Uses the Replacer API to inject Cookie headers into all requests.
 */
async function configureAuthContext({ targetUrl, cookies, scanId, zapClient }) {
  const contextName = `auth_scan_${scanId}`;
  const targetUrlObj = new URL(targetUrl);
  const targetDomain = targetUrlObj.hostname;
  const targetDomainEscaped = targetDomain.replace(/\./g, '\\.');

  console.log(`[ZAP-AUTH] Configuring auth context: ${contextName} for ${targetDomain}`);

  // Create a new context
  const contextResponse = await zapAuthApiWithRetry(
    () => zapClient.get('/JSON/context/action/newContext/', {
      params: { contextName }
    }),
    3, 1000, 'Create context'
  );
  const contextId = contextResponse.data.contextId;
  console.log(`[ZAP-AUTH] Created context: ${contextName} (ID: ${contextId})`);

  // Include target domain and subdomains
  const includePatterns = [
    `https?://${targetDomainEscaped}.*`,
    `https?://.*\\.${targetDomainEscaped}.*`
  ];

  for (const pattern of includePatterns) {
    try {
      await zapClient.get('/JSON/context/action/includeInContext/', {
        params: { contextName, regex: pattern }
      });
    } catch (err) {
      console.warn(`[ZAP-AUTH] Failed to add include pattern: ${err.message}`);
    }
  }

  // Exclude logout URLs to prevent session invalidation
  const excludePatterns = [
    '.*logout.*', '.*signout.*', '.*sign-out.*', '.*/auth/logout.*',
    // Common external domains
    '.*google-analytics\\.com.*', '.*googletagmanager\\.com.*',
    '.*facebook\\.com.*', '.*twitter\\.com.*', '.*linkedin\\.com.*',
    '.*cdn\\.jsdelivr\\.net.*', '.*cdnjs\\.cloudflare\\.com.*',
    '.*cloudflare\\.com.*', '.*cloudfront\\.net.*',
    '.*fonts\\.googleapis\\.com.*', '.*fonts\\.gstatic\\.com.*',
    '.*recaptcha\\.net.*', '.*hcaptcha\\.com.*'
  ];

  for (const pattern of excludePatterns) {
    try {
      await zapClient.get('/JSON/context/action/excludeFromContext/', {
        params: { contextName, regex: pattern }
      });
    } catch (_) {
      // Silently continue
    }
  }

  // Set context in scope
  await zapClient.get('/JSON/context/action/setContextInScope/', {
    params: { contextName, booleanInScope: 'true' }
  });

  // Inject cookies via Replacer API
  if (cookies && cookies.length > 0) {
    const cookieString = cookies
      .map(c => `${c.name}=${c.value}`)
      .join('; ');

    console.log(`[ZAP-AUTH] Injecting ${cookies.length} cookies via Replacer API`);

    try {
      // Remove any existing cookie replacer rule
      try {
        await zapClient.get('/JSON/replacer/action/removeRule/', {
          params: { description: 'auth_cookie' }
        });
      } catch (_) {
        // Rule may not exist yet
      }

      // Add Cookie header replacement rule
      await zapAuthApiWithRetry(
        () => zapClient.get('/JSON/replacer/action/addRule/', {
          params: {
            description: 'auth_cookie',
            enabled: 'true',
            matchType: 'REQ_HEADER',
            matchRegex: 'false',
            matchString: 'Cookie',
            replacement: cookieString,
            initiators: ''
          }
        }),
        3, 1000, 'Add cookie replacer rule'
      );

      console.log(`[ZAP-AUTH] Cookie injection configured successfully`);
    } catch (cookieError) {
      console.error(`[ZAP-AUTH] Failed to configure cookie injection: ${cookieError.message}`);
      throw new Error('Failed to configure authentication cookies in ZAP');
    }
  }

  // Configure file exclusions
  const exclusionPatterns = [
    '.*\\.webm.*', '.*\\.mp4.*', '.*\\.mov.*', '.*\\.avi.*',
    '.*\\.mkv.*', '.*\\.flv.*', '.*\\.wmv.*', '.*\\.m4v.*',
    '.*\\.zip$', '.*\\.tar$', '.*\\.gz$', '.*\\.rar$',
    '.*\\.7z$', '.*\\.iso$', '.*\\.dmg$', '.*\\.bz2$',
    '.*\\.exe$', '.*\\.msi$', '.*\\.app$',
    '.*\\.deb$', '.*\\.rpm$', '.*\\.pkg$',
    '.*\\.pdf$', '.*\\.doc$', '.*\\.docx$', '.*\\.ppt$', '.*\\.pptx$',
    '.*\\.woff$', '.*\\.woff2$', '.*\\.ttf$', '.*\\.eot$'
  ];

  for (const pattern of exclusionPatterns) {
    try {
      await zapClient.get('/JSON/core/action/excludeFromProxy/', {
        params: { regex: pattern }
      });
    } catch (_) {
      // Continue silently
    }
  }

  return { contextId, contextName };
}

// ============================================================================
// MAIN AUTHENTICATED SCAN WORKFLOW
// ============================================================================

/**
 * Run a full authenticated ZAP scan in the background.
 * Updates ScanResult.authScanResult as it progresses.
 */
async function runAuthenticatedScanBackground(targetUrl, loginUrl, cookies, scanId, userId, zapUrl) {
  // Per-scan client pointing at this scan's dedicated container.
  // All zapAuthApi.get() calls inside this function reference this local variable.
  const zapAuthApi = createZapAuthClient(zapUrl || ZAP_AUTH_URL);

  console.log(`[ZAP-AUTH] Starting authenticated scan for user ${userId}: ${targetUrl}`);
  console.log(`[ZAP-AUTH] Scan ID: ${scanId}`);
  console.log(`[ZAP-AUTH] Login URL: ${loginUrl}`);

  let contextName = null;

  const updateProgress = async (phase, progress, additionalData = {}) => {
    try {
      const currentScan = await ScanResult.findOne({ analysisId: scanId });

      // --- TERMINAL STATE CHECK: If scan was stopped/failed, EXIT BACKGROUND PROCESS ---
      if (currentScan && ['stopped', 'failed'].includes(currentScan.status)) {
        console.log(`🛑 [ZAP-AUTH] Scan ${scanId} detected as ${currentScan.status}. Terminating background worker.`);
        throw new Error('STOPPED_BY_USER');
      }

      const updateFields = {
        'authScanResult.phase': phase,
        'authScanResult.progress': progress,
        'authScanResult.lastUpdate': new Date(),
      };
      for (const [key, value] of Object.entries(additionalData)) {
        updateFields[`authScanResult.${key}`] = value;
      }
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: updateFields }
      );
      console.log(`[ZAP-AUTH] Progress: ${phase} - ${progress}%`);

      // Emit real-time WebSocket progress milestone (non-blocking)
      try {
        const { publishScanProgress } = require('./scanProgressService');
        publishScanProgress(scanId, userId, {
          status: currentScan ? currentScan.status : 'running',
          progress: progress,
          phase: phase,
          zapResult: { status: 'running', phase, progress, ...additionalData }
        }).catch(() => {});
      } catch (wsErr) {
        console.error('[ZAP-AUTH] Failed to emit WebSocket progress:', wsErr.message);
      }
    } catch (updateError) {
      if (updateError.message === 'STOPPED_BY_USER') {
        throw updateError;
      }
      console.error('[ZAP-AUTH] Failed to update progress:', updateError.message);
    }
  };

  try {
    // Phase 1: Configure authentication
    await updateProgress('configuring', 5, { status: 'running', message: 'Configuring authentication...' });

    const { contextId, contextName: ctxName } = await configureAuthContext({
      targetUrl,
      cookies,
      scanId,
      zapClient: zapAuthApi
    });
    contextName = ctxName;

    // Access target URL to seed ZAP's session with authenticated cookies
    await updateProgress('authenticating', 10, { message: 'Accessing target with authentication...' });
    try {
      await zapAuthApiWithRetry(
        () => zapAuthApi.get('/JSON/core/action/accessUrl/', {
          params: { url: targetUrl, followRedirects: 'true' }
        }),
        3, 2000, 'Access target URL'
      );
      console.log(`[ZAP-AUTH] Target URL accessed with authentication`);
    } catch (accessError) {
      console.warn(`[ZAP-AUTH] Could not access target URL: ${accessError.message}`);
      // Continue anyway - spider will try to access it
    }

    // Also access the login URL to ensure ZAP knows the session
    try {
      await zapAuthApi.get('/JSON/core/action/accessUrl/', {
        params: { url: loginUrl, followRedirects: 'true' }
      });
    } catch (_) {
      // Non-critical
    }

    // Phase 2: Traditional Spider
    await updateProgress('spidering', 15, { message: 'Crawling authenticated pages...' });
    console.log(`[ZAP-AUTH] Starting spider on ${targetUrl}`);

    const spiderConfig = {
      maxDepth: 15,
      maxDuration: 120,    // 2 hours max for spider
      maxChildren: 5000,
      threadCount: 7
    };

    // Configure spider
    try {
      await zapAuthApi.get('/JSON/spider/action/setOptionMaxDepth/', {
        params: { Integer: spiderConfig.maxDepth }
      });
      await zapAuthApi.get('/JSON/spider/action/setOptionMaxDuration/', {
        params: { Integer: spiderConfig.maxDuration }
      });
      await zapAuthApi.get('/JSON/spider/action/setOptionMaxChildren/', {
        params: { Integer: spiderConfig.maxChildren }
      });
      await zapAuthApi.get('/JSON/spider/action/setOptionThreadCount/', {
        params: { Integer: spiderConfig.threadCount }
      });
    } catch (configError) {
      console.warn(`[ZAP-AUTH] Spider config warning: ${configError.message}`);
    }

    // Start spider with context
    const spiderResponse = await zapAuthApiWithRetry(
      () => zapAuthApi.get('/JSON/spider/action/scan/', {
        params: {
          url: targetUrl,
          contextName: contextName,
          recurse: 'true',
          subtreeOnly: 'false'
        }
      }),
      3, 2000, 'Start spider'
    );
    const spiderId = spiderResponse.data.scan;
    console.log(`[ZAP-AUTH] Spider started: ID ${spiderId}`);

    // Wait for spider to complete
    let spiderComplete = false;
    let urlsFound = 0;
    const spiderMaxIterations = spiderConfig.maxDuration * 60 / 3; // check every 3 seconds

    for (let i = 0; i < spiderMaxIterations && !spiderComplete; i++) {
      await sleep(3000);

      try {
        const statusResponse = await zapAuthApi.get('/JSON/spider/view/status/', {
          params: { scanId: spiderId }
        });
        const spiderProgress = parseInt(statusResponse.data.status || 0);

        // Get URL count
        try {
          const urlsResponse = await zapAuthApi.get('/JSON/spider/view/results/', {
            params: { scanId: spiderId }
          });
          urlsFound = (urlsResponse.data.results || []).length;
        } catch (_) {
          // Continue
        }

        const uiProgress = 15 + Math.floor(spiderProgress * 0.15); // 15-30%
        await updateProgress('spidering', uiProgress, {
          message: `Spider: ${urlsFound} URLs found (${spiderProgress}%)`,
          urlsFound
        });

        if (spiderProgress >= 100) {
          spiderComplete = true;
        }
      } catch (statusError) {
        console.warn(`[ZAP-AUTH] Spider status error: ${statusError.message}`);
      }
    }

    console.log(`[ZAP-AUTH] Spider complete. URLs found: ${urlsFound}`);

    // Phase 2.5: AJAX Spider
    await updateProgress('ajax_spider', 32, { message: 'Running AJAX spider for dynamic content...' });
    console.log(`[ZAP-AUTH] Starting AJAX spider`);

    try {
      await zapAuthApi.get('/JSON/ajaxSpider/action/setOptionMaxDuration/', {
        params: { Integer: 30 } // 30 minutes for AJAX spider
      });
      await zapAuthApi.get('/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/', {
        params: { Integer: 5 }
      });
      await zapAuthApi.get('/JSON/ajaxSpider/action/setOptionNumberOfBrowsers/', {
        params: { Integer: 3 }
      });
    } catch (_) {
      // Continue with defaults
    }

    try {
      await zapAuthApiWithRetry(
        () => zapAuthApi.get('/JSON/ajaxSpider/action/scan/', {
          params: {
            url: targetUrl,
            inScope: 'true',
            contextName: contextName,
            subtreeOnly: 'false'
          }
        }),
        3, 2000, 'Start AJAX spider'
      );

      // Wait for AJAX spider to complete with timeout
      const ajaxMaxIterations = 30 * 60 / 5; // 30 min / 5s intervals
      for (let i = 0; i < ajaxMaxIterations; i++) {
        await sleep(5000);

        try {
          const ajaxStatusResponse = await zapAuthApi.get('/JSON/ajaxSpider/view/status/');
          const ajaxStatus = ajaxStatusResponse.data.status;

          if (ajaxStatus === 'stopped') break;

          const uiProgress = 32 + Math.floor(((i + 1) / ajaxMaxIterations) * 8); // 32-40%
          await updateProgress('ajax_spider', Math.min(uiProgress, 40), {
            message: `AJAX Spider: Discovering dynamic content...`
          });
          console.log(`[ZAP-AUTH] AJAX spider: ${ajaxStatus}`);
        } catch (err) {
          if (err.message === 'STOPPED_BY_USER') {
            throw err;
          }
          break;
        }
      }

      // Stop AJAX spider if still running
      try {
        await zapAuthApi.get('/JSON/ajaxSpider/action/stop/');
      } catch (_) {
        // May already be stopped
      }
    } catch (ajaxError) {
      console.warn(`[ZAP-AUTH] AJAX spider error: ${ajaxError.message}`);
    }

    // Update URL count after AJAX spider
    try {
      const allUrlsResponse = await zapAuthApi.get('/JSON/core/view/urls/', {
        params: { baseurl: targetUrl }
      });
      urlsFound = (allUrlsResponse.data.urls || []).length;
    } catch (_) {
      // Keep previous count
    }

    console.log(`[ZAP-AUTH] Total URLs after AJAX spider: ${urlsFound}`);

    // Phase 3: Passive Scan
    await updateProgress('passive_scan', 42, { message: 'Running passive analysis...', urlsFound });
    console.log(`[ZAP-AUTH] Waiting for passive scan to complete`);

    for (let i = 0; i < 120; i++) { // Max 2 minutes
      await sleep(1000);
      try {
        const passiveResponse = await zapAuthApi.get('/JSON/pscan/view/recordsToScan/');
        const recordsToScan = parseInt(passiveResponse.data.recordsToScan || 0);
        if (recordsToScan === 0) break;
      } catch (_) {
        break;
      }
    }

    console.log(`[ZAP-AUTH] Passive scan complete`);

    // Phase 4: Active Scan
    await updateProgress('active_scan', 45, { message: 'Starting vulnerability testing...', urlsFound });
    console.log(`[ZAP-AUTH] Starting active scan`);

    // Configure active scanner
    try {
      await zapAuthApi.get('/JSON/ascan/action/setOptionMaxScanDurationInMins/', {
        params: { Integer: 180 } // 3 hours max for active scan
      });
      await zapAuthApi.get('/JSON/ascan/action/setOptionMaxRuleDurationInMins/', {
        params: { Integer: 60 } // 1 hour per rule
      });
      await zapAuthApi.get('/JSON/ascan/action/setOptionThreadPerHost/', {
        params: { Integer: 7 }
      });
      await zapAuthApi.get('/JSON/ascan/action/setOptionDelayInMs/', {
        params: { Integer: 0 }
      });
    } catch (configError) {
      console.warn(`[ZAP-AUTH] Active scan config warning: ${configError.message}`);
    }

    const activeScanResponse = await zapAuthApiWithRetry(
      () => zapAuthApi.get('/JSON/ascan/action/scan/', {
        params: {
          url: targetUrl,
          recurse: 'true',
          inScopeOnly: 'true',
          contextId: contextId
        }
      }),
      3, 2000, 'Start active scan'
    );
    const activeScanId = activeScanResponse.data.scan;
    console.log(`[ZAP-AUTH] Active scan started: ID ${activeScanId}`);

    // Wait for active scan
    let lastProgress = -1;
    let stuckCount = 0;
    const activeMaxIterations = 180 * 60 / 5; // 3 hours / 5s intervals

    for (let i = 0; i < activeMaxIterations; i++) {
      await sleep(5000);

      try {
        const scanStatusResponse = await zapAuthApi.get('/JSON/ascan/view/status/', {
          params: { scanId: activeScanId }
        });
        const scanProgress = parseInt(scanStatusResponse.data.status || 0);

        if (scanProgress >= 100) break;

        // Stuck detection
        if (scanProgress === lastProgress) {
          stuckCount++;
          if (stuckCount > 60) { // 5 min stuck
            console.warn(`[ZAP-AUTH] Active scan appears stuck at ${scanProgress}%. Stopping.`);
            try {
              await zapAuthApi.get('/JSON/ascan/action/stop/', {
                params: { scanId: activeScanId }
              });
            } catch (_) {}
            break;
          }
        } else {
          stuckCount = 0;
        }
        lastProgress = scanProgress;

        // Get alert count
        let currentAlerts = 0;
        try {
          const alertsCountResponse = await zapAuthApi.get('/JSON/core/view/numberOfAlerts/');
          currentAlerts = parseInt(alertsCountResponse.data.numberOfAlerts || 0);
        } catch (_) {}

        const uiProgress = 45 + Math.floor(scanProgress * 0.45); // 45-90%
        await updateProgress('active_scan', uiProgress, {
          message: `Testing for vulnerabilities: ${scanProgress}%`,
          alertsFound: currentAlerts
        });
        console.log(`[ZAP-AUTH] Active scan: ${scanProgress}% | Alerts: ${currentAlerts} | Stuck: ${stuckCount}`);
      } catch (scanError) {
        if (scanError.message === 'STOPPED_BY_USER') {
          throw scanError;
        }
        console.warn(`[ZAP-AUTH] Active scan status error: ${scanError.message}`);
      }
    }

    console.log(`[ZAP-AUTH] Active scan complete`);

    // Phase 5: Retrieve and process alerts
    await updateProgress('processing', 92, { message: 'Collecting vulnerability data...' });
    console.log(`[ZAP-AUTH] Retrieving alerts`);

    const alertsResponse = await zapAuthApi.get('/JSON/core/view/alerts/', {
      params: {
        baseurl: targetUrl,
        start: 0,
        count: 10000
      }
    });

    const rawAlerts = alertsResponse.data.alerts || [];
    console.log(`[ZAP-AUTH] Retrieved ${rawAlerts.length} raw alerts`);

    // Generate HTML report
    const htmlReportResponse = await zapAuthApi.get('/OTHER/core/other/htmlreport/', {
      responseType: 'arraybuffer'
    });

    // Process alerts
    const { summaryAlerts, detailedAlerts } = await createDualVersionAlerts(rawAlerts, zapAuthApi);
    console.log(`[ZAP-AUTH] Grouped into ${summaryAlerts.length} unique alert types`);

    const riskCounts = summaryAlerts.reduce((acc, alert) => {
      acc[alert.risk] = (acc[alert.risk] || 0) + 1;
      return acc;
    }, { High: 0, Medium: 0, Low: 0, Informational: 0 });

    // Store reports in GridFS
    await updateProgress('saving', 95, { message: 'Saving reports...' });

    const htmlBuffer = Buffer.from(htmlReportResponse.data);
    const htmlFileId = await gridfsService.uploadFile(
      htmlBuffer,
      `zap_auth_report_${scanId}.html`,
      { scanId, contentType: 'text/html' },
      'zap_auth_reports'
    );

    const detailedAlertsBuffer = Buffer.from(JSON.stringify(detailedAlerts, null, 2), 'utf-8');
    const detailedAlertsFileId = await gridfsService.uploadFile(
      detailedAlertsBuffer,
      `zap_auth_detailed_alerts_${scanId}.json`,
      { scanId, contentType: 'application/json' },
      'zap_auth_reports'
    );

    console.log(`[ZAP-AUTH] Reports stored in GridFS`);

    const authScanResultObj = {
      status: 'completed',
      phase: 'completed',
      progress: 100,
      authenticated: true,
      loginUrl,
      urlsFound,
      alerts: summaryAlerts,
      riskCounts,
      totalAlerts: summaryAlerts.length,
      totalOccurrences: summaryAlerts.reduce((sum, a) => sum + a.totalOccurrences, 0),
      reportFiles: [
        {
          fileId: htmlFileId.toString(),
          filename: `zap_auth_report_${scanId}.html`,
          contentType: 'text/html',
          format: 'html',
          size: htmlBuffer.length
        },
        {
          fileId: detailedAlertsFileId.toString(),
          filename: `zap_auth_detailed_alerts_${scanId}.json`,
          contentType: 'application/json',
          format: 'json',
          size: detailedAlertsBuffer.length,
          description: 'Full alert details with all affected URLs'
        }
      ],
      completedAt: new Date()
    };

    // Update final scan result
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          status: 'combining',
          authScanResult: authScanResultObj,
          zapResult: authScanResultObj, // Copy to zapResult for compatibility
          updatedAt: new Date()
        }
      }
    );

    // Deduct scan from user quota only upon successful completion
    await finalizeSuccessfulScan(scanId).catch(e => console.error(`[ZAP-AUTH][${scanId}] Failed to finalize scan quota:`, e.message));

    console.log(`[ZAP-AUTH] Scan complete: ${scanId}`);
    console.log(`[ZAP-AUTH]   URLs found: ${urlsFound}`);
    console.log(`[ZAP-AUTH]   Alert types: ${summaryAlerts.length}`);
    console.log(`[ZAP-AUTH]   Risk: High=${riskCounts.High}, Medium=${riskCounts.Medium}, Low=${riskCounts.Low}, Info=${riskCounts.Informational}`);

    // Trigger Gemini report generation
    setImmediate(() => {
      try {
        const { checkAndGenerateGemini } = require('./geminiCompletionService');
        checkAndGenerateGemini(scanId, String(userId)).catch(e =>
          console.error(`[ZAP-AUTH][${scanId}] checkAndGenerateGemini error (success path):`, e.message)
        );
      } catch (e) {
        console.error(`[ZAP-AUTH][${scanId}] Failed to load geminiCompletionService:`, e.message);
      }
    });

    // Cleanup: Remove context and replacer rule
    if (contextName) {
      try {
        await zapAuthApi.get('/JSON/context/action/removeContext/', {
          params: { contextName }
        });
        console.log(`[ZAP-AUTH] Cleaned up context: ${contextName}`);
      } catch (_) {}
    }
    try {
      await zapAuthApi.get('/JSON/replacer/action/removeRule/', {
        params: { description: 'auth_cookie' }
      });
    } catch (_) {}

    return { success: true, scanId };

  } catch (error) {
    if (error.message === 'STOPPED_BY_USER') {
      console.log(`🛑 [ZAP-AUTH] Authenticated scan for ${scanId} was successfully terminated due to user cancellation.`);
      // Cleanup: Remove context and replacer rule
      if (contextName) {
        try {
          await zapAuthApi.get('/JSON/context/action/removeContext/', {
            params: { contextName }
          });
          console.log(`[ZAP-AUTH] Cleaned up context: ${contextName}`);
        } catch (_) {}
      }
      try {
        await zapAuthApi.get('/JSON/replacer/action/removeRule/', {
          params: { description: 'auth_cookie' }
        });
      } catch (_) {}
      return { success: false, reason: 'stopped' };
    }

    console.error(`[ZAP-AUTH] Scan failed: ${error.message}`);

    // Update database with failure
    try {
      const zapResultCopy = {
        status: 'failed',
        phase: 'failed',
        error: error.message,
        completedAt: new Date()
      };
      await ScanResult.updateOne(
        { analysisId: scanId },
        {
          $set: {
            status: 'failed',
            'authScanResult.status': 'failed',
            'authScanResult.phase': 'failed',
            'authScanResult.error': error.message,
            'authScanResult.completedAt': new Date(),
            zapResult: zapResultCopy,
            updatedAt: new Date()
          }
        }
      );

      const { checkAndGenerateGemini } = require('./geminiCompletionService');
      checkAndGenerateGemini(scanId, String(userId)).catch(e =>
        console.error(`[ZAP-AUTH] checkAndGenerateGemini error after ZAP failure:`, e.message)
      );
    } catch (updateError) {
      console.error('[ZAP-AUTH] Failed to update failure status:', updateError.message);
    }

    // Cleanup context on failure
    if (contextName) {
      try {
        await zapAuthApi.get('/JSON/context/action/removeContext/', {
          params: { contextName }
        });
      } catch (_) {}
    }
    try {
      await zapAuthApi.get('/JSON/replacer/action/removeRule/', {
        params: { description: 'auth_cookie' }
      });
    } catch (_) {}

    throw error;
  }
}

// ============================================================================
// ASYNC SCAN ENTRY POINT
// ============================================================================

/**
 * Start an authenticated scan asynchronously. Returns immediately.
 * The actual scan runs in the background.
 */
async function startAsyncAuthScan(targetUrl, loginUrl, cookies, scanId, userId, zapUrl, onComplete) {
  console.log(`[ZAP-AUTH] Starting async auth scan for: ${targetUrl}`);

  // Check if a scan already exists for this ID
  const existing = await ScanResult.findOne({ analysisId: scanId });
  if (existing && existing.authScanResult && existing.authScanResult.status === 'running') {
    console.log(`[ZAP-AUTH] Scan ${scanId} already running`);
    return {
      scanId,
      status: 'already_running',
      message: 'An authenticated scan is already in progress for this ID'
    };
  }

  // Create or update the scan result in database
  if (existing) {
    await ScanResult.updateOne(
      { analysisId: scanId },
      {
        $set: {
          status: 'pending',
          authScanResult: {
            status: 'running',
            phase: 'queued',
            progress: 0,
            authenticated: true,
            loginUrl,
            urlsFound: 0,
            alerts: [],
            startedAt: new Date()
          },
          updatedAt: new Date()
        }
      }
    );
  } else {
    const scanResult = new ScanResult({
      analysisId: scanId,
      userId,
      target: targetUrl,
      status: 'pending',
      authScanResult: {
        status: 'running',
        phase: 'queued',
        progress: 0,
        authenticated: true,
        loginUrl,
        urlsFound: 0,
        alerts: [],
        startedAt: new Date()
      }
    });
    await scanResult.save();
  }

  console.log(`[ZAP-AUTH] Scan record created: ${scanId}`);

  // Fire and forget — run scan in background
  runAuthenticatedScanBackground(targetUrl, loginUrl, cookies, scanId, userId, zapUrl)
    .catch(error => {
      console.error(`[ZAP-AUTH] Background scan error for ${scanId}:`, error.message);
    })
    .finally(() => {
      if (typeof onComplete === 'function') onComplete(scanId);
    });

  return {
    scanId,
    status: 'started',
    message: 'Authenticated scan started successfully'
  };
}

// ============================================================================
// STATUS & MANAGEMENT
// ============================================================================

async function getAuthScanStatus(scanId, userId) {
  const scanResult = await ScanResult.findOne({
    analysisId: scanId,
    userId
  });

  if (!scanResult) {
    throw new Error('Scan not found or access denied');
  }

  return {
    scanId: scanResult.analysisId,
    target: scanResult.target,
    status: scanResult.status,
    authScanResult: scanResult.authScanResult,
    createdAt: scanResult.createdAt,
    updatedAt: scanResult.updatedAt
  };
}

async function stopAuthScan(scanId, userId) {
  const scanResult = await ScanResult.findOne({
    analysisId: scanId,
    userId
  });

  if (!scanResult) {
    throw new Error('Scan not found or access denied');
  }

  // Stop all active scans in ZAP
  try {
    await zapAuthApi.get('/JSON/ascan/action/stopAllScans/');
  } catch (_) {}
  try {
    await zapAuthApi.get('/JSON/spider/action/stopAllScans/');
  } catch (_) {}
  try {
    await zapAuthApi.get('/JSON/ajaxSpider/action/stop/');
  } catch (_) {}

  // Cancel active/waiting BullMQ job if present
  try {
    const { getZapQueue } = require('../queues/zapQueue');
    const zapQueue = getZapQueue();
    if (zapQueue) {
      const job = await zapQueue.getJob(`zap-${scanId}`);
      if (job) {
        console.log(`[BullMQ] Found job zap-${scanId} in zap-queue for authenticated scan. Canceling.`);
        try {
          if (typeof job.discard === 'function') {
            await job.discard();
          }
        } catch (_) {}
        try {
          await job.remove();
        } catch (e) {
          console.error(`[BullMQ] Failed to remove job zap-${scanId}:`, e.message);
        }
      }
    }
  } catch (err) {
    console.error(`[BullMQ] Error canceling zap-queue job for ${scanId}:`, err.message);
  }

  // Release AWS Fargate dynamic container
  try {
    const { releaseContainer } = require('./zapContainerManager');
    await releaseContainer(scanId);
  } catch (err) {
    console.warn(`[zapAuthService] Failed to release container for ${scanId}:`, err.message);
  }

  // Update database
  await ScanResult.updateOne(
    { analysisId: scanId },
    {
      $set: {
        status: 'stopped',
        'authScanResult.status': 'stopped',
        'authScanResult.phase': 'stopped',
        'authScanResult.completedAt': new Date(),
        updatedAt: new Date()
      }
    }
  );

  return { success: true, message: 'Authenticated scan stopped' };
}

module.exports = {
  checkZapAuthHealth,
  configureAuthContext,
  startAsyncAuthScan,
  getAuthScanStatus,
  stopAuthScan,
  runAuthenticatedScanBackground
};
