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
const { markerPresentInBody } = require('../utils/loginSignals');
const { redactHeaderBlock, scrubSecrets, scrubText, MIN_SCRUB_LENGTH } = require('../utils/credentialRedaction');
const credentialRules = require('./zapCredentialRules');
const credentialVault = require('./scanCredentialVault');

// ============================================================================
// ZAP AUTH API CONFIGURATION
// ============================================================================

const ZAP_AUTH_URL = process.env.ZAP_AUTH_API_URL || 'http://127.0.0.1:8081';
const ZAP_AUTH_API_KEY = process.env.ZAP_AUTH_API_KEY; // Optional when ZAP runs with api.disablekey=true

// Mirrors AJAX_SPIDER_BROWSERS in zapService.js — headless Firefox processes count
// against the ZAP container's memory limit, not the JVM heap.
const AJAX_SPIDER_BROWSERS = Number(process.env.ZAP_AJAX_BROWSERS) || 1;

// How many times a scan may log itself back in before we accept the session is
// not recoverable and label the remaining coverage as public-pages-only. Capped
// so a site that rejects the credentials outright cannot cause a login storm.
const MAX_RELOGIN_ATTEMPTS = 3;

// Everything recorded about whether the scan was actually signed in. The final
// write replaces `authScanResult` wholesale, so these are re-read and carried
// across; listing them in one place keeps that from rotting as fields are added.
const AUTH_HEALTH_KEYS = [
  'loginOutcome',
  'authVerified',
  'authVerifiedReason',
  'authVerifiedAt',
  'authVerifiedPhase',
  'authLostAt',
  'reloginAttempts',
  'authRepaired',
  'authDegraded',
  'authDegradedReason',
  'authMethod',
  'authEvidence'
];

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

// A scan in any of these states is over: nothing may start, resume or overwrite it.
const TERMINAL_SCAN_STATES = ['stopped', 'cancelled', 'failed', 'completed'];

// ============================================================================
// RUNNING WORKERS (stop support)
// ============================================================================
//
// scanId → the live background worker in THIS process.
//
// Why it exists: stopping used to be a status write plus `stopAllScans` sent to the
// module-level client. The worker noticed the write only at its next progress update
// (up to 5 s in the scan loops, 2 min in the passive-scan wait, never inside the AJAX
// phase, whose catch swallowed the signal), and the `stopAllScans` went to whichever
// scan held the auth ZAP at that moment — for a scan still queueing for the instance,
// another customer's. Now a stop wakes this worker's sleeps at once and talks only to
// this scan's own ZAP client; a scan with no running worker sends nothing to ZAP.
// Single backend process assumed (as for the credential vault); a stop that reaches a
// different process still lands, via the status check in updateProgress.
const runningWorkers = new Map();

function registerWorker(scanId, client) {
  let markDone;
  const entry = {
    client,
    stopRequested: false,
    wakers: new Set(),
    done: new Promise(resolve => { markDone = resolve; })
  };
  entry.markDone = markDone;
  runningWorkers.set(scanId, entry);
  return entry;
}

/** Signal a running worker to stop. Returns its entry, or null if none runs here. */
function signalWorkerStop(scanId) {
  const entry = runningWorkers.get(scanId);
  if (!entry) return null;
  entry.stopRequested = true;
  for (const wake of [...entry.wakers]) wake();
  return entry;
}

/**
 * True when the scan must not (or no longer) run: stopped, cancelled, failed,
 * completed — or gone. Used by the start paths' withZapInstance `isCancelled` hook.
 */
async function isAuthScanCancelled(scanId) {
  const entry = runningWorkers.get(scanId);
  if (entry && entry.stopRequested) return true;
  const scan = await ScanResult.findOne({ analysisId: scanId }).select('status').lean();
  return !scan || TERMINAL_SCAN_STATES.includes(scan.status);
}

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
      // Mirrors zapApiWithRetry in zapService.js: a 504 from the Service Connect proxy
      // is an HTTP response, not a socket error, so it matched nothing here and gave up
      // after one attempt.
      const status = error.response?.status;
      const isRetryable = error.code === 'ECONNRESET' ||
                          error.code === 'ETIMEDOUT' ||
                          error.code === 'ENOTFOUND' ||
                          error.message?.includes('socket hang up') ||
                          error.message?.includes('ECONNREFUSED') ||
                          error.message?.includes('timeout') ||
                          status === 429 ||
                          (status >= 500 && status <= 599);

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
 * Fetch the most recent response body the proxy saw for a URL.
 *
 * Used to answer "are we still signed in?" during a scan. Best-effort: returns
 * null on any failure, and callers must treat null as "cannot tell" rather than
 * as "signed out" — wrongly reporting a lost session is as bad as missing one.
 *
 * @param {import('axios').AxiosInstance} client
 * @param {string} baseurl
 * @returns {Promise<string|null>}
 */
async function fetchLatestResponseBody(client, baseurl) {
  if (!client || !baseurl) return null;
  try {
    const res = await client.get('/JSON/core/view/messages/', {
      params: { baseurl, start: 0, count: 50 }
    });
    const messages = (res && res.data && res.data.messages) || [];
    if (!Array.isArray(messages) || messages.length === 0) return null;
    // Most recent last.
    for (let i = messages.length - 1; i >= 0; i--) {
      const body = messages[i] && messages[i].responseBody;
      if (typeof body === 'string' && body.length > 0) return body;
    }
    return null;
  } catch (err) {
    console.warn(`[ZAP-AUTH] Could not read response body for ${baseurl}: ${err.message}`);
    return null;
  }
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
    // The stored request carries whatever the Replacer injected (Authorization for
    // Basic, the session Cookie for form login). Redacted before it is stored.
    return {
      request: { header: redactHeaderBlock(m.requestHeader || ''), body: m.requestBody || '' },
      response: { header: redactHeaderBlock(m.responseHeader || ''), body: m.responseBody || '' }
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

async function createDualVersionAlerts(alerts, client = null, secrets = []) {
  // Exact-secret scrub before anything is grouped or stored: ZAP's own alert text
  // can quote the credential (rule 10105 writes the decoded Basic password).
  const grouped = groupAlertsByUrl(scrubSecrets(alerts, secrets));

  // Best-effort: attach raw HTTP request/response to each occurrence.
  if (client) {
    await enrichOccurrencesWithMessages(grouped, client);
    if (secrets.length) {
      for (const g of grouped) g.occurrences = scrubSecrets(g.occurrences, secrets);
    }
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
/**
 * Is the scan still signed in?
 *
 * Nothing in this file used to ask. A session that expired twenty minutes into a
 * four-hour scan produced a full report of the publicly visible pages, labelled
 * as authenticated, with no indication anything had gone wrong.
 *
 * Three-valued on purpose:
 *   true  — the signed-in marker is in the response body
 *   false — the marker should be there and is not
 *   null  — we cannot tell, and must not guess
 *
 * `null` is the honest answer for a single-page app: it serves the same shell
 * HTML to everyone and fills it in with JavaScript, so the marker never appears
 * in a response body even when the session is perfectly healthy. That is what
 * `markerCheckableInBody` records at login time.
 *
 * @returns {Promise<{verified:boolean|null, reason:string}>}
 */
async function verifySignedIn({ zapClient, targetUrl, authState }) {
  // HTTP Basic: the server answers a protected URL with 401 unless the credential
  // is accepted, so the status code is the evidence — no page marker needed.
  if (authState && authState.method === 'basic') {
    const url = authState.verifyUrl || targetUrl;
    try {
      await zapClient.get('/JSON/core/action/accessUrl/', { params: { url, followRedirects: 'false' } });
    } catch (_) {
      return { verified: null, reason: 'basic_probe_failed' };
    }
    const status = await credentialRules.latestStatusFor(zapClient, url);
    if (status === null) return { verified: null, reason: 'no_response_captured' };
    if (status === 401) return { verified: false, reason: 'basic_unauthorized' };
    if (status >= 200 && status < 400) return { verified: true, reason: 'basic_accepted' };
    return { verified: null, reason: `basic_status_${status}` };
  }
  if (!authState || !authState.marker) {
    return { verified: null, reason: 'no_marker' };
  }
  if (!authState.markerCheckableInBody) {
    return { verified: null, reason: 'marker_not_in_body' };
  }

  const body = await fetchLatestResponseBody(zapClient, targetUrl);
  if (body === null) {
    return { verified: null, reason: 'no_response_captured' };
  }

  return markerPresentInBody(body, authState.marker)
    ? { verified: true, reason: 'marker_present' }
    : { verified: false, reason: 'marker_absent' };
}

/**
 * Log in again and repoint the proxy at the fresh cookies.
 *
 * The login recipe is held only for the life of the scan. For a manual scan it
 * lives in memory and is never written to disk; for a scheduled scan it comes
 * from the stored schedule, where the credential values are encrypted at rest.
 *
 * @returns {Promise<{ok:boolean, cookies:Array, reason:string}>}
 */
async function reAuthenticate({ zapClient, authState, scanId }) {
  // Basic is stateless: there is no session to renew. A 401 mid-scan means the
  // credential was revoked or the account locked; retrying would only add failed
  // attempts against the customer's account.
  if (authState && authState.method === 'basic') {
    return { ok: false, cookies: [], reason: 'basic_credentials_rejected' };
  }
  if (!authState || !authState.recipe || !authState.recipe.loginUrl) {
    return { ok: false, cookies: [], reason: 'no_recipe' };
  }
  if (authState.reloginAttempts >= MAX_RELOGIN_ATTEMPTS) {
    return { ok: false, cookies: [], reason: 'attempts_exhausted' };
  }

  authState.reloginAttempts = (authState.reloginAttempts || 0) + 1;
  console.log(`[ZAP-AUTH] Session lost for ${scanId} — re-login attempt ${authState.reloginAttempts}`);

  try {
    const { testLogin } = require('./loginTestService');
    const result = await testLogin({
      loginUrl: authState.recipe.loginUrl,
      credentials: authState.recipe.credentials,
      submitButton: authState.recipe.submitButton,
      submitAlternates: authState.recipe.submitAlternates,
      // Only hand back a marker we actually trust. `expectedMarker` is the
      // human-vouched path — testLogin treats whatever arrives there as proof.
      // Feeding a weak auto-derived marker in would promote it to proof on the
      // retry, confirming a sign-in on evidence that was not good enough the
      // first time.
      expectedMarker: authState.markerConfidence === 'high' ? authState.marker : null
    });

    if (!result.authenticated || !result.cookies || result.cookies.length === 0) {
      return { ok: false, cookies: [], reason: 'login_failed' };
    }

    await applyCookieReplacerRule(zapClient, result.cookies);

    // A session was re-established, but that is not the same as knowing we are
    // signed in again. Report the two separately so the scan does not claim a
    // repair it cannot stand behind.
    const confirmed = result.authConfirmed === 'confirmed';
    console.log(
      `[ZAP-AUTH] Re-login for ${scanId}: session restored (${result.cookies.length} cookies), ` +
      `sign-in ${confirmed ? 'confirmed' : 'NOT confirmed'}`
    );
    return {
      ok: true,
      confirmed,
      cookies: result.cookies,
      reason: confirmed ? 'relogin_confirmed' : 'relogin_unconfirmed'
    };
  } catch (err) {
    console.error(`[ZAP-AUTH] Re-login threw for ${scanId}: ${err.message}`);
    return { ok: false, cookies: [], reason: 'relogin_error' };
  }
}

/**
 * Check the session and repair it if it has died. Records what happened on the
 * scan document so the report can tell the truth about coverage.
 *
 * Never throws and never fails the scan: a scan of the public pages is still
 * worth delivering, as long as it is labelled as one.
 *
 * @param {string} phase where in the scan this check ran, for the audit trail
 */
async function checkAndRepairSession({ zapClient, targetUrl, authState, scanId, phase }) {
  if (!authState) return {};

  try {
    return await runSessionCheck({ zapClient, targetUrl, authState, scanId, phase });
  } catch (err) {
    // A problem checking the session must never take down the scan itself.
    console.warn(`[ZAP-AUTH] Session check failed at ${phase} for ${scanId}: ${err.message}`);
    return {};
  }
}

async function runSessionCheck({ zapClient, targetUrl, authState, scanId, phase }) {
  const { verified, reason } = await verifySignedIn({ zapClient, targetUrl, authState });

  const update = {
    'authScanResult.authVerified': verified,
    'authScanResult.authVerifiedReason': reason,
    'authScanResult.authVerifiedAt': new Date(),
    'authScanResult.authVerifiedPhase': phase,
    updatedAt: new Date()
  };

  if (verified === false) {
    update['authScanResult.authLostAt'] = new Date();
    const repair = await reAuthenticate({ zapClient, authState, scanId });
    update['authScanResult.reloginAttempts'] = authState.reloginAttempts || 0;
    // Only a re-login we could actually verify counts as a repair. Getting a
    // fresh session back is necessary but not sufficient — claiming otherwise
    // would let the report assert signed-in coverage it cannot stand behind.
    update['authScanResult.authRepaired'] = Boolean(repair.ok && repair.confirmed);
    if (!repair.ok || !repair.confirmed) {
      update['authScanResult.authDegraded'] = true;
      update['authScanResult.authDegradedReason'] = repair.reason;
    }
  }

  await ScanResult.updateOne({ analysisId: scanId }, { $set: update }).catch(() => {});

  // Returned undotted so the caller can carry these into the final write, which
  // replaces `authScanResult` wholesale and would otherwise discard them at the
  // exact moment the report needs them.
  const carried = {};
  for (const [key, value] of Object.entries(update)) {
    if (key.startsWith('authScanResult.')) carried[key.slice('authScanResult.'.length)] = value;
  }
  return carried;
}

/**
 * Point the proxy's Cookie header at a specific set of cookies.
 *
 * Extracted from `configureAuthContext` so the same path can be reused to
 * refresh the session mid-scan. The rule is removed and re-added rather than
 * edited, which is also how a refresh replaces a stale value.
 *
 * @param {import('axios').AxiosInstance} zapClient
 * @param {Array<{name:string,value:string}>} cookies
 */
async function applyCookieReplacerRule(zapClient, cookies) {
  const cookieString = (cookies || [])
    .map(c => `${c.name}=${c.value}`)
    .join('; ');

  // Remove any existing rule first; it may not exist yet.
  try {
    await zapClient.get('/JSON/replacer/action/removeRule/', {
      params: { description: 'auth_cookie' }
    });
  } catch (_) {
    // Nothing to remove.
  }

  // POST, so the session cookie is never part of a URL. Scanner initiators only:
  // with the default (all initiators) the rule also applies to proxy traffic, and
  // anything able to reach ZAP's port could browse the target with this session.
  await zapAuthApiWithRetry(
    () => credentialRules.zapPost(zapClient, '/JSON/replacer/action/addRule/', {
      description: credentialRules.COOKIE_RULE,
      enabled: 'true',
      matchType: 'REQ_HEADER',
      matchRegex: 'false',
      matchString: 'Cookie',
      replacement: cookieString,
      initiators: credentialRules.SCANNER_INITIATORS
    }),
    3, 1000, 'Add cookie replacer rule'
  );
}

async function configureAuthContext({ targetUrl, cookies, scanId, zapClient, basic = null }) {
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

  // HTTP Basic: one rule, exact https origin, scanner traffic only. Rule 10105 is
  // switched off first — it logs the decoded password if it ever sees Basic over
  // HTTP (the rule cannot match http://, this is the second safeguard).
  if (basic) {
    try {
      await credentialRules.setInsecureAuthRule(zapClient, false);
    } catch (err) {
      console.warn(`[ZAP-AUTH] Could not disable passive rule 10105: ${err.message}`);
    }
    try {
      await zapAuthApiWithRetry(
        () => credentialRules.applyBasicAuthRule(zapClient, { scanId, origin: basic.origin, authorization: basic.authorization }),
        3, 1000, 'Add Basic auth replacer rule'
      );
      console.log(`[ZAP-AUTH] Basic auth rule configured for ${basic.origin}`);
    } catch (err) {
      // Never fall through to an unauthenticated scan labelled as authenticated.
      console.error(`[ZAP-AUTH] Failed to configure Basic auth rule: ${err.message}`);
      throw new Error('Failed to configure authentication in ZAP');
    }
  }

  // Inject cookies via Replacer API
  if (cookies && cookies.length > 0) {
    console.log(`[ZAP-AUTH] Injecting ${cookies.length} cookies via Replacer API`);

    try {
      await applyCookieReplacerRule(zapClient, cookies);
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
async function runAuthenticatedScanBackground(targetUrl, loginUrl, cookies, scanId, userId, zapUrl, authState = null) {
  // Per-scan client pointing at this scan's dedicated container.
  // All zapAuthApi.get() calls inside this function reference this local variable.
  const zapAuthApi = createZapAuthClient(zapUrl || ZAP_AUTH_URL);

  console.log(`[ZAP-AUTH] Starting authenticated scan for user ${userId}: ${targetUrl}`);
  console.log(`[ZAP-AUTH] Scan ID: ${scanId}`);
  console.log(`[ZAP-AUTH] Login URL: ${loginUrl}`);

  let contextName = null;

  // HTTP Basic: the credential lives only in the in-memory vault, keyed by scan.
  // It is read here, used to build the Replacer rule, and never stored.
  const isBasic = Boolean(authState && authState.method === 'basic');
  const basicCred = isBasic ? credentialVault.get(scanId) : null;
  // What must never appear in stored output: the Basic credential in all its forms,
  // or — for a form-login scan — the session cookie values it injected (ZAP's
  // cookie findings can quote them in alert evidence and in the HTML report).
  const secrets = basicCred
    ? basicCred.secrets
    : [...new Set((cookies || []).map(c => c && c.value).filter(v => typeof v === 'string' && v.length >= MIN_SCRUB_LENGTH))];

  // Accumulated sign-in health across the scan. Carried into the final write
  // below, which replaces `authScanResult` wholesale.
  const authHealth = isBasic ? { authMethod: 'basic' } : {};

  // Registered synchronously, before the first await, so a stop that lands at any
  // point after startAsyncAuthScan hands over is seen by this worker.
  const worker = registerWorker(scanId, zapAuthApi);
  const assertRunning = () => {
    if (worker.stopRequested) throw new Error('STOPPED_BY_USER');
  };
  // Polling wait that a stop cuts short: the loops below sleep 1–5 s between polls,
  // and a stop must not wait out the interval (or a 2-minute passive-scan wait).
  const pause = async (ms) => {
    assertRunning();
    await new Promise(resolve => {
      const wake = () => { clearTimeout(timer); worker.wakers.delete(wake); resolve(); };
      const timer = setTimeout(wake, ms);
      worker.wakers.add(wake);
    });
    assertRunning();
  };

  const updateProgress = async (phase, progress, additionalData = {}) => {
    assertRunning();
    try {
      const currentScan = await ScanResult.findOne({ analysisId: scanId });

      // --- TERMINAL STATE CHECK: If scan was stopped/failed, EXIT BACKGROUND PROCESS ---
      if (currentScan && ['stopped', 'cancelled', 'failed'].includes(currentScan.status)) {
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
    if (isBasic && !basicCred) {
      // The vault entry is gone (process restart, or the scan was cancelled before
      // it started). Never run an unauthenticated scan labelled as authenticated.
      throw new Error('Basic credentials unavailable for this scan');
    }

    // Credential rules survive newSession, so a scan that died without cleaning
    // up would otherwise lend its credential to this one. Swept first.
    await credentialRules.purgeCredentialRules(zapAuthApi).catch(() => []);

    // Clear state left by a previous scan on this ZAP instance — see the matching
    // reset in zapService.js. Must run before configureAuthContext below, since
    // newSession discards contexts (including the auth context it creates).
    //
    // zapAuthRoutes recycles the auth container before this runs, so newSession operates
    // on a fresh empty HSQLDB. A failure is now a real signal rather than expected
    // slow-session noise — error level plus a persisted flag. Retained as a second line
    // of defence for when ZAP_RECYCLE_ENABLED=false.
    try {
      await zapAuthApi.get('/JSON/core/action/newSession/', {
        params: { name: `authscan-${scanId}`, overwrite: 'true' },
        timeout: 30000
      });
      console.log(`[ZAP-AUTH] Session reset for scan ${scanId}`);
    } catch (sessionErr) {
      console.error(
        `[ZAP-AUTH] SESSION_RESET_FAILED scanId=${scanId} status=${sessionErr.response?.status || 'none'} ` +
        `code=${sessionErr.code || 'none'} — ${sessionErr.message}`
      );
      await ScanResult.updateOne(
        { analysisId: scanId },
        { $set: { 'authScanResult.sessionResetFailed': true, updatedAt: new Date() } }
      ).catch(() => {});
    }

    // Phase 1: Configure authentication
    await updateProgress('configuring', 5, { status: 'running', message: 'Configuring authentication...' });

    const { contextId, contextName: ctxName } = await configureAuthContext({
      targetUrl,
      cookies,
      scanId,
      zapClient: zapAuthApi,
      basic: isBasic ? { origin: basicCred.origin, authorization: basicCred.authorization } : null
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

    // Also access the login URL to ensure ZAP knows the session (form login only:
    // HTTP Basic has no login page).
    if (!isBasic && loginUrl) {
      try {
        await zapAuthApi.get('/JSON/core/action/accessUrl/', {
          params: { url: loginUrl, followRedirects: 'true' }
        });
      } catch (_) {
        // Non-critical
      }
    }

    // Before crawling anything, confirm the injected session is actually being
    // honoured by the site. Crawling first and asking later is how an entire
    // scan ends up covering the logged-out view of the application.
    Object.assign(authHealth, await checkAndRepairSession({
      zapClient: zapAuthApi,
      targetUrl,
      authState,
      scanId,
      phase: 'before_spider'
    }));

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
      await pause(3000);

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
        // A cancellation (or the watchdog failing the scan) must end the worker, as
        // it does in the AJAX and active-scan loops. Swallowing it here kept a
        // cancelled scan polling for up to the spider's 2 h limit — holding the
        // auth-ZAP lock and leaving its credentials in ZAP the whole time.
        if (statusError.message === 'STOPPED_BY_USER') {
          throw statusError;
        }
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
        params: { Integer: AJAX_SPIDER_BROWSERS }
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
        await pause(5000);

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
      // The AJAX phase is best-effort, but a cancellation is not an AJAX error: this
      // catch used to swallow it, so a stop during the AJAX spider was ignored.
      if (ajaxError.message === 'STOPPED_BY_USER') throw ajaxError;
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
      await pause(1000);
      try {
        const passiveResponse = await zapAuthApi.get('/JSON/pscan/view/recordsToScan/');
        const recordsToScan = parseInt(passiveResponse.data.recordsToScan || 0);
        if (recordsToScan === 0) break;
      } catch (_) {
        break;
      }
    }

    console.log(`[ZAP-AUTH] Passive scan complete`);

    // Crawling is the phase most likely to have ended the session — it follows
    // every link it finds, and sites expire or rotate sessions under that load.
    // Check again before the long active-scan phase commits to it.
    Object.assign(authHealth, await checkAndRepairSession({
      zapClient: zapAuthApi,
      targetUrl,
      authState,
      scanId,
      phase: 'before_active_scan'
    }));

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
      await pause(5000);

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

    // Paged so a large result set can't exceed the client timeout and come back as a
    // 504 — same failure and fix as zapService.js/fetchAlertsPaged.
    const ALERT_PAGE_SIZE = 500;
    const rawAlerts = [];
    for (let start = 0; start < 10000; start += ALERT_PAGE_SIZE) {
      const alertsResponse = await zapAuthApiWithRetry(
        () => zapAuthApi.get('/JSON/core/view/alerts/', {
          params: { baseurl: targetUrl, start, count: ALERT_PAGE_SIZE }
        }),
        5, 3000, `Alerts retrieval (offset ${start})`
      );
      const page = alertsResponse.data.alerts || [];
      rawAlerts.push(...page);
      if (page.length < ALERT_PAGE_SIZE) break;
    }
    console.log(`[ZAP-AUTH] Retrieved ${rawAlerts.length} raw alerts`);

    // Generate HTML report
    const htmlReportResponse = await zapAuthApi.get('/OTHER/core/other/htmlreport/', {
      responseType: 'arraybuffer'
    });

    // HTTP Basic: did the scan reach the application or only the login prompt?
    // Judged from the status codes ZAP recorded for the target origin, because a
    // scan that only ever saw 401 still "completes" with a plausible report.
    if (isBasic) {
      const coverage = await credentialRules.measureAuthCoverage(zapAuthApi, basicCred.origin);
      authHealth.authEvidence = coverage;
      if (coverage.verdict === 'failed' || coverage.verdict === 'degraded') {
        authHealth.authDegraded = true;
        authHealth.authDegradedReason = coverage.verdict === 'failed' ? 'basic_only_unauthorized' : 'basic_mostly_unauthorized';
        if (coverage.verdict === 'failed') authHealth.authVerified = false;
      }
      console.log(`[ZAP-AUTH] Basic coverage for ${scanId}: ok=${coverage.ok} 401=${coverage.unauthorized} 403=${coverage.forbidden} verdict=${coverage.verdict}`);
    }

    // Process alerts (credentials scrubbed from alert text and raw evidence)
    const { summaryAlerts, detailedAlerts } = await createDualVersionAlerts(rawAlerts, zapAuthApi, secrets);
    console.log(`[ZAP-AUTH] Grouped into ${summaryAlerts.length} unique alert types`);

    const riskCounts = summaryAlerts.reduce((acc, alert) => {
      acc[alert.risk] = (acc[alert.risk] || 0) + 1;
      return acc;
    }, { High: 0, Medium: 0, Low: 0, Informational: 0 });

    // Store reports in GridFS
    await updateProgress('saving', 95, { message: 'Saving reports...' });

    // ZAP's HTML report quotes alert text (and so anything rule 10105 captured);
    // scrubbed of the scan's secrets before it is stored.
    const htmlBuffer = secrets.length
      ? Buffer.from(scrubText(Buffer.from(htmlReportResponse.data).toString('utf8'), secrets), 'utf8')
      : Buffer.from(htmlReportResponse.data);
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

    // This write replaces `authScanResult` wholesale, so everything recorded
    // about the sign-in has to be carried across explicitly or it is lost at
    // the exact moment the report needs it. Re-read the whole set rather than
    // naming one field, so adding a new one later cannot silently drop it.
    const priorAuth = await ScanResult.findOne({ analysisId: scanId })
      .select('authScanResult')
      .lean()
      .catch(() => null);

    const prior = (priorAuth && priorAuth.authScanResult) || {};
    const carriedAuth = {};
    for (const key of AUTH_HEALTH_KEYS) {
      if (prior[key] !== undefined) carriedAuth[key] = prior[key];
    }

    const authScanResultObj = {
      status: 'completed',
      phase: 'completed',
      progress: 100,
      authenticated: true,
      // Recorded when the scan was created, then refined while it ran.
      ...carriedAuth,
      ...authHealth,
      loginUrl: isBasic ? null : loginUrl,
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

    // Update final scan result. Conditional: a stop that landed during alert
    // processing or the uploads above must stand. Unconditionally, this write put a
    // stopped scan back to 'combining', from where it completed and was billed.
    assertRunning();
    const finalWrite = await ScanResult.updateOne(
      { analysisId: scanId, status: { $nin: TERMINAL_SCAN_STATES } },
      {
        $set: {
          status: 'combining',
          authScanResult: authScanResultObj,
          zapResult: authScanResultObj, // Copy to zapResult for compatibility
          updatedAt: new Date()
        }
      }
    );
    if (finalWrite && finalWrite.matchedCount === 0) {
      // Stopped meanwhile: the report files just stored belong to nothing.
      await Promise.allSettled([htmlFileId, detailedAlertsFileId].map(id =>
        gridfsService.deleteFile ? gridfsService.deleteFile(id, 'zap_auth_reports') : null
      ));
      throw new Error('STOPPED_BY_USER');
    }

    // Quota is NOT charged here. The scan is only in "combining" at this point —
    // geminiCompletionService charges it when the report is finished, which is the
    // single billing point for both scan flows.
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

    // Credentials are revoked in the `finally` below, on every exit path.
    return { success: true, scanId };

  } catch (error) {
    // A stop makes the ZAP calls in flight fail (scans halted, session discarded), so
    // any error after a stop request is the stop, not a scan failure.
    if (error.message === 'STOPPED_BY_USER' || worker.stopRequested) {
      console.log(`🛑 [ZAP-AUTH] Authenticated scan for ${scanId} was successfully terminated due to user cancellation.`);
      return { success: false, reason: 'stopped' };
    }

    console.error(`[ZAP-AUTH] Scan failed: ${error.message}`);

    // Update database with failure — never over a stop or a finished scan.
    try {
      const zapResultCopy = {
        status: 'failed',
        phase: 'failed',
        error: error.message,
        completedAt: new Date()
      };
      await ScanResult.updateOne(
        { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
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

    throw error;
  } finally {
    // Every exit — success, cancellation, watchdog, failure — revokes the scan's
    // credentials from ZAP. Removing the Replacer rule is not enough on its own:
    // the active scanner replays stored request headers, and the stored requests
    // stay readable through the API until the session is discarded.
    try {
      const { steps } = await credentialRules.revokeScanCredentials(zapAuthApi, {
        scanId,
        contextName,
        reEnableInsecureAuthRule: isBasic
      });
      const failed = Object.entries(steps).filter(([, ok]) => !ok).map(([name]) => name);
      if (failed.length) {
        console.warn(`[ZAP-AUTH] Credential revocation for ${scanId} incomplete: ${failed.join(', ')} (container recycle before the next scan removes the rest)`);
      } else {
        console.log(`[ZAP-AUTH] Credentials revoked from ZAP for ${scanId}`);
      }
    } finally {
      if (isBasic) credentialVault.release(scanId, 'zap');
      if (runningWorkers.get(scanId) === worker) runningWorkers.delete(scanId);
      worker.markDone();
    }
  }
}

// ============================================================================
// ASYNC SCAN ENTRY POINT
// ============================================================================

/**
 * Start an authenticated scan asynchronously. Returns immediately.
 * The actual scan runs in the background.
 */
async function startAsyncAuthScan(targetUrl, loginUrl, cookies, scanId, userId, zapUrl, onComplete, authState = null) {
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

  // Stopped (or otherwise finished) while it was provisioning or queueing for ZAP.
  // This used to set the status back to 'pending' and run the whole scan anyway —
  // after the UI had told the customer it was stopped — and then bill it.
  if (existing && TERMINAL_SCAN_STATES.includes(existing.status)) {
    console.log(`[ZAP-AUTH] Scan ${scanId} is ${existing.status} — not starting`);
    return { scanId, status: 'not_started', reason: existing.status };
  }

  // Create or update the scan result in database
  if (existing) {
    // Dotted paths, not a wholesale replacement. Both callers write the login
    // outcome into the skeleton record immediately before calling this, and
    // replacing the whole object erased it every time — leaving the report
    // unable to say whether the sign-in had been confirmed.
    //
    // Conditional, so a stop landing between the read above and this write still wins.
    const claimed = await ScanResult.updateOne(
      { analysisId: scanId, status: { $nin: TERMINAL_SCAN_STATES } },
      {
        $set: {
          status: 'pending',
          'authScanResult.status': 'running',
          'authScanResult.phase': 'queued',
          'authScanResult.progress': 0,
          'authScanResult.authenticated': true,
          'authScanResult.loginUrl': loginUrl,
          'authScanResult.urlsFound': 0,
          'authScanResult.alerts': [],
          'authScanResult.startedAt': new Date(),
          updatedAt: new Date()
        }
      }
    );
    if (claimed && claimed.matchedCount === 0) {
      console.log(`[ZAP-AUTH] Scan ${scanId} was stopped before it started — not starting`);
      return { scanId, status: 'not_started', reason: 'stopped' };
    }
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
        // No skeleton existed, so record the login outcome here instead.
        loginOutcome: authState && authState.marker ? 'confirmed' : 'unconfirmed',
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
  runAuthenticatedScanBackground(targetUrl, loginUrl, cookies, scanId, userId, zapUrl, authState)
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

// How long a stop waits for the worker to finish revoking credentials and hand the
// ZAP instance back. Beyond this the stop still holds: the worker exits at its next
// check and the revocation runs in its `finally`.
const STOP_WORKER_WAIT_MS = () => Number(process.env.ZAP_AUTH_STOP_WAIT_MS) || 20000;

/**
 * Stop an authenticated scan, whatever stage it is in.
 *
 * Order matters:
 *   1. Mark the scan stopped — atomically and conditionally. This is the claim (a
 *      repeat click or a second tab finds it already stopped and does nothing), and it
 *      is what every start path checks, so a scan still provisioning or queueing for
 *      ZAP can no longer start (startAsyncAuthScan, withZapInstance's isCancelled).
 *   2. Drop the Basic credential, so nothing can use it from here on.
 *   3. Halt the fast scanners (in-house browser checks, WebCheck).
 *   4. If this scan's ZAP worker runs here: wake it, halt ITS ZAP at once, and wait for
 *      it to revoke credentials (stop scans → remove rules → newSession) and release
 *      the instance lock — so when this returns, ZAP is clean and free for the next
 *      scan. A scan with no running worker sends nothing to ZAP: the auth ZAP is
 *      shared, and whatever it is doing belongs to another scan.
 *
 * Nothing is charged: quota is only charged when a report completes, and the
 * completion service refuses a stopped scan.
 */
async function stopAuthScan(scanId, userId, { waitMs = STOP_WORKER_WAIT_MS() } = {}) {
  const scanResult = await ScanResult.findOne({
    analysisId: scanId,
    userId
  });

  if (!scanResult) {
    throw new Error('Scan not found or access denied');
  }

  const stoppedAt = new Date();
  const claim = await ScanResult.updateOne(
    { analysisId: scanId, userId, status: { $nin: TERMINAL_SCAN_STATES } },
    {
      $set: {
        status: 'stopped',
        'authScanResult.status': 'stopped',
        'authScanResult.phase': 'stopped',
        'authScanResult.completedAt': stoppedAt,
        stoppedAt,
        updatedAt: stoppedAt
      }
    }
  );
  if (!claim || claim.matchedCount === 0) {
    // Already finished, or another request stopped it first. Still make sure no
    // credential lingers — purge is idempotent.
    credentialVault.purge(scanId);
    const current = await ScanResult.findOne({ analysisId: scanId }).select('status').lean().catch(() => null);
    return {
      success: true,
      alreadyStopped: true,
      status: (current && current.status) || scanResult.status,
      message: 'Scan already in a terminal state'
    };
  }
  console.log(`🛑 [ZAP-AUTH] Stopping authenticated scan ${scanId} (was ${scanResult.status})`);

  // The credential is dropped at once; the worker revokes it from ZAP on exit.
  credentialVault.purge(scanId);

  // Fast scanners. Lazily required: both modules are heavier than this path needs at load.
  let fastScansStopped = false;
  let webCheckStopped = false;
  try {
    fastScansStopped = require('./authFastScanService').stopAuthFastScans(scanId);
  } catch (err) {
    console.warn(`[ZAP-AUTH] Could not halt fast scanners for ${scanId}: ${err.message}`);
  }
  try {
    webCheckStopped = require('./webCheckService').stopWebCheckScan(scanId);
  } catch (err) {
    console.warn(`[ZAP-AUTH] Could not halt WebCheck for ${scanId}: ${err.message}`);
  }

  // The ZAP leg.
  const worker = signalWorkerStop(scanId);
  let workerStopped = !worker;
  if (worker) {
    // Halt the attack traffic now, on this scan's own ZAP, rather than when the worker
    // next gets control — it may be inside a long ZAP call (alerts, report, accessUrl).
    const halt = { timeout: 10000 };
    await Promise.allSettled([
      worker.client.get('/JSON/ascan/action/stopAllScans/', halt),
      worker.client.get('/JSON/spider/action/stopAllScans/', halt),
      worker.client.get('/JSON/ajaxSpider/action/stop/', halt)
    ]);
    let timer;
    workerStopped = await Promise.race([
      worker.done.then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), waitMs); })
    ]);
    clearTimeout(timer);
    if (!workerStopped) {
      console.warn(`[ZAP-AUTH] Worker for ${scanId} still unwinding after ${waitMs}ms — it exits at its next check`);
    }
  } else {
    // Provisioning, queueing for the lock, or running in another process: the start
    // paths see the stopped status and give the instance up without scanning.
    try {
      const { releaseContainer } = require('./zapContainerManager');
      await releaseContainer(scanId);
    } catch (err) {
      console.warn(`[zapAuthService] Failed to release container for ${scanId}:`, err.message);
    }
  }

  // Other tabs watching this scan.
  try {
    const { publishScanProgress } = require('./scanProgressService');
    publishScanProgress(scanId, userId, { status: 'stopped', scanId, analysisId: scanId }).catch(() => {});
  } catch (_) {}

  console.log(`✅ [ZAP-AUTH] Scan ${scanId} stopped (worker=${worker ? (workerStopped ? 'exited' : 'unwinding') : 'none'} fast=${fastScansStopped} webcheck=${webCheckStopped})`);
  return {
    success: true,
    message: 'Authenticated scan stopped',
    scanId,
    workerStopped,
    fastScansStopped,
    webCheckStopped
  };
}

module.exports = {
  checkZapAuthHealth,
  configureAuthContext,
  applyCookieReplacerRule,
  verifySignedIn,
  checkAndRepairSession,
  startAsyncAuthScan,
  getAuthScanStatus,
  stopAuthScan,
  isAuthScanCancelled,
  runAuthenticatedScanBackground,
  // Exposed for tests.
  _runningWorkers: runningWorkers,
  _createDualVersionAlerts: createDualVersionAlerts,
  _fetchZapMessage: fetchZapMessage,
  _createZapAuthClient: createZapAuthClient
};
