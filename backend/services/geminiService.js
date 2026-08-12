const { GoogleGenAI } = require('@google/genai');
const fs = require('fs');
const {
  sanitizeRefinedReportForLLM,
  sanitizeHistoryRowsForLLM,
  sanitizeTextsForLLM,
  assertNoLeakage,
} = require('./geminiSanitizer');
const { lighthouseScores, formatScore, formatMetric } = require('../utils/scoreFormat');

// gemini-2.5-pro  → deep analysis, final reports, vulnerability reasoning
// gemini-2.5-flash → formatting, translation, summaries (lower latency / cost)
const MODEL_PRO   = process.env.GEMINI_MODEL_PRO   || 'gemini-2.5-pro';
const MODEL_FLASH = process.env.GEMINI_MODEL_FLASH  || 'gemini-2.5-flash';

const VERTEX_PROJECT  = process.env.VERTEX_PROJECT  || process.env.GOOGLE_CLOUD_PROJECT || 'fortexa-495604';
const VERTEX_LOCATION = process.env.VERTEX_LOCATION || 'us-central1';

// Hard deadline per generateContent call, by model tier.
// gemini-2.5-pro can take 60-120s for a full security report on complex sites.
// gemini-2.5-flash is typically under 30s; 90s is a generous safety margin.
// Both are well above the WIF auth overhead (~1s after token is cached).
const GEMINI_CALL_TIMEOUT_PRO_MS   = 150_000; // 2.5 min — deep analysis model
const GEMINI_CALL_TIMEOUT_FLASH_MS =  90_000; // 1.5 min — fast model

// ECS Fargate always injects ECS_CONTAINER_METADATA_URI_V4. Use it to distinguish
// production (Vertex AI + WIF) from local development (API key or ambient ADC).
const IS_ECS = !!process.env.ECS_CONTAINER_METADATA_URI_V4;

// ─── Startup diagnostics ────────────────────────────────────────────────────────
// Logged at module load time so CloudWatch shows the auth decision immediately on
// container start — before any request comes in.
console.log('[Gemini] ── Startup diagnostics ─────────────────────────────');
console.log(`[Gemini]   NODE_ENV                     = ${process.env.NODE_ENV || '(not set)'}`);
console.log(`[Gemini]   IS_ECS (ECS_CONTAINER_METADATA_URI_V4 present) = ${IS_ECS}`);
console.log(`[Gemini]   ECS_CONTAINER_METADATA_URI_V4 = ${process.env.ECS_CONTAINER_METADATA_URI_V4 ? process.env.ECS_CONTAINER_METADATA_URI_V4.slice(0, 40) + '…' : '(not set)'}`);
console.log(`[Gemini]   GEMINI_API_KEY present        = ${!!process.env.GEMINI_API_KEY} ${process.env.GEMINI_API_KEY ? '(key starts: ' + process.env.GEMINI_API_KEY.slice(0, 8) + '…)' : ''}`);
console.log(`[Gemini]   GOOGLE_API_KEY present        = ${!!process.env.GOOGLE_API_KEY}`);
console.log(`[Gemini]   GOOGLE_APPLICATION_CREDENTIALS= ${process.env.GOOGLE_APPLICATION_CREDENTIALS || '(not set)'}`);
console.log(`[Gemini]   VERTEX_PROJECT               = ${VERTEX_PROJECT}`);
console.log(`[Gemini]   VERTEX_LOCATION              = ${VERTEX_LOCATION}`);
console.log(`[Gemini]   GEMINI_MODEL_PRO             = ${MODEL_PRO}`);
console.log(`[Gemini]   GEMINI_MODEL_FLASH           = ${MODEL_FLASH}`);
console.log(`[Gemini]   AWS_REGION                   = ${process.env.AWS_REGION || '(not set)'}`);
console.log(`[Gemini]   AWS_EC2_METADATA_DISABLED    = ${process.env.AWS_EC2_METADATA_DISABLED || '(not set)'}`);
console.log(`[Gemini]   AWS_CONTAINER_CREDENTIALS_RELATIVE_URI present = ${!!process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}`);
console.log('[Gemini] ──────────────────────────────────────────────────────');

// Warn if SDK env-var sniffing could override the auth client we construct below.
// @google/genai v1.x reads GOOGLE_API_KEY from env as a fallback even when you pass
// { vertexai: true } — if this variable is present in ECS, it will silently use AI
// Studio (generativelanguage.googleapis.com) instead of Vertex AI.
if (IS_ECS && process.env.GOOGLE_API_KEY) {
  console.error('[Gemini] ❌ GOOGLE_API_KEY is set in the ECS environment. The @google/genai SDK will use this');
  console.error('[Gemini]    to call generativelanguage.googleapis.com (AI Studio) instead of Vertex AI.');
  console.error('[Gemini]    Remove GOOGLE_API_KEY from the ECS task definition or Secrets Manager.');
}
if (IS_ECS && process.env.GEMINI_API_KEY) {
  console.error('[Gemini] ❌ GEMINI_API_KEY is set in the ECS environment. This will override the WIF auth client.');
  console.error('[Gemini]    Remove GEMINI_API_KEY from the ECS task definition or Secrets Manager immediately.');
}

// Client initialisation — three modes:
//   ECS:         Vertex AI + Workload Identity Federation via programmatic AwsClient
//                (fetches credentials from the ECS container endpoint, not EC2 IMDS)
//   Local-Key:   AI Studio with GEMINI_API_KEY (if set and valid)
//   Local-ADC:   Vertex AI with ambient ADC (gcloud auth application-default login)
//
// AI Studio API keys always start with "AIza". If the key is present but has the wrong
// format (e.g. an OAuth token was accidentally pasted), fall through to Vertex AI mode
// rather than making every Gemini call fail silently with an auth error.

// Exported so other modules can include the auth mode in their own log lines.
let GEMINI_AUTH_MODE;
let ai;
let _wifAuthClient = null; // holds the AwsClient on ECS so verifyCredentials() tests the same path

if (!IS_ECS && process.env.GEMINI_API_KEY) {
  const _rawKey = process.env.GEMINI_API_KEY;
  if (_rawKey.startsWith('AIza') || _rawKey.startsWith('AQ')) {
    GEMINI_AUTH_MODE = 'AI_STUDIO';
    ai = new GoogleGenAI({ apiKey: _rawKey });
    console.log(`[Gemini] AUTH_MODE=AI_STUDIO (local dev, GEMINI_API_KEY) endpoint=generativelanguage.googleapis.com`);
    console.log(`[Gemini]   pro=${MODEL_PRO}  flash=${MODEL_FLASH}`);
  } else {
    GEMINI_AUTH_MODE = 'VERTEX_ADC';
    console.error(`[Gemini] ❌ GEMINI_API_KEY is set but format is invalid (must start with "AIza" or "AQ"). Got: "${_rawKey.slice(0, 12)}…"`);
    console.error(`[Gemini]    Falling back to Vertex AI / ambient ADC.`);
    ai = new GoogleGenAI({ vertexai: true, project: VERTEX_PROJECT, location: VERTEX_LOCATION });
    console.log(`[Gemini] AUTH_MODE=VERTEX_ADC (fallback — invalid API key) endpoint=${VERTEX_LOCATION}-aiplatform.googleapis.com`);
    console.log(`[Gemini]   project=${VERTEX_PROJECT}  location=${VERTEX_LOCATION}`);
  }
} else if (IS_ECS) {
  GEMINI_AUTH_MODE = 'VERTEX_WIF';
  const { AwsClient } = require('google-auth-library');
  const _wifFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;

  // Validate the WIF config file exists and has the required fields before constructing
  // AwsClient — a missing file causes a synchronous crash; missing fields cause silent
  // WIF failures that only surface at the first API call.
  let _wifConfig = {};
  if (!_wifFile) {
    console.error('[Gemini] ❌ GOOGLE_APPLICATION_CREDENTIALS is not set — WIF cannot initialise.');
  } else if (!fs.existsSync(_wifFile)) {
    console.error(`[Gemini] ❌ WIF config file not found: ${_wifFile}`);
    console.error('[Gemini]    Ensure backend/config/gcp-wif.json is present in the Docker image.');
    console.error('[Gemini]    The file is intentionally committed to git — check that it was not .gitignored.');
  } else {
    try {
      _wifConfig = JSON.parse(fs.readFileSync(_wifFile, 'utf8'));
      const required = ['type', 'audience', 'subject_token_type', 'token_url', 'service_account_impersonation_url'];
      const missing  = required.filter(k => !_wifConfig[k]);
      if (missing.length) {
        console.error(`[Gemini] ❌ WIF config is missing required fields: ${missing.join(', ')}`);
      } else {
        console.log(`[Gemini] ✅ WIF config loaded — audience=${_wifConfig.audience}`);
        console.log(`[Gemini]    token_url=${_wifConfig.token_url}`);
        console.log(`[Gemini]    impersonation_url=${_wifConfig.service_account_impersonation_url}`);
      }
    } catch (parseErr) {
      console.error(`[Gemini] ❌ Failed to parse WIF config file: ${parseErr.message}`);
    }
  }

  const _ecsCredentialSupplier = {
    getAwsRegion: async () => {
      const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
      if (!region) throw new Error('[WIF] AWS_REGION is not set in the ECS task environment');
      return region;
    },
    getAwsSecurityCredentials: async () => {
      const relUri = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;
      if (!relUri) throw new Error('[WIF] AWS_CONTAINER_CREDENTIALS_RELATIVE_URI not set — task must have a task IAM role');
      const resp = await fetch(`http://169.254.170.2${relUri}`);
      if (!resp.ok) throw new Error(`[WIF] ECS credentials endpoint returned HTTP ${resp.status}`);
      const creds = await resp.json();
      return { accessKeyId: creds.AccessKeyId, secretAccessKey: creds.SecretAccessKey, token: creds.Token };
    },
  };

  // Do NOT spread the full _wifConfig — AwsClient throws if both credential_source
  // AND aws_security_credentials_supplier are present. Pick only the WIF exchange fields.
  _wifAuthClient = new AwsClient({
    type:                              _wifConfig.type,
    audience:                          _wifConfig.audience,
    subject_token_type:                _wifConfig.subject_token_type,
    token_url:                         _wifConfig.token_url,
    service_account_impersonation_url: _wifConfig.service_account_impersonation_url,
    universe_domain:                   _wifConfig.universe_domain,
    aws_security_credentials_supplier: _ecsCredentialSupplier,
    scopes: ['https://www.googleapis.com/auth/cloud-platform'],
  });

  ai = new GoogleGenAI({
    vertexai: true,
    project: VERTEX_PROJECT,
    location: VERTEX_LOCATION,
    googleAuthOptions: { authClient: _wifAuthClient },
  });
  console.log(`[Gemini] AUTH_MODE=VERTEX_WIF (ECS WIF programmatic) endpoint=${VERTEX_LOCATION}-aiplatform.googleapis.com`);
  console.log(`[Gemini]   project=${VERTEX_PROJECT}  location=${VERTEX_LOCATION}`);
  console.log(`[Gemini]   pro=${MODEL_PRO}  flash=${MODEL_FLASH}`);
  console.log(`[Gemini]   AWS_REGION=${process.env.AWS_REGION || '(not set)'}`);
  console.log(`[Gemini]   AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=${process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '(not set — credentials will fail)'}`);
} else {
  GEMINI_AUTH_MODE = 'VERTEX_ADC';
  // Local dev: ambient ADC (gcloud auth application-default login) or GOOGLE_APPLICATION_CREDENTIALS
  ai = new GoogleGenAI({ vertexai: true, project: VERTEX_PROJECT, location: VERTEX_LOCATION });
  console.log(`[Gemini] AUTH_MODE=VERTEX_ADC (local ADC) endpoint=${VERTEX_LOCATION}-aiplatform.googleapis.com`);
  console.log(`[Gemini]   project=${VERTEX_PROJECT}  location=${VERTEX_LOCATION}`);
  console.log(`[Gemini]   ADC source: GOOGLE_APPLICATION_CREDENTIALS=${process.env.GOOGLE_APPLICATION_CREDENTIALS || '(not set — using ambient ADC)'}`);
}

/**
 * Verify credentials are reachable at startup (non-blocking, informational only).
 *
 * On ECS this tests the actual AwsClient (WIF programmatic path) — the same client
 * that ai.models.generateContent() uses. It does NOT use GoogleAuth / ADC.
 * On local dev (no _wifAuthClient) it uses GoogleAuth with ambient ADC.
 */
async function verifyCredentials() {
  if (GEMINI_AUTH_MODE === 'AI_STUDIO') {
    console.log(`[Gemini] ✅ API Key verification bypassed (AUTH_MODE=AI_STUDIO)`);
    return true;
  }

  try {
    let tokenResult;
    if (_wifAuthClient) {
      // ECS: test through the exact same AwsClient that the ai instance uses
      tokenResult = await Promise.race([
        _wifAuthClient.getAccessToken(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('token fetch timed out after 30s')), 30_000)),
      ]);
    } else {
      // Local dev: test ambient ADC
      const { GoogleAuth } = require('google-auth-library');
      const auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform'] });
      const client = await auth.getClient();
      tokenResult = await Promise.race([
        client.getAccessToken(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('token fetch timed out after 30s')), 30_000)),
      ]);
    }
    const hint = tokenResult?.token ? `token starts with ${String(tokenResult.token).slice(0, 12)}…` : 'no token';
    const label = _wifAuthClient ? 'WIF credential verification' : 'ADC credential verification';
    console.log(`[Gemini] ✅ ${label} passed (AUTH_MODE=${GEMINI_AUTH_MODE}) — ${hint}`);
    return true;
  } catch (err) {
    const label = _wifAuthClient ? 'WIF credential verification' : 'ADC credential verification';
    console.error(`[Gemini] ❌ ${label} FAILED (AUTH_MODE=${GEMINI_AUTH_MODE}): ${err.message}`);
    console.error('[Gemini]    This will cause all Gemini calls to fail.');
    console.error('[Gemini]    Check: WIF config fields, task IAM role, GCP service account binding, ECS credentials endpoint.');
    return false;
  }
}

// Always run credential check — on ECS this validates WIF, on local dev it validates ADC.
// Errors are non-fatal at startup but will cause every Gemini call to fail.
verifyCredentials().catch(() => {});

/**
 * Call Gemini with automatic retry on transient errors (503, overloaded, network).
 * Each call is raced against a model-appropriate timeout to prevent ADC/WIF auth hangs.
 * Auth errors and bad-request errors are surfaced immediately (no retry).
 * @param {string} prompt
 * @param {string} model   - MODEL_PRO or MODEL_FLASH
 * @param {string} caller  - human-readable label for the calling service (appears in logs)
 */
async function _generate(prompt, model, caller = 'unknown', opts = {}) {
  // Centralized pre-flight guardrail — every Gemini call goes through here, so
  // one check covers all callers (refineReport, PDF formatters, translators).
  assertNoLeakage(prompt, caller);
  const tag = `[Gemini/${model}/${caller}][auth=${GEMINI_AUTH_MODE}]`;
  const MAX_RETRIES = opts.maxRetries ?? 5;
  const timeoutMs = opts.timeoutMs ?? (model === MODEL_PRO ? GEMINI_CALL_TIMEOUT_PRO_MS : GEMINI_CALL_TIMEOUT_FLASH_MS);
  const maxBackoffMs = opts.maxBackoffMs ?? 90_000;
  let lastError;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      // Exponential backoff with full jitter: base 10s, cap maxBackoffMs.
      // 503 UNAVAILABLE = Gemini under high demand; needs longer wait than a simple linear ramp.
      const base = Math.min(10000 * Math.pow(2, attempt - 1), maxBackoffMs);
      const delay = Math.floor(base * (0.5 + Math.random() * 0.5)); // 50–100% of base
      console.log(`${tag} Retry ${attempt}/${MAX_RETRIES - 1} in ${(delay / 1000).toFixed(1)}s… (backoff attempt ${attempt})`);
      await new Promise(r => setTimeout(r, delay));
    }
    try {
      console.log(`${tag} generateContent attempt ${attempt + 1}/${MAX_RETRIES} — timeout=${timeoutMs / 1000}s`);

      let timeoutHandle;
      const timeoutPromise = new Promise((_, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new Error(`Gemini call timed out after ${timeoutMs / 1000}s (possible ADC/WIF auth hang)`)),
          timeoutMs
        );
      });

      const callPromise = ai.models.generateContent({ model, contents: prompt });

      let response;
      try {
        response = await Promise.race([callPromise, timeoutPromise]);
      } finally {
        clearTimeout(timeoutHandle);
      }

      console.log(`${tag} generateContent succeeded on attempt ${attempt + 1}`);
      return response.text;
    } catch (err) {
      lastError = err;

      // Auth errors are permanent — fail fast with a clear message.
      const isAuthError =
        err.message?.includes('401')              ||
        err.message?.includes('403')              ||
        err.message?.includes('API_KEY_INVALID')  ||
        err.message?.includes('UNAUTHENTICATED')  ||
        err.message?.includes('PERMISSION_DENIED')||
        err.message?.includes('Invalid API key')  ||
        err.message?.includes('API key not valid')||
        err.message?.includes('invalid_grant')    ||
        err.code === 'GEMINI_AUTH_FAILED';
      if (isAuthError) {
        const authErr = new Error(
          `Gemini authentication failed (AUTH_MODE=${GEMINI_AUTH_MODE}) — check WIF config or ADC credentials. Original: ${err.message}`
        );
        authErr.code = 'GEMINI_AUTH_FAILED';
        console.error(`${tag} Auth error on attempt ${attempt + 1} — not retrying:`, err.message);
        throw authErr;
      }

      // Quota / rate-limit errors: fail fast — retrying on the same model won't help.
      // Callers should switch to the Flash model instead.
      const isQuotaError =
        err.message?.includes('RESOURCE_EXHAUSTED') ||
        err.message?.includes('Quota exceeded')     ||
        err.message?.includes('quota exceeded')     ||
        err.message?.includes('rate limit')         ||
        err.message?.includes('Rate limit exceeded')||
        err.message?.includes('too many requests')  ||
        err.message?.includes('Too many requests')  ||
        err.message?.includes('429');
      if (isQuotaError) {
        const quotaErr = new Error(`Gemini ${model} quota exhausted: ${err.message}`);
        quotaErr.code = 'GEMINI_QUOTA_EXHAUSTED';
        quotaErr.model = model;
        console.warn(`${tag} Quota exhausted — not retrying, caller should switch models`);
        throw quotaErr;
      }

      const isTransient =
        err.message?.includes('503')           ||
        err.message?.includes('overloaded')    ||
        err.message?.includes('UNAVAILABLE')   ||
        err.message?.includes('fetch failed')  ||
        err.message?.includes('ETIMEDOUT')     ||
        err.message?.includes('ECONNRESET')    ||
        err.message?.includes('network')       ||
        err.message?.includes('timed out');    // our own timeout above is retryable
      if (!isTransient) {
        console.error(`${tag} Non-transient error on attempt ${attempt + 1} — not retrying:`, err.message);
        throw err;
      }
      console.warn(`${tag} Transient error (attempt ${attempt + 1}):`, err.message);
    }
  }
  throw lastError;
}

/** Returns true for quota / rate-limit failures from _generate(). */
function _isQuotaError(err) {
  return err?.code === 'GEMINI_QUOTA_EXHAUSTED' || err?.code === 'GEMINI_KEY_EXHAUSTED';
}

/**
 * Try MODEL_PRO; on quota exhaustion switch immediately to MODEL_FLASH.
 * On any other Pro failure also falls back to Flash.
 * Throws only if Flash fails too.
 * @param {string} prompt
 * @param {string} caller - label passed through to _generate for log tagging
 */
async function _generateWithFallback(prompt, caller = 'unknown', opts = {}) {
  try {
    const result = await _generate(prompt, MODEL_PRO, caller, opts);
    return result;
  } catch (proErr) {
    if (_isQuotaError(proErr)) {
      console.warn(`[Gemini/${caller}] Pro quota exhausted, switching to Flash`);
    } else {
      console.warn(`[Gemini/${caller}] Pro model failed (${proErr.message}), falling back to Flash…`);
    }
    const result = await _generate(prompt, MODEL_FLASH, caller, opts);
    console.log(`[Gemini/${caller}] Flash model succeeded`);
    return result;
  }
}

/** Parse JSON from a Gemini response, stripping accidental markdown fences. */
function _parseJson(text) {
  const cleaned = text.trim()
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i,     '')
    .replace(/\s*```$/i,     '')
    .trim();
  return JSON.parse(cleaned);
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Generate the main AI security report from all scanner results.
 */
async function refineReport(_unused, psiReport, observatoryReport, url, zapReport = null, urlscanReport = null, webCheckReport = null) {
  const lighthouseResult  = psiReport?.lighthouseResult || {};
  const categories        = lighthouseResult.categories || {};
  const performanceScore  = categories.performance?.score        ? Math.round(categories.performance.score        * 100) : 'N/A';
  const accessibilityScore= categories.accessibility?.score      ? Math.round(categories.accessibility.score      * 100) : 'N/A';
  const bestPracticesScore= categories['best-practices']?.score  ? Math.round(categories['best-practices'].score  * 100) : 'N/A';
  const seoScore          = categories.seo?.score                ? Math.round(categories.seo.score                * 100) : 'N/A';

  const observatoryGrade       = observatoryReport?.grade          || 'N/A';
  const observatoryScore       = observatoryReport?.score          || 'N/A';
  const observatoryTestsPassed = observatoryReport?.tests_passed   || 0;
  const observatoryTestsFailed = observatoryReport?.tests_failed   || 0;
  const observatoryTestsTotal  = observatoryReport?.tests_quantity || 0;
  const hasObservatoryData     = observatoryReport && !observatoryReport.error;

  const hasZapData    = zapReport && !zapReport.error && zapReport.alerts;
  const zapRiskCounts = zapReport?.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 };
  const zapAlertCount = zapReport?.alerts?.length || 0;
  const zapHighRisk   = zapReport?.alerts?.filter(a => a.risk === 'High')   || [];
  const zapMediumRisk = zapReport?.alerts?.filter(a => a.risk === 'Medium') || [];

  const hasUrlscanData    = urlscanReport && !urlscanReport.error && urlscanReport.verdicts;
  const urlscanVerdicts   = urlscanReport?.verdicts || {};
  const urlscanPage       = urlscanReport?.page     || {};
  const urlscanStats      = urlscanReport?.stats    || {};
  const urlscanIsMalicious= urlscanVerdicts?.overall?.malicious || false;
  const urlscanScore      = urlscanVerdicts?.overall?.score     || 0;

  const hasWebCheckData   = webCheckReport && Object.keys(webCheckReport).length > 0;
  const webCheckHeaders   = webCheckReport?.headers        || {};
  const webCheckTls       = webCheckReport?.tls            || webCheckReport?.ssl || {};
  const webCheckTechStack = webCheckReport?.['tech-stack'] || {};
  const webCheckFirewall  = webCheckReport?.firewall       || {};
  const webCheckDns       = webCheckReport?.dns            || {};
  const webCheckHsts      = webCheckReport?.hsts           || {};
  const webCheckSecurityTxt= webCheckReport?.['security-txt'] || {};
  const webCheckRobotsTxt = webCheckReport?.['robots-txt'] || {};
  const webCheckCookies   = webCheckReport?.cookies        || {};
  const webCheckCarbon    = webCheckReport?.carbon         || {};
  const webCheckQuality   = webCheckReport?.quality        || {};

  // NOTE: url is always "REDACTED" when called correctly via sanitizeScanForLLM().
  // The prompt header deliberately omits the live URL to prevent identity leakage.
  const prompt = `You are a cybersecurity and web performance expert. Analyze the following security scan reports for a web target.

Performance Analysis Report:
- Performance Score: ${performanceScore}/100
- Accessibility Score: ${accessibilityScore}/100
- Best Practices Score: ${bestPracticesScore}/100
- SEO Score: ${seoScore}/100

${hasObservatoryData ? `Security Configuration Analysis:
- Security Grade: ${observatoryGrade}
- Security Score: ${observatoryScore}/100
- Tests Passed: ${observatoryTestsPassed}
- Tests Failed: ${observatoryTestsFailed}
- Total Tests: ${observatoryTestsTotal}` : 'Security Configuration Analysis: Not available for this scan'}

${hasZapData ? `Vulnerability Scan Report:
- Total Alerts: ${zapAlertCount}
- High Risk Vulnerabilities: ${zapRiskCounts.High}
- Medium Risk Vulnerabilities: ${zapRiskCounts.Medium}
- Low Risk Vulnerabilities: ${zapRiskCounts.Low}
- Informational: ${zapRiskCounts.Informational}
${zapHighRisk.length   > 0 ? `- High Risk Issues: ${zapHighRisk.slice(0, 5).map(a => a.alert).join(', ')}`   : ''}
${zapMediumRisk.length > 0 ? `- Medium Risk Issues: ${zapMediumRisk.slice(0, 5).map(a => a.alert).join(', ')}` : ''}` : 'Vulnerability Scan: Not available or still in progress'}

${hasUrlscanData ? `Threat & Reputation Analysis:
- Malicious Verdict: ${urlscanIsMalicious ? 'YES - MALICIOUS' : 'No - Clean'}
- Threat Score: ${urlscanScore}/100
- Domain: ${urlscanPage.domain || 'N/A'}
- Server IP: ${urlscanPage.ip || 'N/A'}
- Country: ${urlscanPage.country || 'N/A'}
- Server: ${urlscanPage.server || 'N/A'}
- TLS Issuer: ${urlscanPage.tlsIssuer || 'N/A'}
- Unique IPs: ${urlscanStats.uniqIPs || 0}
- Total Requests: ${urlscanStats.requests || 0}` : 'Threat & Reputation Analysis: Not available or still in progress'}

${hasWebCheckData ? `Web Security Configuration Report:
- Security Headers: ${JSON.stringify(webCheckHeaders?.headers || webCheckHeaders || 'N/A')}
- TLS/SSL Configuration: ${webCheckTls?.grade || webCheckTls?.valid ? `Grade: ${webCheckTls.grade || 'Valid'}, Protocol: ${webCheckTls.protocol || 'N/A'}, Cipher: ${webCheckTls.cipher || 'N/A'}` : 'N/A'}
- Technology Stack: ${Array.isArray(webCheckTechStack?.technologies) ? webCheckTechStack.technologies.map(t => t.name || t).join(', ') : 'N/A'}
- Firewall/WAF Detection: ${webCheckFirewall?.hasWaf ? `Detected: ${webCheckFirewall.waf || 'Yes'}` : 'No WAF detected'}
- HSTS Status: ${webCheckHsts?.enabled ? `Enabled (max-age: ${webCheckHsts.maxAge || 'N/A'})` : 'Not enabled'}
- DNS Configuration: ${webCheckDns?.a ? `A Records: ${webCheckDns.a.join(', ')}` : 'N/A'}
- Security.txt: ${webCheckSecurityTxt?.present ? 'Present' : 'Not found'}
- Robots.txt: ${webCheckRobotsTxt?.present ? 'Present' : 'Not found'}
- Cookies: ${Array.isArray(webCheckCookies) ? `${webCheckCookies.length} cookies found` : 'N/A'}
- Carbon Footprint: ${webCheckCarbon?.co2 ? `${webCheckCarbon.co2}g CO2 per visit` : 'N/A'}
- Code Quality Score: ${webCheckQuality?.score || 'N/A'}` : 'Web Security Configuration: Not available or still in progress'}

Task:
Generate a comprehensive, professional analysis report that includes:

1. Executive Summary (2-3 sentences): Overall assessment of the URL's security and performance.

2. Security Analysis:
   - Risk level (Low/Medium/High) based on vulnerability scan and threat analysis results
   - Security configuration grade and assessment (if available)
   - Vulnerability findings and their severity (if available)
   - Threat detection and reputation analysis (if available)
   - Security headers, TLS/SSL grade, WAF detection, HSTS status (if available)
   - Key security findings and threats detected (if any)
   - Specific concerns or red flags from all scan sources

3. Infrastructure Analysis (if available):
   - Technology stack and frameworks detected
   - DNS configuration assessment
   - Cookie security analysis
   - Security.txt and robots.txt presence

4. Performance Analysis:
   - Overall performance rating
   - Key performance metrics and their implications
   - Accessibility and SEO considerations
   - Environmental impact (carbon footprint if available)

5. Conclusion: Final verdict on whether the URL is safe to use and performs well.

6. Actionable Recommendations:
   - Security improvements (if needed) - include malware protection, security header configuration, vulnerability remediation, TLS improvements, and HSTS implementation
   - Performance optimizations
   - Best practices to implement

IMPORTANT FORMATTING INSTRUCTIONS:
- Use simple text formatting with headers (use # for headers) and bullet points (use - for lists)
- DO NOT use double asterisks for bolding any terms within headers or list items
- DO NOT wrap the entire response in markdown code blocks (do not use triple backticks)
- Keep the report concise, professional, and actionable
- Focus on practical insights rather than raw data
- Do NOT mention the names of any specific third-party tools or services used to collect the data
- Ensure ALL scores (Performance, Accessibility, Best Practices, SEO, Security Grade, vulnerability counts, and web security configuration findings if available) are mentioned in the analysis`;

  let report;
  try {
    report = await _generate(prompt, MODEL_PRO, 'refineReport');
    console.log('✅ [Gemini] AI security report generated (pro)');
  } catch (proErr) {
    if (_isQuotaError(proErr)) {
      console.warn('[Gemini/refineReport] Pro quota exhausted, switching to Flash');
    } else {
      console.warn(`[Gemini/refineReport] Pro model failed (${proErr.message}), falling back to Flash…`);
    }
    report = await _generate(prompt, MODEL_FLASH, 'refineReport');
    console.log('[Gemini/refineReport] Flash report generated successfully');
  }
  return report;
}

/**
 * Translate an array of texts using Gemini AI (JSON key-mapping for reliable 1:1 output).
 */
async function translateText(texts, targetLang) {
  if (!texts || texts.length === 0) return [];

  const langName  = targetLang === 'ja' ? 'Japanese' : 'English';
  const sourceLang= targetLang === 'ja' ? 'English'  : 'Japanese';

  // Sanitize texts to strip URLs / IPs before sending to Gemini (M-07)
  const safeTexts = sanitizeTextsForLLM(texts);

  const inputObj = {};
  safeTexts.forEach((t, i) => { inputObj[i] = t; });

  const prompt = `Translate the following texts from ${sourceLang} to ${langName}.

INPUT (JSON object with numeric keys):
${JSON.stringify(inputObj, null, 2)}

CRITICAL RULES:
1. Return ONLY a valid JSON object
2. Use the SAME numeric keys as the input
3. Each value should be the translation of the corresponding input value
4. Preserve emojis and special characters
5. Do NOT add any text before or after the JSON

OUTPUT (JSON object only):`;

  const raw = await _generate(prompt, MODEL_FLASH, 'translateText');
  const translatedObj = _parseJson(raw);

  return texts.map((orig, i) => {
    const v = translatedObj[i] ?? translatedObj[String(i)];
    if (v !== undefined) return String(v);
    console.warn(`[Gemini] Missing translation for index ${i}, using original`);
    return orig;
  });
}

/**
 * Format a markdown report into clean plain text for PDF generation.
 * Falls back to basic stripping if Gemini is unavailable.
 */
async function formatReportForPdf(markdownReport) {
  const prompt = `Convert the following markdown report into clean, professionally formatted plain text suitable for a PDF document.

RULES:
1. Remove all markdown syntax (# headers, ** bold, - bullets, etc.)
2. Convert headers into UPPERCASE section titles followed by a blank line
3. Convert bullet points into properly indented paragraphs with ">" prefix
4. Keep the content readable and well-structured
5. Do NOT use any emojis or special Unicode characters
6. Use only standard ASCII characters
7. Preserve all important information
8. Add appropriate spacing between sections

MARKDOWN REPORT:
${markdownReport}

OUTPUT (clean plain text only):`;

  try {
    return (await _generate(prompt, MODEL_FLASH, 'formatReportForPdf')).trim();
  } catch (err) {
    console.warn('[Gemini] formatReportForPdf failed, falling back to basic stripping:', err.message);
    return stripMarkdownBasic(markdownReport);
  }
}

/**
 * Format scan data into structured bilingual JSON for PDF.
 */
async function formatScanDataForPdf(scanResult, options = {}) {
  const zapHighCount   = scanResult.zapResult?.riskCounts?.High || 0;
  const zapMediumCount = scanResult.zapResult?.riskCounts?.Medium || 0;
  const urlscanMalicious = scanResult.urlscanResult?.verdicts?.overall?.malicious || false;
  const overallRisk = (zapHighCount > 0 || urlscanMalicious) ? 'High' : zapMediumCount > 0 ? 'Medium' : 'Low';

  // Scores are `null` when PageSpeed never returned the category — rendered as
  // "N/A", never as "0/100" (see utils/scoreFormat.js).
  const psi               = lighthouseScores(scanResult.pagespeedResult);
  const performanceScore  = formatScore(psi.performance);
  const accessibilityScore= formatScore(psi.accessibility);
  const bestPracticesScore= formatScore(psi.bestPractices);
  const seoScore          = formatScore(psi.seo);

  const obs      = scanResult.observatoryResult || {};
  const zap      = scanResult.zapResult        || {};
  const urlscan  = scanResult.urlscanResult    || {};
  const webCheck = scanResult.webCheckResult?.fullResults || {};

  // A WebCheck that never completed has not "found no WAF" — it found nothing.
  // Report those fields as N/A so neither Gemini nor the PDF states a negative
  // finding that was never measured.
  const wcOk = ['completed', 'completed_partial', 'completed_with_errors']
    .includes(scanResult.webCheckResult?.status);
  const wcYesNo = (present) => wcOk ? (present ? 'Yes' : 'No') : 'N/A';
  const wcTlsGrade = (wcOk && (webCheck.tls?.tlsInfo?.grade || webCheck.ssl?.grade)) || 'N/A';
  const wcWaf = wcOk
    ? (webCheck.firewall?.hasWaf ? `Yes (${webCheck.firewall.waf})` : 'No')
    : 'N/A';
  const wcTech = (wcOk && webCheck['tech-stack']?.technologies?.slice(0, 5).map(t => t.name || t).join(', ')) || 'N/A';

  const scanHistoryRows = Array.isArray(options.scanHistoryRows) ? options.scanHistoryRows : [];

  const scanDataText = `
Target URL: ${scanResult.target}
Scan ID: ${scanResult.analysisId}
Status: ${scanResult.status}
Overall Risk Level: ${overallRisk}

PAGESPEED INSIGHTS:
- Performance Score: ${performanceScore}
- Accessibility Score: ${accessibilityScore}
- Best Practices Score: ${bestPracticesScore}
- SEO Score: ${seoScore}

MOZILLA OBSERVATORY:
- Security Grade: ${obs.grade || 'N/A'}
- Score: ${formatMetric(obs.score)}
- Tests Passed: ${obs.tests_passed || 0}
- Tests Failed: ${obs.tests_failed || 0}

OWASP ZAP VULNERABILITY SCAN:
- Status: ${zap.status || 'N/A'}
- Total Alerts: ${zap.totalAlerts || 0}
- High Risk: ${zap.riskCounts?.High || 0}
- Medium Risk: ${zap.riskCounts?.Medium || 0}
- Low Risk: ${zap.riskCounts?.Low || 0}
- Informational: ${zap.riskCounts?.Informational || 0}
${zap.alerts ? `- Top Vulnerabilities: ${zap.alerts.slice(0, 5).map(a => `[${a.risk}] ${a.alert}`).join('; ')}` : ''}

URLSCAN.IO ANALYSIS:
- Verdict: ${urlscan.verdicts?.overall?.malicious ? 'MALICIOUS' : 'Clean'}
- Threat Score: ${formatMetric(urlscan.verdicts?.overall?.score)}
- Domain: ${urlscan.page?.domain || 'N/A'}
- Server IP: ${urlscan.page?.ip || 'N/A'}
- Country: ${urlscan.page?.country || 'N/A'}
- Server: ${urlscan.page?.server || 'N/A'}

WEBCHECK ANALYSIS:
- TLS Grade: ${wcTlsGrade}
- WAF Detected: ${wcWaf}
- HSTS Enabled: ${wcYesNo(webCheck.hsts?.enabled)}
- Technologies: ${wcTech}
`;

  const prompt = `Convert this security scan data into a structured JSON format for a professional bilingual PDF report (English and Japanese).

SCAN DATA:
${scanDataText}

    SCAN HISTORY INPUT (JSON array):
    ${JSON.stringify(scanHistoryRows, null, 2)}

Return a JSON object with this EXACT structure:
{
  "header": {
    "title": { "en": "Security Scan Report", "ja": "Japanese translation" },
    "target": "${scanResult.target}",
    "scanId": "${scanResult.analysisId}",
    "date": "${new Date().toLocaleDateString()}",
    "status": { "en": "${scanResult.status}", "ja": "Japanese translation" }
  },
  "scanHistory": {
    "title": { "en": "Scan History", "ja": "Japanese translation" },
    "headers": {
      "en": ["Date", "Executed by", "Status"],
      "ja": ["日付", "実行ユーザー", "ステータス"]
    },
    "rows": {
      "en": [["DD/MM/YYYY", "user@example.com", "Completed"]],
      "ja": [["YYYY/MM/DD", "user@example.com", "診断終了"]]
    }
  },
  "summary": {
    "title": { "en": "Executive Summary", "ja": "Japanese translation" },
    "riskLevel": { "en": "${overallRisk}", "ja": "Japanese translation" },
    "riskLabel": { "en": "Overall Risk Level", "ja": "Japanese translation" }
  },
  "sections": [
    {
      "id": "pagespeed",
      "title": { "en": "Performance & Accessibility Analysis", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Performance", "ja": "Japanese" }, "value": "${performanceScore}", "type": "score" },
        { "label": { "en": "Accessibility", "ja": "Japanese" }, "value": "${accessibilityScore}", "type": "score" },
        { "label": { "en": "Best Practices", "ja": "Japanese" }, "value": "${bestPracticesScore}", "type": "score" },
        { "label": { "en": "SEO", "ja": "Japanese" }, "value": "${seoScore}", "type": "score" }
      ]
    },
    {
      "id": "observatory",
      "title": { "en": "Security Configuration Assessment", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Security Grade", "ja": "Japanese" }, "value": "${obs.grade || 'N/A'}", "type": "grade" },
        { "label": { "en": "Score", "ja": "Japanese" }, "value": "${formatMetric(obs.score)}", "type": "score" },
        { "label": { "en": "Tests Passed", "ja": "Japanese" }, "value": "${obs.tests_passed || 0}", "type": "success" },
        { "label": { "en": "Tests Failed", "ja": "Japanese" }, "value": "${obs.tests_failed || 0}", "type": "danger" }
      ]
    },
    {
      "id": "zap",
      "title": { "en": "Vulnerability Scan Results", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Total Alerts", "ja": "Japanese" }, "value": "${zap.totalAlerts || 0}", "type": "stat" },
        { "label": { "en": "High Risk", "ja": "Japanese" }, "value": "${zap.riskCounts?.High || 0}", "type": "danger" },
        { "label": { "en": "Medium Risk", "ja": "Japanese" }, "value": "${zap.riskCounts?.Medium || 0}", "type": "warning" },
        { "label": { "en": "Low Risk", "ja": "Japanese" }, "value": "${zap.riskCounts?.Low || 0}", "type": "info" },
        { "label": { "en": "Informational", "ja": "Japanese" }, "value": "${zap.riskCounts?.Informational || 0}", "type": "stat" }
      ],
      "alerts": ${JSON.stringify((zap.alerts || []).slice(0, 7).map(a => ({ risk: a.risk, alert: a.alert })))},
      "detailedAlerts": ${JSON.stringify((zap.alerts || []).map(a => ({
        name: a.alert,
        risk: a.risk,
        confidence: a.confidence,
        description: a.description || 'No description available',
        solution: a.solution || 'No solution provided',
        reference: a.reference || '',
        cweid: a.cweid,
        wascid: a.wascid,
        totalOccurrences: a.totalOccurrences || 0,
        sampleUrls: a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || []
      })))}
    },
    {
      "id": "urlscan",
      "title": { "en": "Threat & Reputation Analysis", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Verdict", "ja": "Japanese" }, "value": { "en": "${urlscan.verdicts?.overall?.malicious ? 'MALICIOUS' : 'Clean'}", "ja": "Japanese" }, "type": "${urlscan.verdicts?.overall?.malicious ? 'danger' : 'success'}" },
        { "label": { "en": "Threat Score", "ja": "Japanese" }, "value": "${formatMetric(urlscan.verdicts?.overall?.score)}", "type": "score" },
        { "label": { "en": "Domain", "ja": "Japanese" }, "value": "${urlscan.page?.domain || 'N/A'}", "type": "stat" },
        { "label": { "en": "Server IP", "ja": "Japanese" }, "value": "${urlscan.page?.ip || 'N/A'}", "type": "stat" },
        { "label": { "en": "Country", "ja": "Japanese" }, "value": "${urlscan.page?.country || 'N/A'}", "type": "stat" },
        { "label": { "en": "Server", "ja": "Japanese" }, "value": "${urlscan.page?.server || 'N/A'}", "type": "stat" }
      ]
    },
    {
      "id": "webcheck",
      "title": { "en": "Web Security Configuration", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "TLS Grade", "ja": "Japanese" }, "value": "${wcTlsGrade}", "type": "grade" },
        { "label": { "en": "WAF Detected", "ja": "Japanese" }, "value": { "en": "${wcYesNo(webCheck.firewall?.hasWaf)}", "ja": "Japanese" }, "type": "${!wcOk ? 'stat' : (webCheck.firewall?.hasWaf ? 'success' : 'warning')}" },
        { "label": { "en": "HSTS Enabled", "ja": "Japanese" }, "value": { "en": "${wcYesNo(webCheck.hsts?.enabled)}", "ja": "Japanese" }, "type": "${!wcOk ? 'stat' : (webCheck.hsts?.enabled ? 'success' : 'warning')}" },
        { "label": { "en": "Technologies", "ja": "Japanese" }, "value": "${wcTech}", "type": "stat" }
      ]
    }
  ]
}

IMPORTANT RULES:
1. Return ONLY valid JSON, no markdown or extra text
2. Translate ALL "ja" fields to proper Japanese
3. Keep technical terms (like URLs, IPs, scores) unchanged
4. Ensure professional translations suitable for a business report
5. The "scanHistory" section MUST be generated from SCAN HISTORY INPUT:
  - Use the SAME number of rows and SAME row order as input
  - For English rows, use input.dateEn and input.executedByEn EXACTLY (do not change date formats)
  - For Japanese rows, use input.dateJa and input.executedByJa EXACTLY (do not change date formats)
  - Convert the input "status" into a user-friendly label in each language (e.g., completed -> Completed/診断終了, pending/queued/combining -> Scanning/スキャン中, failed -> Failed/失敗, cancelled/stopped -> Cancelled/停止)
  - Do NOT invent rows that are not in the input
`;

  const raw = await _generateWithFallback(prompt, 'formatScanDataForPdf', options);
  const parsed = _parseJson(raw);

  // Always inject full detailedAlerts — Gemini might truncate them
  const zapSection = parsed.sections?.find(s => s.id === 'zap');
  if (zapSection && zap.alerts && zap.alerts.length > 0) {
    zapSection.detailedAlerts = zap.alerts.map(a => ({
      name:             a.alert,
      risk:             a.risk,
      confidence:       a.confidence,
      description:      a.description      || 'No description available',
      solution:         a.solution         || 'No solution provided',
      reference:        a.reference        || '',
      cweid:            a.cweid,
      wascid:           a.wascid,
      totalOccurrences: a.totalOccurrences || a.occurrences?.length || 0,
      sampleUrls:       a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || [],
    }));
    console.log(`[Gemini] Added ${zapSection.detailedAlerts.length} detailed alerts to ZAP section`);
  }

  console.log('✅ [Gemini] Scan data formatted for PDF');
  return parsed;
}

/**
 * Format scan history into structured bilingual JSON for PDF.
 */
async function formatScanHistoryForPdf(scanHistoryRows) {
  const rows = Array.isArray(scanHistoryRows) ? scanHistoryRows : [];

  // Sanitize executor emails before sending to Gemini (M-01)
  const safeRows = sanitizeHistoryRowsForLLM(rows);

  const prompt = `Generate the Scan History table content for a professional bilingual PDF report (English and Japanese).

INPUT (JSON array):
${JSON.stringify(safeRows, null, 2)}

Return ONLY valid JSON with this EXACT structure:
{
  "title": { "en": "Scan History", "ja": "Japanese translation" },
  "headers": {
    "en": ["Date", "Executed by", "Status"],
    "ja": ["日付", "実行ユーザー", "ステータス"]
  },
  "rows": {
    "en": [["DD/MM/YYYY", "user@example.com", "Completed"]],
    "ja": [["YYYY/MM/DD", "user@example.com", "診断終了"]]
  }
}

CRITICAL RULES:
1. Use the SAME number of rows and SAME order as the input array.
2. For English rows, use input.dateEn and input.executedByEn EXACTLY (do not change date formats).
3. For Japanese rows, use input.dateJa and input.executedByJa EXACTLY (do not change date formats).
4. Convert input.status into a user-friendly label in each language:
   - completed -> Completed / 診断終了
   - pending/queued/combining -> Scanning / スキャン中
   - failed -> Failed / 失敗
   - cancelled/stopped -> Cancelled / 停止
5. Do NOT add any text outside of the JSON.`;

  const raw = await _generateWithFallback(prompt, 'formatScanHistoryForPdf');
  const parsed = _parseJson(raw);

  if (!parsed?.title || !parsed?.headers || !parsed?.rows) {
    throw new Error('Invalid scanHistory response — missing title/headers/rows');
  }

  console.log('✅ [Gemini] Scan history formatted for PDF');
  return parsed;
}

/**
 * Format AI analysis into structured JSON for PDF.
 */
async function formatAiAnalysisForPdf(markdownReport, opts = {}) {
  // Strip any URLs / IPs that Gemini may have embedded in the stored report
  // during the original refineReport() call — prevents a second-pass re-leak.
  const cleanMarkdownReport = sanitizeRefinedReportForLLM(markdownReport);
  const prompt = `Convert this security analysis report into a structured JSON format for a professional PDF document.

REPORT:
${cleanMarkdownReport}

Return a JSON object with this EXACT structure:
{
  "title": "AI-Generated Security Analysis",
  "sections": [
    {
      "heading": "Section Title (e.g., Executive Summary)",
      "type": "paragraph|bullets|mixed",
      "content": [
        { "type": "paragraph", "text": "Paragraph text here..." },
        { "type": "bullets", "items": ["Bullet point 1", "Bullet point 2"] },
        { "type": "bold_text", "label": "Risk Level:", "text": "HIGH" }
      ]
    }
  ]
}

CRITICAL RULES - MUST FOLLOW STRICTLY:

**JSON FORMAT:**
1. Return ONLY valid JSON - absolutely NO text before or after the JSON
2. No markdown code blocks (no \`\`\`json) - just raw JSON

**NO DUPLICATES OR OVERLAPS:**
3. Each section heading must appear EXACTLY ONCE - NO DUPLICATES WHATSOEVER
4. NEVER repeat the same content in multiple sections
5. NEVER overlap or mix content between sections
6. Complete one entire section before starting the next
7. Do NOT include an "Executive Summary" section - it is rendered separately in the PDF

**COMPLETE CONTENT BLOCKS - CRITICAL:**
7. Every paragraph MUST be a complete thought with full sentences
8. NEVER break paragraphs mid-sentence or mid-word
9. Every bullet point must be a complete statement
10. NO truncated text ending with "..." unless it's an intentional ellipsis
11. ALL paragraphs must be self-contained and readable on their own

**PROPER STRUCTURE:**
12. Use "paragraph" type for flowing text (2-3 complete sentences per paragraph, split longer ones into separate blocks)
13. Use "bullets" type for lists (3-8 complete items per bullet block)
14. Use "bold_text" type ONLY for key-value metrics - MUST have BOTH "label" AND "text" fields:
    - CORRECT: { "type": "bold_text", "label": "Risk Level:", "text": "HIGH" }
    - WRONG: { "type": "bold_text" } or { "type": "bold_text", "label": "Risk:" }
15. Each section must have at least one complete content block
16. NEVER create bold_text blocks without both label and text properties

**FORMATTING:**
17. NO emojis or special unicode characters
18. Professional business language only
19. Clear section boundaries - do not mix sections
20. Logical flow from one section to the next
21. ALL text must be complete - no mid-sentence cutoffs

**VALIDATION:**
22. Double-check for duplicate headings before returning
23. Verify EVERY paragraph ends with proper punctuation (. ! ?)
24. Ensure no text overlaps between sections
25. Confirm ALL content blocks are complete and readable

EXAMPLE OF COMPLETE VS INCOMPLETE:
✅ CORRECT: "The website uses Cloudflare for content delivery, security (WAF), and TLS/SSL management."
❌ WRONG: "The website uses Cloudflare for content delivery, security (WAF), and"`;

  const raw = await _generateWithFallback(prompt, 'formatAiAnalysisForPdf', opts);
  const parsed = _parseJson(raw);
  const cleaned = cleanDuplicateSections(parsed);
  console.log('✅ [Gemini] AI analysis formatted for PDF');
  return cleaned;
}

/**
 * Translate formatted AI analysis to Japanese (kept for backwards compatibility).
 */
async function translateAiAnalysisToJapanese(formattedAnalysis, opts = {}) {
  // Sanitize the formatted analysis to strip any embedded URLs/IPs before
  // sending to Gemini for translation (C-07, C-08 — compound re-leakage).
  const safeAnalysisText = sanitizeRefinedReportForLLM(JSON.stringify(formattedAnalysis, null, 2));
  const prompt = `Translate this security analysis JSON from English to Japanese. Keep the exact same structure, only translate the text content.

INPUT JSON:
${safeAnalysisText}

CRITICAL RULES - MUST FOLLOW STRICTLY:

**JSON FORMAT:**
1. Return ONLY valid JSON - absolutely NO text before or after
2. No markdown code blocks (no \`\`\`json) - just raw JSON
3. Preserve the EXACT same structure as the input

**TRANSLATION RULES:**
4. Translate ALL text content to Japanese (headings, paragraphs, bullets)
5. Keep technical terms unchanged: URLs, IPs, version numbers, HTTP headers
6. The "title" should be: "AIによるセキュリティ分析"
7. Maintain professional business Japanese (です/ます form)
8. Use proper Japanese punctuation (。、 instead of .,)

**NO DUPLICATES OR OVERLAPS:**
9. Do NOT duplicate any sections - each heading appears EXACTLY ONCE
10. Do NOT add new sections not in the input
11. Preserve the exact number of sections from input (no more, no less)
12. NEVER overlap or mix content between sections

**COMPLETE CONTENT BLOCKS - CRITICAL:**
13. Every translated paragraph MUST be COMPLETE with full sentences
14. NEVER break paragraphs mid-sentence or mid-word
15. Every bullet point must be a complete statement
16. NO truncated text ending with "..." unless intentional ellipsis
17. ALL translated paragraphs must be self-contained and readable
18. Preserve complete sentence structure from English source

**VALIDATION:**
19. Double-check for duplicate headings before returning
20. Verify EVERY paragraph ends with proper Japanese punctuation (。！？)
21. Ensure no text overlaps between sections
22. Count sections: output must match input exactly (same number of sections)
23. Confirm ALL translated content is complete and readable

OUTPUT (Japanese JSON only):`;

  const raw = await _generate(prompt, MODEL_FLASH, 'translateAiAnalysisToJapanese', opts);
  const parsed = _parseJson(raw);
  const cleaned = cleanDuplicateSections(parsed);
  console.log('✅ [Gemini] AI analysis translated to Japanese');
  return cleaned;
}

/**
 * Translate both AI analysis and vulnerability details to Japanese in a single call.
 */
async function translateToJapanese(formattedAnalysis, vulnerabilities, opts = {}) {
  // Sanitize both inputs to strip embedded URLs/IPs before translation
  // (C-07 / C-08 — AI report + vuln detail compound re-leakage).
  const safeAnalysisJson = sanitizeRefinedReportForLLM(JSON.stringify(formattedAnalysis, null, 2));
  const safeVulnJson     = sanitizeRefinedReportForLLM(JSON.stringify(vulnerabilities, null, 2));

  const prompt = `You are translating a security report from English to Japanese. You need to translate TWO things in a SINGLE response:

1. AI Security Analysis (JSON object)
2. Vulnerability Details (JSON array)

Return a JSON object with this structure:
{
  "aiAnalysis": { ...translated AI analysis... },
  "vulnerabilities": [ ...translated vulnerabilities array... ]
}

INPUT AI ANALYSIS:
${safeAnalysisJson}

INPUT VULNERABILITIES:
${safeVulnJson}

CRITICAL RULES - MUST FOLLOW STRICTLY:

**JSON FORMAT:**
1. Return ONLY valid JSON object with "aiAnalysis" and "vulnerabilities" keys
2. No markdown code blocks (no \`\`\`json) - just raw JSON
3. Preserve the EXACT same structure for both inputs

**TRANSLATION RULES FOR AI ANALYSIS:**
4. Translate ALL text content to Japanese (headings, paragraphs, bullets)
5. The "title" should be: "AIによるセキュリティ分析"
6. Maintain professional business Japanese (です/ます form)
7. Use proper Japanese punctuation (。、 instead of .,)
8. Keep technical terms unchanged: URLs, IPs, version numbers, HTTP headers
9. Do NOT duplicate sections - each heading appears EXACTLY ONCE
10. Every paragraph MUST be COMPLETE with full sentences - NO truncation

**TRANSLATION RULES FOR VULNERABILITIES:**
11. Translate "description" and "solution" fields to professional Japanese
12. Keep "name", "risk", "confidence", "reference", "cweid", "wascid", "totalOccurrences" fields unchanged
13. Maintain technical accuracy - do NOT change technical terms like HTTP headers, URLs, code snippets
14. Preserve complete sentence structure - NO fragmented translations

**VALIDATION:**
15. Verify EVERY paragraph ends with proper Japanese punctuation (。！？)
16. Ensure ALL translated content is complete and readable
17. Double-check JSON structure is valid

OUTPUT (Japanese JSON object only):`;

  const raw = await _generate(prompt, MODEL_FLASH, 'translateToJapanese', opts);
  const parsed = _parseJson(raw);

  if (!parsed.aiAnalysis || !parsed.vulnerabilities) {
    throw new Error('Invalid response structure — missing aiAnalysis or vulnerabilities');
  }

  const cleanedAiAnalysis = cleanDuplicateSections(parsed.aiAnalysis);
  console.log(`✅ [Gemini] Translated AI analysis + ${parsed.vulnerabilities.length} vulnerabilities to Japanese`);
  return { aiAnalysis: cleanedAiAnalysis, vulnerabilities: parsed.vulnerabilities };
}

/**
 * Translate a batch of vulnerability objects to Japanese — description + solution
 * only; all other fields (name/risk/confidence/reference/cwe/wasc) are preserved.
 *
 * Kept separate from translateToJapanese so the PDF pipeline can translate
 * vulnerabilities in small chunks. Smaller payloads complete faster and a single
 * transient failure only affects one chunk, not the whole Japanese report.
 * Raw request/response (`occurrences`) must be stripped by the caller before
 * calling this — never send bulky raw HTTP to Gemini.
 *
 * @returns {Promise<Array>} translated array, same length/order as the input.
 */
async function translateVulnerabilitiesToJapanese(vulnerabilities, opts = {}) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) return [];

  const safeVulnJson = sanitizeRefinedReportForLLM(JSON.stringify(vulnerabilities, null, 2));

  const prompt = `You are translating the descriptions and solutions of web security vulnerabilities from English to Japanese.

INPUT (JSON array of vulnerability objects):
${safeVulnJson}

Return ONLY a valid JSON array with the EXACT same length and order as the input.

CRITICAL RULES - MUST FOLLOW STRICTLY:
1. Return ONLY the raw JSON array — no markdown code blocks (no \`\`\`json), no text before or after.
2. Preserve the exact same number of objects and their order.
3. Translate ONLY the "description" and "solution" fields to professional business Japanese (です/ます form).
4. Keep "name", "risk", "confidence", "reference", "cweid", "wascid", "totalOccurrences" fields UNCHANGED.
5. Keep technical terms unchanged: URLs, IPs, HTTP header names, code snippets, version numbers.
6. Use proper Japanese punctuation (。、).
7. Every translated field MUST be COMPLETE — no truncation, no fragments.

OUTPUT (Japanese JSON array only):`;

  const raw = await _generate(prompt, MODEL_FLASH, 'translateVulnerabilitiesToJapanese', opts);
  const parsed = _parseJson(raw);
  const arr = Array.isArray(parsed)
    ? parsed
    : (Array.isArray(parsed?.vulnerabilities) ? parsed.vulnerabilities : null);
  if (!arr) {
    throw new Error('Invalid response structure — expected a JSON array of vulnerabilities');
  }
  console.log(`✅ [Gemini] Translated ${arr.length} vulnerabilities to Japanese`);
  return arr;
}

const AI_SECTION_CHUNK_SIZE = 3;

/**
 * Merge Gemini's translated strings back into the ORIGINAL section structure.
 * Structure (section shape, block order/types) always comes from the source; only
 * string fields (heading, paragraph text, bullet items, bold_text label/text) are
 * replaced, and only when the translation is a non-empty string of the right shape.
 * Anything missing/malformed falls back to the English source — never dropped.
 */
function mergeTranslatedSection(src, ja) {
  const srcContent = Array.isArray(src.content) ? src.content : [];
  const jaContent  = Array.isArray(ja?.content) ? ja.content : [];
  const str = (v) => (typeof v === 'string' && v.trim()) ? v : null;
  const content = srcContent.map((block, i) => {
    const jb = jaContent[i] || {};
    if (block.type === 'paragraph') {
      return { ...block, text: str(jb.text) ?? block.text };
    }
    if (block.type === 'bullets') {
      const items = (Array.isArray(jb.items) &&
                     jb.items.length === (block.items || []).length &&
                     jb.items.every(x => str(x)))
        ? jb.items : block.items;
      return { ...block, items };
    }
    if (block.type === 'bold_text') {
      return { ...block, label: str(jb.label) ?? block.label, text: str(jb.text) ?? block.text };
    }
    return block;
  });
  return { ...src, heading: str(ja?.heading) ?? src.heading, content };
}

/**
 * Translate an AI analysis object to Japanese section-by-section, merging the
 * translated strings back into the original structure via mergeTranslatedSection.
 *
 * Why not one big call: the local markdown parser produces sections without a
 * top-level `type`, and a single large translation is truncation-prone (a
 * truncated response fails JSON parsing and collapses the whole summary to the
 * static stub). Translating in small chunks and rebuilding from the source is
 * resilient — a failed chunk simply keeps its English text while the rest of the
 * report stays Japanese.
 */
async function translateAiAnalysisSectionsToJapanese(aiAnalysis, opts = {}) {
  const title    = 'AIによるセキュリティ分析';
  const sections = Array.isArray(aiAnalysis?.sections) ? aiAnalysis.sections : [];
  if (!sections.length) return { ...(aiAnalysis || {}), title, sections: [] };

  const chunkSize = opts.sectionChunkSize || AI_SECTION_CHUNK_SIZE;
  // `opts.generate` lets tests drive this without a live Gemini call.
  const generate = opts.generate || ((p) => _generate(p, MODEL_FLASH, 'translateAiAnalysisSectionsToJapanese', opts));
  const out = sections.slice(); // English by default; replaced per chunk on success

  for (let start = 0; start < sections.length; start += chunkSize) {
    const chunk = sections.slice(start, start + chunkSize);
    const safeJson = sanitizeRefinedReportForLLM(JSON.stringify(chunk, null, 2));
    const prompt = `Translate the following security-report sections from English to Japanese.

INPUT (JSON array of section objects):
${safeJson}

Return ONLY a valid JSON array with the EXACT same length, order, and structure as the input.

CRITICAL RULES - MUST FOLLOW STRICTLY:
1. Return ONLY the raw JSON array — no markdown code blocks (no \`\`\`json), no text before or after.
2. Preserve the number of sections and, within each section, the number of content blocks and their order.
3. Translate ONLY these string fields to professional business Japanese (です/ます form): each section "heading"; each content block's "text"; every string in a "bullets" block's "items"; any "label".
4. Do NOT translate or alter: URLs, IPs, HTTP header names, code snippets, version numbers, and every block's "type" field.
5. Use Japanese punctuation (。、). Keep every translation COMPLETE — no truncation, no fragments.

OUTPUT (Japanese JSON array only):`;

    try {
      const raw = await generate(prompt);
      const parsed = _parseJson(raw);
      const jaArr = Array.isArray(parsed)
        ? parsed
        : (Array.isArray(parsed?.sections) ? parsed.sections : null);
      if (jaArr) {
        chunk.forEach((srcSection, i) => {
          if (jaArr[i]) out[start + i] = mergeTranslatedSection(srcSection, jaArr[i]);
        });
      }
    } catch (e) {
      console.warn(`[Gemini] AI section chunk ${start + 1}-${start + chunk.length} translation failed (${e.message}) — keeping English for these sections`);
    }
  }

  console.log(`✅ [Gemini] Translated AI analysis (${sections.length} sections, chunked) to Japanese`);
  return { ...aiAnalysis, title, sections: out };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function stripMarkdownBasic(text) {
  return text
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g,     '$1')
    .replace(/__([^_]+)__/g,     '$1')
    .replace(/_([^_]+)_/g,       '$1')
    .replace(/^[-*]\s+/gm,       '  > ')
    .replace(/```[\s\S]*?```/g,  '')
    .replace(/`([^`]+)`/g,       '$1')
    .replace(/\n{3,}/g,          '\n\n')
    .trim();
}

function validateContentBlocks(content) {
  if (!Array.isArray(content)) return [];
  const valid = [];
  for (const block of content) {
    if (!block || typeof block !== 'object') continue;
    if (block.type === 'paragraph') {
      if (!block.text?.trim()) continue;
      valid.push(block);
    } else if (block.type === 'bullets') {
      const items = (block.items || []).filter(i => i && typeof i === 'string' && i.trim());
      if (items.length) valid.push({ ...block, items });
    } else if (block.type === 'bold_text') {
      if (!block.label || !block.text) continue;
      valid.push(block);
    } else {
      valid.push(block);
    }
  }
  return valid;
}

function cleanDuplicateSections(parsed) {
  if (!parsed?.sections) return parsed;
  const seen = new Set();
  const unique = [];
  for (const section of parsed.sections) {
    if (!section.heading?.trim() || !Array.isArray(section.content)) continue;
    const key = section.heading.toLowerCase().trim();
    if (seen.has(key)) continue;
    // `section.type` is optional: the local markdown parser
    // (buildAiAnalysisFromRefinedReport) sets `type` on content BLOCKS, not on the
    // section. Only reject a section whose type is present AND unrecognised — never
    // drop a valid section merely for lacking a top-level type.
    if (section.type && !['paragraph', 'bullets', 'mixed'].includes(section.type)) continue;
    const content = validateContentBlocks(section.content);
    if (!content.length) continue;
    seen.add(key);
    unique.push({ ...section, content });
  }
  console.log(`[Gemini] cleanDuplicateSections: ${parsed.sections.length} → ${unique.length}`);
  return { ...parsed, sections: unique };
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  GEMINI_AUTH_MODE: () => GEMINI_AUTH_MODE, // getter — value is set during init
  refineReport,
  translateText,
  formatReportForPdf,
  formatScanDataForPdf,
  formatScanHistoryForPdf,
  formatAiAnalysisForPdf,
  translateAiAnalysisToJapanese,
  translateAiAnalysisSectionsToJapanese,
  translateVulnerabilitiesToJapanese,
  translateToJapanese,
  // exported for unit tests
  cleanDuplicateSections,
  mergeTranslatedSection,
  verifyCredentials,
};
