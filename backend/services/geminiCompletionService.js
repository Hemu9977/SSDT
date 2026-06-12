/**
 * Gemini Completion Service
 *
 * Triggered by ZAP and WebCheck services when each finishes.
 * Checks whether BOTH background scans are done; if so, generates
 * the Gemini AI report, marks scan as `completed`, and fires notifications.
 *
 * Guarantees:
 *  - Scan always reaches a terminal state (completed / failed) even when Gemini fails.
 *  - A hard 45-minute overall timeout prevents the function from hanging the process.
 *  - Redis lock + done-flag prevent duplicate report generation across processes.
 *  - Comprehensive logging at every step for CloudWatch diagnosis.
 */

const ScanResult = require('../models/ScanResult');
const User = require('../models/User');
const { refineReport } = require('./geminiService');
const { getFullResults } = require('./webCheckService');
const { handleScanComplete } = require('./notificationService');
const { publishScanProgress } = require('./scanProgressService');
const { getPublisher } = require('../config/redis');
const { getSanitizedZapReport } = require('../utils/vulnFilter');
const { sanitizeScanForLLM } = require('./geminiSanitizer');

/**
 * resolveVulnAccessLevel — fetches the plan's vulnerabilityAccessLevel for a user.
 * Falls back to 'critical-high' (most restrictive) on any error.
 */
async function resolveVulnAccessLevel(userId) {
  try {
    const u = await User.findById(userId).select('planType billingCycle accountType proExpiresAt organizationId');
    if (!u) return 'critical-high';
    let org = null;
    if (u.organizationId) {
      const Organization = require('../models/Organization');
      org = await Organization.findById(u.organizationId);
    }
    return u.getAccountLimits(org).vulnerabilityAccessLevel || 'critical-high';
  } catch (_) { /* non-fatal */ }
  return 'critical-high';
}

// In-memory fallback lock (used only when Redis is unavailable in a single-process deploy)
const geminiInProgress = new Set();

const GEMINI_LOCK_TTL_S  = 3600;          // 1 h — long enough to outlive any scan
const GEMINI_DONE_TTL_S  = 24 * 3600;    // 24 h — dedupe window for repeated callbacks
// Hard cap on the entire checkAndGenerateGemini execution.
// Prevents the function from hanging if generateContent ever stalls past its own timeout.
const FUNCTION_TIMEOUT_MS = 45 * 60 * 1000; // 45 minutes

// ─── Redis helpers ─────────────────────────────────────────────────────────────

async function _isGeminiDone(scanId) {
  const doneKey = `scan:${scanId}:gemini_done`;
  try {
    const value = await getPublisher().get(doneKey);
    return value === '1';
  } catch (_) {
    return false;
  }
}

async function _markGeminiDone(scanId) {
  const doneKey = `scan:${scanId}:gemini_done`;
  try {
    await getPublisher().set(doneKey, '1', 'EX', GEMINI_DONE_TTL_S);
  } catch (_) {
    // best-effort
  }
}

/**
 * Acquire an atomic cross-process Gemini lock via Redis SETNX.
 * Returns true if the lock was acquired (caller should proceed).
 * Falls back to the in-memory Set when Redis is unreachable.
 */
async function _acquireGeminiLock(scanId) {
  const lockKey = `scan:${scanId}:gemini`;
  try {
    const result = await getPublisher().set(lockKey, '1', 'NX', 'EX', GEMINI_LOCK_TTL_S);
    return result === 'OK'; // null = key already existed (another process holds the lock)
  } catch (redisErr) {
    console.warn(`[Gemini] Redis lock unavailable for ${scanId}, falling back to in-memory:`, redisErr.message);
    if (geminiInProgress.has(scanId)) return false;
    geminiInProgress.add(scanId);
    return true;
  }
}

// ─── DB helpers ────────────────────────────────────────────────────────────────

/**
 * Persist a DB update with up to maxAttempts retries.
 * Returns true on success, false if all attempts fail.
 */
async function _dbUpdate(filter, update, scanId, label, maxAttempts = 3) {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      const res = await ScanResult.updateOne(filter, update);
      console.log(`[Gemini][${scanId}] DB update "${label}" ok (matched=${res.matchedCount} modified=${res.modifiedCount})`);
      return true;
    } catch (err) {
      console.error(`[Gemini][${scanId}] DB update "${label}" attempt ${i}/${maxAttempts} failed:`, err.message);
      if (i < maxAttempts) await new Promise(r => setTimeout(r, 2000 * i));
    }
  }
  return false;
}

// ─── Structured fallback report ───────────────────────────────────────────────
// Generates a meaningful markdown report from raw scan data without Gemini.
// Used when all Gemini retries are exhausted so the scan always has real content.

function _buildStructuredFallbackReport(scan, zapReport, webCheckReport) {
  const cats   = scan.pagespeedResult?.lighthouseResult?.categories || {};
  const perf   = Math.round((cats.performance?.score      || 0) * 100);
  const access = Math.round((cats.accessibility?.score    || 0) * 100);
  const bp     = Math.round((cats['best-practices']?.score|| 0) * 100);
  const seo    = Math.round((cats.seo?.score              || 0) * 100);

  const obs      = scan.observatoryResult || {};
  const obsGrade = obs.grade  || 'N/A';
  const obsScore = obs.score  || 0;
  const obsPassed= obs.tests_passed || 0;
  const obsFailed= obs.tests_failed || 0;

  const urlscan = scan.urlscanResult || {};
  const isMalicious = urlscan.verdicts?.overall?.malicious || false;
  const threatScore  = urlscan.verdicts?.overall?.score    || 0;

  const zapRisk   = zapReport?.riskCounts || {};
  const zapAlerts = zapReport?.alerts     || [];
  const highAlerts = zapAlerts.filter(a => a.risk === 'High');
  const medAlerts  = zapAlerts.filter(a => a.risk === 'Medium');
  const overallRisk= (zapRisk.High > 0 || isMalicious) ? 'High'
                   : (zapRisk.Medium > 0)               ? 'Medium' : 'Low';

  const wc      = webCheckReport || {};
  const tlsGrade= wc.tls?.tlsInfo?.grade || wc.ssl?.grade || 'N/A';
  const hasWaf  = wc.firewall?.hasWaf    || false;
  const hstsOn  = wc.hsts?.enabled      || false;
  const techs   = (wc['tech-stack']?.technologies || []).slice(0, 6).map(t => t.name || t).filter(Boolean);

  const lines = [];
  lines.push(`# Security Analysis Report — ${scan.target}`);
  lines.push('');
  lines.push('## Executive Summary');
  lines.push(`Automated security scan completed for **${scan.target}**. ` +
    `Overall risk level assessed as **${overallRisk}** based on vulnerability findings and threat analysis. ` +
    (isMalicious ? 'The site has been flagged as **malicious** by threat intelligence. Immediate action is recommended.' :
     zapRisk.High > 0 ? `${zapRisk.High} high-risk vulnerabilities were detected and require prompt remediation.` :
     'No critical threats detected; review medium and low findings below.'));
  lines.push('');

  lines.push('## Performance Analysis');
  lines.push(`- Performance Score: ${perf}/100`);
  lines.push(`- Accessibility Score: ${access}/100`);
  lines.push(`- Best Practices Score: ${bp}/100`);
  lines.push(`- SEO Score: ${seo}/100`);
  lines.push('');

  lines.push('## Security Configuration');
  lines.push(`- Security Grade: ${obsGrade} (Score: ${obsScore}/100)`);
  lines.push(`- Tests Passed: ${obsPassed} / Tests Failed: ${obsFailed}`);
  if (tlsGrade !== 'N/A') lines.push(`- TLS/SSL Grade: ${tlsGrade}`);
  lines.push(`- HSTS Enabled: ${hstsOn ? 'Yes' : 'No'}`);
  lines.push(`- WAF Detected: ${hasWaf ? 'Yes' : 'No'}`);
  if (techs.length) lines.push(`- Technology Stack: ${techs.join(', ')}`);
  lines.push('');

  lines.push('## Vulnerability Scan Results');
  lines.push(`- Total Alerts: ${zapReport?.totalAlerts || 0}`);
  lines.push(`- High Risk: ${zapRisk.High || 0}`);
  lines.push(`- Medium Risk: ${zapRisk.Medium || 0}`);
  lines.push(`- Low Risk: ${zapRisk.Low || 0}`);
  lines.push(`- Informational: ${zapRisk.Informational || 0}`);
  if (highAlerts.length) {
    lines.push('');
    lines.push('High Risk Findings:');
    highAlerts.slice(0, 5).forEach(a => lines.push(`- ${a.alert}`));
  }
  if (medAlerts.length) {
    lines.push('');
    lines.push('Medium Risk Findings:');
    medAlerts.slice(0, 5).forEach(a => lines.push(`- ${a.alert}`));
  }
  lines.push('');

  lines.push('## Threat & Reputation Analysis');
  lines.push(`- Verdict: ${isMalicious ? 'MALICIOUS — Immediate action required' : 'Clean'}`);
  lines.push(`- Threat Score: ${threatScore}/100`);
  if (urlscan.page?.domain)  lines.push(`- Domain: ${urlscan.page.domain}`);
  if (urlscan.page?.country) lines.push(`- Country: ${urlscan.page.country}`);
  lines.push('');

  lines.push('## Recommendations');
  if (isMalicious)        lines.push('- URGENT: Site flagged as malicious. Investigate and remediate immediately.');
  if (zapRisk.High > 0)   lines.push('- Remediate all High risk vulnerabilities identified in the vulnerability scan.');
  if (zapRisk.Medium > 0) lines.push('- Review and address Medium risk vulnerabilities.');
  if (!hstsOn)            lines.push('- Enable HSTS (HTTP Strict Transport Security) to enforce secure connections.');
  if (!hasWaf)            lines.push('- Consider deploying a Web Application Firewall (WAF) for additional protection.');
  if (obsFailed > 0)      lines.push(`- Resolve ${obsFailed} failed security header test(s) to improve your security grade.`);
  if (perf < 80)          lines.push('- Performance score is below 80 — optimize images, scripts, and server response times.');
  if (access < 80)        lines.push('- Accessibility score is below 80 — review WCAG guidelines and improve compliance.');
  lines.push('- Conduct regular security scans to track remediation progress.');
  lines.push('');

  lines.push('## Note');
  lines.push('This report was generated from raw scan data. An AI-enhanced analysis with deeper insights and recommendations will be available on the next scan.');

  return lines.join('\n');
}

// ─── Fallback completion ───────────────────────────────────────────────────────

async function _finishWithFallback(scan, scanId, userId, message) {
  const fallback = message || 'AI analysis could not be generated due to missing scan data.';
  console.log(`[Gemini][${scanId}] Finishing with fallback message`);
  await _dbUpdate(
    { analysisId: scanId, status: { $nin: ['stopped', 'cancelled'] } },
    { $set: { refinedReport: fallback, status: 'completed', updatedAt: new Date() } },
    scanId,
    'fallback-complete'
  );
  _markGeminiDone(scanId).catch(() => {});
  await publishScanProgress(scanId, userId, { status: 'completed', progress: 100, message: 'Scan complete' });
  handleScanComplete(scanId, userId, 'Combined Security Scan', scan.target);
}

// ─── Main entry point ──────────────────────────────────────────────────────────

/**
 * Called by zapService and webCheckService after they save their completion.
 * Safe to call multiple times — uses lock + DB checks to run Gemini exactly once.
 *
 * @param {string} scanId  - analysisId
 * @param {string} userId  - MongoDB user ObjectId string
 */
async function checkAndGenerateGemini(scanId, userId) {
  // Wrap the entire function in a hard timeout so it can never hang the process.
  let timeoutHandle;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutHandle = setTimeout(
      () => reject(new Error(`checkAndGenerateGemini timed out after ${FUNCTION_TIMEOUT_MS / 60000} min`)),
      FUNCTION_TIMEOUT_MS
    );
  });

  try {
    await Promise.race([_doGenerate(scanId, userId), timeoutPromise]);
  } catch (outerErr) {
    console.error(`[Gemini][${scanId}] OUTER TIMEOUT/ERROR:`, outerErr.message);
    // Attempt to rescue the scan from permanent "combining" state.
    try {
      const current = await ScanResult.findOne({ analysisId: scanId }, { status: 1, refinedReport: 1 });
      if (current && !['completed', 'failed', 'stopped', 'cancelled'].includes(current.status) && !current.refinedReport) {
        console.warn(`[Gemini][${scanId}] Marking scan failed due to outer timeout`);
        await _dbUpdate(
          { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
          { $set: { status: 'failed', updatedAt: new Date() } },
          scanId,
          'outer-timeout-fail'
        );
        await publishScanProgress(scanId, userId, {
          status: 'failed',
          progress: 0,
          error: 'AI report generation timed out. Scan data is still available.'
        });
      }
    } catch (rescueErr) {
      console.error(`[Gemini][${scanId}] Rescue update also failed:`, rescueErr.message);
    }
  } finally {
    clearTimeout(timeoutHandle);
  }
}

async function _doGenerate(scanId, userId) {
  let usedInMemoryLock = false;

  console.log(`[Gemini][${scanId}] checkAndGenerateGemini called — userId=${userId}`);

  // ── Fast Redis guard ────────────────────────────────────────────────────────
  if (await _isGeminiDone(scanId)) {
    console.log(`[Gemini][${scanId}] Done flag already set — skipping`);
    return;
  }

  // ── DB pre-check ────────────────────────────────────────────────────────────
  const scan = await ScanResult.findOne({ analysisId: scanId });
  if (!scan) {
    console.warn(`[Gemini][${scanId}] Scan not found in DB — skipping`);
    return;
  }

  console.log(`[Gemini][${scanId}] Scan status=${scan.status} zapStatus=${scan.zapResult?.status} webCheckStatus=${scan.webCheckResult?.status} refinedReport=${scan.refinedReport ? 'present' : 'null'}`);

  if (['stopped', 'cancelled', 'completed'].includes(scan.status)) {
    console.log(`[Gemini][${scanId}] Already in terminal state (${scan.status}) — skipping`);
    return;
  }

  if (scan.refinedReport) {
    console.log(`[Gemini][${scanId}] Already has refinedReport — skipping`);
    _markGeminiDone(scanId).catch(() => {});
    return;
  }

  // ── Readiness check ─────────────────────────────────────────────────────────
  const zapStatus      = scan.zapResult?.status;
  const webCheckStatus = scan.webCheckResult?.status;
  const zapDone        = ['completed', 'failed'].includes(zapStatus);
  const webChkDone     = ['completed', 'completed_partial', 'completed_with_errors', 'failed'].includes(webCheckStatus);

  if (!zapDone || !webChkDone) {
    console.log(`[Gemini][${scanId}] Not ready — ZAP: ${zapStatus}, WebCheck: ${webCheckStatus}`);
    return;
  }

  if (!scan.pagespeedResult && !scan.observatoryResult) {
    console.warn(`[Gemini][${scanId}] Missing fast-scan data — finishing with fallback`);
    await _finishWithFallback(scan, scanId, userId, 'Required scan data unavailable for AI analysis.');
    return;
  }

  // ── Acquire lock ────────────────────────────────────────────────────────────
  const lockAcquired = await _acquireGeminiLock(scanId);
  if (!lockAcquired) {
    console.log(`[Gemini][${scanId}] Lock already held — another process is generating`);
    return;
  }
  usedInMemoryLock = geminiInProgress.has(scanId);
  console.log(`[Gemini][${scanId}] Lock acquired (inMemory=${usedInMemoryLock}) — starting report generation`);

  try {
    // ── Emit 85% progress ─────────────────────────────────────────────────────
    await publishScanProgress(scanId, userId, {
      status: 'combining',
      progress: 85,
      message: 'Generating AI security report...'
    });

    // ── Build inputs ──────────────────────────────────────────────────────────
    // Sanitize scan before any data reaches Gemini — strips target URL, domain,
    // IPs, DNS records, user emails from the object graph. Original scan is NOT
    // mutated; all DB writes still use scan.
    const llmSafeScan = sanitizeScanForLLM(scan);

    const psiReport     = llmSafeScan.pagespeedResult?.error   ? null : llmSafeScan.pagespeedResult;
    const obsReport     = llmSafeScan.observatoryResult?.error ? null : llmSafeScan.observatoryResult;
    const urlscanReport = llmSafeScan.urlscanResult?.error     ? null : llmSafeScan.urlscanResult;

    // Apply plan-level severity filter BEFORE sending to AI.
    // getSanitizedZapReport filters alerts by the user's vulnerabilityAccessLevel;
    // sanitizeScanForLLM already stripped identity fields from llmSafeScan.zapResult.
    const zapCompleted = ['completed', 'completed_partial'].includes(zapStatus);
    const geminiAccessLevel = await resolveVulnAccessLevel(userId);
    const zapReport = zapCompleted
      ? getSanitizedZapReport(llmSafeScan.zapResult, geminiAccessLevel, llmSafeScan.target)
      : null;

    const webChkCompleted = ['completed', 'completed_partial', 'completed_with_errors'].includes(webCheckStatus);
    let webCheckReport = null;
    if (webChkCompleted) {
      try {
        console.log(`[Gemini][${scanId}] Loading WebCheck full results from DB/GridFS…`);
        const rawWebCheck = await getFullResults(scan.webCheckResult);
        if (rawWebCheck) {
          // Wrap in a minimal object so sanitizeScanForLLM can reach dns.a etc.
          const sanitizedWC = sanitizeScanForLLM({ webCheckResult: { fullResults: rawWebCheck } });
          webCheckReport = sanitizedWC?.webCheckResult?.fullResults || rawWebCheck;
        }
        console.log(`[Gemini][${scanId}] WebCheck results loaded`);
      } catch (e) {
        console.warn(`[Gemini][${scanId}] Could not load WebCheck full results:`, e.message);
      }
    }

    // ── Call Gemini ───────────────────────────────────────────────────────────
    let aiReport;
    const geminiStart = Date.now();
    console.log(`[Gemini][${scanId}] Calling refineReport — zapReport=${zapReport ? 'yes' : 'no'} webCheckReport=${webCheckReport ? 'yes' : 'no'}`);

    try {
      aiReport = await refineReport(
        null,
        psiReport,
        obsReport,
        llmSafeScan.target,   // "REDACTED"
        zapReport,
        urlscanReport,
        webCheckReport
      );
      console.log(`[Gemini][${scanId}] refineReport succeeded in ${((Date.now() - geminiStart) / 1000).toFixed(1)}s`);
    } catch (geminiErr) {
      const elapsed = ((Date.now() - geminiStart) / 1000).toFixed(1);
      console.error(`[Gemini][${scanId}] refineReport failed after ${elapsed}s:`, geminiErr.message);
      // Do NOT re-throw. Generate a structured report from raw scan data so the scan
      // always completes with meaningful content even when Gemini is unavailable.
      aiReport = _buildStructuredFallbackReport(scan, zapReport, webCheckReport);
      console.log(`[Gemini][${scanId}] Using structured fallback report (${aiReport.length} chars)`);
    }

    // ── Persist completed state ───────────────────────────────────────────────
    console.log(`[Gemini][${scanId}] Saving refinedReport and marking completed…`);
    const saved = await _dbUpdate(
      { analysisId: scanId, status: { $nin: ['stopped', 'cancelled'] } },
      { $set: { refinedReport: aiReport, status: 'completed', updatedAt: new Date() } },
      scanId,
      'save-report'
    );

    if (!saved) {
      // DB retries exhausted — the scan will stay in "combining".
      // The cleanup watchdog will rescue it within its next cycle.
      console.error(`[Gemini][${scanId}] CRITICAL: failed to persist refinedReport after retries. Scan may stay stuck.`);
      throw new Error('MongoDB update failed after all retries');
    }

    _markGeminiDone(scanId).catch(() => {});
    console.log(`[Gemini][${scanId}] ✅ Scan completed with AI report`);

    // ── Emit 100% progress ────────────────────────────────────────────────────
    await publishScanProgress(scanId, userId, {
      status: 'completed',
      progress: 100,
      message: 'Scan complete',
      aiReport
    });

    // ── Notifications ─────────────────────────────────────────────────────────
    handleScanComplete(scanId, userId, 'Combined Security Scan', scan.target);

  } catch (err) {
    // This outer catch only fires when something OUTSIDE the Gemini call throws
    // (e.g. Redis/MongoDB failure before generateContent, or the function timeout above).
    console.error(`[Gemini][${scanId}] Unexpected error during report generation:`, err.message);
    console.error(`[Gemini][${scanId}] Stack:`, err.stack);

    try {
      await _dbUpdate(
        { analysisId: scanId, status: { $nin: ['stopped', 'cancelled', 'completed'] } },
        { $set: { status: 'failed', updatedAt: new Date() } },
        scanId,
        'mark-failed'
      );
      await publishScanProgress(scanId, userId, {
        status: 'failed',
        progress: 0,
        error: err.message || 'Gemini completion failed'
      });
    } catch (updateErr) {
      console.error(`[Gemini][${scanId}] Failed to mark scan failed:`, updateErr.message);
    }
  } finally {
    if (usedInMemoryLock) {
      geminiInProgress.delete(scanId);
    }
  }
}

module.exports = { checkAndGenerateGemini };
