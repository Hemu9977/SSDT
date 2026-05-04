'use strict';

/**
 * geminiSanitizer.js
 * Centralized sanitization layer for all Gemini API inputs.
 *
 * MUST be called before any data is passed to geminiService functions.
 * Enforced at the geminiService boundary so every future call is protected.
 *
 * Redaction contract:
 *   - All redacted fields are replaced with the string "REDACTED"
 *   - Structure is preserved so prompt templates never break
 *   - No field is deleted; absence would cause template interpolation errors
 *   - The original object is never mutated (deep-clone is used internally)
 *
 * Fields REDACTED (never sent to Gemini):
 *   target / url / hostname / FQDN
 *   IP addresses (IPv4 + IPv6), DNS A / AAAA record arrays
 *   analysisId / scanId (UUID that links to a customer scan)
 *   executedBy / executor / createdBy / any user email
 *   ZAP per-occurrence url and other (often contains URLs)
 *   urlscan page.domain, page.ip, page.country
 *
 * Fields PRESERVED (safe, technology-level intelligence):
 *   ZAP alert names, risk, description, solution, CWE / WASC IDs
 *   PageSpeed / Core Web Vitals scores
 *   Observatory grade, test counts
 *   Server type (nginx, Apache) — technology, not identity
 *   WAF vendor (Cloudflare, Akamai) — technology, not identity
 *   Technology stack list
 *   TLS protocol, cipher suite, grade
 *   Security header names and values
 *   urlscan threat / malicious scores and aggregate request counts
 */

const REDACTED = 'REDACTED';

// ── IPv4 / IPv6 patterns used by the text-level sanitizers ───────────────────
const IPV4_PATTERN = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const IPV6_PATTERN = /\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
const URL_PATTERN  = /https?:\/\/[^\s"'<>)\]]+/gi;

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Primary sanitizer.
 * Call this before refineReport(), formatScanDataForPdf(),
 * translateToJapanese(), and formatAiAnalysisForPdf().
 *
 * @param {Object|null} scanResult  Raw MongoDB ScanResult document or plain object
 * @returns {Object|null}           Deep-cloned, sanitized payload safe for LLM ingestion
 */
function sanitizeScanForLLM(scanResult) {
  if (!scanResult) return null;

  // Deep clone — never mutate the original Mongoose document
  const safe = JSON.parse(JSON.stringify(scanResult));

  // ── Top-level identity fields ─────────────────────────────────────────────
  safe.target     = REDACTED;   // C-01, C-05 — full company URL
  safe.analysisId = REDACTED;   // C-05, L-05 — internal scan UUID

  // ── urlscan page block ────────────────────────────────────────────────────
  if (safe.urlscanResult?.page) {
    safe.urlscanResult.page.domain  = REDACTED;   // C-02, M-08
    safe.urlscanResult.page.ip      = REDACTED;   // C-03, M-08
    safe.urlscanResult.page.country = REDACTED;   // medium risk — geolocation
    // .server, .tlsIssuer, .tlsProtocol preserved — technology info only
  }

  // Raw IP lists inside the urlscan lists block (if present)
  if (Array.isArray(safe.urlscanResult?.lists?.ips)) {
    safe.urlscanResult.lists.ips = [REDACTED];
  }
  if (Array.isArray(safe.urlscanResult?.lists?.urls)) {
    // Full URL list — each entry exposes the target domain
    safe.urlscanResult.lists.urls = [REDACTED];
  }
  if (Array.isArray(safe.urlscanResult?.lists?.domains)) {
    safe.urlscanResult.lists.domains = [REDACTED];
  }

  // ── WebCheck DNS A / AAAA records ─────────────────────────────────────────
  if (safe.webCheckResult) {
    // Top-level dns field (if present)
    if (safe.webCheckResult.dns?.a)    safe.webCheckResult.dns.a    = [REDACTED]; // C-04
    if (safe.webCheckResult.dns?.aaaa) safe.webCheckResult.dns.aaaa = [REDACTED];

    // fullResults may nest its own dns block
    if (safe.webCheckResult.fullResults?.dns?.a)    safe.webCheckResult.fullResults.dns.a    = [REDACTED];
    if (safe.webCheckResult.fullResults?.dns?.aaaa) safe.webCheckResult.fullResults.dns.aaaa = [REDACTED];
  }

  // ── ZAP alert occurrence URLs ─────────────────────────────────────────────
  // Alert names, descriptions, solutions, CWE IDs are preserved.
  // Only the per-instance URL field (and 'other' which may embed URLs) is stripped.
  const _redactAlerts = (alerts) => {
    if (!Array.isArray(alerts)) return alerts;
    return alerts.map(alert => {
      const out = { ...alert };
      out.url   = REDACTED;   // occurrence URL contains target domain
      if (out.other) out.other = REDACTED;   // sometimes contains URLs
      // Redact occurrence-level instance arrays that embed per-URL data
      if (Array.isArray(out.instances)) {
        out.instances = out.instances.map(inst => ({
          ...inst,
          uri: REDACTED,
          param: inst.param,   // parameter names preserved
          evidence: inst.evidence,
          attack: inst.attack,
        }));
      }
      if (Array.isArray(out.occurrences)) {
        out.occurrences = out.occurrences.map(occ => ({
          ...occ,
          url: REDACTED,
        }));
      }
      if (Array.isArray(out.sampleUrls)) {
        out.sampleUrls = [REDACTED];
      }
      return out;
    });
  };

  if (safe.zapResult?.alerts) {
    safe.zapResult.alerts = _redactAlerts(safe.zapResult.alerts);
  }
  if (safe.authScanResult?.alerts) {
    safe.authScanResult.alerts = _redactAlerts(safe.authScanResult.alerts);
  }

  // ── User / executor identity ──────────────────────────────────────────────
  if (safe.executedBy)  safe.executedBy  = REDACTED;   // M-01
  if (safe.executor)    safe.executor    = REDACTED;
  if (safe.createdBy)   safe.createdBy   = REDACTED;

  // Nested userId populated fields (Mongoose populate result)
  if (safe.userId && typeof safe.userId === 'object') {
    if (safe.userId.email) safe.userId.email = REDACTED;
    if (safe.userId.name)  safe.userId.name  = REDACTED;
  }

  return safe;
}

/**
 * Sanitizer for scan history rows passed to formatScanHistoryForPdf().
 * Strips user email from executedBy fields while keeping dates and status.
 *
 * @param {Array} rows   Array of row objects built by pdfService.fetchScanHistoryRows()
 * @returns {Array}      Sanitized rows (new array; originals are not mutated)
 */
function sanitizeHistoryRowsForLLM(rows) {
  if (!Array.isArray(rows)) return rows;
  return rows.map(row => ({
    ...row,
    executedByEn: REDACTED,   // M-01 — user email
    executedByJa: REDACTED,
  }));
}

/**
 * Sanitizer for freeform text arrays (used by the /api/translate endpoint).
 * Replaces anything that looks like a URL or IP address with REDACTED.
 *
 * @param {Array<string>} texts   User-supplied text strings
 * @returns {Array<string>}       Sanitized copy
 */
function sanitizeTextsForLLM(texts) {
  if (!Array.isArray(texts)) return texts;
  return texts.map(t => {
    if (typeof t !== 'string') return t;
    return t
      .replace(URL_PATTERN, REDACTED)
      .replace(IPV4_PATTERN, REDACTED)
      .replace(IPV6_PATTERN, REDACTED);
  });
}

/**
 * Sanitizer for AI-generated report text before re-sending to Gemini.
 * The refinedReport stored in MongoDB may contain the company URL embedded
 * in prose (because refineReport() included it in the original prompt).
 * This strips URLs and IPs from the markdown string before the second pass.
 *
 * @param {string} reportText  The stored refinedReport markdown
 * @returns {string}           Sanitized markdown
 */
function sanitizeRefinedReportForLLM(reportText) {
  if (typeof reportText !== 'string') return reportText;
  return reportText
    .replace(URL_PATTERN, REDACTED)
    .replace(IPV4_PATTERN, REDACTED)
    .replace(IPV6_PATTERN, REDACTED);
}

/**
 * Pre-flight guardrail validator.
 * Throws if a prompt string contains what appears to be a live URL or IP address.
 * Only active when GEMINI_STRICT_GUARDRAIL=true in environment.
 * ~0 performance overhead in production (env check exits immediately).
 *
 * @param {string} prompt    The full prompt string about to be sent to Gemini
 * @param {string} context   Human-readable label for error messages (function name)
 */
function assertNoLeakage(prompt, context = '') {
  if (process.env.GEMINI_STRICT_GUARDRAIL !== 'true') return;

  // Match URLs that are NOT the literal string "REDACTED"
  const urlHit = /https?:\/\/(?!REDACTED[^a-z])[^\s"'<>]{4,}/i.test(prompt);
  // Match IPv4 that are NOT preceded by "REDACTED"
  const ipHit  = /(?<!REDACTED\s*)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(prompt);

  if (urlHit || ipHit) {
    const snippet = prompt.slice(0, 400);
    throw new Error(
      `[GEMINI GUARDRAIL] Potential identity leakage detected in Gemini prompt (context: ${context}).\n` +
      `Snippet (first 400 chars): ${snippet}`
    );
  }
}

module.exports = {
  sanitizeScanForLLM,
  sanitizeHistoryRowsForLLM,
  sanitizeTextsForLLM,
  sanitizeRefinedReportForLLM,
  assertNoLeakage,
  REDACTED,
};
