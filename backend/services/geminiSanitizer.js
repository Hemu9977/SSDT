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
 *   Security header NAMES (presence/absence of CSP, HSTS, X-Frame-Options, etc.)
 *   urlscan threat / malicious scores and aggregate request counts
 *
 * Fields SANITIZED IN PLACE (structure kept, embedded identity stripped):
 *   HTTP response header VALUES — see sanitizeHeadersForLLM(). Header names are
 *   safe technology signal, but values can embed the target's own hostname
 *   (Content-Security-Policy directives, Set-Cookie Domain=, Location /
 *   Content-Location / Refresh redirect targets). Structurally identity-bearing
 *   headers (Set-Cookie, Location, Content-Location, Refresh) are fully
 *   redacted; all other header values have embedded URLs/IPs/hostnames
 *   scrubbed while directives, flags, and numeric settings (max-age, etc.)
 *   are preserved.
 */

const REDACTED = 'REDACTED';

// ── IPv4 / IPv6 patterns used by the text-level sanitizers ───────────────────
const IPV4_PATTERN = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const IPV6_PATTERN = /\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
const URL_PATTERN  = /https?:\/\/[^\s"'<>)\]]+/gi;

// Bare hostname with no scheme (e.g. a CSP `default-src` token like
// "cdn.example.com"). The final label is required to be alphabetic so this
// does not match version strings like "1.19.0" (Server: nginx/1.19.0) or
// other dotted numeric tokens that are safe technology info.
const BARE_DOMAIN_PATTERN = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g;

// Header names whose VALUE is structurally identity-bearing regardless of
// whether it happens to match a URL/hostname pattern — e.g. a Set-Cookie
// value can carry a session token plus "Domain=" without ever containing
// "http://". The whole value is redacted rather than pattern-scrubbed.
const FULL_REDACT_HEADER_NAMES = new Set([
  'set-cookie', 'set-cookie2', 'location', 'content-location', 'refresh',
]);

/** Strip URLs, IPs, and bare hostnames from a single string value. */
function _scrubIdentityTokens(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(URL_PATTERN, REDACTED)
    .replace(IPV4_PATTERN, REDACTED)
    .replace(IPV6_PATTERN, REDACTED)
    .replace(BARE_DOMAIN_PATTERN, REDACTED);
}

/**
 * Sanitize an HTTP response-headers object (header-name -> value, as returned
 * by the WebCheck `headers` sub-scan) before it reaches an LLM prompt.
 *
 * Called from sanitizeScanForLLM() for both `webCheckResult.headers` and
 * `webCheckResult.fullResults.headers` — see the callers of this function for
 * every path that must stay covered if the WebCheck result shape changes.
 *
 * @param {Object|null} headers  header-name -> value (or value[]) map
 * @returns {Object|null}        new object; input is never mutated
 */
function sanitizeHeadersForLLM(headers) {
  if (!headers || typeof headers !== 'object') return headers;
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    const key = String(name).toLowerCase();
    if (FULL_REDACT_HEADER_NAMES.has(key)) {
      out[name] = Array.isArray(value) ? [REDACTED] : REDACTED;
    } else if (Array.isArray(value)) {
      out[name] = value.map(_scrubIdentityTokens);
    } else {
      out[name] = _scrubIdentityTokens(value);
    }
  }
  return out;
}

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

    // HTTP response headers — values can embed the target's own domain via
    // CSP, Set-Cookie, or Location even though header presence/names are safe
    // technology signal. Covers both the inline and fullResults-nested shape,
    // matching every path getFullResults()/GridFS results can take.
    if (safe.webCheckResult.headers) {
      safe.webCheckResult.headers = sanitizeHeadersForLLM(safe.webCheckResult.headers);
    }
    if (safe.webCheckResult.fullResults?.headers) {
      safe.webCheckResult.fullResults.headers = sanitizeHeadersForLLM(safe.webCheckResult.fullResults.headers);
    }
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
 * Resolve the guardrail mode from the environment.
 *   'throw' — GEMINI_STRICT_GUARDRAIL='true': hard-fail on a hit, before the
 *             Gemini call is made (CI / controlled environments where every
 *             caller is known to avoid legitimate-URL fields)
 *   'warn'  — default in EVERY environment, including production: log a clear,
 *             non-fatal warning on a hit so leakage is never silent
 *   'off'   — GEMINI_STRICT_GUARDRAIL='false' (explicit opt-out only)
 *
 * Why is 'warn' the default everywhere (not 'throw')? ZAP's `alert.reference`
 * field is copied verbatim from ZAP's own knowledge base and legitimately
 * contains external documentation URLs (OWASP, CWE, etc.) — it is sent as-is
 * to formatScanDataForPdf() by design (see geminiSanitizer.js module docstring,
 * "PRESERVED" fields). A hard throw by default would fail nearly every PDF
 * generation call that includes ZAP findings, which is not an acceptable
 * trade-off for a check with no vendor-specific allowlist. 'warn' still runs
 * unconditionally and logs every hit, closing the previous gap where
 * production ran the check in 'off' mode and detected leakage was invisible
 * unless someone had already opted in with GEMINI_STRICT_GUARDRAIL=true.
 * Set GEMINI_STRICT_GUARDRAIL=true to upgrade to hard-fail once a given
 * deployment's prompts are known not to carry legitimate reference URLs.
 *
 * @returns {'throw'|'warn'|'off'}
 */
function _guardrailMode() {
  const flag = process.env.GEMINI_STRICT_GUARDRAIL;
  if (flag === 'true')  return 'throw';
  if (flag === 'false') return 'off';
  return 'warn';
}

/**
 * Pre-flight guardrail validator. MUST be called — and is called, from
 * _generate() in geminiService.js — before the Gemini API request is issued,
 * so a 'throw' hit prevents the prompt from ever leaving the process.
 *
 * Detects whether a prompt string still contains a live URL or IP after
 * sanitization. Behaviour depends on the resolved mode (see _guardrailMode()).
 * ~0 performance overhead when 'off' (env check exits immediately).
 *
 * Log safety: the matched leak text itself is NEVER written to logs or into
 * the thrown Error's message — only its kind (URL/IP), length, and offset
 * within the prompt. A log line that echoed the leaked domain/IP back out
 * would just be a second copy of the same leak.
 *
 * @param {string} prompt    The full prompt string about to be sent to Gemini
 * @param {string} context   Human-readable label for error messages (function name)
 */
function assertNoLeakage(prompt, context = '') {
  const mode = _guardrailMode();
  if (mode === 'off') return;

  // Match URLs that are NOT the literal string "REDACTED"
  const urlMatch = prompt.match(/https?:\/\/(?!REDACTED[^a-z])[^\s"'<>]{4,}/i);
  // Match IPv4 that are NOT preceded by "REDACTED"
  const ipMatch  = prompt.match(/(?<!REDACTED\s*)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);

  if (!urlMatch && !ipMatch) return;

  const hits = [];
  if (urlMatch) hits.push(`URL-like token (length ${urlMatch[0].length}) at offset ${urlMatch.index}`);
  if (ipMatch)  hits.push(`IPv4-like token at offset ${ipMatch.index}`);

  const msg =
    `[GEMINI GUARDRAIL] Potential identity leakage detected in Gemini prompt ` +
    `(context: ${context}, mode: ${mode}). ${hits.join('; ')}. ` +
    `Prompt length: ${prompt.length} chars. Matched value withheld from this log.`;

  if (mode === 'throw') {
    // Thrown before any network call — the caller (_generate) has not yet
    // invoked ai.models.generateContent() at this point.
    throw new Error(msg);
  }
  // 'warn' — never blocks the request, but always logs at error level so the
  // hit is visible in production log aggregation, not just dev consoles.
  console.error(`⚠️  ${msg}`);
}

module.exports = {
  sanitizeScanForLLM,
  sanitizeHeadersForLLM,
  sanitizeHistoryRowsForLLM,
  sanitizeTextsForLLM,
  sanitizeRefinedReportForLLM,
  assertNoLeakage,
  REDACTED,
  // exported for unit tests only
  _guardrailMode,
};
