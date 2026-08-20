'use strict';

/**
 * geminiSanitizer.js
 * Centralized sanitization layer for all Gemini API inputs.
 *
 * MUST be called before any data is passed to geminiService functions.
 *
 * NOT enforced at the geminiService boundary — this is a caller contract, not a
 * guarantee. `refineReport()` and `formatScanDataForPdf()` read `target`,
 * `analysisId` and urlscan fields straight off their argument and will happily
 * send an unsanitized object. Both live callers do sanitize first
 * (geminiCompletionService.js and pdfService.js each call sanitizeScanForLLM),
 * but nothing stops a future caller from skipping it. The only automatic net is
 * assertNoLeakage() in _generate(), which by default warns rather than blocks.
 * Treat that as detection, not prevention.
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

// IPv6, including zero-compression. The previous pattern was
// /\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/ which required a FULLY
// EXPANDED address, so every compressed form — `::1`, `fe80::1`,
// `2001:db8::1`, `::ffff:192.0.2.1`, i.e. how IPv6 is actually written —
// passed through unredacted, and partially compressed addresses matched only a
// substring and came out mangled as `REDACTED::REDACTED`.
// It also matched any `h:h:h` sequence, so it redacted clock times and HTTP
// `Date` header values (`12:30:45`, `Mon, 01 Jan 2024 10:20:30 GMT`).
// Built by alternation: 8 full groups, or a form containing `::`. Every
// quantifier is bounded, so there is no catastrophic backtracking.
const _H6 = '[0-9a-fA-F]{1,4}';
const _V4_IN_V6 =
  '(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}';
const IPV6_PATTERN = new RegExp(
  '(?<![0-9a-fA-F:.])(?:' +
    `(?:${_H6}:){7}${_H6}` + '|' +
    `(?:${_H6}:){1,7}:` + '|' +
    `(?:${_H6}:){1,6}:${_H6}` + '|' +
    `(?:${_H6}:){1,5}(?::${_H6}){1,2}` + '|' +
    `(?:${_H6}:){1,4}(?::${_H6}){1,3}` + '|' +
    `(?:${_H6}:){1,3}(?::${_H6}){1,4}` + '|' +
    `(?:${_H6}:){1,2}(?::${_H6}){1,5}` + '|' +
    `${_H6}:(?::${_H6}){1,6}` + '|' +
    `:(?:(?::${_H6}){1,7}|:)` + '|' +
    `::(?:ffff(?::0{1,4})?:)?${_V4_IN_V6}` + '|' +
    `(?:${_H6}:){1,4}:${_V4_IN_V6}` +
  ')(?:%[0-9a-zA-Z._-]+)?(?![0-9a-fA-F:.])',
  'gi'
);

const URL_PATTERN  = /https?:\/\/[^\s"'<>)\]]+/gi;

// Email addresses. BARE_DOMAIN_PATTERN alone only removed the domain half,
// leaving `admin@REDACTED` — and the local part is usually a real username.
// Matched before BARE_DOMAIN so the whole address goes at once.
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;

// Bare hostname with no scheme (e.g. a CSP `default-src` token like
// "cdn.example.com"). The final label is required to be alphabetic so this
// does not match version strings like "1.19.0" (Server: nginx/1.19.0) or
// other dotted numeric tokens that are safe technology info.
const BARE_DOMAIN_PATTERN = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g;

// Header names whose VALUE is structurally identity-bearing regardless of
// whether it happens to match a URL/hostname pattern — e.g. a Set-Cookie
// value can carry a session token plus "Domain=" without ever containing
// "http://". The whole value is redacted rather than pattern-scrubbed.
// The host-ish names below carry a bare infrastructure hostname with no dot
// and no scheme — `backend-prod-01`, `zap-auth`, an ECS Service Connect name.
// BARE_DOMAIN_PATTERN cannot catch those because it requires a dot, and a
// blanket "redact any single word" rule is not an option: it would also strip
// `nginx`, `apache`, `cloudflare` from Server/Via, destroying exactly the
// technology information this module deliberately PRESERVES. Redacting the
// whole value of the headers that structurally hold a host is the targeted fix.
const FULL_REDACT_HEADER_NAMES = new Set([
  'set-cookie', 'set-cookie2', 'location', 'content-location', 'refresh',
  'host', 'x-forwarded-host', 'x-forwarded-for', 'x-real-ip',
  'x-served-by', 'x-backend-server', 'x-host', 'origin', 'referer',
]);

/**
 * Ordered token scrub, shared by every text-level sanitizer in this module so
 * the passes cannot drift apart.
 *
 * Order is load-bearing:
 *   1. URL first — a URL contains a host and may contain an IP.
 *   2. Email before BARE_DOMAIN, which would otherwise consume only the domain
 *      half and leave `admin@REDACTED`, i.e. the username still in the clear.
 *   3. IPv6 BEFORE IPv4 — on an IPv4-mapped address such as `::ffff:192.0.2.1`
 *      the IPv4 pass would otherwise eat the tail first and leave a dangling
 *      `::ffff:` prefix.
 *
 * @param {*} value                   value to scrub (non-strings pass through)
 * @param {boolean} includeBareDomain whether to also strip dotted hostnames
 */
function _scrubTokens(value, includeBareDomain) {
  if (typeof value !== 'string') return value;
  const out = value
    .replace(URL_PATTERN, REDACTED)
    .replace(EMAIL_PATTERN, REDACTED)
    .replace(IPV6_PATTERN, REDACTED)
    .replace(IPV4_PATTERN, REDACTED);
  return includeBareDomain ? out.replace(BARE_DOMAIN_PATTERN, REDACTED) : out;
}

/** Strip URLs, emails, IPs, and bare hostnames from a single string value. */
function _scrubIdentityTokens(value) {
  return _scrubTokens(value, true);
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
  // Bare dotted hostnames are deliberately NOT stripped here: this path
  // translates arbitrary UI copy, and redacting every domain-shaped token
  // would mangle legitimate prose. URLs, emails and IPs are unambiguous.
  return texts.map(t => _scrubTokens(t, false));
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
  // Same reasoning as sanitizeTextsForLLM: this is generated prose, so dotted
  // hostnames are left alone to avoid mangling the report body.
  return _scrubTokens(reportText, false);
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
let _warnedAboutFlag = false;

function _guardrailMode() {
  const flag = process.env.GEMINI_STRICT_GUARDRAIL;
  if (flag === undefined || flag === '') return 'warn';

  const normalized = String(flag).trim().toLowerCase();
  if (normalized === 'true')  return 'throw';
  if (normalized === 'false') return 'off';

  // Anything else used to fall silently through to 'warn'. An operator who set
  // GEMINI_STRICT_GUARDRAIL=TRUE or =1 intending to harden the guardrail got
  // the non-blocking default instead, with nothing anywhere saying so. Warn
  // once, then use the safe default.
  if (!_warnedAboutFlag) {
    _warnedAboutFlag = true;
    console.error(
      `[GEMINI GUARDRAIL] Unrecognised GEMINI_STRICT_GUARDRAIL value ${JSON.stringify(flag)} — ` +
      `expected 'true' or 'false'. Falling back to 'warn' (check runs, never blocks).`
    );
  }
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

  // This backstop used to check only URLs and IPv4, which left it blind to
  // exactly the shapes the sanitizer was also missing — a leaked `fe80::1`
  // sailed through even with GEMINI_STRICT_GUARDRAIL=true. A guardrail that
  // cannot see what its sanitizer misses is not a second line of defence.
  // A bare `::` is not a leak, so require the match to carry a hex quartet.
  let ipv6Match = prompt.match(new RegExp(IPV6_PATTERN.source, 'i'));
  if (ipv6Match && !/[0-9a-f]/i.test(ipv6Match[0])) ipv6Match = null;

  const emailMatch = prompt.match(new RegExp(EMAIL_PATTERN.source));

  if (!urlMatch && !ipMatch && !ipv6Match && !emailMatch) return;

  const hits = [];
  if (urlMatch)   hits.push(`URL-like token (length ${urlMatch[0].length}) at offset ${urlMatch.index}`);
  if (ipMatch)    hits.push(`IPv4-like token at offset ${ipMatch.index}`);
  if (ipv6Match)  hits.push(`IPv6-like token (length ${ipv6Match[0].length}) at offset ${ipv6Match.index}`);
  if (emailMatch) hits.push(`email-like token (length ${emailMatch[0].length}) at offset ${emailMatch.index}`);

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
