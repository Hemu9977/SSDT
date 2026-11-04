'use strict';

/**
 * Reads a scan's ZAP detailed-alerts file (GridFS) for a report without loading
 * the whole file.
 *
 * The file is `JSON.stringify(detailedAlerts)`: an array of alerts, each holding
 * EVERY occurrence with its raw HTTP request and response. On a large site that is
 * hundreds of MB — a production scan's was 287 MB. Downloading it into one Buffer
 * and JSON.parse-ing it took more than the 2 GB heap when a PDF and a JSON export
 * did it at once, and blocked the event loop long enough that the load balancer
 * took the backend task out of service mid-PDF.
 *
 * A report draws a handful of occurrences per finding, so this streams the file,
 * parses one occurrence at a time, and keeps only those `selectOccurrence` asks
 * for. Memory is bounded by the largest single occurrence, and the event loop
 * runs between GridFS chunks.
 */

const gridfsService = require('./gridfsService');

const QUOTE = 0x22, BACKSLASH = 0x5c, COLON = 0x3a, COMMA = 0x2c;
const LBRACE = 0x7b, RBRACE = 0x7d, LBRACKET = 0x5b, RBRACKET = 0x5d;
const isWhitespace = (b) => b === 0x20 || b === 0x0a || b === 0x0d || b === 0x09;
const KEY_MAX_BYTES = 64;

/**
 * Incremental parser for `[ {alert…, "occurrences": [ occ, occ, … ] }, … ]`.
 *
 * Works on raw bytes: every JSON structural character is ASCII and no byte of a
 * multi-byte UTF-8 sequence is, so chunk boundaries and non-ASCII text are safe.
 *
 * @param {(occ: object, index: number, state: object) => object|null} selectOccurrence
 *   called for every occurrence in order; returns what to keep (or null). `state`
 *   is a fresh object per alert for the selector's own bookkeeping.
 * @param {(alert: object, state: object) => void} [finishAlert] called once per
 *   alert after its occurrences, with the same `state`.
 * @returns {{ write(chunk: Buffer): void, end(): object[] }} end() returns the
 *   alerts with `occurrences` = the kept ones and `occurrenceCount` = all of them.
 */
function createDetailedAlertsParser(selectOccurrence, finishAlert = () => {}) {
  const alerts = [];
  let depth = 0;
  let inString = false, escaped = false, done = false;
  let keyBytes = null, lastKey = null, currentKey = null;

  let inAlert = false, skeleton = [], skeletonFrom = -1;
  let inOccurrences = false, occActive = false, occPieces = [], occFrom = -1;
  let kept = [], occIndex = 0, selectorState = {};

  function finishOccurrence(chunk, end) {
    occPieces.push(chunk.subarray(occFrom, end));
    const occ = JSON.parse(Buffer.concat(occPieces).toString('utf8'));
    occPieces = []; occFrom = -1; occActive = false;
    const keep = selectOccurrence(occ, occIndex++, selectorState);
    if (keep != null) kept.push(keep);
  }

  function write(chunk) {
    if (done) return;
    for (let i = 0; i < chunk.length; i++) {
      const b = chunk[i];

      if (inString) {
        if (escaped) escaped = false;
        else if (b === BACKSLASH) escaped = true;
        else if (b === QUOTE) {
          inString = false;
          if (keyBytes) { lastKey = keyBytes.length > KEY_MAX_BYTES ? null : Buffer.from(keyBytes).toString('utf8'); keyBytes = null; }
          continue;
        }
        if (keyBytes && keyBytes.length <= KEY_MAX_BYTES) keyBytes.push(b);
        continue;
      }
      if (isWhitespace(b)) continue;

      if (inOccurrences && depth === 3 && !occActive && b !== COMMA && b !== RBRACKET) {
        occActive = true; occFrom = i; occPieces = [];
      }

      if (b === QUOTE) {
        inString = true;
        keyBytes = (inAlert && depth === 2) ? [] : null;
      } else if (b === COLON) {
        if (inAlert && depth === 2) currentKey = lastKey;
      } else if (b === COMMA) {
        if (inOccurrences && depth === 3 && occActive) finishOccurrence(chunk, i);
      } else if (b === LBRACE || b === LBRACKET) {
        if (depth === 0 && b !== LBRACKET) throw new Error('detailed alerts file is not a JSON array');
        if (depth === 1 && b === LBRACE) {
          inAlert = true; skeleton = []; skeletonFrom = i;
          kept = []; occIndex = 0; selectorState = {}; currentKey = null;
        } else if (inAlert && depth === 2 && b === LBRACKET && currentKey === 'occurrences') {
          // Leave the occurrences out of the alert's own text; they are parsed one by one.
          skeleton.push(Buffer.from(chunk.subarray(skeletonFrom, i + 1)));
          skeletonFrom = -1; inOccurrences = true;
        }
        depth++;
      } else if (b === RBRACE || b === RBRACKET) {
        if (inOccurrences && depth === 3) {
          if (occActive) finishOccurrence(chunk, i);
          inOccurrences = false; skeletonFrom = i;
        }
        depth--;
        if (inAlert && depth === 1) {
          skeleton.push(Buffer.from(chunk.subarray(skeletonFrom, i + 1)));
          const alert = JSON.parse(Buffer.concat(skeleton).toString('utf8'));
          alert.occurrences = kept;
          alert.occurrenceCount = occIndex;
          finishAlert(alert, selectorState);
          alerts.push(alert);
          inAlert = false; skeleton = []; skeletonFrom = -1;
        }
        if (depth === 0) { done = true; return; }
      }
    }
    // Carry the open captures over to the next chunk.
    if (skeletonFrom >= 0) { skeleton.push(Buffer.from(chunk.subarray(skeletonFrom))); skeletonFrom = 0; }
    if (occActive) { occPieces.push(chunk.subarray(occFrom)); occFrom = 0; }
  }

  function end() {
    if (!done) throw new Error('detailed alerts file ended before its closing bracket');
    return alerts;
  }

  return { write, end };
}

/** Parse a whole readable stream with createDetailedAlertsParser. */
async function readDetailedAlerts(stream, selectOccurrence, finishAlert) {
  const parser = createDetailedAlertsParser(selectOccurrence, finishAlert);
  for await (const chunk of stream) parser.write(chunk);
  return parser.end();
}

// ─── What each view keeps ───────────────────────────────────────────────────────

// PDF: it lists the first 10 occurrence URLs and draws the raw request/response of
// the first 3 occurrences that have one (pdfService renderVulnerabilityDetailsSection).
// It draws a 600-character body snippet (buildEvidenceText) and checks the first
// 2048 characters for binary content, so nothing past 4096 characters is used.
const REPORT_LIMITS = { sampleUrls: 10, evidence: 3, bodyMaxChars: 4096 };
// Scan page evidence panel (ZapReportEnhanced): shows 3 pairs per finding, more on
// request. Everything beyond this is in the JSON report, which the panel says.
const EVIDENCE_LIMITS = { sampleUrls: 0, evidence: 10, bodyMaxChars: 32768 };

const hasRawEvidence = (occ) => !!(occ && (occ.request || occ.response));

function trimPart(part, maxChars) {
  if (!part || typeof part !== 'object' || typeof part.body !== 'string' || part.body.length <= maxChars) return part;
  return { ...part, body: part.body.slice(0, maxChars), bodyTruncated: true };
}

/**
 * Keeps the first `sampleUrls` occurrences and the first `evidence` occurrences
 * with raw request/response, bodies cut to `bodyMaxChars` (marked bodyTruncated).
 * Counts every occurrence with raw evidence, for "N more in the JSON export".
 */
function occurrenceSelector({ sampleUrls, evidence, bodyMaxChars }) {
  return (occ, index, state) => {
    const raw = hasRawEvidence(occ);
    if (raw) state.raw = (state.raw || 0) + 1;
    const wanted = index < sampleUrls || (raw && (state.rawKept || 0) < evidence);
    if (!wanted) return null;
    if (raw) state.rawKept = (state.rawKept || 0) + 1;
    if (!occ || typeof occ !== 'object') return occ;
    return { ...occ, request: trimPart(occ.request, bodyMaxChars), response: trimPart(occ.response, bodyMaxChars) };
  };
}

/** Parse with `limits`; each alert also gets `rawOccurrenceCount`. */
function readAlerts(stream, limits) {
  return readDetailedAlerts(stream, occurrenceSelector(limits), (alert, state) => {
    alert.rawOccurrenceCount = state.raw || 0;
  });
}

const readReportAlerts = (stream) => readAlerts(stream, REPORT_LIMITS);

// Concurrent and back-to-back reads of the same scan (EN and JA PDFs, a retry,
// reopening the scan) share one read instead of each streaming the file again.
const CACHE_TTL_MS = 5 * 60 * 1000;
const cache = new Map();

function loadCached(fileId, bucket, view, limits, deps) {
  const openStream = deps.openStream || ((id, b) => gridfsService.downloadFileStream(id, b));
  const key = `${view}:${bucket}:${fileId}`;
  if (cache.has(key)) return cache.get(key);

  const started = Date.now();
  const promise = readAlerts(openStream(fileId, bucket), limits).then(
    (alerts) => {
      const occurrences = alerts.reduce((n, a) => n + a.occurrenceCount, 0);
      console.log(`[ZapAlerts] Read ${alerts.length} alerts (${occurrences} occurrences) for ${key} in ${Date.now() - started}ms`);
      setTimeout(() => cache.delete(key), CACHE_TTL_MS).unref();
      return alerts;
    },
    (err) => { cache.delete(key); throw err; }
  );
  cache.set(key, promise);
  return promise;
}

/**
 * Every alert in a detailed-alerts file in GridFS, with only the occurrences a PDF
 * draws. Callers must not mutate the returned alerts (they are shared).
 */
function loadReportAlerts(fileId, bucket, deps = {}) {
  return loadCached(fileId, bucket, 'report', REPORT_LIMITS, deps);
}

/** As loadReportAlerts, with what the scan page's evidence panel shows. */
function loadEvidenceAlerts(fileId, bucket, deps = {}) {
  return loadCached(fileId, bucket, 'evidence', EVIDENCE_LIMITS, deps);
}

/** Bucket holding a detailed-alerts file, from its name. */
function detailedAlertsBucket(file) {
  return file?.filename?.includes('zap_auth') ? 'zap_auth_reports' : 'zap_reports';
}

module.exports = {
  createDetailedAlertsParser,
  readDetailedAlerts,
  readReportAlerts,
  loadReportAlerts,
  loadEvidenceAlerts,
  detailedAlertsBucket,
  REPORT_LIMITS,
  EVIDENCE_LIMITS,
  _cache: cache,
};
