'use strict';

/**
 * pdfJobStore.js
 * Pure decision logic for the async PDF-job flow (routes/virustotalRoutes.js).
 * No I/O here — Redis/GridFS live in the route — so these functions are unit-testable.
 *
 * Durability model:
 *   - Small job metadata lives in Redis (pdf:job:{jobId}, 24h TTL).
 *   - The multi-MB PDF itself lives in GridFS (bucket PDF_BUCKET), NOT Redis, so it
 *     can't be evicted/OOM-rejected like a large Redis value.  meta.bufferFileId
 *     points to the GridFS file.
 */

const PDF_BUCKET = 'pdf_reports';
const DEFAULT_JOB_TIMEOUT_MS = 300000; // 5 min — mirrors PDF_JOB_TIMEOUT_MS in the route

/**
 * Decide the HTTP response for a status poll, given the (already access-checked)
 * job metadata and whether its stored PDF file still exists.
 *
 * @returns {{code:number, kind:string, body?:object, streamFileId?:string}}
 *   kind ∈ not_found | processing | timeout | failed | expired | completed | unknown
 *   For `completed`, the caller streams the file identified by streamFileId.
 */
function resolvePdfJobResponse(meta, fileExists, now = Date.now(), timeoutMs = DEFAULT_JOB_TIMEOUT_MS) {
  if (!meta) {
    return { code: 404, kind: 'not_found', body: { error: 'Job not found or expired' } };
  }

  if (meta.status === 'pending' || meta.status === 'processing') {
    // Only a job with a real timestamp can be judged stale — never declare a
    // timestamp-less job "timed out" (now - 0 would falsely exceed the window).
    const ts = meta.lastUpdated || meta.createdAt;
    if (ts && (now - ts) > timeoutMs) {
      return { code: 500, kind: 'timeout', body: { status: 'failed', error: 'PDF generation timed out (orphaned)' } };
    }
    return { code: 202, kind: 'processing', body: { status: meta.status } };
  }

  if (meta.status === 'failed') {
    const code = meta.errorCode === 'GEMINI_KEY_EXHAUSTED' ? 429 : 500;
    return { code, kind: 'failed', body: { status: 'failed', errorCode: meta.errorCode, error: meta.error } };
  }

  if (meta.status === 'completed') {
    // The metadata survived but the PDF file is gone (expired/cleaned). Signal a
    // distinct, regenerable state (409) instead of a bare 404 so the client can
    // transparently start a fresh job.
    if (!fileExists) {
      return { code: 409, kind: 'expired', body: { status: 'expired', error: 'PDF expired — please regenerate' } };
    }
    return { code: 200, kind: 'completed', streamFileId: meta.bufferFileId };
  }

  return { code: 500, kind: 'unknown', body: { status: meta.status, error: 'Unexpected job state' } };
}

/**
 * Whether a deduplication candidate job may be reused instead of starting a new one.
 * A completed job is only reusable while its PDF file still exists; pending/processing
 * jobs are reusable (the caller separately rejects orphaned/timed-out ones). Pure.
 */
function shouldReuseJob(existingMeta, fileExists) {
  if (!existingMeta) return false;
  if (existingMeta.status === 'completed') return !!fileExists;
  return existingMeta.status === 'pending' || existingMeta.status === 'processing';
}

module.exports = { PDF_BUCKET, DEFAULT_JOB_TIMEOUT_MS, resolvePdfJobResponse, shouldReuseJob };
