/**
 * Shared PDF report download flow.
 *
 * Used by Hero (normal scan) and AuthenticatedScanPanel (authenticated scan), for
 * both languages — four call sites that previously carried four copies of this
 * logic and drifted apart. CLAUDE.md requires feature parity between the two
 * panels, so the flow lives here rather than being duplicated.
 *
 * Two defects this module exists to prevent:
 *
 * 1. SCAN IDENTITY MUST BE CAPTURED ONCE. The caller passes an immutable
 *    { analysisId, target } snapshot taken at click time. The old code read
 *    `report.analysisId` when starting the job but `report.target` minutes later
 *    when naming the file, and `report` can be replaced mid-poll by a background
 *    scan update. That produced a real report named for one site containing
 *    another site's data.
 *
 * 2. POLLING MUST BACK OFF. A flat 5s poll issued dozens of requests per
 *    download and tripped the server's rate limiter, so a second download failed.
 *
 * 3. EVERY REQUEST HAS A DEADLINE. MAX_WAIT_MS used to be checked only between
 *    polls, so one request the server never answered kept the button on
 *    "Generating" with no end. Each request, body included, now gives up after
 *    REQUEST_TIMEOUT_MS.
 *
 * Errors are thrown with a `messageKey` naming an i18n key. Backend `error`
 * strings are never surfaced: they are English-only and name the scan engines.
 */
import { requestTimeout } from './requestTimeout';

/** Poll delay by elapsed time: responsive at first, then progressively cheaper. */
export function pollDelayMs(elapsedMs) {
  if (elapsedMs < 60_000) return 5_000;
  if (elapsedMs < 180_000) return 10_000;
  return 15_000;
}

const MAX_WAIT_MS = 10 * 60 * 1000; // 10 minutes
const MAX_RECOVERABLE_RETRIES = 3;
const REQUEST_TIMEOUT_MS = 60 * 1000; // one request; the whole job is bounded by MAX_WAIT_MS

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** fetch and read the body with `read`, within REQUEST_TIMEOUT_MS. */
async function boundedFetch(url, init, read) {
  const deadline = requestTimeout(REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: deadline.signal });
    return { res, body: await read(res) };
  } finally {
    deadline.clear();
  }
}

const readJson = (res) => res.json().catch(() => ({}));

/** A 200 can still be a proxy's HTML error page or an empty body. */
const isPdfBlob = (blob) => !!blob && blob.size > 0 && /pdf/i.test(blob.type || '');

function reportError(messageKey, cause) {
  const err = new Error(messageKey);
  err.messageKey = messageKey;
  if (cause) err.cause = cause;
  return err;
}

/** Map a non-success poll/start response to an i18n key. */
function classifyFailure(status, body) {
  if (status === 429) {
    if (body?.errorCode === 'GEMINI_KEY_EXHAUSTED') return 'geminiKeyExhausted';
    return 'pdfRateLimited';
  }
  if (body?.errorCode === 'EN_CONTENT_NOT_ENGLISH' || body?.errorCode === 'EN_TEMPLATE_NOT_ENGLISH') {
    return 'englishPdfOnly';
  }
  if (body?.errorCode === 'SCAN_NOT_COMPLETE' || status === 400) return 'pdfScanIncomplete';
  return 'pdfGenerationFailed';
}

function triggerBrowserDownload(blob, filename) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

/** Build the download filename from the snapshot taken at click time. */
export function pdfFilename(target, lang) {
  const safeTarget = String(target || 'report').replace(/[^a-z0-9]/gi, '_');
  return `security_report_${lang.toUpperCase()}_${safeTarget}_${Date.now()}.pdf`;
}

/**
 * Run the full request → poll → download flow.
 *
 * @param {object}   opts
 * @param {string}   opts.analysisId  scan id captured at click time
 * @param {string}   opts.target      scan target captured at click time
 * @param {'en'|'ja'} opts.lang
 * @param {string}   opts.apiBase
 * @param {string}   opts.token
 * @param {string}   [opts.apiPrefix] defaults to '/api/scan'
 * @param {(step: number) => void} [opts.onPoll] called before each poll
 * @throws {Error} with `.messageKey` set to an i18n key
 */
export async function downloadPdfReport({
  analysisId,
  target,
  lang,
  apiBase,
  token,
  apiPrefix = '/api/scan',
  onPoll,
}) {
  if (!analysisId) throw reportError('pdfScanIncomplete');

  const startJob = async () => {
    let res, body;
    try {
      ({ res, body } = await boundedFetch(`${apiBase}${apiPrefix}/pdf-job`, {
        method: 'POST',
        headers: { 'x-auth-token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysisId, lang }),
      }, readJson));
    } catch (err) {
      throw reportError('pdfGenerationFailed', err); // network failure or timeout
    }
    if (!res.ok) throw reportError(classifyFailure(res.status, body));
    if (!body?.jobId) throw reportError('pdfGenerationFailed');
    return body.jobId;
  };

  let jobId = await startJob();
  let restarted = false;
  let recoverable = 0;
  let pollCount = 0;
  const startedAt = Date.now();

  for (;;) {
    const elapsed = Date.now() - startedAt;
    if (elapsed > MAX_WAIT_MS) throw reportError('pdfGenerationTimedOut');

    await sleep(pollDelayMs(elapsed));
    pollCount++;
    onPoll?.(pollCount);

    let res, body;
    try {
      ({ res, body } = await boundedFetch(`${apiBase}${apiPrefix}/pdf-job/${jobId}`, {
        headers: { 'x-auth-token': token },
      }, (r) => (r.status === 200 ? r.blob() : readJson(r))));
    } catch {
      continue; // transient network error or timeout — the loop's deadline bounds this
    }

    if (res.status === 202) { recoverable = 0; continue; }

    if (res.status === 200) {
      if (!isPdfBlob(body)) throw reportError('pdfGenerationFailed');
      triggerBrowserDownload(body, pdfFilename(target, lang));
      return;
    }

    // 404 = job metadata gone (e.g. cache miss); 409 = a finished job's file
    // expired. Both are recoverable: start ONE fresh job, then fall back to a
    // bounded retry budget.
    if (res.status === 404 || res.status === 409) {
      if (!restarted) {
        restarted = true;
        try {
          jobId = await startJob();
          recoverable = 0;
          continue;
        } catch {
          // fall through to the retry budget below
        }
      }
      recoverable++;
      if (recoverable < MAX_RECOVERABLE_RETRIES) continue;
      throw reportError('pdfJobExpired');
    }

    throw reportError(classifyFailure(res.status, body));
  }
}
