/**
 * One queue for every in-house headless-Chromium diagnostic (performance audit,
 * page capture, quality audit).
 *
 * These are the fallbacks for third-party checks that a client's IP allowlist
 * refuses: run here, the target sees them from Fortexa's own egress IP, which
 * the client has allowlisted. Two rules follow from running them on our own
 * 1-vCPU task:
 *
 *   - One at a time. A performance audit measures CPU time; a second Chromium
 *     beside it skews the score, and two extra browsers beside the PDF Chromium
 *     and the in-process worker would crowd the task's memory.
 *   - Bounded. Each job gets a hard timeout so a hung page cannot hold the slot
 *     for the scans queued behind it.
 */

const Bottleneck = require('bottleneck');

const LAUNCH_ARGS = [
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-dev-shm-usage',
  '--disable-gpu',
  '--disable-extensions',
  '--no-first-run'
];

const limiter = new Bottleneck({ maxConcurrent: 1 });

/**
 * The Chromium binary: the image's system Chromium in production
 * (PUPPETEER_EXECUTABLE_PATH, set in the Dockerfile), puppeteer's own
 * download in local development.
 */
function chromiumPath() {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) return process.env.PUPPETEER_EXECUTABLE_PATH;
  return require('puppeteer').executablePath();
}

function timeoutError(label, timeoutMs) {
  const err = new Error(`${label} timed out after ${Math.round(timeoutMs / 1000)}s`);
  err.code = 'ETIMEDOUT';
  return err;
}

function abortedError(label) {
  const err = new Error(`${label} aborted`);
  err.code = 'ERR_ABORTED';
  return err;
}

/**
 * Run `job` once the slot is free.
 *
 * The timeout covers the job only, not the wait for the slot. When it fires,
 * `onTimeout` is called so the job can kill its browser, and the slot is released.
 *
 * @param {string}   label
 * @param {(ctx: { signal: AbortSignal }) => Promise<any>} job
 * @param {object}   [opts]
 * @param {number}   [opts.timeoutMs=120000]
 * @param {AbortSignal} [opts.signal] - Caller cancellation (skips a queued job, aborts a running one)
 */
function runInBrowserSlot(label, job, { timeoutMs = 120_000, signal } = {}) {
  if (signal?.aborted) return Promise.reject(abortedError(label));

  return limiter.schedule(async () => {
    if (signal?.aborted) throw abortedError(label);

    const controller = new AbortController();
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort, { once: true });

    let timer;
    const guard = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(timeoutError(label, timeoutMs));
      }, timeoutMs);
      controller.signal.addEventListener('abort', () => {
        if (signal?.aborted) reject(abortedError(label));
      }, { once: true });
    });

    try {
      return await Promise.race([job({ signal: controller.signal }), guard]);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      // A job that lost the race must still stop its browser.
      if (!controller.signal.aborted) controller.abort();
    }
  });
}

module.exports = {
  LAUNCH_ARGS,
  chromiumPath,
  runInBrowserSlot,
  // Exposed for tests.
  _limiter: limiter
};
