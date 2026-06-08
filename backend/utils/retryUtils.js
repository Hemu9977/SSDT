/**
 * Generic retry wrapper with exponential backoff and random jitter.
 *
 * Key design choices:
 *  - Only retries transient network errors (ECONNRESET, timeout, DNS, 5xx, rate-limit).
 *    Permanent failures (TLS cert invalid, 4xx, aborted) propagate immediately.
 *  - Jitter prevents simultaneous retries from all concurrent scan slots hitting
 *    the WebCheck container in a thundering herd after a brief outage.
 *  - Every retry attempt is logged with error type, delay, and attempt number
 *    so CloudWatch can track retry rates without custom metrics.
 */

const { classifyError } = require('./errorClassifier');

/**
 * @param {Function} fn          - `async (attempt: number) => T` — the operation to retry.
 *                                 Receives the current attempt number (1-based).
 * @param {object}   [options]
 * @param {number}   [options.maxAttempts=3]        - Total attempts (1 original + N-1 retries)
 * @param {number}   [options.initialDelayMs=1000]  - Delay before the first retry
 * @param {number}   [options.maxDelayMs=15000]     - Hard cap on any single delay
 * @param {number}   [options.backoffFactor=2]      - Exponential multiplier per retry
 * @param {number}   [options.jitterFactor=0.3]     - ±fraction of delay added as random jitter
 * @param {string}   [options.label='operation']    - Name for log lines (e.g. "WebCheck/tls")
 * @returns {Promise<T>}
 */
async function withRetry(fn, options = {}) {
  const {
    maxAttempts    = 3,
    initialDelayMs = 1_000,
    maxDelayMs     = 15_000,
    backoffFactor  = 2,
    jitterFactor   = 0.3,
    label          = 'operation',
  } = options;

  let lastError;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (error) {
      lastError = error;

      const { type: errType, isTransient, message: errMsg } = classifyError(error);

      // Permanent failure — fail immediately, no retries
      if (!isTransient) {
        console.warn(
          `[Retry] ${label} attempt ${attempt}/${maxAttempts}: ` +
          `permanent failure (${errType}) — ${errMsg}`
        );
        throw error;
      }

      // Final attempt exhausted
      if (attempt === maxAttempts) {
        console.error(
          `[Retry] ${label} exhausted all ${maxAttempts} attempts. ` +
          `Last error (${errType}): ${errMsg}`
        );
        throw error;
      }

      // Calculate backoff: exponential + bounded random jitter
      const exponential = initialDelayMs * Math.pow(backoffFactor, attempt - 1);
      const capped      = Math.min(exponential, maxDelayMs);
      const jitter      = capped * jitterFactor * (Math.random() * 2 - 1); // ±jitterFactor
      const delay       = Math.max(100, Math.round(capped + jitter));

      console.warn(
        `[Retry] ${label} attempt ${attempt}/${maxAttempts} failed ` +
        `(${errType}): ${errMsg}. Retrying in ${delay}ms...`
      );

      await sleep(delay);
    }
  }

  // Should not be reached, but satisfy linters
  throw lastError;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { withRetry, sleep };
