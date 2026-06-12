/**
 * Promise-based concurrency limiter (CommonJS, no dependencies).
 *
 * Equivalent to p-limit v3 but avoids the ESM-only constraint of p-limit v4+.
 * Used to replace uncontrolled Promise.all launches with a bounded queue so
 * ECS Fargate tasks never exhaust ephemeral ports by opening too many simultaneous
 * outbound sockets.
 *
 * Usage:
 *   const limit = createConcurrencyLimiter(5);
 *   const results = await Promise.allSettled(
 *     items.map(item => limit(() => doWork(item)))
 *   );
 */

/**
 * @param {number|{ concurrency: number, maxQueueSize?: number, queueTimeoutMs?: number, name?: string }} concurrencyOrOptions
 * @returns {(fn: () => Promise<T>, options?: { signal?: AbortSignal }) => Promise<T>} limit — wrap any async fn to be queued.
 */
function createConcurrencyLimiter(concurrencyOrOptions) {
  const options =
    (typeof concurrencyOrOptions === 'object' && concurrencyOrOptions !== null)
      ? concurrencyOrOptions
      : { concurrency: concurrencyOrOptions };

  let concurrency = options.concurrency;
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new TypeError(`concurrency must be a positive integer, got: ${concurrency}`);
  }

  const name = options.name || 'limiter';
  const maxQueueSize = Number.isInteger(options.maxQueueSize) ? options.maxQueueSize : Infinity;
  const queueTimeoutMs = Number.isInteger(options.queueTimeoutMs) ? options.queueTimeoutMs : 0;

  let active = 0;
  const queue = [];

  // AbortSignal fan-out:
  // Many queued tasks can share the same AbortSignal (e.g. one analysis-wide controller).
  // Adding an abort listener per queued task trips MaxListenersExceededWarning under load.
  // Instead, attach at most ONE listener per signal and reject all queued entries for it.
  const signalState = new WeakMap(); // AbortSignal -> { entries: Set, onAbort: Function }

  function _attachToSignal(signal, entry) {
    let state = signalState.get(signal);
    if (!state) {
      const entries = new Set();
      const onAbort = () => {
        // Reject all still-queued entries associated with this signal.
        // (Entries that are already running use their own cancellation path.)
        for (const e of entries) {
          const idx = queue.indexOf(e);
          if (idx >= 0) queue.splice(idx, 1);
          if (e.timeoutHandle) clearTimeout(e.timeoutHandle);
          e.reject(makeLimiterError('ERR_ABORTED', `${name}: task aborted while queued`));
        }
        entries.clear();
        try { signalState.delete(signal); } catch (_) {}
      };
      signal.addEventListener('abort', onAbort, { once: true });
      state = { entries, onAbort };
      signalState.set(signal, state);
    }
    state.entries.add(entry);
    entry._signal = signal;
  }

  function _detachFromSignal(entry) {
    const signal = entry._signal;
    if (!signal) return;
    entry._signal = null;

    const state = signalState.get(signal);
    if (!state) return;
    state.entries.delete(entry);
    if (state.entries.size === 0) {
      signal.removeEventListener('abort', state.onAbort);
      signalState.delete(signal);
    }
  }

  function runNext() {
    while (active < concurrency && queue.length > 0) {
      active++;
      const entry = queue.shift();
      if (entry.timeoutHandle) clearTimeout(entry.timeoutHandle);
      _detachFromSignal(entry);

      // Micro-task boundary prevents stack overflow on large queues
      Promise.resolve()
        .then(() => entry.fn())
        .then(
          result => { active--; entry.resolve(result); runNext(); },
          err    => { active--; entry.reject(err);    runNext(); }
        );
    }
  }

  function makeLimiterError(code, message) {
    const err = new Error(message);
    err.code = code;
    return err;
  }

  /**
   * Enqueue fn and return a Promise that resolves/rejects when fn completes.
   * @param {() => Promise<T>} fn
   * @param {{ signal?: AbortSignal }} [runOptions]
   * @returns {Promise<T>}
   */
  function limit(fn, runOptions = {}) {
    const { signal } = runOptions;

    if (signal?.aborted) {
      return Promise.reject(makeLimiterError('ERR_ABORTED', `${name}: task aborted before enqueue`));
    }

    if (queue.length >= maxQueueSize) {
      return Promise.reject(makeLimiterError('WEBCHECK_QUEUE_FULL', `${name}: queue_full (max=${maxQueueSize})`));
    }

    return new Promise((resolve, reject) => {
      const entry = {
        fn,
        resolve,
        reject,
        enqueuedAt: Date.now(),
        _signal: null,
        timeoutHandle: null,
      };

      if (signal) _attachToSignal(signal, entry);

      if (queueTimeoutMs > 0) {
        entry.timeoutHandle = setTimeout(() => {
          const idx = queue.indexOf(entry);
          if (idx >= 0) queue.splice(idx, 1);
          _detachFromSignal(entry);
          reject(makeLimiterError('WEBCHECK_QUEUE_TIMEOUT', `${name}: queue_timeout after ${queueTimeoutMs}ms`));
        }, queueTimeoutMs);
      }

      queue.push(entry);
      runNext();
    });
  }

  /** @returns {{ active: number, queued: number, concurrency: number, maxQueueSize: number, name: string }} */
  limit.stats = () => ({ active, queued: queue.length, concurrency, maxQueueSize, name });

  /** Adjust concurrency at runtime (used for memory-pressure throttling). */
  limit.setConcurrency = (next) => {
    if (!Number.isInteger(next) || next < 1) return;
    concurrency = next;
    runNext();
  };

  return limit;
}

module.exports = { createConcurrencyLimiter };
