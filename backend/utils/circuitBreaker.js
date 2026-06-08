/**
 * Minimal per-key circuit breaker (CommonJS, no deps).
 *
 * States: CLOSED -> OPEN -> HALF_OPEN -> CLOSED
 *
 * - Rolling window is implemented by pruning failure timestamps older than windowMs.
 * - When OPEN, new requests are rejected until resetMs elapses.
 * - When HALF_OPEN, allow a single probe request at a time.
 */

function nowMs() {
  return Date.now();
}

class CircuitBreaker {
  /**
   * @param {object} options
   * @param {string} options.name
   * @param {number} options.threshold          - failures within window before opening
   * @param {number} options.resetMs            - open cooldown duration
   * @param {number} [options.windowMs=resetMs] - rolling window for failures
   */
  constructor({ name, threshold, resetMs, windowMs }) {
    this.name = name || 'breaker';
    this.threshold = Number.isInteger(threshold) ? threshold : 5;
    this.resetMs = Number.isInteger(resetMs) ? resetMs : 60_000;
    this.windowMs = Number.isInteger(windowMs) ? windowMs : this.resetMs;

    this.state = 'CLOSED';
    this.openedAt = 0;
    this.halfOpenProbeInFlight = false;

    this.failures = []; // timestamps

    this.metrics = {
      opened: 0,
      halfOpened: 0,
      closed: 0,
      rejected: 0,
      successes: 0,
      failures: 0,
      lastStateChangeAt: nowMs(),
      lastFailureAt: 0,
      lastSuccessAt: 0,
    };
  }

  _pruneFailures(t) {
    const cutoff = t - this.windowMs;
    while (this.failures.length > 0 && this.failures[0] < cutoff) {
      this.failures.shift();
    }
  }

  _setState(nextState, t) {
    if (this.state === nextState) return;
    this.state = nextState;
    this.metrics.lastStateChangeAt = t;
    if (nextState === 'OPEN') this.metrics.opened++;
    if (nextState === 'HALF_OPEN') this.metrics.halfOpened++;
    if (nextState === 'CLOSED') this.metrics.closed++;
  }

  /**
   * @returns {{ allowed: boolean, state: string, retryAfterMs?: number }}
   */
  canRequest() {
    const t = nowMs();
    this._pruneFailures(t);

    if (this.state === 'OPEN') {
      const elapsed = t - this.openedAt;
      if (elapsed >= this.resetMs) {
        this.halfOpenProbeInFlight = false;
        this._setState('HALF_OPEN', t);
      } else {
        this.metrics.rejected++;
        return { allowed: false, state: this.state, retryAfterMs: Math.max(0, this.resetMs - elapsed) };
      }
    }

    if (this.state === 'HALF_OPEN') {
      if (this.halfOpenProbeInFlight) {
        this.metrics.rejected++;
        return { allowed: false, state: this.state, retryAfterMs: this.resetMs };
      }
      this.halfOpenProbeInFlight = true;
      return { allowed: true, state: this.state };
    }

    return { allowed: true, state: this.state };
  }

  recordSuccess() {
    const t = nowMs();
    this.metrics.successes++;
    this.metrics.lastSuccessAt = t;

    if (this.state === 'HALF_OPEN') {
      this.halfOpenProbeInFlight = false;
      this.failures = [];
      this._setState('CLOSED', t);
    }
  }

  recordFailure() {
    const t = nowMs();
    this.metrics.failures++;
    this.metrics.lastFailureAt = t;

    this._pruneFailures(t);
    this.failures.push(t);

    if (this.state === 'HALF_OPEN') {
      this.halfOpenProbeInFlight = false;
      this.openedAt = t;
      this._setState('OPEN', t);
      return;
    }

    if (this.failures.length >= this.threshold) {
      this.openedAt = t;
      this._setState('OPEN', t);
    }
  }

  snapshot() {
    const t = nowMs();
    this._pruneFailures(t);
    return {
      name: this.name,
      state: this.state,
      failureCountWindow: this.failures.length,
      threshold: this.threshold,
      resetMs: this.resetMs,
      windowMs: this.windowMs,
      openedAt: this.openedAt,
      metrics: { ...this.metrics },
    };
  }
}

module.exports = { CircuitBreaker };
