/**
 * Classifies HTTP/network errors into structured categories.
 *
 * Used by retryUtils to decide whether to retry, and by webCheckService to
 * emit meaningful structured logs so CloudWatch filters can isolate failure types.
 *
 * Return shape: { type: string, isTransient: boolean, message: string }
 *
 * isTransient = true  → safe to retry (network blip, NAT hiccup, 5xx, rate limit)
 * isTransient = false → permanent failure, retrying will not help
 */

const ERROR_TYPES = {
  TIMEOUT:        'timeout',
  DNS:            'dns_failure',
  ECONNRESET:     'connection_reset',
  SOCKET_HANG_UP: 'socket_hang_up',
  TLS:            'tls_failure',
  RATE_LIMIT:     'rate_limit',
  UPSTREAM_5XX:   'upstream_5xx',
  UPSTREAM_4XX:   'upstream_4xx',
  CIRCUIT_OPEN:   'circuit_open',
  QUEUE_FULL:     'queue_full',
  QUEUE_TIMEOUT:  'queue_timeout',
  EMPTY_RESULT:   'empty_result',
  CONN_REFUSED:   'connection_refused',
  ABORTED:        'aborted',
  INVALID_URL:    'invalid_url',
  UNKNOWN:        'unknown',
};

/**
 * @param {Error} error
 * @returns {{ type: string, isTransient: boolean, message: string }}
 */
function classifyError(error) {
  const code    = error.code;
  const message = error.message || '';
  const status  = error.response?.status;
  const msgLow  = message.toLowerCase();

  // ── Internal backpressure / breaker signals — transient ─────────────────
  if (code === 'WEBCHECK_CIRCUIT_OPEN' || msgLow.includes('circuit_open')) {
    return { type: ERROR_TYPES.CIRCUIT_OPEN, isTransient: false, message: `Circuit open: ${message}` };
  }
  if (code === 'WEBCHECK_QUEUE_FULL' || msgLow.includes('queue_full')) {
    return { type: ERROR_TYPES.QUEUE_FULL, isTransient: false, message: `Queue full: ${message}` };
  }
  if (code === 'WEBCHECK_QUEUE_TIMEOUT' || msgLow.includes('queue_timeout')) {
    return { type: ERROR_TYPES.QUEUE_TIMEOUT, isTransient: false, message: `Queue timeout: ${message}` };
  }
  if (code === 'WEBCHECK_EMPTY_RESULT' || msgLow.includes('empty_result')) {
    return { type: ERROR_TYPES.EMPTY_RESULT, isTransient: true, message: `Empty result: ${message}` };
  }

  // ── Intentional cancellation (AbortController) — never retry ─────────────
  if (code === 'ERR_CANCELED' || code === 'ERR_ABORTED' || error.name === 'CanceledError') {
    return { type: ERROR_TYPES.ABORTED, isTransient: false, message: `Request cancelled: ${message}` };
  }

  // ── Request timeout (axios ECONNABORTED / AbortSignal.timeout) ───────────
  if (code === 'ECONNABORTED' || code === 'ETIMEDOUT' ||
      (error.isAxiosError && msgLow.includes('timeout'))) {
    return { type: ERROR_TYPES.TIMEOUT, isTransient: true, message: `Request timed out: ${message}` };
  }

  // ── DNS resolution failure (transient in ECS — NAT Gateway DNS cache) ────
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_NODATA') {
    return { type: ERROR_TYPES.DNS, isTransient: true, message: `DNS failure: ${message}` };
  }

  // ── Connection reset — very common in ECS Fargate with NAT Gateway ────────
  if (code === 'ECONNRESET' || msgLow.includes('econnreset')) {
    return { type: ERROR_TYPES.ECONNRESET, isTransient: true, message: `Connection reset: ${message}` };
  }

  // ── Socket hang up — TCP RST or premature close from upstream ─────────────
  if (msgLow.includes('socket hang up') || msgLow.includes('socket hangup') ||
      msgLow.includes('read econnreset')) {
    return { type: ERROR_TYPES.SOCKET_HANG_UP, isTransient: true, message: `Socket hang up: ${message}` };
  }

  // ── Connection refused (container restarting / not yet ready) ─────────────
  if (code === 'ECONNREFUSED') {
    return { type: ERROR_TYPES.CONN_REFUSED, isTransient: true, message: `Connection refused: ${message}` };
  }

  // ── HTTP rate limit — transient, back off before retry ───────────────────
  if (status === 429) {
    return { type: ERROR_TYPES.RATE_LIMIT, isTransient: true, message: `Rate limited (429): ${message}` };
  }

  // ── Upstream server errors — transient ────────────────────────────────────
  if (status >= 500) {
    return { type: ERROR_TYPES.UPSTREAM_5XX, isTransient: true, message: `Upstream ${status}: ${message}` };
  }

  // ── Client errors — permanent (bad URL, auth, not found) ─────────────────
  if (status >= 400) {
    return { type: ERROR_TYPES.UPSTREAM_4XX, isTransient: false, message: `Client error ${status}: ${message}` };
  }

  // ── TLS/SSL failures — usually permanent (bad cert, protocol mismatch) ────
  // IMPORTANT: do NOT classify purely based on endpoint path (e.g. "/api/tls").
  // HTTP 5xx/4xx must be classified above as upstream errors.
  const TLS_CODES = [
    'CERT_HAS_EXPIRED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID',
    'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  ];
  const TLS_MARKERS = [
    'ssl handshake',
    'handshake failure',
    'alert handshake failure',
    'wrong version number',
    'certificate',
    'cert has expired',
    'self signed',
    'unable to verify',
    'unable to get issuer',
    'tlsv1 alert',
  ];
  if (TLS_CODES.includes(code) || TLS_MARKERS.some(m => msgLow.includes(m))) {
    return { type: ERROR_TYPES.TLS, isTransient: false, message: `TLS error: ${message}` };
  }

  return { type: ERROR_TYPES.UNKNOWN, isTransient: false, message };
}

module.exports = { classifyError, ERROR_TYPES };
