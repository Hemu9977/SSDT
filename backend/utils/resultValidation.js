/**
 * Strict result validation for WebCheck scan payloads.
 *
 * Rejects: null/undefined, empty object, empty array, empty string.
 *
 * Returns a normalized per-scan result:
 *  - valid payload -> { success: true, data }
 *  - invalid -> { success: false, error: 'empty_result', scanType, timestamp }
 */

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}

function isEmptyPayload(data) {
  if (data === null || data === undefined) return true;
  if (typeof data === 'string') return data.trim().length === 0;
  if (Array.isArray(data)) return data.length === 0;
  if (isPlainObject(data)) return Object.keys(data).length === 0;
  return false;
}

function validateScanResult(scanType, data) {
  if (isEmptyPayload(data)) {
    return {
      success: false,
      error: 'empty_result',
      scanType,
      timestamp: new Date().toISOString(),
    };
  }

  // If WebCheck returns a normalized error object, treat as failure.
  if (isPlainObject(data) && typeof data.error === 'string' && data.error.trim()) {
    return {
      success: false,
      error: data.error,
      errorType: data.errorType,
      scanType,
      timestamp: new Date().toISOString(),
    };
  }

  return { success: true, data };
}

module.exports = { validateScanResult, isEmptyPayload };
