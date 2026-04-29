import { API_BASE } from '../config/api';

const DEFAULT_TIMEOUT_MS = 30000;
const MAX_RETRIES = 2;
// Only retry on transient network or server errors, never on client errors (4xx)
const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wraps fetch with:
 *  - Automatic base URL from REACT_APP_API_URL
 *  - JWT token injection from localStorage
 *  - Configurable timeout (default 30s)
 *  - Exponential-backoff retry for transient errors (502/503/504/429)
 *  - Structured error objects with { status, message, data }
 *
 * @param {string} path  - API path starting with / (e.g. '/api/vt/combined-analysis')
 * @param {RequestInit} options - fetch options (method, body, headers, signal, ...)
 * @param {object} config
 * @param {number} [config.timeoutMs=30000]
 * @param {number} [config.retries=2]
 * @returns {Promise<any>} - parsed JSON response body
 */
export async function apiFetch(path, options = {}, config = {}) {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, retries = MAX_RETRIES } = config;

  const token = localStorage.getItem('token');

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'x-auth-token': token } : {}),
    ...options.headers,
  };

  let attempt = 0;

  while (attempt <= retries) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    // Caller can pass their own signal; merge by aborting on either
    const callerSignal = options.signal;
    if (callerSignal) {
      callerSignal.addEventListener('abort', () => controller.abort());
    }

    try {
      const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        if (RETRYABLE_STATUSES.has(response.status) && attempt < retries) {
          await sleep(Math.pow(2, attempt) * 500); // 500ms, 1000ms
          attempt++;
          continue;
        }

        let errorData = {};
        try {
          errorData = await response.json();
        } catch {
          // response body may not be JSON
        }

        const err = new Error(errorData.message || `Request failed: ${response.status}`);
        err.status = response.status;
        err.data = errorData;
        throw err;
      }

      // 204 No Content has no body
      if (response.status === 204) return null;
      return response.json();
    } catch (err) {
      clearTimeout(timeoutId);

      if (err.name === 'AbortError') {
        const timeout = new Error('Request timed out. Please try again.');
        timeout.status = 408;
        throw timeout;
      }

      // Network failure (offline, DNS, etc.) — retry
      if (!err.status && attempt < retries) {
        await sleep(Math.pow(2, attempt) * 500);
        attempt++;
        continue;
      }

      throw err;
    }
  }
}

/** Convenience wrappers */
export const apiGet = (path, config) => apiFetch(path, { method: 'GET' }, config);

export const apiPost = (path, body, config) =>
  apiFetch(path, { method: 'POST', body: JSON.stringify(body) }, config);

export const apiDelete = (path, config) => apiFetch(path, { method: 'DELETE' }, config);

/**
 * Returns a user-facing message string from any thrown API error.
 * Use this in catch blocks instead of raw err.message to avoid leaking internals.
 */
export function getErrorMessage(err) {
  if (!err) return 'An unexpected error occurred.';
  if (err.status === 401) return 'Session expired. Please log in again.';
  if (err.status === 403) return 'You do not have permission to perform this action.';
  if (err.status === 408) return 'The request timed out. Please check your connection.';
  if (err.status === 429) return 'Too many requests. Please wait a moment and try again.';
  if (err.status >= 500) return 'The server encountered an error. Please try again shortly.';
  return err.message || 'Something went wrong. Please try again.';
}
