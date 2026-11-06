const axios = require('axios');
const { gradeHost } = require('./inHouse/headerGrade');
const { withInHouseFallback, httpErrorReason } = require('./inHouse/fallback');

// Multiple Observatory API endpoints for fallback
const OBSERVATORY_ENDPOINTS = [
  'https://observatory-api.mdn.mozilla.net/api/v2/scan',
  'https://http-observatory.security.mozilla.org/api/v1/analyze'
];

/**
 * Scan a hostname using Mozilla Observatory API with fallback endpoints
 * @param {string} host - The hostname to scan (e.g., 'google.com')
 * @returns {Promise<Object>} - Scan results from Mozilla Observatory
 */
async function requestObservatoryScan(host) {
  console.log(`🔍 Scanning host with Mozilla Observatory: ${host}`);

  let lastError = null;

  // Try each endpoint until one succeeds
  for (let i = 0; i < OBSERVATORY_ENDPOINTS.length; i++) {
    const endpoint = OBSERVATORY_ENDPOINTS[i];
    const isV2 = endpoint.includes('mdn.mozilla.net');

    try {
      console.log(`📡 Attempting Observatory endpoint ${i + 1}/${OBSERVATORY_ENDPOINTS.length}: ${endpoint}`);

      const response = await axios.post(
        `${endpoint}?host=${encodeURIComponent(host)}`,
        {},
        {
          timeout: 60000, // 60 second timeout (scans can take time)
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );

      console.log(`✅ Observatory scan completed for ${host} using endpoint ${i + 1}`);
      return response.data;

    } catch (error) {
      lastError = error;
      console.warn(`⚠️  Observatory endpoint ${i + 1} failed:`, error.message);

      // If this isn't the last endpoint, continue to next one
      if (i < OBSERVATORY_ENDPOINTS.length - 1) {
        console.log(`🔄 Trying next Observatory endpoint...`);
        continue;
      }
    }
  }

  // All endpoints failed, throw the last error with detailed information
  console.error('❌ All Observatory API endpoints failed');
  console.error('Last error details:', {
    message: lastError.message,
    status: lastError.response?.status,
    data: lastError.response?.data
  });

  // Create a detailed error object
  const error = new Error('Observatory scan failed');

  if (lastError.response) {
    // HTTP error response received
    error.status = lastError.response.status;
    error.details = lastError.response.data?.error || lastError.response.statusText || 'Mozilla Observatory API error';
    error.data = lastError.response.data;

    // Add specific error messages for common status codes
    if (lastError.response.status === 429) {
      error.message = 'Observatory API rate limit exceeded. Please try again later.';
    } else if (lastError.response.status === 404) {
      error.message = 'Observatory API endpoint not found. The service may be unavailable.';
    } else if (lastError.response.status === 500) {
      error.message = 'Observatory API internal server error. Please try again later.';
    } else {
      error.message = `Observatory API error: ${error.details}`;
    }
  } else if (lastError.request) {
    // No response received
    error.status = 503;
    error.message = 'No response from Mozilla Observatory API. The service may be down.';
    error.details = 'Network timeout or service unavailable';
  } else {
    // Request setup error
    error.status = 500;
    error.message = 'Failed to initiate Observatory scan';
    error.details = lastError.message;
  }

  throw error;
}

/**
 * A grade only describes the site if the API actually reached it. It also grades
 * 401/403 answers — which is what a client's IP allowlist gives Mozilla's servers —
 * and reports scan failures in `error`.
 */
function observatoryUnusable(result) {
  if (!result) return 'empty';
  if (result.error) return `error_${result.error}`;
  if (!result.grade) return 'no_grade';
  return httpErrorReason(result.status_code);
}

/**
 * Grade a hostname: the public Observatory API first, exactly as before; when it
 * cannot grade the site itself (refused by an IP allowlist, down, rate-limited),
 * the same engine runs in-house from our egress IP.
 * @param {string} host - The hostname to scan (e.g., 'google.com')
 * @returns {Promise<Object>} - Observatory v2 /scan-shaped result
 */
async function scanHost(host) {
  return withInHouseFallback({
    name: 'Observatory',
    external: () => requestObservatoryScan(host),
    inHouse: () => gradeHost(host),
    unusable: observatoryUnusable
  });
}

/**
 * Get detailed test results for a scan
 * @param {string} host - The hostname
 * @returns {Promise<Object>} - Detailed test results
 */
async function getTestResults(host) {
  try {
    const response = await axios.get(
      `https://observatory-api.mdn.mozilla.net/api/v2/tests?host=${encodeURIComponent(host)}`,
      { timeout: 30000 }
    );
    return response.data;
  } catch (error) {
    console.error('❌ Failed to fetch test results:', error.message);

    // Create a detailed error object
    const detailedError = new Error('Failed to fetch Observatory test results');

    if (error.response) {
      detailedError.status = error.response.status;
      detailedError.details = error.response.data?.error || error.response.statusText;
      detailedError.message = `Observatory test results error (${error.response.status}): ${detailedError.details}`;
    } else if (error.request) {
      detailedError.status = 503;
      detailedError.message = 'No response from Observatory API when fetching test results';
    } else {
      detailedError.status = 500;
      detailedError.details = error.message;
    }

    throw detailedError;
  }
}

module.exports = {
  scanHost,
  getTestResults,
  // Exposed for tests.
  _observatoryUnusable: observatoryUnusable
};
