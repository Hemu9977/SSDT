/**
 * The one place a customer-supplied scan target is judged safe to fetch.
 *
 * Several routes hand a URL to something that fetches it server-side: a headless
 * browser during login detection and the login test, ZAP once a scan starts, and
 * the WebCheck container. The scanner runs inside your VPC, so any address the
 * customer supplies is resolved from *there* — not from their network.
 *
 * That is the whole reason the rules below are strict. A customer's internal
 * staging host is not reachable from ECS at all without a VPN or agent, which
 * this product does not have. So allowing private ranges grants no capability
 * and only exposes your own infrastructure.
 *
 * Three rules, because IP ranges alone were not enough:
 *   1. Blocked IP ranges — RFC-1918, loopback, link-local, IPv6 ULA, `.local`.
 *   2. The internal service hosts, read from the environment rather than
 *      hardcoded, so the list cannot drift when a service is renamed.
 *   3. Any single-label hostname. `zap-scanner`, `webcheck` and `redis` match no
 *      IP pattern and appear on no denylist until someone remembers to add them.
 *      No customer site is a bare word, so this catches the next service too.
 *
 * Rule 3 is the one that mattered: ZAP runs with `api.disablekey=true` and
 * `api.addrs.addr.name=.*`, so `http://zap-scanner:8080/JSON/...` reached an
 * unauthenticated admin API from any account.
 */

// Adopted verbatim from the public scan route, which had the stricter and more
// complete set. It is now the only copy.
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,                       // 127.0.0.0/8 loopback
  /^0\./,                         // 0.0.0.0/8
  /^10\./,                        // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./,   // 172.16.0.0/12
  /^192\.168\./,                  // 192.168.0.0/16
  /^169\.254\./,                  // 169.254.0.0/16 link-local, incl. cloud metadata
  /^::1$/,                        // IPv6 loopback
  /^fc00:/i,                      // IPv6 ULA fc00::/7
  /^fe[89ab][0-9a-f]:/i,          // IPv6 link-local fe80::/10
  /\.local$/i,                    // mDNS
];

// Named metadata endpoints, which are hostnames rather than addresses.
const METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  'instance-data.ec2.internal'
]);

/**
 * Hosts of our own backing services, taken from the environment.
 *
 * Derived rather than listed so that renaming a service in the task definition
 * cannot silently open a hole here.
 */
function internalServiceHosts() {
  const hosts = new Set();
  for (const key of ['ZAP_API_URL', 'ZAP_AUTH_API_URL', 'WEBCHECK_URI', 'REDIS_URL', 'ELASTICACHE_REDIS_URL']) {
    const value = process.env[key];
    if (!value) continue;
    try {
      const host = new URL(value).hostname.toLowerCase();
      if (host) hosts.add(host);
    } catch {
      // Not a parseable URL (a bare host:port, say) — take the leading token.
      const bare = String(value).split('/').pop().split(':')[0].trim().toLowerCase();
      if (bare) hosts.add(bare);
    }
  }
  return hosts;
}

/**
 * Strip an IPv6 literal's brackets and a fully-qualified name's trailing dot.
 * Both resolve identically to the un-normalised form but slip past a plain match.
 */
function normaliseHost(hostname) {
  return String(hostname || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}

/**
 * Is this URL safe to fetch on the customer's behalf?
 *
 * @param {string} rawUrl
 * @param {{allowInternal?: boolean}} [options] escape hatch for local development
 *        only; no production path passes it.
 * @returns {{ok: true, url: URL} | {ok: false, code: string, error: string}}
 */
function checkScanTarget(rawUrl, options = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, code: 'INVALID_URL', error: 'Invalid URL format' };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, code: 'INVALID_URL', error: 'Invalid URL format' };
  }

  // A browser follows file:// and data:, which read the scanner's own disk.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, code: 'UNSUPPORTED_SCHEME', error: 'Only HTTP and HTTPS URLs are allowed' };
  }

  if (options.allowInternal) return { ok: true, url: parsed };

  const host = normaliseHost(parsed.hostname);
  const refuse = { ok: false, code: 'BLOCKED_TARGET', error: 'Localhost and private IPs are not allowed' };

  if (BLOCKED_HOST_PATTERNS.some(p => p.test(host))) return refuse;
  if (METADATA_HOSTS.has(host)) return refuse;
  if (internalServiceHosts().has(host)) return refuse;

  // Rule 3. A bare word is a VPC-internal name; every real site has a dot.
  if (!host.includes('.') && !host.includes(':')) return refuse;

  return { ok: true, url: parsed };
}

/**
 * Back-compat shape for callers that already spoke `{ valid, error }`.
 * @returns {{valid: boolean, error?: string, code?: string}}
 */
function isValidScanUrl(rawUrl) {
  const result = checkScanTarget(rawUrl);
  return result.ok ? { valid: true } : { valid: false, error: result.error, code: result.code };
}

module.exports = {
  checkScanTarget,
  isValidScanUrl,
  normaliseHost,
  internalServiceHosts,
  BLOCKED_HOST_PATTERNS,
  METADATA_HOSTS
};
