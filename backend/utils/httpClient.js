/**
 * Shared axios HTTP client with keep-alive agents and DNS caching.
 *
 * Why this matters on ECS Fargate:
 *  - Without keep-alive, every axios.get() opens a new TCP connection.
 *    With 29 concurrent WebCheck scans, that's 29 fresh sockets, each burning
 *    an ephemeral port from Fargate's limited range.
 *  - Keep-alive reuses TCP connections so port pressure drops dramatically.
 *  - maxSockets caps the pool so we don't accidentally exhaust file descriptors.
 *
 * DNS caching (cacheable-lookup):
 *  - Fargate tasks resolve DNS through the VPC resolver (Route 53) on every
 *    new connection. Under concurrent load this floods the resolver and causes
 *    ENOTFOUND / EAI_AGAIN spikes that look like the target is unreachable.
 *  - cacheable-lookup installs an in-process DNS cache directly on the agents,
 *    so repeated lookups for the same host (webcheck container, external APIs)
 *    are served from memory. Only the first lookup hits the resolver.
 *  - TTL is configurable; default 30 s is long enough to eliminate storm spikes
 *    while short enough to pick up legitimate DNS changes.
 *
 * This module exports a singleton axios instance.
 * Call destroyHttpClient() during graceful shutdown to release pooled sockets.
 */

const axios           = require('axios');
const http            = require('http');
const https           = require('https');
const dns             = require('dns');
const CacheableLookup = require('cacheable-lookup');
const config          = require('../config/scanConfig');

// Hostnames that must never go through cacheable-lookup's dns.resolve4() path.
//
// cacheable-lookup uses dns.resolve4() (c-ares, labelled "queryA" in errors).
// c-ares honours dns.setServers() overrides and does NOT read /etc/hosts.
// Two categories of hostnames need to bypass it and use dns.lookup() (OS) instead:
//
//  1. Loopback / link-local names (localhost, 127.x.x.x, ::1, *.local):
//     These exist only in /etc/hosts or mDNS.  Neither 8.8.8.8 nor any external
//     DNS knows about them, so resolve4() always returns ECONNREFUSED/ENOTFOUND.
//
//  2. Short Docker / ECS service names (webcheck, zap-scanner, etc.):
//     On ECS Fargate, containers in the same task communicate via the shared
//     network namespace.  Their hostnames are resolved by the VPC DNS embedded
//     resolver (169.254.169.253) and are not FQDN, so they have no dots.
//     Using dns.lookup() (getaddrinfo) is correct here: the OS reads the
//     right resolver from /etc/resolv.conf without needing c-ares to know about
//     DNS server overrides.  On local dev these names are never used (IPs are
//     used instead), so the bypass is a no-op there.
//
// Pattern explanation:
//   localhost|127…|::1|0.0.0.0|*.local  — loopback / link-local
//   [^.]+                                — any bare hostname without a dot
//                                          (catches "webcheck", "zap-scanner",
//                                           "redis", "db", etc.)
const LOOPBACK_RE = /^(localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0|.*\.local|[^.]+)$/i;

// Wraps an agent's lookup function so loopback hostnames skip the DNS cache
// and go directly to dns.lookup() (which reads /etc/hosts).
function installSmartLookup(agent, cachedLookup) {
  agent.lookup = function smartLookup(hostname, options, callback) {
    if (LOOPBACK_RE.test(hostname)) {
      return dns.lookup(hostname, options, callback);
    }
    return cachedLookup(hostname, options, callback);
  };
}

let _client     = null;
let _httpAgent  = null;
let _httpsAgent = null;
let _dnsCache   = null;

/**
 * Return the shared axios instance, creating it on first call.
 * Thread-safe in Node.js (single-threaded event loop).
 * @returns {import('axios').AxiosInstance}
 */
function getHttpClient() {
  if (_client) return _client;

  const { keepAlive, maxSockets, maxFreeSockets, keepAliveMsecs } = config.http;
  const { cacheTtlSeconds } = config.dns;

  // One shared DNS cache instance — installed on both agents so http:// and
  // https:// requests both benefit without duplicating cached entries.
  _dnsCache = new CacheableLookup({
    maxTtl: cacheTtlSeconds,       // seconds (cacheable-lookup uses seconds)
    // errorTtl: how long to cache ENOTFOUND responses (avoids hammering a bad host)
    errorTtl: Math.min(cacheTtlSeconds, 5),
  });

  _httpAgent = new http.Agent({
    keepAlive,
    maxSockets,
    maxFreeSockets,
    timeout: keepAliveMsecs,
  });

  _httpsAgent = new https.Agent({
    keepAlive,
    maxSockets,
    maxFreeSockets,
    timeout: keepAliveMsecs,
  });

  // Attach the DNS cache to both agents. After this point every request routed
  // through these agents resolves hostnames via the local cache first.
  _dnsCache.install(_httpAgent);
  _dnsCache.install(_httpsAgent);

  // Override the installed lookup so loopback hostnames (localhost, 127.x.x.x)
  // skip cacheable-lookup's dns.resolve4() and go straight to dns.lookup().
  // This prevents queryA ECONNREFUSED localhost on local dev where the system
  // DNS stub at 127.0.0.1:53 may not be running.
  installSmartLookup(_httpAgent,  _dnsCache.lookup.bind(_dnsCache));
  installSmartLookup(_httpsAgent, _dnsCache.lookup.bind(_dnsCache));

  console.log(
    `[HttpClient] Initialized — keepAlive=${keepAlive} maxSockets=${maxSockets} ` +
    `dnsCacheTtl=${cacheTtlSeconds}s`
  );

  _client = axios.create({
    httpAgent:  _httpAgent,
    httpsAgent: _httpsAgent,
    // Default timeout — overridden per call via { timeout: N } config.
    timeout: config.http.scanRequestTimeoutMs,
    // Decompress gzip/deflate/br automatically
    decompress: true,
    // Don't throw on 4xx/5xx — our response interceptor handles those explicitly
    // so that classifyError() can inspect the status code and message cleanly.
    validateStatus: null,
  });

  // ── Request interceptor — stamp start time ─────────────────────────────
  _client.interceptors.request.use(
    request => {
      // Attach timing metadata; avoids mutating the public config object
      request._ssdt_start = Date.now();
      return request;
    },
    error => Promise.reject(error)
  );

  // ── Response interceptor — surface HTTP errors + add duration ──────────
  _client.interceptors.response.use(
    response => {
      response.durationMs = Date.now() - (response.config._ssdt_start || Date.now());

      if (response.status >= 400) {
        // Turn HTTP error status into a thrown Error so callers see a rejection,
        // consistent with how axios behaves under the default validateStatus.
        const err = new Error(`HTTP ${response.status} from ${response.config.url}`);
        err.response   = response;
        err.code       = `HTTP_${response.status}`;
        err.durationMs = response.durationMs;
        return Promise.reject(err);
      }

      return response;
    },
    error => {
      // Attach duration to network errors too for logging
      error.durationMs = Date.now() - (error.config?._ssdt_start || Date.now());
      return Promise.reject(error);
    }
  );

  return _client;
}

/**
 * Destroy the pooled sockets. Call this during graceful shutdown so ECS doesn't
 * wait for TIME_WAIT sockets to expire before the task terminates.
 */
function destroyHttpClient() {
  if (_httpAgent)  { _httpAgent.destroy();  _httpAgent  = null; }
  if (_httpsAgent) { _httpsAgent.destroy(); _httpsAgent = null; }
  _dnsCache = null;
  _client   = null;
}

module.exports = { getHttpClient, destroyHttpClient };
