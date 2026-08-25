/**
 * Refuse scan targets that are really requests to our own infrastructure.
 *
 * Several routes hand a customer-supplied URL to something that fetches it
 * server-side — a headless browser in detection and the login test, and ZAP
 * itself once a scan starts. Only `/scan` checked the host at all, and only for
 * `localhost` and `127.0.0.1`, so `169.254.169.254` went straight through. On
 * EC2 that address returns the instance role's temporary credentials, and the
 * login test would have reported back what it found.
 *
 * Private ranges are deliberately **allowed**: this is a security scanner and
 * customers legitimately point it at internal staging hosts. What is refused is
 * the set of addresses that are never a customer's site and only ever reach our
 * own metadata service or loopback.
 */

// Cloud instance metadata. Reachable only from inside the instance, and holds
// credentials on every major provider.
const METADATA_HOSTS = new Set([
  '169.254.169.254',      // AWS, Azure, GCP, DigitalOcean, Oracle
  '169.254.170.2',        // AWS ECS task metadata / task role credentials
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  'instance-data.ec2.internal'
]);

// Loopback, in the spellings a blocklist of two strings misses.
const LOOPBACK_HOSTS = new Set([
  'localhost', 'localhost.localdomain',
  '127.0.0.1', '0.0.0.0',
  '::1', '[::1]', '::', '[::]'
]);

/**
 * Normalise a hostname for comparison: strip brackets from IPv6 literals and the
 * trailing dot of a fully-qualified name, both of which resolve identically but
 * would slip past a plain string match.
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
 * @param {{allowLoopback?: boolean}} [options]  loopback is refused by default;
 *        set true only where a local target is genuinely meaningful.
 * @returns {{ok: true, url: URL} | {ok: false, code: string}}
 */
function checkScanTarget(rawUrl, options = {}) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, code: 'INVALID_URL' };
  }

  // A browser will happily follow file:// and data:, which read the scanner's
  // own disk rather than anything on the customer's site.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, code: 'UNSUPPORTED_SCHEME' };
  }

  const host = normaliseHost(parsed.hostname);

  if (METADATA_HOSTS.has(host)) {
    return { ok: false, code: 'BLOCKED_TARGET' };
  }

  // 169.254.0.0/16 as a whole: link-local, and the metadata range lives in it.
  if (/^169\.254\./.test(host)) {
    return { ok: false, code: 'BLOCKED_TARGET' };
  }

  if (!options.allowLoopback && LOOPBACK_HOSTS.has(host)) {
    return { ok: false, code: 'BLOCKED_TARGET' };
  }

  // 127.0.0.0/8 in full — 127.0.0.1 is only the most common spelling of it.
  if (!options.allowLoopback && /^127\./.test(host)) {
    return { ok: false, code: 'BLOCKED_TARGET' };
  }

  return { ok: true, url: parsed };
}

module.exports = {
  checkScanTarget,
  normaliseHost,
  METADATA_HOSTS,
  LOOPBACK_HOSTS
};
