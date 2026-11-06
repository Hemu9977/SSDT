/**
 * Threat verdict for a domain from public security-filtering DNS resolvers.
 *
 * Used when the in-house page capture stands in for the external page-analysis
 * service, whose own verdict is then unavailable. Each resolver
 * below refuses to resolve domains on its malware/phishing blocklist — it answers
 * "no such domain" or with its own block-page address. We ask each one directly
 * and compare with resolvers that don't filter. DNS lookups never contact the
 * target, so an IP allowlist does not affect this.
 *
 * (WebCheck's `block-lists` check is not used here: it passes `{ server }` to
 * dns.resolve4, which Node ignores, so all its "resolvers" are the system one.)
 */

const { Resolver } = require('dns').promises;

const SECURITY_RESOLVERS = [
  { name: 'Quad9',                  ip: '9.9.9.9' },
  { name: 'Cloudflare Security',    ip: '1.1.1.2' },
  { name: 'OpenDNS',                ip: '208.67.222.222' },
  { name: 'CleanBrowsing Security', ip: '185.228.168.9' },
  { name: 'Comodo Secure',          ip: '8.26.56.26' },
  { name: 'Neustar Protection',     ip: '156.154.70.2' },
  { name: 'Yandex Safe',            ip: '77.88.8.88' }
];
const UNFILTERED_RESOLVERS = [
  { name: 'Google DNS', ip: '8.8.8.8' },
  { name: 'Cloudflare', ip: '1.1.1.1' }
];

// Addresses the filtering resolvers answer with instead of a blocked domain's own.
const SINKHOLE_ADDRESSES = new Set([
  '0.0.0.0', '127.0.0.1', '::', '::1',
  '213.180.193.250', '93.158.134.250',   // Yandex Safe block pages
  '156.154.112.16', '156.154.113.16'     // Neustar / UltraDNS block pages
]);
const SINKHOLE_PREFIXES = ['146.112.61.']; // OpenDNS / Cisco Umbrella block pages

const QUERY_TIMEOUT_MS = 4000;

function isSinkhole(addr) {
  return SINKHOLE_ADDRESSES.has(addr) || SINKHOLE_PREFIXES.some(p => addr.startsWith(p));
}

/** @returns {Promise<{ addresses?: string[], code?: string }>} */
async function query(domain, server) {
  const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 2 });
  resolver.setServers([server]);
  try {
    return { addresses: await resolver.resolve4(domain) };
  } catch (err) {
    if (err.code === 'ENODATA') {
      // IPv6-only domain
      try { return { addresses: await resolver.resolve6(domain) }; }
      catch (err6) { return { code: err6.code }; }
    }
    return { code: err.code };
  }
}

/**
 * Pure classification, for tests.
 * @param {Array<{name:string, answer:{addresses?:string[], code?:string}}>} security
 * @param {Array<{answer:{addresses?:string[], code?:string}}>} unfiltered
 */
function classify(security, unfiltered) {
  const resolvesPublicly = unfiltered.some(u => u.answer.addresses?.length);
  // An address the non-filtering resolvers also give is the domain's own (e.g.
  // a name that really points at 127.0.0.1), not a block page.
  const publicAddresses = new Set(unfiltered.flatMap(u => u.answer.addresses || []));
  const answered = [];
  const hits = [];
  // A domain the public resolvers don't resolve gets no verdict: there is no
  // "real" answer to compare the filtering resolvers' answers against.
  for (const { name, answer } of resolvesPublicly ? security : []) {
    if (answer.addresses?.length) {
      answered.push(name);
      if (answer.addresses.some(a => isSinkhole(a) && !publicAddresses.has(a))) hits.push(name);
    } else if (answer.code === 'ENOTFOUND') {
      // "No such domain" from a filter, for a domain that exists for everyone else.
      answered.push(name);
      hits.push(name);
    }
    // Timeouts / refusals / SERVFAIL: that resolver gave no opinion.
  }
  const total = answered.length;
  const malicious = hits.length > 0;
  const score = total ? Math.round((100 * hits.length) / total) : 0;
  const categories = malicious ? ['malicious'] : [];
  return {
    overall:   { score, malicious, hasVerdicts: malicious, categories },
    urlscan:   { score, malicious, categories },
    engines:   { score, malicious: hits.length, benign: total - hits.length, enginesTotal: total, maliciousEngines: hits },
    community: { score: 0, votesMalicious: 0, votesBenign: 0, votesTotal: 0 }
  };
}

/**
 * @param {string} url - only the hostname is checked
 * @returns {Promise<object>} verdicts in the shape the report reads
 */
async function lookupVerdict(url) {
  const domain = new URL(url).hostname;
  const ask = list => Promise.all(list.map(async r => ({ name: r.name, answer: await query(domain, r.ip) })));
  const [security, unfiltered] = await Promise.all([ask(SECURITY_RESOLVERS), ask(UNFILTERED_RESOLVERS)]);
  return classify(security, unfiltered);
}

module.exports = {
  lookupVerdict,
  // Exposed for tests.
  _classify: classify,
  _isSinkhole: isSinkhole
};
