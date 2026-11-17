'use strict';

/**
 * Everything that puts a credential into ZAP, takes it out again, or measures
 * whether it worked. Shared by the authenticated scan (form login and HTTP Basic).
 *
 * Behaviour verified against the production ZAP image (2.17.0, digest
 * sha256:781a2bdaea47…) in the Phase 0 proof of concept:
 *
 *  - A Replacer rule's `url` is a WHOLE-URL match. `(?i)^https://<host>(:<port>)?(/.*)?$`
 *    covers the slashless root, an explicit default port, query strings and an
 *    upper-case host, and matches no other scheme, port, subdomain or host.
 *  - `initiators` 2,3,6,10 (active scan, spider, manual request, AJAX spider) keep
 *    every scanner authenticated. The default (all initiators) also covers 1 —
 *    proxy traffic — so anything able to reach ZAP's port could browse the
 *    customer's site through ZAP with the customer's credentials.
 *  - Removing the rule does NOT revoke the credential during a scan: the active
 *    scanner replays stored request headers (69/69 and 91/91 requests stayed
 *    authenticated). Revocation is: stop every scan → remove rules → newSession.
 *  - newSession does not clear Replacer rules, and duplicate rule descriptions are
 *    rejected, so rules are named per scan and swept explicitly.
 *  - Passive rule 10105 logs the decoded Basic password at INFO (ZAP stdout →
 *    CloudWatch) when it sees Basic over HTTP. Disabled for Basic scans.
 */

const SCANNER_INITIATORS = '2,3,6,10';
const COOKIE_RULE = 'auth_cookie';
const BASIC_RULE_PREFIX = 'auth_basic_';
// Form logins whose session is a Bearer token the app sends to its API (kept in
// localStorage, not a cookie). One rule per API origin, named per scan.
const BEARER_RULE_PREFIX = 'auth_bearer_';
const INSECURE_AUTH_PSCAN_RULE = '10105';

const FORM = { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };

/** ZAP API action sent as a POST form, so values never appear in a URL. */
function zapPost(zapClient, path, params) {
  return zapClient.post(path, new URLSearchParams(params).toString(), FORM);
}

/** Per-scan rule name: ZAP rejects duplicate descriptions. */
function basicRuleDescription(scanId) {
  return `${BASIC_RULE_PREFIX}${String(scanId).replace(/[^A-Za-z0-9_-]/g, '_')}`;
}

function escapeJavaRegex(s) {
  return String(s).replace(/[\\^$.|?*+()[\]{}]/g, '\\$&');
}

/**
 * Java regex matching exactly one https origin, any path.
 * @param {string} origin e.g. 'https://example.com' or 'https://example.com:8443'
 */
function originRuleRegex(origin) {
  const u = new URL(origin);
  if (u.protocol !== 'https:') throw new Error('Basic credentials are only ever scoped to an https origin');
  const port = u.port || '443';
  return `(?i)^https://${escapeJavaRegex(u.hostname)}(:${port})${u.port ? '' : '?'}(/.*)?$`;
}

/**
 * Inject `Authorization` for one https origin, scanner traffic only.
 * The value is passed in a POST body and is never logged.
 */
async function applyBasicAuthRule(zapClient, { scanId, origin, authorization }) {
  await zapPost(zapClient, '/JSON/replacer/action/addRule/', {
    description: basicRuleDescription(scanId),
    enabled: 'true',
    matchType: 'REQ_HEADER',
    matchRegex: 'false',
    matchString: 'Authorization',
    replacement: authorization,
    initiators: SCANNER_INITIATORS,
    url: originRuleRegex(origin)
  });
}

/**
 * Java regex matching exactly one origin (http or https — whichever the app
 * itself used to send the token), any path. Same whole-URL shape as
 * `originRuleRegex`; never matches another scheme, port, host or subdomain.
 * @param {string} origin
 */
function exactOriginRegex(origin) {
  const u = new URL(origin);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('Only http(s) origins can be scoped');
  const scheme = u.protocol.slice(0, -1);
  const defaultPort = scheme === 'https' ? '443' : '80';
  const port = u.port || defaultPort;
  return `(?i)^${scheme}://${escapeJavaRegex(u.hostname)}(:${port})${u.port ? '' : '?'}(/.*)?$`;
}

// Path fragments of session-ending endpoints, as regex source shared with the
// JS side (utils/bearerApiScope.js) so ZAP and the seed filter agree.
const { LOGOUT_PATH_FRAGMENTS } = require('../utils/bearerApiScope');
const LOGOUT_PATH_ALTERNATION = `(?:${LOGOUT_PATH_FRAGMENTS.join('|')})`;

/**
 * Java regex for the Bearer Replacer rule: exactly one origin, any path EXCEPT a
 * logout-shaped one. Whatever a scanner replays — a crawled link, an attack on a
 * seeded endpoint, a call the AJAX spider's browser makes — the token is never
 * attached to a request that would end the session. The negative lookahead sits
 * after the optional port, so `:443/logout` cannot slip past by backtracking.
 * @param {string} origin
 */
function bearerRuleRegex(origin) {
  const u = new URL(origin);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('Only http(s) origins can be scoped');
  const scheme = u.protocol.slice(0, -1);
  const port = u.port || (scheme === 'https' ? '443' : '80');
  return `(?i)^${scheme}://${escapeJavaRegex(u.hostname)}(:${port})${u.port ? '' : '?'}` +
    `(?![/][^?#]*${LOGOUT_PATH_ALTERNATION})(/.*)?$`;
}

/**
 * Context include regexes for the scanned site: its host and its subdomains,
 * on a label boundary. The old `https?://host.*` also matched
 * `https://host.evil.net/…`, and `https?://.*\.host.*` matched
 * `https://x.host.evil.net/…` — both put a different domain in scope.
 * ZAP matches context regexes against the whole URL.
 * @param {string} hostname
 */
function siteScopeRegexes(hostname) {
  const host = escapeJavaRegex(String(hostname).toLowerCase().replace(/^\[|\]$/g, ''));
  const rest = '(?::[0-9]+)?(?:[/?#].*)?$';
  return [
    `(?i)^https?://${host}${rest}`,
    `(?i)^https?://(?:[a-z0-9_-]+\\.)+${host}${rest}`
  ];
}

/**
 * Context excludes for an API origin's own context: every logout-shaped path
 * (case-insensitive, unlike the site context's legacy `.*logout.*` list).
 * @param {string} origin
 */
function apiContextExcludeRegexes(origin) {
  const u = new URL(origin);
  const scheme = u.protocol.slice(0, -1);
  const port = u.port || (scheme === 'https' ? '443' : '80');
  return [
    `(?i)^${scheme}://${escapeJavaRegex(u.hostname)}(:${port})${u.port ? '' : '?'}/[^?#]*${LOGOUT_PATH_ALTERNATION}.*$`
  ];
}

/** Per-scan, per-origin rule name: ZAP rejects duplicate descriptions. */
function bearerRuleDescription(scanId, index) {
  return `${BEARER_RULE_PREFIX}${String(scanId).replace(/[^A-Za-z0-9_-]/g, '_')}_${Number(index) || 0}`;
}

/**
 * Inject the app's own `Authorization: Bearer …` header for one API origin,
 * scanner traffic only, never on a logout-shaped path. The value is passed in a
 * POST body and is never logged.
 */
async function applyBearerRule(zapClient, { scanId, index, origin, authorization }) {
  await zapPost(zapClient, '/JSON/replacer/action/addRule/', {
    description: bearerRuleDescription(scanId, index),
    enabled: 'true',
    matchType: 'REQ_HEADER',
    matchRegex: 'false',
    matchString: 'Authorization',
    replacement: authorization,
    initiators: SCANNER_INITIATORS,
    url: bearerRuleRegex(origin)
  });
}

async function credentialRuleNames(zapClient) {
  const res = await zapClient.get('/JSON/replacer/view/rules/');
  const rules = (res && res.data && res.data.rules) || [];
  return rules
    .map(r => r && r.description)
    .filter(d => typeof d === 'string' &&
      (d === COOKIE_RULE || d.startsWith(BASIC_RULE_PREFIX) || d.startsWith(BEARER_RULE_PREFIX)));
}

/**
 * Remove every credential rule on this ZAP instance, whichever scan left it.
 * Rules survive newSession, so a scan that died without cleaning up would
 * otherwise hand its credential to the next scan on the same instance.
 * @returns {Promise<string[]>} names removed
 */
async function purgeCredentialRules(zapClient) {
  const removed = [];
  let names = [];
  try { names = await credentialRuleNames(zapClient); } catch (_) { names = [COOKIE_RULE]; }
  for (const description of names) {
    try {
      await zapPost(zapClient, '/JSON/replacer/action/removeRule/', { description });
      removed.push(description);
    } catch (_) { /* already gone */ }
  }
  return removed;
}

async function setInsecureAuthRule(zapClient, enabled) {
  await zapPost(zapClient, `/JSON/pscan/action/${enabled ? 'enable' : 'disable'}Scanners/`, { ids: INSECURE_AUTH_PSCAN_RULE });
}

/**
 * Revoke a scan's credentials from ZAP. Order matters (Phase 0, K.2/K.2b/K.2c):
 *   1. stop every scan — the active scanner replays stored request headers, so a
 *      running scan keeps authenticating after its rule is gone;
 *   2. remove the credential rules;
 *   3. newSession — discards the stored requests, which still carry the header,
 *      and are readable through the API;
 *   4. re-enable rule 10105 (instance-wide setting) for whoever scans next.
 * Never throws: every step is attempted even if an earlier one failed.
 * @returns {Promise<{steps: Object<string, boolean>}>} which steps succeeded
 */
async function revokeScanCredentials(zapClient, { scanId, contextName, extraContextNames = [], reEnableInsecureAuthRule = false } = {}) {
  const steps = {};
  const attempt = async (name, fn) => { try { await fn(); steps[name] = true; } catch (_) { steps[name] = false; } };
  await attempt('stopActiveScans', () => zapClient.get('/JSON/ascan/action/stopAllScans/'));
  await attempt('stopSpiders', () => zapClient.get('/JSON/spider/action/stopAllScans/'));
  await attempt('stopAjaxSpider', () => zapClient.get('/JSON/ajaxSpider/action/stop/'));
  await attempt('removeRules', async () => {
    await purgeCredentialRules(zapClient);
    if (scanId) {
      try { await zapPost(zapClient, '/JSON/replacer/action/removeRule/', { description: basicRuleDescription(scanId) }); } catch (_) { /* gone */ }
    }
  });
  if (contextName) {
    await attempt('removeContext', () => zapClient.get('/JSON/context/action/removeContext/', { params: { contextName } }));
  }
  // A token scan's per-API-host contexts (form login only; Basic passes none).
  for (const [i, name] of (Array.isArray(extraContextNames) ? extraContextNames : []).entries()) {
    if (name) await attempt(`removeApiContext${i}`, () => zapClient.get('/JSON/context/action/removeContext/', { params: { contextName: name } }));
  }
  await attempt('newSession', () => zapClient.get('/JSON/core/action/newSession/', {
    params: { name: `revoked-${scanId || Date.now()}`, overwrite: 'true' }, timeout: 30000
  }));
  if (reEnableInsecureAuthRule) await attempt('reEnableInsecureAuthRule', () => setInsecureAuthRule(zapClient, true));
  return { steps };
}

/**
 * How much of the target ZAP actually reached signed in, from the status codes
 * ZAP stored (search API: no response bodies are transferred).
 * A scan whose requests mostly got 401 "completed" against the login prompt, not
 * the application — that must be reported as an authentication failure.
 * @returns {Promise<{ok:number, unauthorized:number, forbidden:number, other:number, verdict:'authenticated'|'degraded'|'failed'|'unknown'}>}
 */
async function measureAuthCoverage(zapClient, origin, { pageSize = 500, maxMessages = 20000, anyScheme = false } = {}) {
  const counts = { ok: 0, unauthorized: 0, forbidden: 0, other: 0 };
  // Basic is https-only by construction; a Bearer API origin is whatever the app used.
  const regex = anyScheme ? exactOriginRegex(origin) : originRuleRegex(origin);
  try {
    for (let start = 0; start < maxMessages; start += pageSize) {
      const res = await zapClient.get('/JSON/search/view/urlsByUrlRegex/', { params: { regex, baseurl: origin, start, count: pageSize } });
      const rows = (res && res.data && res.data.urlsByUrlRegex) || [];
      for (const r of rows) {
        const code = Number(r && r.code);
        if (code >= 200 && code < 400) counts.ok++;
        else if (code === 401) counts.unauthorized++;
        else if (code === 403) counts.forbidden++;
        else counts.other++;
      }
      if (rows.length < pageSize) break;
    }
  } catch (_) {
    return { ...counts, verdict: 'unknown' };
  }
  const judged = counts.ok + counts.unauthorized;
  const verdict = judged === 0 ? 'unknown'
    : counts.ok === 0 ? 'failed'
      : counts.unauthorized >= counts.ok ? 'degraded'
        : 'authenticated';
  return { ...counts, verdict };
}

/**
 * Status code of the most recent response ZAP stored for a URL, or null.
 * Used to ask "is the Basic credential still accepted?" during a scan.
 */
async function latestStatusFor(zapClient, url) {
  try {
    const exact = `^${escapeJavaRegex(url)}$`;
    const res = await zapClient.get('/JSON/search/view/urlsByUrlRegex/', { params: { regex: exact, start: 0, count: 1000 } });
    const rows = (res && res.data && res.data.urlsByUrlRegex) || [];
    if (!rows.length) return null;
    const last = rows.reduce((a, b) => (Number(b.id) > Number(a.id) ? b : a));
    const code = Number(last.code);
    return Number.isFinite(code) ? code : null;
  } catch (_) {
    return null;
  }
}

module.exports = {
  SCANNER_INITIATORS,
  COOKIE_RULE,
  BASIC_RULE_PREFIX,
  BEARER_RULE_PREFIX,
  INSECURE_AUTH_PSCAN_RULE,
  basicRuleDescription,
  bearerRuleDescription,
  originRuleRegex,
  exactOriginRegex,
  bearerRuleRegex,
  siteScopeRegexes,
  apiContextExcludeRegexes,
  applyBasicAuthRule,
  applyBearerRule,
  purgeCredentialRules,
  setInsecureAuthRule,
  revokeScanCredentials,
  measureAuthCoverage,
  latestStatusFor,
  zapPost,
};
