'use strict';

/**
 * The scan-target guard — one implementation, every entry point.
 *
 * There used to be two guards with different rules: a strict one in
 * virustotalRoutes and a looser one in utils, written on my advice that
 * "customers scan internal apps". That advice was wrong: the scanner runs in
 * ECS, so a private address resolves inside our own VPC, not the customer's.
 *
 * And both matched on IP ranges, while the internal services are reached by
 * hostname — `zap-scanner`, `webcheck`. Combined with ZAP running
 * `api.disablekey=true`, any authenticated customer could aim the login test at
 * `http://zap-scanner:8080/JSON/...` and reach an unauthenticated admin API.
 *
 * Run with: node --test backend/tests/scanTargetGuard.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { checkScanTarget, isValidScanUrl } = require('../utils/scanTargetGuard');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
const refuse = (url) => {
  const r = checkScanTarget(url);
  assert.equal(r.ok, false, `${url} must be refused`);
  return r.code;
};
const allow = (url) => assert.equal(checkScanTarget(url).ok, true, `${url} must be allowed`);

// ─────────────────────────────────────────────────────────────────────────────
// The hole that prompted this round
// ─────────────────────────────────────────────────────────────────────────────

test('our own service hostnames are refused', () => {
  // ZAP runs with no API key and accepts any caller address, so reaching it at
  // all is reaching its admin API.
  for (const url of [
    'http://zap-scanner:8080/JSON/core/action/shutdown/',
    'http://zap-auth-scanner:8080/JSON/core/view/messages/',
    'http://webcheck:3000/api/ssl?url=x',
    'http://redis:6379/',
    'http://backend/'
  ]) {
    assert.equal(refuse(url), 'BLOCKED_TARGET', url);
  }
});

test('a single-label host is refused even if nobody listed it', () => {
  // The rule that catches the *next* internal service, rather than the ones
  // someone remembered to add to a denylist.
  for (const url of ['http://anything-internal:9000/', 'https://newservice/', 'http://db:5432/']) {
    assert.equal(refuse(url), 'BLOCKED_TARGET', url);
  }
});

test('hosts named by the environment are refused, derived not hardcoded', () => {
  // Renaming a service in the task definition must not silently open a hole.
  const previous = process.env.ZAP_API_URL;
  process.env.ZAP_API_URL = 'http://renamed-scanner.svc.internal:8080';
  try {
    // Re-require so module-load-time reads pick up the change.
    delete require.cache[require.resolve('../utils/scanTargetGuard')];
    const fresh = require('../utils/scanTargetGuard');
    assert.equal(fresh.checkScanTarget('http://renamed-scanner.svc.internal/').ok, false);
  } finally {
    if (previous === undefined) delete process.env.ZAP_API_URL;
    else process.env.ZAP_API_URL = previous;
    delete require.cache[require.resolve('../utils/scanTargetGuard')];
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// No regression in what the public scan already refused
// ─────────────────────────────────────────────────────────────────────────────

test('every host the public scan already blocked is still blocked', () => {
  // Its rules were adopted wholesale; this proves nothing was lost in the move.
  for (const url of [
    'http://localhost/', 'http://127.0.0.1/', 'http://127.5.5.5/',
    'http://0.0.0.0/', 'http://10.1.2.3/', 'http://172.16.0.1/',
    'http://172.31.255.254/', 'http://192.168.0.1/', 'http://169.254.169.254/',
    'http://[::1]/', 'http://[fc00::1]/', 'http://[fe80::1]/',
    'http://printer.local/'
  ]) {
    assert.equal(refuse(url), 'BLOCKED_TARGET', url);
  }
});

test('172.32 is public and must NOT be blocked', () => {
  // The private range stops at 172.31; a range check that is one octet sloppy
  // would refuse real customer sites.
  allow('http://172.32.0.1/');
  allow('http://172.15.0.1/');
});

test('non-http schemes are refused', () => {
  for (const url of ['file:///etc/passwd', 'data:text/html,<h1>x', 'ftp://example.com/']) {
    assert.equal(refuse(url), 'UNSUPPORTED_SCHEME', url);
  }
});

test('malformed input is refused rather than throwing', () => {
  for (const bad of ['', '   ', 'not a url', '://nope', null, undefined, {}, 42]) {
    const r = checkScanTarget(bad);
    assert.equal(r.ok, false);
    assert.equal(r.code, 'INVALID_URL');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Real customer sites still work
// ─────────────────────────────────────────────────────────────────────────────

test('ordinary customer sites are allowed', () => {
  for (const url of [
    'https://example.com/', 'https://demo.testfire.net/login.jsp',
    'https://preview.owasp-juice.shop/#/login', 'https://quizmint.me/',
    'http://example.com:8080/path?q=1', 'https://sub.domain.co.jp/a/b'
  ]) allow(url);
});

test('the back-compat shape still answers { valid, error }', () => {
  // virustotalRoutes speaks this shape; changing it would alter the response the
  // existing UI already handles.
  assert.deepEqual(isValidScanUrl('https://example.com/'), { valid: true });
  const bad = isValidScanUrl('http://localhost/');
  assert.equal(bad.valid, false);
  assert.equal(typeof bad.error, 'string');
  assert.equal(bad.code, 'BLOCKED_TARGET');
});

// ─────────────────────────────────────────────────────────────────────────────
// Every entry point uses it, and there is only one of it
// ─────────────────────────────────────────────────────────────────────────────

test('every route that takes a URL from the client guards it', () => {
  // A census, so a new route cannot quietly skip the check.
  const expected = {
    'routes/zapAuthRoutes.js': 4,   // detect, test-login, scan target + login
    'routes/scheduleRoutes.js': 4,  // create and update, target + login each
    'routes/webCheckRoutes.js': 1,
    'routes/zapRoutes.js': 1,
    'routes/urlscanRoutes.js': 1,
    'routes/pageSpeedRoutes.js': 1
  };
  for (const [file, count] of Object.entries(expected)) {
    const found = (read(file).match(/checkScanTarget\(/g) || []).length;
    assert.ok(found >= count, `${file}: expected at least ${count} guard calls, found ${found}`);
  }
  // The public scan uses the back-compat wrapper.
  assert.match(read('routes/virustotalRoutes.js'), /isValidScanUrl/);
});

test('there is exactly one implementation of the host rules', () => {
  // Two guards drifted apart once already; that is what let the hostname gap
  // exist in both.
  const routeDir = path.join(__dirname, '..', 'routes');
  for (const file of fs.readdirSync(routeDir)) {
    const src = fs.readFileSync(path.join(routeDir, file), 'utf8');
    assert.ok(
      !/BLOCKED_HOST_PATTERNS\s*=/.test(src),
      `${file} defines its own host blocklist; there must be only one`
    );
  }
});
