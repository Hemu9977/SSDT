'use strict';

/**
 * The scan-target guard.
 *
 * Several routes hand a customer-supplied URL to something that fetches it
 * server-side: a headless browser during detection and the login test, and ZAP
 * once the scan starts. Before this, only `/scan` checked the host, and only
 * against the two literal strings `localhost` and `127.0.0.1` — so the cloud
 * metadata address went straight through, and `/scan` never checked `loginUrl`
 * at all even though ZAP fetches it with the session cookies attached.
 *
 * Run with: node --test backend/tests/scanTargetGuard.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { checkScanTarget } = require('../utils/scanTargetGuard');

const refused = (url) => {
  const r = checkScanTarget(url);
  assert.equal(r.ok, false, `${url} should be refused`);
  return r.code;
};
const allowed = (url) => {
  const r = checkScanTarget(url);
  assert.equal(r.ok, true, `${url} should be allowed`);
};

// ─────────────────────────────────────────────────────────────────────────────
// Must be refused
// ─────────────────────────────────────────────────────────────────────────────

test('cloud metadata addresses are refused', () => {
  // On EC2 this returns the instance role's temporary credentials.
  for (const url of [
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.170.2/v2/credentials',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://169.254.1.1/',            // rest of link-local
    'http://metadata.google.internal./' // trailing dot resolves the same
  ]) {
    assert.equal(refused(url), 'BLOCKED_TARGET', url);
  }
});

test('loopback is refused in every spelling, not just two', () => {
  // The old check compared against the literal strings 'localhost' and
  // '127.0.0.1'. Everything else here reaches the same place.
  for (const url of [
    'http://localhost/', 'http://127.0.0.1/', 'http://127.0.0.2/',
    'http://127.1.2.3:8080/', 'http://0.0.0.0/', 'http://[::1]/',
    'http://LOCALHOST/', 'http://localhost./'
  ]) {
    assert.equal(refused(url), 'BLOCKED_TARGET', url);
  }
});

test('non-http schemes are refused', () => {
  // A browser follows these, and they read the scanner's own disk.
  for (const url of ['file:///etc/passwd', 'data:text/html,<h1>x', 'ftp://example.com/']) {
    assert.equal(refused(url), 'UNSUPPORTED_SCHEME', url);
  }
});

test('malformed input is refused rather than throwing', () => {
  for (const bad of ['', 'not a url', '://nope', null, undefined, {}, 42]) {
    const r = checkScanTarget(bad);
    assert.equal(r.ok, false);
    assert.equal(r.code, 'INVALID_URL');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Must still be allowed
// ─────────────────────────────────────────────────────────────────────────────

test('ordinary customer sites are allowed', () => {
  for (const url of [
    'https://example.com/', 'https://demo.testfire.net/login.jsp',
    'https://preview.owasp-juice.shop/#/login', 'https://quizmint.me/',
    'http://example.com:8080/path?q=1'
  ]) allowed(url);
});

test('private ranges stay allowed — customers scan internal apps', () => {
  // This is a security scanner. Refusing 10.x would silently break anyone
  // pointing it at a staging box, which is a legitimate and common use.
  for (const url of [
    'http://10.0.0.5/', 'http://192.168.1.10:3000/',
    'http://172.16.4.4/', 'http://staging.internal/'
  ]) allowed(url);
});

test('loopback can be opted into where a local target is meaningful', () => {
  assert.equal(checkScanTarget('http://localhost:3000/', { allowLoopback: true }).ok, true);
});

// ─────────────────────────────────────────────────────────────────────────────
// Every server-side fetch is behind the guard
// ─────────────────────────────────────────────────────────────────────────────

test('every route that fetches a customer URL applies the guard', () => {
  // The gap was not the guard's strength, it was that two of the three routes
  // had no guard at all — and the one that did never checked `loginUrl`.
  const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

  const zapAuth = read('routes/zapAuthRoutes.js');
  // detect-login-fields, test-login, and both URLs on /scan.
  assert.ok(
    (zapAuth.match(/checkScanTarget\(/g) || []).length >= 4,
    'detect-login-fields, test-login and both /scan URLs must each be guarded'
  );

  const schedules = read('routes/scheduleRoutes.js');
  assert.match(schedules, /checkScanTarget\(targetUrl\)/);
  assert.match(schedules, /checkScanTarget\(authConfig\.loginUrl\)/);
});

test('the browser-launching routes are rate limited', () => {
  // Both spawn Chrome, and one types credentials into a third-party site.
  const zapAuth = fs.readFileSync(path.join(__dirname, '..', 'routes/zapAuthRoutes.js'), 'utf8');
  assert.match(zapAuth, /'\/detect-login-fields', auth, loginSetupLimiter/);
  assert.match(zapAuth, /'\/test-login', auth, loginSetupLimiter/);
});

test('the scan route does not take triggerSource from the caller', () => {
  // It steers notification behaviour and the active-scan query; a caller could
  // label their own manual scan 'scheduled'.
  const zapAuth = fs.readFileSync(path.join(__dirname, '..', 'routes/zapAuthRoutes.js'), 'utf8');
  assert.ok(
    !/const \{[^}]*triggerSource[^}]*\} = req\.body/.test(zapAuth),
    'triggerSource must not be read from the request body'
  );
});
