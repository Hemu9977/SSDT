'use strict';

/**
 * HTTP Basic pre-flight probe (services/basicAuthProbe.js) against real local
 * HTTPS servers. The target is https://127.0.0.1:<A>; a different origin is
 * https://localhost:<B>. Both servers record every Authorization header they
 * receive, so "never sent to another origin" and "tried once" are measured, not
 * assumed. Mirrors Phase 0 cases E1–E10.
 *
 * Run with: node --test backend/tests/basicAuthProbe.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

const { probeBasicAuth, parseChallenges, CODES } = require('../services/basicAuthProbe');
const { checkScanTarget } = require('../utils/scanTargetGuard');

const TLS = {
  key: fs.readFileSync(path.join(__dirname, 'fixtures/tls/test-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'fixtures/tls/test-cert.pem'))
};
const USER = 'alice', PASS = 'S3cr3t-Pa55!';
const GOOD = `Basic ${Buffer.from(`${USER}:${PASS}`).toString('base64')}`;

let target, other, A, B;
const seen = { target: [], other: [] };

function listen(handler) {
  return new Promise((resolve) => {
    const srv = https.createServer(TLS, handler);
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}
const challenge = (res, realm = 'Fortexa Test') => { res.writeHead(401, { 'WWW-Authenticate': `Basic realm="${realm}"` }); res.end('login'); };

test.before(async () => {
  other = await listen((req, res) => {
    seen.other.push({ url: req.url, auth: req.headers.authorization || null });
    if (req.url === '/challenge') return challenge(res, 'Elsewhere');
    res.writeHead(200); res.end('other');
  });
  B = other.address().port;
  target = await listen((req, res) => {
    const auth = req.headers.authorization || null;
    seen.target.push({ url: req.url, auth });
    const ok = auth === GOOD;
    switch (req.url) {
      case '/protected': return ok ? (res.writeHead(200), res.end('secret')) : challenge(res);
      case '/realm-b': return ok ? (res.writeHead(200), res.end('b')) : challenge(res, 'Other Realm');
      case '/public': res.writeHead(200); return res.end('public');
      case '/forbidden': res.writeHead(403); return res.end('waf');
      case '/digest': res.writeHead(401, { 'WWW-Authenticate': 'Digest realm="d", nonce="x", qop="auth"' }); return res.end();
      case '/same': res.writeHead(302, { Location: '/protected' }); return res.end();
      case '/cross': res.writeHead(302, { Location: `https://localhost:${B}/challenge` }); return res.end();
      case '/cross-after-auth':
        if (!ok) return challenge(res);
        res.writeHead(302, { Location: `https://localhost:${B}/landing` }); return res.end();
      case '/denied-user': return ok ? (res.writeHead(403), res.end('no')) : challenge(res);
      case '/loop': res.writeHead(302, { Location: '/loop' }); return res.end();
      case '/teapot': res.writeHead(418); return res.end();
      default: res.writeHead(404); return res.end();
    }
  });
  A = target.address().port;
});
test.after(() => { target.close(); other.close(); });

const deps = () => ({
  agent: new https.Agent({ ca: TLS.cert, keepAlive: false }),
  guard: (u) => checkScanTarget(u, { allowInternal: true })
});
const T = () => `https://127.0.0.1:${A}`;
async function probe(input) {
  seen.target.length = 0; seen.other.length = 0;
  const r = await probeBasicAuth({ username: USER, password: PASS, ...input }, deps());
  return {
    r,
    authSentToTarget: seen.target.filter(x => x.auth).length,
    authSentElsewhere: seen.other.filter(x => x.auth).length,
    requestsToOther: seen.other.length
  };
}

test('E1 valid credentials on a Basic-protected page are confirmed with one authenticated request', async () => {
  const { r, authSentToTarget, authSentElsewhere } = await probe({ targetUrl: `${T()}/protected` });
  assert.equal(r.code, CODES.CONFIRMED);
  assert.equal(r.serverRealm, 'Fortexa Test');
  assert.equal(r.origin, T());
  assert.equal(authSentToTarget, 1);
  assert.equal(authSentElsewhere, 0);
  assert.ok(!JSON.stringify(r).includes(PASS) && !JSON.stringify(r).includes(GOOD.slice(6)), 'result carries no credential');
});

test('E2 wrong password: rejected after exactly ONE attempt (no account lockout)', async () => {
  const { r, authSentToTarget } = await probe({ targetUrl: `${T()}/protected`, password: 'wrong-password' });
  assert.equal(r.code, CODES.INVALID_CREDENTIALS);
  assert.equal(authSentToTarget, 1);
});

test('E3 a public page is not "verified" by any password', async () => {
  const { r, authSentToTarget } = await probe({ targetUrl: `${T()}/public` });
  assert.equal(r.code, CODES.NOT_REQUIRED);
  assert.equal(authSentToTarget, 0, 'no credential sent to a page that never asked');
});

test('E4 a separate protected page on the same origin can be the verify URL', async () => {
  const { r } = await probe({ targetUrl: `${T()}/`, verifyUrl: '/protected' });
  assert.equal(r.code, CODES.CONFIRMED);
  assert.equal(r.verifyUrl, `${T()}/protected`);
});

test('E5 same-origin redirect is followed; the credential goes only to the page that challenged', async () => {
  const { r, authSentToTarget } = await probe({ targetUrl: `${T()}/same` });
  assert.equal(r.code, CODES.CONFIRMED);
  assert.equal(authSentToTarget, 1);
  assert.ok(seen.target.filter(x => x.auth).every(x => x.url === '/protected'));
});

test('E6 cross-origin redirect (before or after sign-in): the credential is never sent to the other origin', async () => {
  const before = await probe({ targetUrl: `${T()}/cross` });
  assert.equal(before.r.code, CODES.CROSS_ORIGIN_REDIRECT);
  assert.equal(before.authSentElsewhere, 0);
  const after = await probe({ targetUrl: `${T()}/cross-after-auth` });
  assert.equal(after.r.code, CODES.CROSS_ORIGIN_REDIRECT);
  assert.equal(after.authSentElsewhere, 0);
  assert.equal(after.requestsToOther, 0, 'the probe stops at the redirect instead of following it');
});

test('E7 a realm that differs from the one entered is a warning, not a failure', async () => {
  const { r } = await probe({ targetUrl: `${T()}/realm-b`, realm: 'Fortexa Test' });
  assert.equal(r.code, CODES.CONFIRMED);
  assert.deepEqual(r.warnings, [CODES.REALM_MISMATCH]);
  assert.equal(r.serverRealm, 'Other Realm');
});

test('E8 HTTP targets are refused before any request is made', async () => {
  const { r } = await probe({ targetUrl: `http://127.0.0.1:${A}/protected` });
  assert.equal(r.code, CODES.REQUIRES_HTTPS);
  assert.equal(r.requests, 0);
  assert.equal(seen.target.length, 0);
});

test('E9 a 403 / WAF before sign-in, and a 403 after sign-in, are told apart', async () => {
  assert.equal((await probe({ targetUrl: `${T()}/forbidden` })).r.code, CODES.TARGET_FORBIDDEN);
  assert.equal((await probe({ targetUrl: `${T()}/denied-user` })).r.code, CODES.ACCESS_DENIED);
});

test('E10 credentials embedded in the URL, and a verify URL on another origin, are refused unsent', async () => {
  assert.equal((await probe({ targetUrl: `https://u:p@127.0.0.1:${A}/protected` })).r.code, CODES.URL_HAS_CREDENTIALS);
  const off = await probe({ targetUrl: `${T()}/`, verifyUrl: `https://localhost:${B}/challenge` });
  assert.equal(off.r.code, CODES.VERIFY_URL_OFF_ORIGIN);
  assert.equal(off.requestsToOther, 0);
});

test('non-Basic schemes, redirect loops and odd statuses fail closed', async () => {
  const d = await probe({ targetUrl: `${T()}/digest` });
  assert.equal(d.r.code, CODES.SCHEME_UNSUPPORTED);
  assert.deepEqual(d.r.schemes, ['digest']);
  assert.equal(d.authSentToTarget, 0);
  assert.equal((await probe({ targetUrl: `${T()}/loop` })).r.code, CODES.TOO_MANY_REDIRECTS);
  assert.equal((await probe({ targetUrl: `${T()}/teapot` })).r.code, CODES.UNEXPECTED_STATUS);
});

test('input that could inject headers or break Basic encoding is refused', async () => {
  for (const bad of [{ username: 'a:b' }, { username: '' }, { password: '' }, { password: 'x\r\nX-Evil: 1' },
    { username: 'u\n' }, { password: 'p'.repeat(300) }, { realm: 'r\r\n' }]) {
    const { r } = await probe({ targetUrl: `${T()}/protected`, ...bad });
    assert.equal(r.code, CODES.INVALID_INPUT, JSON.stringify(Object.keys(bad)));
    assert.equal(r.requests, 0);
  }
});

test('the production guard (no allowInternal) refuses private targets before any request', async () => {
  seen.target.length = 0;
  const r = await probeBasicAuth({ targetUrl: `${T()}/protected`, username: USER, password: PASS });
  assert.equal(r.code, 'BLOCKED_TARGET');
  assert.equal(seen.target.length, 0);
});

test('WWW-Authenticate parsing handles several challenges in one header', () => {
  assert.deepEqual(parseChallenges('Digest realm="d", qop="auth", Basic realm="b"'),
    [{ scheme: 'digest', realm: 'd' }, { scheme: 'basic', realm: 'b' }]);
  assert.deepEqual(parseChallenges(['Negotiate', 'Basic realm="x"']).map(c => c.scheme), ['negotiate', 'basic']);
});
