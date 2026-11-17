'use strict';

/**
 * The Bearer API-host policy (utils/bearerApiScope.js), the ZAP regexes built
 * from it (services/zapCredentialRules.js), and POST /api/zap-auth/test-login
 * applying it to testLogin's result.
 *
 *  - host matching is label-boundary exact (`credit.villdesign.com.evil.net`);
 *  - shared third-party API providers are never eligible; customer-owned hosting
 *    (credit-managment-managment.onrender.com) is;
 *  - a login that set a session cookie yields no token hosts at all;
 *  - seeds are same-origin, never logout-shaped; the probe is a vetted seed;
 *  - the route stores only eligible sessions and sends host names, never tokens.
 *
 * Run with: node --test backend/tests/bearerApiScope.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const scope = require('../utils/bearerApiScope');
const rules = require('../services/zapCredentialRules');

const asJs = (javaRegex) => new RegExp(javaRegex.replace(/^\(\?i\)/, ''), javaRegex.startsWith('(?i)') ? 'i' : '');
const RENDER = 'https://credit-managment-managment.onrender.com';
const TOKEN = 'Bearer eyJhbGciOi.user-token.value-123';

// ─── Host boundaries ─────────────────────────────────────────────────────────

test('hostMatchesDomain matches the domain and its subdomains on a label boundary only', () => {
  const yes = [
    ['credit.villdesign.com', 'credit.villdesign.com'], ['a.credit.villdesign.com', 'credit.villdesign.com'],
    ['API.Stripe.com.', 'stripe.com'], ['x.y.supabase.co', 'supabase.co']
  ];
  const no = [
    ['credit.villdesign.com.evil.net', 'credit.villdesign.com'], ['evilcredit.villdesign.com', 'credit.villdesign.com'],
    ['villdesign.com', 'credit.villdesign.com'], ['evilstripe.com', 'stripe.com'], ['stripe.com.attacker.example', 'stripe.com'],
    ['', 'stripe.com'], ['stripe.com', '']
  ];
  for (const [h, d] of yes) assert.equal(scope.hostMatchesDomain(h, d), true, `${h} ∈ ${d}`);
  for (const [h, d] of no) assert.equal(scope.hostMatchesDomain(h, d), false, `${h} ∉ ${d}`);
});

test('shared third-party API providers are excluded; customer-owned hosting stays eligible', () => {
  const shared = [
    'api.stripe.com', 'm.stripe.network', 'api-m.paypal.com', 'tenant.us.auth0.com', 'dev-1.okta.com',
    'clerk.example.accounts.dev', 'api.clerk.com', 'identitytoolkit.googleapis.com', 'securetoken.googleapis.com',
    'firestore.googleapis.com', 'proj-default-rtdb.firebaseio.com', 'abcd.supabase.co', 'graph.microsoft.com',
    'login.microsoftonline.com', 'tenant.b2clogin.com', 'cognito-idp.ap-northeast-1.amazonaws.com',
    'my-bucket.s3.amazonaws.com', 'sts.amazonaws.com', 'app.auth.ap-northeast-1.amazoncognito.com',
    'api.github.com', 'shop.myshopify.com', 'abc.algolia.net', 'cdn.contentful.com', 'api.openai.com',
    'o1.ingest.sentry.io', 'api.segment.io', 'www.google-analytics.com', 'api.twilio.com', 'api.cloudflare.com'
  ];
  const eligible = [
    'credit-managment-managment.onrender.com', 'my-api.herokuapp.com', 'app.vercel.app', 'api.netlify.app',
    'api.fly.dev', 'svc-abc-an.a.run.app', 'region-proj.cloudfunctions.net', 'proj.appspot.com',
    'api.azurewebsites.net', 'abc123.execute-api.ap-northeast-1.amazonaws.com', 'xyz.appsync-api.us-east-1.amazonaws.com',
    'my-alb-1.ap-northeast-1.elb.amazonaws.com', 'api.workers.dev', 'api.villdesign.com',
    // Look-alikes of a provider are not the provider.
    'evilstripe.com', 'api.stripe.com.attacker.example'
  ];
  for (const h of shared) assert.equal(scope.isSharedThirdPartyApiHost(h), true, `${h} must be excluded`);
  for (const h of eligible) assert.equal(scope.isSharedThirdPartyApiHost(h), false, `${h} must stay eligible`);
  assert.equal(scope.apiOriginRefusal(RENDER), null, 'credit.villdesign.com\'s API stays eligible');
  assert.equal(scope.apiOriginRefusal('https://api.stripe.com'), 'shared_third_party');
  assert.equal(scope.apiOriginRefusal('http://10.0.0.5:8080'), 'refused_target');
  assert.equal(scope.apiOriginRefusal('https://api.example.com/v1'), 'invalid_origin');
  assert.equal(scope.apiOriginRefusal('https://user:pw@api.example.com'), 'invalid_origin');
});

test('logout-shaped paths are recognised (any case, camelCase, plural), other paths are not', () => {
  const logout = ['/logout', '/api/auth/logout', '/api/Logout', '/v1/signOut', '/auth/sign-out', '/sign_out', '/logoff',
    '/api/tokens/revoke', '/oauth/revoke', '/session/end', '/sessions/destroy', '/api/end-session', '/api/session/invalidate',
    '/api/log%6Fut'];
  const fine = ['/api/me', '/api/applications', '/api/users/42', '/api/session', '/auth/me', '/login', '/api/logs'];
  for (const p of logout) assert.equal(scope.isLogoutUrl(`https://h${p}`), true, p);
  for (const p of fine) assert.equal(scope.isLogoutUrl(`https://h${p}`), false, p);
  assert.equal(scope.isLogoutUrl('https://h/api/users?next=/logout'), false, 'only the path counts');
  assert.equal(scope.isLogoutUrl('not a url'), true, 'unparseable is never replayed');
});

// ─── Session filter ──────────────────────────────────────────────────────────

test('eligibleBearerSessions: a login that set a session cookie yields no token hosts', () => {
  const sessions = [{ origin: RENDER, authorization: TOKEN, seedUrls: [`${RENDER}/api/me`], verifyUrl: `${RENDER}/api/me` }];
  assert.deepEqual(scope.eligibleBearerSessions(sessions, { hasSessionCookie: true }), []);
  assert.equal(scope.eligibleBearerSessions(sessions, { hasSessionCookie: false }).length, 1);
  assert.equal(scope.eligibleBearerSessions(sessions).length, 1);
});

test('eligibleBearerSessions: shared, private, malformed and duplicate origins are dropped; seeds vetted', () => {
  const many = Array.from({ length: 60 }, (_, i) => `${RENDER}/api/items/${i}`);
  const input = [
    { origin: RENDER, authorization: ` ${TOKEN} `, verifyUrl: `${RENDER}/api/auth/logout`, seedUrls: [
      `${RENDER}/api/auth/logout`, `${RENDER}/api/me`, `${RENDER}/api/applications?page=1`,
      `${RENDER}.evil.net/api/me`, 'https://other.example/api/me', `${RENDER}/api/me`, `http://credit-managment-managment.onrender.com/api/x`,
      ...many
    ] },
    { origin: RENDER, authorization: 'Bearer second-token-for-same-origin' },
    { origin: 'https://api.stripe.com', authorization: 'Bearer sk_live_xxxxxxxxxxxx', seedUrls: [] },
    { origin: 'https://abcd.supabase.co', authorization: TOKEN, seedUrls: [] },
    { origin: 'http://169.254.169.254', authorization: TOKEN, seedUrls: [] },
    { origin: 'https://api.example.com/v1', authorization: TOKEN },
    { origin: 'https://api.example.org', authorization: 'Basic dXNlcjpwYXNz' },
    { origin: 'https://api.example.org', authorization: 'Bearer short' },
    null, 'x'
  ];
  const before = JSON.stringify(input);
  const out = scope.eligibleBearerSessions(input);
  assert.equal(JSON.stringify(input), before, 'input not mutated');
  assert.equal(out.length, 1);
  const [s] = out;
  assert.equal(s.origin, RENDER);
  assert.equal(s.authorization, TOKEN, 'trimmed');
  assert.equal(s.seedUrls.length, scope.MAX_SEEDS_PER_ORIGIN);
  assert.deepEqual(s.seedUrls.slice(0, 2), [`${RENDER}/api/me`, `${RENDER}/api/applications?page=1`]);
  assert.ok(!s.seedUrls.some(u => /logout|evil|other\.example|^http:/.test(u)), 'same origin only, no logout');
  assert.equal(s.verifyUrl, `${RENDER}/api/me`, 'a logout "probe" is replaced by the who-am-I seed');
});

// ─── ZAP regexes ─────────────────────────────────────────────────────────────

test('bearerRuleRegex: exact origin, any path except a logout path — port forms cannot bypass it', () => {
  const rx = asJs(rules.bearerRuleRegex(RENDER));
  for (const u of [RENDER, `${RENDER}/`, `${RENDER}/api/me`, `${RENDER}:443/api/me?x=1`, 'HTTPS://CREDIT-MANAGMENT-MANAGMENT.ONRENDER.COM/api/me']) {
    assert.ok(rx.test(u), u);
  }
  for (const u of [`${RENDER}/api/auth/logout`, `${RENDER}:443/api/auth/logout`, `${RENDER}/v1/SignOut`, `${RENDER}/oauth/revoke?x`,
    `${RENDER}.evil.net/api/me`, `${RENDER}:8443/api/me`, 'http://credit-managment-managment.onrender.com/api/me',
    'https://x.credit-managment-managment.onrender.com/api/me', `${RENDER}@evil.net/`]) {
    assert.ok(!rx.test(u), u);
  }
  const custom = asJs(rules.bearerRuleRegex('http://api.example.test:8080'));
  assert.ok(custom.test('http://api.example.test:8080/api/me'));
  assert.ok(!custom.test('http://api.example.test/api/me') && !custom.test('http://api.example.test:8080/logout'));
});

test('siteScopeRegexes: host and subdomains, never a look-alike domain', () => {
  const [host, subs] = rules.siteScopeRegexes('credit.villdesign.com').map(asJs);
  const inScope = (u) => host.test(u) || subs.test(u);
  for (const u of ['https://credit.villdesign.com', 'https://credit.villdesign.com/', 'http://credit.villdesign.com:8080/a?b=1',
    'https://www.credit.villdesign.com/x', 'https://a.b.credit.villdesign.com/']) assert.ok(inScope(u), u);
  for (const u of ['https://credit.villdesign.com.evil.net/', 'https://credit.villdesign.com.evil.net', 'https://x.credit.villdesign.com.evil.net/a',
    'https://evilcredit.villdesign.com/', 'https://credit.villdesign.com@evil.net/', 'https://villdesign.com/', 'ftp://credit.villdesign.com/']) {
    assert.ok(!inScope(u), u);
  }
});

test('apiContextExcludeRegexes: every logout-shaped path on that origin, nothing else', () => {
  const [ex] = rules.apiContextExcludeRegexes(RENDER).map(asJs);
  for (const u of [`${RENDER}/api/auth/logout`, `${RENDER}/LOGOUT?x=1`, `${RENDER}:443/v1/signOut`, `${RENDER}/sessions/destroy`]) assert.ok(ex.test(u), u);
  for (const u of [`${RENDER}/api/me`, `${RENDER}/api/users?next=/logout`, 'https://other.example/logout']) assert.ok(!ex.test(u), u);
});

// ─── Route: POST /api/zap-auth/test-login ────────────────────────────────────

const BACKEND = path.join(__dirname, '..');
const stub = (rel, exports) => {
  const file = path.join(BACKEND, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};
let nextLogin = null;
stub('services/loginTestService.js', { testLogin: async () => nextLogin });
stub('models/ScanResult.js', { updateOne: async () => ({}), findOne: async () => null });
stub('services/planService.js', { claimScanSlot: async () => true });
stub('services/zapCapacityManager.js', { markZapDemand: async () => {}, ensureZapCapacity: async () => {} });
stub('services/zapContainerManager.js', { requestContainer: async () => ({}), releaseContainer: async () => {} });
stub('services/zapRecycler.js', { withZapInstance: async (_k, _id, fn) => fn() });
stub('services/authFastScanService.js', { ensureAuthFastScans: async () => ({ started: true }) });
stub('services/zapAuthService.js', {
  checkZapAuthHealth: async () => ({}), startAsyncAuthScan: async () => ({}), getAuthScanStatus: async () => ({}),
  stopAuthScan: async () => ({}), isAuthScanCancelled: async () => false
});
const router = require('../routes/zapAuthRoutes');

const handlerFor = (p, method) => {
  const layer = router.stack.find(l => l.route?.path === p && l.route.methods[method]);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle;
};
async function testLoginRoute(result) {
  nextLogin = { authenticated: true, authConfirmed: 'confirmed', evidence: 'x', marker: 'Log out', cookies: [], bearer: [], ...result };
  const lines = [];
  const orig = console.log;
  console.log = (...a) => { lines.push(a.join(' ')); };
  try {
    return await new Promise((resolve) => {
      const res = {
        statusCode: 200,
        status(c) { this.statusCode = c; return this; },
        json(body) { resolve({ status: this.statusCode, body, lines }); return this; }
      };
      handlerFor('/test-login', 'post')({
        body: { loginUrl: 'https://credit.villdesign.com/login', credentials: [{ selector: '#e', value: 'qa@example.test' }] },
        user: { id: 'u1' }, params: {}, query: {}
      }, res);
    });
  } finally {
    console.log = orig;
  }
}
const renderSession = { origin: RENDER, authorization: TOKEN, seedUrls: [`${RENDER}/api/me`, `${RENDER}/api/auth/logout`], verifyUrl: `${RENDER}/api/me` };

test('route: credit.villdesign.com\'s shape — a token for its onrender.com API is accepted; only the host name leaves the server', async () => {
  const r = await testLoginRoute({ bearer: [renderSession], hasSessionCookie: false });
  assert.equal(r.body.authenticated, true);
  assert.equal(r.body.sessionKind, 'bearer');
  assert.deepEqual(r.body.authHosts, ['credit-managment-managment.onrender.com']);
  assert.equal(typeof r.body.tempSessionId, 'string');
  assert.ok(!JSON.stringify(r.body).includes('user-token'), 'never the token');
  assert.ok(!r.lines.join('\n').includes('user-token'), 'never logged');
});

test('route: a site with a session cookie keeps its cookie session and gets no token hosts', async () => {
  const r = await testLoginRoute({
    cookies: [{ name: 'sid', value: 'cookie-value-123' }], hasSessionCookie: true, bearer: [renderSession]
  });
  assert.equal(r.body.authenticated, true);
  assert.equal(r.body.sessionKind, 'cookie');
  assert.deepEqual(r.body.authHosts, []);
  assert.match(r.lines.join('\n'), /session=cookie, apiOrigins=0\)/);
});

test('route: a token sent only to a shared third-party API is no session at all', async () => {
  const r = await testLoginRoute({
    hasSessionCookie: false,
    bearer: [{ origin: 'https://api.stripe.com', authorization: 'Bearer sk_live_shared-token-123', seedUrls: [], verifyUrl: null }]
  });
  assert.equal(r.body.authenticated, false);
  assert.equal(r.body.errorCode, 'NO_SESSION_COOKIES');
  assert.equal(r.body.tempSessionId, undefined);
});
