'use strict';

/**
 * ZAP credential rules (services/zapCredentialRules.js), against a recording stub
 * of the axios ZAP client. The live behaviour these encode was verified on the
 * production ZAP image (2.17.0, sha256:781a2bdaea47…) in the Phase 0 PoC.
 *
 * Run with: node --test backend/tests/zapCredentialRules.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const R = require('../services/zapCredentialRules');

const AUTH = `Basic ${Buffer.from('alice:S3cr3t-Pa55!').toString('base64')}`;

function stubClient({ rules = [], failOn = null, searchRows = [] } = {}) {
  const calls = [];
  const fail = (path) => failOn && path.includes(failOn);
  return {
    calls,
    get: async (path, cfg = {}) => {
      calls.push({ method: 'GET', path, params: cfg.params || {} });
      if (fail(path)) throw new Error('boom');
      if (path === '/JSON/replacer/view/rules/') return { data: { rules: rules.map(d => ({ description: d })) } };
      if (path === '/JSON/search/view/urlsByUrlRegex/') {
        const { start = 0, count = 500 } = cfg.params || {};
        return { data: { urlsByUrlRegex: searchRows.slice(start, start + count) } };
      }
      return { data: { Result: 'OK' } };
    },
    post: async (path, body, cfg = {}) => {
      calls.push({ method: 'POST', path, body: String(body), headers: cfg.headers || {} });
      if (fail(path)) throw new Error('boom');
      return { data: { Result: 'OK' } };
    }
  };
}

// Java `(?i)` → JS flag, so the regex ZAP receives can be exercised here.
const asJs = (javaRegex) => new RegExp(javaRegex.replace(/^\(\?i\)/, ''), javaRegex.startsWith('(?i)') ? 'i' : '');

test('origin regex: whole-URL match for exactly one https origin (Phase 0 R.1/RCI.1 matrix)', () => {
  const re = asJs(R.originRuleRegex('https://target.example.com'));
  const yes = ['https://target.example.com', 'https://target.example.com/', 'https://target.example.com:443',
    'https://target.example.com/admin/?x=1', 'https://TARGET.EXAMPLE.COM/api/'];
  const no = ['http://target.example.com/', 'http://target.example.com:443/', 'https://target.example.com:8443/',
    'https://target.example.com:4430/', 'https://sub.target.example.com/', 'https://other.example.com/',
    'https://other.example.com/?u=https://target.example.com/', 'https://target.example.com.other.example.com/',
    'https://target.example.com@other.example.com/', 'https://targetXexample.com/'];
  for (const u of yes) assert.ok(re.test(u), `should match ${u}`);
  for (const u of no) assert.ok(!re.test(u), `must not match ${u}`);

  const port = asJs(R.originRuleRegex('https://target.example.com:8443'));
  assert.ok(port.test('https://target.example.com:8443/x'));
  assert.ok(!port.test('https://target.example.com/x'), 'explicit port is required when the origin has one');
  assert.throws(() => R.originRuleRegex('http://target.example.com'), /https/);
});

test('Basic rule: POST body, scanner initiators only, per-scan name, never in a URL', async () => {
  const c = stubClient();
  await R.applyBasicAuthRule(c, { scanId: 'zap-auth-1/x', origin: 'https://t.example', authorization: AUTH });
  assert.equal(c.calls.length, 1);
  const call = c.calls[0];
  assert.equal(call.method, 'POST');
  assert.equal(call.path, '/JSON/replacer/action/addRule/');
  assert.equal(call.headers['Content-Type'], 'application/x-www-form-urlencoded');
  const p = new URLSearchParams(call.body);
  assert.equal(p.get('replacement'), AUTH);
  assert.equal(p.get('initiators'), '2,3,6,10', 'proxy initiator (1) excluded');
  assert.equal(p.get('matchString'), 'Authorization');
  assert.equal(p.get('description'), 'auth_basic_zap-auth-1_x');
  assert.equal(p.get('url'), R.originRuleRegex('https://t.example'));
  assert.ok(!call.path.includes('Basic') && !JSON.stringify(call.params || {}).includes('Basic'));
});

test('purge removes every credential rule left by any scan (rules survive newSession)', async () => {
  const c = stubClient({ rules: ['Remove CSP', 'auth_cookie', 'auth_basic_old-1', 'auth_basic_old-2', 'unrelated'] });
  const removed = await R.purgeCredentialRules(c);
  assert.deepEqual(removed.sort(), ['auth_basic_old-1', 'auth_basic_old-2', 'auth_cookie']);
  assert.ok(c.calls.filter(x => x.path === '/JSON/replacer/action/removeRule/').every(x => x.method === 'POST'));
});

test('revocation order: stop every scan → remove rules → newSession → re-enable 10105 (Phase 0 K.2/K.2b/K.2c)', async () => {
  const c = stubClient({ rules: ['auth_basic_s1'] });
  const { steps } = await R.revokeScanCredentials(c, { scanId: 's1', contextName: 'auth_scan_s1', reEnableInsecureAuthRule: true });
  const seq = c.calls.map(x => x.path);
  const idx = (p) => seq.findIndex(s => s.startsWith(p));
  const lastIdx = (p) => seq.map((s, i) => (s.startsWith(p) ? i : -1)).filter(i => i >= 0).pop();
  assert.ok(idx('/JSON/ascan/action/stopAllScans/') >= 0);
  assert.ok(idx('/JSON/spider/action/stopAllScans/') >= 0);
  assert.ok(idx('/JSON/ajaxSpider/action/stop/') >= 0);
  const firstRemove = idx('/JSON/replacer/action/removeRule/');
  assert.ok(firstRemove > idx('/JSON/ascan/action/stopAllScans/'), 'rules removed only after scans stop');
  assert.ok(idx('/JSON/core/action/newSession/') > lastIdx('/JSON/replacer/action/removeRule/'), 'session discarded after rules removed');
  assert.ok(idx('/JSON/pscan/action/enableScanners/') > idx('/JSON/core/action/newSession/'));
  assert.ok(Object.values(steps).every(Boolean), JSON.stringify(steps));
});

test('revocation never throws and still attempts every step when ZAP misbehaves', async () => {
  const c = stubClient({ failOn: 'stopAllScans' });
  const { steps } = await R.revokeScanCredentials(c, { scanId: 's2' });
  assert.equal(steps.stopActiveScans, false);
  assert.equal(steps.newSession, true, 'later steps still ran');
  assert.ok(c.calls.some(x => x.path === '/JSON/core/action/newSession/'));
  assert.ok(!c.calls.some(x => x.path === '/JSON/pscan/action/enableScanners/'), '10105 untouched for form scans');
});

test('rule 10105 is toggled through pscan by POST', async () => {
  const c = stubClient();
  await R.setInsecureAuthRule(c, false);
  await R.setInsecureAuthRule(c, true);
  assert.deepEqual(c.calls.map(x => `${x.method} ${x.path} ${x.body}`), [
    'POST /JSON/pscan/action/disableScanners/ ids=10105',
    'POST /JSON/pscan/action/enableScanners/ ids=10105'
  ]);
});

test('coverage verdict separates a signed-in scan from one that only met the login prompt (Phase 0 E11/E12)', async () => {
  const rows = (ok, unauth, forbidden = 0) => [
    ...Array.from({ length: ok }, (_, i) => ({ id: String(i), code: '200' })),
    ...Array.from({ length: unauth }, (_, i) => ({ id: String(1000 + i), code: '401' })),
    ...Array.from({ length: forbidden }, (_, i) => ({ id: String(2000 + i), code: '403' }))];
  const v = async (r) => (await R.measureAuthCoverage(stubClient({ searchRows: r }), 'https://t.example', { pageSize: 50 })).verdict;
  assert.equal(await v(rows(62, 0)), 'authenticated');
  assert.equal(await v(rows(0, 6)), 'failed');
  assert.equal(await v(rows(3, 9)), 'degraded');
  assert.equal(await v(rows(0, 0, 4)), 'unknown');
  const many = await R.measureAuthCoverage(stubClient({ searchRows: rows(120, 1, 2) }), 'https://t.example', { pageSize: 50 });
  assert.deepEqual([many.ok, many.unauthorized, many.forbidden], [120, 1, 2], 'paged through every row');
  const broken = await R.measureAuthCoverage(stubClient({ failOn: 'search' }), 'https://t.example');
  assert.equal(broken.verdict, 'unknown', 'a failed read is "unknown", never "authenticated"');
});

test('latest status for a URL comes from the most recent message', async () => {
  const c = stubClient({ searchRows: [{ id: '3', code: '200' }, { id: '9', code: '401' }, { id: '5', code: '200' }] });
  assert.equal(await R.latestStatusFor(c, 'https://t.example/admin/'), 401);
  assert.equal(await R.latestStatusFor(stubClient(), 'https://t.example/'), null);
});
