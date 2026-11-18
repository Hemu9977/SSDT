'use strict';

/**
 * Credentials, tokens and API keys are never written to the logs.
 *
 * Found 2026-11-09: geminiService logged the first 12 characters of the Google
 * OAuth access token on every start ("token starts with ya29.a0AehfT…"), the first
 * 8–12 characters of GEMINI_API_KEY, and the AWS container-credentials URI; 46
 * call sites logged whole error objects (an axios error prints its request config:
 * API-key headers, `apikey` URL parameters and the POSTed body, which for a login
 * test is the customer's username and password); and a dead zapService.js.backup
 * shipped in the image with a hard-coded ZAP API key and a log of its prefix.
 *
 * Four layers, each tested here:
 *   1. the offending call sites are fixed — exercised in fresh child processes
 *      WITHOUT the redactor, so a regression at the call site fails on its own;
 *   2. utils/logRedaction.js redacts whatever a call site passes;
 *   3. a source census forbids the patterns that leaked;
 *   4. every process entry point installs the redactor before anything logs.
 *
 * Run with: node --test backend/tests/secretLogging.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BACKEND = path.join(__dirname, '..');
const { install, uninstall, redactString, sanitize, formatSafe, collectSecretValues, REDACTED } =
  require('../utils/logRedaction');

// Fake but realistically shaped secrets.
const OAUTH_TOKEN = 'ya29.a0AehfTSECRETtokenVALUEabcdefghijklmnopqrstuvwxyz0123456789';
const GEMINI_KEY = 'AIzaSyTESTsecretKEYvalue0123456789abcdE';
const ZAP_KEY = 'zapKEY-0123456789-secret';
const RELATIVE_URI = '/v2/credentials/2f1d7c1e-SECRET-4b2a-9e6b-0123456789ab';

/** No log contains the secret, or any 8-character window of it. */
function assertNoSecret(output, secret, label) {
  assert.ok(!output.includes(secret), `${label}: the full secret was logged`);
  for (let i = 0; i + 8 <= secret.length; i++) {
    const window = secret.slice(i, i + 8);
    if (/^[A-Za-z]+$/.test(window) && window.length < 9 && /^(AIza|ya29)/.test(window) === false && !/[0-9]/.test(window)) continue;
    assert.ok(!output.includes(window), `${label}: a fragment of the secret ("${window}") was logged`);
  }
}

// ── 1. Call sites (fresh processes, no redactor) ──────────────────────────────

/**
 * Load geminiService in a child process with `env`, optionally stubbing
 * google-auth-library so no network is touched, wait for the startup credential
 * check, and return everything written to stdout/stderr.
 */
function loadGemini(env, { stubToken } = {}) {
  const script = `
    process.chdir(${JSON.stringify(BACKEND)});
    ${stubToken ? `
    const gal = require('google-auth-library');
    const TOKEN = ${JSON.stringify(stubToken)};
    gal.GoogleAuth = class { async getClient() { return { getAccessToken: async () => ({ token: TOKEN }) }; } };
    gal.AwsClient = class { constructor() {} async getAccessToken() { return { token: TOKEN }; } };
    ` : ''}
    const g = require('./services/geminiService');
    setTimeout(async () => { try { await g.verifyCredentials(); } catch {} process.exit(0); }, 50);
  `;
  const clean = { ...process.env };
  for (const k of ['GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GOOGLE_APPLICATION_CREDENTIALS', 'ECS_CONTAINER_METADATA_URI_V4',
    'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']) delete clean[k];
  const r = spawnSync(process.execPath, ['-e', script], { env: { ...clean, ...env }, encoding: 'utf8', timeout: 60_000 });
  return `${r.stdout}\n${r.stderr}`;
}

test('geminiService start-up: a Gemini API key is reported present, never shown', () => {
  const out = loadGemini({ GEMINI_API_KEY: GEMINI_KEY });
  assert.match(out, /GEMINI_API_KEY present\s+= true/);
  assertNoSecret(out, GEMINI_KEY, 'valid key');
});

test('geminiService start-up: a malformed key is described by its length, never shown', () => {
  const bad = 'not-a-valid-key-SECRET-0123456789';
  const out = loadGemini({ GEMINI_API_KEY: bad }, { stubToken: OAUTH_TOKEN });
  assert.match(out, /format is invalid/);
  assertNoSecret(out, bad, 'malformed key');
  assertNoSecret(out, OAUTH_TOKEN, 'malformed key → ADC token');
});

test('ADC credential check: the Google OAuth access token is never logged, not even a prefix', () => {
  const out = loadGemini({}, { stubToken: OAUTH_TOKEN });
  assert.match(out, /credential verification passed .*access token obtained/);
  assertNoSecret(out, OAUTH_TOKEN, 'ADC token');
  assert.ok(!/token starts with/i.test(out));
});

test('ECS (WIF) start-up and credential check: neither the token nor the AWS credentials URI is logged', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wif-'));
  const wif = path.join(dir, 'gcp-wif.json');
  fs.writeFileSync(wif, JSON.stringify({ type: 'external_account', audience: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws',
    subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request', token_url: 'https://sts.googleapis.com/v1/token',
    service_account_impersonation_url: 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken' }));
  const out = loadGemini({ ECS_CONTAINER_METADATA_URI_V4: 'http://169.254.170.2/v4/test', AWS_REGION: 'ap-northeast-1',
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: RELATIVE_URI, GOOGLE_APPLICATION_CREDENTIALS: wif }, { stubToken: OAUTH_TOKEN });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /AUTH_MODE=VERTEX_WIF/);
  assert.match(out, /AWS_CONTAINER_CREDENTIALS_RELATIVE_URI present = true/);
  assertNoSecret(out, OAUTH_TOKEN, 'WIF token');
  assertNoSecret(out, RELATIVE_URI, 'credentials URI');
});

// ── 2. The redactor ───────────────────────────────────────────────────────────

/** An error shaped like the axios errors the ZAP / urlscan / PSI clients throw. */
function axiosError() {
  const err = new Error('Request failed with status code 500');
  err.name = 'AxiosError';
  err.code = 'ERR_BAD_RESPONSE';
  err.isAxiosError = true;
  err.config = {
    method: 'post', url: `http://zap:8080/JSON/users/action/setAuthenticationCredentials/?apikey=${ZAP_KEY}&contextId=1`,
    headers: { 'X-ZAP-API-Key': ZAP_KEY, Authorization: 'Bearer abcdef0123456789secret', 'x-auth-token': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl' },
    params: { apikey: ZAP_KEY },
    data: 'username=alice&password=Pa55-word-SECRET',
  };
  err.request = { _header: `POST / HTTP/1.1\r\nX-ZAP-API-Key: ${ZAP_KEY}\r\n` };
  err.response = { status: 500, headers: { 'set-cookie': ['sid=SESSIONSECRET123'] }, data: { echoed: 'Pa55-word-SECRET' } };
  return err;
}

test('an HTTP-client error keeps its diagnosis and loses its request: no key, header, body or URL secret', () => {
  const line = formatSafe(['❌ ZAP scan error:', axiosError()]);
  for (const s of [ZAP_KEY, 'abcdef0123456789secret', 'eyJhbGciOiJIUzI1NiJ9', 'Pa55-word-SECRET', 'SESSIONSECRET123', 'alice']) {
    assert.ok(!line.includes(s), `${s} was logged`);
  }
  for (const keep of ['Request failed with status code 500', 'ERR_BAD_RESPONSE', '500', 'POST', 'http://zap:8080/JSON/users/action/setAuthenticationCredentials/']) {
    assert.ok(line.includes(keep), `diagnosis lost: ${keep}`);
  }
});

test('every token format is redacted from plain text', () => {
  const cases = [
    `token starts with ${OAUTH_TOKEN}`,
    `key=${GEMINI_KEY}`,
    'Authorization: Bearer abcdefghij0123456789',
    'proxy says Basic dXNlcjpwYXNzd29yZA==',
    'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl',
    'stripe sk_live_51HxxxxSECRET0123456789 and whsec_abcdef0123456789',
    'aws AKIAABCDEFGHIJKLMNOP',
    'redis rediss://fortexa-app:VerySecretPass1@redis.fortexa.internal:6379',
    'mongodb+srv://admin:MongoPass99@cluster0.example.mongodb.net/db',
    'GET /api?apikey=abc123SECRET&token=tok456SECRET&page=2',
    '{"password":"hunter2-SECRET","email":"a@b.c"}',
    'Cookie: sid=COOKIESECRET; theme=dark',
    'refresh 1//0gSECRETrefreshTOKENvalue0123456789',
  ];
  for (const c of cases) {
    const out = redactString(c);
    assert.ok(out.includes(REDACTED), `not redacted: ${c}`);
    for (const s of ['ya29.a0Aeh', 'AIzaSyTEST', 'abcdefghij0123456789', 'dXNlcjpwYXNz', 'eyJhbGciOiJIUzI1NiJ9', 'sk_live_51H', 'whsec_abcd',
      'AKIAABCDEF', 'VerySecretPass1', 'MongoPass99', 'abc123SECRET', 'tok456SECRET', 'hunter2-SECRET', 'COOKIESECRET', '1//0gSECRET']) {
      assert.ok(!out.includes(s), `${s} survived in: ${out}`);
    }
  }
  // Diagnostics that only look similar are kept.
  for (const keep of ['HTTP Basic authentication protects the site', 'page=2', 'GET for POST', 'scan zap-auth-1794152897672-vmzt6y',
    'Authorization header missing', '[ZAP-AUTH] Injecting 3 cookies via Replacer API']) {
    assert.ok(redactString(keep).includes(keep.replace(/page=2/, 'page=2')), `over-redacted: ${keep}`);
  }
});

test('objects: sensitive keys are redacted at any depth; circular references are safe; input untouched', () => {
  const obj = { user: 'u1', headers: { Authorization: 'x', Cookie: 'y', 'X-ZAP-API-Key': 'z', Accept: 'text/html' },
    body: { password: 'p', otp: '123456', nested: { deeper: { token: 't', apiKey: 'k', client_secret: 's' } } } };
  obj.self = obj;
  const out = sanitize(obj);
  assert.equal(out.headers.Authorization, REDACTED);
  assert.equal(out.headers.Cookie, REDACTED);
  assert.equal(out.headers['X-ZAP-API-Key'], REDACTED);
  assert.equal(out.headers.Accept, 'text/html');
  assert.equal(out.body.password, REDACTED);
  assert.equal(out.body.otp, REDACTED);
  assert.deepEqual(out.body.nested.deeper, { token: REDACTED, apiKey: REDACTED, client_secret: REDACTED });
  assert.equal(out.self, '[Circular]');
  assert.equal(obj.body.password, 'p', 'the logged object itself is not modified');
});

test('exact values of secret environment variables are redacted anywhere in a line', () => {
  const env = { ZAP_API_KEY: ZAP_KEY, JWT_SECRET: 'jwt-signing-SECRET-value', STRIPE_SECRET_KEY: 'opaque-stripe-value-123',
    FRONTEND_URL: 'https://fortexa.aevus.jp', GOOGLE_APPLICATION_CREDENTIALS: '/app/config/gcp-wif.json', SHORT_KEY: 'abc' };
  const values = collectSecretValues(env);
  assert.ok(values.includes(ZAP_KEY) && values.includes('jwt-signing-SECRET-value') && values.includes('opaque-stripe-value-123'));
  assert.ok(!values.includes('https://fortexa.aevus.jp') && !values.includes('/app/config/gcp-wif.json') && !values.includes('abc'));

  const lines = [];
  install({ env, sink: (m, l) => lines.push(l) });
  try {
    console.log(`using key ${ZAP_KEY} for ${env.FRONTEND_URL}`);
    console.error('signing failed', { secretUsed: env.JWT_SECRET });
    console.warn('%s', 'opaque-stripe-value-123 rejected');
    console.error('❌ ZAP scan error:', axiosError());
  } finally { uninstall(); }
  const all = lines.join('\n');
  for (const s of [ZAP_KEY, 'jwt-signing-SECRET-value', 'opaque-stripe-value-123', 'Pa55-word-SECRET']) assert.ok(!all.includes(s), `${s} logged`);
  assert.ok(all.includes('https://fortexa.aevus.jp'), 'non-secret configuration is still logged');
  assert.equal(lines.length, 4);
});

// ── 2b. Bypasses found by the 2026-11-09 review (each reproduced before the fix) ──

const { ReplyError } = require('redis-errors');

test('secret-named keys in text without object context: JSON, double-encoded JSON, form bodies, prose', () => {
  const ZAP = 'hardcodedzapkeyabcdefgh';
  const PW = 'Hunter2PasswordX';
  const cases = [
    `{"X-ZAP-API-Key":"${ZAP}"}`,
    `{"cookie":"sid=s%3AcookieValueQQ"}`,
    JSON.stringify({ headers: { 'X-ZAP-API-Key': ZAP }, data: JSON.stringify({ password: PW }) }), // JSON.stringify(err.config)
    `password=${PW}&user=u`,                         // form body, password first
    `login password=${PW} rejected`,                 // prose
    `{"password":"${PW.slice(0, 8)}\\"${PW.slice(8)}"}`, // escaped quote inside the value
    `{ data: 'password: \`${PW}'x"y\`' }`,            // backtick-quoted (value has both quote kinds)
    `{"pass":"${PW}","user":"a"}`,                   // nodemailer auth object
    `'x-goog-api-key': '${ZAP}'`,
    `stripe-signature: t=1,v1=${ZAP}`,
  ];
  for (const c of cases) {
    const out = redactString(c);
    for (const s of [ZAP, PW, PW.slice(8), 'cookieValueQQ']) {
      if (c.includes(s)) assert.ok(!out.includes(s), `"${s}" survived in: ${out}`);
    }
  }
  for (const keep of ['pass: 3/5 units', 'tokens=1200 used', 'cacheKey: report-ja-1', 'secretsLoaded: 3',
    '[Localization] {"units":3,"cacheHits":2}', 'Basic auth rule configured for https://example.jp',
    'No signatures found matching the expected signature for payload']) {
    assert.equal(redactString(keep), keep, `over-redacted: ${keep}`);
  }
});

test('Basic credentials are redacted whatever their base64 looks like, also URL-encoded (Replacer body)', () => {
  const b64 = Buffer.from('user:pass').toString('base64'); // dXNlcjpwYXNz: letters only
  assert.ok(!/[0-9+/=]/.test(b64));
  for (const line of [`sent Authorization: Basic ${b64}`, `value Basic ${b64} end`, JSON.stringify({ Authorization: `Basic ${b64}` }),
    `description=auth_basic_1&matchString=Authorization&${new URLSearchParams({ replacement: `Basic ${b64}` })}`,
    `replacement=Basic%20${encodeURIComponent(Buffer.from('alice:pa ss').toString('base64'))}`]) {
    const out = redactString(line);
    assert.ok(!out.includes(b64) && !out.includes('YWxpY2U6'), `credential survived: ${out}`);
  }
  assert.equal(redactString('HTTP Basic authentication protects the site'), 'HTTP Basic authentication protects the site');
});

test('EMAIL_PASS and passwords inside MONGO_URI / REDIS_URL are scrubbed as exact values', () => {
  const env = { EMAIL_PASS: 'smtp app passwrd', MONGO_URI: 'mongodb+srv://app:M0ngo%40Pass-xyz@c0.example.net/db',
    REDIS_URL: 'rediss://fortexa-app:redisAclPassw0rdZZ@redis.fortexa.internal:6379',
    ADMIN_TOKEN_TTL: '8h-and-more', ZAP_CAPACITY_KEYS: 'normal,auth', BYPASS_CACHE: 'true-value' };
  const values = collectSecretValues(env);
  for (const v of ['smtp app passwrd', 'M0ngo%40Pass-xyz', 'M0ngo@Pass-xyz', 'redisAclPassw0rdZZ']) assert.ok(values.includes(v), `${v} not collected`);
  for (const v of ['8h-and-more', 'normal,auth', 'true-value']) assert.ok(!values.includes(v), `${v} wrongly treated as a secret`);

  const lines = [];
  install({ env, sink: (m, l) => lines.push(l) });
  try {
    console.error('smtp', { user: 'a', smtpPassword: env.EMAIL_PASS, note: `auth with ${env.EMAIL_PASS}` });
    console.error('[BullMQ] AUTH failed for', ['fortexa-app', 'redisAclPassw0rdZZ'], 'and', 'M0ngo@Pass-xyz');
  } finally { uninstall(); }
  const all = lines.join('\n');
  for (const s of ['smtp app passwrd', 'redisAclPassw0rdZZ', 'M0ngo@Pass-xyz']) assert.ok(!all.includes(s), `${s} logged`);
});

test('a Redis error never prints its command arguments (AUTH carries the ACL password)', () => {
  const err = new ReplyError('WRONGPASS invalid username-password pair or user is disabled.');
  err.command = { name: 'auth', args: ['fortexa-app', 'shortpw'] }; // what ioredis's DataHandler attaches
  const lines = [formatSafe(['[Redis] error', err]), formatSafe(['cmd', err.command]),
    formatSafe([{ wrapped: { command: { name: 'set', args: ['k', 'job-data-pw'] } } }])];
  for (const l of lines) assert.ok(!/shortpw|job-data-pw/.test(l), `args logged: ${l}`);
  assert.match(lines[0], /WRONGPASS/);
  assert.match(lines[0], /name: 'auth', args: '\[REDACTED: 2 args\]'/);
});

test('every console method is redacted: dir, trace, table, dirxml, group, assert, count, timeLog', () => {
  const ZAP = 'hardcodedzapkeyabcdefgh';
  const lines = [];
  install({ env: {}, sink: (m, l) => lines.push(`${m}:${l}`) });
  try {
    const err = axiosError();
    console.dir(err, { depth: 5, showHidden: true });
    console.dir({ headers: { 'X-ZAP-API-Key': ZAP } });
    console.trace({ headers: { 'X-ZAP-API-Key': ZAP } });
    console.table([{ apikey: ZAP, scan: 1 }]);
    console.dirxml({ password: 'Pa55-word-SECRET' });
    console.group({ token: ZAP }); console.groupEnd();
    console.assert(false, { apiKey: ZAP });
    console.count(`apikey=${ZAP}`);
    console.time('t'); console.timeLog('t', { secret: ZAP }); console.timeEnd('t');
  } finally { uninstall(); }
  const all = lines.join('\n');
  for (const s of [ZAP, 'Pa55-word-SECRET', 'abcdef0123456789secret']) assert.ok(!all.includes(s), `${s} logged: ${all}`);
  assert.match(all, /^trace:Trace: /m, 'console.trace still prints a trace');
  assert.match(all, /scan/, 'console.table still renders the rows');
});

test('cross-realm errors, AggregateError members, object-valued err.code and Map keys are sanitized', () => {
  const vm = require('node:vm');
  const foreign = vm.runInNewContext('new Error("from another realm")');
  foreign.config = axiosError().config;
  const agg = new AggregateError([axiosError()], 'all failed');
  const coded = new Error('c'); coded.code = { cookie: 'sid=COOKIESECRET123' };
  const line = formatSafe([foreign, agg, coded, new Map([[{ cookie: 'sid=COOKIESECRET123' }, 1]])]);
  for (const s of [ZAP_KEY, 'Pa55-word-SECRET', 'COOKIESECRET123']) assert.ok(!line.includes(s), `${s} logged`);
  assert.match(line, /from another realm/);
  assert.match(line, /Request failed with status code 500/, 'AggregateError members are still described');
});

/** Run `body` in a child process that installs the redactor exactly as an entry point does. */
function runInstalled(body, env = {}) {
  const script = `require(${JSON.stringify(path.join(BACKEND, 'utils/logRedaction'))}).install();\n${body}`;
  const r = spawnSync(process.execPath, ['-e', script], { env: { ...process.env, ...env }, encoding: 'utf8', timeout: 30_000 });
  return { out: `${r.stdout}\n${r.stderr}`, status: r.status };
}

const CRASH = `const e = new Error('Request failed with status code 500');
  e.config = { headers: { 'X-ZAP-API-Key': 'hardcodedzapkeyabcdefgh' }, data: '{"password":"Hunter2PasswordX"}' };`;

test('an exception before the process registers its handlers is logged redacted, and the process still exits 1', () => {
  for (const trigger of ['throw e;', 'Promise.reject(e);']) {
    const { out, status } = runInstalled(`${CRASH}\n${trigger}`);
    assert.equal(status, 1, `${trigger} must still crash the process`);
    assert.ok(!/hardcodedzapkey|Hunter2Password/.test(out), `${trigger}: secret printed:\n${out}`);
    assert.match(out, /Request failed with status code 500/);
  }
});

test('once the process registers its own crash handlers, the early ones step aside', () => {
  const { out, status } = runInstalled(`${CRASH}
    process.on('uncaughtException', (err) => { console.error('APP HANDLER', err); process.exit(7); });
    setTimeout(() => { throw e; }, 10);`);
  assert.equal(status, 7);
  assert.match(out, /APP HANDLER/);
  assert.ok(!/before the process registered/.test(out), 'the early handler also logged');
  assert.ok(!/hardcodedzapkey|Hunter2Password/.test(out));
  // An unhandled rejection reaches the app's exception handler, as Node's default would route it.
  const r2 = runInstalled(`process.on('uncaughtException', () => { console.error('ROUTED'); process.exit(8); });
    Promise.reject(new Error('late'));`);
  assert.equal(r2.status, 8);
  assert.match(r2.out, /ROUTED/);
});

test('writers that bypass console (the debug module behind ioredis, raw stream writes) are scrubbed', () => {
  const { out } = runInstalled(`
    const debug = require(${JSON.stringify(path.join(BACKEND, 'node_modules/debug'))});
    debug.enable('ioredis:*');
    debug('ioredis:redis')('write command[%s]: 0 -> auth(%o)', '10.0.128.50:6379', ['fortexa-app', 'redisAclPassw0rdZZ']);
    process.stderr.write('raw {"X-ZAP-API-Key":"hardcodedzapkeyabcdefgh"}\\n');
    process.stdout.write(Buffer.from('binary passes untouched\\n'));`,
  { REDIS_URL: 'rediss://fortexa-app:redisAclPassw0rdZZ@redis.fortexa.internal:6379' });
  assert.ok(!/redisAclPassw0rdZZ|hardcodedzapkey/.test(out), out);
  assert.match(out, /write command/);
  assert.match(out, /binary passes untouched/);
});

// ── 3. Source census ──────────────────────────────────────────────────────────

function sourceFiles(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'tests', '.git'].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) sourceFiles(p, out);
    else out.push(p);
  }
  return out;
}

/** Each console.* call as text (from `console.` to its closing parenthesis). */
function consoleCalls(src) {
  const calls = [];
  const re = /console\.(log|info|warn|error|debug)\(/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    let depth = 0, i = m.index + m[0].length - 1, quote = null;
    for (; i < src.length; i++) {
      const c = src[i];
      if (quote) { if (c === '\\') { i++; continue; } if (c === quote) quote = null; continue; }
      if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
      if (c === '(') depth++;
      else if (c === ')' && --depth === 0) break;
    }
    calls.push({ text: src.slice(m.index, i + 1), line: src.slice(0, m.index).split('\n').length });
  }
  return calls;
}

const SECRET_ENV = /process\.env\.([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS_RELATIVE_URI|_PASS\b|_PWD\b|MONGO_URI|MONGODB_URI|REDIS_URL)[A-Z0-9_]*)/g;
const FORBIDDEN = [
  [/(key|token|secret|passw|credential)\w*\)?\s*\.\s*(slice|substring|substr)\s*\(/i, 'prints part of a key/token/secret/password'],
  [/(token|key)\s+starts/i, 'prints the start of a token or key'],
  [/\$\{\s*(token|accessToken|idToken|refreshToken|apiKey|API_KEY|secret|password|jwtToken|otp)\s*\}/, 'interpolates a secret variable'],
  [/,\s*(token|accessToken|idToken|refreshToken|apiKey|API_KEY|password|otp)\s*\)/, 'passes a secret variable to console'],
];

test('source census: no console call in the backend prints a secret, or part of one', () => {
  const offenders = [];
  for (const file of sourceFiles(BACKEND).filter(f => f.endsWith('.js'))) {
    const src = fs.readFileSync(file, 'utf8');
    for (const { text, line } of consoleCalls(src)) {
      const where = `${path.relative(BACKEND, file)}:${line}`;
      for (const [re, why] of FORBIDDEN) if (re.test(text)) offenders.push(`${where} ${why}`);
      for (const env of text.matchAll(SECRET_ENV)) {
        const before = text.slice(0, env.index);
        if (!/!!\s*$/.test(before)) offenders.push(`${where} prints process.env.${env[1]}`);
      }
    }
  }
  assert.deepEqual(offenders, []);
});

test('no backup copies of source files (one shipped a hard-coded API key in the image)', () => {
  // Timestamped copies too (scripts/zap_ai_scanner.py.backup-20260107-003958 shipped
  // in the image because `*.backup` does not match it).
  const BACKUP = /\.(backup|bak|orig)([-._~]|$)/i;
  const backups = sourceFiles(BACKEND).filter(f => BACKUP.test(path.basename(f))).map(f => path.relative(BACKEND, f));
  assert.deepEqual(backups, []);
  const ignore = fs.readFileSync(path.join(BACKEND, '.dockerignore'), 'utf8');
  for (const pattern of ['*.backup*', '*.bak*', '*.orig']) {
    assert.ok(ignore.split(/\r?\n/).includes(pattern), `.dockerignore lacks ${pattern}`);
  }
});

// ── 4. Entry points ───────────────────────────────────────────────────────────

// Every process that can run with production env: the two entry points and every
// operational script (run as one-off ECS tasks; their output goes to CloudWatch).
const BUILTINS = new Set(['dotenv', 'path', 'fs', 'crypto', 'os', 'util', 'url', 'stream', 'http', 'https', 'readline', 'child_process']);
function processEntryPoints() {
  const scripts = fs.readdirSync(path.join(BACKEND, 'scripts')).filter(f => f.endsWith('.js')).map(f => `scripts/${f}`);
  const rootScripts = fs.readdirSync(BACKEND).filter(f => f.endsWith('.js') && !['db.js'].includes(f))
    .filter(f => fs.statSync(path.join(BACKEND, f)).size > 0);
  return ['workers/startWorker.js', ...rootScripts, ...scripts];
}

test('every process entry point and script installs the redactor before it loads anything that logs', () => {
  const entries = processEntryPoints();
  assert.ok(entries.includes('server.js') && entries.includes('scripts/grantSystemRole.js') && entries.includes('clear-stuck-scans.js'));
  for (const entry of entries) {
    const src = fs.readFileSync(path.join(BACKEND, entry), 'utf8');
    const installAt = src.search(/require\(['"][./]+utils\/logRedaction['"]\)\.install\(\)/);
    assert.ok(installAt >= 0, `${entry} does not install log redaction`);
    const dotenvAt = src.search(/require\(['"]dotenv['"]\)/);
    const appRequires = [...src.matchAll(/require\(['"]([^'"]+)['"]\)/g)]
      .filter(m => !BUILTINS.has(m[1].replace(/^node:/, '')) && !/logRedaction/.test(m[1]));
    if (appRequires.length) {
      assert.ok(installAt < appRequires[0].index, `${entry}: '${appRequires[0][1]}' is loaded before log redaction is installed`);
    }
    if (dotenvAt !== -1) assert.ok(dotenvAt < installAt, `${entry}: install after dotenv so secret env values are known`);
  }
});
