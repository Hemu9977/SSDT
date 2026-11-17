'use strict';

/**
 * Which request was the login, and what did the site answer?
 * (`utils/loginRequestSignals.js` — pure, no browser.)
 *
 * The login test used to judge a submission only by the page. A single-page app
 * that answers with a `role="status"` toast, or whose API is still waking up,
 * looks exactly like a click that sent nothing — and was reported as "the form
 * had no effect, pick another button" (credit.villdesign.com, 2026-11-13).
 *
 * Run with: node --test backend/tests/loginRequestSignals.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  classifyLoginRequest, classifyLoginResponse, isFailureNotice, bodyKeys
} = require('../utils/loginRequestSignals');

const EMAIL = 'qa.person@example.com';
const PASS = 'Pa ss/w0rd+&"x';
const base = { method: 'POST', resourceType: 'fetch', credentialValues: [EMAIL, PASS] };
const req = (over) => classifyLoginRequest({ ...base, ...over });

test('request: a JSON body carrying a typed value is the login', () => {
  const r = req({ url: 'https://api.other-origin.example/api/auth/login', contentType: 'application/json',
    postData: JSON.stringify({ email: EMAIL, password: PASS }) });
  assert.deepEqual(r, { isLogin: true, matchedBy: 'credential_value' });
});

test('request: URL-encoded and multipart bodies are recognised, whatever the encoding of the value', () => {
  const form = new URLSearchParams({ user: EMAIL, pass: PASS }).toString(); // '+' for spaces
  assert.equal(req({ url: 'https://site.example/login.php', contentType: 'application/x-www-form-urlencoded', postData: form }).matchedBy, 'credential_value');
  const uri = `u=${encodeURIComponent(EMAIL)}&p=${encodeURIComponent(PASS)}`; // %20 for spaces
  assert.equal(req({ url: 'https://site.example/x', postData: uri }).matchedBy, 'credential_value');
  const multipart = `--b\r\nContent-Disposition: form-data; name="username"\r\n\r\n${EMAIL}\r\n--b--`;
  assert.equal(req({ url: 'https://site.example/x', contentType: 'multipart/form-data; boundary=b', postData: multipart }).matchedBy, 'credential_value');
});

test('request: no credential value needed — a password-shaped key, a form POST, or an auth path also count', () => {
  // The browser does not always expose the body, and some apps hash or encrypt
  // the password client-side: the value would never match.
  assert.equal(req({ url: 'https://site.example/x', contentType: 'application/json', postData: '{"login":"h","passwd":"9f86d0"}', credentialValues: [] }).matchedBy, 'password_key');
  assert.equal(req({ url: 'https://site.example/x', contentType: 'application/x-www-form-urlencoded', postData: 'user_password=abc', credentialValues: [] }).matchedBy, 'password_key');
  assert.equal(req({ url: 'https://site.example/do', resourceType: 'document', postData: undefined, credentialValues: [] }).matchedBy, 'form_post');
  assert.equal(req({ url: 'https://api.example/v1/session', postData: undefined, credentialValues: [] }).matchedBy, 'auth_path');
  assert.equal(req({ url: 'https://api.example/graphql/signin', method: 'PUT', postData: '{}', credentialValues: [] }).matchedBy, 'auth_path');
});

test('request: analytics, telemetry, beacons and reads are never the login', () => {
  const body = JSON.stringify({ email: EMAIL, password: PASS });
  for (const url of [
    'https://www.google-analytics.com/g/collect?v=2', 'https://region1.analytics.google.com/g/collect',
    'https://o123.ingest.sentry.io/api/1/envelope/', 'https://api.segment.io/v1/t', 'https://in.hotjar.com/api/v2/client/sites/1/visit-data',
    'https://site.example/api/telemetry', 'https://site.example/collect', 'https://site.example/api/events',
    'https://site.example/cdn-cgi/rum', 'https://site.example/api/logs'
  ]) {
    assert.equal(req({ url, postData: body }).isLogin, false, url);
  }
  assert.equal(req({ url: 'https://site.example/api/auth/login', resourceType: 'ping', postData: body }).isLogin, false, 'sendBeacon');
  assert.equal(req({ url: 'https://site.example/login', resourceType: 'image', postData: body }).isLogin, false, 'asset');
  assert.equal(req({ url: 'https://site.example/api/auth/me', method: 'GET', postData: undefined }).isLogin, false, 'GET xhr');
  assert.equal(req({ url: 'https://site.example/api/auth/login', method: 'OPTIONS' }).isLogin, false, 'preflight');
  // `/log` must not swallow `/login`.
  assert.equal(req({ url: 'https://site.example/api/login', postData: '{}', credentialValues: [] }).matchedBy, 'auth_path');
  // A POST with no credential evidence to a non-auth path is not attributed.
  assert.equal(req({ url: 'https://site.example/api/cart', postData: '{"qty":1}', credentialValues: [] }).isLogin, false);
});

test('request: a GET form counts only for a top-level navigation that carries the credentials', () => {
  const q = `?u=${encodeURIComponent(EMAIL)}&pw=x`;
  assert.equal(req({ url: `https://site.example/login${q}`, method: 'GET', resourceType: 'document' }).matchedBy, 'credential_value');
  assert.equal(req({ url: 'https://site.example/login?password=x', method: 'GET', resourceType: 'document', credentialValues: [] }).matchedBy, 'password_key');
  assert.equal(req({ url: `https://site.example/login${q}`, method: 'GET', resourceType: 'fetch' }).isLogin, false);
  assert.equal(req({ url: 'https://site.example/login', method: 'GET', resourceType: 'document' }).isLogin, false);
});

test('request: values too short to be distinctive are not matched against bodies', () => {
  assert.equal(req({ url: 'https://site.example/api/cart', postData: '{"id":"ab"}', credentialValues: ['ab'] }).isLogin, false);
});

test('request: garbage in, no throw', () => {
  for (const input of [undefined, {}, { url: 'not a url' }, { url: 'javascript:alert(1)', method: 'POST', resourceType: 'fetch' },
    { url: 'https://x.example/login', method: 'POST', resourceType: 'fetch', postData: '{bad json', contentType: 'application/json' }]) {
    assert.doesNotThrow(() => classifyLoginRequest(input));
  }
  assert.deepEqual(bodyKeys('{bad', 'application/json'), []);
});

test('response: HTTP errors, JSON refusals and successes', () => {
  assert.equal(classifyLoginResponse({ status: 401 }), 'http_error');
  assert.equal(classifyLoginResponse({ status: 403, json: { token: 'x' } }), 'http_error');
  assert.equal(classifyLoginResponse({ status: 500 }), 'http_error');
  assert.equal(classifyLoginResponse({ status: 200, json: { success: false, message: 'Invalid email or password' } }), 'app_error');
  assert.equal(classifyLoginResponse({ status: 200, json: { ok: false } }), 'app_error');
  assert.equal(classifyLoginResponse({ status: 200, json: { status: 'error', message: 'x' } }), 'app_error');
  assert.equal(classifyLoginResponse({ status: 200, json: { errors: [{ message: 'bad credentials' }], data: { login: null } } }), 'app_error');
  assert.equal(classifyLoginResponse({ status: 200, json: { error: 'locked' } }), 'app_error');
  // Success shapes.
  assert.equal(classifyLoginResponse({ status: 200, json: { token: 'abc', user: { id: 1 } } }), 'ok');
  assert.equal(classifyLoginResponse({ status: 200, json: { data: { accessToken: 'abc' }, errors: [] } }), 'ok');
  assert.equal(classifyLoginResponse({ status: 200, json: { success: true } }), 'ok');
  assert.equal(classifyLoginResponse({ status: 200, json: { user: { id: 1 }, warning: 'password expires soon', error: null } }), 'ok');
  assert.equal(classifyLoginResponse({ status: 302 }), 'ok');
  assert.equal(classifyLoginResponse({ status: 200 }), 'ok');
  assert.equal(classifyLoginResponse({ status: 200, json: 'just a string' }), 'ok');
  assert.equal(classifyLoginResponse(), 'ok');
});

test('notice: refusal wording in English and Japanese; greetings are not refusals', () => {
  for (const text of ['Invalid email or password.', 'Incorrect password', 'Login failed', 'Your account is locked',
    'Please verify your email address before logging in.', 'Account is deactivated. Please contact support.',
    'Too many attempts', 'メールアドレスまたはパスワードが正しくありません。', 'ログインに失敗しました', 'アカウントが無効化されています。',
    'ログインする前にメールアドレスの認証を完了してください。']) {
    assert.equal(isFailureNotice(text), true, text);
  }
  for (const text of ['Welcome back, Alice!', 'Signed in', 'ようこそ', '', '   ', 'x'.repeat(400)]) {
    assert.equal(isFailureNotice(text), false, text);
  }
  assert.equal(isFailureNotice(undefined), false);
});
