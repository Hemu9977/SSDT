'use strict';

/**
 * Credential redaction (utils/credentialRedaction.js) and the in-memory Basic
 * credential vault (services/scanCredentialVault.js).
 *
 * Run with: node --test backend/tests/credentialRedaction.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const util = require('node:util');

const {
  REDACTED, redactHeaderBlock, secretVariants, scrubText, scrubSecrets, redactAlertsEvidence, MIN_SCRUB_LENGTH
} = require('../utils/credentialRedaction');
const vault = require('../services/scanCredentialVault');
const { getSanitizedAlerts } = require('../utils/vulnFilter');

const CRED = { username: 'alice', password: 'S3cr3t-Pa55!' };
const B64 = Buffer.from('alice:S3cr3t-Pa55!').toString('base64');

// ─── Header redaction ────────────────────────────────────────────────────────

test('Authorization keeps its scheme, loses its value; every case and spacing', () => {
  const block = `GET /a HTTP/1.1\r\nHost: x.example\r\nAuthorization: Basic ${B64}\r\nauthorization:Bearer abc.def.ghi\r\nPROXY-AUTHORIZATION:   Basic ${B64}\r\n\r\n`;
  const out = redactHeaderBlock(block);
  assert.ok(!out.includes(B64), 'base64 credential survived');
  assert.ok(!out.includes('abc.def.ghi'), 'bearer token survived');
  assert.match(out, /^Authorization: Basic \[REDACTED\]\r$/m);
  assert.match(out, /^authorization:Bearer \[REDACTED\]\r$/m, 'original spacing preserved');
  assert.match(out, /^PROXY-AUTHORIZATION:\s+Basic \[REDACTED\]\r$/m);
  assert.match(out, /^Host: x\.example\r$/m, 'unrelated headers untouched');
  assert.ok(out.startsWith('GET /a HTTP/1.1\r\n'), 'request line untouched');
});

test('Cookie keeps names, loses values; Set-Cookie keeps its security attributes', () => {
  const req = 'GET / HTTP/1.1\r\nCookie: sid=abc123secret; theme=dark; csrftoken=zzz999\r\n\r\n';
  const res = 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=newsecret456; Path=/; Secure; HttpOnly; SameSite=Lax\r\n\r\n';
  const r1 = redactHeaderBlock(req), r2 = redactHeaderBlock(res);
  for (const s of ['abc123secret', 'zzz999', 'newsecret456']) assert.ok(!(r1 + r2).includes(s), `${s} survived`);
  assert.match(r1, /Cookie: sid=\[REDACTED\]; theme=\[REDACTED\]; csrftoken=\[REDACTED\]/);
  assert.match(r2, /Set-Cookie: sid=\[REDACTED\]; Path=\/; Secure; HttpOnly; SameSite=Lax/);
});

test('header names inside bodies or URLs are not mistaken for headers', () => {
  const block = 'GET /search?q=Authorization:%20Basic%20xyz HTTP/1.1\r\nHost: a\r\n\r\n';
  assert.equal(redactHeaderBlock(block), block);
  assert.equal(redactHeaderBlock(''), '');
  assert.equal(redactHeaderBlock(undefined), undefined);
});

// ─── Exact-secret scrub ──────────────────────────────────────────────────────

test('secretVariants covers password, user:password and its base64 / URL-encoded forms', () => {
  const v = secretVariants(CRED);
  for (const s of [CRED.password, `alice:${CRED.password}`, B64, encodeURIComponent(CRED.password)]) {
    assert.ok(v.includes(s), `missing variant ${s}`);
  }
  assert.deepEqual(secretVariants({ username: 'a', password: 'ab' }).filter(s => s === 'ab'), [], 'too-short secrets are not scrub targets');
  assert.ok(MIN_SCRUB_LENGTH >= 4);
});

test('scrubSecrets reaches every string at any depth and never mutates its input', () => {
  // Shape of a ZAP rule-10105 alert (Phase 0, X.2): the decoded password is in `other`.
  const alert = {
    alert: 'Authentication Credentials Captured',
    other: `[GET] [http://t/] uses insecure authentication mechanism [Basic], revealing username [alice] and password [${CRED.password}].`,
    evidence: `Authorization: Basic ${B64}`,
    instances: [{ attack: `alice:${CRED.password}`, param: encodeURIComponent(CRED.password) }]
  };
  const frozen = JSON.stringify(alert);
  const out = scrubSecrets(alert, secretVariants(CRED));
  assert.equal(JSON.stringify(alert), frozen, 'input mutated');
  const s = JSON.stringify(out);
  for (const secret of secretVariants(CRED)) assert.ok(!s.includes(secret), `secret survived: ${secret}`);
  assert.ok(s.includes(REDACTED));
  assert.equal(scrubText('nothing here', secretVariants(CRED)), 'nothing here');
  const buf = scrubSecrets(Buffer.from(`<td>${B64}</td>`), secretVariants(CRED));
  assert.ok(Buffer.isBuffer(buf) && !buf.toString().includes(B64), 'buffer (HTML report) scrubbed');
});

// ─── Output chokepoint: legacy evidence is redacted on the way out ───────────

test('getSanitizedAlerts redacts stored evidence (incl. data written before this change)', () => {
  const legacy = [{
    alert: 'X', risk: 'High',
    occurrences: [{ url: 'https://t/', request: { header: `GET / HTTP/1.1\r\nAuthorization: Basic ${B64}\r\nCookie: s=legacycookie\r\n\r\n`, body: '' },
      response: { header: 'HTTP/1.1 200 OK\r\nSet-Cookie: s=legacy2; HttpOnly\r\n\r\n', body: 'ok' } }]
  }, { alert: 'Y', risk: 'Low', occurrences: [] }];
  const out = JSON.stringify(getSanitizedAlerts(legacy, 'all'));
  for (const s of [B64, 'legacycookie', 'legacy2']) assert.ok(!out.includes(s), `${s} reached an output`);
  assert.equal(getSanitizedAlerts(legacy, 'critical-high').length, 1, 'severity filtering unchanged');
  assert.deepEqual(redactAlertsEvidence(null), null);
});

// ─── Vault ───────────────────────────────────────────────────────────────────

test('vault: two holders, released independently; purge drops at once', () => {
  vault._clear();
  vault.put('scan-a', { ...CRED, origin: 'https://a.example' });
  const c = vault.get('scan-a');
  assert.equal(c.authorization, `Basic ${B64}`);
  assert.equal(c.origin, 'https://a.example');
  vault.release('scan-a', 'zap');
  assert.ok(vault.has('scan-a'), 'one holder left');
  vault.release('scan-a', 'fast');
  assert.ok(!vault.has('scan-a'), 'removed after the last holder');
  vault.put('scan-b', { ...CRED, origin: 'https://b.example' });
  assert.ok(vault.purge('scan-b'));
  assert.ok(!vault.has('scan-b'));
});

test('vault: TTL expiry is enforced on read and by the sweep', () => {
  vault._clear();
  let t = 1_000_000;
  vault._setClock(() => t);
  try {
    vault.put('scan-ttl', { ...CRED, origin: 'https://t.example' }, { ttlMs: 1000 });
    vault.put('scan-ttl2', { ...CRED, origin: 'https://t.example' }, { ttlMs: 1000 });
    t += 999; assert.ok(vault.has('scan-ttl'));
    t += 2; assert.equal(vault.get('scan-ttl'), null, 'expired entry readable');
    assert.equal(vault.sweep(), 1, 'sweep removes the other expired entry');
    assert.equal(vault.size(), 0);
  } finally { vault._setClock(null); }
});

test('vault: a credential cannot be printed, stringified or logged', () => {
  vault._clear();
  vault.put('scan-p', { ...CRED, origin: 'https://p.example' });
  const c = vault.get('scan-p');
  for (const rendered of [util.inspect(c), JSON.stringify(c), String(c), `${c}`, util.format('%o', c), util.format('%j', { c })]) {
    for (const secret of secretVariants(CRED)) assert.ok(!rendered.includes(secret), `leaked via ${rendered}`);
  }
  assert.throws(() => { c.origin = 'https://evil.example'; }, TypeError, 'frozen');
  vault._clear();
});

test('vault: concurrent scans with different credentials never see each other', () => {
  vault._clear();
  vault.put('scan-1', { username: 'u1', password: 'first-password', origin: 'https://one.example' });
  vault.put('scan-2', { username: 'u2', password: 'second-password', origin: 'https://two.example' });
  assert.equal(vault.get('scan-1').password, 'first-password');
  assert.equal(vault.get('scan-2').password, 'second-password');
  assert.notEqual(vault.get('scan-1').authorization, vault.get('scan-2').authorization);
  vault.purge('scan-1');
  assert.equal(vault.get('scan-2').origin, 'https://two.example', 'purging one scan leaves the other');
  vault._clear();
});

test('vault: refuses incomplete input', () => {
  assert.throws(() => vault.put('', { ...CRED, origin: 'https://x' }));
  assert.throws(() => vault.put('s', { username: 'a', origin: 'https://x' }));
  assert.throws(() => vault.put('s', { ...CRED }));
});
