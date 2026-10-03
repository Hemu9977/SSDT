#!/usr/bin/env node
'use strict';

/**
 * Negative security checks for the production Valkey: every connection that is not
 * "TLS + Fortexa CA + correct hostname + ACL user with the right password" must fail.
 * Uses REDIS_URL / REDIS_TLS_CA / REDIS_TLS_SERVERNAME like the backend does.
 * Exit code 0 = every probe was refused as expected.
 */

const Redis = require('ioredis');

const url = new URL(process.env.REDIS_URL);
const ca = (process.env.REDIS_TLS_CA || '').replace(/\\n/g, '\n');
const servername = process.env.REDIS_TLS_SERVERNAME || url.hostname;
const host = url.hostname;
const port = Number(url.port || 6379);

function attempt(opts) {
  return new Promise(resolve => {
    const r = new Redis({
      host, port, lazyConnect: true, connectTimeout: 5000,
      maxRetriesPerRequest: 0, retryStrategy: () => null, enableOfflineQueue: false, ...opts
    });
    let lastError = '';
    r.on('error', e => { lastError = e.message; });
    r.connect()
      .then(() => r.ping())
      .then(res => resolve({ ok: true, detail: `answered ${res}` }))
      // The 'error' event carries the real cause (TLS/auth); the rejection is often
      // just "Connection is closed".
      .catch(e => resolve({ ok: false, detail: (lastError || e.message).slice(0, 90) }))
      .finally(() => r.disconnect());
  });
}

const probes = [
  ['plaintext (no TLS) is refused', {}],
  ['TLS without the Fortexa CA is refused (untrusted chain)', { tls: { servername } }],
  ['TLS with a wrong hostname is refused', { tls: { ca, servername: 'not-redis.example.com' } }],
  ['the disabled default user is refused', { tls: { ca, servername } }],
  ['the app user with a wrong password is refused', {
    tls: { ca, servername }, username: decodeURIComponent(url.username), password: 'wrong-password'
  }],
  ['a non-existent user is refused', { tls: { ca, servername }, username: 'admin', password: 'admin' }],
];

(async () => {
  let failures = 0;
  // Positive control: the correct credentials must work, or the negatives prove nothing.
  const good = await attempt({
    tls: { ca, servername },
    username: decodeURIComponent(url.username), password: decodeURIComponent(url.password)
  });
  console.log(`${good.ok ? 'PASS' : 'FAIL'}  control: correct TLS + CA + ACL credentials connect   ${good.detail}`);
  if (!good.ok) failures++;

  for (const [name, opts] of probes) {
    const res = await attempt(opts);
    // The default user gets NOAUTH on PING rather than a handshake failure.
    const refused = !res.ok || /NOAUTH/i.test(res.detail);
    console.log(`${refused ? 'PASS' : 'FAIL'}  ${name.padEnd(56)} ${res.detail}`);
    if (!refused) failures++;
  }
  console.log(`\n${probes.length + 1 - failures}/${probes.length + 1} passed`);
  process.exit(failures ? 1 : 0);
})();
