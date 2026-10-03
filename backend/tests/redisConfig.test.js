'use strict';

/**
 * Redis connection-option tests.
 *
 * Production Redis is a self-managed Valkey on EC2 whose certificate is issued by
 * Fortexa's private CA, so every client must be built with that CA and the
 * certificate's hostname — and the same code must keep working unchanged against
 * public-CA endpoints (ElastiCache, Redis Cloud) and plain redis:// in development.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const ENV_KEYS = ['REDIS_URL', 'REDIS_TLS_CA', 'REDIS_TLS_SERVERNAME'];

function withEnv(env, fn) {
  const saved = Object.fromEntries(ENV_KEYS.map(k => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, env);
  try {
    return fn();
  } finally {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

const { tlsOptions, checkRedisClientHealth } = require('../config/redis');

const PEM = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n';

test('plain redis:// gets no TLS options', () => {
  withEnv({ REDIS_URL: 'redis://localhost:6379', REDIS_TLS_CA: PEM }, () => {
    assert.deepEqual(tlsOptions(), {});
  });
});

test('rediss:// without a CA trusts the public CA store (ElastiCache / Redis Cloud)', () => {
  withEnv({ REDIS_URL: 'rediss://master.example.cache.amazonaws.com:6379' }, () => {
    assert.deepEqual(tlsOptions(), { tls: {} });
  });
});

test('rediss:// with REDIS_TLS_CA pins the private CA', () => {
  withEnv({ REDIS_URL: 'rediss://u:p@redis.fortexa.internal:6379', REDIS_TLS_CA: PEM }, () => {
    assert.deepEqual(tlsOptions(), { tls: { ca: PEM } });
  });
});

test('a CA stored with escaped newlines is restored to real newlines', () => {
  const escaped = PEM.replace(/\n/g, '\\n');
  withEnv({ REDIS_URL: 'rediss://u:p@redis.fortexa.internal:6379', REDIS_TLS_CA: escaped }, () => {
    assert.equal(tlsOptions().tls.ca, PEM);
  });
});

test('REDIS_TLS_SERVERNAME overrides the name checked against the certificate', () => {
  withEnv({
    REDIS_URL: 'rediss://u:p@10.0.128.50:6379',
    REDIS_TLS_CA: PEM,
    REDIS_TLS_SERVERNAME: ' redis.fortexa.internal '
  }, () => {
    assert.deepEqual(tlsOptions(), { tls: { ca: PEM, servername: 'redis.fortexa.internal' } });
  });
});

test('blank TLS env vars are ignored rather than producing an empty CA', () => {
  withEnv({ REDIS_URL: 'rediss://h:6379', REDIS_TLS_CA: '  ', REDIS_TLS_SERVERNAME: '' }, () => {
    assert.deepEqual(tlsOptions(), { tls: {} });
  });
});

test('never disables certificate verification', () => {
  withEnv({ REDIS_URL: 'rediss://h:6379', REDIS_TLS_CA: PEM, REDIS_TLS_SERVERNAME: 'h' }, () => {
    assert.equal('rejectUnauthorized' in tlsOptions().tls, false);
  });
});

test('the startup health check gives up fast when Redis is unreachable', async () => {
  // It runs before server.listen; it used to retry for ~2 minutes, which is longer
  // than the ALB health-check grace period. Port 1 on loopback refuses at once.
  const saved = process.env.REDIS_URL;
  process.env.REDIS_URL = 'redis://127.0.0.1:1';
  const errors = console.error;
  console.error = () => {};
  try {
    const started = Date.now();
    await checkRedisClientHealth(); // must resolve, never throw
    assert.ok(Date.now() - started < 3000, `took ${Date.now() - started}ms`);
  } finally {
    console.error = errors;
    if (saved === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = saved;
  }
});
