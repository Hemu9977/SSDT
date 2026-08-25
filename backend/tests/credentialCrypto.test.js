'use strict';

/**
 * Tests for credential encryption at rest.
 *
 * Scheduled authenticated scans keep the customer's login details so the scan
 * can sign itself in later. Those values used to be written to MongoDB as
 * readable text.
 *
 * Run with: node --test backend/tests/credentialCrypto.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const crypto = require('../utils/credentialCrypto');

const KEY = 'a'.repeat(32);

function withKey(value, fn) {
  const previous = process.env.CREDENTIAL_ENCRYPTION_KEY;
  if (value === undefined) {
    delete process.env.CREDENTIAL_ENCRYPTION_KEY;
  } else {
    process.env.CREDENTIAL_ENCRYPTION_KEY = value;
  }
  crypto._resetKeyCache();
  try {
    return fn();
  } finally {
    if (previous === undefined) {
      delete process.env.CREDENTIAL_ENCRYPTION_KEY;
    } else {
      process.env.CREDENTIAL_ENCRYPTION_KEY = previous;
    }
    crypto._resetKeyCache();
  }
}

test('round-trips a password', () => {
  withKey(KEY, () => {
    const secret = 'correct horse battery staple';
    const stored = crypto.encrypt(secret);

    assert.notEqual(stored, secret, 'the stored value must not be the plaintext');
    assert.ok(!stored.includes(secret), 'the plaintext must not appear in the stored value');
    assert.equal(crypto.decrypt(stored), secret);
  });
});

test('the same input encrypts differently every time', () => {
  withKey(KEY, () => {
    // A fresh random IV per value, so identical passwords across two schedules
    // do not produce identical ciphertext.
    const a = crypto.encrypt('same');
    const b = crypto.encrypt('same');
    assert.notEqual(a, b);
    assert.equal(crypto.decrypt(a), 'same');
    assert.equal(crypto.decrypt(b), 'same');
  });
});

test('a tampered value is refused, not silently mangled', () => {
  withKey(KEY, () => {
    const stored = crypto.encrypt('hunter2');
    const [version, iv, tag, data] = stored.split(':');
    // Flip the final byte of the ciphertext.
    const flipped = Buffer.from(data, 'base64');
    flipped[flipped.length - 1] ^= 0xff;
    const tampered = [version, iv, tag, flipped.toString('base64')].join(':');

    assert.throws(() => crypto.decrypt(tampered), /could not be decrypted/);
  });
});

test('a value encrypted under a different key is refused', () => {
  const stored = withKey(KEY, () => crypto.encrypt('hunter2'));
  withKey('b'.repeat(32), () => {
    assert.throws(() => crypto.decrypt(stored), /could not be decrypted/);
  });
});

test('legacy plaintext is returned unchanged', () => {
  withKey(KEY, () => {
    // Existing schedules were written before this module existed. They must keep
    // working, and get re-encrypted the next time the document is saved.
    assert.equal(crypto.decrypt('an-old-plaintext-password'), 'an-old-plaintext-password');
    assert.equal(crypto.isEncrypted('an-old-plaintext-password'), false);
  });
});

test('encrypting an already-encrypted value is a no-op', () => {
  withKey(KEY, () => {
    // Reading a document and saving it again must not wrap the value twice.
    const once = crypto.encrypt('secret');
    const twice = crypto.encrypt(once);
    assert.equal(twice, once);
    assert.equal(crypto.decrypt(twice), 'secret');
  });
});

test('refuses to encrypt without a key rather than storing plaintext', () => {
  withKey(undefined, () => {
    assert.equal(crypto.isConfigured(), false);
    assert.throws(() => crypto.encrypt('secret'), /CREDENTIAL_ENCRYPTION_KEY/);
  });
});

test('accepts a 64-character hex key as raw key material', () => {
  withKey('0'.repeat(64), () => {
    assert.equal(crypto.isConfigured(), true);
    assert.equal(crypto.decrypt(crypto.encrypt('secret')), 'secret');
  });
});

test('passes through non-strings and empty values', () => {
  withKey(KEY, () => {
    assert.equal(crypto.encrypt(null), null);
    assert.equal(crypto.encrypt(undefined), undefined);
    assert.equal(crypto.encrypt(''), '');
    assert.equal(crypto.decrypt(null), null);
    assert.equal(crypto.decrypt(''), '');
  });
});

test('the key is never derived from JWT_SECRET', () => {
  // A signing secret must not double as an encryption key: compromising one
  // would otherwise compromise both. The file may *mention* JWT_SECRET to
  // explain that; what it must never do is read it.
  const source = require('fs').readFileSync(require.resolve('../utils/credentialCrypto'), 'utf8');
  assert.ok(
    !/process\.env\.JWT_SECRET/.test(source),
    'credentialCrypto must not read JWT_SECRET'
  );
});
