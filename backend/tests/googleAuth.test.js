'use strict';

/**
 * N1 — Google sign-in only accepts credentials issued to Fortexa, for a
 * Google-verified email. Executes utils/googleAuth.js with axios and
 * google-auth-library stubbed: no network.
 *
 * Run with: node --test backend/tests/googleAuth.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');
const CLIENT_ID = 'fortexa-client.apps.googleusercontent.com';

// ── Stubs (registered before googleAuth.js is loaded) ───────────────────────
const google = { tokeninfo: null, userinfo: null, idPayload: null, calls: [] };

require.cache[require.resolve('axios', { paths: [BACKEND] })] = {
  id: 'axios', filename: 'axios', loaded: true,
  exports: {
    async get(url, opts = {}) {
      google.calls.push(url);
      if (url.includes('tokeninfo')) {
        if (opts.params && opts.params.access_token === 'bad') throw Object.assign(new Error('invalid_token'), { response: { status: 400 } });
        return { data: google.tokeninfo };
      }
      if (url.includes('userinfo')) return { data: google.userinfo };
      throw new Error(`unexpected URL ${url}`);
    },
  },
};
require.cache[require.resolve('google-auth-library', { paths: [BACKEND] })] = {
  id: 'gal', filename: 'gal', loaded: true,
  exports: {
    OAuth2Client: class {
      async verifyIdToken({ audience }) {
        if (audience !== CLIENT_ID) throw new Error('Wrong recipient');
        return { getPayload: () => google.idPayload };
      }
    },
  },
};

const { verifyGoogleCredential } = require(path.join(BACKEND, 'utils/googleAuth.js'));

function reset({ clientVar = 'GOOGLE_CLIENT_ID' } = {}) {
  delete process.env.GOOGLE_CLIENT_ID;
  delete process.env.REACT_APP_GOOGLE_CLIENT_ID;
  if (clientVar) process.env[clientVar] = CLIENT_ID;
  google.calls = [];
  google.tokeninfo = { aud: CLIENT_ID, azp: CLIENT_ID, sub: 'g-123', email: 'boss@aevus.jp', email_verified: 'true' };
  google.userinfo = { sub: 'g-123', name: 'Boss', picture: 'https://x/p.png', email: 'boss@aevus.jp' };
  google.idPayload = { sub: 'g-123', email: 'boss@aevus.jp', email_verified: true, name: 'Boss' };
}

test('access token issued to Fortexa with a verified email is accepted', async () => {
  reset();
  const out = await verifyGoogleCredential({ googleAccessToken: 'tok' });
  assert.deepEqual(out, { name: 'Boss', email: 'boss@aevus.jp', googleId: 'g-123', picture: 'https://x/p.png' });
});

test('access token issued to ANOTHER app is refused (token replay)', async () => {
  reset();
  google.tokeninfo = { ...google.tokeninfo, aud: 'other-app.apps.googleusercontent.com', azp: 'other-app.apps.googleusercontent.com' };
  await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'audience' });
  assert.equal(google.calls.some((u) => u.includes('userinfo')), false, 'identity must not be read from a foreign token');
});

test('unverified Google email is refused on both flows', async () => {
  reset();
  google.tokeninfo.email_verified = 'false';
  await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'email_unverified' });

  reset();
  google.idPayload.email_verified = false;
  await assert.rejects(verifyGoogleCredential({ token: 'id-token' }), { reason: 'email_unverified' });
});

test('userinfo must describe the same account as tokeninfo', async () => {
  reset();
  google.userinfo.sub = 'g-999';
  await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'subject_mismatch' });
});

test('an invalid or expired access token is refused', async () => {
  reset();
  await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'bad' }));
});

test('production supplies the client id as REACT_APP_GOOGLE_CLIENT_ID: still accepted', async () => {
  reset({ clientVar: 'REACT_APP_GOOGLE_CLIENT_ID' });
  const out = await verifyGoogleCredential({ googleAccessToken: 'tok' });
  assert.equal(out.email, 'boss@aevus.jp');
  const viaId = await verifyGoogleCredential({ token: 'id-token' });
  assert.equal(viaId.googleId, 'g-123');
});

// Production incident: the backend's client-id variable held the OAuth client
// secret, so every token from the real frontend failed `audience`, unexplained.
test('a client SECRET in the client-id variable is refused as misconfigured, never logged', async () => {
  const secret = 'GOCSPX-notARealSecret0123456789ab';
  for (const clientVar of ['GOOGLE_CLIENT_ID', 'REACT_APP_GOOGLE_CLIENT_ID']) {
    reset({ clientVar: null });
    process.env[clientVar] = secret;
    const logged = [];
    const { error } = console;
    console.error = (...a) => logged.push(a.join(' '));
    try {
      await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'misconfigured' });
      await assert.rejects(verifyGoogleCredential({ token: 'id-token' }), { reason: 'misconfigured' });
    } finally {
      console.error = error;
    }
    assert.equal(google.calls.length, 0, 'no token may be sent to Google against a bad audience');
    assert.ok(logged.some((l) => l.includes(clientVar) && l.includes('client SECRET')), 'log names the variable and the cause');
    assert.ok(!logged.some((l) => l.includes(secret)), 'the secret itself is never logged');
  }
});

test('a value that is not a web client id is refused as misconfigured', async () => {
  for (const bad of ['971111874550', 'fortexa-client', 'x.apps.googleusercontent.com.evil.example', ' ' + CLIENT_ID]) {
    reset({ clientVar: null });
    process.env.GOOGLE_CLIENT_ID = bad;
    const { error } = console;
    console.error = () => {};
    try {
      await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'misconfigured' }, bad);
    } finally {
      console.error = error;
    }
  }
});

test('an audience mismatch logs both client ids so frontend/backend drift is diagnosable', async () => {
  reset();
  const other = '971111874550-other.apps.googleusercontent.com';
  google.tokeninfo = { ...google.tokeninfo, aud: other, azp: other };
  const logged = [];
  const { warn } = console;
  console.warn = (...a) => logged.push(a.join(' '));
  try {
    await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'audience' });
  } finally {
    console.warn = warn;
  }
  assert.ok(logged.some((l) => l.includes(other) && l.includes(CLIENT_ID)));
});

test('with no client id configured, Google sign-in is refused rather than unchecked', async () => {
  reset({ clientVar: null });
  await assert.rejects(verifyGoogleCredential({ googleAccessToken: 'tok' }), { reason: 'not_configured' });
  assert.equal(google.calls.length, 0);
});
