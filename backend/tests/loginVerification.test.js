'use strict';

/**
 * Tests for the login verification logic.
 *
 * These run against recorded page snapshots — no browser, no network, no
 * database. That is the whole point of splitting the decision out of
 * `services/loginTestService.js`: the part that decides whether a login worked
 * is the part that was wrong, and it needs to be testable on its own.
 *
 * Run with: node --test backend/tests/loginVerification.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  cookieDelta,
  newErrorMessages,
  deriveMarker,
  scoreLoginAttempt,
  markerPresentInBody
} = require('../utils/loginSignals');

// ─────────────────────────────────────────────────────────────────────────────
// Cookies: only movement is evidence
// ─────────────────────────────────────────────────────────────────────────────

test('a protected cookie that was already there is not evidence of login', () => {
  // The regression that mattered most: nearly every site hands an anonymous
  // visitor an httpOnly session cookie on first contact. Treating its mere
  // presence as proof meant a wrong password could score as success.
  const jar = [{ name: 'JSESSIONID', value: 'abc', httpOnly: true }];
  const delta = cookieDelta(jar, jar);

  assert.equal(delta.added.length, 0);
  assert.equal(delta.changed.length, 0);
  assert.equal(delta.sessionLike.length, 0);
});

test('a session cookie whose value changed counts', () => {
  const before = [{ name: 'JSESSIONID', value: 'anonymous', httpOnly: true }];
  const after = [{ name: 'JSESSIONID', value: 'signed-in', httpOnly: true }];

  const delta = cookieDelta(before, after);
  assert.deepEqual(delta.changed, ['JSESSIONID']);
  assert.deepEqual(delta.sessionLike, ['JSESSIONID']);
});

test('a newly issued token cookie counts even without httpOnly', () => {
  const delta = cookieDelta(
    [{ name: 'lang', value: 'en' }],
    [{ name: 'lang', value: 'en' }, { name: 'token', value: 'xyz', httpOnly: false }]
  );
  assert.deepEqual(delta.sessionLike, ['token']);
});

test('a new but unrelated cookie is movement, not a session', () => {
  const delta = cookieDelta(
    [],
    [{ name: 'cookieconsent_status', value: 'dismiss', httpOnly: false }]
  );
  assert.deepEqual(delta.added, ['cookieconsent_status']);
  assert.equal(delta.sessionLike.length, 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// Errors: only new ones count
// ─────────────────────────────────────────────────────────────────────────────

test('validation markup present before and after submit is not an error', () => {
  // Component libraries keep `ng-invalid` and error wrappers in the DOM
  // permanently. Matching on presence failed logins that had succeeded.
  const standing = ['Email is required', 'Password is required'];
  assert.deepEqual(newErrorMessages(standing, standing), []);
});

test('an error that appears only after submit counts', () => {
  const after = newErrorMessages(
    ['Email is required'],
    ['Email is required', 'Invalid email or password.']
  );
  assert.deepEqual(after, ['Invalid email or password.']);
});

// ─────────────────────────────────────────────────────────────────────────────
// Marker derivation from the anonymous baseline
// ─────────────────────────────────────────────────────────────────────────────

test('derives a sign-out control as the marker', () => {
  const { marker } = deriveMarker({
    signedInText: 'Home\nAccounts\nWelcome back\nSign Off',
    anonymousText: 'Home\nAccounts\nSign In'
  });
  assert.equal(marker, 'Sign Off');
});

test('prefers an explicit sign-out control over other new text', () => {
  const { marker } = deriveMarker({
    signedInText: 'Latest offers\nLog out\nSpecial promotion',
    anonymousText: 'Home'
  });
  assert.equal(marker, 'Log out');
});

test('never picks volatile text as a marker', () => {
  // A clock or a counter differs on every load and would report the session as
  // lost the moment it ticked over.
  const { marker } = deriveMarker({
    signedInText: 'Last updated 14:32\nSession 918273645',
    anonymousText: 'Home'
  });
  assert.equal(marker, null);
});

test('identical pages yield no marker', () => {
  const text = 'Home\nAbout\nContact';
  const { marker } = deriveMarker({ signedInText: text, anonymousText: text });
  assert.equal(marker, null);
});

test('a marker absent from the raw HTML is flagged as not body-checkable', () => {
  // A single-page app renders its content with JavaScript, so the marker never
  // appears in a response body. Verification during the scan must know that and
  // return "cannot tell" rather than "signed out".
  const result = deriveMarker({
    signedInText: 'Log out',
    anonymousText: 'Home',
    signedInHtml: '<html><body><app-root></app-root></body></html>'
  });
  assert.equal(result.marker, 'Log out');
  assert.equal(result.checkableInBody, false);
});

test('a marker present in the raw HTML is body-checkable', () => {
  const result = deriveMarker({
    signedInText: 'Log out',
    anonymousText: 'Home',
    signedInHtml: '<html><body><a href="/logout">Log out</a></body></html>'
  });
  assert.equal(result.checkableInBody, true);
});

// ─────────────────────────────────────────────────────────────────────────────
// The verdict
// ─────────────────────────────────────────────────────────────────────────────

const jar = (...names) => names.map(n => ({ name: n, value: `${n}-v`, httpOnly: true }));

test('a correct login on a classic site is confirmed', () => {
  const verdict = scoreLoginAttempt({
    before: { url: 'https://site/login.jsp', cookies: jar('JSESSIONID'), errorTexts: [] },
    after: { url: 'https://site/main.jsp', cookies: [{ name: 'JSESSIONID', value: 'new', httpOnly: true }], errorTexts: [] },
    markerResult: { marker: 'Sign Off', checkableInBody: true }
  });

  assert.equal(verdict.authConfirmed, 'confirmed');
  assert.equal(verdict.authenticated, true);
  assert.equal(verdict.markerCheckableInBody, true);
});

test('a wrong password is never confirmed', () => {
  // The headline regression. Everything the old scoring accepted is present
  // here — an httpOnly cookie and a page that looks like an app — and the
  // verdict must still not be "confirmed".
  const verdict = scoreLoginAttempt({
    before: { url: 'https://site/login', cookies: jar('JSESSIONID'), errorTexts: [] },
    after: { url: 'https://site/login', cookies: jar('JSESSIONID'), errorTexts: ['Invalid email or password.'] },
    markerResult: { marker: null, checkableInBody: false }
  });

  assert.equal(verdict.authConfirmed, 'failed');
  assert.equal(verdict.authenticated, false);
});

test('a wrong password with no error message is still not confirmed', () => {
  // Some sites fail silently. Without a marker there is nothing to confirm, so
  // the answer is "could not confirm" — amber, never green.
  const verdict = scoreLoginAttempt({
    before: { url: 'https://site/login', cookies: [], errorTexts: [] },
    after: { url: 'https://site/login', cookies: jar('sessionid'), errorTexts: [] },
    markerResult: { marker: null, checkableInBody: false }
  });

  assert.equal(verdict.authConfirmed, 'unconfirmed');
  assert.notEqual(verdict.authConfirmed, 'confirmed');
});

test('a click that reached nothing is reported as no observable change', () => {
  // The Juice Shop case: the detector picked a header button, the click
  // succeeded at doing nothing, and this was reported as a credential problem.
  const identical = { url: 'https://site/#/login', cookies: jar('lang'), errorTexts: [] };
  const verdict = scoreLoginAttempt({
    before: identical,
    after: identical,
    markerResult: { marker: null, checkableInBody: false }
  });

  assert.equal(verdict.authConfirmed, 'failed');
  assert.ok(verdict.evidenceCodes.includes('no_observable_change'));
});

test('a marker outranks a stale error message', () => {
  const verdict = scoreLoginAttempt({
    before: { url: 'https://site/login', cookies: [], errorTexts: [] },
    after: { url: 'https://site/home', cookies: [], errorTexts: ['Please check your details'] },
    markerResult: { marker: 'Log out', checkableInBody: true }
  });
  assert.equal(verdict.authConfirmed, 'confirmed');
});

test('evidence codes are identifiers, never prose', () => {
  // These reach the frontend, where the language policy forbids rendering any
  // backend-authored English.
  const verdict = scoreLoginAttempt({
    before: { url: 'https://site/login', cookies: [], errorTexts: [] },
    after: { url: 'https://site/home', cookies: jar('session'), errorTexts: [] },
    markerResult: { marker: 'Log out', checkableInBody: true }
  });

  for (const code of verdict.evidenceCodes) {
    assert.match(code, /^[a-z_]+$/, `evidence code "${code}" must be a stable identifier`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Body checking
// ─────────────────────────────────────────────────────────────────────────────

test('marker matching in a body is case-insensitive', () => {
  assert.equal(markerPresentInBody('<a>LOG OUT</a>', 'Log out'), true);
  assert.equal(markerPresentInBody('<a>Sign in</a>', 'Log out'), false);
});

test('an empty body is not a match', () => {
  assert.equal(markerPresentInBody('', 'Log out'), false);
  assert.equal(markerPresentInBody(null, 'Log out'), false);
});

// ─────────────────────────────────────────────────────────────────────────────
// Hostile inputs
//
// These run inside a scan that must degrade rather than crash: a thrown error
// here would fail a scan that should simply have reported "could not confirm".
// ─────────────────────────────────────────────────────────────────────────────

test('marker derivation survives missing pages', () => {
  for (const args of [
    {},
    { signedInText: null, anonymousText: null },
    { signedInText: '', anonymousText: '' },
    { signedInText: undefined, anonymousText: 'Home', signedInHtml: undefined }
  ]) {
    const r = deriveMarker(args);
    assert.equal(r.marker, null);
    assert.equal(r.checkableInBody, false);
    assert.ok(Array.isArray(r.alternates));
  }
});

test('scoring survives missing snapshots', () => {
  const v = scoreLoginAttempt({});
  assert.equal(v.authConfirmed, 'failed');
  assert.equal(v.authenticated, false);
  assert.ok(v.evidenceCodes.includes('no_observable_change'));
});

test('cookie comparison survives null jars', () => {
  for (const [a, b] of [[null, null], [undefined, []], [[], undefined]]) {
    const d = cookieDelta(a, b);
    assert.deepEqual(d.added, []);
    assert.deepEqual(d.changed, []);
    assert.deepEqual(d.sessionLike, []);
  }
});

test('error diffing survives null lists', () => {
  assert.deepEqual(newErrorMessages(null, null), []);
  assert.deepEqual(newErrorMessages(undefined, ['boom']), ['boom']);
});

test('a marker containing regex characters is matched literally', () => {
  // Markers come from the customer's own page, so they can contain anything.
  // Building a regex from one unescaped would throw, or match the wrong thing.
  assert.equal(markerPresentInBody('welcome (admin) back', 'welcome (admin)'), true);
  assert.equal(markerPresentInBody('a+b', 'a+b'), true);
  assert.doesNotThrow(() => markerPresentInBody('x', 'a[unclosed'));
  assert.doesNotThrow(() => markerPresentInBody('x', 'a( b'));
});
