'use strict';

/**
 * Tests for choosing the button that submits a login form.
 *
 * The bug this guards against: with no `<form>` element on the page, detection
 * swept the whole document and took the first `<button>` in document order.
 * On any modern app that is a header control — a sidebar toggle, a language
 * picker, an account menu — and never the login button. Clicking it succeeded
 * at doing nothing, which was then reported to the customer as a login failure.
 *
 * Run with: node --test backend/tests/submitButtonRanking.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  rankSubmitButtons,
  isNavigationButton,
  isThirdPartyButton,
  autoRetryCandidates,
  scoreSubmitButton
} = require('../utils/loginFormRanking');

const button = (id, text, extra = {}) => ({
  tagName: 'BUTTON',
  inputType: 'submit',
  id,
  buttonText: text,
  label: text,
  className: '',
  selector: id ? `#${id}` : 'button',
  ...extra
});

const input = (id, inputType) => ({
  tagName: 'INPUT',
  inputType,
  id,
  buttonText: '',
  label: '',
  className: '',
  selector: `#${id}`,
  classification: inputType === 'password' ? 'password' : 'username'
});

// ─────────────────────────────────────────────────────────────────────────────
// The shape that started this
// ─────────────────────────────────────────────────────────────────────────────

test('ranks the login button above header controls on a page with no form', () => {
  // Document order as a single-page app actually emits it: the whole
  // application shell comes before the routed login view.
  const fields = [
    button('', 'menu', { className: 'mat-icon-button' }),
    button('navbarLanguageSelector', 'Language'),
    button('navbarAccount', 'Account'),
    input('email', 'text'),
    input('password', 'password'),
    button('loginButton', 'Log in'),
    button('loginButtonGoogle', 'Log in with Google')
  ];

  const ranked = rankSubmitButtons(fields);

  assert.equal(ranked[0].id, 'loginButton', 'the real login button must rank first');
  assert.ok(
    !ranked.some(f => f.id === 'navbarAccount' || f.id === 'navbarLanguageSelector'),
    'header navigation controls must be excluded entirely'
  );
});

test('a third-party sign-in button ranks below the real one but stays available', () => {
  const fields = [
    input('password', 'password'),
    button('loginButtonGoogle', 'Log in with Google'),
    button('loginButton', 'Log in')
  ];

  const ranked = rankSubmitButtons(fields);
  assert.equal(ranked[0].id, 'loginButton');
  // Still offered, in case a site genuinely only has third-party sign-in.
  assert.ok(ranked.some(f => f.id === 'loginButtonGoogle'));
});

test('links that leave the form rank below the submit button', () => {
  const fields = [
    input('password', 'password'),
    button('forgotPassword', 'Forgot password?'),
    button('newCustomerLink', 'Not yet a customer?'),
    button('loginButton', 'Log in')
  ];

  assert.equal(rankSubmitButtons(fields)[0].id, 'loginButton');
});

// ─────────────────────────────────────────────────────────────────────────────
// Not breaking what already worked
// ─────────────────────────────────────────────────────────────────────────────

test('a classic form with a single submit input is unchanged', () => {
  // The Altoro Mutual shape — the site that works today and must keep working.
  const fields = [
    input('uid', 'text'),
    input('passw', 'password'),
    { tagName: 'INPUT', inputType: 'submit', id: '', buttonText: '', label: '', className: '', selector: 'input[name="btnSubmit"]' }
  ];

  const ranked = rankSubmitButtons(fields);
  assert.equal(ranked.length, 1);
  assert.equal(ranked[0].selector, 'input[name="btnSubmit"]');
});

test('document order breaks ties, so equal candidates resolve as before', () => {
  const first = { ...button('', 'Submit'), selector: 'button.first' };
  const second = { ...button('', 'Submit'), selector: 'button.second' };
  // No password field, so the proximity term drops out entirely and the two
  // candidates score identically. Only the tie-break can separate them.
  const fields = [first, second];

  const ranked = rankSubmitButtons(fields);
  assert.equal(ranked.length, 2);
  // The earlier one must win — exactly what the previous `.find()` returned,
  // so pages that already resolved correctly are unaffected.
  assert.equal(ranked[0].selector, 'button.first');
});

test('a page with no buttons at all ranks nothing', () => {
  assert.deepEqual(rankSubmitButtons([input('email', 'text')]), []);
  assert.deepEqual(rankSubmitButtons([]), []);
  assert.deepEqual(rankSubmitButtons(null), []);
});

// ─────────────────────────────────────────────────────────────────────────────
// Navigation detection
// ─────────────────────────────────────────────────────────────────────────────

test('recognises navigation controls by text, id and class', () => {
  assert.equal(isNavigationButton({ buttonText: 'Close' }), true);
  assert.equal(isNavigationButton({ id: 'navbarAccount' }), true);
  assert.equal(isNavigationButton({ className: 'hamburger-toggle' }), true);
  assert.equal(isNavigationButton({ buttonText: 'Log in', id: 'loginButton' }), false);
});

test('navigation controls are refused a score outright', () => {
  assert.equal(scoreSubmitButton(button('navbarAccount', 'Account'), 0, 4), null);
});

test('a non-button field is never a submit candidate', () => {
  assert.equal(scoreSubmitButton(input('email', 'text'), 0, 1), null);
});

// ─────────────────────────────────────────────────────────────────────────────
// Automatic retry safety
// ─────────────────────────────────────────────────────────────────────────────

test('third-party sign-in is never clicked automatically', () => {
  // The retry chain runs headlessly with no one watching. Clicking "Log in with
  // Google" would navigate to an external provider and score whatever loaded
  // there.
  const fields = [
    input('password', 'password'),
    button('loginButton', 'Log in'),
    button('loginButtonGoogle', 'Log in with Google'),
    button('altSubmit', 'Continue')
  ];

  const retries = autoRetryCandidates(rankSubmitButtons(fields));
  assert.ok(
    !retries.some(f => f.id === 'loginButtonGoogle'),
    'third-party buttons must be excluded from automatic retries'
  );
  assert.ok(retries.some(f => f.id === 'altSubmit'), 'ordinary runners-up stay');
});

test('the top-ranked button is not repeated as its own retry', () => {
  const ranked = rankSubmitButtons([
    input('password', 'password'),
    button('loginButton', 'Log in'),
    button('altSubmit', 'Continue')
  ]);
  const retries = autoRetryCandidates(ranked);
  assert.notEqual(retries[0] && retries[0].id, ranked[0].id);
});

test('recognises third-party sign-in by text or id', () => {
  assert.equal(isThirdPartyButton(button('x', 'Sign in with GitHub')), true);
  assert.equal(isThirdPartyButton(button('loginButtonGoogle', 'Continue')), true);
  assert.equal(isThirdPartyButton(button('loginButton', 'Log in')), false);
  assert.equal(isThirdPartyButton(null), false);
});

test('retries are capped so the customer is not left waiting', () => {
  const many = [input('password', 'password')];
  for (let i = 0; i < 10; i++) many.push(button(`submit${i}`, 'Continue'));
  assert.ok(autoRetryCandidates(rankSubmitButtons(many)).length <= 3);
});

test('proximity decides when document order would pick the wrong one', () => {
  // The only shape where proximity actually changes the answer: two equally
  // worded buttons that both sit *before* the password field. Document order
  // alone would take the first, which is the further one from the form.
  // Without this case the whole proximity block is untested — removing it
  // leaves every other test in this file green.
  const far = { ...button('submitA', 'Continue'), selector: '#submitA' };
  const near = { ...button('submitB', 'Continue'), selector: '#submitB' };
  const ranked = rankSubmitButtons([far, near, input('password', 'password')]);

  assert.equal(ranked[0].id, 'submitB', 'the button nearest the password field must win');
});
