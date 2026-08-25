'use strict';

/**
 * End-to-end decision tests against realistic page shapes.
 *
 * This is as close as we can get to the live check without a browser: the same
 * snapshots `captureSnapshot` would produce for each site, run through the real
 * `deriveMarker` + `scoreLoginAttempt` pipeline. It does not prove the browser
 * automation reaches these states — only that, once it does, the verdict is
 * right.
 *
 * The rule every scenario enforces: **a wrong password must never be
 * "confirmed".**
 *
 * Run with: node --test backend/tests/loginScenarios.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { deriveMarker, scoreLoginAttempt } = require('../utils/loginSignals');

/** Run a recorded scenario through the real pipeline. */
function verdictFor(scenario) {
  const markerResult = deriveMarker({
    signedInText: scenario.after.visibleText,
    anonymousText: scenario.anonymousText,
    signedInHtml: scenario.after.html,
    // Exactly what `testLogin` passes — without it, a failure message on the
    // page becomes its own proof of a successful sign-in.
    excludeTexts: scenario.after.errorTexts
  });
  return { ...scoreLoginAttempt({ ...scenario, markerResult }), markerResult };
}

const cookie = (name, value, httpOnly = true) => ({ name, value, httpOnly });

// ─────────────────────────────────────────────────────────────────────────────
// Altoro Mutual — the classic site that works today and must keep working
// ─────────────────────────────────────────────────────────────────────────────

const ALTORO_ANON =
  'Online Banking Login\nUsername\nPassword\nSign In\nAbout Us\nContact Us';

test('Altoro: correct password is confirmed', () => {
  const v = verdictFor({
    before: {
      url: 'https://demo.testfire.net/login.jsp',
      cookies: [cookie('JSESSIONID', 'anonymous')],
      errorTexts: []
    },
    after: {
      url: 'https://demo.testfire.net/bank/main.jsp',
      cookies: [cookie('JSESSIONID', 'authenticated'), cookie('AltoroAccounts', 'x', false)],
      errorTexts: [],
      visibleText: 'Hello Admin User\nView Account Summary\nTransfer Funds\nSign Off',
      html: '<html><body><a href="/logout.jsp">Sign Off</a></body></html>'
    },
    anonymousText: ALTORO_ANON
  });

  assert.equal(v.authConfirmed, 'confirmed');
  assert.equal(v.markerResult.marker, 'Sign Off');
  // A server-rendered site puts the marker in the response body, so the scan
  // can keep re-checking it while it runs.
  assert.equal(v.markerCheckableInBody, true);
});

test('Altoro: wrong password is never confirmed', () => {
  const v = verdictFor({
    before: {
      url: 'https://demo.testfire.net/login.jsp',
      cookies: [cookie('JSESSIONID', 'anonymous')],
      errorTexts: []
    },
    after: {
      url: 'https://demo.testfire.net/login.jsp',
      cookies: [cookie('JSESSIONID', 'anonymous')],
      errorTexts: ['Login Failed: We\'re sorry, but this username or password was not found.'],
      visibleText: ALTORO_ANON + '\nLogin Failed',
      html: '<html><body>Login Failed</body></html>'
    },
    anonymousText: ALTORO_ANON
  });

  assert.equal(v.authConfirmed, 'failed');
  assert.notEqual(v.authConfirmed, 'confirmed');
});

// ─────────────────────────────────────────────────────────────────────────────
// Juice Shop — the app-style site that used to fail
// ─────────────────────────────────────────────────────────────────────────────

const JUICE_ANON = 'All Products\nApple Juice\nLemon Juice\nAccount\nSearch';

test('Juice Shop: correct password is confirmed despite only a hash change', () => {
  const v = verdictFor({
    before: {
      url: 'https://preview.owasp-juice.shop/#/login',
      cookies: [cookie('language', 'en', false), cookie('cookieconsent_status', 'dismiss', false)],
      errorTexts: ['Please provide an email address.'] // Standing Material markup
    },
    after: {
      url: 'https://preview.owasp-juice.shop/#/search',
      cookies: [
        cookie('language', 'en', false),
        cookie('cookieconsent_status', 'dismiss', false),
        cookie('token', 'eyJhbGciOi', false)
      ],
      errorTexts: ['Please provide an email address.'], // Unchanged — must not veto
      visibleText: 'All Products\nYour Basket\nLog Out\nadmin@juice-sh.op',
      // A single-page app serves the same shell to everyone.
      html: '<html><body><app-root></app-root></body></html>'
    },
    anonymousText: JUICE_ANON
  });

  assert.equal(v.authConfirmed, 'confirmed');
  assert.equal(v.markerResult.marker, 'Log Out');
  // Crucially: the scan must know it cannot re-check this in a response body,
  // or it would read the shell, miss the marker and wrongly report a lost
  // session halfway through.
  assert.equal(v.markerCheckableInBody, false);
});

test('Juice Shop: standing validation markup does not fail a real login', () => {
  // The original defect: `[class*="invalid"]` matched Angular's permanent
  // `ng-invalid`, and any match vetoed the login outright.
  const v = verdictFor({
    before: {
      url: 'https://x/#/login',
      cookies: [],
      errorTexts: ['Please provide an email address.', 'Please provide a password.']
    },
    after: {
      url: 'https://x/#/search',
      cookies: [cookie('token', 'abc', false)],
      errorTexts: ['Please provide an email address.', 'Please provide a password.'],
      visibleText: 'Log Out',
      html: '<a>Log Out</a>'
    },
    anonymousText: 'Sign In'
  });
  assert.equal(v.authConfirmed, 'confirmed');
});

test('Juice Shop: wrong password is never confirmed', () => {
  const v = verdictFor({
    before: {
      url: 'https://preview.owasp-juice.shop/#/login',
      cookies: [cookie('language', 'en', false)],
      errorTexts: []
    },
    after: {
      url: 'https://preview.owasp-juice.shop/#/login',
      cookies: [cookie('language', 'en', false)],
      errorTexts: ['Invalid email or password.'],
      visibleText: JUICE_ANON + '\nInvalid email or password.',
      html: '<html><body><app-root></app-root></body></html>'
    },
    anonymousText: JUICE_ANON
  });

  assert.equal(v.authConfirmed, 'failed');
});

// ─────────────────────────────────────────────────────────────────────────────
// quizmint.me — login panel behind "Get Started", URL never changes
// ─────────────────────────────────────────────────────────────────────────────

test('quizmint: confirmed even though the address never changes', () => {
  // Nothing about the URL says a login happened. The anonymous baseline is the
  // only thing that can tell the difference — which is the whole point of it.
  const v = verdictFor({
    before: {
      url: 'https://quizmint.me/',
      cookies: [],
      errorTexts: []
    },
    after: {
      url: 'https://quizmint.me/',
      cookies: [cookie('session', 'abc123')],
      errorTexts: [],
      visibleText: 'My Quizzes\nCreate Quiz\nLog out',
      html: '<html><body><nav><a href="/logout">Log out</a></nav></body></html>'
    },
    anonymousText: 'Get Started\nSign In\nPricing'
  });

  assert.equal(v.authConfirmed, 'confirmed');
  assert.equal(v.markerResult.marker, 'Log out');
  assert.ok(!v.evidenceCodes.includes('url_changed'), 'the URL genuinely did not change');
});

test('quizmint: wrong password with no error message is not confirmed', () => {
  // A silent failure: the panel just stays open. Nothing proves a login, so the
  // answer is "could not confirm" — amber, never green.
  const v = verdictFor({
    before: { url: 'https://quizmint.me/', cookies: [], errorTexts: [] },
    after: {
      url: 'https://quizmint.me/',
      cookies: [cookie('session', 'anon-rotated')],
      errorTexts: [],
      visibleText: 'Get Started\nSign In\nPricing',
      html: '<html><body>Get Started</body></html>'
    },
    anonymousText: 'Get Started\nSign In\nPricing'
  });

  assert.notEqual(v.authConfirmed, 'confirmed');
  assert.equal(v.authConfirmed, 'unconfirmed');
});

// ─────────────────────────────────────────────────────────────────────────────
// The shape that produced the original bug report
// ─────────────────────────────────────────────────────────────────────────────

test('a click that never reached the form is reported as such, not as bad credentials', () => {
  // Juice Shop with the wrong submit button: the detector picked a header
  // control, the click opened a menu, and nothing was submitted. The customer
  // was told their correct password had failed.
  const identical = {
    url: 'https://preview.owasp-juice.shop/#/login',
    cookies: [cookie('language', 'en', false)],
    errorTexts: []
  };
  const v = verdictFor({
    before: identical,
    after: { ...identical, visibleText: 'Sign In', html: '<app-root></app-root>' },
    anonymousText: 'Sign In'
  });

  assert.equal(v.authConfirmed, 'failed');
  assert.ok(v.evidenceCodes.includes('no_observable_change'));
});

// ─────────────────────────────────────────────────────────────────────────────
// The invariant, stated once over every scenario above
// ─────────────────────────────────────────────────────────────────────────────

test('no scenario without a signed-in marker is ever confirmed', () => {
  // Belt and braces: "confirmed" must be reachable only through a marker
  // derived from the anonymous baseline. Nothing else may produce a green tick.
  const noMarker = [
    { url: 'https://a/', cookies: [cookie('sessionid', 'new')], errorTexts: [] },
    { url: 'https://b/', cookies: [cookie('token', 'new', false)], errorTexts: [] },
    { url: 'https://c/', cookies: [], errorTexts: ['whatever'] }
  ];

  for (const after of noMarker) {
    const v = scoreLoginAttempt({
      before: { url: 'https://start/', cookies: [], errorTexts: [] },
      after,
      markerResult: { marker: null, checkableInBody: false }
    });
    assert.notEqual(v.authConfirmed, 'confirmed', `${after.url} must not be confirmed`);
  }
});

test('an error message the pattern does not recognise is still not a marker', () => {
  // Second layer of defence. A site's own wording will not always look like a
  // failure ("Those details don't match our records"), so pattern-matching
  // alone is not enough — whatever the page is currently showing as an error is
  // excluded outright, however it happens to be phrased.
  const v = verdictFor({
    before: { url: 'https://bank.test/login', cookies: [], errorTexts: [] },
    after: {
      url: 'https://bank.test/login',
      cookies: [],
      errorTexts: ["Those details do not match our records"],
      visibleText: 'Sign In\nThose details do not match our records',
      html: '<html><body>Sign In</body></html>'
    },
    anonymousText: 'Sign In'
  });

  assert.notEqual(v.authConfirmed, 'confirmed');
});

// ─────────────────────────────────────────────────────────────────────────────
// Only an explicit signed-in control may produce a green tick
//
// The wrong-password bug had a whole family behind it. Excluding failure-shaped
// wording was not enough: plenty of failure notices read perfectly neutrally
// ("Please check your details", "Too many attempts today"), carry no error
// styling, and are new text — so they sailed through both earlier defences and
// became the proof of a successful sign-in.
// ─────────────────────────────────────────────────────────────────────────────

const neutralFailureNotices = [
  'Please check your details',
  'Let us try that once more',
  'Need help signing in',
  'Signing in as your account',
  'Too many attempts today'
];

for (const notice of neutralFailureNotices) {
  test(`a neutral failure notice is never proof: "${notice}"`, () => {
    const v = verdictFor({
      before: { url: 'https://s/login', cookies: [], errorTexts: [] },
      after: {
        url: 'https://s/login',
        cookies: [cookie('sid', 'rotated')],
        errorTexts: [],
        visibleText: `Sign In\n${notice}`,
        html: `<p>${notice}</p>`
      },
      anonymousText: 'Sign In'
    });
    assert.notEqual(v.authConfirmed, 'confirmed');
  });
}

test('an explicit signed-in control still confirms', () => {
  for (const control of ['Log out', 'Sign Off', 'My Account', 'ログアウト']) {
    const v = verdictFor({
      before: { url: 'https://s/login', cookies: [], errorTexts: [] },
      after: {
        url: 'https://s/home',
        cookies: [cookie('sid', 'new')],
        errorTexts: [],
        visibleText: `Welcome\n${control}`,
        html: `<a>${control}</a>`
      },
      anonymousText: 'Sign In'
    });
    assert.equal(v.authConfirmed, 'confirmed', `${control} should confirm`);
  }
});

test('a weak marker is still returned for change detection, just not as proof', () => {
  // It cannot prove the sign-in, but it remains a usable canary for noticing the
  // page change later in the scan. Callers must read `authConfirmed`, never the
  // presence of `marker`, to decide whether the sign-in was verified.
  const v = verdictFor({
    before: { url: 'https://s/login', cookies: [], errorTexts: [] },
    after: {
      url: 'https://s/login',
      cookies: [cookie('sid', 'rotated')],
      errorTexts: [],
      visibleText: 'Sign In\nWelcome to the portal',
      html: '<p>Welcome to the portal</p>'
    },
    anonymousText: 'Sign In'
  });
  assert.equal(v.authConfirmed, 'unconfirmed');
  assert.equal(v.marker, 'Welcome to the portal');
});

// ─────────────────────────────────────────────────────────────────────────────
// The invariant, asserted over generated input rather than hand-picked cases
// ─────────────────────────────────────────────────────────────────────────────

test('across 20,000 generated pages, "confirmed" always rests on a signed-in control', () => {
  // Hand-written scenarios only cover what the author thought of — and what the
  // author did not think of is exactly how a wrong password came to score as a
  // success. This generates page pairs instead and asserts the rule holds every
  // single time. Seeded, so a failure is reproducible.
  let seed = 1337;
  const rnd = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };

  const words = [
    'Home', 'About', 'Contact', 'Welcome', 'Portal', 'Dashboard', 'Log out',
    'Sign Off', 'My Account', 'Please check your details', 'Invalid password',
    'Too many attempts', 'Basket', 'Search', 'Profile', 'Settings',
    'Try again later', 'Session expired', 'Hello there', 'Order History',
    'Log In', 'Sign In', 'Register'
  ];
  const pick = (n) => Array.from({ length: n }, () => words[Math.floor(rnd() * words.length)]);

  let confirmed = 0;
  const violations = [];

  for (let i = 0; i < 20000; i++) {
    const errorTexts = rnd() < 0.3 ? pick(1) : [];
    const after = {
      url: rnd() < 0.5 ? 'https://s/a' : 'https://s/b',
      cookies: rnd() < 0.5 ? [cookie('sid', String(rnd()))] : [],
      errorTexts,
      visibleText: pick(1 + Math.floor(rnd() * 6)).join('\n'),
      html: ''
    };
    const v = verdictFor({
      before: { url: 'https://s/a', cookies: [], errorTexts: [] },
      after,
      anonymousText: pick(1 + Math.floor(rnd() * 5)).join('\n')
    });

    if (v.authConfirmed === 'confirmed') {
      confirmed++;
      if (v.markerResult.confidence !== 'high') violations.push(v.marker);
    }
  }

  assert.ok(confirmed > 100, `expected confirmations to occur, got ${confirmed}`);
  assert.deepEqual(violations.slice(0, 5), [], 'confirmed without a signed-in control');
});
