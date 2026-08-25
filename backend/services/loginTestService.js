// File path: backend/services/loginTestService.js

const puppeteer = require('puppeteer');
const { revealLoginPanel } = require('../utils/revealLoginPanel');
const { deriveMarker, scoreLoginAttempt, markerPresentInBody } = require('../utils/loginSignals');

const NAV_TIMEOUT_MS = 30000;
const SETTLE_AFTER_SUBMIT_MS = 2500;
const ANONYMOUS_PROBE_TIMEOUT_MS = 20000;

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const LAUNCH_ARGS = [
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-dev-shm-usage',
  '--disable-gpu',
  '--disable-extensions',
  '--no-first-run'
];

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/**
 * Read the state of the page that we compare before and after submitting.
 *
 * Everything the scoring logic needs comes from here, so that the decision
 * itself (in `utils/loginSignals.js`) stays free of browser code and testable.
 *
 * @param {import('puppeteer').Page} page
 * @param {boolean} withContent also capture full text and HTML (after-submit only)
 */
async function captureSnapshot(page, withContent = false) {
  const dom = await page.evaluate((includeContent) => {
    const isVisible = (el) => {
      const style = window.getComputedStyle(el);
      if (style.display === 'none' || style.visibility === 'hidden') return false;
      if (parseFloat(style.opacity || '1') === 0) return false;
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    };

    const errorSelectors = [
      '.error', '.alert-danger', '.login-error', '.message-error',
      '[class*="error"]', '[class*="invalid"]', '[class*="danger"]', '[role="alert"]'
    ];

    const errorTexts = new Set();
    for (const selector of errorSelectors) {
      let nodes = [];
      try {
        nodes = document.querySelectorAll(selector);
      } catch {
        continue;
      }
      for (const el of nodes) {
        if (!isVisible(el)) continue;
        // A real error message does not wrap the form. Component libraries put
        // `ng-invalid` on the <form> and on field wrappers, whose text is the
        // whole login box; matching those made every Angular page look like a
        // failed login.
        if (el.querySelector('input, form, button, select, textarea')) continue;
        const text = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
        if (text && text.length <= 300) errorTexts.add(text);
        // The target page controls how many of these exist. Without a bound, a
        // page with thousands of error-classed elements would be shipped back
        // over the wire and then diffed line by line.
        if (errorTexts.size >= 50) break;
      }
      if (errorTexts.size >= 50) break;
    }

    // A single-page app can log you in without changing the URL or setting a
    // cookie. The login form disappearing is the signal that it worked, so it
    // has to be part of what we compare before and after.
    let visiblePasswordFields = 0;
    for (const input of document.querySelectorAll('input[type="password"]')) {
      if (isVisible(input)) visiblePasswordFields++;
    }

    const bodyText = document.body ? document.body.innerText : '';

    return {
      errorTexts: [...errorTexts],
      visiblePasswordFields,
      // Bucketed so a clock or a view counter ticking over does not read as a
      // page change, while a real re-render does.
      textLengthBucket: Math.round(bodyText.length / 100),
      // Both capped: the size of these is decided by the site being scanned,
      // and a signed-in marker is always near the top of a page anyway. The
      // marker diff runs a dozen patterns per line, so an uncapped page would
      // cost real time for nothing.
      visibleText: includeContent ? bodyText.slice(0, 300000) : '',
      html: includeContent ? document.documentElement.outerHTML.slice(0, 500000) : ''
    };
  }, withContent);

  let cookies = [];
  try {
    cookies = await page.cookies();
  } catch {
    cookies = [];
  }

  return { url: page.url(), cookies, ...dom };
}

/**
 * Two fingerprints, because not every change means the form was submitted.
 *
 * `strong` covers things only a real submission does: the address moves, a
 * cookie is issued, or the login form goes away. `weak` adds page text, which
 * also changes when a dropdown opens — exactly what happens if we click a
 * header menu by mistake. Treating that as a successful submit would mask the
 * very problem this is here to catch.
 *
 * @param {{url:string, cookies:Array, errorTexts:string[]}} snapshot
 */
function fingerprint(snapshot) {
  const cookiePart = (snapshot.cookies || [])
    .map(c => `${c.name}=${c.value}`)
    .sort()
    .join('|');

  const strong = [snapshot.url, cookiePart, snapshot.visiblePasswordFields].join('::');
  const weak = [(snapshot.errorTexts || []).join('~'), snapshot.textLengthBucket].join('::');

  return { strong, weak: `${strong}::${weak}` };
}

/**
 * Submit the form, and keep trying until something actually happens.
 *
 * The previous implementation only fell back to pressing Enter when the click
 * *threw*. A click that lands on the wrong element — a header menu button
 * picked by the detector, or a modal backdrop covering the form — does not
 * throw. It quietly succeeds at doing nothing, and the login was then reported
 * as failed. So we compare the page before and after instead.
 *
 * @returns {Promise<{strategy:string, changed:boolean}>}
 */
async function submitLogin(page, submitButton, alternates) {
  // Capturing runs script in the page, so a navigation in flight can tear it
  // down mid-call. A failed capture means the page moved, which is itself the
  // change we are looking for.
  const safeFingerprint = async () => {
    try {
      return fingerprint(await captureSnapshot(page));
    } catch {
      return null;
    }
  };

  const before = await safeFingerprint();
  // If the baseline could not be captured we cannot compare, so accept the
  // first attempt and let the scoring below make the real judgement — it
  // reports "no observable change" on its own evidence anyway.
  if (before === null) {
    try {
      if (submitButton && submitButton.selector) {
        await page.click(submitButton.selector);
      } else {
        await page.keyboard.press('Enter');
      }
    } catch {
      // Fall through; scoring will see that nothing moved.
    }
    await wait(SETTLE_AFTER_SUBMIT_MS);
    return { strategy: 'unverified', changed: true };
  }

  const attempts = [];
  if (submitButton && submitButton.selector) {
    attempts.push({ strategy: 'primary_button', selector: submitButton.selector });
  }
  attempts.push({ strategy: 'enter_key', selector: null });
  for (const alternate of (alternates || []).slice(0, 3)) {
    const selector = typeof alternate === 'string' ? alternate : alternate && alternate.selector;
    if (selector && selector !== (submitButton && submitButton.selector)) {
      attempts.push({ strategy: 'alternate_button', selector });
    }
  }

  // Remembered in case no attempt produces a strong change: a weak one is still
  // better evidence than nothing, and the scoring stage judges it properly.
  let weakHit = null;
  let baseline = before;

  for (const [index, attempt] of attempts.entries()) {
    if (index > 0) {
      // Clear whatever the previous attempt opened. Clicking a header control
      // pops a dropdown or a modal whose backdrop then swallows every later
      // click — so without this, the retry that would have worked cannot land.
      try {
        await page.keyboard.press('Escape');
      } catch {
        // Page may have navigated; nothing to dismiss.
      }
      await wait(300);
      // Re-measure, so each attempt is judged against the state it started
      // from rather than against a page two clicks ago.
      const refreshed = await safeFingerprint();
      if (refreshed) baseline = refreshed;
    }

    // The first attempt gets the full budget because it is the one expected to
    // work. Retries are only reached when nothing happened, so waiting as long
    // again for each would push the customer's wait past a minute and a half.
    const navTimeout = index === 0 ? 15000 : 8000;
    const settle = index === 0 ? SETTLE_AFTER_SUBMIT_MS : 1500;

    try {
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle2', timeout: navTimeout }).catch(() => null),
        attempt.selector ? page.click(attempt.selector) : page.keyboard.press('Enter')
      ]);
    } catch {
      continue; // Element vanished or was not clickable; try the next approach.
    }

    await wait(settle);

    const after = await safeFingerprint();
    if (after === null) {
      // The page went away underneath us, which only a real navigation does.
      return { strategy: attempt.strategy, changed: true };
    }
    if (after.strong !== baseline.strong) {
      return { strategy: attempt.strategy, changed: true };
    }
    if (after.weak !== baseline.weak && !weakHit) {
      // Something moved on the page but nothing that a submission would move —
      // most likely we opened a menu. Keep trying the other candidates.
      weakHit = attempt.strategy;
    }
  }

  return weakHit
    ? { strategy: weakHit, changed: true }
    : { strategy: 'none', changed: false };
}

/**
 * Load a URL with no cookies at all, to see what an anonymous visitor sees.
 *
 * This is what lets us prove a login worked without asking the customer to
 * describe their own site, and without sending a deliberately wrong password
 * (which risks locking their account).
 *
 * @returns {Promise<string>} visible text, or '' if the probe failed
 */
async function fetchAnonymousText(browser, url) {
  let context = null;
  try {
    // Puppeteer 23 API. Older releases called this createIncognitoBrowserContext.
    context = await browser.createBrowserContext();
    const page = await context.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent(USER_AGENT);
    await page.goto(url, { waitUntil: 'networkidle2', timeout: ANONYMOUS_PROBE_TIMEOUT_MS });
    await wait(1000);
    return await page.evaluate(() => (document.body ? document.body.innerText : ''));
  } catch (err) {
    console.warn(`[LoginTest] Anonymous baseline unavailable: ${err.message}`);
    return '';
  } finally {
    if (context) {
      try {
        await context.close();
      } catch {
        // Context already gone.
      }
    }
  }
}

function failure(errorCode, errorMessage, evidence) {
  return {
    success: false,
    authenticated: false,
    authConfirmed: 'failed',
    errorCode,
    errorMessage,
    postLoginUrl: null,
    cookies: [],
    marker: null,
    markerCheckableInBody: false,
    evidenceCodes: [],
    evidence
  };
}

/**
 * Test login credentials by filling and submitting the login form.
 *
 * @param {Object} options
 * @param {string} options.loginUrl
 * @param {Array}  options.credentials  [{ selector, value, inputType }, ...]
 * @param {Object} [options.submitButton]
 * @param {Array}  [options.submitAlternates] ranked runners-up from detection
 * @param {string} [options.expectedMarker] customer-supplied signed-in text
 * @returns {Promise<Object>}
 */
async function testLogin(options) {
  const { loginUrl, credentials, submitButton, submitAlternates, expectedMarker } = options;

  let browser = null;

  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: LAUNCH_ARGS,
      timeout: NAV_TIMEOUT_MS
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent(USER_AGENT);

    await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT_MS });

    // The form may be behind a header dropdown or a "Get Started" button.
    if (credentials && credentials.length > 0) {
      try {
        await page.waitForSelector(credentials[0].selector, { visible: true, timeout: 10000 });
      } catch {
        const { revealed } = await revealLoginPanel(page);
        if (!revealed) {
          return failure(
            'LOGIN_PANEL_NOT_FOUND',
            'Could not open the login form on the page.',
            'No visible password field, and no toggle revealed one'
          );
        }
        try {
          await page.waitForSelector(credentials[0].selector, { visible: true, timeout: 5000 });
        } catch {
          return failure(
            'FIELD_NOT_FOUND',
            'Could not find the first login field on the page.',
            'First field selector still not visible after opening the login panel'
          );
        }
      }
    }

    // State before we touch anything — the baseline every signal is measured
    // against. A nav bar or a cookie that is already here proves nothing.
    const before = await captureSnapshot(page);

    for (const cred of credentials) {
      try {
        await page.waitForSelector(cred.selector, { visible: true, timeout: 5000 });
        await page.click(cred.selector, { clickCount: 3 }); // Select existing text
        await page.type(cred.selector, cred.value, { delay: 50 });
      } catch (err) {
        return failure(
          'FIELD_FILL_FAILED',
          `Could not fill field: ${cred.selector}`,
          `Field fill failed: ${err.message}`
        );
      }
    }

    const submitResult = await submitLogin(page, submitButton, submitAlternates);

    if (!submitResult.changed) {
      // Nothing we clicked reached the site. Reporting this as "wrong password"
      // is what sent people hunting for credential problems that did not exist.
      return failure(
        'SUBMIT_NO_EFFECT',
        'Submitting the login form had no effect on the page.',
        'No URL, cookie or message change after every submit strategy'
      );
    }

    const after = await captureSnapshot(page, true);

    // Compare against the same page with no session at all.
    const anonymousText = await fetchAnonymousText(browser, after.url);
    let markerResult = deriveMarker({
      signedInText: after.visibleText,
      anonymousText,
      signedInHtml: after.html,
      // Never let a message the page is showing become the proof of success.
      excludeTexts: after.errorTexts
    });

    // A marker the customer gave us beats anything we inferred, but only if it
    // is really on the page — otherwise we would confirm a login that did not
    // happen. If it is not there, keep whatever we derived ourselves rather
    // than discarding it: a typo in an optional field should not downgrade a
    // sign-in we had already confirmed on our own.
    if (expectedMarker && typeof expectedMarker === 'string' && expectedMarker.trim()) {
      const wanted = expectedMarker.trim();
      if ((after.visibleText || '').toLowerCase().includes(wanted.toLowerCase())) {
        markerResult = {
          marker: wanted,
          // A person told us this text means "signed in", so it counts as proof
          // even though we would not have trusted it on our own.
          confidence: 'high',
          alternates: markerResult.alternates,
          checkableInBody: markerPresentInBody(after.html, wanted)
        };
      } else {
        console.warn('[LoginTest] Supplied signed-in text was not found on the page; using the derived marker.');
      }
    }

    const verdict = scoreLoginAttempt({ before, after, markerResult });

    await browser.close();
    browser = null;

    const evidence = verdict.evidenceCodes.join('; ') || 'no_observable_change';

    return {
      success: true,
      authenticated: verdict.authenticated,
      authConfirmed: verdict.authConfirmed,
      postLoginUrl: after.url,
      cookies: after.cookies,
      marker: verdict.marker,
      markerCheckableInBody: verdict.markerCheckableInBody,
      markerAlternates: markerResult.alternates || [],
      evidenceCodes: verdict.evidenceCodes,
      submitStrategy: submitResult.strategy,
      anonymousBaselineAvailable: Boolean(anonymousText),
      evidence,
      errorCode:
        verdict.authConfirmed === 'confirmed'
          ? null
          : verdict.authConfirmed === 'unconfirmed'
            ? 'AUTH_UNCONFIRMED'
            : 'LOGIN_ANALYSIS_FAILED',
      errorMessage:
        verdict.authConfirmed === 'confirmed'
          ? null
          : verdict.authConfirmed === 'unconfirmed'
            ? 'Signed-in state could not be confirmed.'
            : 'Login appears to have failed based on page analysis'
    };
  } catch (error) {
    console.error('Login test error:', error);
    return failure(
      'UNEXPECTED_ERROR',
      error.message || 'An unexpected error occurred during login test',
      `Exception: ${error.message}`
    );
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        // Ignore close errors
      }
    }
  }
}

module.exports = {
  testLogin,
  captureSnapshot,
  submitLogin,
  fetchAnonymousText
};
