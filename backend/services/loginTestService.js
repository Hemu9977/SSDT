// File path: backend/services/loginTestService.js

const puppeteer = require('puppeteer');
const { revealLoginPanel } = require('../utils/revealLoginPanel');
const {
  deriveMarker, scoreLoginAttempt, markerPresentInBody, cookieDelta, newErrorMessages, toLines
} = require('../utils/loginSignals');
const {
  classifyLoginRequest, classifyLoginResponse, isFailureNotice, MAX_RESPONSE_JSON_BYTES, ANALYTICS_HOST_PATTERN
} = require('../utils/loginRequestSignals');
const {
  eligibleBearerSessions, isSharedThirdPartyApiHost, isLogoutUrl, IDENTITY_PATH_PATTERN
} = require('../utils/bearerApiScope');

const NAV_TIMEOUT_MS = 30000;
const SETTLE_AFTER_SUBMIT_MS = 2500;
const ANONYMOUS_PROBE_TIMEOUT_MS = 20000;
// How long to wait for the site to answer a login request we saw go out. Long
// enough for a sleeping API to wake (a cold Render service measured 23 s), short
// enough that the whole test stays inside the load balancer's 60 s idle timeout.
const LOGIN_RESPONSE_WAIT_MS = 25000;

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

    // Toasts and status lines. Component libraries announce a sign-in result
    // through ARIA live regions (`role="status"`, `aria-live`) with generated
    // class names, which the error selectors above cannot see — and on many
    // single-page apps such a toast is the *only* visible answer to a refused
    // login. Kept apart from `errorTexts` on purpose: a "Welcome back" toast is
    // a live region too, and must not count as an error.
    const noticeTexts = new Set();
    let noticeNodes = [];
    try {
      noticeNodes = document.querySelectorAll('[role="status"], [role="alert"], [aria-live]:not([aria-live="off"])');
    } catch {
      noticeNodes = [];
    }
    for (const el of noticeNodes) {
      if (!isVisible(el)) continue;
      if (el.querySelector('input, form, button, select, textarea')) continue;
      const text = (el.innerText || el.textContent || '').trim();
      if (text && text.length <= 300) noticeTexts.add(text);
      if (noticeTexts.size >= 50) break;
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
      // Raw innerText (line breaks kept), so a multi-line toast can be excluded
      // line by line from the signed-in marker.
      noticeTexts: [...noticeTexts],
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
  const weak = [
    (snapshot.errorTexts || []).join('~'),
    noticeLines(snapshot.noticeTexts).join('~'),
    snapshot.textLengthBucket
  ].join('::');

  return { strong, weak: `${strong}::${weak}` };
}

/**
 * Every line of every visible notice, whitespace-collapsed.
 * @param {string[]} noticeTexts raw innerText of live regions
 * @returns {string[]}
 */
function noticeLines(noticeTexts) {
  const out = new Set();
  for (const text of Array.isArray(noticeTexts) ? noticeTexts : []) {
    const whole = String(text).replace(/\s+/g, ' ').trim();
    if (whole) out.add(whole);
    for (const line of toLines(String(text))) out.add(line);
  }
  return [...out];
}

/**
 * Failure-worded notices or error messages that appeared since `before`.
 * @returns {boolean}
 */
function newFailureNoticeShown(before, after) {
  const fresh = (beforeList, afterList) => {
    const seen = new Set(beforeList);
    return afterList.filter(t => !seen.has(t));
  };
  const appeared = [
    ...fresh(noticeLines(before && before.noticeTexts), noticeLines(after && after.noticeTexts)),
    ...newErrorMessages(before && before.errorTexts, after && after.errorTexts)
  ];
  return appeared.some(isFailureNotice);
}

// At most this many API URLs per origin are kept to seed the scan, and only
// GETs: a captured POST/PUT/DELETE (create user, delete member…) is never replayed,
// and neither is a logout-shaped GET (utils/bearerApiScope.js).
const MAX_BEARER_SEEDS = 50;

/**
 * Record the Bearer tokens the page's own code sends after the login.
 *
 * Single-page apps that keep their session in localStorage never set a cookie:
 * their JavaScript adds `Authorization: Bearer <token>` to calls to their API,
 * often on another origin. Watching what the app actually sends is the one
 * reliable way to learn the session — no guessing at storage keys or token
 * formats. A token only counts once the API has answered a request carrying it
 * with 2xx, i.e. the site itself accepted it.
 *
 * Values are held in memory for the caller only; nothing here logs them.
 *
 * @param {import('puppeteer').Page} page
 */
function watchBearerTokens(page) {
  const before = new Set(); // tokens the page used before the login: not a session
  const origins = new Map(); // origin -> { authorization, accepted, seeds: Map(url -> status) }
  let armed = false;

  const bearerOf = (request) => {
    const value = (request.headers() || {}).authorization;
    return typeof value === 'string' && /^Bearer\s+\S{8,}/i.test(value) ? value.trim() : null;
  };
  const originOf = (url) => {
    try {
      const u = new URL(url);
      // Shared third-party APIs (payments, identity, BaaS…) are never a session
      // host the scan could use: not recorded at all.
      if (!/^https?:$/.test(u.protocol) || ANALYTICS_HOST_PATTERN.test(u.hostname) ||
          isSharedThirdPartyApiHost(u.hostname)) return null;
      return u.origin;
    } catch {
      return null;
    }
  };

  const onRequest = (request) => {
    try {
      const authorization = bearerOf(request);
      if (!authorization) return;
      if (!armed) { before.add(authorization); return; }
    } catch {
      // Not attributable.
    }
  };
  const onResponse = (response) => {
    try {
      if (!armed) return;
      const request = response.request();
      const authorization = bearerOf(request);
      if (!authorization || before.has(authorization)) return;
      const origin = originOf(request.url());
      if (!origin) return;
      const status = response.status();
      const entry = origins.get(origin) || { authorization, accepted: false, seeds: new Map() };
      // A refreshed token replaces the old one: the newest is the live session.
      if (entry.authorization !== authorization) {
        entry.authorization = authorization;
        entry.accepted = false;
        entry.seeds = new Map();
      }
      if (status >= 200 && status < 300) {
        entry.accepted = true;
        if (request.method() === 'GET' && entry.seeds.size < MAX_BEARER_SEEDS && !isLogoutUrl(request.url())) {
          entry.seeds.set(request.url(), status);
        }
      }
      origins.set(origin, entry);
    } catch {
      // Not attributable.
    }
  };

  page.on('request', onRequest);
  page.on('response', onResponse);

  return {
    /** From now on, a newly used token is a candidate session. */
    arm() { armed = true; },
    stop() {
      page.off('request', onRequest);
      page.off('response', onResponse);
    },
    /**
     * @returns {Array<{origin:string, authorization:string, seedUrls:string[], verifyUrl:string|null}>}
     *   accepted tokens only. Contains the secret: in memory only, never logged.
     */
    sessions() {
      const out = [];
      for (const [origin, entry] of origins) {
        if (!entry.accepted) continue;
        const seedUrls = [...entry.seeds.keys()];
        const verifyUrl = seedUrls.find(u => IDENTITY_PATH_PATTERN.test(new URL(u).pathname)) || seedUrls[0] || null;
        out.push({ origin, authorization: entry.authorization, seedUrls, verifyUrl });
      }
      return out;
    }
  };
}

/**
 * Is the element this selector resolves to a show/hide-password control?
 *
 * Same rule as `isPasswordToggle` in `loginDetectionService.js` (kept in step
 * by hand: both run inside the page, where neither can import the other). A
 * `type="submit"` or a button worded like a sign-in is never a toggle.
 *
 * @returns {Promise<boolean>}
 */
async function targetIsPasswordToggle(page, selector) {
  try {
    return await page.evaluate((sel) => {
      const btn = document.querySelector(sel);
      if (!btn || btn.tagName !== 'BUTTON') return false;
      const type = (btn.getAttribute('type') || '').toLowerCase();
      if (type === 'submit') return false;
      const text = (btn.textContent || '').trim();
      if (/log\s?in|sign\s?in|submit|continue|ログイン|サインイン|送信/i.test(text)) return false;
      const hints = [
        btn.getAttribute('aria-label'), btn.getAttribute('title'), btn.id,
        typeof btn.className === 'string' ? btn.className : '', btn.getAttribute('data-testid'), text
      ].filter(Boolean).join(' ');
      if (/show|hide|reveal|visib|eye|peek|unmask|表示|非表示/i.test(hints)) return true;
      const wrapper = btn.parentElement;
      return !text && type === 'button' && Boolean(wrapper && wrapper.querySelector('input[type="password"]'));
    }, selector);
  } catch {
    return false;
  }
}

/**
 * Watch the page's requests for the login submission and its answer.
 *
 * Only a verdict is kept — which signal matched, the status code, and whether
 * the site answered. The request body is inspected in memory to decide and is
 * never stored, logged or returned; neither is the URL or the response body.
 *
 * @param {import('puppeteer').Page} page
 * @param {string[]} credentialValues values the test typed
 */
function watchLoginRequest(page, credentialValues) {
  const state = { detected: false, matchedBy: null, status: null, outcome: null, done: false };
  let tracked = null;
  let resolveDone;
  const done = new Promise(resolve => { resolveDone = resolve; });
  const finish = (outcome, status) => {
    if (state.done) return;
    state.done = true;
    state.outcome = outcome;
    state.status = status === undefined ? null : status;
    resolveDone();
  };

  const onRequest = (request) => {
    try {
      // A redirect is a new request object; keep following the one we picked.
      if (tracked && request.redirectChain().includes(tracked)) {
        tracked = request;
        return;
      }
      if (state.detected) return;
      const headers = request.headers() || {};
      let postData;
      try { postData = request.postData(); } catch { postData = undefined; }
      const verdict = classifyLoginRequest({
        method: request.method(),
        url: request.url(),
        resourceType: request.resourceType(),
        contentType: headers['content-type'],
        postData,
        credentialValues
      });
      if (verdict.isLogin) {
        tracked = request;
        state.detected = true;
        state.matchedBy = verdict.matchedBy;
      }
    } catch {
      // A request we cannot inspect is not one we can attribute.
    }
  };

  const onFinished = async (request) => {
    if (request !== tracked || state.done) return;
    const response = request.response();
    const status = response ? response.status() : null;
    let json = null;
    try {
      const type = String((response && response.headers()['content-type']) || '').toLowerCase();
      if (response && type.includes('json')) {
        const text = await response.text();
        if (text.length <= MAX_RESPONSE_JSON_BYTES) json = JSON.parse(text);
      }
    } catch {
      json = null;
    }
    finish(classifyLoginResponse({ status, json }), status);
  };

  const onFailed = (request) => {
    if (request !== tracked || state.done) return;
    finish('network_error', null);
  };

  page.on('request', onRequest);
  page.on('requestfinished', onFinished);
  page.on('requestfailed', onFailed);

  return {
    state,
    done,
    stop() {
      page.off('request', onRequest);
      page.off('requestfinished', onFinished);
      page.off('requestfailed', onFailed);
    },
    /** Safe to log: no URL, body, header or value. */
    summary() {
      return {
        detected: state.detected,
        matchedBy: state.matchedBy,
        status: state.status,
        outcome: state.detected ? (state.done ? state.outcome : 'timeout') : null
      };
    }
  };
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
 * The page is not the only witness. Every attempt also watches the network for
 * the login request itself (`watchLoginRequest`). Once one has gone out, no
 * further strategy runs — pressing Enter or clicking a runner-up would send the
 * customer's password again, and repeated failed sign-ins are how accounts get
 * locked. Instead we wait (up to LOGIN_RESPONSE_WAIT_MS) for the site's answer,
 * so that a refused login and an API that is slow to wake are told apart from a
 * click that sent nothing.
 *
 * @param {import('puppeteer').Page} page
 * @param {{selector:string}|null} submitButton
 * @param {Array} alternates
 * @param {{credentialValues?:string[], responseWaitMs?:number}} [options]
 * @returns {Promise<{strategy:string, changed:boolean, loginRequest:Object}>}
 */
async function submitLogin(page, submitButton, alternates, options = {}) {
  const credentialValues = Array.isArray(options.credentialValues) ? options.credentialValues : [];
  const responseWaitMs = Number.isFinite(options.responseWaitMs) ? options.responseWaitMs : LOGIN_RESPONSE_WAIT_MS;
  const noRequest = { detected: false, matchedBy: null, status: null, outcome: null };

  // Capturing runs script in the page, so a navigation in flight can tear it
  // down mid-call. A failed capture means the page moved, which is itself the
  // change we are looking for.
  const safeSnapshot = async () => {
    try {
      return await captureSnapshot(page);
    } catch {
      return null;
    }
  };

  const beforeSnapshot = await safeSnapshot();
  // If the baseline could not be captured we cannot compare, so accept the
  // first attempt and let the scoring below make the real judgement — it
  // reports "no observable change" on its own evidence anyway.
  if (beforeSnapshot === null) {
    const watcher = watchLoginRequest(page, credentialValues);
    const startedAt = Date.now();
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
    if (watcher.state.detected && !watcher.state.done) {
      const remaining = responseWaitMs - (Date.now() - startedAt);
      if (remaining > 0) await Promise.race([watcher.done, wait(remaining)]);
    }
    watcher.stop();
    return { strategy: 'unverified', changed: true, loginRequest: watcher.summary() };
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
  let baseline = beforeSnapshot;

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
      const refreshed = await safeSnapshot();
      if (refreshed) baseline = refreshed;
    }

    // The first attempt gets the full budget because it is the one expected to
    // work. Retries are only reached when nothing happened, so waiting as long
    // again for each would push the customer's wait past a minute and a half.
    const navTimeout = index === 0 ? 15000 : 8000;
    const settle = index === 0 ? SETTLE_AFTER_SUBMIT_MS : 1500;

    // A selector saved by older detection (`form:nth-of-type(1) button`, still
    // stored in schedules) can resolve to the show/hide-password control. A
    // click there only unmasks the password, so skip it and let the next
    // strategy (Enter) submit the form.
    if (attempt.selector && await targetIsPasswordToggle(page, attempt.selector)) {
      continue;
    }

    const watcher = watchLoginRequest(page, credentialValues);
    const startedAt = Date.now();
    const navigation = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: navTimeout }).catch(() => null);

    try {
      await (attempt.selector ? page.click(attempt.selector) : page.keyboard.press('Enter'));
    } catch {
      watcher.stop();
      continue; // Element vanished or was not clickable; try the next approach.
    }

    // A navigation, or the login request being answered — whichever is first.
    // A single-page app never navigates, and waiting out the full navigation
    // budget after the site has already said no only makes the customer wait.
    await Promise.race([navigation, watcher.done]);

    if (watcher.state.detected) {
      // The login went out. Wait for the answer rather than trying anything
      // else: a sleeping API can take tens of seconds to wake.
      if (!watcher.state.done) {
        const remaining = responseWaitMs - (Date.now() - startedAt);
        if (remaining > 0) await Promise.race([watcher.done, wait(remaining)]);
      }
      if (watcher.state.done && watcher.state.outcome === 'ok') {
        // An accepted login is usually followed by a navigation; let it land
        // before the page is read.
        await Promise.race([navigation, wait(settle)]);
      }
      await wait(settle);
      watcher.stop();
      return { strategy: attempt.strategy, changed: true, loginRequest: watcher.summary() };
    }

    await wait(settle);
    watcher.stop();

    const afterSnapshot = await safeSnapshot();
    if (afterSnapshot === null) {
      // The page went away underneath us, which only a real navigation does.
      return { strategy: attempt.strategy, changed: true, loginRequest: noRequest };
    }
    const after = fingerprint(afterSnapshot);
    const base = fingerprint(baseline);
    if (after.strong !== base.strong) {
      return { strategy: attempt.strategy, changed: true, loginRequest: noRequest };
    }
    if (newFailureNoticeShown(baseline, afterSnapshot)) {
      // The site answered with a refusal we could not attribute to a request
      // (a WebSocket, a body the browser did not expose). Trying again would
      // only send the password again.
      return { strategy: attempt.strategy, changed: true, loginRequest: noRequest };
    }
    if (after.weak !== base.weak && !weakHit) {
      // Something moved on the page but nothing that a submission would move —
      // most likely we opened a menu. Keep trying the other candidates.
      weakHit = attempt.strategy;
    }
  }

  return weakHit
    ? { strategy: weakHit, changed: true, loginRequest: noRequest }
    : { strategy: 'none', changed: false, loginRequest: noRequest };
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

function failure(errorCode, errorMessage, evidence, extra = {}) {
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
    evidenceCodes: extra.evidenceCodes || [],
    submitStrategy: extra.submitStrategy || null,
    loginRequest: extra.loginRequest || null,
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
 * @param {number} [options.responseWaitMs] how long to wait for the site to
 *   answer a login request (default LOGIN_RESPONSE_WAIT_MS; tests shorten it)
 * @returns {Promise<Object>} `errorCode` is one of the codes the UI maps; the
 *   new `loginRequest` summary carries no URL, body, header or value.
 */
async function testLogin(options) {
  const { loginUrl, credentials, submitAlternates, expectedMarker, responseWaitMs } = options;
  // A bare selector string is a submit button too. The scan form's dropdown
  // used to send one, and reading `.selector` off a string silently dropped
  // the customer's choice: only Enter was ever pressed.
  const submitButton = typeof options.submitButton === 'string' && options.submitButton.trim()
    ? { selector: options.submitButton.trim() }
    : options.submitButton;

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

    // Watching from the first request, so a token the page already used before
    // anyone signed in (a public API key sent as Bearer) is never mistaken for
    // the session.
    const bearerWatch = watchBearerTokens(page);

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

    bearerWatch.arm();
    const submitResult = await submitLogin(page, submitButton, submitAlternates, {
      // Compared against request bodies in memory to recognise the login
      // request; never logged, stored or returned.
      credentialValues: (credentials || []).map(c => c && c.value).filter(v => typeof v === 'string'),
      responseWaitMs
    });
    const loginRequest = submitResult.loginRequest || { detected: false, matchedBy: null, status: null, outcome: null };
    const strategy = submitResult.strategy;

    if (!submitResult.changed) {
      // Nothing we clicked reached the site: no login request went out and the
      // page did not move. Reporting this as "wrong password" is what sent
      // people hunting for credential problems that did not exist.
      return failure(
        'SUBMIT_NO_EFFECT',
        'Submitting the login form had no effect on the page.',
        'No login request, URL, cookie or message change after every submit strategy',
        { loginRequest, submitStrategy: strategy, evidenceCodes: ['no_login_request'] }
      );
    }

    if (loginRequest.detected && (loginRequest.outcome === 'timeout' || loginRequest.outcome === 'network_error')) {
      // The login went out and the site never answered — typically an API that
      // is asleep and still waking. Not a credential problem, and not a wrong
      // button either: the same test usually succeeds a minute later.
      const code = loginRequest.outcome === 'timeout' ? 'login_request_unanswered' : 'login_request_network_error';
      return failure(
        'LOGIN_NO_RESPONSE',
        'The site did not answer the login request in time.',
        code,
        { loginRequest, submitStrategy: strategy, evidenceCodes: [code] }
      );
    }

    const after = await captureSnapshot(page, true);

    // The site said no. Three things must hold, so a site that did sign us in
    // despite an odd status code is never reported as refused: the login form
    // is still on screen, the address did not move, and no session cookie
    // arrived. Then either the login request was answered with an error (HTTP
    // or in its JSON), or a failure message appeared — in an error element or
    // a toast, which is the only answer many single-page apps give.
    const stillOnLoginForm =
      after.visiblePasswordFields > 0 &&
      before.url === after.url &&
      cookieDelta(before.cookies, after.cookies).sessionLike.length === 0;
    const refusedOnWire =
      loginRequest.detected && (loginRequest.outcome === 'http_error' || loginRequest.outcome === 'app_error');
    if (stillOnLoginForm && (refusedOnWire || newFailureNoticeShown(before, after))) {
      const code = refusedOnWire ? `login_${loginRequest.outcome}` : 'failure_notice_shown';
      return failure(
        'LOGIN_REJECTED',
        'The site rejected the login.',
        code,
        { loginRequest, submitStrategy: strategy, evidenceCodes: [code] }
      );
    }

    // Compare against the same page with no session at all.
    const anonymousText = await fetchAnonymousText(browser, after.url);
    let markerResult = deriveMarker({
      signedInText: after.visibleText,
      anonymousText,
      signedInHtml: after.html,
      // Never let a message the page is showing become the proof of success —
      // an error, or a toast. A "Welcome back" toast fades within seconds, so
      // a marker taken from one would make every later check think the
      // session had been lost.
      excludeTexts: [...(after.errorTexts || []), ...noticeLines(after.noticeTexts)]
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

    // Token session. If the sign-in worked but no cookie arrived and the app has
    // not yet called its API, load the signed-in page once more: an app that
    // keeps its token in storage reads it on start-up and sends it with its
    // first API call, which is what we record. Only after a sign-in that scored
    // as one — never to manufacture a session out of a failed login.
    //
    // A site that signed us in with a session cookie never gets token API hosts:
    // the cookie is its session, and it is scanned exactly as before Bearer
    // support existed. Every recorded session then passes the shared host policy
    // (no shared third-party API, label-boundary host checks, no logout seeds).
    const hasSessionCookie = cookieDelta(before.cookies, after.cookies).sessionLike.length > 0;
    if (verdict.authenticated && !hasSessionCookie &&
        eligibleBearerSessions(bearerWatch.sessions()).length === 0) {
      try {
        await page.reload({ waitUntil: 'networkidle2', timeout: 15000 });
        await wait(1500);
      } catch {
        // A slow or failing reload just means no token was seen.
      }
    }
    bearerWatch.stop();
    const bearer = verdict.authenticated
      ? eligibleBearerSessions(bearerWatch.sessions(), { hasSessionCookie })
      : [];

    await browser.close();
    browser = null;

    const evidence = verdict.evidenceCodes.join('; ') || 'no_observable_change';

    return {
      success: true,
      authenticated: verdict.authenticated,
      authConfirmed: verdict.authConfirmed,
      postLoginUrl: after.url,
      cookies: after.cookies,
      // Bearer sessions the app sent to its API after signing in, one per API
      // origin, each with the GET URLs the API answered with 2xx. Contains the
      // token: held in memory by the caller, never logged, stored or returned.
      // Always empty when the login set a session cookie.
      bearer,
      hasSessionCookie,
      marker: verdict.marker,
      markerCheckableInBody: verdict.markerCheckableInBody,
      // Whether the marker is strong enough to prove a sign-in, or merely
      // useful for spotting a change. A re-login must not treat a weak one as
      // proof by feeding it back in as a supplied marker.
      markerConfidence: markerResult.confidence || 'low',
      markerAlternates: markerResult.alternates || [],
      evidenceCodes: verdict.evidenceCodes,
      submitStrategy: submitResult.strategy,
      loginRequest,
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
