/**
 * Login Signals
 *
 * Pure decision logic for "did this login actually work?", split out of
 * `services/loginTestService.js` so it can be exercised against recorded page
 * snapshots with no browser, no network and no database.
 *
 * The rule this module exists to enforce: **evidence is a change, not a state.**
 * The previous implementation accepted "the page has a nav bar" and "some cookie
 * is protected from JavaScript" as proof of login. Both are true on most sites
 * before anyone types anything, so a wrong password could score as success.
 * Everything here compares before-submit against after-submit, and compares the
 * signed-in page against the same page fetched anonymously.
 */

// Cookie names that carry a session on the overwhelming majority of stacks.
const SESSION_COOKIE_PATTERN = /(^|[._-])(sess|session|sid|token|auth|jwt|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|remember)/i;

// Phrases that only appear once you are signed in. Ordered best-first: these are
// short, stable, and survive a page reload, which is exactly what we need from a
// marker we will re-check for hours.
const HIGH_SIGNAL_MARKERS = [
  /\blog\s?out\b/i,
  /\bsign\s?out\b/i,
  /\blogout\b/i,
  /\bsignoff\b/i,
  /\bsign\s?off\b/i,
  /\bmy\s+account\b/i,
  /\bmy\s+profile\b/i,
  /\bdashboard\b/i,
  /ログアウト/,
  /サインアウト/,
  /マイページ/,
  /マイアカウント/
];

// Text that means the opposite of being signed in. This must never become a
// marker, and the reason is not theoretical: on a failed login the error
// message *is* new text, so a naive diff against the anonymous baseline picks
// "Login Failed" as proof of a successful sign-in. A wrong password then scores
// as confirmed — the single failure this whole feature exists to prevent.
const FAILURE_TEXT_PATTERN =
  /\bfail|\binvalid\b|\bincorrect\b|not found|\bdenied\b|try again|\bwrong\b|\bunable\b|\berror\b|\bexpired\b|失敗|正しくありません|エラー|見つかりません/i;

// Text that looks different on every page load and must never become a marker:
// clocks, counters, ids, money, and anything long enough to be a paragraph.
const VOLATILE_MARKER_PATTERN = /\d{2,}|[0-9a-f]{12,}|\b\d{1,2}:\d{2}\b|[¥$€£]/i;

const MIN_MARKER_LENGTH = 3;
const MAX_MARKER_LENGTH = 40;

/**
 * Normalise page text for comparison: collapse whitespace, drop empties.
 * @param {string} text
 * @returns {string[]} distinct trimmed lines
 */
function toLines(text) {
  if (!text || typeof text !== 'string') return [];
  const seen = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s+/g, ' ').trim();
    if (line) seen.add(line);
  }
  return [...seen];
}

/**
 * Compare two cookie jars.
 *
 * Only cookies that are **new or whose value changed** count — the anonymous
 * session cookie a site hands out on first contact is present before login and
 * proves nothing about it.
 *
 * @param {Array<{name:string,value:string,httpOnly?:boolean}>} before
 * @param {Array<{name:string,value:string,httpOnly?:boolean}>} after
 * @returns {{added:string[], changed:string[], sessionLike:string[]}}
 */
function cookieDelta(before, after) {
  // `x || []` lets a truthy non-array through and then throws on .map — the
  // fuzzer found this in four places. Shape-check instead of truth-check.
  const beforeList = Array.isArray(before) ? before : [];
  const afterList = Array.isArray(after) ? after : [];
  const isCookie = (c) => c && typeof c === 'object';
  const beforeMap = new Map(beforeList.filter(isCookie).map(c => [c.name, c.value]));
  const added = [];
  const changed = [];

  for (const cookie of afterList.filter(isCookie)) {
    if (!beforeMap.has(cookie.name)) {
      added.push(cookie.name);
    } else if (beforeMap.get(cookie.name) !== cookie.value) {
      changed.push(cookie.name);
    }
  }

  // A session-like cookie only counts as evidence if it is one of the ones that
  // actually moved. `httpOnly` alone is deliberately NOT sufficient here: it was
  // the single biggest source of false "login successful" results.
  const moved = new Set([...added, ...changed]);
  const sessionLike = afterList
    .filter(isCookie)
    .filter(c => moved.has(c.name))
    .filter(c => SESSION_COOKIE_PATTERN.test(c.name) || c.httpOnly === true)
    .map(c => c.name);

  return { added, changed, sessionLike };
}

/**
 * Error messages that appeared *because of* this submission.
 *
 * Angular Material and most component libraries keep validation markup in the
 * DOM permanently (`ng-invalid`, `mat-mdc-form-field-error-wrapper`). Matching
 * on presence vetoed logins that had genuinely succeeded, so we diff instead:
 * only text that was not on the page before the submit counts.
 *
 * @param {string[]} beforeErrors visible error text before submit
 * @param {string[]} afterErrors  visible error text after submit
 * @returns {string[]}
 */
function newErrorMessages(beforeErrors, afterErrors) {
  const beforeList = Array.isArray(beforeErrors) ? beforeErrors : [];
  const afterList = Array.isArray(afterErrors) ? afterErrors : [];
  const before = new Set(beforeList.map(t => String(t).replace(/\s+/g, ' ').trim()).filter(Boolean));
  return afterList
    .map(t => String(t))
    .map(t => t.replace(/\s+/g, ' ').trim())
    .filter(t => t && !before.has(t));
}

/**
 * Score a single marker candidate. Higher is better; null means unusable.
 * @param {string} candidate
 * @returns {number|null}
 */
function scoreMarkerCandidate(candidate) {
  if (typeof candidate !== 'string') return null;
  const text = candidate.replace(/\s+/g, ' ').trim();
  if (text.length < MIN_MARKER_LENGTH || text.length > MAX_MARKER_LENGTH) return null;
  if (VOLATILE_MARKER_PATTERN.test(text)) return null;
  // A failure message is new text too. Without this, a wrong password produces
  // "Login Failed" as its own proof of success.
  if (FAILURE_TEXT_PATTERN.test(text)) return null;

  const highSignalIndex = HIGH_SIGNAL_MARKERS.findIndex(re => re.test(text));
  if (highSignalIndex !== -1) {
    // Earlier entries in the list are better markers; shorter is better again.
    return 1000 - highSignalIndex * 10 - text.length;
  }

  // Anything else is a fallback: usable, but far less trustworthy than an
  // explicit sign-out control. Prefer short, word-shaped phrases.
  if (!/^[\p{L}\p{N} '&_/-]+$/u.test(text)) return null;
  return 100 - text.length;
}

/**
 * Derive the phrase that proves we are signed in.
 *
 * @param {Object} input
 * @param {string} input.signedInText  visible text of the page after logging in
 * @param {string} input.anonymousText visible text of the same URL with no cookies
 * @param {string} [input.signedInHtml] raw HTML of the signed-in page
 * @returns {{marker:string|null, alternates:string[], checkableInBody:boolean}}
 */
function deriveMarker({ signedInText, anonymousText, signedInHtml, excludeTexts }) {
  const anonymousLines = toLines(anonymousText);
  const anonymous = new Set(anonymousLines.map(l => l.toLowerCase()));
  const anonymousBlob = anonymousLines.join('\n').toLowerCase();
  // Anything the page is currently showing as an error is disqualified, however
  // it is worded — a site's own phrasing will not always match a pattern.
  const excluded = new Set(
    (Array.isArray(excludeTexts) ? excludeTexts : [])
      .map(t => String(t).replace(/\s+/g, ' ').trim().toLowerCase())
      .filter(Boolean)
  );
  const candidates = [];

  for (const line of toLines(signedInText)) {
    if (anonymous.has(line.toLowerCase())) continue;
    if (excluded.has(line.toLowerCase())) continue;

    // Prefer the phrase itself over the line it happens to sit in. "Sign Off |
    // Contact Us" is a worse marker than "Sign Off": the shorter one survives a
    // layout change and, crucially, can still be found in a raw response body,
    // where the surrounding text belongs to different elements.
    for (const pattern of HIGH_SIGNAL_MARKERS) {
      const found = line.match(pattern);
      if (found && found[0] && !anonymousBlob.includes(found[0].toLowerCase())) {
        const score = scoreMarkerCandidate(found[0]);
        if (score !== null) candidates.push({ line: found[0], score: score + 5, high: true });
      }
    }

    const score = scoreMarkerCandidate(line);
    if (score !== null) {
      candidates.push({ line, score, high: HIGH_SIGNAL_MARKERS.some(re => re.test(line)) });
    }
  }

  candidates.sort((a, b) => b.score - a.score);
  const best = candidates.length > 0 ? candidates[0] : null;
  const marker = best ? best.line : null;

  // Whether this marker is strong enough to *prove* a sign-in, as opposed to
  // merely being useful for spotting a later change.
  //
  // Only an explicit signed-in control counts. Any other new text is just text:
  // a site's failure notice ("Please check your details", "Too many attempts
  // today") is new too, and treating that as proof turned a wrong password into
  // a green tick. Excluding failure-*shaped* wording was not enough — plenty of
  // failure messages read perfectly neutrally.
  const confidence = best && best.high ? 'high' : 'low';

  // A single-page app serves the same shell HTML to everyone and fills it in
  // with JavaScript, so the marker will not appear in a raw response body. We
  // must know that up front: otherwise scan-time verification would read the
  // shell, fail to find the marker, and wrongly report the session as lost.
  const checkableInBody = Boolean(marker && markerPresentInBody(signedInHtml, marker));

  return {
    marker,
    confidence,
    alternates: candidates.slice(1, 4).map(c => c.line),
    checkableInBody
  };
}

/**
 * Decide the outcome of a login attempt.
 *
 * Returns three fields that mean different things on purpose:
 *  - `authConfirmed` — the honest answer, one of confirmed/unconfirmed/failed.
 *  - `authenticated` — the legacy gate that decides whether the flow may
 *    continue. Kept permissive (anything that is not an outright failure) so
 *    that sites which work today keep working; the UI reports the honest field.
 *  - `evidenceCodes` — stable identifiers, never prose. The frontend maps these
 *    through `t()`; nothing here is ever shown to a customer verbatim.
 *
 * @param {Object} input
 * @param {{url:string, cookies:Array, errorTexts:string[]}} input.before
 * @param {{url:string, cookies:Array, errorTexts:string[]}} input.after
 * @param {{marker:string|null, checkableInBody:boolean}} [input.markerResult]
 * @returns {{authenticated:boolean, authConfirmed:string, evidenceCodes:string[], marker:string|null, markerCheckableInBody:boolean}}
 */
function scoreLoginAttempt({ before, after, markerResult }) {
  const evidenceCodes = [];

  const urlChanged = Boolean(before && after && before.url !== after.url);
  if (urlChanged) evidenceCodes.push('url_changed');

  const delta = cookieDelta(before && before.cookies, after && after.cookies);
  if (delta.sessionLike.length > 0) evidenceCodes.push('session_cookie_issued');

  const errors = newErrorMessages(before && before.errorTexts, after && after.errorTexts);
  if (errors.length > 0) evidenceCodes.push('error_shown');

  const marker = (markerResult && markerResult.marker) || null;
  if (marker) evidenceCodes.push('signed_in_marker_found');

  // Nothing moved at all: the submit did not reach the site. This is the Juice
  // Shop case where the click landed on a header button instead of the form.
  const nothingHappened =
    !urlChanged && delta.added.length === 0 && delta.changed.length === 0 && errors.length === 0 && !marker;

  if (nothingHappened) {
    evidenceCodes.push('no_observable_change');
    return {
      authenticated: false,
      authConfirmed: 'failed',
      evidenceCodes,
      marker: null,
      markerCheckableInBody: false
    };
  }

  // Only a strong marker confirms. A weak one — arbitrary text that happens to
  // be new — is kept for spotting a later change, but it is not proof: a site's
  // failure notice is new text too, and treating that as evidence is what let a
  // wrong password score as a success.
  const strongMarker = marker && (!markerResult.confidence || markerResult.confidence === 'high');

  // A strong marker outranks an error message: some sites render a stale
  // validation hint next to a form that nonetheless logged you in.
  if (strongMarker) {
    return {
      authenticated: true,
      authConfirmed: 'confirmed',
      evidenceCodes,
      marker,
      markerCheckableInBody: Boolean(markerResult && markerResult.checkableInBody)
    };
  }

  if (errors.length > 0) {
    return {
      authenticated: false,
      authConfirmed: 'failed',
      evidenceCodes,
      marker: null,
      markerCheckableInBody: false
    };
  }

  // Something moved, but nothing proves it was a login. The scan may proceed —
  // the customer is told it could not be confirmed, and the report repeats it.
  //
  // A weak marker is still handed back: it cannot prove the sign-in, but it is
  // a usable canary for noticing the page change later in the scan. Callers
  // must read `authConfirmed`, never the presence of `marker`, to decide
  // whether the sign-in was actually verified.
  return {
    authenticated: true,
    authConfirmed: 'unconfirmed',
    evidenceCodes,
    marker: marker || null,
    markerCheckableInBody: Boolean(marker && markerResult && markerResult.checkableInBody)
  };
}

/**
 * Is the signed-in marker still present in this response body?
 *
 * @param {string} body raw response body
 * @param {string} marker
 * @returns {boolean}
 */
function markerPresentInBody(body, marker) {
  if (typeof body !== 'string' || typeof marker !== 'string') return false;
  if (!body || !marker) return false;

  const lower = body.toLowerCase();
  const wanted = marker.toLowerCase();
  if (lower.includes(wanted)) return true;

  // Rendered text collapses whitespace; HTML source does not. "Sign Off" on the
  // page can be "Sign\n      Off" in the markup, so match across any run of
  // whitespace between the words rather than requiring a single space.
  const parts = wanted.split(/\s+/).filter(Boolean);
  if (parts.length < 2) return false;

  const escaped = parts.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(escaped.join('\\s+'), 'i').test(body);
}

module.exports = {
  cookieDelta,
  newErrorMessages,
  deriveMarker,
  scoreLoginAttempt,
  markerPresentInBody,
  scoreMarkerCandidate,
  toLines,
  SESSION_COOKIE_PATTERN,
  FAILURE_TEXT_PATTERN,
  HIGH_SIGNAL_MARKERS
};
