/**
 * Login Form Ranking
 *
 * Pure logic for "which of these buttons submits the login form?", split out of
 * `services/loginDetectionService.js` so it can be tested against recorded DOM
 * shapes without a browser.
 *
 * Why this exists: the detector had a filter that skipped header/menu buttons,
 * but applied it only when the page used a real `<form>` element. Modern
 * single-page apps frequently have no `<form>`, which sent detection down a
 * fallback that swept the entire document and picked the first `<button>` in
 * document order — the sidebar toggle or the account menu in the header, never
 * the login button. The click then "succeeded" at doing nothing, and the login
 * was reported as failed.
 */

// Buttons that move you around the page rather than submitting anything.
const NAVIGATION_PATTERN = /toggle|menu|nav|hamburger|close|cancel|back|skip|dismiss|drawer|sidebar/i;

// Buttons that start a third-party sign-in flow. They often say "Log in with
// Google", so they match the submit patterns too — they must lose to the real
// submit button, but stay selectable in case the site genuinely only has these.
const THIRD_PARTY_PATTERN = /google|facebook|github|twitter|apple|microsoft|oauth|openid|sso|linkedin/i;

// Text on the button that actually submits credentials.
const SUBMIT_TEXT_PATTERN = /log\s?in|sign\s?in|submit|continue|enter|proceed|ログイン|サインイン|送信/i;

// Links that leave the login form entirely.
// Written to match both visible text ("Not yet a customer?") and camelCase ids
// ("newCustomerLink"), which is why the separators are optional.
const AWAY_PATTERN = /forgot|reset|register|sign\s?up|signup|new\s*customer|create\s*account|help|support/i;

/**
 * Would clicking this element navigate rather than submit?
 * @param {{id?:string, label?:string, buttonText?:string, className?:string}} field
 * @returns {boolean}
 */
function isNavigationButton(field) {
  if (!field) return false;
  const text = (field.buttonText || field.label || '').trim();
  const id = field.id || '';
  const className = field.className || '';
  return NAVIGATION_PATTERN.test(text) || NAVIGATION_PATTERN.test(id) || NAVIGATION_PATTERN.test(className);
}

/**
 * Score one button candidate. Higher is better.
 *
 * @param {Object} field           classified field record
 * @param {number} index           position of this field in document order
 * @param {number} passwordIndex   position of the password field, or -1
 * @returns {number|null} null if the button must not be used at all
 */
function scoreSubmitButton(field, index, passwordIndex) {
  if (!field) return null;
  const isButton = field.tagName === 'BUTTON' || field.inputType === 'submit';
  if (!isButton) return null;
  if (isNavigationButton(field)) return null;

  const text = (field.buttonText || field.label || '').trim();
  const id = field.id || '';
  let score = 0;

  // The strongest signal the platform gives us.
  if (field.inputType === 'submit') score += 60;
  if (SUBMIT_TEXT_PATTERN.test(text)) score += 40;
  if (/login|signin|submit/i.test(id)) score += 30;

  // Third-party sign-in and "forgot password" style controls sit right next to
  // the real button and read similarly. Push them below it without excluding
  // them, so they remain available in the manual override dropdown.
  if (THIRD_PARTY_PATTERN.test(text) || THIRD_PARTY_PATTERN.test(id)) score -= 70;
  if (AWAY_PATTERN.test(text) || AWAY_PATTERN.test(id)) score -= 60;

  // Proximity to the password field. This is a refinement, not the main event:
  // header controls are already removed by `isNavigationButton`, and the id and
  // text signals above usually settle the rest. Proximity only changes the
  // answer when two equally worded buttons both sit before the form, where
  // document order alone would take the further one.
  if (passwordIndex >= 0) {
    const distance = Math.abs(index - passwordIndex);
    score += Math.max(0, 50 - distance * 5);
    // A button before the password field is far less likely to submit it.
    if (index < passwordIndex) score -= 25;
  }

  return score;
}

/**
 * Rank every button on the page, best submit candidate first.
 *
 * @param {Array<Object>} fields classified fields, in document order
 * @returns {Array<Object>} ranked button fields (may be empty)
 */
function rankSubmitButtons(fields) {
  const list = Array.isArray(fields) ? fields : [];
  const passwordIndex = list.findIndex(
    f => f && (f.inputType === 'password' || f.classification === 'password')
  );

  return list
    .map((field, index) => ({ field, index, score: scoreSubmitButton(field, index, passwordIndex) }))
    .filter(entry => entry.score !== null)
    // Document order is the tie-break, so pages that were already being handled
    // correctly keep resolving to exactly the same button as before.
    .sort((a, b) => (b.score - a.score) || (a.index - b.index))
    .map(entry => entry.field);
}

/**
 * Would clicking this start a third-party sign-in flow?
 *
 * Such buttons stay selectable by hand — some sites genuinely only offer
 * third-party sign-in — but they must never be clicked by the automatic retry
 * chain, which would send the headless browser off to an external provider.
 *
 * @param {{id?:string, label?:string, buttonText?:string}} field
 * @returns {boolean}
 */
function isThirdPartyButton(field) {
  if (!field) return false;
  const text = (field.buttonText || field.label || '').trim();
  return THIRD_PARTY_PATTERN.test(text) || THIRD_PARTY_PATTERN.test(field.id || '');
}

/**
 * The runners-up that are safe to click automatically if the first choice does
 * nothing. Ranked order, minus anything that would leave the site.
 *
 * @param {Array<Object>} ranked output of rankSubmitButtons
 * @returns {Array<Object>}
 */
function autoRetryCandidates(ranked) {
  const list = Array.isArray(ranked) ? ranked : [];
  return list.slice(1).filter(f => !isThirdPartyButton(f)).slice(0, 3);
}

module.exports = {
  isNavigationButton,
  isThirdPartyButton,
  autoRetryCandidates,
  scoreSubmitButton,
  rankSubmitButtons,
  NAVIGATION_PATTERN,
  THIRD_PARTY_PATTERN,
  SUBMIT_TEXT_PATTERN
};
