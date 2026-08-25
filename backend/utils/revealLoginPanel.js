/**
 * Reveal a hidden login panel.
 *
 * Many sites have no dedicated login page: the form lives in a header dropdown,
 * a modal, or behind a call-to-action like "Get Started", and only enters a
 * usable state after a click. quizmint.me is one of these — the URL never
 * changes, so nothing about the address tells us a login form exists.
 *
 * This used to live inside `services/loginTestService.js`, which meant the
 * *test* step could open such a panel but the *detection* step never could.
 * Detection ran first, found no password field, and the flow stopped before the
 * test could have helped. Shared here so both steps behave the same way.
 *
 * Takes a Puppeteer page; imports nothing, so it stays cheap to reuse.
 */

// Ordered most-specific first: an explicit login control is a better thing to
// click than a generic account icon.
const TOGGLE_SELECTORS = [
  'a[href*="login" i]',
  'a[href*="signin" i]',
  'a[href*="sign-in" i]',
  'button[class*="login" i]',
  'a[class*="login" i]',
  'button[id*="login" i]',
  '[aria-label*="login" i]',
  '[aria-label*="sign in" i]',
  '[aria-label*="ログイン" i]',
  '[aria-label*="account" i]',
  'button[class*="account" i]',
  'a[class*="account" i]',
  'button[class*="user" i]',
  'a[class*="user" i]'
];

// Call-to-action wording that commonly gates a signup/login panel.
const CTA_TEXT_PATTERN = /get\s?started|sign\s?in|log\s?in|sign\s?up|始める|ログイン/i;

const SETTLE_MS = 600;

// Hard cap on how many things we are willing to click. Without it, a page with
// no login at all walks the entire selector list — three handles each, with a
// settle between — and spends close to half a minute clicking before reporting
// what it could have reported immediately.
const MAX_TOGGLE_CLICKS = 8;

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Does the page currently show a usable password field?
 * @param {import('puppeteer').Page} page
 * @returns {Promise<boolean>}
 */
async function hasVisiblePasswordField(page) {
  try {
    return await page.evaluate(() => {
      const inputs = document.querySelectorAll('input[type="password"]');
      for (const input of inputs) {
        const style = window.getComputedStyle(input);
        if (style.display === 'none' || style.visibility === 'hidden') continue;
        const rect = input.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) return true;
      }
      return false;
    });
  } catch {
    return false;
  }
}

/**
 * Click likely toggles until a password field becomes visible.
 *
 * Stops at the first click that works, so we disturb the page as little as
 * possible. Returns whether a password field is visible when we are done.
 *
 * @param {import('puppeteer').Page} page
 * @returns {Promise<{revealed:boolean, clicked:string|null}>}
 */
async function revealLoginPanel(page) {
  if (await hasVisiblePasswordField(page)) {
    return { revealed: true, clicked: null };
  }

  let clicks = 0;

  for (const selector of TOGGLE_SELECTORS) {
    if (clicks >= MAX_TOGGLE_CLICKS) break;

    let handles = [];
    try {
      handles = await page.$$(selector);
    } catch {
      continue; // Malformed selector for this page; try the next candidate.
    }

    for (const handle of handles.slice(0, 2)) {
      if (clicks >= MAX_TOGGLE_CLICKS) break;
      try {
        clicks++;
        await handle.click({ delay: 20 });
        await wait(SETTLE_MS);
        if (await hasVisiblePasswordField(page)) {
          return { revealed: true, clicked: selector };
        }
      } catch {
        // Not clickable (covered, detached, off-screen). Move on.
      }
    }
  }

  // Nothing matched on attributes — fall back to matching on button text, which
  // is how call-to-action entry points like "Get Started" are usually written.
  try {
    const clickedText = await page.evaluate((pattern) => {
      const re = new RegExp(pattern, 'i');
      const candidates = document.querySelectorAll('button, a, [role="button"]');
      for (const el of candidates) {
        const text = (el.textContent || '').replace(/\s+/g, ' ').trim();
        if (text && text.length <= 30 && re.test(text)) {
          el.click();
          return text;
        }
      }
      return null;
    }, CTA_TEXT_PATTERN.source);

    if (clickedText) {
      await wait(SETTLE_MS);
      if (await hasVisiblePasswordField(page)) {
        return { revealed: true, clicked: `text:${clickedText}` };
      }
    }
  } catch {
    // Page navigated away or evaluation blocked; fall through to the result.
  }

  return { revealed: await hasVisiblePasswordField(page), clicked: null };
}

module.exports = {
  revealLoginPanel,
  hasVisiblePasswordField,
  TOGGLE_SELECTORS,
  CTA_TEXT_PATTERN
};
