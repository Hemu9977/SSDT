'use strict';

/**
 * HTTP Basic credentials for a headless Chromium page, answered for ONE origin.
 *
 * Never use Puppeteer's `page.authenticate()` or Lighthouse's `extraHeaders` for a
 * scan credential (Phase 0, tests 2.3 / 3.2 / 3.4):
 *   - `page.authenticate` answers every Basic challenge the page meets. It sent
 *     the credential to another origin (directly, after a redirect, and from an
 *     embedded image), to a subdomain, and to plain-HTTP `http://target`.
 *   - `extraHeaders` attaches the header to every request, third parties included
 *     (9 leaked requests on one page load).
 *
 * This handler answers a challenge only when ALL of these hold:
 *   - it comes from the server (not a proxy),
 *   - the request's origin is exactly the target origin (scheme + host + port),
 *   - the request has not already been answered (a wrong password is tried once,
 *     never looped, so a customer account is not locked).
 * Every other challenge is cancelled. Requests the page session cannot see (a
 * cross-origin iframe in its own process, a service worker) are never answered
 * at all, which fails closed.
 */

/**
 * @param {import('puppeteer').Page} page
 * @param {{origin: string, username: string, password: string}} cred
 * @returns {Promise<{answered: number, refused: string[], detach: () => Promise<void>}>}
 *   `refused` holds origins only (never full URLs), for logging.
 */
async function installScopedBasicAuth(page, { origin, username, password }) {
  const target = new URL(origin).origin;
  if (!target.startsWith('https://')) throw new Error('Basic credentials are only ever sent to an https origin');

  const cdp = await page.createCDPSession();
  const answered = new Set();
  const stats = { answered: 0, refused: [] };

  cdp.on('Fetch.requestPaused', (e) => {
    cdp.send('Fetch.continueRequest', { requestId: e.requestId }).catch(() => {});
  });
  cdp.on('Fetch.authRequired', (e) => {
    let reqOrigin = null;
    try { reqOrigin = new URL(e.request.url).origin; } catch (_) { /* unparseable: refuse */ }
    const allow = e.authChallenge && e.authChallenge.source === 'Server'
      && reqOrigin === target
      && !answered.has(e.requestId);
    answered.add(e.requestId);
    if (allow) stats.answered++;
    else stats.refused.push(reqOrigin || 'unknown');
    cdp.send('Fetch.continueWithAuth', {
      requestId: e.requestId,
      authChallengeResponse: allow
        ? { response: 'ProvideCredentials', username, password }
        : { response: 'CancelAuth' }
    }).catch(() => {});
  });
  await cdp.send('Fetch.enable', { handleAuthRequests: true, patterns: [{ urlPattern: '*' }] });

  return {
    get answered() { return stats.answered; },
    get refused() { return stats.refused.slice(); },
    detach: async () => { try { await cdp.send('Fetch.disable'); await cdp.detach(); } catch (_) { /* page gone */ } }
  };
}

module.exports = { installScopedBasicAuth };
