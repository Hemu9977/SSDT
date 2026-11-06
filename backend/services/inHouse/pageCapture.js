const crypto = require('crypto');
const puppeteer = require('puppeteer');
const { LAUNCH_ARGS, chromiumPath, runInBrowserSlot } = require('./browserSlot');
const { countryOf } = require('../../utils/ipCountry');
const { lookupVerdict } = require('./threatVerdict');

/**
 * In-house page capture — the fallback for the external page-analysis service
 * (services/urlscanService.js). The threat verdict comes from ./threatVerdict.
 *
 * The external service loads the target from its own servers. Behind a client's
 * IP allowlist that is refused: it fails, times out, or captures the 403 page.
 * Then we load the page in our own headless Chromium, from our own egress IP, and
 * keep the screenshot in our own storage.
 *
 * The result has the shape every reader uses (score card, details panel, PDF,
 * AI prompt): `page.*`, `stats.*`, `verdicts.*`, `lists.*`, `screenshot`.
 */

const CAPTURE_TIMEOUT_MS = Number(process.env.PAGE_CAPTURE_TIMEOUT_MS) || 60_000;
const NAV_TIMEOUT_MS = 45_000;
const SETTLE_MS = 1500;
const SCREENSHOT_BUCKET = 'page_screenshots';
const SCREENSHOT_ROUTE = '/api/scan/screenshot';

// ── Capture ──────────────────────────────────────────────────────────────────

const dayMs = 24 * 60 * 60 * 1000;

/**
 * Build the stored shape from what the browser observed. Pure, for tests.
 * @param {object} c
 * @param {string} c.requestedUrl
 * @param {string} c.finalUrl
 * @param {{ip?:string, server?:string, tlsIssuer?:string, validFrom?:number, validTo?:number}} c.main
 * @param {Array<{url:string, ip?:string}>} c.responses
 * @param {number} c.requestCount
 * @param {number} c.dataLength
 */
function buildCaptureResult({ requestedUrl, finalUrl, main, responses, requestCount, dataLength }) {
  const ips = [...new Set(responses.map(r => r.ip).filter(Boolean))];
  const countries = [...new Set(ips.map(countryOf).filter(Boolean))];
  const domains = [...new Set(responses.map(r => { try { return new URL(r.url).hostname; } catch { return null; } }).filter(Boolean))];

  const validFrom = Number(main.validFrom);
  const validTo = Number(main.validTo);
  const tlsValidDays = Number.isFinite(validFrom) && Number.isFinite(validTo) && validTo > validFrom
    ? Math.floor(((validTo - validFrom) * 1000) / dayMs)
    : undefined;
  const tlsAgeDays = Number.isFinite(validFrom) && validFrom > 0
    ? Math.max(0, Math.floor((Date.now() - validFrom * 1000) / dayMs))
    : undefined;

  const page = {
    url: finalUrl,
    domain: new URL(finalUrl).hostname,
    ip: main.ip || null,
    country: countryOf(main.ip),
    server: main.server || null
  };
  if (main.tlsIssuer) page.tlsIssuer = main.tlsIssuer;
  if (tlsValidDays !== undefined) page.tlsValidDays = tlsValidDays;
  if (tlsAgeDays !== undefined) page.tlsAgeDays = tlsAgeDays;

  return {
    url: requestedUrl,
    page,
    stats: {
      uniqIPs: ips.length,
      uniqCountries: countries.length,
      dataLength,
      requests: requestCount
    },
    lists: {
      ips,
      countries,
      domains,
      urls: [...new Set(responses.map(r => r.url))].slice(0, 20)
    }
  };
}

/** Load the page, observe its traffic, and take a screenshot. */
async function capturePage(url, { signal }) {
  const browser = await puppeteer.launch({
    headless: true,
    executablePath: chromiumPath(),
    args: LAUNCH_ARGS,
    timeout: NAV_TIMEOUT_MS
  });
  const close = () => browser.close().catch(() => {});
  signal.addEventListener('abort', close, { once: true });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    // A headless user agent is refused by many WAFs; present as the Chrome it is.
    await page.setUserAgent((await browser.userAgent()).replace('HeadlessChrome', 'Chrome'));

    const cdp = await page.createCDPSession();
    await cdp.send('Network.enable');
    let dataLength = 0;
    cdp.on('Network.dataReceived', e => { dataLength += e.dataLength || 0; });

    let requestCount = 0;
    page.on('request', () => { requestCount++; });

    const responses = [];
    let mainResponse = null;
    page.on('response', res => {
      const remote = res.remoteAddress?.() || {};
      responses.push({ url: res.url(), ip: remote.ip || null });
      const req = res.request();
      if (req.isNavigationRequest() && req.frame() === page.mainFrame()) mainResponse = res;
    });

    try {
      await page.goto(url, { waitUntil: 'networkidle2', timeout: NAV_TIMEOUT_MS });
    } catch (err) {
      // A page that never goes network-idle (long polling, streaming) has still
      // loaded; only fail when the document itself never arrived.
      if (!mainResponse) throw err;
      console.warn(`[PageCapture] Navigation did not settle (${err.message}) — using the loaded page`);
    }
    if (!mainResponse) throw new Error('No response for the page');

    const status = mainResponse.status();
    if (status >= 400) {
      // Refused or broken page (e.g. 403 from an IP allowlist): report the check as
      // unavailable, not a screenshot and statistics of the error page.
      throw new Error(`Page answered HTTP ${status}`);
    }

    await new Promise(r => setTimeout(r, SETTLE_MS));
    const screenshot = await page.screenshot({ type: 'jpeg', quality: 80 });

    const headers = mainResponse.headers();
    const security = mainResponse.securityDetails();
    const remote = mainResponse.remoteAddress?.() || {};

    return {
      capture: buildCaptureResult({
        requestedUrl: url,
        finalUrl: page.url() || url,
        main: {
          ip: remote.ip,
          server: headers.server,
          tlsIssuer: security?.issuer(),
          validFrom: security?.validFrom(),
          validTo: security?.validTo()
        },
        responses,
        requestCount,
        dataLength
      }),
      screenshot
    };
  } finally {
    signal.removeEventListener('abort', close);
    await close();
  }
}

/**
 * Store the screenshot. Its URL carries an unguessable token instead of the
 * caller's credentials, because the report shows it with a plain <img>
 * (as it did the external service's public screenshot URL).
 */
async function storeScreenshot(buffer) {
  const gridfsService = require('../gridfsService');
  const token = crypto.randomBytes(32).toString('hex');
  const fileId = await gridfsService.uploadFile(
    buffer, `${token}.jpg`, { token, contentType: 'image/jpeg' }, SCREENSHOT_BUCKET, 60_000
  );
  return { token, fileId: String(fileId) };
}

/**
 * Run the complete page analysis.
 * @param {string} targetUrl
 * @param {number} [maxWaitTime] - overall capture budget in ms
 * @returns {Promise<object>} Page analysis result (see buildCaptureResult + verdicts/screenshot)
 */
async function runPageCapture(targetUrl, maxWaitTime = CAPTURE_TIMEOUT_MS) {
  console.log(`🔍 [PageCapture] Starting for: ${targetUrl}`);

  // The verdict is DNS-only, so it runs beside the capture rather than in the slot.
  const [captured, verdicts] = await Promise.all([
    runInBrowserSlot('Page capture', ctx => capturePage(targetUrl, ctx), { timeoutMs: maxWaitTime }),
    lookupVerdict(targetUrl)
  ]);

  let screenshot = null;
  let screenshotFileId = null;
  try {
    const stored = await storeScreenshot(captured.screenshot);
    screenshot = `${SCREENSHOT_ROUTE}/${stored.token}.jpg`;
    screenshotFileId = stored.fileId;
  } catch (err) {
    // The analysis is still valid without the picture.
    console.warn(`[PageCapture] Screenshot not stored: ${err.message}`);
  }

  console.log(`✅ [PageCapture] Completed for: ${targetUrl}`);
  return {
    uuid: crypto.randomUUID(),
    ...captured.capture,
    task: { time: new Date().toISOString(), url: targetUrl },
    verdicts,
    screenshot,
    screenshotFileId,
    reportUrl: null
  };
}

module.exports = {
  runPageCapture,
  SCREENSHOT_BUCKET,
  // Exposed for tests.
  _buildCaptureResult: buildCaptureResult
};
