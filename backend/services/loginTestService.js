// File path: backend/services/loginTestService.js

const puppeteer = require('puppeteer');

/**
 * Some sites don't have a dedicated login page — the form lives in a
 * hidden header dropdown/modal that only appears after clicking a toggle
 * (e.g. an "account"/"login" icon). Try common toggles to reveal it.
 */
async function revealHiddenLoginPanel(page) {
  const toggleSelectors = [
    'a[href*="login" i]', 'button[class*="login" i]', 'a[class*="login" i]',
    '[aria-label*="login" i]', '[aria-label*="account" i]', '[aria-label*="ログイン" i]',
    'button[class*="account" i]', 'a[class*="account" i]', 'button[class*="user" i]',
    'a[class*="user" i]'
  ];
  for (const sel of toggleSelectors) {
    try {
      const handle = await page.$(sel);
      if (handle) {
        await handle.click({ delay: 20 }).catch(() => null);
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    } catch {
      // Toggle not clickable, try next candidate
    }
  }
}

/**
 * Test login credentials by filling and submitting the login form with dynamic fields
 * @param {Object} options
 * @param {string} options.loginUrl - URL of the login page
 * @param {Array} options.credentials - Array of credential objects: [{ selector, value, inputType }, ...]
 * @param {Object} [options.submitButton] - Submit button descriptor (optional)
 * @returns {Promise<Object>} Test result with cookies if successful
 */
async function testLogin(options) {
  const { loginUrl, credentials, submitButton } = options;

  let browser = null;

  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions',
        '--no-first-run'
      ],
      timeout: 30000
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );

    // Navigate to login page
    await page.goto(loginUrl, {
      waitUntil: 'networkidle2',
      timeout: 30000
    });

    // Wait for first field to be visible
    if (credentials && credentials.length > 0) {
      try {
        await page.waitForSelector(credentials[0].selector, { visible: true, timeout: 10000 });
      } catch {
        // Field exists in the DOM (it was found during detection) but may be
        // hidden inside a collapsed login dropdown/modal on a fresh page load.
        const existsInDom = await page.$(credentials[0].selector).catch(() => null);
        if (existsInDom) {
          await revealHiddenLoginPanel(page);
          try {
            await page.waitForSelector(credentials[0].selector, { visible: true, timeout: 5000 });
          } catch {
            return {
              success: false,
              authenticated: false,
              errorCode: 'FIELD_NOT_FOUND',
              errorMessage: 'Could not find the first login field on the page.',
              postLoginUrl: null,
              cookies: [],
              evidence: 'First field selector present but not visible after attempting to open login panel'
            };
          }
        } else {
          return {
            success: false,
            authenticated: false,
            errorCode: 'FIELD_NOT_FOUND',
            errorMessage: 'Could not find the first login field on the page.',
            postLoginUrl: null,
            cookies: [],
            evidence: 'First field selector not found'
          };
        }
      }
    }

    // Get the URL before login for comparison
    const preLoginUrl = page.url();

    // Fill all credential fields
    for (const cred of credentials) {
      try {
        // Wait for field to be available
        await page.waitForSelector(cred.selector, { visible: true, timeout: 5000 });

        // Clear and fill the field
        await page.click(cred.selector, { clickCount: 3 }); // Select all
        await page.type(cred.selector, cred.value, { delay: 50 });

        console.log(`✅ Filled field: ${cred.selector}`);
      } catch (err) {
        console.error(`❌ Failed to fill field: ${cred.selector}`, err.message);
        return {
          success: false,
          authenticated: false,
          errorCode: 'FIELD_FILL_FAILED',
          errorMessage: `Could not fill field: ${cred.selector}`,
          postLoginUrl: null,
          cookies: [],
          evidence: `Field fill failed: ${err.message}`
        };
      }
    }

    // Submit the form
    if (submitButton && submitButton.selector) {
      try {
        await Promise.all([
          page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null),
          page.click(submitButton.selector)
        ]);
      } catch {
        // If click fails, try pressing Enter on the last field
        await Promise.all([
          page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null),
          page.keyboard.press('Enter')
        ]);
      }
    } else {
      // No submit button found, press Enter
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null),
        page.keyboard.press('Enter')
      ]);
    }

    // Wait a bit for any post-login actions
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get the URL after login
    const postLoginUrl = page.url();

    // Get all cookies
    const cookies = await page.cookies();

    // Check if login was successful

    // Evidence 1: URL changed (common pattern)
    const urlChanged = postLoginUrl !== preLoginUrl;

    // Evidence 2: Check for error messages on the page
    const errorSelectors = [
      '.error', '.alert-danger', '.login-error', '[class*="error"]',
      '[class*="invalid"]', '[role="alert"]', '.message-error'
    ];

    let hasErrorMessages = false;
    for (const selector of errorSelectors) {
      try {
        const errorElem = await page.$(selector);
        if (errorElem) {
          const text = await page.evaluate(el => el.textContent, errorElem);
          if (text && text.trim().length > 0) {
            hasErrorMessages = true;
            console.log(`Found error message: ${text.trim().substring(0, 100)}`);
            break;
          }
        }
      } catch {
        // Selector not found, continue
      }
    }

    // Evidence 3: Session cookies received
    const hasSessionCookies = cookies.some(cookie =>
      cookie.name.toLowerCase().includes('session') ||
      cookie.name.toLowerCase().includes('token') ||
      cookie.name.toLowerCase().includes('auth') ||
      cookie.httpOnly === true
    );

    // Evidence 4: Check for common post-login elements
    const postLoginSelectors = [
      '[class*="logout"]', '[class*="signout"]', '[class*="dashboard"]',
      '[class*="profile"]', '[class*="account"]', 'nav', '.navbar'
    ];

    let hasPostLoginElements = false;
    for (const selector of postLoginSelectors) {
      try {
        const elem = await page.$(selector);
        if (elem) {
          hasPostLoginElements = true;
          break;
        }
      } catch {
        // Continue
      }
    }

    // Determine authentication success
    let authenticated = false;
    let evidence = [];

    if (hasErrorMessages) {
      evidence.push('Error message detected on page');
    }

    if (urlChanged) {
      evidence.push('URL changed after submission');
      authenticated = true;
    }

    if (hasSessionCookies) {
      evidence.push(`Session cookies received (${cookies.length} total)`);
      authenticated = true;
    }

    if (hasPostLoginElements) {
      evidence.push('Post-login UI elements detected');
      authenticated = true;
    }

    // If error messages but other evidence, still mark as failed
    if (hasErrorMessages) {
      authenticated = false;
    }

    // If no evidence at all, consider failed
    if (evidence.length === 0) {
      evidence.push('No clear authentication indicators');
      authenticated = false;
    }

    await browser.close();

    return {
      success: true,
      authenticated,
      postLoginUrl,
      cookies,
      evidence: evidence.join('; '),
      errorCode: authenticated ? null : 'LOGIN_ANALYSIS_FAILED',
      errorMessage: authenticated ? null : 'Login appears to have failed based on page analysis'
    };
  } catch (error) {
    if (browser) {
      try {
        await browser.close();
      } catch {
        // Ignore close errors
      }
    }

    console.error('Login test error:', error);

    return {
      success: false,
      authenticated: false,
      errorCode: 'UNEXPECTED_ERROR',
      errorMessage: error.message || 'An unexpected error occurred during login test',
      postLoginUrl: null,
      cookies: [],
      evidence: `Exception: ${error.message}`
    };
  }
}

module.exports = {
  testLogin
};
