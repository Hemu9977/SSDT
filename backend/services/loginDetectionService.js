/**
 * Login Detection Service
 * Uses Puppeteer to detect login form fields on a given URL.
 * Handles both traditional HTML forms and SPA-rendered forms.
 */

const puppeteer = require('puppeteer');
const { revealLoginPanel } = require('../utils/revealLoginPanel');
const { rankSubmitButtons, autoRetryCandidates } = require('../utils/loginFormRanking');

// Field name/id patterns for classification
const USERNAME_PATTERNS = /user|email|login|account|name|identifier|uid|uname/i;
const PASSWORD_PATTERNS = /pass|pwd|secret|credential/i;
const SUBMIT_PATTERNS = /login|sign.?in|log.?in|submit|enter|auth|continue/i;
const CAPTCHA_PATTERNS = /captcha|recaptcha|hcaptcha|turnstile/i;
const OAUTH_PATTERNS = /google|facebook|github|twitter|apple|microsoft|oauth|openid|sso|social/i;

/**
 * Classify an input field based on its attributes
 * @param {Object} field - Field attributes from page evaluation
 * @returns {string} - 'username' | 'password' | 'email' | 'submit' | 'other'
 */
function classifyField(field) {
  const { inputType, name, id, placeholder, ariaLabel, autocomplete } = field;

  // Password fields are easy to identify
  if (inputType === 'password') return 'password';

  // Submit buttons
  if (inputType === 'submit' || field.tagName === 'BUTTON') return 'submit';

  // Check autocomplete attribute first (most reliable)
  if (autocomplete) {
    if (/username|email/i.test(autocomplete)) return 'username';
    if (/password|current-password|new-password/i.test(autocomplete)) return 'password';
  }

  // Email type inputs
  if (inputType === 'email') return 'username';

  // Check name, id, placeholder, aria-label for username patterns
  const combinedText = [name, id, placeholder, ariaLabel].filter(Boolean).join(' ');
  if (USERNAME_PATTERNS.test(combinedText)) return 'username';
  if (PASSWORD_PATTERNS.test(combinedText)) return 'password';

  // Text inputs near password fields are likely usernames (handled by caller)
  if (inputType === 'text' || inputType === 'tel') return 'other';

  return 'other';
}

/**
 * Detect login form fields on a given URL using Puppeteer
 * @param {string} loginUrl - The URL to scan for login forms
 * @returns {Promise<Object>} Detection result with fields, warnings, and metadata
 */
async function detectLoginFields(loginUrl) {
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
        '--disable-background-networking',
        '--no-first-run'
      ],
      timeout: 30000
    });

    const page = await browser.newPage();

    // Set a realistic viewport and user agent
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );

    // Navigate to the login page
    await page.goto(loginUrl, {
      waitUntil: 'networkidle2',
      timeout: 30000
    });

    // Wait a bit for any dynamic content to render
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Some sites have no login page at all — the form is behind a header
    // dropdown or a "Get Started" call to action, and the URL never changes.
    // Detection used to give up here, before the login test (which did know how
    // to open such panels) ever got a chance to run.
    const reveal = await revealLoginPanel(page);
    if (reveal.clicked) {
      console.log(`[LoginDetection] Opened a hidden login panel via ${reveal.clicked}`);
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    // Get page title
    const pageTitle = await page.title();

    // Detect CAPTCHA
    const hasCaptcha = await page.evaluate(() => {
      const html = document.documentElement.innerHTML.toLowerCase();
      const hasCaptchaIframe = !!document.querySelector('iframe[src*="recaptcha"], iframe[src*="hcaptcha"], iframe[src*="turnstile"]');
      const hasCaptchaDiv = !!document.querySelector('.g-recaptcha, .h-captcha, [data-sitekey], .cf-turnstile');
      const hasCaptchaText = /captcha/i.test(html);
      return hasCaptchaIframe || hasCaptchaDiv || hasCaptchaText;
    });

    // Detect OAuth buttons
    const hasOAuth = await page.evaluate(() => {
      const buttons = document.querySelectorAll('button, a, [role="button"]');
      const oauthPatterns = /google|facebook|github|twitter|apple|microsoft|oauth|openid|sso|sign.?in.?with/i;
      for (const btn of buttons) {
        const text = (btn.textContent || '').trim();
        const className = btn.className || '';
        const href = btn.href || '';
        if (oauthPatterns.test(text) || oauthPatterns.test(className) || oauthPatterns.test(href)) {
          return true;
        }
      }
      return false;
    });

    // Extract all forms and their fields
    const formsData = await page.evaluate(() => {
      const forms = document.querySelectorAll('form');
      const results = [];

      const extractFieldData = (input, formIndex) => {
        const tagName = input.tagName.toUpperCase();
        const inputType = (input.type || 'text').toLowerCase();

        // Skip hidden, file, and irrelevant inputs
        if (inputType === 'hidden' || inputType === 'file' || inputType === 'image') return null;
        if (tagName === 'INPUT' && inputType === 'checkbox' && !/remember|keep/i.test(input.name + input.id)) return null;
        if (tagName === 'INPUT' && inputType === 'radio') return null;

        // Get associated label
        let label = '';
        if (input.id) {
          const labelEl = document.querySelector(`label[for="${input.id}"]`);
          if (labelEl) label = labelEl.textContent.trim();
        }
        if (!label && input.closest('label')) {
          label = input.closest('label').textContent.trim();
        }
        if (!label) label = input.getAttribute('aria-label') || '';

        // Build CSS selector
        let selector = '';
        if (input.id) {
          selector = `#${CSS.escape(input.id)}`;
        } else if (input.name) {
          selector = `${tagName.toLowerCase()}[name="${CSS.escape(input.name)}"]`;
        } else {
          // Use nth-child as fallback
          const parent = input.parentElement;
          if (parent) {
            const siblings = Array.from(parent.children);
            const index = siblings.indexOf(input);
            selector = `${tagName.toLowerCase()}:nth-child(${index + 1})`;
          }
        }

        return {
          tagName,
          inputType,
          name: input.name || '',
          id: input.id || '',
          placeholder: input.placeholder || '',
          selector,
          label,
          required: input.required || false,
          ariaLabel: input.getAttribute('aria-label') || '',
          autocomplete: input.getAttribute('autocomplete') || '',
          // Carried out of the page so button ranking can run in Node, where it
          // is testable without a browser.
          className: typeof input.className === 'string' ? input.className : '',
          buttonText: tagName === 'BUTTON' ? (input.textContent || '').replace(/\s+/g, ' ').trim() : '',
          // Whether this field belongs to the login box itself. Fields inside a
          // real <form> always do; the no-form branch overrides this. Only
          // affects what is pre-selected, never what is offered.
          inLoginScope: true,
          formIndex
        };
      };

      // Process actual <form> elements
      forms.forEach((form, formIndex) => {
        const inputs = form.querySelectorAll('input');
        const fields = [];

        inputs.forEach(input => {
          const data = extractFieldData(input, formIndex);
          if (data) fields.push(data);
        });

        // Look for submit buttons - only those clearly related to form submission
        const buttons = form.querySelectorAll('button');
        buttons.forEach(btn => {
          const text = (btn.textContent || '').trim().toLowerCase();
          const btnId = (btn.id || '').toLowerCase();
          const btnClass = (btn.className || '').toLowerCase();
          const btnType = btn.type || '';

          // Exclude navigation/toggle buttons
          const isNavigationButton = /toggle|menu|nav|hamburger|close|cancel|back/i.test(text) ||
            /toggle|menu|nav|hamburger/i.test(btnId) ||
            /toggle|menu|nav|hamburger/i.test(btnClass);

          if (isNavigationButton) return; // Skip this button

          // Include if it's a submit button OR has submit-like text
          const isSubmitButton = btnType === 'submit' ||
            /login|sign.?in|log.?in|submit|enter|continue|go/i.test(text);

          if (isSubmitButton) {
            const existing = fields.find(f => f.tagName === 'BUTTON' && f.selector === (btn.id ? `#${CSS.escape(btn.id)}` : ''));
            if (!existing) {
              fields.push({
                tagName: 'BUTTON',
                inputType: 'submit',
                name: btn.name || '',
                id: btn.id || '',
                placeholder: '',
                selector: btn.id ? `#${CSS.escape(btn.id)}` : `form:nth-of-type(${formIndex + 1}) button`,
                label: btn.textContent.trim(),
                required: false,
                ariaLabel: btn.getAttribute('aria-label') || '',
                autocomplete: '',
                className: typeof btn.className === 'string' ? btn.className : '',
                formIndex,
                buttonText: btn.textContent.trim()
              });
            }
          }
        });

        if (fields.length > 0) {
          results.push({
            formAction: form.action || '',
            method: (form.method || 'GET').toUpperCase(),
            formIndex,
            fields
          });
        }
      });

      // If no forms found, look for standalone inputs (SPA pattern)
      if (results.length === 0) {
        // Work out which container holds the login box, but do NOT narrow the
        // collection to it. Every input and button on the page is still
        // returned, because the manual override in the UI is the escape hatch
        // when our guess is wrong — dropping candidates here would leave a
        // customer with no way to correct us. The container is only used to
        // decide what gets *pre-selected*.
        const password = document.querySelector('input[type="password"]');
        let scope = null;
        if (password) {
          let node = password.parentElement;
          while (node && node !== document.body) {
            const inputCount = node.querySelectorAll('input:not([type="hidden"])').length;
            const buttonCount = node.querySelectorAll('button').length;
            if (inputCount >= 2 && buttonCount >= 1) break;
            node = node.parentElement;
          }
          scope = node && node !== document.body ? node : null;
        }

        const allInputs = document.querySelectorAll('input:not([type="hidden"]), button');
        const standaloneFields = [];

        allInputs.forEach(input => {
          if (input.closest('form')) return; // Skip inputs already in forms
          const data = extractFieldData(input, -1);
          if (data) {
            // Drives auto-selection only. A field outside the login box (a
            // header search box, a newsletter signup) is still listed and can
            // be ticked by hand; it just is not treated as a credential the
            // customer must fill in before they can continue.
            data.inLoginScope = scope ? scope.contains(input) : true;
            standaloneFields.push(data);
          }
        });

        if (standaloneFields.length > 0) {
          results.push({
            formAction: window.location.href,
            method: 'POST',
            formIndex: -1,
            fields: standaloneFields
          });
        }
      }

      return results;
    });

    // Classify fields and identify best-guess username/password/submit for each form
    const forms = formsData.map(form => {
      const classifiedFields = form.fields.map(field => ({
        ...field,
        classification: classifyField(field)
      }));

      // Find best-guess fields
      let usernameField = classifiedFields.find(f => f.classification === 'username') || null;
      let passwordField = classifiedFields.find(f => f.classification === 'password') || null;

      // Rank rather than take the first in document order. On a page with no
      // <form> element the fallback collects the whole document, so the first
      // button is a header control — the sidebar toggle, the language picker,
      // the account menu — and never the login button. Ranking scores proximity
      // to the password field and drops navigation controls, with document
      // order as the tie-break so pages that already resolved correctly are
      // unaffected.
      const rankedButtons = rankSubmitButtons(classifiedFields);
      const submitButton = rankedButtons[0] || null;

      // If no username field found but there's a text/tel input before the password, assume it's username
      if (!usernameField && passwordField) {
        const passwordIndex = classifiedFields.indexOf(passwordField);
        const textFields = classifiedFields
          .filter((f, i) => i < passwordIndex && (f.inputType === 'text' || f.inputType === 'tel' || f.inputType === 'email'))
          .reverse(); // Get the closest one before password
        if (textFields.length > 0) {
          usernameField = textFields[0];
          usernameField.classification = 'username';
        }
      }

      return {
        formAction: form.formAction,
        method: form.method,
        fields: classifiedFields,
        usernameField,
        passwordField,
        submitButton,
        // Runners-up the login test may click automatically if the first choice
        // turns out not to submit anything. Third-party sign-in buttons are
        // excluded here — clicking one would navigate off the site — but they
        // stay in `fields`, so the manual override still offers them.
        submitAlternates: autoRetryCandidates(rankedButtons)
      };
    });

    // Build warnings
    const warnings = [];
    if (hasCaptcha) {
      warnings.push('CAPTCHA detected on login page. Automated login may not work.');
    }
    if (hasOAuth) {
      warnings.push('OAuth/SSO buttons detected. Only form-based login is supported.');
    }
    if (forms.length === 0) {
      warnings.push('No login forms detected on this page.');
    } else {
      const hasAnyUsername = forms.some(f => f.usernameField);
      const hasAnyPassword = forms.some(f => f.passwordField);
      if (!hasAnyUsername) {
        warnings.push('Could not identify a username/email field. You may need to select it manually.');
      }
      if (!hasAnyPassword) {
        warnings.push('Could not identify a password field. This may not be a login page.');
      }
    }

    return {
      success: true,
      loginUrl,
      pageTitle,
      forms,
      hasCaptcha,
      hasOAuth,
      warnings
    };
  } catch (error) {
    const message = error.message || 'Unknown error';

    if (message.includes('ERR_NAME_NOT_RESOLVED') || message.includes('ERR_CONNECTION_REFUSED')) {
      return { success: false, error: 'Could not reach the URL. Please check the address.', loginUrl };
    }
    if (message.includes('Timeout') || message.includes('timeout')) {
      return { success: false, error: 'Page took too long to load. Please try again.', loginUrl };
    }
    if (message.includes('ERR_CERT') || message.includes('SSL')) {
      return { success: false, error: 'SSL/certificate error when accessing the page.', loginUrl };
    }

    return { success: false, error: `Failed to analyze login page: ${message}`, loginUrl };
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch (_) {
        // Ignore close errors
      }
    }
  }
}

module.exports = { detectLoginFields };
