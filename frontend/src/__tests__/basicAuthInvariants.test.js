/**
 * HTTP Basic authentication option in AuthenticatedScanPanel — static invariants,
 * in the style of appInvariants.test.js:
 *  - every error code the backend can answer with resolves to translated text;
 *  - every new string exists in English AND has its own Japanese translation;
 *  - no customer-facing string names a scan engine (resale rule, CLAUDE.md);
 *  - Basic is never offered for schedules; the password leaves browser state once
 *    the server holds it; backend prose is never rendered.
 */

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(SRC, p), 'utf8');

const ownLocale = (file, name) => {
  const src = read(file)
    .replace(/^\s*import[^;]*;\s*$/gm, '')
    .replace(/export\s+const\s+(\w+)\s*=/, 'const $1 =')
    .replace(/\.\.\.en,?/, '');
  // eslint-disable-next-line no-new-func
  return new Function(`${src}\nreturn ${name};`)();
};
const en = ownLocale('locales/en.js', 'en');
const ja = ownLocale('locales/ja.js', 'ja');

const panel = read('components/AuthenticatedScanPanel.jsx');
const apiErrors = read('utils/apiErrors.js');
const codeKeys = Object.fromEntries(
  [...apiErrors.slice(apiErrors.indexOf('const CODE_KEYS')).matchAll(/([A-Z_]+):\s*'([A-Za-z0-9_]+)'/g)].map((m) => [m[1], m[2]])
);
const probeSrc = fs.readFileSync(path.join(SRC, '../../backend/services/basicAuthProbe.js'), 'utf8');
const backendCodes = [...probeSrc.slice(probeSrc.indexOf('const CODES'), probeSrc.indexOf('});', probeSrc.indexOf('const CODES')))
  .matchAll(/'([A-Z_]+)'/g)].map((m) => m[1]);

describe('HTTP Basic authentication option', () => {
  it('maps every probe/route error code to a key translated in both locales', () => {
    const notErrors = ['BASIC_CONFIRMED', 'BASIC_REALM_MISMATCH']; // success and a warning
    const routeCodes = ['BASIC_ORIGIN_MISMATCH', 'BASIC_AUTH_MANUAL_ONLY', 'BASIC_VERIFY_FAILED', 'URL_HAS_CREDENTIALS'];
    const missing = [];
    for (const code of [...backendCodes.filter((c) => !notErrors.includes(c)), ...routeCodes]) {
      const key = codeKeys[code];
      if (!key || !(key in en) || !(key in ja)) missing.push(`${code} -> ${key}`);
    }
    expect(backendCodes.length).toBeGreaterThan(10);
    expect(missing).toEqual([]);
  });

  it('every t() key the Basic UI uses has its own English and Japanese text', () => {
    const used = [...panel.matchAll(/t\('((?:basic|authMethod|verify)[A-Za-z]+)'\)/g)].map((m) => m[1]);
    expect(used.length).toBeGreaterThan(10);
    const missing = [...new Set(used)].filter((k) => !en[k] || !ja[k] || ja[k] === en[k]);
    expect(missing).toEqual([]);
  });

  it('names no scan engine in any new customer-facing string', () => {
    const banned = /ZAP|OWASP|WebCheck|urlscan|Observatory|PageSpeed|Lighthouse|Gemini|Mozilla|Puppeteer|Chrom(e|ium)/i;
    const keys = Object.keys(en).filter((k) => /^(basic|authMethod|verifyCredentials|verifyingCredentials|errUrlHasCredentials)/.test(k));
    const offenders = keys.filter((k) => banned.test(en[k]) || banned.test(ja[k] || ''));
    expect(keys.length).toBeGreaterThan(20);
    expect(offenders).toEqual([]);
  });

  it('is never offered while setting up a schedule', () => {
    expect(panel).toMatch(/disabled=\{!!pendingSchedule\}/);
    expect(panel).toMatch(/pendingSchedule \? t\('basicScheduleUnavailable'\)/);
    // The schedule payload is built only from the form-login fields.
    const submitSchedule = panel.slice(panel.indexOf('const submitSchedule'), panel.indexOf('const handleStartScan'));
    expect(submitSchedule).not.toMatch(/basicPassword|basicUsername/);
  });

  it('drops the password from browser state once the server holds it, and sends it nowhere else', () => {
    const handler = panel.slice(panel.indexOf('const handleTestBasic'), panel.indexOf('// ========== Step 1: Detect Login Fields'));
    expect(handler).toMatch(/\/api\/zap-auth\/test-basic/);
    expect(handler).toMatch(/setBasicPassword\(''\)/);
    expect(panel.match(/password: basicPassword/g)).toHaveLength(1);
    expect(panel).not.toMatch(/localStorage\.setItem\([^)]*basic/i);
    expect(panel).not.toMatch(/sessionStorage\.setItem\([^)]*basic/i);
  });

  it('renders only translated text for Basic outcomes, never backend prose', () => {
    const handler = panel.slice(panel.indexOf('const handleTestBasic'), panel.indexOf('// ========== Step 1: Detect Login Fields'));
    expect(handler).toMatch(/getApiErrorLabel\(t, \{ code: data\.errorCode \|\| data\.code \}, 'basicErrGeneric'\)/);
    expect(handler).not.toMatch(/data\.(message|error)\b/);
  });

  it('leaves the login-form flow intact', () => {
    expect(panel).toMatch(/useState\('form'\)/);
    expect(panel).toMatch(/onClick=\{handleDetectFields\}/);
    expect(panel).toMatch(/\/api\/zap-auth\/test-login/);
    expect(panel).toMatch(/: \{ targetUrl, loginUrl, tempSessionId \}/);
  });
});
