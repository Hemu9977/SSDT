'use strict';

/**
 * WebCheck's page-level site checks — `firewall` (WAF detection), `hsts` and
 * `tech-stack` — computed from a page load we already made, in the shapes the
 * WebCheck container returns (new/scripts/firewall.js, hsts.js, tech-stack.js), so
 * every reader (report PDF, AI prompt, summary, details panel) is unchanged.
 *
 * Why: for an HTTP Basic scan the container fetches the page without the
 * credential and gets 401 (`ERR_INVALID_AUTH_CREDENTIALS`), so these report rows
 * were N/A. The in-house page capture loads the page signed in — the credential
 * answered for the target origin only (scopedBasicAuth) — so the same rules run on
 * the signed-in response instead. No extra request reaches the customer's site and
 * the credential goes nowhere new.
 *
 * Also: `normalizeHsts`. The container's hsts check returns { message, compatible,
 * hstsHeader } and never `enabled`, while every reader asked for `hsts.enabled` —
 * so every report said "HSTS: No", including for sites that send the header.
 */

// ── firewall (port of new/scripts/firewall.js) ─────────────────────────────────

const has = (h, name) => h[name] !== undefined && h[name] !== null && h[name] !== '';
const includes = (h, name, needle) => typeof h[name] === 'string' && h[name].includes(needle);

/**
 * @param {Record<string, string|string[]>} rawHeaders - response headers (any case)
 * @returns {{hasWaf: boolean, waf?: string}}
 */
function detectWaf(rawHeaders) {
  const h = lowerHeaders(rawHeaders);
  const waf = (name) => ({ hasWaf: true, waf: name });
  if (includes(h, 'server', 'cloudflare')) return waf('Cloudflare');
  if (includes(h, 'x-powered-by', 'AWS Lambda')) return waf('AWS WAF');
  if (includes(h, 'server', 'AkamaiGHost')) return waf('Akamai');
  if (includes(h, 'server', 'Sucuri')) return waf('Sucuri');
  if (includes(h, 'server', 'BarracudaWAF')) return waf('Barracuda WAF');
  if (includes(h, 'server', 'F5 BIG-IP') || includes(h, 'server', 'BIG-IP')) return waf('F5 BIG-IP');
  if (has(h, 'x-sucuri-id') || has(h, 'x-sucuri-cache')) return waf('Sucuri CloudProxy WAF');
  if (includes(h, 'server', 'FortiWeb')) return waf('Fortinet FortiWeb WAF');
  if (includes(h, 'server', 'Imperva')) return waf('Imperva SecureSphere WAF');
  if (includes(h, 'x-protected-by', 'Sqreen')) return waf('Sqreen');
  if (has(h, 'x-waf-event-info')) return waf('Reblaze WAF');
  if (includes(h, 'set-cookie', '_citrix_ns_id')) return waf('Citrix NetScaler');
  if (has(h, 'x-denied-reason') || has(h, 'x-wzws-requested-method')) return waf('WangZhanBao WAF');
  if (has(h, 'x-webcoment')) return waf('Webcoment Firewall');
  if (includes(h, 'server', 'Yundun')) return waf('Yundun WAF');
  if (has(h, 'x-yd-waf-info') || has(h, 'x-yd-info')) return waf('Yundun WAF');
  if (includes(h, 'server', 'Safe3WAF')) return waf('Safe3 Web Application Firewall');
  if (includes(h, 'server', 'NAXSI')) return waf('NAXSI WAF');
  if (has(h, 'x-datapower-transactionid')) return waf('IBM WebSphere DataPower');
  if (includes(h, 'server', 'QRATOR')) return waf('QRATOR WAF');
  if (includes(h, 'server', 'ddos-guard')) return waf('DDoS-Guard WAF');
  return { hasWaf: false };
}

// ── hsts (port of new/scripts/hsts.js, plus the fields readers expect) ─────────

const NO_HSTS_MESSAGE = 'Site does not serve any HSTS headers.';

/**
 * @param {Record<string, string|string[]>} rawHeaders
 * @returns {{message: string, compatible: boolean, hstsHeader: string|null, enabled: boolean, maxAge: number|null}}
 */
function hstsResult(rawHeaders) {
  const header = lowerHeaders(rawHeaders)['strict-transport-security'];
  if (!header) return { message: NO_HSTS_MESSAGE, compatible: false, hstsHeader: null, enabled: false, maxAge: null };
  const m = header.match(/max-age=(\d+)/);
  const maxAge = m ? Number(m[1]) : null;
  // Same verdicts, in the same order, as the container. Like the container,
  // `hstsHeader` is set only when the site qualifies for the preload list.
  const base = { compatible: false, hstsHeader: null, enabled: true, maxAge };
  if (!m || maxAge < 10886400) return { ...base, message: 'HSTS max-age is less than 10886400.' };
  if (!header.includes('includeSubDomains')) return { ...base, message: 'HSTS header does not include all subdomains.' };
  if (!header.includes('preload')) return { ...base, message: 'HSTS header does not contain the preload directive.' };
  return { ...base, message: 'Site is compatible with the HSTS preload list!', compatible: true, hstsHeader: header };
}

/**
 * Whether a stored hsts result says the site sends HSTS — for results written
 * before `enabled` was recorded (the container never set it).
 */
function isHstsEnabled(hsts) {
  if (!hsts || hsts.error) return false;
  if (typeof hsts.enabled === 'boolean') return hsts.enabled || !!hsts.preloaded;
  if (hsts.preloaded) return true;
  // Container shape: every message except "does not serve any" means the header was sent.
  return typeof hsts.message === 'string' && hsts.message !== NO_HSTS_MESSAGE;
}

/** Add `enabled` (and keep everything else) to the container's hsts result. */
function normalizeHsts(data) {
  if (!data || typeof data !== 'object' || data.error || typeof data.enabled === 'boolean') return data;
  return { ...data, enabled: isHstsEnabled(data) };
}

// ── tech-stack (port of new/scripts/tech-stack.js) ─────────────────────────────

const TECH_PATTERNS = {
  'React': { scripts: ['/react', 'react.js', 'react.min.js'], globals: ['React', 'ReactDOM'] },
  'Vue.js': { scripts: ['/vue', 'vue.js', 'vue.min.js'], globals: ['Vue'] },
  'Angular': { scripts: ['angular', 'ng-'], globals: ['angular', 'ng'] },
  'jQuery': { scripts: ['jquery'], globals: ['jQuery', '$'] },
  'Next.js': { scripts: ['_next'], meta: { generator: 'Next.js' } },
  'Nuxt.js': { scripts: ['_nuxt'], globals: ['$nuxt'] },
  'Svelte': { scripts: ['svelte'] },
  'WordPress': { meta: { generator: 'WordPress' }, paths: ['/wp-content/', '/wp-includes/'] },
  'Drupal': { meta: { generator: 'Drupal' }, paths: ['/sites/default/', '/modules/'] },
  'Joomla': { meta: { generator: 'Joomla' } },
  'Shopify': { globals: ['Shopify'], headers: { 'x-shopify-stage': true } },
  'Wix': { scripts: ['wix.com'], meta: { generator: 'Wix' } },
  'Squarespace': { scripts: ['squarespace'] },
  'Google Analytics': { scripts: ['google-analytics.com', 'googletagmanager.com', 'gtag'] },
  'Google Tag Manager': { scripts: ['googletagmanager.com/gtm.js'] },
  'Facebook Pixel': { scripts: ['connect.facebook.net'] },
  'Hotjar': { scripts: ['hotjar.com'] },
  'Cloudflare': { headers: { 'cf-ray': true, 'server': 'cloudflare' } },
  'AWS': { headers: { 'x-amz-cf-id': true, 'server': 'AmazonS3' } },
  'Vercel': { headers: { 'x-vercel-id': true, 'server': 'Vercel' } },
  'Netlify': { headers: { 'x-nf-request-id': true, 'server': 'Netlify' } },
  'Nginx': { headers: { 'server': 'nginx' } },
  'Apache': { headers: { 'server': 'Apache' } },
  'IIS': { headers: { 'server': 'Microsoft-IIS' } },
  'Bootstrap': { scripts: ['bootstrap'], classes: ['container', 'row', 'col-'] },
  'Tailwind CSS': { classes: ['flex', 'grid', 'px-', 'py-', 'text-'] },
  'Material-UI': { scripts: ['@material-ui', '@mui'] },
  'reCAPTCHA': { scripts: ['recaptcha', 'grecaptcha'] },
  'hCaptcha': { scripts: ['hcaptcha'] },
};

const TECH_CATEGORIES = {
  'React': 'JavaScript framework', 'Vue.js': 'JavaScript framework', 'Angular': 'JavaScript framework',
  'jQuery': 'JavaScript library', 'Next.js': 'JavaScript framework', 'Nuxt.js': 'JavaScript framework',
  'Svelte': 'JavaScript framework', 'WordPress': 'CMS', 'Drupal': 'CMS', 'Joomla': 'CMS',
  'Shopify': 'E-commerce', 'Wix': 'Website builder', 'Squarespace': 'Website builder',
  'Google Analytics': 'Analytics', 'Google Tag Manager': 'Tag manager', 'Facebook Pixel': 'Analytics',
  'Hotjar': 'Analytics', 'Cloudflare': 'CDN', 'AWS': 'Cloud hosting', 'Vercel': 'PaaS', 'Netlify': 'PaaS',
  'Nginx': 'Web server', 'Apache': 'Web server', 'IIS': 'Web server', 'Bootstrap': 'CSS framework',
  'Tailwind CSS': 'CSS framework', 'Material-UI': 'UI framework', 'reCAPTCHA': 'Security', 'hCaptcha': 'Security',
};

/**
 * Runs in the page (page.evaluate). Exactly what the container collects.
 * Kept free of closures so it serializes.
 */
function collectPageData() {
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
  const inlineScripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join(' ');
  const metas = {};
  document.querySelectorAll('meta[name], meta[property]').forEach(m => {
    const key = m.getAttribute('name') || m.getAttribute('property');
    metas[key] = m.getAttribute('content');
  });
  const html = document.documentElement.outerHTML;
  const globals = Object.keys(window).slice(0, 100);
  return { scripts, inlineScripts, metas, html, globals };
}

/**
 * @param {{scripts:string[], inlineScripts:string, metas:object, html:string, globals:string[]}} pageData
 * @param {Record<string, string|string[]>} rawHeaders - the document's response headers
 * @param {string} url
 * @returns {{url: string, technologies: Array<{name:string, confidence:number, categories:string[]}>} | {error: string}}
 */
function detectTechStack(pageData, rawHeaders, url) {
  const headers = lowerHeaders(rawHeaders);
  const detected = [];
  for (const [name, p] of Object.entries(TECH_PATTERNS)) {
    let hit = false;
    let confidence = 0;
    if (p.scripts && pageData.scripts.some(s => p.scripts.some(x => s.toLowerCase().includes(x.toLowerCase())))) {
      hit = true; confidence += 30;
    }
    if (p.scripts && pageData.inlineScripts && p.scripts.some(x => pageData.inlineScripts.toLowerCase().includes(x.toLowerCase()))) {
      hit = true; confidence += 20;
    }
    if (p.meta) {
      for (const [k, v] of Object.entries(p.meta)) {
        if (String(pageData.metas[k] || '').toLowerCase().includes(v.toLowerCase())) { hit = true; confidence += 40; }
      }
    }
    if (p.globals && p.globals.some(g => pageData.globals.includes(g))) { hit = true; confidence += 30; }
    if (p.headers) {
      for (const [k, v] of Object.entries(p.headers)) {
        const actual = headers[k.toLowerCase()];
        if (actual && (v === true || actual.toLowerCase().includes(v.toLowerCase()))) { hit = true; confidence += 40; }
      }
    }
    if (p.paths && p.paths.some(x => pageData.html.includes(x))) { hit = true; confidence += 25; }
    if (hit) detected.push({ name, confidence: Math.min(confidence, 100) });
  }
  detected.sort((a, b) => b.confidence - a.confidence);
  // The container reports "nothing found" as an error; keep that, so "N/A" means the same.
  if (!detected.length) return { error: 'Unable to find any technologies for site' };
  return {
    url,
    technologies: detected.map(t => ({ name: t.name, confidence: t.confidence, categories: [TECH_CATEGORIES[t.name] || 'Other'] })),
  };
}

// ── helpers ────────────────────────────────────────────────────────────────────

/** Lower-case header names; multi-value headers joined like Chromium does. */
function lowerHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw || {})) out[k.toLowerCase()] = Array.isArray(v) ? v.join('\n') : v;
  return out;
}

/**
 * All three checks from one signed-in page load. Results carry the same
 * provenance markers as the other in-house checks (never shown to customers).
 */
function siteChecksFromPage({ headers, pageData, url }) {
  const mark = (r) => (r && typeof r === 'object' ? { ...r, diagnosticSource: 'in-house', fallbackReason: 'basic_auth' } : r);
  return {
    firewall: mark(detectWaf(headers)),
    hsts: mark(hstsResult(headers)),
    'tech-stack': mark(detectTechStack(pageData, headers, url)),
  };
}

module.exports = {
  detectWaf,
  hstsResult,
  isHstsEnabled,
  normalizeHsts,
  detectTechStack,
  collectPageData,
  siteChecksFromPage,
  SITE_CHECKS: ['firewall', 'hsts', 'tech-stack'],
};
