/**
 * Static invariants for routing, the admin guard, and i18n.
 *
 * These began as throwaway scripts in a scratch directory during the
 * admin-dashboard review; that directory was wiped mid-task and took every
 * assertion with it. They live here now so they actually guard the codebase,
 * and so `npm test` has something to run — until this file existed, CRA's
 * runner found zero test files, which some CI configurations treat as failure.
 *
 * Deliberately static: they read source files rather than mounting components,
 * so they need no DOM setup, no mocking, and no running backend.
 */

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(SRC, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(SRC, p));

const app = read('App.js');
const header = read('components/header.jsx');

// Load a locale module without a bundler. `ja.js` spreads `...en`, so a key
// absent from ja legitimately falls back to en — resolve against the spread.
const loadLocale = (file, name, base) => {
  let src = read(file)
    .replace(/^\s*import[^;]*;\s*$/gm, '')
    .replace(/export\s+const\s+(\w+)\s*=/, 'const $1 =');
  if (base) src = src.replace(/\.\.\.en,?/, '');
  // eslint-disable-next-line no-new-func
  const own = new Function(`${src}\nreturn ${name};`)();
  return base ? Object.assign({}, base, own) : own;
};
const en = loadLocale('locales/en.js', 'en', null);
const ja = loadLocale('locales/ja.js', 'ja', en);

const walk = (dir, out = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else if (/\.(jsx?|js)$/.test(entry.name) && !p.includes('__tests__')) out.push(p);
  }
  return out;
};
const sourceFiles = walk(SRC);

// ─────────────────────────────────────────────────────────────────────────────
// Admin route guard
// ─────────────────────────────────────────────────────────────────────────────

describe('RequireAdmin', () => {
  const guardSrc = read('components/RequireAdmin.jsx');
  const stripComments = (s) =>
    s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  // eslint-disable-next-line no-new-func
  const { isSystemAdmin, postLoginTarget } = new Function(
    `${read('utils/authRedirect.js').replace(/export const/g, 'const')}
     return { isSystemAdmin, postLoginTarget };`
  )();

  const decide = ({ loading, user }) => {
    if (loading) return 'render:loading';
    if (!user) return 'redirect:/login';
    if (!isSystemAdmin(user)) return 'redirect:/profile';
    return 'render:admin';
  };

  it('decides during render, not in an effect', () => {
    // Redirecting from an effect let one frame of the admin shell mount and
    // fire admin API calls that could only come back 403.
    expect(stripComments(guardSrc)).not.toMatch(/useEffect/);
    expect(guardSrc).toMatch(/<Navigate to="\/login" replace \/>/);
    expect(guardSrc).toMatch(/<Navigate to="\/profile" replace \/>/);
  });

  it.each([
    [{ loading: true, user: null }, 'render:loading'],
    [{ loading: false, user: null }, 'redirect:/login'],
    [{ loading: false, user: { systemRole: 'user' } }, 'redirect:/profile'],
    [{ loading: false, user: {} }, 'redirect:/profile'],
    [{ loading: false, user: { systemRole: 'admin' } }, 'render:admin'],
    [{ loading: false, user: { systemRole: 'superadmin' } }, 'render:admin'],
  ])('%j -> %s', (state, expected) => {
    expect(decide(state)).toBe(expected);
  });

  it('sends admins to /admin and everyone else to /', () => {
    expect(postLoginTarget({ systemRole: 'admin' })).toBe('/admin');
    expect(postLoginTarget({ systemRole: 'superadmin' })).toBe('/admin');
    expect(postLoginTarget({ systemRole: 'user' })).toBe('/');
    expect(postLoginTarget(undefined)).toBe('/');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Post-login context refresh
// ─────────────────────────────────────────────────────────────────────────────

describe('post-login refresh', () => {
  // UserProvider fetches the profile once on mount and sits above
  // BrowserRouter, so navigate() never remounts it. Without an explicit
  // refresh a freshly-logged-in admin reached /admin with user still null and
  // was bounced straight back to /login.
  it.each([
    'pages/auth/LoginPage.jsx',
    'pages/auth/RegisterPage.jsx',
    'pages/auth/OTPVerification.jsx',
  ])('%s refreshes the user context before navigating', (file) => {
    const src = read(file);
    expect(src).toMatch(/const \{ refreshUser \} = useUser\(\);/);
    const firstRefresh = src.indexOf('await refreshUser()');
    expect(firstRefresh).toBeGreaterThan(-1);
    const firstNav = src.indexOf('setTimeout(() => navigate(target)');
    if (firstNav !== -1) expect(firstRefresh).toBeLessThan(firstNav);
    // Role checks must go through the shared helper, not an inlined list.
    expect(src).not.toMatch(/\['admin', 'superadmin'\]\.includes\(data\.user/);
  });

  it('UserContext treats a disabled OR revoked session as dead', () => {
    const ctx = read('contexts/UserContext.jsx');
    // Assert the two terminal codes are both covered rather than pinning the
    // exact expression, so widening the condition doesn't break the test.
    const cond = ctx.slice(ctx.indexOf('const sessionIsDead'), ctx.indexOf('if (sessionIsDead)'));
    expect(cond).toMatch(/res\.status === 401/);
    expect(cond).toMatch(/ACCOUNT_DISABLED/);
    expect(cond).toMatch(/SESSION_REVOKED/);
    const after = ctx.slice(ctx.indexOf('sessionIsDead'));
    expect(after).toMatch(/setUser\(null\)/);
    expect(after).toMatch(/removeItem\('user_data'\)/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Routing
// ─────────────────────────────────────────────────────────────────────────────

describe('routing', () => {
  it('wraps /admin in the guard', () => {
    const flat = app.replace(/\s+/g, ' ').replace(/> </g, '><');
    expect(flat).toMatch(/<RequireAdmin><AdminPanel \/><\/RequireAdmin>/);
  });

  it('keeps removed URLs resolving instead of rendering blank', () => {
    expect(app).toMatch(/<Route path="\/about" element=\{<Navigate to="\/" replace \/>\} \/>/);
    expect(app).toMatch(/<Route path="\*" element=\{<Navigate to="\/" replace \/>\} \/>/);
  });

  it('has no route or import for a deleted component', () => {
    expect(app).not.toMatch(/path="\/dashboard"/);
    expect(app).not.toMatch(/import (Dashboard|SplashScreen|About) /);
    expect(exists('components/sidebar.jsx')).toBe(false);
    expect(exists('components/SplashScreen.jsx')).toBe(false);
    expect(exists('pages/About.jsx')).toBe(false);
    // MarketingHome absorbed the About content and imports its stylesheet.
    expect(exists('styles/About.scss')).toBe(true);
  });

  it('every header link resolves to a declared route', () => {
    const routes = [...app.matchAll(/<Route\s+path="([^"]+)"/g)].map((m) => m[1]);
    const links = [...header.matchAll(/to="(\/[^"]*)"/g)].map((m) => m[1]);
    const dead = links.filter((l) => !routes.includes(l) && !routes.includes('*'));
    expect(dead).toEqual([]);
  });

  it('every relative import resolves to a real file', () => {
    const unresolved = [];
    for (const file of sourceFiles) {
      const src = fs.readFileSync(file, 'utf8');
      for (const m of src.matchAll(/from\s+['"](\.[^'"]+)['"]|import\s+['"](\.[^'"]+)['"]/g)) {
        const spec = m[1] || m[2];
        const base = path.resolve(path.dirname(file), spec);
        const candidates = [
          base, `${base}.js`, `${base}.jsx`, `${base}.json`, `${base}.scss`, `${base}.css`,
          path.join(base, 'index.js'), path.join(base, 'index.jsx'),
        ];
        if (!candidates.some((c) => fs.existsSync(c) && fs.statSync(c).isFile())) {
          unresolved.push(`${path.relative(SRC, file)} -> ${spec}`);
        }
      }
    }
    expect(unresolved).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// i18n
// ─────────────────────────────────────────────────────────────────────────────

describe('translations', () => {
  it('every t() key used anywhere resolves in both locales', () => {
    const missing = {};
    for (const file of sourceFiles) {
      const src = fs.readFileSync(file, 'utf8');
      for (const m of src.matchAll(/\bt\(\s*'([A-Za-z0-9_]+)'/g)) {
        const key = m[1];
        if (!(key in en) || !(key in ja)) {
          (missing[key] = missing[key] || []).push(path.relative(SRC, file));
        }
      }
    }
    expect(missing).toEqual({});
  });

  it('has no duplicate keys in either locale file', () => {
    for (const [name, file] of [['en', 'locales/en.js'], ['ja', 'locales/ja.js']]) {
      const keys = [...read(file).matchAll(/^\s{2}([A-Za-z0-9_]+):/gm)].map((m) => m[1]);
      const dupes = keys.filter((k, i) => keys.indexOf(k) !== i);
      expect({ [name]: [...new Set(dupes)] }).toEqual({ [name]: [] });
    }
  });

  it('the admin health panel resolves its service names through t()', () => {
    const health = read('pages/Admin/AdminSystemHealth.jsx');
    expect(health.match(/title: '[^']+'/g)).toBeNull();
    expect(health).toMatch(/title=\{t\(svc\.labelKey\)\}/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// API error codes
// ─────────────────────────────────────────────────────────────────────────────

describe('API error code mapping', () => {
  const apiErrors = read('utils/apiErrors.js');
  const codeKeys = Object.fromEntries(
    [...apiErrors.slice(apiErrors.indexOf('const CODE_KEYS'))
      .matchAll(/([A-Z_]+):\s*'([A-Za-z0-9_]+)'/g)].map((m) => [m[1], m[2]])
  );

  it('maps every code the mapper claims to handle to a key present in both locales', () => {
    const missing = [];
    for (const [code, key] of Object.entries(codeKeys)) {
      if (!(key in en) || !(key in ja)) missing.push(`${code} -> ${key}`);
    }
    expect(missing).toEqual([]);
  });

  it.each([
    'ALREADY_SUBSCRIBED', 'INSUFFICIENT_ROLE', 'ORG_CREATING',
    'PLAN_CHECK_ERROR', 'USER_NOT_FOUND', 'SESSION_REVOKED',
  ])('%s resolves to a specific message rather than a generic fallback', (code) => {
    // These previously fell through to t('checkoutFailed') / t('scanFailedGeneric').
    expect(codeKeys[code]).toBeDefined();
  });

  it('treats a revoked session as terminal, like a disabled account', () => {
    expect(apiErrors).toMatch(/SESSION_REVOKED/);
    expect(read('contexts/UserContext.jsx')).toMatch(/SESSION_REVOKED/);
  });

  it('routes checkout and scan-start failures through the shared mapper', () => {
    expect(read('pages/Profile.jsx')).toMatch(/getApiErrorLabel\(t, data, 'checkoutFailed'\)/);
    expect(read('components/Hero.jsx')).toMatch(/getApiErrorLabel\(t, errorData, 'scanFailedGeneric'\)/);
  });

  it('keeps the client password minimum aligned with the server', () => {
    // A 6-char client minimum against an 8-char server rule meant a password
    // could pass validation and then be rejected server-side.
    for (const f of ['pages/auth/ResetPasswordPage.jsx', 'pages/JoinOrganization.jsx']) {
      expect(read(f)).toMatch(/password\.length < 8/);
    }
    expect(en.passwordMinLength).toMatch(/8/);
    expect(ja.passwordMinLength).toMatch(/8/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Authenticated scan: sign-in verification
// ─────────────────────────────────────────────────────────────────────────────

describe('sign-in verification', () => {
  const panel = read('components/AuthenticatedScanPanel.jsx');
  const loginCodeKeys = Object.fromEntries(
    [...panel.slice(panel.indexOf('const LOGIN_ERROR_MESSAGE_KEYS'), panel.indexOf('};', panel.indexOf('const LOGIN_ERROR_MESSAGE_KEYS')))
      .matchAll(/([A-Z_]+):\s*'([A-Za-z0-9_]+)'/g)].map((m) => [m[1], m[2]])
  );

  it('maps every login error code to a key present in both locales', () => {
    const missing = [];
    for (const [code, key] of Object.entries(loginCodeKeys)) {
      if (!(key in en) || !(key in ja)) missing.push(`${code} -> ${key}`);
    }
    expect(missing).toEqual([]);
  });

  it.each(['SUBMIT_NO_EFFECT', 'AUTH_UNCONFIRMED', 'LOGIN_PANEL_NOT_FOUND'])(
    '%s resolves to a specific message rather than the generic fallback',
    (code) => {
      expect(loginCodeKeys[code]).toBeDefined();
    }
  );

  it('has a third outcome between success and failure', () => {
    // "Could not confirm" must be distinguishable from a green tick: the scan
    // may proceed, but coverage may be limited to publicly visible pages.
    expect(panel).toMatch(/authConfirmed === 'unconfirmed'/);
    expect(panel).toMatch(/test-caution/);
  });

  it('does not auto-advance past an unconfirmed sign-in', () => {
    // Advancing automatically would scroll the caution out of view unread.
    expect(panel).toMatch(/if \(data\.authConfirmed === 'confirmed'\) \{\s*setStep\(3\);/);
    expect(panel).toMatch(/t\('continueAnyway'\)/);
  });

  it('states the coverage of a finished scan from a structured field', () => {
    // Never derived in the browser from authScanResult, which carries English
    // operator strings that must not be rendered.
    expect(panel).toMatch(/report\?\.authCoverage/);
    for (const key of ['authCoverageConfirmed', 'authCoverageUnconfirmed']) {
      expect(en[key]).toBeDefined();
      expect(ja[key]).toBeDefined();
    }
  });

  it('always offers every detected button, not just the ranked ones', () => {
    // Automatic detection will sometimes pick the wrong button. The manual
    // override is the only way a customer can correct that, so the dropdown
    // must be built from the complete field list — never from the ranked
    // shortlist, and never from a list narrowed to the login box. Narrowing it
    // strands anyone whose page we guessed wrong about.
    expect(panel).toMatch(
      /detectedFields\.forms\[0\]\.fields\.filter\(f =>\s*f\.tagName === 'BUTTON' \|\| f\.inputType === 'submit'/
    );
  });

  it('pre-selects only login-box fields but still lists the rest', () => {
    // The checkbox list is rendered from the full `fields` array, while only
    // in-scope inputs are ticked by default. A field outside the login box is
    // therefore visible and addable, not silently dropped.
    expect(panel).toMatch(/f\.inLoginScope !== false/);
    expect(panel).toMatch(/scopedFields\.length > 0 \? scopedFields : inputFields/);
  });

  it('sends a schedule authConfig the model can actually store', () => {
    // The bug: the panel sent `submitButton` as the whole detected-field object
    // while ScheduledScan declares it `String` and schedulerService reads it as
    // one (`{ selector: authConfig.submitButton }`). Mongoose refuses to cast a
    // plain object to String, so scheduled authenticated scans could never
    // store a usable submit button — the feature was dead end to end.
    const MODEL = path.join(SRC, '..', '..', 'backend', 'models', 'ScheduledScan.js');
    if (!fs.existsSync(MODEL)) return; // Backend not checked out alongside.
    const model = fs.readFileSync(MODEL, 'utf8');

    const schema = model.slice(model.indexOf('authConfig: {'));
    const scalarStringPaths = [...schema.slice(0, schema.indexOf('createdAt'))
      .matchAll(/^\s{4}(\w+):\s*\{\s*type:\s*String/gm)].map((m) => m[1]);
    expect(scalarStringPaths).toContain('submitButton');

    const objStart = panel.indexOf('const authConfigObj = {');
    const authConfigObj = panel.slice(objStart, panel.indexOf('\n    };', objStart));
    expect(objStart).toBeGreaterThan(-1);

    // Every key sent must exist on the schema, or it is silently dropped.
    const sentKeys = [...authConfigObj.matchAll(/^\s{6}(\w+):/gm)].map((m) => m[1]);
    const declared = [...schema.slice(0, schema.indexOf('createdAt'))
      .matchAll(/^\s{4}(\w+):/gm)].map((m) => m[1]);
    expect(sentKeys.filter((k) => !declared.includes(k))).toEqual([]);

    // A path declared String must not be handed a whole object. Reading a
    // property off one (`?.selector`) is the shape that satisfies this.
    for (const key of scalarStringPaths) {
      const line = authConfigObj.split('\n').find((l) => new RegExp(`^\\s{6}${key}:`).test(l));
      if (!line) continue;
      const value = line.slice(line.indexOf(':') + 1).trim().replace(/,$/, '');
      const looksScalar =
        /^'.*'$/.test(value) || value.includes('.') || /^\w+$/.test(value);
      expect(looksScalar).toBe(true);
      // The specific regression: the bare detected-field object.
      expect(value).not.toBe('selectedSubmitButton');
    }
  });

  it('asks for the signed-in marker without naming any tooling', () => {
    // The product is resold; the customer must not learn how the check works.
    for (const key of ['signedInMarkerLabel', 'signedInMarkerHint', 'loginUnconfirmedExplain']) {
      for (const locale of [en, ja]) {
        expect(locale[key]).toBeDefined();
        expect(locale[key]).not.toMatch(/ZAP|Puppeteer|browser|Chrome|crawler|spider|WebCheck|urlscan|Gemini/i);
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Admin role management
// ─────────────────────────────────────────────────────────────────────────────

describe('granting and revoking admin', () => {
  const users = read('pages/Admin/AdminUsers.jsx');

  it('offers both directions, not just revoke', () => {
    // The strings existed but the grant action was never wired, so the only way
    // to create an admin was scripts/makeAdmin.js on the server — meaning an
    // accidental revoke needed shell access to undo.
    expect(users).toMatch(/case 'makeAdmin':/);
    expect(users).toMatch(/systemRole: 'admin'/);
    expect(users).toMatch(/case 'removeAdmin':/);
    expect(users).toMatch(/systemRole: 'user'/);
  });

  it('gates both controls on the caller being a superadmin', () => {
    // routes/admin.js refuses either change from a plain admin
    // (ADMIN_SUPERADMIN_REQUIRED), so showing the button would offer an action
    // guaranteed to fail.
    expect(users).toMatch(/const isSuperadmin = currentUser\?\.systemRole === 'superadmin';/);
    expect(users).toMatch(/isSuperadmin && u\.systemRole === 'user'/);
    expect(users).toMatch(/isSuperadmin && u\.systemRole === 'admin'/);
  });

  it('uses the confirmation strings that were previously dead', () => {
    for (const key of ['adminMakeAdmin', 'adminGrantAdminTitle', 'adminGrantAdminMessage']) {
      expect(users).toContain(key);
      expect(en[key]).toBeDefined();
      expect(ja[key]).toBeDefined();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CLAUDE.md: backend strings must never reach the UI
// ─────────────────────────────────────────────────────────────────────────────

describe('admin pages never render a backend-supplied string', () => {
  const adminDir = path.join(SRC, 'pages/Admin');
  const adminFiles = fs.readdirSync(adminDir).filter((f) => /\.(jsx|js)$/.test(f));

  it('renders no thrown Error message', () => {
    const leaks = [];
    for (const f of adminFiles) {
      fs.readFileSync(path.join(adminDir, f), 'utf8').split('\n').forEach((l, i) => {
        if (/\b(err|error)\.(message|data\.error|data\.message)\b/.test(l)) {
          leaks.push(`${f}:${i + 1}`);
        }
      });
    }
    expect(leaks).toEqual([]);
  });

  it('renders no backend string arriving as a payload field', () => {
    // This shape is how {check.error} reached the UI unnoticed: the earlier
    // check only matched err.message-style expressions.
    const leaks = [];
    for (const f of adminFiles) {
      const lines = fs.readFileSync(path.join(adminDir, f), 'utf8').split('\n');
      lines.forEach((l, i) => {
        if (/console\.\w+\(/.test(l)) return; // operator diagnostics, not UI
        const m = l.match(/(^|[^$])\{\s*([A-Za-z_$][\w$]*)\.(error|message)\s*\}/);
        if (!m) return;
        const ident = m[2];
        if (/^(err|error)$/.test(ident)) return;
        // An object built locally from t() is already translated.
        const decl = lines.find(
          (x) => x.includes(`const ${ident} =`) || x.includes(`let ${ident} =`)
        ) || '';
        if (/\(\s*t\s*[,)]/.test(decl) || /\bt\(/.test(decl)) return;
        leaks.push(`${f}:${i + 1}  ${l.trim()}`);
      });
    }
    expect(leaks).toEqual([]);
  });

  it('adminService propagates a structured code for the UI to translate', () => {
    expect(read('services/adminService.js')).toMatch(/err\.code\s*=/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Plan catalog parity
// ─────────────────────────────────────────────────────────────────────────────

describe('plan catalog', () => {
  // The frontend cannot import the backend, so it keeps its own copy of the
  // commercial numbers rather than fetching them (a pricing endpoint would put a
  // network round-trip in front of the signed-out landing page). Nothing at
  // runtime makes the two agree — this test is what makes them agree.
  //
  // Before the catalogs existed these figures were hand-copied into five places
  // and happened to match. A price change had to land in five diffs to be right.
  const BACKEND_CATALOG = path.join(SRC, '..', '..', 'backend', 'config', 'planCatalog.js');

  // eslint-disable-next-line no-new-func
  const frontendCatalog = new Function(
    `${read('config/planCatalog.js').replace(/export const/g, 'const').replace(/export /g, '')}
     return { PLAN_CATALOG, PLANS };`
  )();

  const backendAvailable = fs.existsSync(BACKEND_CATALOG);
  // Skips rather than fails when only the frontend tree is checked out (the
  // deploy workflow builds frontend/ alone).
  const maybeIt = backendAvailable ? it : it.skip;

  maybeIt('agrees with the backend catalog on every plan', () => {
    const src = fs
      .readFileSync(BACKEND_CATALOG, 'utf8')
      .replace(/^\s*(const|function)\s+(RECURRING_PLANS|ONETIME_PLANS|ONETIME_SCANS|PLAN_PROVISIONING|monthlyEquivalent)[\s\S]*$/m, '');
    // eslint-disable-next-line no-new-func
    const backend = new Function(`${src}\nreturn PLAN_CATALOG;`)();

    const frontend = frontendCatalog.PLAN_CATALOG;

    expect(Object.keys(frontend).sort()).toEqual(Object.keys(backend).sort());

    for (const plan of Object.keys(backend)) {
      expect([plan, frontend[plan].seats]).toEqual([plan, backend[plan].seats]);
      expect([plan, frontend[plan].scans]).toEqual([plan, backend[plan].scans]);
      expect([plan, frontend[plan].severity]).toEqual(
        [plan, backend[plan].vulnerabilityAccessLevel]
      );
      expect([plan, frontend[plan].price]).toEqual([plan, backend[plan].price]);
    }
  });

  it('renders every price as a grouped yen string', () => {
    const rendered = []
      .concat(frontendCatalog.PLANS.monthly, frontendCatalog.PLANS.annual, frontendCatalog.PLANS.onetime)
      .map((p) => p.price);
    expect(rendered.length).toBe(8);
    for (const price of rendered) expect(price).toMatch(/^¥[\d,]+$/);
  });

  it('is the only place the UI states a plan price', () => {
    // A literal yen figure anywhere else is a copy that will drift.
    const offenders = sourceFiles
      .filter((f) => !f.endsWith(path.join('config', 'planCatalog.js')))
      .filter((f) => /¥\s?\d{2,3},\d{3}/.test(fs.readFileSync(f, 'utf8')))
      .map((f) => path.relative(SRC, f));
    expect(offenders).toEqual([]);
  });
});
