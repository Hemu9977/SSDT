# SSDT - Security Scanning & Detection Tool

## Project Overview
MERN stack (MongoDB, Express 5, React 19, Node.js) web application that performs comprehensive website security scanning. Users submit a URL and get results from 7 integrated scanners. Supports both unauthenticated (normal) and authenticated website scanning.

## Architecture

### Backend (Express, port 3001)
- **MongoDB** with Mongoose ODM. Large scan results stored in **GridFS** (WebCheck results >10MB, ZAP detailed alerts).
- **Authentication**: JWT tokens via `x-auth-token` header, Google OAuth, email OTP verification.
- **AI Reports**: Gemini via Vertex AI. Models come from `GEMINI_MODEL_PRO`
  (default `gemini-2.5-pro`) and `GEMINI_MODEL_FLASH` (default `gemini-2.5-flash`)
  — see `services/geminiService.js:13-14`. There is no `GEMINI_MODEL` variable.
  Everything sent to Gemini passes through `services/geminiSanitizer.js` first.
- **PDF Generation**: Bilingual (English/Japanese) vulnerability reports.

### Frontend (React 19, CRA, port 3000 dev)
- **Styling**: SCSS + inline styles with theme support (light/dark via `ThemeContext`).
- **Theme pattern**: `theme === 'light' ? 'rgba(255,255,255,0.75)' : 'rgba(0,0,0,0.65)'` for card backgrounds.
- **Color palette**: `--accent` (cyan), `#00d084` (green), `#e81123` (red), `#ffb900` (orange).
- **No chart libraries** - pure CSS visualizations.

### External Services (Docker)
- **OWASP ZAP**: Two instances on ports 8080 (normal) and 8081 (authenticated scans).
- **WebCheck**: Docker container on port 3002, runs 29 scan types via REST API (`/api/{scan-type}?url=`).

## 6 Scanners
1. **PageSpeed Insights** - Lighthouse performance/accessibility/SEO scores
2. **Mozilla Observatory** - HTTP security headers grading
3. **OWASP ZAP** - Active vulnerability scanning (spider + active scan)
4. **WebCheck** - 29 sub-scans (SSL, DNS, headers, cookies, tech stack, ports, etc.)
5. **urlscan.io** - Screenshot + page analysis
6. **Gemini AI** - Synthesized security report from all scanner data

## Key Components

### Normal Scan Flow (`Hero.jsx`)
- User enters URL → `POST /api/scan/combined-url-scan` → polls `GET /api/scan/active-scan`
  every 3s, then `GET /api/scan/combined-analysis/:id` for the result.
  (`virustotalRoutes.js` is mounted at **`/api/scan`** — `server.js:157`. The
  `/api/vt` prefix in older notes never existed on this codebase.)
- Background scans (ZAP, WebCheck) run independently on the server
- Results displayed in 26 score cards + 2 collapsible details sections (ZAP Report, WebCheck Analysis)
- Downloads: PDF (English/Japanese), JSON export

### Authenticated Scan Flow (`AuthenticatedScanPanel.jsx`)
- User provides URL + login field definitions (dynamic multi-field form)
- `POST /api/zap-auth/start` → polls `/api/zap-auth/status/:id` every 3s
- Same 26 score cards + ZAP Report + WebCheck Analysis
- Uses ZAP instance on port 8081

### Shared Components
- **`WebCheckDetails.jsx`** - Renders all 29 WebCheck scan types. Props: `{ webCheckReport, theme }`. Used by both Hero.jsx and AuthenticatedScanPanel.jsx.
- **`ZapReportEnhanced.jsx`** - ZAP vulnerability report with severity filtering. Props include `apiPrefix` (different for auth vs normal).

### Admin Panel (`pages/Admin/`)
- `AdminPanel.jsx` is the shell; tabs are `AdminOverview`, `AdminAnalytics`,
  `AdminUsers`, `AdminOrganizations`, `AdminScans`, `AdminSystemHealth`.
- `adminLabels.js` maps backend enums **and error codes** to translation keys;
  `adminFormat.js` handles locale-aware number/date formatting;
  `adminCharts.jsx` is pure CSS (no chart library).
- `services/adminService.js` is the only place admin API calls are made.
- `components/RequireAdmin.jsx` guards the route. It decides during render with
  `<Navigate>` rather than in an effect, so an unauthorised visitor never mounts
  the panel and never fires admin requests that could only 403.

### Shared Frontend Utilities
- `utils/apiErrors.js` — backend error code → translation key for the whole app.
- `utils/authRedirect.js` — `ADMIN_ROLES`, `isSystemAdmin`, `postLoginTarget`.
  The role list lives here once; do not inline it at call sites.
- `components/MarketingHome.jsx` — the signed-out landing page. It replaced the
  splash screen and absorbed the old `/about` page (which now redirects to `/`).

### Historical Scans
- `ScanViewer.jsx` loads historical scan via `GET /api/scan/scan/:analysisId`
- Passes data to `LandingPage → Hero` for display
- Profile page lists past scans with 7-day retention

## Scan Result Storage (MongoDB)
```
ScanResult {
  userId, target, analysisId, status,
  pagespeedResult, observatoryResult, urlscanResult,
  zapResult: { status, alerts[], reportFiles[], detailedAlerts... },
  webCheckResult: { status, fullResults|resultsFileId, summary, completedScans... },
  authScanResult: { ... },
  refinedReport (AI),
  createdAt, updatedAt
}
```
- Terminal states for WebCheck: `completed`, `completed_partial`, `completed_with_errors`, `failed`
- Terminal states for ZAP: `completed`, `completed_partial`, `failed`
- Stale scan watchdog: ZAP 24h timeout, WebCheck 6h timeout → fails entire scan

## Backend Route Files
- `virustotalRoutes.js` - Normal scan orchestration (combined-analysis, active-scan polling, historical scan loading, PDF/JSON export). Filename is legacy — do NOT rename.
- `zapAuthRoutes.js` - Authenticated scan orchestration (same pattern, different ZAP instance)
- `webcheckRoutes.js` - Direct WebCheck API proxy
- `zapRoutes.js` - Direct ZAP API proxy
- `auth.js` - Login, register, OTP, Google OAuth
- `profile.js` - User profile, scan history
- `translateRoutes.js` - Japanese translation via Google Translate
- `pageSpeedRoutes.js`, `urlscanRoutes.js` - Direct API proxies
- `admin.js` - Platform admin API (KPIs, users, organizations, scans, system
  health, analytics + user/org mutations). Guarded by `auth` + `adminAuth`.
- `orgRoutes.js` - Organization invites and membership (accept-invite issues a JWT)
- `scheduleRoutes.js` - Scheduled scans
- `notificationRoutes.js` - Notification polling (WebSocket fallback)
- `stripeRoutes.js` - Checkout, webhooks, subscription lifecycle

## WebCheck Data
- `getFullResults(webCheckResult)` in `webCheckService.js` handles both inline and GridFS storage
- 60-second in-memory cache prevents redundant GridFS downloads
- Summary extraction (`extractWebCheckSummary`) creates lightweight data for MongoDB document (full results in GridFS)

## Feature Parity Requirements
Both Hero.jsx (normal scan) and AuthenticatedScanPanel.jsx (auth scan) MUST have identical feature sets:
- Score cards (PSI, Observatory, ZAP, WebCheck, urlscan, AI)
- WebCheckDetails component (29 scan sections)
- ZapReportEnhanced component
- Screenshot preview
- AI report with Japanese translation
- PDF download (English/Japanese language selector)
- JSON export
- Observatory grade summary

## Testing

Both halves have real suites and neither needs credentials, a database, Docker,
or a running server — they are static analysis plus handler-level execution.

```bash
cd backend  && npm test                                    # node --test
cd frontend && CI=true npx react-scripts test --watchAll=false
cd frontend && CI=true npx react-scripts build              # must stay warning-free
```

- `backend/tests/adminApiInvariants.test.js` — query projections, the
  admin/superadmin decision matrix, `$regex` escaping, and a census asserting
  every `jwt.sign` is gated and every independent `jwt.verify` checks disabled state.
- `backend/tests/geminiSanitizer*.test.js` — redaction and over-redaction, incl.
  compressed IPv6, emails and internal hostnames.
- `backend/tests/passwordReset.test.js` — executes the reset/resend handlers
  against a stubbed model layer.
- `backend/tests/billingInvariants.test.js` — executes `finalizeSuccessfulScan` and
  `claimScanSlot` against a stubbed model layer: charge-exactly-once under concurrency,
  claim release when a charge is declined, rank/capacity arithmetic, and a census
  asserting quota is charged from exactly one service.
- `frontend/src/__tests__/appInvariants.test.js` — route guard decision table,
  import resolution, locale parity, that no backend string reaches the UI, and
  plan-catalog parity with the backend catalog.

The build is clean at `CI=true`; `.github/workflows/frontend-deploy.yml` still
sets `CI: false`, which can now be removed. **That workflow auto-deploys to S3 +
CloudFront on any push to `main` touching `frontend/**`.**

## Current Branch: `main`

Most recent work — the billing and quota defects `HANDOFF.md` §6 reported but did not fix:
- **One billing point.** `finalizeSuccessfulScan` is now called from
  `geminiCompletionService` only, for both scan flows. The ~80-line inline Gemini block in
  the authenticated status route is gone, as are `zapService`/`zapAuthService`'s own calls
  (`zapAuthService`'s was a no-op: it fired while the scan was still `combining`).
  Auth scans were previously billed non-deterministically: the completion service charges,
  the status-poll route did not, and whichever reached the write first decided whether the
  customer paid.
  `schedulerService.finalizeRunningScans` was a fourth such path and is gone too — it
  also skipped the plan severity filter when building the AI prompt.
- **Concurrency cannot beat the cap.** `planService.claimScanSlot()` (rank by `_id` among
  in-flight scans vs. remaining capacity), called after each `ScanResult` is created.
  `ScanResult.organizationId` is finally written — it was indexed but set by nothing.
- **`finalizeSuccessfulScan` claims `quotaConsumed` atomically** before charging and
  releases the claim if the charge is declined; the paying pool lands in
  `ScanResult.quotaSource`.
- **`backend/config/planCatalog.js`** replaces five hand-copied pricing tables, with a test
  holding the frontend mirror in step.
- Dead code removed: 72 orphaned locale keys (both files), `/api/webcheck/types` and
  `/save-results`, and five orphaned frontend files.

Earlier work — that batch merged three feature branches and reviewed them; see
`HANDOFF.md` for the full account:
- Merged `admin-dashboard`, `gemini-masking`, and `landing-page`.
- Admin dashboard made reachable and hardened: a render-time route guard,
  superadmin hierarchy, `$regex` escaping, and per-request `isDisabled`
  enforcement with a 30s cache that admin mutations invalidate directly.
- Session revocation: `User.tokensValidFrom` is stamped by a password reset and
  checked in `middleware/auth.js`, so a reset actually ends older sessions.
- Password reset and OTP resend implemented — they were previously stubs that
  returned success while sending no email and changing no password.
- Gemini sanitizer: compressed IPv6, emails and dotless internal hostnames were
  leaking to the LLM; the same pattern also over-redacted HTTP `Date` headers.
- Every backend error response now carries a stable `code`, mapped to a
  translated string (see the UI Language Policy above).
- The marketing landing page replaced the splash screen; `Dashboard.jsx`,
  `sidebar.jsx`, `SplashScreen.jsx` and `About.jsx` were deleted. `/about` and
  any unmatched path now redirect to `/`.

Earlier work still worth knowing:
- Shared `WebCheckDetails.jsx` extracted from Hero/AuthenticatedScanPanel.
- Stale scan watchdog (24h ZAP, 6h WebCheck); GridFS cache and 1h timeout.
- recharts removed in favour of pure CSS visualisations.

## Service Plan - Implementation Goals

### Product Name: SSD (Simple Security Diagnosis)

### Subscription Tiers

> **Single source of truth: `PLAN_CATALOG` in `backend/config/planCatalog.js`.** The table
> below mirrors that constant — if they ever disagree, the code is right and this table is
> stale. `PLAN_LIMITS` (`models/User.js`), Stripe provisioning and the admin revenue figures
> are all derived from it. Read quota limits via `user.getAccountLimits(org)`; keys are
> `` `${planType}_${billingCycle}` ``.
>
> The frontend keeps a mirror at `frontend/src/config/planCatalog.js` — it cannot import
> backend code, and a pricing endpoint would put a network call in front of the signed-out
> landing page. A test in `frontend/src/__tests__/appInvariants.test.js` reads the backend
> file off disk and fails if the two disagree, so **a price change must land in both.**

| Feature | Light | Basic | Pro |
|---------|-------|-------|-----|
| **Monthly Price** | ¥30,000 | ¥50,000 | ¥100,000 |
| **Annual Price** | ¥300,000 | ¥500,000 | ¥1,000,000 |
| **Accounts** (`seatsAllowed`) | 1 | 3 | 5 |
| **Scans/month** (`scansPerMonth`) | 3 | 5 | 10 |
| **Max targets/month** (`targetsPerMonth`) | 3 | 5 | 10 |
| **Scans per target** (`scansPerTarget`) | monthly: none · annual: 3 | monthly: none · annual: 5 | monthly: none · annual: 10 |
| **Max schedules** (`maxSchedules`) | 1 | 3 | 10 |
| **Severity shown** (`vulnerabilityAccessLevel`) | `critical-high` | `all` | `all` |

Notes:
- **Monthly plans have no per-target cap** (`scansPerTarget: null`) — the cap is the global
  `scansPerMonth`. Only *annual* plans enforce per-target limits.
- **ZAP never emits a "Critical" severity** (`backend/utils/vulnFilter.js:23`), so the
  `critical-high` tier resolves to **High only** in practice.
- **Free / no-plan tier**: `scansPerMonth: 20`, unlimited targets, `critical-high`,
  `maxSchedules: 2`. Also the fallback for an org whose paid plan was nulled on cancellation.

### One-Time Trial Plans
- **Trial 1** (`trial1_onetime`): ¥20,000 — 1 account, 1 scan, 1 target, `critical-high`, no schedules
- **Trial 2** (`trial2_onetime`): ¥30,000 — 1 account, 2 scans, 1 target, `all` severities, no schedules

Scan allocations are derived in `ONETIME_SCANS` (`backend/config/planCatalog.js`).
One-time purchases are **credit batches** (`Organization.scanCredits`), consumed only after
the monthly allowance is exhausted, so a subscriber can buy a top-up without losing their
plan. `billingCycle === 'onetime'` survives as a legacy org-wide mode for unmigrated trial
accounts — see `hasLegacyOneTimeBalance` in `planService.js`.

### Environment Scale Targets
- Light plan: support 10 companies
- Basic plan: support 20 companies
- Pro plan: support 5 companies
- Scale adjusted based on contract status

### Implementation Status
- [x] **TASK 1**: VirusTotal API removal (VT removed from all files, 6 scanners remain)
- [x] **TASK 2**: Multi-tenant account system — `backend/models/Organization.js`, `middleware/requireOrg.js`
- [x] **TASK 3**: Severity-level gating — `backend/utils/vulnFilter.js`, driven by `vulnerabilityAccessLevel`
- [x] **TASK 4**: Plan-based scan limits — `backend/services/planService.js` (`checkScanQuota`, `consumeScan`, `finalizeSuccessfulScan`) enforced by `middleware/planCheck.js`
- [x] **TASK 5**: Trial one-time scan mode — `billingCycle: 'onetime'` + `Organization.oneTimeRemainingScans`
- [x] **Stripe billing** (not originally listed) — `backend/routes/stripeRoutes.js`, `models/StripeEvent.js` for webhook idempotency
- [x] **TASK 6**: Usage tracking dashboard — the Profile Statistics grid shows the plan
  scan limit, scans this month, and remaining purchased credits with their expiry date
- [x] **TASK 7**: Admin panel — `backend/routes/admin.js` (12 endpoints),
  `frontend/src/pages/Admin/*`, guarded by `components/RequireAdmin.jsx` at the
  `/admin` route. Platform role lives on `User.systemRole`
  (`user` | `admin` | `superadmin`), separate from the org-level `role`.
  **Only a `superadmin` may grant or revoke an admin role, or act on an account
  that already holds one** (`middleware/adminAuth.js` admits both, so the
  hierarchy is enforced in `routes/admin.js`).
  Bootstrap: `cd backend && node scripts/backfillSystemRole.js`, then
  `node scripts/makeAdmin.js <email> superadmin` — the second argument is
  load-bearing; anything but `superadmin` yields a plain `admin`.

### Quota Enforcement Notes
- Quota is checked at scan **start** (`planCheck.js`) but charged only at successful
  **completion** (`finalizeSuccessfulScan`, guarded by `ScanResult.quotaConsumed`).
- Monthly counters reset on a **UTC** calendar-month boundary (`planService.js:93-96`).
  `backend/routes/profile.js:35` also uses `Date.UTC(...)`, so the two agree. (An
  earlier note here claimed they disagreed; the code was fixed without updating
  the doc.) `profile.js`'s `scansThisMonth` is cosmetic anyway — bounded by the
  7-day TTL — while `org.scansUsed` is the authoritative counter.
- `planCheck` is **advisory** — `checkScanQuota` reserves nothing. The authoritative check
  is `planService.claimScanSlot()`, which every scan-start path calls immediately after
  creating its `ScanResult`: it admits a scan only if the number of the org's in-flight
  scans with a **lower `_id`** is below the org's remaining capacity (subscription
  allowance + live credits). ObjectIds are unique and monotonic, so concurrent starters get
  distinct ranks and exactly `capacity` of them win. Nothing is reserved, so nothing can
  leak and lock a customer out, and the stale-scan watchdog frees a wedged scan's slot.
- **`finalizeSuccessfulScan` is the only place quota is charged**, and it is called from
  `geminiCompletionService` **only** — for both the normal and the authenticated flow. It
  claims `quotaConsumed` atomically *before* charging, and releases the claim if the charge
  is declined. `backend/tests/billingInvariants.test.js` enforces the single-caller rule; a
  second billing site is how authenticated scans previously went unbilled. Standalone
  one-shot routes (`pageSpeedRoutes`, `webCheckRoutes`, `zapRoutes`) are the exception:
  they create no `ScanResult`, never enter the pipeline, and call `consumeScan()` inline.
- `ScanResult` documents carry a **7-day TTL**, so they cannot be used to compute monthly
  usage. `Organization.scansUsed` is authoritative.

### Other Infrastructure
- `User.getAccountLimits(org)` also returns legacy `scansPerDay` (derived as
  `scansPerMonth / 30`) and `maxFileSize` — **neither is enforced anywhere**; do not treat
  them as real limits.
- `virustotalRoutes.js` is the main scan orchestration file (filename is legacy) — handles ALL scan workflows

## UI Language Policy

- **Japanese is the default UI language**; English stays available via the header toggle
  (`components/LanguageToggle.jsx`). Default lives in `frontend/src/locales/index.js`.
- `ja.js` spreads `...en`, so a missing JA key silently renders English rather than a raw key.
  **Every new user-facing string needs entries in both `en.js` and `ja.js`.** Both files are
  flat key objects — check for an existing key before adding one, duplicates are easy to create.
- **Never display third-party scanner names to users.** The product is resold; clients must not
  learn that OWASP ZAP, WebCheck, urlscan.io, Mozilla Observatory, PageSpeed, or Gemini are
  used. Score cards and progress text use neutral wording; scan progress is reported as
  "Step N of 6" via `frontend/src/utils/scanStatus.js`.
- **Two mapping tables implement the rule below** — every backend response carries a
  stable `code`, and these are the only places a code becomes user-facing text:
  `frontend/src/utils/apiErrors.js` (app-wide) and
  `frontend/src/pages/Admin/adminLabels.js` (admin API). Adding a backend `code`
  means adding a row to one of them plus keys in **both** `en.js` and `ja.js`.
- **Never render a backend-supplied `message` or `error` string in the UI.** Those are English-only,
  bypass i18n, and name the scan engines (e.g. `'ZAP scan timed out'`). They are for server logs.
  Derive user-facing status from structured fields and resolve it through `t()`.
