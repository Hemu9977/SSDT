# SSDT - Security Scanning & Detection Tool

## Project Overview
MERN stack (MongoDB, Express 5, React 19, Node.js) web application that performs comprehensive website security scanning. Users submit a URL and get results from 7 integrated scanners. Supports both unauthenticated (normal) and authenticated website scanning.

## Architecture

### Backend (Express, port 3001)
- **MongoDB** with Mongoose ODM. Large scan results stored in **GridFS** (WebCheck results >10MB, ZAP detailed alerts).
- **Authentication**: JWT tokens via `x-auth-token` header, Google OAuth, email OTP verification.
- **AI Reports**: Gemini API (`GEMINI_MODEL` in .env, currently `gemini-3-flash`) generates security analysis reports.
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
- User enters URL → `POST /api/vt/combined-analysis` → polls `/api/vt/active-scan` every 3s
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

### Historical Scans
- `ScanViewer.jsx` loads historical scan via `GET /api/vt/scan/:analysisId`
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

## Current Branch: `main`
Recent work:
- Extracted shared WebCheckDetails.jsx component from duplicated code in Hero.jsx and AuthenticatedScanPanel.jsx
- Added stale scan watchdog (24h ZAP, 6h WebCheck) that fails entire scan on timeout
- Backend GridFS cache to prevent redundant downloads
- Frontend AbortController to prevent React StrictMode double-fetches
- Fixed: Quality Metrics raw JSON display, trace route all-asterisk rows, ranking visualization, font consistency
- Fixed GridFS bucket mismatch for auth scans (pdfService, virustotalRoutes, historical loader)
- Increased GridFS timeout to 1 hour
- Removed recharts, replaced with pure CSS ranking visualization
- Synced AJAX spider behavior (no stuck detection) between normal and auth scan

## Service Plan - Implementation Goals

### Product Name: SSD (Simple Security Diagnosis)

### Subscription Tiers

> **Single source of truth: `PLAN_LIMITS` in `backend/models/User.js`.** The table below
> mirrors that constant — if they ever disagree, the code is right and this table is stale.
> Read via `user.getAccountLimits(org)`; keys are `` `${planType}_${billingCycle}` ``.

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

Scan allocations live in `ONETIME_SCANS` (`backend/routes/stripeRoutes.js`). One-time is
currently an org-wide *mode* (`Organization.billingCycle === 'onetime'`), not a credit balance —
see `planchanges.md` for the planned rework.

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
- [ ] **TASK 6**: Usage tracking dashboard — partially present in the Profile page; see `planchanges.md`
- [ ] **TASK 7**: Admin panel for managing company accounts and plans

### Quota Enforcement Notes
- Quota is checked at scan **start** (`planCheck.js`) but charged only at successful
  **completion** (`finalizeSuccessfulScan`, guarded by `ScanResult.quotaConsumed`).
- Monthly counters reset on a **UTC** calendar-month boundary (`planService.js`).
  `backend/routes/profile.js` currently computes its month boundary in *server-local* time —
  these disagree; see `planchanges.md`.
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
- **Never render a backend-supplied `message` or `error` string in the UI.** Those are English-only,
  bypass i18n, and name the scan engines (e.g. `'ZAP scan timed out'`). They are for server logs.
  Derive user-facing status from structured fields and resolve it through `t()`.
