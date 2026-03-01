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

| Feature | Light | Basic | Pro |
|---------|-------|-------|-----|
| **Monthly Price** | ¥30,000 | ¥50,000 | ¥100,000 |
| **Annual Price** | ¥300,000 | ¥500,000 | ¥1,000,000 |
| **Accounts** | 1 | 3 | 5 |
| **Scans per target/month** | 1 | 3 | 10 |
| **Max targets/month** | 3 | 5 | 10 |
| **Severity levels shown** | Critical, High only | All (Critical→Informational) | All (Critical→Informational) |

### One-Time Trial Plans
- **Trial 1**: ¥20,000 - 1 account, 1 scan, 1 target, Critical+High only
- **Trial 2**: ¥30,000 - 1 account, 2 scans, 1 target, all severity levels

### Environment Scale Targets
- Light plan: support 10 companies
- Basic plan: support 20 companies
- Pro plan: support 5 companies
- Scale adjusted based on contract status

### Features NOT YET Implemented (Goals)
- [x] **TASK 1**: VirusTotal API removal (completed — VT removed from all files, 6 scanners remain)
- [ ] **TASK 2**: Multi-tenant account system (Company model, multiple accounts per company)
- [ ] **TASK 3**: Severity-level gating (Light plan: only show Critical + High vulnerabilities)
- [ ] **TASK 4**: Plan-based scan limits (scans per target per month, max targets per month)
- [ ] **TASK 5**: Trial plan one-time scan mode
- [ ] **TASK 6**: Usage tracking dashboard
- [ ] **TASK 7**: Admin panel for managing company accounts and plans

**Full implementation details for each task: see `IMPLEMENTATION_PLAN.md`**

### Existing Infrastructure (useful for plan features)
- User model already has `accountType` ('free'/'pro'), `proExpiresAt`, `isPro()`, `getAccountLimits()`
- Prototype upgrade/downgrade endpoints exist in `backend/routes/profile.js`
- `virustotalRoutes.js` is the main scan orchestration file (filename is legacy) - handles ALL scan workflows
