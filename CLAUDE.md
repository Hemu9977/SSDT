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
- **Card/panel backgrounds**: always `var(--panel-bg)` (`index.css`; opaque, theme-aware — no
  `theme === 'light'` branch needed). For a tinted surface layer the tint over it:
  `linear-gradient(<tint>, <tint>) var(--panel-bg)`. Never give a text container a translucent
  `rgba`/`transparent` background or rely on `backdrop-filter`: the particle canvas is
  `position: fixed; z-index: -1` behind every page, so its dots show through the text.
- **Color palette**: `--accent` (cyan), `#00d084` (green), `#e81123` (red), `#ffb900` (orange).
- **No chart libraries** - pure CSS visualizations.

### External Services (Docker)
- **OWASP ZAP**: Two instances on ports 8080 (normal) and 8081 (authenticated scans).
- **WebCheck**: Docker container on port 3002, runs 29 scan types via REST API (`/api/{scan-type}?url=`).

### Redis
- Everything Redis goes through `backend/config/redis.js` (BullMQ `scan-queue`/`zap-queue`,
  ZAP locks, capacity state, scan progress pub/sub, Gemini dedup, PDF job metadata).
- **Production Redis: self-managed Valkey 9.0 on EC2** (`i-0ae101f3fba1e6cf5`,
  `redis.fortexa.internal` / 10.0.128.50, private subnet, TLS-only with Fortexa's private CA,
  ACL user `fortexa-app`, AOF + RDB, `noeviction`). Production revision: **`fortexa-backend:98`**
  (image `v66` = `sha256:7526c61b…`, deployed 2026-11-09 14:20 UTC: log redaction, report
  localization, no `*.backup*` files). `:98` is `:97` with only the image changed, so `:97`
  (image `v_basicauth`) is the immediate rollback. `REDIS_URL`,
  `REDIS_TLS_CA` and `REDIS_TLS_SERVERNAME` all come from `fortexa-redis/app`. Runbook, scripts
  and verification: `infrastructure/redis-ec2/README.md`.
- **The Redis Cloud rollback (`fortexa-backend:85`) no longer exists.** Its image (`v55`, also
  `:86`'s) and every image before `v61` were deleted from ECR (the repo has no lifecycle
  policy), so revisions `:80–:90` cannot start. Startable revisions are `:91–:97`, all on the
  EC2 Valkey. Whether Redis Cloud and `fortexa-backend-secrets:REDIS_URL` are still needed is
  now a deliberate decision, not a rollback window. Re-check ECR before naming any rollback.
- **ElastiCache is retired.** Cluster `fortexa-redis` was deleted on 2026-10-03 (it never
  served traffic) and is neither a production nor a rollback target. Neither 86 nor 85
  references `fortexa-backend-secrets:ELASTICACHE_REDIS_URL`; revisions 80–84 still do and
  cannot start once that key is removed (README, "ElastiCache retirement").
- A private CA needs `REDIS_TLS_CA` (+ `REDIS_TLS_SERVERNAME`); images older than this
  change cannot connect to the EC2 Valkey.
- Do **not** add a blanket `commandTimeout` to the publisher: on timeout,
  `zapRecycler.tryAcquire` falls back to an in-memory lock while another scan may still
  hold the Redis lock (ZAP recycled under a running scan). Blocking until Redis returns
  is the safe behaviour for locks.
- `cd backend && node scripts/redisMigrationSmoke.js` (and `redisSecurityProbe.js`) check
  any Redis against everything Fortexa uses; `infrastructure/redis-ec2/vpc-smoke.sh` runs
  them from inside the VPC.

## 6 Scanners
1. **PageSpeed Insights** - Lighthouse performance/accessibility/SEO scores
2. **Mozilla Observatory** - HTTP security headers grading
3. **OWASP ZAP** - Active vulnerability scanning (spider + active scan)
4. **WebCheck** - 29 sub-scans (SSL, DNS, headers, cookies, tech stack, ports, etc.)
5. **urlscan.io** - Screenshot + page analysis
6. **Gemini AI** - Synthesized security report from all scanner data

### In-house fallbacks for IP-restricted targets (`backend/services/inHouse/`)
PageSpeed, Observatory and urlscan.io — and WebCheck's `tls` (calls the Observatory
API) and `quality` (calls PSI) — fetch the target from **third-party** servers. A client
whose site only admits Fortexa's egress IP (**54.178.209.53**, the NAT gateway every ECS
task routes through) refuses them. Every other check (ZAP, the rest of WebCheck, login
detection) fetches from our own IP, so the client's allowlist entry covers it.
- **External first, always.** `pagespeedService.getPageSpeedReport`,
  `observatoryService.scanHost`, `urlscanService.runUrlScan` and `webCheckService.runScan`
  (tls/quality) wrap the unchanged external call in `inHouse/fallback.js`
  `withInHouseFallback`: a usable external result is returned untouched; only an error or
  an unusable result (a 4xx/5xx page, a Lighthouse `runtimeError`, a urlscan timeout)
  runs the in-house check. If ours is refused too, the external outcome stands.
  A fallback result carries `diagnosticSource: 'in-house'` + `fallbackReason` (never shown).
- WebCheck `tls`/`quality`: the container gets **one** attempt (a retry only re-asks the
  refused third party, ~20 s each) and the check a **10-minute** limit instead of 150 s
  (`WEBCHECK_FALLBACK_SCAN_TIMEOUT_MS`), so a queued in-house run is never cut off.
- Measured: refused targets make PSI give up in ~18 s, the Observatory API in 1–10 s;
  urlscan.io never finishes (still "not finished" at 150 s), so its 90 s poll ends and the
  capture runs. Production before this change stored that timeout as a "Clean" verdict.
- In-house checks: `lighthouseAudit.js` (Lighthouse 13, PSI's settings; desktop for the
  card, mobile for `quality`; CrUX field data via `CRUX_API_KEY`/`PSI_API_KEY` if the
  Chrome UX Report API is enabled), `headerGrade.js` (`@mdn/mdn-http-observatory`, the
  engine behind the public API — identical grades), `pageCapture.js` (Puppeteer capture +
  `utils/ipCountry.js` + `threatVerdict.js`, a DNS blocklist verdict queried resolver by
  resolver). All Chromium work queues on `browserSlot.js` (one at a time, hard timeouts).
- In-house screenshots live in GridFS bucket `page_screenshots`, served by
  `GET /api/scan/screenshot/:token.jpg` (no auth; the 256-bit token is the credential) —
  the UI prefixes `API_BASE` via `frontend/src/utils/screenshotUrl.js`. Deleted with the
  scan's artifacts and swept after the 7-day TTL (`jobs/cleanupJob.js`).
- The UI tells customers to allowlist that IP (ports 80/443, plus WAF/bot-rule exemption) in
  the "Before You Start" notice on **both** scan forms — `components/IpAllowlistNote.jsx`,
  styled by the shared `styles/_scanNote.scss` mixin. The IP comes only from
  `frontend/src/config/egress.js` (`REACT_APP_FORTEXA_EGRESS_IP` overrides it at build time).
- The backend image is **Node 24** (`node:24-bookworm-slim`; the grading engine requires
  it), with `fonts-noto-cjk` and `NODE_EXTRA_CA_CERTS` set in the Dockerfile.
- Known WebCheck bug (not used by the fallback): `new/scripts/block-lists.js` passes
  `{ server }` to `dns.resolve4`, which Node ignores, so every "resolver" is the system one.

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

### Form-login test outcomes (`loginTestService.testLogin`, 2026-11-16)
- Detection (`loginDetectionService.js`) gives every field and button a selector that
  `querySelectorAll` resolves to **that element only** (`uniqueSelector`: id → name → test hooks →
  `type` → positional path). The old `form:nth-of-type(N) button` resolved to the first button in the
  form — on credit.villdesign.com the show-password toggle, so no login was ever sent. Show/hide-password
  controls are never offered or auto-picked (`passwordToggle`), and `submitLogin` refuses to click one
  even when a stale stored selector points at it.
- The submit dropdown hands `onChange` the field **object**. It used to pass the option's string, which
  `testLogin` ignored (`.selector` of a string) — only Enter was pressed. `testLogin` now also accepts a
  bare selector string.
- `submitLogin` watches the network (`utils/loginRequestSignals.js`): a login request is a write (or a
  GET form navigation) that carries a typed value, a password-shaped key, is a document POST, or hits an
  auth-shaped path — never analytics/telemetry/beacons. Once one is seen **no other strategy runs**
  (no second password submission) and the answer is awaited up to 25 s (cold APIs; ALB idle is 60 s).
- Codes: `SUBMIT_NO_EFFECT` = nothing was sent and the page did not move; `LOGIN_REJECTED` = the login
  form is still there, same URL, no session cookie, and the request got 4xx/5xx or a JSON refusal, or a
  failure-worded notice/toast appeared; `LOGIN_NO_RESPONSE` = sent, never answered (or network error);
  `NO_SESSION_COOKIES` (route) = signed in but no cookie to carry. Live-region text (`role=status`,
  `aria-live`) is never the signed-in marker.
- A failed test logs one line of codes only: `[ZAP-AUTH] Login test failed: code=… strategy=…
  loginRequest=… matchedBy=… status=… outcome=… timedOut=… evidence=… cookies=…`.
- **Token sessions (approved 2026-11-16).** Apps that keep the session as a Bearer token in
  `localStorage` and send it to a separate API origin (e.g. credit.villdesign.com: `lumina_token` →
  `credit-managment-managment.onrender.com`) are now carried. `testLogin`'s `watchBearerTokens` records
  the `Authorization: Bearer` the app itself sends after signing in; a token counts only once the API
  answered it 2xx, never one used before the login, never to analytics hosts. If none was seen it reloads
  the signed-in page once (apps send it on start-up). Result field `bearer: [{ origin, authorization,
  seedUrls (GETs only, ≤50), verifyUrl ("who am I" call) }]` — in memory only, never logged/stored/returned.
  - **Policy: `utils/bearerApiScope.js` `eligibleBearerSessions`**, applied by `testLogin`, `/test-login`,
    the scheduler and the scan worker alike. (1) A login that set a **session cookie** gets **no** token
    hosts (`testLogin` returns `hasSessionCookie`; cookie sites scan exactly as before). (2) **Shared
    third-party API providers are never eligible** (`SHARED_API_PROVIDER_DOMAINS`: payments, identity,
    Google/Firebase, Supabase/BaaS, SaaS APIs, analytics, CDNs; every `*.amazonaws.com` except API
    Gateway/AppSync/ELB/EC2). Customer hosting — `*.onrender.com` (credit's API), Heroku, Vercel, Cloud
    Run… — stays eligible. (3) Hosts match on a **label boundary** (`hostMatchesDomain`), never a suffix
    (`credit.villdesign.com.evil.net`). (4) **Logout-shaped URLs** (`LOGOUT_PATH_FRAGMENTS`: logout,
    signOut, revoke, sessions/destroy…) are never seeds or the `verifyUrl`. Origins/seeds also pass
    `checkScanTarget`; seeds are same-origin GETs, ≤50.
  - `/test-login` accepts cookies **or** bearer. The browser gets `sessionKind` and `authHosts` (host
    names only); the UI says that host is scanned too.
  - Scan (`zapAuthService`) — **the site scan is exactly the entered URL** (`ascan url=targetUrl`, site
    context = host + subdomains via boundary-safe `siteScopeRegexes`; the old `https?://host.*` also
    matched `host.evil.net`). **Each API host is a separate scan**: own context `auth_api_<scanId>_<i>`
    (exact origin, logout paths excluded via `apiContextExcludeRegexes`), `ascan url=<origin>`, run after
    the site scan, preceded by a session check (`before_api_scan`); outcome in `apiScans[]`
    (`completed`/`not_started`/`stopped_stuck`). A token for the site's own origin rides with the site
    scan (seeds inside the entered URL only). Replacer rule `auth_bearer_<scanId>_<i>` (POST,
    `bearerRuleRegex` = exact origin **minus logout paths**, so no scanner ever sends the token to a
    logout URL; initiators 2,3,6,10). Alerts: site base = target, API base = `<origin>/` (ZAP's
    `baseurl` is a prefix), and every alert must be on its base's origin. Revocation also removes the
    API contexts. Session probed via `verifyUrl` (401/403 → re-login, which only renews origins
    already in scope); API coverage → `apiAuthEvidence`/`api_only_unauthorized`. Token values are
    scrubbed like cookies. Cookie-only scans make the same ZAP requests as before.
  - Verified on the pinned ZAP image (2026-11-16, internal Docker network, production host names as
    aliases): two active scans (site URL, then API origin); 477/477 API requests carried the token
    (231 attacks), 0 site requests did, 0 logout requests, 0 requests to `credit.villdesign.com.evil.net`
    or `api.stripe.com`; no `auth_*` rule or scan context left. Cookie scan alongside: one active scan,
    cookie on every site request, no API traffic.
- Tests: `tests/loginRequestSignals.test.js` (pure), `tests/loginFlows.browser.test.js` (real Chromium,
  local fixtures incl. a copy of the credit.villdesign.com shape; skips without Chromium),
  `tests/bearerScanLifecycle.test.js` (real scan worker, fake ZAP: scope, logout, look-alike alerts,
  failure / refused API scan / Stop mid-API-scan cleanup), `tests/bearerApiScope.test.js` (policy
  tables, ZAP regexes, `/test-login`), `tests/bearerScheduler.test.js` (real `triggerAuthenticatedScan`).

### HTTP Basic authentication (authenticated scans, manual-only)
Second auth method beside the login form (radio choice in step 1 of `AuthenticatedScanPanel.jsx`;
form login is the default and unchanged). Design and evidence: `docs/BASIC_AUTH_IMPLEMENTATION.md`.
- `POST /api/zap-auth/test-basic` → `services/basicAuthProbe.js`: HTTPS only; anonymous request
  must get `401` + `WWW-Authenticate: Basic`, then ONE authenticated attempt (no lockout loops);
  credentials only ever sent to the exact origin; SSRF guard on every redirect hop. Returns a
  `tempSessionId` (15-min TTL), never the credential. Codes `BASIC_*` map in `utils/apiErrors.js`.
- `POST /scan` (Basic branch) binds the session to the verified origin (`BASIC_ORIGIN_MISMATCH`)
  and moves the credential to `services/scanCredentialVault.js` — **in memory only**, holders
  `zap` + `fast`, purged on cancel/provisioning failure/watchdog, 25 h TTL. Never in MongoDB,
  Redis, GridFS or logs; a lost entry fails the scan closed. Single backend process assumed.
- ZAP: `services/zapCredentialRules.js`. Replacer rule `auth_basic_<scanId>` by **POST**,
  `url=(?i)^https://<host>(:<port>)?(/.*)?$` (ZAP does a whole-URL match), `initiators=2,3,6,10`
  (never the proxy initiator 1). Passive rule 10105 disabled during Basic scans (it logs decoded
  passwords). **Revocation on every exit = stop all scans → remove rules → newSession**; removing
  the rule alone does not revoke (the active scanner replays stored headers). Leftover credential
  rules are purged at scan start (they survive newSession).
- Browser checks (page capture, performance audit) use `services/inHouse/scopedBasicAuth.js`
  (CDP `Fetch.authRequired`, target origin only, one attempt). **Never `page.authenticate()` or
  Lighthouse `extraHeaders`** — both send the credential to other origins (Phase 0 evidence).
  The external PSI/urlscan/Observatory services are skipped for Basic scans.
- **Basic reports have the same sections, filled the same way, as any other** (2026-11-09; this
  reversed design decision 11). Every check behind a PDF row runs in-house, signed in:
  - header grade: `headerGrade.gradeHostWithBasicAuth` — the engine's HTTP clients get a guard
    (AsyncLocalStorage-scoped request interceptor on `Session.prototype.init`) that adds
    `Authorization` only for the exact target origin and strips it on every redirect hop that
    leaves it (follow-redirects keeps it for same-port subdomains). **Never the engine's
    `customHeaders`** — it sends to every host. The engine is pinned exactly (1.7.2); the guard
    patches its internal `Session`, so re-verify on any upgrade (the tests fail if it stops applying).
    One run also yields WebCheck's `tls` grade.
  - WebCheck `firewall` / `hsts` / `tech-stack`: `inHouse/siteChecks.js` ports of the container
    rules, run on the page capture's own signed-in document (`runPageCapture(..., { siteChecks:
    true })`) — no extra request, no new credential path.
  - Those four go to `startAsyncWebCheckScan(..., { precomputed })` and never to the container
    (which only sees 401). A failed one is recorded as failed, never retried unauthenticated.
  - Other WebCheck detail checks (headers, cookies, redirects, quality…) still run without the
    credential; only the UI notice (`basicScopeNotice`) says so. The PDF's Basic-only scope
    section is gone (`RENDERER_REVISION` 4).
- **HSTS was "No" in every report** until 2026-11-09: the container's `hsts` returns
  `{ message, compatible, hstsHeader }`, never `enabled`, which every reader used. Results are now
  normalized when recorded (`normalizeHsts`) and read via `isHstsEnabled` (also covers stored ones).
- Schedules refuse Basic (`BASIC_AUTH_MANUAL_ONLY`). `checkScanTarget` refuses any URL with
  embedded credentials (`URL_HAS_CREDENTIALS`).
- Redaction (`utils/credentialRedaction.js`): credential header values are redacted at capture
  (`fetchZapMessage`, both services) and again at every output (`getSanitizedAlerts`, PDF
  `buildEvidenceText`), so legacy evidence is covered too; exact secrets (Basic variants, or the
  injected session cookie values for form scans) are scrubbed from alerts and the ZAP HTML report.
- ZAP API key is required (`ZAP_API_KEY` / `ZAP_AUTH_API_KEY`, same secret); images pinned to
  `ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47…` (what production actually ran). `zap-sg` already
  limits :8080 to `fortexa-backend-sg`.
- **Production ZAP stays keyless until `infrastructure/zap-key-rotation/` is rolled out** —
  `zapKeyRollout.js` (rotate → restart backend → register → verify → switch; README has the
  evidence and rollback = ZAP back to keyless `:21`/`:12`, never the backend). Facts verified
  against the pinned image: ZAP logs every `-config`/`-configfile` value at INFO
  (`Setting config api.key = <key>`), so the keyed task definitions set `AbstractParam` to WARN
  in a home `log4j2.properties` — keep that when editing the command; a missing/wrong key is a
  closed connection (`socket hang up`, curl 52), not 401/403; the start command refuses an
  empty or non-alphanumeric key. Only backend `:97`+ can drive a keyed ZAP.

### PDF report localization (`services/reportLocalization.js`)
Every prose field of both PDF generators (`generateSingleLanguagePdf`, `generateZapPdf`; public,
form-login and Basic scans alike) goes through `localizeReport`, which returns localized prose
**or throws before anything is rendered** — `REPORT_TRANSLATION_UNAVAILABLE` (the model could not
be used: outage, rate limit, credentials, deadline; "try again later") or
`REPORT_LOCALIZATION_INCOMPLETE` (anything else). An English-only line is never drawn in a JA
report and no finding is ever dropped. (Root cause of the old mixed JA reports: chunks of five
whole findings as free-text JSON failed `JSON.parse` and silently stayed English.)
- **2026-11-17 production failure (fixed):** every JA report with an XSS finding was refused. ZAP's
  shared WASC-8 solution line "Consult the XSS Prevention Cheat Sheet…" came back (correctly) as
  "…XSS Prevention Cheat Sheet を参照してください。"; the audit read "Prevention Cheat Sheet" as an
  English run, and at temperature 0 every retry returned the identical text. Found by hashing the
  pinned image's alert text against the logged unit hash (`6bc5e042a6`). Fixes below.
- **Prose vs data.** Prose = finding title/description/solution, AI analysis, static labels,
  template text. Data (never translated, never sent) = occurrences/evidence, URLs, references,
  ids, risk/confidence enums, counts, scan values, target, scan history.
- **Labels** come only from `i18n/reportStrings.js` (`t(lang, key)`); JA finding titles from the
  reviewed `i18n/zapAlertNames.ja.js` (Japanese only — `originalName`/`pluginId` are kept on the
  finding, never drawn), anything else via the engine.
- **Pipeline (per line):** `i18n/protectTokens.js` masks secrets/identity/technical literals as
  `{{Tn}}` → **JA: the scanner's own reviewed Japanese** (`i18n/zapCatalog.ja.json`, 1,244 lines
  from the pinned ZAP image's `vulnerabilities_ja_JP.xml` + `Messages_ja_JP.properties`, aligned
  line by line; rebuilt by `scripts/buildZapJaCatalog.js <plugin dir>` whenever the ZAP image
  digest or the audit changes — `tests/zapJaCatalog.test.js` checks the digest) → store lookup →
  `geminiService.translateReportUnits` batches (schema-constrained JSON, temperature 0, thinking
  off; no `seed`) → per-unit validation (`hardCheck`: placeholders, no new URL/host/email, no
  Markdown, length, enough target language; then the language audit) → a batch that fails as a
  whole is halved; **a rejected unit goes straight to the single-unit ladder: Flash → Flash in
  repair mode (told why — fixed templates + the plain English words it kept — temperature 0.3)
  → Pro in repair mode** (Pro cannot disable thinking: budget 512). Rate limits (429) re-send the
  same batch after 2/5/10 s, never split. Outage (6 availability failures, no success) fails fast.
- **Last resort (JA, user decision 2026-11-17):** a unit with no clean translation after the ladder
  is drawn with its **best Japanese candidate** if it passed every hard check and failed only
  wording rules (`en_run`/`en_share`/`en_function_word`/`en_word_in_short_field`); a short
  sentence-free literal (`isLiteralLine`, ≤ 6 words, no function word, not a title) the model
  returned unchanged twice, once in repair mode, is kept as is. Both are logged
  (`translation_best_japanese_used` / `translation_literal_kept`, `softAccepted`, `softReasons`)
  and never stored. A candidate that breaks a hard check is never used.
- **`i18n/languageAudit.js`** judges words, not characters: an explicit allowlist
  (`i18n/technicalTerms.js`; plain words match only in canonical case) keeps header names, ids,
  products, protocol and document names (`… Cheat Sheet` titles, capitalised words only) and
  notation (incl. command-line options) legal in Japanese; English function words, 3+ word runs,
  a high English share, or any English word in a title fail. Extend it only with proper names and
  notation found by `scripts/zapCatalogSweep.js <plugin dir> <out.json>` (every scanner alert text
  through the real model; 2026-11-17: 747 lines + 199 titles, 7/7 chunks complete), never with
  ordinary English words.
- **Store: `models/ReportTranslation.js`** (`report_translations`). `_id` = sha256(ENGINE_VERSION ‖
  lang ‖ kind ‖ masked text); no source text, no unmasked value. Rows are immutable
  (`$setOnInsert`, E11000 = success) and re-read after writing so concurrent writers converge.
  ENGINE_VERSION hashes model, prompts (incl. the repair note), schema and scrubber — **not the
  audit**: every stored row is re-validated against the current audit when read, so an allowlist
  fix keeps stored translations. TTL 180 days on `lastUsedAt`. The single-flight map is **per
  process**; correctness across tasks comes from the store. Completed units are stored even when
  the report is refused, so a retry only translates what was missing.
- **Jobs / UI:** both codes reach the UI as `errorCode` (job poll and the ZAP PDF routes: 503) →
  `pdfTranslationUnavailable` (JA; `…Any` for EN) / `pdfLocalizationIncomplete`. Hero and
  AuthenticatedScanPanel end the generating state at once on failure and show a persistent
  `role="alert"` line until the next attempt. A finished job is reused only while its
  `reportVersion` (`pdfService.reportVersion()`, renderer revision + engine) matches.
- Logs carry counts, categories and unit-hash prefixes only (`[Localization] {json}`); `_generate`
  logs error class/status, never `err.message` (SDK and `JSON.parse` messages quote model text).
- Real-model check (local, Vertex via gcloud ADC, no DB): `node scripts/pdfLocalizationSmoke.js
  <outDir> [--outage]` — 16 PDFs (incl. an XSS report) + drawn-text dumps; run twice to see zero
  model calls.

### Logging: no secrets, ever (`utils/logRedaction.js`)
- `server.js`, `workers/startWorker.js` **and every script** (`scripts/*.js`,
  `clear-stuck-scans.js`, `test-stripe.js` — one-off ECS tasks log to CloudWatch too) call
  `require('…/utils/logRedaction').install()` right after dotenv, before anything else loads.
  Keep new entry points and scripts doing the same (the test enforces it for both folders).
- It wraps `console.log/info/warn/error/debug` **and `dir/dirxml/trace/table`** (those used to
  print the raw object): errors lose their HTTP request/response (axios `config` holds API-key
  headers, `apikey` params and POSTed login bodies), a Redis error's `command.args` becomes a
  count (ioredis puts AUTH's `[user, password]` there), sensitive object keys are redacted at
  any depth, and the text is scrubbed of secret env values (incl. `*_PASS`/`*_PWD`, and the
  password inside every URL-valued variable — `MONGO_URI`, `REDIS_URL`), OAuth (`ya29.`) /
  `AIza` keys, JWTs, Bearer/Basic/Digest credentials (also letters-only base64 and
  URL-encoded `Basic+…`), Stripe/AWS keys, PEM private keys, `user:pass@` URLs, secret query
  params, credential header lines, and the value after any secret-named key in JSON
  (incl. double-encoded), inspected objects, form bodies and prose.
- Outside tests it also wraps `process.stdout/stderr.write` for strings (the `debug` module
  behind ioredis/socket.io/puppeteer writes there directly) and registers early
  `uncaughtException`/`unhandledRejection` handlers: Node's own crash printer dumps an axios
  error's config verbatim. They step aside once the entry point registers its own.
- Checked against 10,000 real production log lines: only the OAuth-token-prefix leak and
  nothing legitimate changed. Never loosen a rule without re-running that kind of check.
- Still never log a secret at the call site — not even a prefix ("token starts with …" leaked
  the Google OAuth token prefix on every start until 2026-11-09). Log presence (`!!value`) or
  length. `tests/secretLogging.test.js` runs `geminiService` in child processes, checks the
  redactor, and scans every backend `console.*` call for secret env values, sliced keys/tokens
  and secret variables; it also forbids `*.backup` source copies (one shipped a hard-coded ZAP
  key in the image; `.dockerignore` now excludes `*.backup`/`*.bak`).

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
- `backend/tests/redisConfig.test.js` — Redis TLS option building (private CA, escaped
  newlines, servername, never `rejectUnauthorized:false`) and that the startup health
  check gives up fast instead of holding `server.listen`.
- `backend/tests/pdfEvidence.test.js` — renders the PDF Request/Response evidence (EN and
  JA) and checks every drawn line: no glyph missing from the font it is drawn with
  (squares), Arabic/Hebrew/Thai/Devanagari drawn via the Noto fallbacks in `backend/fonts/`
  (`EVIDENCE_FALLBACK_FONTS`), nothing outside the content frame, no label stranded at a
  page foot, and evidence shown verbatim (no entity/escape decoding or NFKC) in both languages.
- `backend/tests/subscriptionLifecycle.test.js` — cancel → paid until period end → Free.
  Drives the real webhook and cancel handlers against an in-memory store and a stubbed
  Stripe: the exact expiry boundary, duplicate/out-of-order/stale webhooks, failed Stripe
  reads, renewals and payment failures, the sweep, both Stripe payload shapes, and a scan
  that straddles the end of the period (never spends a purchased credit).
- `backend/tests/adminRoutes.test.js` — executes the admin route handlers against an
  in-memory model layer (`tests/support/fakeMongo.js`, sift-based) and a stubbed Stripe:
  superadmin-only billing/deletion, Stripe failure aborting an org delete, soft delete,
  audit rows (incl. fail closed), re-auth, KPI sources, projections, health states.
- `backend/tests/sessionRules.test.js` — writes fail closed when the account check
  cannot run, admin token lifetime, no OTP bypass for admins, `lastLoginAt` on login.
- `backend/tests/pdfEnglishReport.test.js` — runs the real `generateSingleLanguagePdf` for a
  Japanese site and records every drawn string: EN and JA generate in either order (EN used to
  abort with `EN_CONTENT_NOT_ENGLISH`), the site's Japanese is drawn translated with URLs
  restored, raw HTTP evidence stays verbatim, EN is **refused** (not drawn half-Japanese) when the
  site's Japanese cannot be translated, an English-only EN report needs no model, a repeat
  download reuses the stored translations, and no URL/host/operator name/email reaches Gemini.
- Report localization: `reportLocalization.test.js` (the reproduced Path Traversal failure, every
  failure category, retry-by-halving, outage, deadline, scrubber, injection, store/single-flight/
  cross-task/E11000, logs), `languageAudit.test.js` (false-positive and false-negative tables),
  `pdfLocalization.test.js` (real generators: {Basic, form, public} × {full, vulnerability} ×
  {en, ja} audited on drawn text, evidence verbatim, glyphs, margins, outage refusal, page breaks),
  `pdfJobLocalization.test.js` (job fails with the code, nothing in GridFS, retry reuses work,
  version-aware reuse), `reportTranslationCall.test.js` (the real SDK request and response
  classification). Fixture: `tests/fixtures/zapAlerts/stgEbx8.en.json` (exact scanner text).
  (The PDF no longer calls `formatScanDataForPdf`: after 19 Aug 2026 it never once beat its
  35s timeout in production, so every PDF used the deterministic data after waiting 35s.)
- `backend/tests/zapDetailedAlerts.test.js` — the streaming reader for the ZAP detailed-alerts
  file (`services/zapDetailedAlerts.js`) matches `JSON.parse` at every chunk size and keeps only
  what the PDF / evidence panel draws. Never `downloadFile` + `JSON.parse` that file for a
  report: a 287 MB one took production past its 2 GB heap mid-PDF (26 Oct 2026).
- `backend/tests/reportTemplateEnglish.test.js` — the EN template text (disclaimer, closing
  page) comes from `TEMPLATE_ENGLISH` without Gemini, and a Gemini failure falls back to
  built-in English instead of failing (and caching the failure for) every EN report.
- `backend/tests/historicalScanLoad.test.js` — runs the real `GET /api/scan/scan/:analysisId`:
  opening a scan from Recent Scans never inlines the ZAP detailed-alerts file (a production
  file was 287 MB and kept the page on its spinner for minutes); the evidence is fetched on
  demand from `/api/zap/detailed-report/:scanId`, which still serves authenticated scans.
- `backend/tests/inHouseDiagnostics.test.js` — the in-house fallbacks: a usable external
  result is untouched; an error or 403 page runs the in-house check; a site that refuses
  us too keeps the external outcome; each service's wiring; the in-house results keep
  every field the report reads; verdict rules; one browser at a time; screenshot route.
- `backend/tests/inHouseAiPrompt.test.js` — a scan whose results came from the fallbacks,
  through the real sanitizer and `refineReport`, capturing the request the Gemini SDK
  sends: all scores/grade/verdict reach the prompt; no host, path, IP, screenshot token or
  fallback detail does.
- `backend/tests/authScanStop.test.js` — the authenticated Stop button, end to end (real worker,
  stop, start guard, fast scanners, ZAP lock; fake ZAP): a stop wakes the worker at once and
  revokes ZAP before answering; a scan with no running worker sends nothing to the shared auth
  ZAP; a scan stopped while provisioning/queueing never starts (it used to be reset to
  `pending`, scanned and billed); a stop during the report save is not overwritten by
  `combining`; browser checks are aborted and WebCheck never starts; the lock is not leaked.
- `backend/tests/failedScanRetention.test.js`, `subscriptionState.test.js`.
- HTTP Basic auth: `credentialRedaction.test.js` (redaction + vault), `zapCredentialRules.test.js`,
  `basicAuthProbe.test.js` (local HTTPS servers, `tests/fixtures/tls` test-only cert),
  `basicAuthScanLifecycle.test.js` (the real scan worker against a fake ZAP: revocation on every
  exit, no stored secrets, concurrent isolation), `basicAuthOutputs.test.js` (PDF EN/JA, JSON
  export, Gemini inputs), `basicAuthRoutes.test.js`, and `scopedBasicAuth.browser.test.js` (real
  Chromium: iframes, workers, redirects, real capture + Lighthouse + site checks; skips without
  Chromium), `basicAuthSiteChecks.test.js` (the site-check ports, HSTS normalization, the header
  grade's credential guard against real local HTTPS servers — run in a subprocess,
  `tests/support/basicGradeScenario.js`, because the engine's sockets inside the runner process
  intermittently corrupted its IPC frames under full-suite load — the Basic fast-scan
  orchestration, and the PDF rows). `pdfLocalization.test.js` also asserts Basic, form and public
  reports draw identical section headings. Frontend: `src/__tests__/basicAuthInvariants.test.js`.
- `frontend/src/__tests__/appInvariants.test.js` — route guard decision table,
  import resolution, locale parity, that no backend string reaches the UI, and
  plan-catalog parity with the backend catalog.
- `frontend/src/__tests__/adminDashboard.test.jsx` — renders the admin tabs with a
  mocked API: role-dependent controls, computed states, health states, adminService
  error codes, and every label-map key present in both locales.
- `frontend/src/__tests__/loadingStates.test.jsx` — Profile/Recent Scans, ScanViewer and the
  PDF download always leave their loading state (unanswered requests time out via
  `utils/requestTimeout.js`), show translated text only, and download JA/EN independently;
  the scan page's evidence panel asks for `/detailed-report/:id?view=evidence` (first pairs
  per finding), never the whole file, and a failed load offers a retry.

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
| **Monthly Price** | ¥50,000 | ¥80,000 | ¥100,000 |
| **Annual Price** | ¥500,000 | ¥800,000 | ¥1,000,000 |
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
- **Trial 1** (`trial1_onetime`): ¥30,000 — 1 account, 1 scan, 1 target, `critical-high`, no schedules
- **Trial 2** (`trial2_onetime`): ¥40,000 — 1 account, 2 scans, 1 target, `all` severities, no schedules

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
- [x] **TASK 7**: Admin panel — `backend/routes/admin.js` (13 endpoints),
  `frontend/src/pages/Admin/*`, guarded by `components/RequireAdmin.jsx` at the
  `/admin` route. Platform role lives on `User.systemRole`
  (`user` | `admin` | `superadmin`), separate from the org-level `role`.
  **Only a `superadmin` may grant or revoke an admin role, act on an account
  that already holds one, disable an organization containing one, cancel an
  organization's subscription, delete an organization, or read the audit log**
  (`middleware/adminAuth.js` admits both, so the hierarchy is enforced in
  `routes/admin.js`).
  - Every admin mutation writes `AdminAuditLog` via `services/adminAudit.js`: a
    `pending` row first (if it cannot be written the action is refused), then the
    outcome; refused attempts are recorded as `denied`.
  - Destructive actions (delete user/org, cancel billing, change admin rights)
    need a sign-in within 15 min (`isRecentAuth`, token `iat`); admin tokens live
    8 h (`utils/sessionPolicy.js`) and admins never get the post-reset OTP bypass.
  - Organization delete is a **soft delete** (`Organization.deletedAt`): Stripe is
    set to end first and the delete aborts if Stripe fails; members are detached.
    Admin listings filter `deletedAt: null`.
  - Dashboard numbers: all-time scans = sum of `Organization.totalScansAllTime`;
    active = `entitlementFilter()`; per-org state from `utils/subscriptionState.js`.
  - Failed/stopped scans keep their record until the 7-day TTL; the hourly
    cleanup only purges their artifacts (`purgeFailedScanArtifacts`).
  - **No action may leave zero reachable superadmins** (`ADMIN_LAST_SUPERADMIN`); the
    last-admin guards count plain admins too, so they are not enough on their own.
    Nobody may disable their own organization (`ADMIN_SELF_ORG`). Hard-deleting a user
    is superadmin-only.
  Bootstrap (run as a one-off ECS task with the backend task definition, not with a
  production `MONGO_URI` in a laptop `.env`): `node scripts/backfillSystemRole.js`, then
  `node scripts/adminRoster.js --check <email>` (read-only), then
  `node scripts/grantSystemRole.js <email> superadmin --operator "<name>" --ticket <id>`
  (dry run; add `--apply` to write). It refuses unverified/disabled accounts and the last
  superadmin, writes an `AdminAuditLog` row (`actorType: 'script'`) first, and ends the
  account's old sessions. `makeAdmin.js` and `transferAdmin.js` (which copied a password
  hash between accounts) are deleted; never reintroduce either.
- **Sign-in rules for admins**: every admin sign-in passes the emailed OTP, Google
  included (`/auth/google` returns `AUTH_OTP_SENT`; the invite page sends admins to the
  normal login). Google credentials are accepted only if issued to our client id
  (`GOOGLE_CLIENT_ID`, else `REACT_APP_GOOGLE_CLIENT_ID` — production's task definition
  only has the latter) with a Google-verified email (`utils/googleAuth.js`).
- **OTPs** (`utils/otp.js`): only an HMAC is stored (`otpHash`); each code allows 5
  attempts, reserved atomically before comparing (`AUTH_OTP_LOCKED` after that).

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
- **Subscription cancellation lifecycle** (`services/subscriptionLifecycle.js`):
  - Cancelling (`POST /api/stripe/cancel-subscription`, org owner/admin only) sets Stripe
    `cancel_at_period_end` — auto-pay stops, the plan keeps working, and
    `Organization.cancelAtPeriodEnd` + `expiresAt` record when it ends. No undo, no refund.
  - **Paid access is computed, not stored**: `utils/entitlement.js` `isSubscriptionEntitled`
    = status `active|trialing` **and** `now < expiresAt` (cancelling: hard stop; renewing:
    +24h grace for a late renewal webhook). `planService`, `getAccountLimits`, `isPro` and
    the profile's `entitled` flag all use it, so a plan ends on time even if Stripe's
    webhook never arrives. Never test `subscriptionStatus === 'active'` alone.
  - **Stored state changes only on Stripe's word**: webhooks pass just the subscription id;
    `reconcileById` re-reads the subscription from Stripe and applies it to the org whose
    `stripeSubscriptionId` matches (conditional write; no customer→user fallback). Also
    triggered on demand by `planCheck`/profile once `expiresAt` passes, and by a 5-minute
    sweep in `jobs/cleanupJob.js`.
  - **Downgrade** (`downgradeOrgToFree`, the only one) makes the org look never-purchased:
    plan fields null, `scanLimit/scansUsed` 0, `seatsAllowed` 1, members' legacy User plan
    fields cleared, schedules disabled, pending invites expired. **Purchased credits are kept.**
  - Stripe API is pinned in `config/stripe.js` (`2026-05-27.dahlia`): billing period is on
    `subscription.items.data[]`, an invoice's subscription on
    `invoice.parent.subscription_details`. The helpers read old and new shapes.
  - Before deploying: `node scripts/backfillSubscriptionIds.js` (dry run; `--apply` writes).
- **Checkout safety** (`routes/stripeRoutes.js`):
  - An org with a subscription that has not ended (`hasLiveSubscription` — active, scheduled
    to cancel, past_due, unpaid) cannot start a second one (`409 ALREADY_SUBSCRIBED`), and a
    trial it buys is a **top-up** that never detaches the subscription. Otherwise the old
    subscription would keep billing with nothing attached.
  - A completed session is applied through `applyCheckoutOnce` (claim `checkout:<id>` in
    `StripeEvent`): the webhook and the post-redirect sync call race, and without the claim
    they created two orgs. The loser gets 500 (webhook → Stripe retries) or
    `409 CHECKOUT_PROCESSING` (sync → the page polls). Abandoned claims are taken over after 5 min.
  - Price ids come only from `STRIPE_PRICE_*`; an unset one is `503 PLAN_NOT_CONFIGURED`.
  - The webhook is mounted in `server.js` with `express.raw()` **outside** `apiLimiter`
    (Stripe's delivery bursts must not be answered 429); the signature authenticates it.
- `ScanResult` documents carry a **7-day TTL**, so they cannot be used to compute monthly
  usage. `Organization.scansUsed` is authoritative.
- **Superadmins scan without restriction** — `isQuotaExempt(user)` in
  `utils/quotaExemption.js` (`systemRole === 'superadmin'` only; plain `admin` is not exempt).
  `planCheck` lets them through with or without an org and sets `req.quotaExempt`, which
  makes the standalone routes skip their inline charge and swaps `scanLimiter`'s plan budget
  (20/10 min) for **one scan start per minute** (`exemptScanLimiter`, one store shared by
  every scan-start route — an external scanner accepts 1 request/min). `combinedScanLimiter`
  applies to them as to everyone. `claimScanSlot` admits them as `admittedBy: 'exempt'` (excluded from other
  members' rank count); `finalizeSuccessfulScan` settles them as `quotaSource: 'exempt'`
  without charging (only `totalScansAllTime` moves). `getAccountLimits` returns
  `scansPerMonth: -1`, `maxSchedules: -1`, `vulnerabilityAccessLevel: 'all'`. Any
  `User.findById(...).select(...)` feeding `getAccountLimits` must include `systemRole`.
  Tests: `backend/tests/quotaExemption.test.js` + the superadmin cases in `billingInvariants`.

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
