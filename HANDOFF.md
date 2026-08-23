# Handoff — admin dashboard, Gemini masking, landing page

**Branch:** `main` · **Written:** 2026-08-22

Three feature branches were merged and reviewed, and several defects found
during that review were fixed. This is what landed, what is actually verified,
and — more importantly — what is not.

> **Read this first:** nothing here has been run against a database, a scanner
> container, or a real API key. **No email has ever actually been sent.** Every
> claim below is from static analysis, unit tests, or handler-level execution
> with stubbed models. The manual checklist in §4 is not optional.

---

## 1. Before you can use any of it

The platform has **no admins**. Run both, from `backend/` (they resolve `.env`
relative to that directory):

```bash
cd backend
node scripts/backfillSystemRole.js          # existing users have no systemRole
node scripts/makeAdmin.js you@example.com superadmin
```

`makeAdmin.js` defaults to plain `admin` for **any** second argument that isn't
exactly `superadmin`. Get it right the first time: only a superadmin can grant
or revoke admin roles, so a plain admin cannot promote anyone — including
themselves — and recovery means re-running this script on the server.

The backfill matters because the admin API reads users with `.lean()`, which
bypasses Mongoose's default injection: documents created before `systemRole`
existed come back `undefined` until it runs.

---

## 2. What landed

| Area | Change |
|---|---|
| Admin dashboard | `systemRole` (`user`/`admin`/`superadmin`) + `isDisabled` on User and Organization; `routes/admin.js` (12 endpoints); `pages/Admin/*`; `RequireAdmin.jsx` route guard |
| Access control | Superadmin hierarchy; `isDisabled` enforced on **every** request (30s cache, invalidated directly by admin mutations); Socket.IO handshake gated and live sockets evicted |
| Session revocation | `User.tokensValidFrom`, stamped by a password reset and checked in `middleware/auth.js` |
| Password reset | `/forgot-password`, `/reset-password`, `/resend-otp` implemented — they were stubs returning success while doing nothing |
| Gemini masking | Compressed IPv6, emails and dotless internal hostnames were reaching the LLM; the same pattern also over-redacted HTTP `Date` headers |
| i18n | All 66 backend error codes now carry a stable `code` mapped to a translated string |
| Landing page | `MarketingHome` replaced the splash screen; `Dashboard.jsx`, `sidebar.jsx`, `SplashScreen.jsx`, `About.jsx` deleted; `/about` and unmatched paths redirect to `/` |

### Defects found and fixed during review

- **The admin panel was unreachable.** `UserContext` fetches the profile once on
  mount and sits above `BrowserRouter`, so a freshly-logged-in admin arrived at
  `/admin` with `user` still null and was bounced to `/login`. Nothing rendered
  `Sidebar` either, so its admin link appeared nowhere.
- **`GET /api/admin/scans` shipped every customer's full vulnerability payload**
  to the browser — `zapResult` and `webCheckResult` were selected and spread but
  never read by anything.
- **Compressed IPv6 leaked to Gemini** (`fe80::1`, `::1`), and `assertNoLeakage`
  was blind to the same shapes even with `GEMINI_STRICT_GUARDRAIL=true`.
- **Session revocation locked users out of their own reset.** `jwt.sign` floors
  `iat` to the second while `tokensValidFrom` is millisecond-precision, so a
  login in the same second as the reset was rejected as revoked.
- **`JoinOrganization` branched on `data.error.includes('already a member')`** —
  control flow driven by the wording of an English server string.

---

## 3. What is verified, and how

```bash
cd backend  && npm test                                     # 117 tests
cd frontend && CI=true npx react-scripts test --watchAll=false   # 39 tests
cd frontend && CI=true npx react-scripts build              # clean, warnings-as-errors
```

None of these need credentials, Docker, or a running server.

- `backend/tests/passwordReset.test.js` and `orgInviteLockout.test.js` **execute
  the real route handlers** against a stubbed model layer.
- `geminiSanitizer*.test.js` covers redaction and over-redaction. The leak-vector
  tests were checked against the pre-fix code: 11 of them fail there, so they
  test behaviour rather than passing vacuously.
- `adminApiInvariants.test.js` includes a census asserting every `jwt.sign` is
  gated and every independent `jwt.verify` checks disabled state — that is what
  catches a future token path bypassing the lockout.
- The frontend suite is static: route guard decision table, import resolution,
  locale parity, and that no backend string reaches the UI.

**Coverage is honest, not complete:** 10 of 14 changed backend files are
exercised. `routes/profile.js` and the two ops scripts are not.

---

## 4. What you need to test manually

Ordered by how much breaks if the change was wrong.

1. **Auth flows.** 48 backend responses and 31 frontend render sites were
   rewritten to use structured codes. A wrong code degrades to a generic
   message rather than throwing, so nothing crashes — you have to *read* what
   appears. Register a duplicate email, log in with a wrong then right password,
   submit a bad then good OTP, accept an invite (then a used one, then an
   expired one). Re-run the whole sequence with the language toggle, and switch
   language **while an error is on screen**.
2. **Password reset, end to end.** This is the one thing no test here can cover.
   Request a reset, confirm the mail actually arrives, follow the link, set a
   new password — then confirm the **old session is rejected** (`SESSION_REVOKED`).
3. **AI reports and PDFs.** The sanitizer regexes sit in front of every prompt.
   Run a real scan, read the report for over-redaction — technology and version
   findings should survive, timestamps should still look like timestamps — and
   download both language PDFs.
4. **Login → `/admin`.** The P0 above was fixed by reasoning, never clicked.
   Log in as superadmin (should land on `/admin` with no bounce), hard-reload
   `/admin`, then try `/admin` as an ordinary user.
5. **Disable a user, then an org.** With the target logged in elsewhere and a
   scan streaming: their next API call should 403 and the socket should drop.
   Watch the network panel, not just the UI. Then try disabling the org holding
   the last administrator — it should refuse with `ADMIN_LAST_ADMIN_ORG`.
6. **Admin scans + organizations tabs.** Both projections were narrowed; a
   projection that drops one field too many renders a blank cell, not an error.
7. **Light theme across the admin panel.** Flagged as unverifiable without a
   browser from the start. No test can see a contrast failure.

Two things that will look like bugs and are not:

- The disabled-state cache is **per process** with a 30s TTL. Admin mutations
  invalidate it directly, so revocation is immediate on the task that served the
  request; another ECS task picks it up within 30s. Test against a single task
  or allow the window.
- The auth middleware **fails open on a database error**, logging and allowing
  the request, so a transient Mongo blip cannot lock everyone out at once. A
  revocation that appears not to take could be a DB error — check the logs.

---

## 5. AWS — nothing blocking

No AWS change is required. Reset email uses the same `sendEmail()` path as the
OTP mail already working in production: `iam-policies.json:65-68` grants
`ses:SendEmail`/`ses:SendRawEmail`, and `backend-task-def.json` already sets
`AWS_REGION=ap-northeast-1`, `SES_FROM_EMAIL=fortexa@aevus.jp` and
`FRONTEND_URL=https://fortexa.aevus.jp`, so reset links resolve to production.

Worth your time, none of it blocking:

1. **Confirm SES is out of the sandbox** in `ap-northeast-1` and that
   `fortexa@aevus.jp` is verified. In sandbox SES only delivers to verified
   addresses and reset mail fails silently. This already applies to today's OTP
   mail — if registration OTP arrives in production, reset will too.
2. **Dead config in `backend-task-def.json`:** `SES_SMTP_USER`, `SES_SMTP_PASS`
   (from Secrets Manager), `USE_AWS_SES`, `SES_FROM`, `SES_HOST`, `SES_PORT` are
   read by nothing — `emailService.js` only reads `SES_FROM_EMAIL` and
   `AWS_REGION`. Leftovers from an SMTP-based design; harmless but misleading.
3. **`.github/workflows/frontend-deploy.yml` sets `CI: false`** to tolerate lint
   warnings. The build is now clean at `CI=true`, so that line can go whenever
   you want warnings enforced. Note this workflow **auto-deploys to S3 +
   CloudFront on any push to `main` touching `frontend/**`.**

---

## 6. Billing and quota defects — RESOLVED

> **Update (2026-08-22, follow-up batch).** All four defects below are fixed, and the
> smaller loose ends are cleared. Two claims in the original write-up were wrong; they are
> corrected in place. `backend/tests/billingInvariants.test.js` (28 tests) now covers this
> area — it did not exist when this section was written.

### The four defects, and what was done

**1. Concurrent scans could exceed the monthly cap.** — **Fixed.**
`planCheck` stays advisory; `planService.claimScanSlot()` is the new authoritative check,
called by every scan-start path immediately after the `ScanResult` is created. It admits a
scan only if the count of the org's in-flight scans with a **lower `_id`** is below its
remaining capacity (subscription allowance + live credits).

A reservation counter was considered and rejected: it needs a release on every failure
path, and a leaked reservation locks a paying customer out of their own plan — strictly
worse than the over-delivery it fixes. Deriving rank from documents that already exist
leaves nothing to leak; the stale-scan watchdog frees a wedged scan’s slot for free.

This required `ScanResult.organizationId` to actually be written. It was declared and
indexed but **set by nothing anywhere in the repo**, so the rank query would have matched
zero documents and admitted everything. All four creation sites now stamp it.

**2. Auth scans may never be billed.** — **Fixed.** The defect was real; the explanation
given here was not.

This section claimed a successful auth ZAP "has already charged the quota by this point
(zapAuthService)". It had not. `zapAuthService` called `finalizeSuccessfulScan` immediately
after writing `status: 'combining'`, and that function returns early unless the status is
`completed` — **that call was a no-op.**

What actually billed an auth scan was `checkAndGenerateGemini`, triggered by
`zapAuthService` on ZAP completion and by `webCheckService` on WebCheck completion.
`zapAuthService` copies `authScanResult` into `zapResult`, so its readiness check passed and
it charged on its own completion path.

So auth scans were billed **non-deterministically**, not never: the background completion
service charges, the status-poll route's inline block does not, and both could run for the
same scan. Whether the customer paid depended on which reached the write first. Once the
poll route had set `refinedReport`, *later* `checkAndGenerateGemini` invocations
short-circuited and never charged — though one already in flight continued and did.

An earlier draft of this update said auth scans "have never been billed". That was wrong,
and wrong in the direction that matters: it would have you expecting a uniform revenue
increase from this fix rather than the removal of a coin-flip.

The ~80-line inline Gemini block in the status route is gone; the route now triggers
`checkAndGenerateGemini` like every other completion path. `finalizeSuccessfulScan` is
called from `geminiCompletionService` **only**, for both flows, and a census test enforces
that — a second billing site is exactly how this defect arose.

**A further unbilled path, not in the original list.** `schedulerService.finalizeRunningScans`
— the 2-minute poller that finishes scheduled scans — was a *fourth* re-implementation of
Gemini completion. It wrote `refinedReport` + `status: 'completed'` directly, so scheduled
scans it finished were never charged, it raced `checkAndGenerateGemini` (which then
short-circuited on the report it found), and it sent alerts to the LLM **without the plan's
severity filter** and without loading WebCheck full results from GridFS. It now delegates
like every other path.

**A scan with a failed WebCheck was delivered free — also fixed.** This one was a
contradiction between two files rather than a duplicated path.
`geminiCompletionService` treats a failed WebCheck as explicitly **non-fatal**: the scan
completes, the AI report is generated, and that section renders N/A. But
`finalizeSuccessfulScan` then refused the charge on `webCheckResult.status === 'failed'`.
So the customer received a complete report and the org was never billed. The guard is gone;
billing now follows the completion policy instead of second-guessing it.

**The resulting rule, which is now the whole of it:** a scan is charged if and only if it
reached `completed`, and it reaches `completed` if and only if the vulnerability assessment
produced results. Everything else — WebCheck, PageSpeed, Observatory, even Gemini itself
falling back to a structured report — degrades the report without voiding the sale. If you
ever want a failed phase to void the sale, make it stop the scan completing; do not add a
second opinion in the billing path. `billingInvariants.test.js` asserts the two files agree.

Consequence worth knowing, agreed before implementing: a scan that never reaches a completed
report is **no longer charged**. Previously the normal flow charged at ZAP completion
(`zapService.js`), so it billed for scans that never produced a report.

**3. `finalizeSuccessfulScan` was check-then-act.** — **Fixed.**
It now claims `quotaConsumed` with an atomic `findOneAndUpdate` *before* charging, and
releases the claim if `consumeScan` declines — so a decline cannot silently deliver a free
scan. The resolved pool (`subscription` / `credit` / `legacy`) is persisted to
`ScanResult.quotaSource` for support.

**4. Plan pricing was hand-duplicated.** — **Fixed. It was five places, not four**:
`MarketingHome.jsx` carried a fifth copy. Now `backend/config/planCatalog.js` is the single
source — `PLAN_LIMITS`, Stripe provisioning and the admin revenue figures all derive from
it. The frontend keeps a deliberate mirror at `frontend/src/config/planCatalog.js` (a
pricing endpoint would put a network call in front of the signed-out landing page), and a
test reads the backend file off disk and fails if the two disagree.

The tax rate remains genuinely unenforceable: `TAX_RATE` in `Profile.jsx` must match the
Stripe Tax Rate object behind `STRIPE_TAX_RATE_ID`, which no code can read. Comments warn;
nothing checks.

**Also found while doing this:** `refundScan` has **no callers anywhere**, despite a comment
in `virustotalRoutes.js` claiming the error path refunds a gated slot. It is kept (a Stripe
refund handler will need a refund primitive) but is now documented as unused, and flagged as
unsafe for credit-funded scans until it takes a batch id.

Still **correct** and untouched: Stripe webhook idempotency (atomic claim before side
effects), signature verification, raw-body mount ordering, and the cancellation →
free-tier fallback.

### Smaller loose ends — cleared

- **Orphaned locale keys: 72 removed** from `en.js` and `ja.js` in lockstep (not ~21 as
  estimated here). A naive scan reports 113; ~30 of those are false positives because
  `MarketingHome.jsx` builds keys dynamically (`` t(`aboutFeature${key}Title`) ``). The
  detector used an explicit allowlist for those prefixes. Both files now have zero orphans,
  zero duplicates, and no ja-only key.
- **Two WebCheck endpoints removed**: `/types` and `/save-results`. The latter took a
  client-supplied `results` object and wrote it onto the scan document with no shape
  validation, so this removed an unused write path as well as dead code.
- **Four orphaned frontend files deleted** — plus `ScanCompletionPopup.scss`, which only
  that component imported. Note `context/LanguageContext.js` is **not** dead despite
  appearing so: `contexts/TranslationContext.jsx` is a re-export shim over it, and it is the
  live implementation.
- `Admin.scss` light theme — **deliberately not touched.** No static change can confirm a
  contrast result; see checklist item 7.

---

## 7. Documentation

`CLAUDE.md` had four provably wrong claims, now corrected: `TASK 7` was
unchecked though the admin panel ships; `GEMINI_MODEL`/`gemini-3-flash` do not
exist (it is `GEMINI_MODEL_PRO`/`GEMINI_MODEL_FLASH`, `gemini-2.5-*`); the scan
API was documented at `/api/vt` when it is mounted at `/api/scan`; and the quota
note claimed `profile.js` used a server-local month boundary when it already
uses `Date.UTC` — the doc described a bug that had been fixed without it.

`README.md` repeated the endpoint error. `AUDIT_FIXES.md` W3 described the
Gemini guardrail as defaulting to `off` in production, which would have left you
believing production skips the leak check; it is now marked superseded.

If you change plan pricing, an error code, or a route mount, update `CLAUDE.md`
in the same commit — it is what the next agent or engineer reads first, and this
handoff exists partly because it had drifted.
