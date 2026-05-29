# Audit Fixes — SHRAVYA merge (`ee8bebc..f50bfa2`)

**Branch:** `fix/audit-warnings` (off `main` @ `f50bfa2`)
**Started:** 2026-05-30
**Purpose:** Track and fix the blocker + warnings from the merge audit. This file is the
resume point — if a session is cut short (rate limit), read this file to see exactly what
is done, in progress, and pending.

## Status legend
- ⬜ TODO — not started
- 🟦 IN PROGRESS — partially done
- ✅ DONE — code changed + self-verified
- 📝 DOC-ONLY — resolved as a documented decision (no code change, or doc change only)
- ⏭️ DEFERRED — intentionally out of scope (explained)

## Progress summary
| # | Item | Severity | Status |
|---|------|----------|--------|
| B1 | `cancel-subscription` reads stale `user.stripeSubscriptionId` | BLOCKER | ✅ |
| W1 | Webhook idempotency TOCTOU (record created after processing) | WARNING | ✅ |
| W2 | `.env.example` missing all `STRIPE_*` + `GEMINI_STRICT_GUARDRAIL` | WARNING | ✅ |
| W3 | Gemini leakage guardrail off by default / assert scope | WARNING | ✅ |
| W4 | Invite token not bound to invited email (logged-in acceptor) | WARNING | ✅ |
| W5 | Scan quota consumed at gate, no refund on early failure | WARNING | ✅ |
| W6 | `targetsPerMonth` / `scansPerTarget` not enforced | WARNING | ✅ |
| W7 | `free`/expired plans get `'all'` vulnerability access | WARNING | ✅ |

**All items complete.** Syntax-checked (`node --check`) + functional spot-checks pass.

---

## B1 — `cancel-subscription` stale read (BLOCKER)
**File:** `backend/routes/stripeRoutes.js:161-186`
**Problem:** Webhook writes subscription ID only to `org.stripeSubscriptionId`
(`:353`, `:401`); `cancel-subscription` reads `user.stripeSubscriptionId` (`:166`,
`:171`), which is never set in the new org flow → every new subscriber gets
`400 "No active subscription found"`.
**Fix:** Load the org via `user.organizationId` and use `org.stripeSubscriptionId`
(fallback to `user.stripeSubscriptionId` for legacy pre-migration accounts).
**Status:** ✅ DONE — `stripeRoutes.js:161-195`. Resolves
`subscriptionId = (org && org.stripeSubscriptionId) || user.stripeSubscriptionId`.

## W1 — Webhook idempotency TOCTOU (WARNING)
**File:** `backend/routes/stripeRoutes.js:226-291`
**Problem:** `StripeEvent.findOne` check (`:227`) and `StripeEvent.create` (`:283`)
straddle the processing switch. Concurrent duplicate deliveries can both pass the
check and double-process (e.g. reset `scansUsed = 0` twice).
**Fix:** Claim-first — `StripeEvent.create` BEFORE processing; duplicate-key (11000)
→ treat as already processed, return `{received:true}`. On processing error, DELETE
the claim and return 500 so Stripe retries.
**Status:** ✅ DONE — `stripeRoutes.js`: claim via `StripeEvent.create` before the
switch (11000 → skip), removed the trailing post-process `create`, added
`StripeEvent.deleteOne` in the catch to release the claim on failure.

## W2 — `.env.example` missing Stripe vars (WARNING)
**File:** `backend/.env.example`
**Problem:** No `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_*`, nor
`GEMINI_STRICT_GUARDRAIL`. Stripe routes silently disabled if `STRIPE_SECRET_KEY`
unset (`server.js:76,96`).
**Fix:** Add a documented Stripe section (secret, webhook secret, all 8 price IDs) +
`GEMINI_STRICT_GUARDRAIL` with its caveat.
**Status:** ✅ DONE — `.env.example`: added Stripe section (`STRIPE_SECRET_KEY`,
`STRIPE_WEBHOOK_SECRET`, 8 `STRIPE_PRICE_*`) and `GEMINI_STRICT_GUARDRAIL` with caveat.

## W3 — Gemini guardrail off by default (WARNING)
**File:** `backend/services/geminiSanitizer.js:207-222`, `geminiService.js:580`
**Problem:** `assertNoLeakage` is a no-op unless `GEMINI_STRICT_GUARDRAIL==='true'`;
it's the only runtime backstop if a caller forgets `sanitizeScanForLLM`.
**Investigation note:** Auto-enabling in prod is UNSAFE — legitimate URLs appear in
ZAP `reference` fields (OWASP doc links) and in CSP/Location header values passed to
`refineReport`, which would false-positive and break report generation. The author's
choice to assert on `scanDataText` (identity-bearing fields only) in
`formatScanDataForPdf` is therefore correct, not a bug.
**Fix:** Enable the guardrail by DEFAULT in non-production (dev/test/CI) so leaks are
caught during development, keep it opt-in for production, and document the caveat.
**Status:** ✅ DONE — `geminiSanitizer.js`: added `_guardrailMode()` →
`'throw'` (flag=true) / `'warn'` (unset + non-prod) / `'off'` (flag=false or prod).
Warn mode logs without breaking reports (avoids false-positives on reference/CSP URLs).
Left the `formatScanDataForPdf` assert on `scanDataText` (correct: full prompt embeds
legit OWASP reference URLs in detailedAlerts).

## W4 — Invite not bound to invited email (WARNING)
**File:** `backend/routes/orgRoutes.js:186-242`
**Problem:** Logged-in acceptor path assigns the JWT user to the org without checking
`user.email === invite.email`. A logged-in user with a different email who holds the
token can consume the invite/seat.
**Fix:** In the logged-in branch, reject with 403 if
`user.email.toLowerCase() !== invite.email.toLowerCase()`.
**Status:** ✅ DONE — `orgRoutes.js` accept-invite: added email-match guard before
org assignment. Because the invite is atomically flipped to `accepted` at the top of
the handler, the mismatch path now reverts it to `pending` so the real invitee can
still use it.

## W5 — Scan quota not refunded on early failure (WARNING)
**Files:** `backend/middleware/planCheck.js`, `backend/services/planService.js`,
scan route handlers.
**Problem:** `consumeScan` increments usage at the gate before the scan starts; an
invalid-URL `400` or duplicate `409` after the gate permanently burns a slot.
**Fix:** Add `refundScan(orgId, billingCycle)` to planService (reverses the exact
increment). `planCheck` attaches `req.refundScan()`. Scan handlers call it on
pre-scan early returns / errors.
**Status:** ✅ DONE.
- `planService.js`: added `refundScan(orgId, billingCycle)` (mirrors consumeScan, underflow-guarded).
- `planCheck.js`: attaches idempotent one-shot `req.refundScan()`.
- Wired into pre-scan failure paths: `virustotalRoutes` /combined-url-scan (invalid/missing URL + catch),
  `zapAuthRoutes` /scan (4 validation returns + sync catch), `zapRoutes` /scan (2 validation returns + sync catch),
  `webCheckRoutes` /scan (3 validation returns), `pageSpeedRoutes` /analyze (missing URL).
- Deliberately NOT refunded on mid-scan external-API errors (webCheck/pageSpeed catch) — the scan actually ran;
  refunding there would let users dodge quota by forcing failures.

## W6 — Target limits not enforced (WARNING)
**Files:** `backend/services/planService.js`, `backend/middleware/planCheck.js`,
`backend/models/Organization.js`.
**Problem:** `consumeScan` only checks `scansUsed < scanLimit`. `targetsUsed` is
incremented but never checked (and counts scans, not distinct targets);
`scansPerTarget` (annual plans) is unenforced.
**Fix:** Track distinct targets + per-target counts on the Organization, pass the
target into `consumeScan`, enforce `targetsPerMonth` and `scansPerTarget`.
**Status:** ✅ DONE.
- `Organization.js`: added `targetScanCounts` Map (key = sha1 of normalized hostname —
  hashing avoids illegal `.`/`$` in Mongo map keys / dotted `$inc` paths).
- `planService.js`: `consumeScan(orgId, {target, scansPerTarget, targetsPerMonth})` now
  enforces distinct-target cap (`-1`/`null` = unlimited) and per-target cap (`null` =
  unlimited); the per-target counter advances in the SAME atomic `$inc` as `scansUsed`
  so it never drifts. Monthly reset clears the map.
- `planCheck.js`: loads the org, derives limits via `getAccountLimits(org)`, extracts the
  target (`req.body.url || req.body.targetUrl`), passes both to consume + refund.
- `refundScan` also reverses the per-target counter.
- Stripe checkout/renewal clear `targetScanCounts` alongside `scansUsed`.
- **Known limitation:** the distinct-target check is read-then-write (not a single atomic
  op). The per-user 1-scan/min combined limiter makes a same-org race practically
  impossible; documented rather than adding a transaction.

## W7 — `free`/expired → `'all'` vuln access (WARNING)
**File:** `backend/models/User.js:194` (+ `resolveVulnAccessLevel` callers)
**Problem:** `PLAN_LIMITS.free.vulnerabilityAccessLevel === 'all'`, so an org whose
plan was nulled on cancellation shows ALL severities on historical scans.
**Fix:** Make the no-active-plan default restrictive (`'critical-high'`), consistent
with `vulnFilter.DEFAULT_LEVEL`.
**Status:** ✅ DONE — `User.js`: `PLAN_LIMITS.free.vulnerabilityAccessLevel`
`'all'` → `'critical-high'`. A canceled/expired org (planType nulled) now falls back to
the most restrictive level. Paid tiers unchanged (Light already `critical-high`,
Basic/Pro/trial2 `all`).
**Behavior note:** genuine free/no-plan accounts now see only Critical+High on historical
scans. Intended (product is org/paid-only); flag if a free tier should keep full access.

---

## Files changed
- `backend/routes/stripeRoutes.js` — B1, W1, W6 (target reset)
- `backend/routes/orgRoutes.js` — W4
- `backend/routes/virustotalRoutes.js`, `zapAuthRoutes.js`, `zapRoutes.js`,
  `webCheckRoutes.js`, `pageSpeedRoutes.js` — W5 (refunds)
- `backend/middleware/planCheck.js` — W5, W6
- `backend/services/planService.js` — W5 (refundScan), W6 (consumeScan + target caps)
- `backend/services/geminiSanitizer.js` — W3
- `backend/models/Organization.js` — W6 (targetScanCounts)
- `backend/models/User.js` — W7
- `backend/.env.example` — W2

## Verification done
- `node --check` on all 12 modified backend JS files → all OK.
- Functional spot-checks: guardrail modes (throw/warn/off), target hostname
  normalization + collision-free hashed keys, planService loads cleanly → all PASS.
- NOT run: full app boot, DB integration, frontend build, live Stripe webhook. Those
  need a running stack and are recommended before merge.

## Suggested follow-ups (not done — out of the warning scope)
- Add automated tests for `consumeScan` target/per-target caps and `refundScan`.
- Consider a Mongo transaction or conditional update to make the distinct-target
  check fully race-proof if direct (non-combined) scan routes ever drop the 1/min limiter.

## Change log (most recent first)
- 2026-05-30: Fixed all 8 items (B1, W1–W7) on `fix/audit-warnings`. Syntax + functional
  checks pass. Tracking file finalized.
- 2026-05-30: Created branch `fix/audit-warnings`, wrote this tracking file.
