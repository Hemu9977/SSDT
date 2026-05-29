# Boost Score — Roadmap to 80/100 for Japanese Clients

**Current score:** ~60/100 (solid bilingual MVP, not yet enterprise-grade for JP).
**Target:** ≥ 80/100 next session.
**Baseline already merged to `main`:** audit blocker + 7 warnings (commit `7e5f4af`,
see `AUDIT_FIXES.md`).

## How the score breaks down
| Axis | Now | Why |
|------|-----|-----|
| Localization (JP/EN reports, translation, ¥ pricing) | ~80 | Genuine strength, keep it |
| Trust / compliance / data-handling | ~45 | The drag — this is where we win the +20 |
| Correctness / billing reliability | ~70 | Lifted by the merged audit fixes |

To reach 80 we mostly lift the **trust / data-handling** axis. Items below are ordered
by **score-impact ÷ effort**. Each is tagged `[+N]` = approx points toward the target,
`(effort)`.

---

## Phase 1 — Quick wins (target: 60 → 72)

### 1. urlscan.io: force private/unlisted scans `[+5]` (S)
**Why:** This is the single biggest JP red flag. urlscan public scans expose the
client's site (URL, screenshot) to a public, searchable feed. For a *security* tool that
is unacceptable to Japanese clients handling 機密情報.
**Do:** In `backend/services/urlscanService.js`, ensure the submit call sends
`visibility: 'unlisted'` (or `'private'` with an API key) — never `'public'`. Add a test
that asserts the payload visibility.

### 2. SSRF guard on ALL scan routes `[+4]` (S)
**Why:** `virustotalRoutes.js` already blocks private IPs / cloud metadata via
`BLOCKED_HOST_PATTERNS` + `isValidUrl` (lines ~48–78) — but the **direct** routes only do
`new URL(url)`: `zapRoutes /scan`, `webCheckRoutes /scan`, `pageSpeedRoutes /analyze`,
`zapAuthRoutes /scan`. A user can point those at `169.254.169.254` or internal hosts.
**Do:** Extract `isValidUrl` / `BLOCKED_HOST_PATTERNS` into `backend/utils/urlGuard.js`
and call it in every scan route's validation block (right where the W5 refunds were added).

### 3. Distributed rate limiting (Redis store) `[+3]` (M)
**Why:** `express-rate-limit` is in-memory. On multi-task ECS the limits are per-instance,
so they're effectively bypassable behind the load balancer — a real security gap, not just
hygiene.
**Do:** Add `rate-limit-redis` + a Redis/ElastiCache connection; wire it as the `store`
for all limiters in `backend/middleware/rateLimiter.js`. Falls back to memory in dev.

### 4. Secrets out of `.env` → AWS Secrets Manager / SSM `[+2]` (M)
**Why:** JP security reviews check secret handling. `JWT_SECRET`, Stripe keys, Gemini keys
should not live in plaintext env on the box.
**Do:** Load secrets at boot from Secrets Manager; document rotation. Keep `.env.example`
as the contract.

---

## Phase 2 — Enterprise trust (target: 72 → 80)

### 5. MFA / 2FA (TOTP) `[+3]` (M)
**Why:** Email OTP at signup is not MFA. JP enterprise expects authenticator-app 2FA.
**Do:** Add TOTP (e.g. `otplib`) enrollment + verification on login; store the secret
encrypted; add recovery codes.

### 6. Audit logging `[+3]` (M)
**Why:** Required for ISMS/ISO 27001 conversations. Log security-relevant events: login,
invite sent/accepted, role change, plan change, scan started, subscription change.
**Do:** New `AuditLog` model + a small `logAudit()` helper called from auth, orgRoutes,
stripeRoutes, planCheck. Make it queryable per-org for admins.

### 7. Data-residency + third-party egress statement `[+2]` (S/M)
**Why:** JP clients ask "where does my data go?" Today scan data egresses to Gemini
(Google, US) and urlscan.io.
**Do:** Pin MongoDB Atlas + AWS to `ap-northeast-1` (Tokyo). Document the data-flow and
which fields leave the region (note: `geminiSanitizer.js` already redacts target URL/IP/
domain before Gemini — cite that as a control). Add a DPA / 個人情報 handling note.

### 8. JP billing formalities `[+2]` (M)
**Why:** インボイス制度 (qualified invoice), 消費税 10%, and bank-transfer/請求書 payment
are commonly required by JP companies.
**Do:** Enable Stripe Tax (JP consumption tax) + invoice PDFs with the company's
登録番号; optionally support bank transfer.

### 9. Automated tests + CI security gates `[+2]` (M)
**Why:** Confidence + a visible quality bar.
**Do:** Unit tests for `consumeScan` target caps and `refundScan` (the W5/W6 work);
authz tests (no cross-org scan access). Add CI: `npm audit`, Dependabot, secret scanning,
a SAST step.

---

## Stretch (beyond 80, for GA / larger contracts)
- SSO / SAML for enterprise orgs.
- Short-lived JWT access tokens + refresh + revocation (currently 7-day, no revocation).
- Field-level encryption for PII; request-body schema validation (zod/Joi) everywhere.
- Third-party penetration test before GA.
- Restrict `/api/stripe/webhook` from the shared `apiLimiter`; assert `event.livemode`.

---

## Suggested order for next session (fastest path to 80)
1. #1 urlscan private  →  #2 SSRF guard  →  #9 tests for the merged W5/W6 work (cheap, high trust)
2. #3 Redis rate limit  →  #4 secrets manager
3. #5 MFA  →  #6 audit logging  →  #7 residency doc
4. #8 JP invoicing/tax

Hitting Phase 1 + items #5–#7 of Phase 2 should clear 80.

_Last updated: 2026-05-30. Companion to `AUDIT_FIXES.md`._
