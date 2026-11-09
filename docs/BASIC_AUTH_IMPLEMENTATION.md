# HTTP Basic Authentication: Phase 1 implementation report

**Branch:** `feature/basic-auth-phase1`, based on `main` at `4a58c7f`.

**Status:** implemented and tested. **Not deployed.** Nothing in AWS was changed.

**Readiness: ready for code review and a staging run. NOT ready for a production deploy** until the staging checks in §8 pass and the deploy is approved.

Phase 0 (proof of concept, 2026-11-08) recommended GO WITH CHANGES. This branch implements those 14 changes. Every Phase 0 finding cited here was measured on the production ZAP image `ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47…` (ZAP 2.17.0).

---

## 1. Checklist: the 14 required changes, in implementation order

| # | Change | Stage | Status |
|---|---|---|---|
| 5 | Redact `Authorization` / `Proxy-Authorization` / `Cookie` / `Set-Cookie` values at capture; scrub exact secrets from alerts and the ZAP HTML report | A | Done |
| 7 | Never log whole error objects (axios errors carry request config) | A | Done (`server.js` global handler) |
| 4 | Revoke on every exit: stop all scans → remove rules → `newSession` | A | Done; leftover rules also purged at start |
| 1 | Pin the ZAP image by digest | A | Done in compose and both task-def files (not registered in AWS) |
| 2 | ZAP API key on both instances | A | Done in repo config; the normal-instance probe now sends the key |
| 3 | Replacer: whole-origin regex, initiators `2,3,6,10`, per-scan name, POST | A | Done (Basic); the cookie rule also gets initiators + POST |
| 6 | Disable passive rule 10105 for Basic scans | A | Done; re-enabled on revoke |
| 8 | Origin-scoped CDP handler; never `page.authenticate` / `extraHeaders` | B | Done (`scopedBasicAuth.js`) |
| 9 | Handler wired into the real page capture | B | Done (`pageCapture.js`) |
| 10 | Real `runLighthouseAudit` uses a Puppeteer page for Basic scans | B | Done; the existing path is unchanged for every other scan |
| 11 | Observatory (and WebCheck) unauthenticated; disclosed | B | Done (UI notice + both PDFs) |
| 12 | Pre-flight probe + coverage classifier | B | Done (`basicAuthProbe.js`, `measureAuthCoverage`) |
| 13 | In-memory vault; `authSessions` TTL for Basic; origin binding | B | Done (Basic 15 min; form unchanged at 24 h) |
| 14 | One scan per ZAP instance | — | Unchanged: the existing `zap:lock:auth` lock |

---

## 2. What changed

### New files

| File | Purpose |
|---|---|
| `backend/utils/credentialRedaction.js` | Header-value redaction (keeps the scheme, cookie names and `Set-Cookie` attributes as evidence); exact-secret scrub; secret variants |
| `backend/services/zapCredentialRules.js` | Basic rule, origin regex, leftover-rule purge, 10105 toggle, revocation sequence, coverage measurement (ZAP search API: status codes only, no bodies) |
| `backend/services/scanCredentialVault.js` | In-memory credential store for one scan. Holders `zap` + `fast`; `purge`; 25 h TTL. The credential object refuses to be printed or JSON-stringified |
| `backend/services/basicAuthProbe.js` | Pre-flight check: HTTPS only; the SSRF guard on every hop; at most one authenticated chain; credentials only on the verified origin; header-injection input refused |
| `backend/services/inHouse/scopedBasicAuth.js` | CDP `Fetch.authRequired` handler: answers only server challenges from the exact target origin, once per request; everything else is cancelled |
| `frontend/src/__tests__/basicAuthInvariants.test.js` | Frontend invariants (codes mapped, locales, no engine names, schedule exclusion, password lifecycle) |
| `backend/tests/*` (7 files) + `tests/fixtures/tls` | See §4. The certificate is test-only and self-signed |

### Modified files

**Backend services:**
- `backend/services/zapAuthService.js`
  - Credentials only via `configureAuthContext(basic)`; the 10105 toggle.
  - Basic verification and coverage.
  - A single `finally` revocation replaces three duplicated cleanup blocks.
  - Secret scrubbing of alerts and the HTML report.
  - **Bug fix:** the spider loop swallowed cancellation (§3).
- `backend/services/zapService.js`: header redaction at capture (normal scans).
- `backend/services/authFastScanService.js`: for Basic scans, the performance audit and page capture run in-house with the scoped credential; external PSI/urlscan are skipped; Observatory and WebCheck are unchanged.
- `backend/services/inHouse/pageCapture.js`: optional `basicAuth`. Without it the behaviour is unchanged.
- `backend/services/inHouse/lighthouseAudit.js`: optional `basicAuth`. Uses a Puppeteer page and skips the CrUX lookup, which would send the URL to an external API. The `chrome-launcher` path is unchanged otherwise.
- `backend/services/pdfService.js`
  - `buildEvidenceText` redacts headers.
  - `renderAuthScopeNote` (EN/JA, no engine names) is drawn in both the full report and the vulnerability report for Basic scans.
- `backend/services/zapContainerManager.js`: the ephemeral-mode probe sends the API key.

**Backend routes and utilities:**
- `backend/routes/zapAuthRoutes.js`
  - `POST /test-basic`.
  - The Basic branch of `/scan`.
  - Session TTL per method.
  - Vault purge on provisioning, recycle, start and watchdog failures.
  - `authMethod` in the status responses.
- `backend/routes/scheduleRoutes.js`: refuses Basic (`BASIC_AUTH_MANUAL_ONLY`).
- `backend/utils/scanTargetGuard.js`: refuses URLs with userinfo (`URL_HAS_CREDENTIALS`).
- `backend/utils/vulnFilter.js`: `getSanitizedAlerts` redacts evidence. This is the chokepoint for the JSON export, both evidence endpoints and PDF findings, so legacy data is covered too.
- `backend/config/zapInstances.js`: the normal-instance probe sends `ZAP_API_KEY`.
- `backend/server.js`: the error handler logs the stack, not the error object.

**Frontend:**
- `AuthenticatedScanPanel.jsx`
  - Method choice in step 1; the form flow is the default and untouched.
  - Basic fields: user, password with show/hide, optional realm, optional verify page.
  - Step 3 summary for Basic.
  - Scope disclosure in the results.
- `apiErrors.js`, `en.js`, `ja.js` (34 keys each, own Japanese translations), `AuthenticatedScan.scss`.

**Infrastructure (repo files only):**
- `docker-compose.yml`: digest pin, a required `ZAP_API_KEY`, keyed health checks.
- `infrastructure/zap-task-def.json`, `zap-auth-task-def.json`: digest pin, `-config api.key="$ZAP_API_KEY"` from `fortexa-backend-secrets:ZAP_AUTH_API_KEY`, health check sends the key.
- `infrastructure/backend-task-def.json`: `ZAP_API_KEY` from the same secret.

**Docs:** `CLAUDE.md` (Basic flow, rules, tests) and this report.

### Behaviour changes to existing flows (please review)

These are deliberate security changes that also affect scans that are not Basic:

1. **Evidence display (all scans).** Cookie, `Set-Cookie` and `Authorization` header **values** now show as `[REDACTED]` in the evidence panel, PDF and JSON export, including for historical scans. Header names, the auth scheme and cookie attributes remain.
2. **Form-login scans.**
   - The cookie rule is sent by POST and limited to scanner initiators (`2,3,6,10`). Its URL scope is unchanged.
   - At the end of every scan, all scans are stopped and the ZAP session is discarded.
   - The injected session cookie values are scrubbed from stored alerts and the HTML report.
3. **Cancellation during crawling** now ends the worker immediately (bug fix, §3).
4. **Any scan route** refuses `https://user:pass@host` URLs.
5. **Local development:** `docker compose up` now requires `ZAP_API_KEY` in the root `.env`. The backend `.env` needs the same value as `ZAP_API_KEY` and `ZAP_AUTH_API_KEY`.

---

## 3. Defects found and fixed while testing

| Defect | Impact | Fix |
|---|---|---|
| **Spider loop swallowed `STOPPED_BY_USER`** (pre-existing). The progress update throws on cancel *before* the "spider finished" check, and the catch only logged it | A scan cancelled (or failed by the watchdog) during crawling kept polling for up to the spider's **2 h** limit. It held `zap:lock:auth`, blocking every other authenticated scan, and kept its credential rule in ZAP | Re-throw `STOPPED_BY_USER`, as the AJAX and active-scan loops already did. Covered by `basicAuthScanLifecycle` (cancelled and watchdog scenarios) |
| Form scans did not scrub injected cookie values from stored alerts or the HTML report | Session cookie values could be stored in GridFS when ZAP's cookie findings quote them | The injected cookie values (≥ 4 characters) become the scan's scrub secrets |
| `revokeScanCredentials` defaulted to re-enabling rule 10105 | A form scan's revocation would have flipped an instance-wide setting it never changed | Default `false`; only Basic scans re-enable it |

---

## 4. Test evidence

| Suite | Result |
|---|---|
| Backend `npm test` (existing 506 + new 64) | **570 / 570 pass**, 55 s |
| Frontend `CI=true react-scripts test` | **156 / 156 pass**, 7 suites |
| Frontend `CI=true react-scripts build` | Compiled successfully, no warnings |
| Live check of `zapCredentialRules` against the real production-digest ZAP (with API key) | 9/9 behaviours confirmed (one check's expected count was too strict; it swept a real leftover rule) |

### New backend tests and what each proves

**`credentialRedaction.test.js` (11):**
- header redaction, case- and spacing-preserving;
- cookie names and attributes kept;
- deep exact-secret scrub, including the rule-10105 `other` text and Buffers;
- legacy evidence redacted by `getSanitizedAlerts`;
- vault holders, purge and TTL;
- the vault can't be printed or JSON-stringified;
- concurrent scans don't see each other's credentials.

**`zapCredentialRules.test.js` (8):**
- the origin regex matrix from Phase 0 R.1/RCI.1 (slashless root, `:443`, uppercase host; never `:8443`, `http://`, subdomains, `@`-userinfo, suffix or query-string tricks);
- the rule sent by POST with initiators `2,3,6,10`;
- leftover-rule purge;
- revocation order;
- revocation never throws;
- the 10105 toggle;
- coverage verdicts (authenticated / degraded / failed / unknown).

**`basicAuthProbe.test.js` (14), on real local HTTPS servers:**
- E1 valid;
- E2 wrong password, exactly one attempt;
- E3 public page not "verified";
- E4 verify URL;
- E5 same-origin redirect;
- E6 cross-origin redirect before and after sign-in (0 credentials to the other server);
- E7 realm mismatch is a warning;
- E8 HTTP refused before any request;
- E9 403 before vs after sign-in;
- E10 URL credentials and an off-origin verify URL;
- Digest-only, redirect loop, odd status;
- injection input refused;
- the production SSRF guard refuses private targets.

**`basicAuthScanLifecycle.test.js` (11): the real `runAuthenticatedScanBackground` against a fake ZAP API.**

Scenarios:
- success;
- only-401 coverage;
- active-scan failure;
- user cancellation;
- watchdog timeout;
- storage failure;
- missing vault credential (fails closed: no rule, no crawl);
- form-login regression;
- two concurrent Basic scans with different credentials.

It asserts:
- every call carries the API key;
- the credential appears only in a POST body;
- 10105 is off during the scan and on afterwards;
- revocation in order on **every** exit, with 0 rules left;
- no secret in the scan record, the detailed-alerts file or the HTML report;
- the coverage verdict;
- the vault holder is released;
- no cross-scan credential mixing.

**`basicAuthOutputs.test.js` (6):**
- PDF evidence EN and JA never draws a credential, even from unredacted legacy data;
- the scope note renders in EN/JA with no engine names;
- the JSON export and evidence endpoints redact;
- alerts are scrubbed at capture (incl. 10105);
- the Gemini report input is clean;
- the JA translation payload is clean and carries no raw evidence.

**`basicAuthRoutes.test.js` (8):**
- `/test-basic` returns a session id only, with the credential in no response and no log line;
- error codes and statuses;
- `/scan` moves the credential to the vault, and the worker gets no password, cookies or login URL;
- the session is single-use;
- origin mismatch is refused;
- 15-min expiry;
- provisioning failure purges the vault;
- schedules refuse Basic;
- URL-embedded credentials are refused.

**`scopedBasicAuth.browser.test.js` (6), real Chromium:**
- the protected page loads with its canary;
- a same-origin iframe loads;
- a cross-origin (out-of-process) iframe, a dedicated-worker cross-origin fetch, a service-worker fetch, a subdomain image and a direct plain-HTTP navigation all reach their servers **with no credential**;
- the dedicated worker's same-origin fetch got 200;
- a redirect to a challenging origin is refused;
- a wrong password is tried exactly once;
- the real `capturePage` and the real `runLighthouseAudit({ basicAuth })` score the protected page with 0 leaks, and the wrong password fails closed;
- two concurrent sites never exchange credentials.

---

## 5. Unresolved issues and limitations

1. **No end-to-end run against a real Basic-protected site through the full stack** (real ZAP + MongoDB + GridFS + Gemini). The storage, report and AI paths are proven by handler-level and unit tests, plus the live ZAP API check. **Staging run required** (§8).
2. **The vault is single-process.** It is correct today (one backend task, no autoscaling, no stickiness), but:
   - a deploy or restart drops in-flight Basic credentials, and those scans fail closed;
   - a second backend task would need sticky routing or a shared encrypted store.
3. **Out-of-process frames and workers are not answered.** The handler only sees the page target, so challenges from out-of-process iframes and service workers are never answered (fail closed). A cross-origin iframe on the **target** origin that itself requires Basic would therefore render as unauthenticated in the screenshot and audit. This doesn't affect the vulnerability scan.
4. **Header grade and WebCheck are unauthenticated** (by decision) and reflect the public 401 response. This is disclosed in the UI and both PDFs.
5. **The external urlscan/PSI services are skipped for Basic scans.** The screenshot and performance card come from the in-house engines only, and there is no CrUX field data.
6. **Not supported:**
   - Digest, NTLM and Negotiate (refused with `BASIC_SCHEME_UNSUPPORTED`);
   - different credentials per realm on one site.
7. **Short passwords and the coverage heuristic:**
   - Exact-secret scrubbing ignores secrets shorter than 4 characters, to avoid over-redaction. Header redaction is structural and covers any length.
   - The coverage verdict treats a scan as degraded when 401s ≥ 2xx/3xx responses. Real sites may need tuning.
8. **The repo task-definition files are stale copies** (`backend-task-def.json` is `v50`; production runs `fortexa-backend:95`). The same deltas must be applied to the **live** revisions (§8).
9. **The frontend auto-deploys:** `.github/workflows/frontend-deploy.yml` deploys on any push to `main` touching `frontend/**`. Merging must follow the backend rollout, or users would see a Basic option the backend doesn't serve.

---

## 6. Security properties (what the tests guarantee)

- **Never sent anywhere but the target:** HTTPS only, the exact origin (scheme, host, port), scanner traffic only (not ZAP's proxy), never to subdomains, other ports, HTTP or third parties. Applies to the probe, ZAP and the browser alike.
- **Never stored or exposed:** not in MongoDB, GridFS (alerts, evidence, HTML report), PDFs (EN/JA), the JSON export, evidence endpoints, Gemini prompts or translation payloads, API responses or log lines.
- **Revoked on every exit:** success, failure, cancellation, watchdog, storage failure, missing credential; plus purge on provisioning, recycle and start failure.
- **No account lockout:** one authenticated attempt per verification and per browser request.
- **Manual-only:** schedules refuse Basic.

---

## 7. Deployment plan (requires approval; not executed)

Order matters, because ZAP must not require a key before the backend sends one.

1. **Secret.** No new secret. `fortexa-backend-secrets:ZAP_AUTH_API_KEY` exists. Confirm its value is a strong random string.
2. **Backend.**
   - Build and push a new image.
   - Register a new `fortexa-backend` revision from the **live** revision 95, plus `ZAP_API_KEY` (same secret).
   - Deploy. Sending a key to a ZAP that runs `disablekey=true` is harmless.
3. **ZAP task definitions.**
   - Register new `zap-auth-task` and `zap-scanner-task` revisions from the live revisions, plus the digest pin, `-config api.key="$ZAP_API_KEY"`, the `secrets` entry and the keyed health check.
   - Update both services. They scale from zero, so the next scale-out picks them up.
   - Confirm `ecsTaskExecutionRole` can read `fortexa-backend-secrets` for the ZAP families.
4. **Verify (staging first):**
   - one form-login scan and one Basic scan end-to-end;
   - `/ecs/zap-auth-task` contains no 10105 lines and no credential;
   - the ZAP API answers without a key → refused.
5. **Frontend:** merge to `main` (auto-deploys).
6. **Rollback:** previous backend revision (95) and ZAP revisions (12 / 21). The frontend reverts by revert-merge.

---

## 8. Readiness assessment

| Area | Ready? |
|---|---|
| Code complete for the agreed scope | Yes |
| Regression suites (backend, frontend, build) | Pass |
| New security tests | Pass (64 backend + 7 frontend) |
| Live API compatibility with the production ZAP digest | Confirmed |
| Staging E2E (real ZAP, MongoDB, Gemini, Basic-protected site) | **Not done — required** |
| Production task definitions updated | **No — needs approval** (§7) |
| Deployment | **Not deployed, by instruction** |

**Recommendation:** proceed to code review and a staging run. Deploy to production only after the staging checks in §7.4 pass and the rollout is approved.
