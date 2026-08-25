# Authenticated scan — 3-phase verification log

Static verification of the sign-in verification work. **Nothing was executed** —
no tests, no build, no server — per instruction. Findings below were reached by
reading code and tracing data flow, and every fix is likewise unrun.

| Phase | Scope | Findings |
|---|---|---|
| 1 | Structural: parse integrity, imports/exports, dangling refs | 1 |
| 2 | Logic and data flow: contracts between layers, end-to-end traces | 2 |
| 3 | Adversarial: regressions, failure modes, timing, security | 5 |

All 8 fixed. 3 observations logged without change.

---

## Phase 1 — Structural

Brace/paren balance across all 12 touched backend files: OK. Every destructured
import from the four new utils resolves to a real export (checked
programmatically). No dangling references to the removed
`revealHiddenLoginPanel`.

### F1 — `authScanResult` wiped on every scan start  *(mine · high)*

`startAsyncAuthScan` did a wholesale `$set: { authScanResult: {...} }` on the
existing-record branch. Both callers write the login outcome into the skeleton
record immediately before calling it, so **`loginOutcome` was erased every
time** — meaning the report could never report a confirmed sign-in through that
path, and the scheduler's `authDegraded` flag was destroyed too.

**Fix:** dotted `$set` paths so only the intended fields are touched
(`zapAuthService.js`). The new-record branch now records `loginOutcome` itself.

---

## Phase 2 — Logic and data flow

Traced: detection → test-login → scan start → in-scan verification → completion →
status response → UI, plus the scheduler path and the encryption path. Verified
all 8 login error codes resolve in both locales, and confirmed every new frontend
test assertion matches the real source text.

### F2 — Scheduled authenticated scans could never work  *(pre-existing · high)*

`submitSchedule` sent `submitButton` as the whole field **object**, but
`ScheduledScan` declares it `String` and `schedulerService` reads it as a string
selector (`{ selector: authConfig.submitButton }`). Mongoose casting a plain
object to String throws a CastError — so either schedule creation failed
outright, or a garbage selector was stored and the background login could never
submit the form.

Present at `HEAD` and untouched by this work, but it sits in the exact path being
hardened, so it is fixed here rather than left.

**Fix:** send `selectedSubmitButton?.selector` (`AuthenticatedScanPanel.jsx`).
The optional signed-in marker is now carried onto the schedule too.

### F3 — Green tick on a dead end  *(mine · medium)*

The test-login failure branch passed `result.authConfirmed` straight through. A
site that authenticates but issues **no cookies** (session held in the browser)
produced `authConfirmed: 'confirmed'` with `authenticated: false` and no
`tempSessionId` — so the UI showed "Login Successful" in green and then silently
refused to advance.

**Fix:** that branch is always `'failed'`; only the reason varies. Added
`NO_SESSION_COOKIES` with an honest message in both locales — an authenticated
scan genuinely is not possible for such a site, because there is no session for
the scan to carry.

---

## Phase 3 — Adversarial

### F4 — Unbounded click storm during detection  *(mine · medium)*

`revealLoginPanel` tried 3 handles × 14 selectors with a 600ms settle each —
roughly 25 seconds of clicking on any page without a visible password field,
which is now every failed detection.

**Fix:** hard cap of 8 clicks, 2 handles per selector.

### F5 — Automatic retry could navigate off-site  *(mine · medium)*

`submitAlternates` feeds the automatic retry chain, which runs headless with
nobody watching. Rank #2 is frequently "Log in with Google", so a failed primary
click would send the browser to an external identity provider and then score
whatever loaded there.

**Fix:** new `autoRetryCandidates()` filters third-party sign-in out of the
*retry* list only. They remain in `fields`, so the manual override dropdown still
offers them — a site that only has third-party sign-in stays selectable by hand.

### F6 — A customer typo discarded a good marker  *(mine · low-medium)*

If the optional "text shown only when signed in" field held something not on the
page, the derived marker was thrown away and the result downgraded to
unconfirmed — punishing a typo in an optional field by discarding a sign-in we
had already confirmed ourselves.

**Fix:** fall back to the derived marker and log it, instead of nulling.

### F7 — Worst-case submit chain ran ~87 seconds  *(mine · medium)*

Every retry inherited the full 15s navigation wait plus a 2.5s settle.

**Fix:** the first attempt keeps the full budget (it is the one expected to
work); retries drop to 8s/1.5s. Worst case is now ~46s, and typical is one
attempt.

### F8 — Completion write dropped the degraded flag  *(mine · medium)*

The final write replaces `authScanResult` wholesale and I had re-read only
`loginOutcome`, so the scheduler's `authDegraded` was lost. The reported outcome
happened to stay correct, but only by luck.

**Fix:** `AUTH_HEALTH_KEYS` lists the whole verification set in one place and it
is carried across explicitly, so adding a field later cannot silently drop it.

---

## Observations — logged, not changed

1. **`authScanResult.authenticated` is dead and misleading.** Written as a
   hardcoded `true`, read by nothing anywhere in the repo. A field with that name
   sitting `true` on a scan that is not authenticated will mislead someone
   eventually. Pre-existing; safe to delete in a separate change.

2. **Detection `warnings[]` are raw backend English rendered in the UI**
   (`AuthenticatedScanPanel.jsx`, `⚠️ {warning}`). This breaks the UI language
   policy — the strings bypass i18n and are English-only. Pre-existing and
   outside this change; worth converting to codes.

3. **Infrastructure drift.** `backend-task-def.json` declares
   `"family": "fortexa-backend-task"` while its own verification note records the
   live task as `fortexa-backend:63`, and `iam-policies.json` documents that the
   live role uses broad AWS-managed policies rather than the scoped document in
   the file. Both are called out in `infrastructure/CREDENTIAL_ENCRYPTION_KEY.md`
   so the deploy does not silently register a task family nothing points at.

---

## Still unverified

Static review is not a passing test run. When execution is allowed:

```bash
cd backend  && npm test
cd frontend && CI=true npx react-scripts test --watchAll=false
cd frontend && CI=true npx react-scripts build     # must stay warning-free
```

Then the live checks: Altoro Mutual must stay `confirmed` (regression guard),
quizmint.me should now get past detection, and **a wrong password must never
produce a green tick** — that is the headline test.


---

# Round 2 — deeper inspection

Executed this time: `node --check`, both test suites, and the production build.
Still no dynamic testing — no app, no server, no scanner.

## Result

```
node --check      14/14 files parse
backend  npm test 178 passed, 0 failed
frontend jest      50 passed, 0 failed
frontend build    Compiled successfully  (CI=true, warnings-as-errors)
```

## Correction to round 1's stated root cause

Round 1 claimed the toolchain "would have caught several of the eight". Running
it shows that is **wrong**. All 14 files already parsed, both suites were green,
and the build was clean — every one of F1–F8 was an integration-seam defect
(route ↔ service ↔ model ↔ UI) that no existing test covered. Nothing in the
toolchain would have flagged them.

The real root cause was writing ~1000 lines across four layers with no
regression tests at the seams. That makes the tests below the valuable output of
this round, not the green checkmarks.

## F9 — Retries blocked by what the previous attempt opened *(mine · medium)*

`submitLogin` clicks candidate buttons in sequence. If an early attempt hits a
header control, the dropdown or modal it opens leaves a backdrop that swallows
every later click — so the retry that *would* have worked cannot land. Every
attempt was also being compared against the original baseline rather than the
state it actually started from.

**Fix:** press Escape and re-measure between attempts, so each is judged
independently and overlays cannot block the rest of the chain.

## Regression tests — all eight now guarded, and each one verified to fire

`backend/tests/authScanRegressions.test.js` is new; the rest extend existing
suites. Every guard was **mutation-tested**: the fix was reverted, the suite
re-run, and the specific test confirmed to fail.

| Finding | Guard | Mutation |
|---|---|---|
| F1 / F8 | census: every wholesale `authScanResult` write creates the document or carries `carriedAuth` | fires |
| F2 | panel `authConfig` vs `ScheduledScan` declared path types | fires |
| F3 | refusal branch never answers `confirmed` | fires |
| F4 | reveal click cap present and sane | fires |
| F5 | `autoRetryCandidates` excludes third-party | fires |
| F6 | unmatched customer marker falls back | fires |
| F7 | retry budget shorter than first attempt | fires |

Plus: credentials never persisted or returned, hostile-input coverage for every
new pure function, and regex-metacharacter safety for markers taken from
customer pages.

### The mutation testing earned its keep

The first version of the F1/F8 census **passed with the fix removed** — it
matched only inline object literals, and the completion write assigns a variable
(`authScanResult: authScanResultObj`). It was silently skipping the exact site
whose wholesale replacement caused F8. A decorative guard on the most important
bug. Found only by deliberately breaking the code and checking the test noticed.

Two further false alarms came from **CRLF**: Node counts ``, Python strips it,
so byte offsets disagreed, and a `
`-terminated patch silently matched nothing —
making a real guard look decorative. Both were tooling errors, not code defects.

## Audits that came back clean

- **Persistence overwrite, repo-wide.** `zapService.js` and `webCheckService.js`
  both mix dotted and wholesale writes to the same subdocument — the same shape
  as F1. Every instance checked: they are either WebSocket payloads (not database
  writes) or intentional resets at scan start/stop, and the completion write
  re-sets what it needs. **No clobber bugs outside the auth path.**
- **Browser lifecycle.** All six exit paths of `testLogin` close the browser,
  including the `browser = null` handoff to `finally`; `fetchAnonymousText`
  closes its context in `finally`.
- **Backend prose never reaches the UI.** `evidence` is now stable identifiers
  rather than English, and nothing renders `errorMessage` or
  `authScanResult.error`.

## New observation

`ScanResult.languagePreference` is written in three places and read nowhere. It
looks like it should drive report language, but Japanese reports are produced by
translating client-side through `/api/translate`, so the field is simply dead.
Harmless; worth deleting in a cleanup.

## Still out of reach

Dynamic checks remain unverified: Altoro Mutual staying `confirmed`, quizmint.me
getting past detection, and the headline test — **a wrong password must never
produce a green tick.**


---

# Round 3 — the round that mattered

Your instinct to run one more was right. This round used techniques the first
two did not: mutation testing of the *logic* suites, offline Mongoose document
construction, fuzzing, and end-to-end scenarios built from realistic page
shapes. It found the single worst defect of the whole engagement.

```
backend  npm test  189 passed, 0 failed
frontend jest       50 passed, 0 failed
frontend build     Compiled successfully
```

## F12 — A wrong password scored "confirmed"  *(mine · critical)*

The exact failure this entire feature exists to prevent.

On a failed login the error message **is new text**. `deriveMarker` diffs the
signed-in page against the anonymous baseline and takes what is new — so for
Altoro Mutual it selected **"Login Failed"** as the proof of a successful
sign-in. Because a marker deliberately outranks error messages, the verdict came
back `confirmed`.

**Why two rounds of review missed it:** the unit test named *"a wrong password
is never confirmed"* passed all along — because it hand-fed
`markerResult: { marker: null }`. It stubbed the very component that fails. The
test asserted the conclusion while mocking away the thing under test.

It only surfaced when the scenario suite ran the **real** `deriveMarker` over a
realistic wrong-password page.

**Fix, two independent layers, each verified load-bearing by mutation:**
1. `FAILURE_TEXT_PATTERN` disqualifies failure-shaped text outright.
2. Whatever the page is currently showing as an error is excluded by exact text,
   however it is phrased — because a site's own wording ("Those details do not
   match our records") will not always match a pattern.

## F10 — Proximity scoring was untested, and its comment was wrong

Removing `score += Math.max(0, 50 - distance * 5)` broke no test. Investigation
showed the term only changes the answer in one shape: two equally worded buttons
that both sit *before* the password field, where document order would take the
further one. Added a test for exactly that (mutation-verified), and corrected a
comment that claimed proximity was what rescued Juice Shop — the real mechanism
is `isNavigationButton` exclusion.

## F11 — Utilities crashed on non-array inputs

Fuzzing 7,112 input combinations produced **2,481 crashes** across four
functions. `x || []` lets a truthy non-array through and then throws on `.map`.
None were reachable through current call paths, but these are shared utilities.
After hardening: **6,925 combinations, 0 crashes.**

## Empirical confirmation of F2

Previously argued from reasoning only. Mongoose builds and validates documents
without a database, so it is now proven:

```
OBJECT payload -> validation error: authConfig.submitButton ; stored: null
STRING payload -> validation error: none ; stored: "#loginButton"
encryption     -> stored v1:+IloWVkvjPR6x... ; getter returns "hunter2"
```

Scheduled authenticated scans genuinely could never store a submit button.

## Mutation testing summary

Every guard was verified by reverting its fix and confirming the specific test
fails. **One was decorative and had to be rewritten** (the F1/F8 census matched
only inline object literals, so it silently skipped the completion write — the
exact site that caused F8). Of the logic mutations, 6 of 7 were caught; the
seventh became F10.

## New scenario suite

`backend/tests/loginScenarios.test.js` runs realistic page shapes for Altoro,
Juice Shop and quizmint — right password and wrong — through the real decision
pipeline. It is the closest approximation available to the live check, and it
encodes the invariant directly: **no scenario without a signed-in marker is ever
confirmed.**

## Standing caveat, unchanged

These scenarios prove the verdict is right *once the browser reaches that state*.
They do not prove the automation gets there. Altoro staying confirmed,
quizmint getting past detection, and a real wrong-password attempt still need a
live run.


---

# Round 4 — the last one

```
backend  npm test  197 passed, 0 failed
frontend jest       50 passed, 0 failed
frontend build     Compiled successfully
repo hygiene       no stray .bak/.orig files
```

## F13 — F12 was an instance, not the class  *(mine · critical)*

Round 3 fixed "the error message becomes the marker" by excluding failure-shaped
wording. That was too narrow. Probing five *neutral* failure notices — text that
carries no error styling and reads nothing like a failure — every one still
produced `confirmed`:

```
"Please check your details"    -> confirmed
"Let us try that once more"    -> confirmed
"Need help signing in"         -> confirmed
"Signing in as your account"   -> confirmed
"Too many attempts today"      -> confirmed
```

The structural defect: **arbitrary new text was being treated as proof of a
sign-in.** Pattern-matching failure wording can never be complete, because a
site can phrase a failure any way it likes.

**Fix:** a marker now carries a confidence. Only an explicit signed-in control
(`Log out`, `Sign Off`, `My Account`, `ログアウト`, …) — or a marker a person
supplied and we verified is present — can produce `confirmed`. Any other new
text is still captured and still used as a canary for spotting a change later
in the scan, but it is no longer evidence: the verdict becomes `unconfirmed`,
which is the honest answer.

Knock-on fix: `zapAuthRoutes` derived `loginOutcome` from the mere presence of a
marker, which would now read a weak marker as a confirmed sign-in. It reads the
verdict instead.

## The invariant, proven over generated input

Hand-written scenarios only cover what the author thought of — and what the
author did not think of is exactly how F12 and F13 happened. So the rule is now
asserted over 20,000 generated page pairs (seeded, deterministic):

```
runs=20000  confirmed=8159  confirmed-without-a-signed-in-control=0
```

## F14 — Unbounded input from the scanned page

`html` was capped at 500KB but `visibleText` and the error list were not, and
their size is decided by the site being scanned. The marker diff runs a dozen
patterns per line. Capped at 300KB of text and 50 error elements.

## Merge readiness

You mentioned merging with your friend's branch later, so:

- No stray `.bak` / `.orig` files — the mutation-testing cycles all restored
  cleanly, and all 13 fixes were re-verified present afterwards.
- Nothing committed or pushed. 15 modified files, 12 new ones, all listed in
  `git status`.
- Highest conflict risk on merge: `AuthenticatedScanPanel.jsx`, `en.js`/`ja.js`
  (append-only additions near the top of the login block), and `zapAuthService.js`.
  The four new `utils/` files and five new `tests/` files are additions and
  should merge without contest.

## Closing note on the four rounds

The severity of what each round found went **up**, not down:

| Round | Method | Worst find |
|---|---|---|
| 1 | Reading and tracing | Silent data loss between layers |
| 2 | Running the toolchain | Nothing new — everything already passed |
| 3 | Mutation + realistic scenarios | A wrong password scored `confirmed` |
| 4 | Probing the class + property testing | The same, for every neutral failure notice |

A green suite meant much less than it looked like. What actually found bugs was
deliberately breaking things and generating inputs nobody thought to write down.

**Still not verified, and it is the one that counts:** none of this proves the
browser automation reaches these states on a live site. Point it at Altoro with
a deliberately wrong password.
