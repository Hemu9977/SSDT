# planchanges.md — Profile usage panel + one-off scan top-ups

---

## ⛔ STOP — READ BEFORE WRITING ANY CODE

**Instruction to any engineer or AI agent picking up this plan:**

> This plan is **NOT executable as written.** It contains unresolved product decisions that
> change the data model and the billing behaviour. You **MUST** put the questions in
> [Open questions for the product owner](#open-questions-for-the-product-owner) to the product
> owner and get explicit answers **BEFORE** editing a single file. Do not pick defaults. Do not
> infer intent from the code — parts of the code contradict the spec, which is one of the
> questions. Do not begin with "the easy parts first"; the ambiguous questions determine the
> schema, so there are no safe easy parts.
>
> **Blocking questions — all must be answered before implementation starts:**
>
> 1. **Q3 — what is the plan's scan limit?** `CLAUDE.md` and `PLAN_LIMITS` in
>    `backend/models/User.js` disagree about scans-per-target vs. scans-per-month. This decides
>    what the new Profile card is even supposed to display. **The whole of Request 1 is blocked
>    on this.**
> 2. **Q1 — credit expiry window.** Determines the `expiresAt` written on every purchased batch.
>    Wrong value = wrong data persisted to real customer records, needing a migration to undo.
> 3. **Q4 — do credits bypass per-target caps?** If they do not, a Light customer who has used
>    their 3 targets cannot spend credits at all, which defeats the entire feature.
> 4. **Q5 — severity level of a credit-funded scan.** Determines whether
>    `vulnerabilityAccessLevel` is read from the batch or the subscription at scan time.
> 5. **Q6 — repeat/stacked purchases allowed?** Determines whether `scanCredits` is genuinely
>    an array or should be a single object.
>
> Questions 2, 7–11 are lower-risk and may be confirmed in parallel with implementation, but
> **should still be asked up front.**

### ⚠️ Do not remove the frontend purchase gate first

`frontend/src/pages/Profile.jsx:667` (`{!hasPlan && (`) is currently the **only** thing
preventing data loss. With it removed and the webhook unchanged, a subscriber who buys a one-off
scan will have `stripeSubscriptionId` set to `null` (`backend/routes/stripeRoutes.js:410`),
permanently breaking cancellation **while Stripe continues to bill them**, plus losing their
seats, plan, and month-to-date usage.

**Order of work is mandatory:** fix the webhook (Backend §2) → verify with a test purchase →
*then* touch the frontend gate (Frontend §3).

---

## Context

Two product-owner requests, both about how scan capacity is *shown* and *sold*:

1. **Profile usage panel is wrong.** The Statistics grid on `/profile` currently shows "Daily Limit" and "Max File Size". Neither is a real product concept — "daily limit" is a synthetic number derived by dividing the monthly quota by 30, and file size is irrelevant to a URL scanner. Replace with: the **plan's scan limit**, **scans performed this month**, and — for one-time purchases — **purchased scans remaining + their expiry date**.

2. **One-off scans must be purchasable while subscribed.** Today an active subscriber never sees the one-time plans. The product owner's framing: the one-off plan is a *top-up*, bought precisely when the monthly allowance is exhausted. So it must be purchasable at any time, and its scans must be consumed **after** the monthly allowance runs out — never instead of it.

Request 2 is bigger than deleting an `if`. The current data model treats "one-time" as an **organization-wide mode** (`Organization.billingCycle === 'onetime'`), and the Stripe webhook **overwrites** the org's plan on every completed checkout. Letting a subscriber buy a one-off today would silently destroy their subscription record. The fix requires making credits a *separate axis* from the plan.

---

## Current behaviour

### A. The Profile section that must change

`frontend/src/pages/Profile.jsx:443-464` — the Statistics section:

```jsx
{/* Statistics */}
<div className="profile-section">
  <h2>{t('statistics')}</h2>
  <div className="stats-grid">
    <div className="stat-card">
      <div className="stat-value">{user.totalScans}</div>
      <div className="stat-label">{t('totalScans')}</div>
    </div>
    <div className="stat-card">
      <div className="stat-value">{user.scansThisMonth}</div>
      <div className="stat-label">{t('thisMonth')}</div>
    </div>
    <div className="stat-card">
      <div className="stat-value">{limits.scansPerDay === -1 ? '∞' : limits.scansPerDay}</div>
      <div className="stat-label">{t('dailyLimit')}</div>
    </div>
    <div className="stat-card">
      <div className="stat-value">{(limits.maxFileSize / (1024 * 1024)).toFixed(0)}MB</div>
      <div className="stat-label">{t('maxFileSize')}</div>
    </div>
  </div>
</div>
```

Where those values come from:

| Value | Source |
|---|---|
| `user.totalScans` | `backend/routes/profile.js:25` — `ScanResult.countDocuments({ userId })` |
| `user.scansThisMonth` | `backend/routes/profile.js:31-39` — `ScanResult.countDocuments` since `startOfMonth`, computed in **server-local time** (`setDate(1); setHours(0,0,0,0)`) |
| `limits.scansPerDay` | `backend/models/User.js:220` — `Math.ceil(limits.scansPerMonth / 30)`. Purely derived; nothing enforces it. |
| `limits.maxFileSize` | `backend/models/User.js:222` — `isPro ? 100MB : 32MB`. Nothing in the scan pipeline reads it. |

Note there is already a *separate*, more accurate usage display further down the page in the "Your Plan" card at `Profile.jsx:526-548`: a `{org.scansUsed} / {org.scanLimit}` progress bar (only when `org.scanLimit > 0`, so never for one-time orgs) and a one-time remaining-scans line gated on `org.billingCycle === 'onetime'` (`Profile.jsx:539-548`). Note also `Profile.jsx:545` renders `t('validityPeriod')` = the **hard-coded string** "Validity Period: 90 days" — not the actual expiry date.

i18n keys in play: `en.js:225-229` / `ja.js:225-229` (`statistics`, `totalScans`, `thisMonth`, `dailyLimit`, `maxFileSize`), `en.js:267` `oneTimeScansRemaining`, `en.js:296` `validityPeriod`.

### B. Where the one-off purchase is blocked

The gate is **in the frontend**, not the API.

- `frontend/src/pages/Profile.jsx:346` — `const hasPlan = org && org.subscriptionStatus === 'active' && org.planType;`
- `frontend/src/pages/Profile.jsx:667` — `{!hasPlan && (` wraps the **entire** "Choose Your Plan" section (lines 667-767), which contains the billing-cycle tabs including `'onetime'` (line 673) and the plan cards rendered from `PLANS[selectedBilling]` (line 705, definitions at lines 13-28). With an active plan, the whole block — including both trial cards — is unmounted. There is no way to reach checkout for a one-off.

The backend has **no** gate: `backend/routes/stripeRoutes.js:46-125` (`POST /create-checkout-session`) accepts any `{ planType, billingCycle }` from any authenticated user.

**But** the webhook would corrupt the account. `backend/routes/stripeRoutes.js:402-430`, on *every* completed checkout:

```js
org.planType = planType || null;          // :402  → 'trial1'
org.billingCycle = billingCycle || null;  // :403  → 'onetime'
org.subscriptionStatus = 'active';        // :404
...
if (billingCycle === 'onetime') {         // :407
  org.seatsAllowed = 1;                   // :408  ← team members lose access
  org.oneTimeRemainingScans = ONETIME_SCANS[key] || 1;  // :409  ← overwrite, not add
  org.stripeSubscriptionId = null;        // :410  ← subscription link lost forever
  org.expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // :411
}
...
org.scansUsed = 0;                        // :428  ← monthly usage wiped
org.targetScanCounts = {};                // :429
org.lastScanReset = new Date();           // :430
```

So a subscriber buying Trial 1 today would: drop to 1 seat, lose `stripeSubscriptionId` (making `POST /cancel-subscription` at `stripeRoutes.js:211-214` fail permanently while Stripe keeps billing them), and have their plan replaced by a 1-scan trial. **This is the real work item, and it must be fixed before the frontend gate is removed.**

### C. How scans are counted and quota enforced

- `backend/middleware/planCheck.js:21-81` runs before every scan route. It loads the user, resolves `limits = user.getAccountLimits(org)` (`planCheck.js:51`), then calls `checkScanQuota` (`planCheck.js:57-61`). On `null` it returns **403 `PLAN_LIMIT_EXCEEDED`** (`planCheck.js:63-71`) — this is exactly the error handled at `frontend/src/components/Hero.jsx:812-815`.
- `backend/services/planService.js:45-109` `checkScanQuota()` — read-only pre-check:
  - `:50-52` rejects unless `billingCycle === 'onetime'` **or** status is `active`/`trialing`.
  - `:56-78` UTC calendar-month reset of `scansUsed`, `targetsUsed`, `targetScanCounts`, `lastScanReset` — **skipped entirely when `billingCycle === 'onetime'`**.
  - `:81-83` **one-time short-circuit**: `if (org.billingCycle === "onetime") return org.oneTimeRemainingScans > 0 ? org : null;` — returns before any monthly/target logic.
  - `:86-88` subscription monthly cap: `if (org.scansUsed >= org.scanLimit) return null;`
  - `:90-106` per-target caps via sha1-keyed `targetScanCounts`.
- `backend/services/planService.js:125-190` `consumeScan()` mirrors the same order and does the atomic writes: `:158-164` guarded `$inc: { oneTimeRemainingScans: -1 }` for one-time; `:185-189` guarded `findOneAndUpdate({ scansUsed: { $lt: org.scanLimit } }, { $inc: ... })` for subscriptions.
- `backend/services/planService.js:196-254` `finalizeSuccessfulScan()` charges quota **only after** a scan reaches a clean terminal state, guarded by `ScanResult.quotaConsumed` (`backend/models/ScanResult.js:95-98`). Called from `geminiCompletionService.js:230,429`, `zapService.js:1345`, `zapAuthService.js:879`.
- `backend/services/schedulerService.js:127-131` runs the same `checkScanQuota` for scheduled scans.
- Other consumers of `checkScanQuota`/`consumeScan` to keep in sync: `routes/pageSpeedRoutes.js:15,29`, `routes/webCheckRoutes.js:13,42`, `routes/zapRoutes.js:79`, `routes/zapAuthRoutes.js:208`, `routes/virustotalRoutes.js:476`.

**Two deliberate charging strategies — do not "unify" them.** There are two distinct quota paths, and they never both fire for the same scan:

- **Orchestrated combined scan** — `planCheck` *checks* at scan start; `finalizeSuccessfulScan(scanId)` *charges* at successful completion, guarded by `ScanResult.quotaConsumed` (`models/ScanResult.js:95-98`). The guard is needed because several components (`geminiCompletionService.js:230,429`, `zapService.js:1345`, `zapAuthService.js:879`) can each reach finalize for the same scan. Charging at the end means a scan that dies halfway costs the customer nothing.
- **Standalone one-shot routes** — `pageSpeedRoutes.js:29` and `webCheckRoutes.js:42` call `consumeScan()` inline right after a successful result. These create no `ScanResult` and never enter the pipeline above, so one HTTP request charges exactly once. No idempotency flag is needed or possible.

Both paths call `consumeScan()`, so **any change to consumption ordering must be applied inside `consumeScan()` itself**, not at the call sites — otherwise the standalone routes will keep the old subscription-only behaviour and never fall back to credits. (Note: neither standalone endpoint is currently called from the frontend.)

### D. Counting "scans this month" from ScanResult

`backend/models/ScanResult.js` has `userId` (indexed, `:57-62`), `organizationId` (indexed, `:68-72`), `status` (`:52-56`), `createdAt` (`:86-90`). An org-level monthly count is therefore:

```js
ScanResult.countDocuments({
  organizationId: org._id,
  quotaConsumed: true,
  createdAt: { $gte: startOfUtcMonth }
})
```

**However `createdAt` carries a 7-day TTL index** (`ScanResult.js:89` — `index: { expires: 604800 }`). Scan documents self-delete after a week, so `ScanResult` **cannot** be the source of truth for a monthly counter. `Organization.scansUsed` must remain authoritative; `ScanResult` is only usable for the cosmetic "recent activity" number.

---

## Data model changes

### Decision: credits attach to the **Organization**, not the User

Every quota decision in the codebase already keys off `user.organizationId` (`planCheck.js:57`, `planService.js:48,128,237`, `schedulerService.js:127`). `User.oneTimeRemainingScans` (`models/User.js:106-109`) is explicitly legacy-fallback-only (`profile.js:101`, `stripeRoutes.js:149`). Putting credits on the User would mean two independent quota pools and would break Basic/Pro teams (an owner's top-up would be invisible to members). **Credits are org-scoped.**

### `backend/models/Organization.js` — new fields

Add after `oneTimeRemainingScans` (currently `Organization.js:31`):

```js
// Purchased one-off scan credit batches. Each Stripe one-time checkout appends
// one batch. Kept sorted by expiresAt ascending ($push … $sort) so the atomic
// positional-$ decrement below always burns the soonest-expiring batch first.
scanCredits: [{
  source:        { type: String, default: 'trial1' },   // plan key that granted it
  scansTotal:    { type: Number, required: true },
  scansRemaining:{ type: Number, required: true },
  purchasedAt:   { type: Date,   default: Date.now },
  expiresAt:     { type: Date,   required: true },
  stripeCheckoutSessionId: { type: String, default: null },  // idempotency
  vulnerabilityAccessLevel: { type: String, default: 'critical-high' }
}],
```

Keep the existing scalar `oneTimeRemainingScans` as a **denormalised mirror** of `sum(scanCredits[].scansRemaining)` for live batches. Rationale: `profile.js:93,101`, `stripeRoutes.js:149`, and `Profile.jsx:542` all read it today; keeping it in sync avoids a breaking rewrite and gives a cheap `$gt: 0` query guard. It is written in the same atomic update as the array element, so it never drifts.

No new field is needed for "scans used this month" — `Organization.scansUsed` (`Organization.js:24`) already is it, reset by `planService.js:62-78`.

### Monthly counter reset

Unchanged mechanism, one bug fixed: the reset at `planService.js:62` and `:140` is **UTC calendar-month** and is currently skipped when `org.billingCycle === 'onetime'`. Change the condition from `isNewMonth && org.billingCycle !== "onetime"` to just `isNewMonth` — with credits now separate from the plan, an org may simultaneously be on a subscription *and* hold credits, and there is no longer any reason to suppress the monthly roll-over. Credit batches are unaffected by the roll-over; they expire only by their own `expiresAt`.

Also fix `stripeRoutes.js:428-430`: the `scansUsed = 0` reset must move **inside** the new-subscription branch so a top-up purchase never wipes the month's usage.

### Migration

One-off script (not part of the app boot): for every org with `billingCycle === 'onetime'` and `oneTimeRemainingScans > 0`, push a `scanCredits` batch with `scansRemaining = oneTimeRemainingScans`, `expiresAt = org.expiresAt`, `source = org.planType`. Leave `billingCycle` as-is so existing pure-trial orgs keep working through the legacy path. Read-only verification query to run first: count of such orgs.

---

## Backend changes

### 1. `backend/services/planService.js` — quota ordering

Add two helpers and rewire both entry points. **Ordering is mandatory: subscription allowance first, credits only as fallback.**

**`checkScanQuota()` (`planService.js:45-109`)**

- `:50-52` — widen the gate: also allow through when the org has live credits, so an expired/cancelled org can still burn credits it paid for. New condition ≈ `isSubscriptionUsable(org) || hasLiveCredits(org)`.
- `:62` — drop the `&& org.billingCycle !== "onetime"` guard on the monthly reset (see above).
- `:81-83` — **remove the one-time short-circuit.** Replace with the ordered evaluation below.
- New body order:
  1. If subscription is usable (`status active|trialing`, `scansUsed < scanLimit`) **and** per-target/target-count caps pass (existing `:90-106` logic) → return `org` with `req.quotaSource = 'subscription'`.
  2. Else if a live credit batch exists (`scansRemaining > 0 && expiresAt > now`) → return `org` with `quotaSource = 'credit'`.
  3. Else `null` → `PLAN_LIMIT_EXCEEDED`.
- Return shape: today the middleware stores the raw org (`planCheck.js:73`). Return `{ org, quotaSource }` and update `planCheck.js:73` to `req.organization = result.org; req.quotaSource = result.quotaSource;`. **All five call sites of `req.organization`** must be checked (`pageSpeedRoutes.js:29`, `webCheckRoutes.js:42`, plus `zapRoutes.js`, `zapAuthRoutes.js`, `virustotalRoutes.js`) — they use `req.organization._id`, so a shape change is a breaking edit. Lower-risk alternative: keep returning the org document and attach `org.__quotaSource` as a non-persisted property.

**`consumeScan()` (`planService.js:125-190`)**

Same ordering. Two atomic paths, tried in order:

```js
// 1. Subscription slot (existing :185-189, unchanged)
const sub = await Organization.findOneAndUpdate(
  { _id: orgId, subscriptionStatus: { $in: ['active','trialing'] }, scansUsed: { $lt: org.scanLimit } },
  { $inc: inc }, { new: true });
if (sub) return sub;

// 2. Credit fallback — positional `$` updates ONLY the first array element
//    matched by $elemMatch, which is the soonest-expiring live batch because
//    the array is kept sorted on insert.
return Organization.findOneAndUpdate(
  { _id: orgId,
    scanCredits: { $elemMatch: { scansRemaining: { $gt: 0 }, expiresAt: { $gt: new Date() } } } },
  { $inc: { 'scanCredits.$.scansRemaining': -1, oneTimeRemainingScans: -1 } },
  { new: true });
```

Do **not** use `arrayFilters`/`$[c]` here — it would decrement *every* matching batch. The positional `$` is the correct single-element atomic operator, and the `$elemMatch` in the query is what makes the whole thing race-safe (a loser of the race matches zero elements and gets `null`).

**`refundScan()` (`planService.js:259-285`)** — take the batch id (or `quotaSource`) so a refund returns the credit to the batch it came from rather than blindly `$inc`-ing `oneTimeRemainingScans` (`planService.js:263`).

**`finalizeSuccessfulScan()` (`planService.js:196-254`)** — no signature change; it calls `consumeScan`, which now handles ordering. Consider persisting the resolved `quotaSource` onto the `ScanResult` for support/debugging.

**Severity gating interaction:** `User.getAccountLimits()` (`models/User.js:201-225`) derives `vulnerabilityAccessLevel` from `planType_billingCycle`. A Light subscriber (critical-high) burning a **Trial 2** credit (all severities) is ambiguous — see Open Questions. Recommended default: the *subscription's* level always wins while the subscription is active; the credit's own level applies only when there is no active subscription. Store `vulnerabilityAccessLevel` on the batch so either policy is implementable without a schema change.

### 2. `backend/routes/stripeRoutes.js` — top-up vs. new plan

In `handleCheckoutComplete()` (`stripeRoutes.js:357-444`), before the mutation block at `:402`, branch:

```js
const isTopUp = billingCycle === 'onetime'
  && org.subscriptionStatus === 'active'
  && org.billingCycle && org.billingCycle !== 'onetime'
  && org.planType;
```

**If `isTopUp`:** append a credit batch and touch nothing else.

```js
if (org.scanCredits.some(c => c.stripeCheckoutSessionId === session.id)) return; // idempotent
await Organization.updateOne({ _id: org._id }, {
  $push: { scanCredits: { $each: [{
      source: key,
      scansTotal: ONETIME_SCANS[key] || 1,      // stripeRoutes.js:40-43
      scansRemaining: ONETIME_SCANS[key] || 1,
      purchasedAt: new Date(),
      expiresAt: new Date(Date.now() + CREDIT_VALIDITY_DAYS * 864e5),
      stripeCheckoutSessionId: session.id,
      vulnerabilityAccessLevel: key === 'trial2_onetime' ? 'all' : 'critical-high'
    }], $sort: { expiresAt: 1 } },
  $inc: { oneTimeRemainingScans: ONETIME_SCANS[key] || 1 }
});
await User.updateOne({ _id: user._id }, { $set: { stripePending: false } });
return;   // do NOT fall through to :402-443
```

Explicitly **not** touched on a top-up: `planType`, `billingCycle`, `subscriptionStatus`, `stripeSubscriptionId`, `seatsAllowed`, `scanLimit`, `expiresAt`, `scansUsed`, `targetScanCounts`, `lastScanReset`, `stripeCheckoutSessionId`.

**Else (no active subscription):** keep the existing path (`:402-443`), but *also* push a `scanCredits` batch alongside setting `oneTimeRemainingScans` (`:409`) so both code paths produce identical, inspectable state.

`CREDIT_VALIDITY_DAYS` = 90, matching the current hard-coded `90 * 24 * 60 * 60 * 1000` at `stripeRoutes.js:411` and the `validityPeriod` copy at `en.js:296`. See Open Questions.

**Also fix the `expiresAt` clobber for top-ups on a one-time-only org:** stacking a second trial on a trial org currently *overwrites* `oneTimeRemainingScans` (`:409`) rather than adding — the batch model fixes this by construction.

### 3. Where to remove the "already subscribed → cannot buy one-off" gate

- **Frontend:** `frontend/src/pages/Profile.jsx:667` (`{!hasPlan && (`) — see Frontend Changes.
- **Backend:** there is no such gate to remove. Instead **add** a narrow guard in `POST /create-checkout-session` (`stripeRoutes.js:46-125`, after `:62`): reject a *subscription* checkout (`billingCycle !== 'onetime'`) when the org already has an active subscription — that path is genuinely destructive and there is no plan-change flow. Explicitly allow `billingCycle === 'onetime'` through in all cases. Return `409 { code: 'ALREADY_SUBSCRIBED' }`.

### 4. `backend/routes/profile.js` — expose the new numbers

In `GET /profile` (`profile.js:16-118`):

- `:31-39` — change `startOfMonth` to a **UTC** boundary (`Date.UTC(y, m, 1)`) so it agrees with the UTC reset in `planService.js:59-60`. Right now a server in JST reports a different month boundary than the quota engine.
- In the `organization` block (`:81-97`) add:
  - `scanLimit` (already at `:90`),
  - `scansUsed` (already at `:91`),
  - `extraScansRemaining`: sum of live batches,
  - `extraScansExpiresAt`: **earliest** `expiresAt` among live batches,
  - `scanCredits`: array of `{ scansRemaining, scansTotal, expiresAt, source }` for live batches (lets the UI show multiple expiry dates later),
  - `canPurchaseTopUp`: boolean (true whenever the user is an org owner/admin).
- Mirror the same three fields in `GET /api/stripe/subscription` (`stripeRoutes.js:142-153`) so both endpoints agree.
- `limits` (`:108`) still ships `scansPerDay`/`maxFileSize` from `models/User.js:220-222`. Leave them in the payload (other code may read them) but stop rendering them. Optionally mark both as `@deprecated` in `User.js`.

### 5. `backend/middleware/planCheck.js` — better error signal

At `:63-71`, when `checkScanQuota` returns `null`, distinguish "monthly allowance exhausted but you could buy a top-up" from "no plan at all". Keep `code: 'PLAN_LIMIT_EXCEEDED'` (Hero.jsx:812 matches on it) and add a non-breaking `canPurchaseTopUp: true` + `limitType: 'monthly_scans'` so the UI can deep-link to the top-up section. Do **not** rename the code.

---

## Frontend changes

### 1. Replace the Statistics grid — `Profile.jsx:443-464`

Four cards, replacing the `dailyLimit` and `maxFileSize` cards:

| Card | Value | Label key |
|---|---|---|
| 1 | `user.totalScans` | `totalScans` *(existing)* |
| 2 | `org ? org.scansUsed : user.scansThisMonth` | `scansThisMonthLabel` **(new)** |
| 3 | `org?.scanLimit > 0 ? org.scanLimit : '—'` | `planScanLimitLabel` **(new)** |
| 4 | `org?.extraScansRemaining ?? 0` + expiry sub-line | `extraScansRemainingLabel` **(new)** |

Card 3 renders `t('noPlanScanLimit')` when there is no subscription (`scanLimit` is `0` for one-time-only orgs — `stripeRoutes.js:407-411` never sets it).

Card 4 renders only when `org?.extraScansRemaining > 0`, with a sub-line `t('extraScansExpireOn', { date: formatDate(org.extraScansExpiresAt) })` using the existing `formatDate` (`Profile.jsx:318-322`, already locale-aware). This replaces the hard-coded `t('validityPeriod')` at `Profile.jsx:545` with the **real** date.

Reuse `.stats-grid` / `.stat-card` / `.stat-value` / `.stat-label` from `frontend/src/styles/Profile.scss:274-327` — `grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))` already reflows for 3 or 4 cards, so no SCSS change is required. Add one small `.stat-sublabel` rule if the expiry line needs its own size.

### 2. Also update the "Your Plan" card

- `Profile.jsx:526-536` — progress bar: keep, but when credits exist show `{scansUsed} / {scanLimit} (+{extraScansRemaining})`.
- `Profile.jsx:539-548` — change the condition from `org.billingCycle === 'onetime'` to `org.extraScansRemaining > 0`, and swap `t('validityPeriod')` for the real date.

### 3. Unblock the one-off purchase — `Profile.jsx:666-767`

Split the block. Keep `{!hasPlan && ( … )}` as-is for the full plan chooser. Add, **inside** the `{hasPlan && ( … )}` section (after the plan card, ~`Profile.jsx:573`), a top-up sub-section:

```jsx
{/* Top-up: extra scans, purchasable at any time */}
<div style={{ marginTop: '2.5rem', borderTop: '1px solid rgba(255,107,0,0.3)', paddingTop: '2.5rem' }}>
  <h2>{t('topUpSectionTitle')}</h2>
  <p>{t('topUpSectionDescription')}</p>
  {org.scanLimit > 0 && org.scansUsed >= org.scanLimit && (
    <p className="save-message info">{t('planLimitExhaustedHint')}</p>
  )}
  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
    {PLANS.onetime.map(plan => ( /* same card markup as :706-763 */ ))}
  </div>
</div>
```

Reuse `PLANS.onetime` (`Profile.jsx:24-27`) and `startCheckout(plan.planType, 'onetime')` (`Profile.jsx:228-245`) verbatim. Button copy: `t('buyExtraScans')` instead of `t('selectPlan')`. Extract the plan-card JSX (`Profile.jsx:706-763`) into a local `PlanCard` component so both sections share it — avoids a 60-line copy-paste.

Restrict to `['owner','admin'].includes(user.role)` — the same pattern already used for invite revoke at `Profile.jsx:646`.

### 4. i18n — new keys for **both** `en.js` and `ja.js`

`ja.js` starts with `...en` (`ja.js:1-4`), so a missing `ja` key silently falls back to English — the plan therefore lists both explicitly. **All keys below were verified absent from `en.js` and `ja.js`.** Insert near the existing profile block (`en.js:225-296` / `ja.js:225-296`) to keep related keys together.

**`frontend/src/locales/en.js`:**
```js
scansThisMonthLabel: 'Scans This Month',
planScanLimitLabel: 'Plan Scan Limit',
noPlanScanLimit: 'No plan',
extraScansRemainingLabel: 'Extra Scans Remaining',
extraScansExpireOn: 'Expires {date}',
noExtraScans: 'No extra scans',
topUpSectionTitle: 'Need More Scans?',
topUpSectionDescription: 'Used up your monthly allowance? Add one-off scans on top of your current plan. Extra scans are used only after your monthly allowance is exhausted.',
planLimitExhaustedHint: "You've used all scans included in your plan this month. Purchase extra scans below to keep scanning.",
buyExtraScans: 'Buy Extra Scans',
extraScansPurchased: 'Extra scans added to your account.',
extraScansValidity: 'Valid for {days} days from purchase',
```

**`frontend/src/locales/ja.js`:**
```js
scansThisMonthLabel: '今月のスキャン数',
planScanLimitLabel: 'プランのスキャン上限',
noPlanScanLimit: 'プランなし',
extraScansRemainingLabel: '追加スキャン残数',
extraScansExpireOn: '有効期限: {date}',
noExtraScans: '追加スキャンはありません',
topUpSectionTitle: 'スキャン回数を追加しますか？',
topUpSectionDescription: '月間のスキャン上限を使い切った場合は、現在のプランに単発スキャンを追加できます。追加スキャンは、月間の上限を使い切った後にのみ消費されます。',
planLimitExhaustedHint: '今月のプラン内スキャンをすべて使用しました。引き続きスキャンするには、以下から追加スキャンをご購入ください。',
buyExtraScans: '追加スキャンを購入',
extraScansPurchased: '追加スキャンがアカウントに追加されました。',
extraScansValidity: '購入日から{days}日間有効',
```

Interpolation uses `{name}` placeholders, handled by `interpolate()` in `frontend/src/context/LanguageContext.js`.

> **Note:** Japanese is now the **default** language (`frontend/src/locales/index.js`), so the `ja` strings above are what most users will actually see. Review the Japanese copy with a native speaker before shipping. Do not introduce duplicate keys — verify with the duplicate check in the Verification section.

**Keys becoming unused:** `dailyLimit` (`en.js:228`/`ja.js:228`) and `maxFileSize` (`en.js:229`/`ja.js:229`). Leave them in place — harmless, and removal risks breaking any other consumer. Grep confirms `Profile.jsx` is currently their only use.

**Reused existing keys** (do *not* redefine): `totalScans` (`en.js:226`), `thisMonth` (`en.js:227`), `statistics` (`en.js:225`), `oneTimeScansRemaining` (`en.js:267`), `planTrial1`/`planTrial2` (`en.js:287-288`), `validityPeriod` (`en.js:296`), `startingCheckout` (`en.js:243`).

---

## Edge cases

1. **Expired credits.** A batch with `expiresAt <= now` must never be spendable. Enforced in the query predicate (`expiresAt: { $gt: new Date() }`), not by a sweeper — so there is no window where a cron lag lets an expired credit through. The mirror `oneTimeRemainingScans` *will* drift high as batches expire; the UI must therefore compute `extraScansRemaining` from live batches server-side (`profile.js`), never trust the scalar. Optionally add a nightly sweeper to re-derive the mirror.
2. **Mid-month plan change / upgrade.** `Organization.scansUsed` is *not* reset on `customer.subscription.updated` (`stripeRoutes.js:508-527`) but *is* reset on `invoice.paid` (`stripeRoutes.js:473-475`). An in-cycle upgrade raises `scanLimit` without resetting usage — probably correct (pro-rated), but it is undefined product behaviour. Credits are unaffected either way.
3. **Subscription cancelled while credits remain.** `handleSubscriptionDeleted` (`stripeRoutes.js:484-506`) nulls `planType`/`billingCycle` and sets `accountType='free'`. With the widened gate in `checkScanQuota:50-52`, the user can still burn purchased credits — which is correct (they paid for them) and is a deliberate behaviour change from today.
4. **Refunds / chargebacks.** No `charge.refunded` / `charge.dispute.created` handler exists in the webhook switch (`stripeRoutes.js:291-338`). A refunded top-up leaves spendable credits. Out of scope, but should be logged as a follow-up: match `scanCredits.stripeCheckoutSessionId` and zero the batch.
5. **Concurrent scans racing the last credit.** Solved by the single guarded `findOneAndUpdate` with `$elemMatch` + positional `$` — MongoDB applies the document update atomically; the loser matches nothing and gets `null` → clean `PLAN_LIMIT_EXCEEDED`. Note the *existing* structural race remains: `planCheck.js:57` checks quota at scan **start** while `finalizeSuccessfulScan` (`planService.js:196`) charges at scan **end**, so N concurrent scans can all pass the check with 1 credit left; N-1 then fail to charge and run free. Pre-existing; out of scope, but worth flagging.
6. **Timezone for "this month".** Three different boundaries exist today: `planService.js:59-60` (UTC), `profile.js:32-34` (server local), `Profile.jsx:319` (browser locale, display only). Standardise the first two on **UTC** and note it in the UI copy if the JP market expects JST. Flagged in Open Questions.
7. **Webhook replay / double-delivery.** Guarded at two levels: the `StripeEvent` unique-index claim (`stripeRoutes.js:278-287`) and the new per-batch `stripeCheckoutSessionId` check. Both are needed — `sync-checkout-session` (`stripeRoutes.js:163-196`) calls `handleCheckoutComplete` *outside* the `StripeEvent` guard, so a top-up could otherwise be granted twice (once by the redirect sync, once by the webhook).
8. **`isPlanActive()` polling after a top-up.** `Profile.jsx:56-59` returns true when `org.subscriptionStatus === 'active' && org.planType` — for a subscriber buying a top-up this is *already* true before the webhook lands, so `waitForPlanActivation` (`:113-137`) returns instantly and the user sees "activated" before their credits appear. Add a top-up-specific success path that polls `extraScansRemaining` increasing.
9. **`stripePending`.** Set unconditionally at `stripeRoutes.js:95`. Harmless for a subscriber mid-top-up (planCheck only reads it when `!organizationId`, `planCheck.js:28-38`), but if checkout is abandoned it stays `true` until `checkout.session.expired`. No change needed; noted so it isn't mistaken for a regression.
10. **Team members / seats.** A member of a Basic org buying a top-up credits the whole org. Correct given org-scoped credits, but should be role-restricted (owner/admin) to avoid surprise team spend.
11. **Per-target caps and credits.** `checkScanQuota:92-106` enforces `targetsPerMonth`/`scansPerTarget` from the *subscription* plan. Should a credit-funded scan also be bound by those caps? If yes, a Light user who exhausted 3 targets cannot use credits at all — defeating the feature. Recommended: credits **bypass** the target caps but still increment `targetScanCounts` for reporting. Flagged below.

---

## Open questions for the product owner

1. **Credit expiry window.** Code and copy both say 90 days (`stripeRoutes.js:411`, `en.js:296`). Confirm 90 days from *purchase*, and that it is independent of the subscription's own `expiresAt`.
2. **Roll-over.** Do unused *monthly* scans roll over? Current code resets to zero (`planService.js:66-72`). Assumed: **no roll-over**.
3. **Per-target vs. global limit.** `CLAUDE.md` specifies "Scans per target/month: Light 1, Basic 3, Pro 10" and "Max targets/month: 3, 5, 10". The code (`models/User.js:183-185`) sets monthly plans to `scansPerMonth: 3/5/10, targetsPerMonth: 3/5/10, scansPerTarget: null` — i.e. a **global** monthly cap with no per-target cap, and the numbers are transposed relative to the spec. Which is authoritative? This directly determines what "the scan limit associated with the subscription plan" means in the new Profile card.
4. **Do credits bypass the target caps?** See Edge Case 11.
5. **Severity level of a credit-funded scan.** If a Light subscriber buys Trial 2 (all severities), does that one scan show all severities, or stay Critical+High? See Backend Changes §1.
6. **Repeat top-ups.** May a user buy the same trial multiple times? May they hold several concurrent batches? (The batch model supports it; the UI needs to say so.)
7. **Multiple expiry dates in the UI.** With several batches, show only the soonest expiry (proposed) or a full list?
8. **Should trials remain "trials"?** Sold as top-ups to paying customers, "Trial 1 / Trial 2" (`en.js:287-288`) reads oddly. Rename in the top-up context (e.g. "1-Scan Pack" / "2-Scan Pack")?
9. **Timezone.** Is "this month" JST or UTC for the Japanese market? Currently inconsistent (Edge Case 6).
10. **Plan-change flow.** Should a subscriber be able to *switch* subscription tiers from Profile? Currently impossible (`Profile.jsx:667`) and destructive if attempted (`stripeRoutes.js:402-426`). Out of scope but adjacent.
11. **Should `maxFileSize` / `dailyLimit` disappear entirely,** or move to a "Plan details" area? The plan removes them from the Statistics grid but leaves them in the API payload.

---

## Verification

**Static / read-only checks**
1. `grep -rn "dailyLimit\|maxFileSize" frontend/src` → only the (retained, unused) locale definitions at `en.js:228-229` / `ja.js:228-229`.
2. Every new key exists in **both** `en.js` and `ja.js`, and neither file has duplicates:
   `awk -F: '/^  [a-zA-Z0-9_]+:/{k=$1; gsub(/ /,"",k); print k}' en.js | sort | uniq -d` → empty.
3. Confirm no remaining `billingCycle === 'onetime'` short-circuits in `planService.js` outside the migration-compat path.

**Manual E2E — display**
4. Free/no-org user → Statistics shows Total, This Month, "No plan", no extra-scans card.
5. Light monthly subscriber → "Plan Scan Limit" = 3, "Scans This Month" = `org.scansUsed`. Run one scan to completion, reload, confirm both the card and the progress bar (`Profile.jsx:529`) increment by exactly 1 and stay equal.
6. Toggle to English via `LanguageToggle` and back — all four labels translated, no raw key strings, no English leakage in JA.

**Manual E2E — top-up purchase (`stripe listen --forward-to localhost:3001/api/stripe/webhook`)**
7. As an **active Basic subscriber**, confirm the "Need More Scans?" section is visible and buy Trial 2 via Stripe test card `4242…`.
8. After the redirect, assert in MongoDB that the org has: `planType` still `basic`, `billingCycle` still `monthly`, `stripeSubscriptionId` **unchanged and non-null**, `seatsAllowed` still 3, `scansUsed` **unchanged** (not reset), and one new `scanCredits` entry with `scansRemaining: 2` and `expiresAt ≈ now + 90d`.
9. Profile shows "Extra Scans Remaining: 2" with the correct localised expiry date.
10. `POST /api/stripe/cancel-subscription` still succeeds (proves the subscription link survived) — then re-subscribe or restore.

**Manual E2E — consumption ordering**
11. Set `scansUsed` to `scanLimit - 1`. Run a scan → `scansUsed` increments, credits **unchanged** (subscription first).
12. Run another scan (allowance now exhausted) → `scansUsed` stays at `scanLimit`, one credit is decremented from the **soonest-expiring** batch, and `oneTimeRemainingScans` decrements in the same operation.
13. Exhaust all credits → next scan returns 403 `PLAN_LIMIT_EXCEEDED`, and `Hero.jsx:812-815` still displays the guidance message.

**Edge / regression**
14. Manually set a batch's `expiresAt` to the past → it is not spendable, and the Profile card excludes it.
15. Replay the same `checkout.session.completed` event (`stripe events resend`) → exactly one credit batch, no double-grant. Then hit `POST /api/stripe/sync-checkout-session` with the same session id → still one batch.
16. Fire two scans concurrently with exactly 1 credit left → exactly one succeeds; the other 403s. Verify `scansRemaining` never goes negative.
17. Set `lastScanReset` to the previous UTC month on an org holding credits → next quota check resets `scansUsed` to 0 and leaves `scanCredits` untouched.
18. Existing pure-trial org (`billingCycle: 'onetime'`, no subscription) still scans correctly after migration — this is the main backward-compatibility risk.

---

### Critical files for implementation

- `backend/services/planService.js`
- `backend/routes/stripeRoutes.js`
- `backend/models/Organization.js`
- `frontend/src/pages/Profile.jsx`
- `backend/routes/profile.js` (plus paired i18n edits in `frontend/src/locales/en.js` and `frontend/src/locales/ja.js`)
