# Deploy runbook — consumption tax at checkout (`53e9063`)

Covers everything on `main` since the last deploy, but the part that **needs new
configuration** is the tax change. Region `ap-south-1`, account `459181228792`.

> **Checkout is disabled until step 1–3 are done.** The backend now refuses to create a
> Stripe session (`503 TAX_NOT_CONFIGURED`) while `STRIPE_TAX_RATE_ID` is unset, because the
> pricing UI quotes a tax-inclusive total and taking payment without the tax rate attached
> would charge customers less than they were shown. Do steps 1–3 **before** step 4.

---

## 1. Stripe Dashboard — create the tax rate

Products → **Tax rates** → *Create tax rate*

| Field | Value |
|---|---|
| Rate | `10` % |
| Inclusive / Exclusive | **Exclusive** |
| Region | Japan |
| Description | Japanese consumption tax |

Copy the id — it looks like `txr_1AbC...`.

**Why exclusive:** every `STRIPE_PRICE_*` is the tax-excluded amount (Light monthly = ¥30,000).
Stripe adds 10% on top, so the customer is charged ¥33,000 — matching the "Including Tax"
figure on the plan card.

---

## 2. Secrets Manager — store it

Same naming convention as the existing secrets (`ssdt/<VARNAME>`, plaintext value):

```bash
aws secretsmanager create-secret \
  --region ap-south-1 \
  --name ssdt/STRIPE_TAX_RATE_ID \
  --secret-string 'txr_XXXXXXXXXXXX'
```

**No IAM change needed.** The execution role already grants
`arn:aws:secretsmanager:ap-south-1:459181228792:secret:ssdt/*`, which covers this.

---

## 3. Task definition — map the secret in

⚠️ **This is the step that gets missed.** Creating the secret does nothing on its own; ECS only
injects what is listed in the container's `secrets[]` array.

⚠️ **Do NOT edit `infrastructure/backend-task-def.json` and register that.** That file has **no
Stripe variables in it at all** — no `STRIPE_SECRET_KEY`, no price IDs, no webhook secret — so
it is out of date with what is actually running. Registering it would strip Stripe config off
the live task and break billing entirely.

Pull the **live** definition, edit that, and register it:

```bash
# 1. dump what is actually deployed
aws ecs describe-task-definition --region ap-south-1 \
  --task-definition ssdt-backend-task \
  --query 'taskDefinition' > live-backend-task-def.json

# 2. add the entry to containerDefinitions[0].secrets[]:
#    { "name": "STRIPE_TAX_RATE_ID",
#      "valueFrom": "arn:aws:secretsmanager:ap-south-1:459181228792:secret:ssdt/STRIPE_TAX_RATE_ID" }
#
#    (strip the read-only fields ECS returns: taskDefinitionArn, revision, status,
#     requiresAttributes, compatibilities, registeredAt, registeredBy)

# 3. register the new revision
aws ecs register-task-definition --region ap-south-1 \
  --cli-input-json file://live-backend-task-def.json
```

Confirm before moving on:

```bash
aws ecs describe-task-definition --region ap-south-1 \
  --task-definition ssdt-backend-task \
  --query 'taskDefinition.containerDefinitions[0].secrets[?name==`STRIPE_TAX_RATE_ID`]'
```

**Also do this for the worker task** (`ssdt-worker-task`, same image). The worker mounts
`stripeRoutes` too (`server.js:124`), so without the var it logs the startup warning on every
boot. It does not serve checkout traffic, so this is log hygiene rather than a functional need —
but it avoids a confusing warning during incident triage.

---

## 4. Backend — build, push, deploy

```bash
aws ecr get-login-password --region ap-south-1 \
  | docker login --username AWS --password-stdin 459181228792.dkr.ecr.ap-south-1.amazonaws.com

docker build -t ssdt-backend ./backend
docker tag ssdt-backend:latest 459181228792.dkr.ecr.ap-south-1.amazonaws.com/ssdt-backend:latest
docker push 459181228792.dkr.ecr.ap-south-1.amazonaws.com/ssdt-backend:latest

aws ecs update-service --region ap-south-1 \
  --cluster <cluster> --service <backend-service> \
  --task-definition ssdt-backend-task \
  --force-new-deployment
```

Watch the new task come up and check the log **does not** contain:

```
⚠️  [stripe] STRIPE_TAX_RATE_ID is not set. Checkout is DISABLED until it is
```

If it does, step 2 or 3 did not take effect.

---

## 5. Frontend — must be rebuilt

Not optional. The tax display, the new locale strings, the Japanese default and the checkout
fixes are all compiled into the JS bundle, so an unchanged frontend will not show any of it.

```bash
cd frontend
npm ci
REACT_APP_API_URL=<api url> npm run build

aws s3 sync build/ s3://<frontend-bucket>/ --delete
aws cloudfront create-invalidation --distribution-id <dist-id> --paths '/*'
```

The CloudFront invalidation matters — without it users keep the cached old bundle and will still
see prices without tax.

---

## 6. Outstanding from the earlier merge — confirm before or after

**`backend/scripts/migrateOneTimeCredits.js` has not been confirmed as run.** It backfills legacy
one-time trial customers onto the new `scanCredits` model.

It is **no longer a hard blocker** — `c15d9ee` added a fallback so unmigrated orgs keep working
off the old `oneTimeRemainingScans` field — but it should still be run to close one gap: an
unmigrated org that buys a *new* one-time plan gets a credit batch for the new purchase only,
and its old remaining balance becomes unreachable.

```bash
# dry run first — prints candidates, writes nothing
node backend/scripts/migrateOneTimeCredits.js

# then apply
node backend/scripts/migrateOneTimeCredits.js --apply

# re-run the dry run; it is idempotent, so this should now report 0 candidates
node backend/scripts/migrateOneTimeCredits.js
```

Needs `MONGO_URI` in the environment it runs from.

---

## 7. Verify

1. **Checkout is live** — open the pricing section, confirm each card shows the price,
   "Excluding Tax", and "Including Tax: ¥33,000".
2. **Tax is actually charged** — start a checkout with Stripe test card `4242 4242 4242 4242`.
   The Stripe page must show a **Tax** line and a ¥33,000 total, not ¥30,000. This is the whole
   point of the change; if the total is ¥30,000 the tax rate is not attached.
3. **Cancelled payment behaves** — click browser Back from Stripe. The button must return to
   "Buy Extra Scans" (not stay on "Redirecting…"), and the cancelled banner must **not** offer a
   refresh button.
4. **Plan label** — an account with no purchase shows **Free** / フリープラン, never "PRO".
5. **Language** — toggle to English, reload; it must stay English.

---

## Rollback

Config-only rollback (fastest, restores billing to the pre-tax behaviour):

```bash
aws ecs update-service --region ap-south-1 \
  --cluster <cluster> --service <backend-service> \
  --task-definition ssdt-backend-task:<previous-revision> \
  --force-new-deployment
```

Note the previous revision **undercharges** — it takes ¥30,000 against a ¥33,000 quote if the
frontend is still deployed. If you roll the backend back, roll the frontend back too, or the
displayed and charged amounts disagree.

Leaving `STRIPE_TAX_RATE_ID` unset is *not* a rollback: checkout stays refused by design.

---

## One thing to remember afterwards

The 10% lives in **two places** with nothing enforcing they agree:

- the Stripe Tax Rate created in step 1
- `TAX_RATE` in `frontend/src/pages/Profile.jsx`

If the rate ever changes, change both. Both files carry a comment pointing at the other.
