# Adding `CREDENTIAL_ENCRYPTION_KEY`

Handover note for whoever manages AWS. Should take about ten minutes.

## What this is and why

Scheduled authenticated scans have to keep the customer's website login details,
because the scan signs itself in later with nobody present. Those details were
being stored in MongoDB as readable text. They are now encrypted, and this is
the key.

**Nothing else in the product uses it.** If the key is missing the API still
boots and every other feature works normally — only creating or updating a
*scheduled authenticated scan* fails. That is deliberate: the app refuses to save
rather than quietly falling back to storing a password in the clear.

## Where it goes

Same place as everything else: the existing Secrets Manager secret.

| | |
|---|---|
| Region | `ap-northeast-1` |
| Secret | `fortexa-backend-secrets` (full suffix `-NxEnZI`) |
| New key | `CREDENTIAL_ENCRYPTION_KEY` |
| Value | 64 hex characters |

It is one JSON object holding all the backend secrets, and the task definition
pulls out individual keys. You are adding one key to that object — not creating a
new secret.

## Step 1 — add the key to the secret

Generate and write it in one go, so the key never touches disk or your shell
history:

```bash
aws secretsmanager put-secret-value \
  --secret-id fortexa-backend-secrets \
  --region ap-northeast-1 \
  --secret-string "$(
    aws secretsmanager get-secret-value \
      --secret-id fortexa-backend-secrets \
      --region ap-northeast-1 \
      --query SecretString --output text \
    | jq --arg k "$(openssl rand -hex 32)" '. + {CREDENTIAL_ENCRYPTION_KEY: $k}'
  )"
```

`put-secret-value` replaces the whole JSON object, which is why the command reads
the current value and adds to it. Do not hand-write the object — you would drop
the other twenty keys.

Check it took, without printing the value:

```bash
aws secretsmanager get-secret-value \
  --secret-id fortexa-backend-secrets \
  --region ap-northeast-1 \
  --query SecretString --output text | jq 'keys'
```

`CREDENTIAL_ENCRYPTION_KEY` should be in that list.

**Console alternative:** Secrets Manager → `fortexa-backend-secrets` → Retrieve
secret value → Edit → add the row → Save. Generate the value with
`openssl rand -hex 32` locally and paste it.

## Step 2 — IAM: nothing to do

Secrets Manager permissions are per *secret*, not per key inside it. The task
already reads this secret, so it can read the new key. No policy edit, no role
change.

(For context: the live `fortexa-backend-task-role` currently has the AWS-managed
`SecretsManagerReadWrite` attached, which is broader than the scoped policy in
`iam-policies.json`. That drift is noted in that file and is a separate
conversation — it does not affect this task.)

## Step 3 — deploy the task definition

`infrastructure/backend-task-def.json` already has the new line (and
`worker-task-def.json`, for whenever that split actually happens). Register it
and roll the service.

**Confirm the live names first — the checked-in file has drifted.** It says
`"family": "fortexa-backend-task"`, but its own verification note records the
live task as `fortexa-backend:63`. Read the truth from the running service rather
than trusting either:

```bash
aws ecs describe-services \
  --cluster fortexa-cluster \
  --services fortexa-ec2-backend \
  --region ap-northeast-1 \
  --query 'services[0].taskDefinition'
```

If the family that comes back is not `fortexa-backend-task`, fix the `family`
field in the JSON to match before registering — otherwise you create a brand new
task family that no service is pointing at, and nothing appears to happen.

Then:

```bash
aws ecs register-task-definition \
  --cli-input-json file://infrastructure/backend-task-def.json \
  --region ap-northeast-1

aws ecs update-service \
  --cluster fortexa-cluster \
  --service fortexa-ec2-backend \
  --task-definition <family-from-above> \
  --region ap-northeast-1
```

Also check the `image` tag in the JSON before registering — it is pinned to a
specific version (`fortexa-backend:v40` as checked in) and you almost certainly
want the tag you are actually deploying.

## Step 4 — verify

In the backend task's CloudWatch logs after it restarts, this line should be
**absent**:

```
⚠️  CREDENTIAL_ENCRYPTION_KEY is not set.
```

If it is still there, the container did not pick up the secret — check that the
task definition revision the service is running is the new one.

Functional check: create a scheduled authenticated scan in the app. If it saves,
the key is working.

## Order of operations

Add the secret **before** deploying the code, but either order is safe. Without
the key the app just logs the warning and refuses to save scheduled
authenticated scans; existing scans and everything else keep running.

## Two things to know before you rotate it

1. **Rotating this key makes existing stored credentials unreadable.** They are
   encrypted with it. Any scheduled authenticated scan created before the change
   will fail to log in until its credentials are re-entered. This is not like
   rotating an API key — plan it, and expect to tell affected customers.

2. **It must stay different from `JWT_SECRET`.** A secret used to sign tokens
   must not also encrypt stored data; compromising one would otherwise
   compromise both. There is a test asserting the code never reads `JWT_SECRET`
   for this purpose, but nothing stops someone pasting the same *value* into
   both keys. Don't.

## If you need a key of a specific shape

The app accepts either:

- 64 hex characters — used directly as the 256-bit key (what `openssl rand -hex 32`
  produces, and what you should use).
- Any other non-empty string — stretched into a key. Works, but only as strong as
  the string you chose, so use the hex form.
