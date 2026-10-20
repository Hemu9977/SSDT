# Backend monitoring and log retention

Scripts for two audit findings that need AWS changes (see
`docs/ADMIN_DASHBOARD_AUDIT.md`). **Neither has been run.** Both change
production AWS resources and need team approval first.

| Script | Finding | What it changes |
|---|---|---|
| `create-alarms.sh` | M8: no alarm watches the API | 4 CloudWatch alarms on `fortexa-alb` / `fortexa-tg` (no healthy target, unhealthy target, 5xx rate) and a metric filter + alarm on `❌` error lines in `/ecs/fortexa-backend` |
| `set-log-retention.sh` | L7: logs kept forever, contain personal data | `put-retention-policy` on the backend log groups (default 365 days) |

## Before running

1. Create or choose an SNS topic that actually reaches on-call, and pass its ARN as
   `ALERT_TOPIC_ARN`. (The Redis alarms use `fortexa-redis-alerts`.)
2. Agree on the log retention period. Applying it **deletes** older log events.
3. Check that the dimensions still match:
   `aws elbv2 describe-target-groups --names fortexa-tg` and
   `aws elbv2 describe-load-balancers --names fortexa-alb`.

## Verify afterwards

```bash
aws cloudwatch describe-alarms --alarm-name-prefix fortexa-backend \
  --query 'MetricAlarms[].[AlarmName,StateValue]' --output text
aws cloudwatch set-alarm-state --alarm-name fortexa-backend-5xx \
  --state-value ALARM --state-reason "drill"   # confirm the page arrives, then:
aws cloudwatch set-alarm-state --alarm-name fortexa-backend-5xx --state-value OK --state-reason "drill over"
```

Alarm 5 (`fortexa-backend-running-tasks`) is created only with `CONTAINER_INSIGHTS=true`,
because it needs Container Insights enabled on `fortexa-cluster` (extra cost). Alarm cost:
about US$0.10 per alarm per month, plus the metric filter's custom metric (about US$0.30/month).

## Admin System Health: AWS cards (not applied)

The `aws_backend`, `aws_alarms` and `email` cards (`backend/config/healthInventory.js`) read
AWS through the task role. Until the steps below are approved and done, the first two show
**Unknown — not configured** (no env vars) or **Unknown — permission denied** (no IAM); nothing
else is affected and no card claims the resources are healthy.

1. IAM: `system-health-iam-policy.json` (read-only: `ecs:DescribeServices` on the backend
   service, `elasticloadbalancing:DescribeTargetHealth`, `cloudwatch:GetMetricData`,
   `cloudwatch:DescribeAlarms` on `fortexa-*`). SES reads are already covered.
2. Task-definition environment (new revision; values from §3.3 of the audit, re-verify first):

   | Variable | Value |
   |---|---|
   | `HEALTH_ECS_SERVICE` | `fortexa-ec2-backend` |
   | `HEALTH_ALB_TARGET_GROUP_ARN` | `arn:aws:elasticloadbalancing:ap-northeast-1:459181228792:targetgroup/fortexa-tg/6a576c2b619be6c3` |
   | `HEALTH_ALB_LOAD_BALANCER_ARN` | `arn:aws:elasticloadbalancing:ap-northeast-1:459181228792:loadbalancer/app/fortexa-alb/96dcec7a7809f822` |
   | `HEALTH_ALARM_PREFIX` | `fortexa-` |
   | `GIT_SHA` (optional) | commit the image was built from |

   `ECS_CLUSTER_NAME` and `USE_AWS_SES` are already set.

## Admin System Health: PageSpeed, urlscan and Gemini (Vertex AI)

All three are checked live from the backend; keys never leave the server
(`backend/services/systemHealth.js`). Verified 2026-10-20 against the real APIs:
valid PageSpeed and urlscan keys → healthy; invalid keys → "credentials rejected".

| Card | Environment variables (names only) | Production source | Check | Quota / cost |
|---|---|---|---|---|
| PageSpeed | `PSI_API_KEY` | `fortexa-backend-secrets` key `PSI_API_KEY` (task-def `secrets`) | `runPagespeed?url=not-a-url&key=…`: Google validates the key and API, then rejects the URL (`400 INVALID_PARAMETER`); no Lighthouse run | 1 query per check, healthy result cached 5 min (≤ 288/day); default quota 25,000/day |
| urlscan | `URLSCAN_API_KEY` | `fortexa-backend-secrets` key `URLSCAN_API_KEY` | `GET https://urlscan.io/user/quotas/` with header `API-Key`; returns remaining quotas | No scan spent; cached 5 min |
| Gemini | `GOOGLE_APPLICATION_CREDENTIALS` (`/app/config/gcp-wif.json`), `VERTEX_PROJECT`, `VERTEX_LOCATION`, `GEMINI_MODEL_PRO`, `GEMINI_MODEL_FLASH` | Task-def environment + WIF config in the image (no key: AWS → Google workload identity federation, pool `fortexa-aws-pool`) | `countTokens` on both models through the scans' own client: proves auth, project, API, IAM and regional model availability; generates nothing | Not billed (Google Vertex AI docs); own quota; cached 5 min |

Failed results are re-checked after 1 minute, so a fixed key shows up quickly.

**Configuring the keys securely (needs approval; not done):**
1. PageSpeed: in the Google Cloud project that owns the key, enable *PageSpeed Insights API*.
   Restrict the key to that API only (API restriction). Do not use an HTTP-referrer
   restriction: the call comes from the server.
2. Store or rotate a value with
   `aws secretsmanager put-secret-value` on `fortexa-backend-secrets`, keeping every other
   JSON key. Never put a key in the repo, the task-definition `environment` or a log.
   The backend reads secrets at task start, so a rotated value needs a new deployment.
3. urlscan: use the team account's API key (urlscan.io → Settings → API Keys).
4. Gemini: nothing to add. The impersonated service account needs `roles/aiplatform.user`
   (or `aiplatform.endpoints.predict`) on the Vertex project, the same permission real
   reports already use. A `SERVICE_DISABLED` result means the Vertex AI API is off in that
   project; `model_unavailable` means a model name is not served in `VERTEX_LOCATION`.

## Application-side changes already made

- Admin request logs (`middleware/adminAuth.js`, `routes/admin.js`) now log account
  ids instead of email addresses. Other routes still log emails in places; a wider
  sweep is a separate task.
- `GET /api/admin/system-health` no longer returns raw driver/axios error text
  (which held internal hostnames); failures carry a coarse `reason` code.
