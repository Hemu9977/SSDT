# Fortexa Redis — self-managed Valkey on EC2

Production Redis for the Fortexa backend (BullMQ queues, ZAP locks, scan progress,
Gemini dedup, PDF jobs). Replaced Redis Cloud on 2026-10-03. Production runs
**`fortexa-backend:86`**; Redis Cloud via **`fortexa-backend:85`** is the rollback path
(below). The ElastiCache cluster `fortexa-redis` was deleted on 2026-10-03 and is not a
rollback option.

**Stage A (current): always running.** Stage B (idle stop/start) is designed in the
migration plan and must not be enabled until Stage A has run stable in production.

## What exists (ap-northeast-1, account 459181228792)

| Resource | Value |
|---|---|
| Instance | `i-0ae101f3fba1e6cf5` `fortexa-redis-1`, t4g.small arm64, AL2023, Valkey 9.0.6 |
| Network | `subnet-014a7ae2b498c12d3` (private, 1a), fixed IP **10.0.128.50**, no public IP |
| DNS | private zone `fortexa.internal` (`Z0853976OP55AOVHDUKQ`): `redis.fortexa.internal` A 10.0.128.50, TTL 60 |
| Security group | `fortexa-redis-ec2-sg` `sg-0210ca9e77d5136cf`: in tcp/6379 **only** from `fortexa-backend-sg` (sg-0a203b60a3700290e); out tcp/443 only |
| IAM | role + instance profile `fortexa-redis-instance-role`: `AmazonSSMManagedInstanceCore`, `CloudWatchAgentServerPolicy`. Secret access comes from the **resource policy** on `fortexa-redis/host` (the SSO permission set cannot write inline policies). |
| Secrets | `fortexa-redis/host` (cert/key/CA, ACL hashes, ops-admin password; readable only by the instance role) · `fortexa-redis/app` (`REDIS_URL`, `REDIS_TLS_CA`, `REDIS_TLS_SERVERNAME`; read by the backend task definition) |
| Storage | gp3 10 GiB encrypted, `DeleteOnTermination=false`; DLM `policy-0042868d2432c0e03` daily 02:00 JST, keep 7 |
| Protection | termination protection **on**, stop protection **on**, IMDSv2 required (hop 1), no key pair, EC2 auto-recovery on |
| Monitoring | namespace `Fortexa/Redis`, log group `/ec2/fortexa-redis` (30 d), 10 alarms `fortexa-redis-*` → SNS `fortexa-redis-alerts` |
| Patching | SSM association `fortexa-redis-patch-scan` (daily scan only; installs are manual, below) |
| Verification | ECS task family `fortexa-redis-smoke` (Fargate, run on demand by `vpc-smoke.sh`), log group `/ecs/fortexa-redis-smoke` |

The CA private key **never** goes to AWS. It lives in the offline PKI directory
(`~/.fortexa-redis-pki`: `ca.key`, `ca.crt`, `server.*`, `passwords.json`). Keep that
directory in the team password vault; it is needed for certificate renewal.

## Files

| File | Purpose |
|---|---|
| `valkey.conf` | server config (TLS-only port 6379, ACL file, `noeviction`, AOF everysec + RDB) |
| `users.acl.tmpl` | `default` off; `fortexa-app` = all commands except `@dangerous` (+INFO, CLIENT SETNAME); `ops-admin` = everything |
| `fortexa-valkey-secrets` (+ `.service`) | pulls TLS material + ACL hashes from Secrets Manager before **every** Valkey start; retries ~5 min; Valkey does not hard-depend on it, so a Secrets Manager blip cannot keep Redis down |
| `valkey-override.conf` | systemd drop-in: `Restart=always`, never give up, 90 s stop timeout for the shutdown save, sandboxing |
| `fortexa-valkey-metrics` (+ `.service`/`.timer`) | every 60 s: `ValkeyUp` (PING over TLS), memory, clients, AOF/RDB status, cert days left |
| `cloudwatch-agent.json` | host memory/disk + Valkey/bootstrap logs |
| `sysctl-valkey.conf`, `disable-thp.service` | `vm.overcommit_memory=1`, `somaxconn=1024`, THP off |
| `bootstrap.sh`, `build-user-data.sh` | first-boot provisioning, packed into a ≤16 KB user-data |
| `create-secrets.sh` | creates/rotates both secrets from the PKI directory (prints no secrets) |
| `launch-instance.sh` | launches the instance with every setting above |
| `create-alarms.sh` | alarms + backend log metric filter (idempotent) |
| `vpc-smoke.sh` | runs `backend/scripts/redisMigrationSmoke.js` / `redisSecurityProbe.js` from inside the VPC as the backend would |
| `render-backend-taskdef.sh` | builds the cut-over task definition from the **live** revision (read-only) |

## Verified on 2026-10-03

From inside the VPC (Fargate task, backend SG, private subnets, credentials from `fortexa-redis/app`):

- `vpc-smoke.sh full`: **20/20** — TLS, Valkey 9.0.6, `noeviction`, AOF on, ACL user, FLUSHALL/CONFIG SET/DEBUG denied, `zap:lock` SET NX PX + Lua renew/release, SET EX/GET/DEL, PUBLISH→SUBSCRIBE, BullMQ custom jobId, duplicate-jobId no-op, retries with exponential backoff, delayed jobs, getJobCounts/getJob/remove, limiter, 14 h `lockDuration`, stalled-job recovery after a worker crash, obliterate
- `vpc-smoke.sh security`: **7/7** — plaintext reset, no-CA "self-signed certificate in chain", wrong hostname rejected, `default` user NOAUTH, wrong password / unknown user WRONGPASS; control connection works
- `vpc-smoke.sh netblocked` (VPC default SG): port unreachable
- Persistence (key + TTL, waiting job, delayed job) survived `systemctl restart valkey`, an instance **reboot** (Valkey serving 7 s after boot) and an EC2 **stop/start** (stop 21 s; Valkey serving ~35 s after start; IP unchanged)
- `fortexa-redis-valkey-down` fired ~4.5 min after Valkey was stopped, executed the SNS action, and cleared ~1.5 min after restart
- Locally, the backend image built from this code started against the same config: publisher, subscriber, scan-worker and zap-worker connected over TLS, `/ready` reported Redis ready

## Cutover (Stage A) — completed 2026-10-03 (`fortexa-backend:84`); kept for reference

1. **Image:** build and push a backend image from code that contains `REDIS_TLS_CA` support
   (`backend/config/redis.js` → `tlsOptions`). The live `v54` does **not** have it.
2. **Window:** low-traffic JST; no scans in flight (admin → Scans); no scheduled scan due.
3. **Task definition:**
   ```bash
   bash infrastructure/redis-ec2/render-backend-taskdef.sh <NEW_TAG> > /tmp/td.json   # prints the rollback revision
   aws ecs register-task-definition --cli-input-json file:///tmp/td.json
   aws ecs update-service --cluster fortexa-cluster --service fortexa-ec2-backend --task-definition fortexa-backend:<NEW_REV>
   ```
   Only `REDIS_URL` changes source (now `fortexa-redis/app`), plus the two new
   `REDIS_TLS_*` secrets; everything else is copied from the live revision.
4. **Verify:** backend log shows `[Redis] Connected` for publisher, subscriber,
   scan-worker, zap-worker and `In-process BullMQ scan + ZAP workers started`; admin
   System Health shows Redis OK; on the instance `CLIENT LIST` shows ~6 `fortexa-app`
   clients; run one normal scan, one authenticated scan, a PDF (EN + JA), a scheduled
   run-now and a stop-scan.

## Revisions

| Revision | Image | Redis | Role |
|---|---|---|---|
| `fortexa-backend:86` | `v55` @ `sha256:eca8df50…` | EC2 Valkey (`fortexa-redis/app`) | **production** (deployed 2026-10-03) |
| `fortexa-backend:85` | `v55` @ `sha256:eca8df50…` | Redis Cloud (`fortexa-backend-secrets:REDIS_URL`, no `REDIS_TLS_*`) | **rollback** |
| `fortexa-backend:84` | `v55` @ `sha256:eca8df50…` | EC2 Valkey | superseded by 86 (references `ELASTICACHE_REDIS_URL`) |
| `fortexa-backend:83` | `v54` (mutable tag) | Redis Cloud | old, superseded rollback — do not use |

86 and 85 run the same image, so a rollback changes configuration only, not code.

## Rollback

| From → to | Action |
|---|---|
| EC2 → Redis Cloud | `aws ecs update-service --cluster fortexa-cluster --service fortexa-ec2-backend --task-definition fortexa-backend:85`. Its `REDIS_URL` maps to the untouched `fortexa-backend-secrets:REDIS_URL`. In-flight jobs on EC2 are lost (watchdog fails them, quota is not charged). |

Redis Cloud accepts plaintext only (no TLS on its endpoint) and allows 30 clients, so treat
it as an emergency path. Before relying on it, confirm in the Redis Cloud console that the
database is active and its eviction policy is `noeviction`.

**Any deployment of this service causes ~7–8 minutes of downtime**, not seconds: with one task,
`minimumHealthyPercent: 0` and `maximumPercent: 150`, ECS stops the old task before starting
the new one, and the target group (`fortexa-tg`) drains for its 300 s `deregistration_delay`
first. Measured on the 84 → 86 deployment: 503s from 16:23:28 to 16:31:09 UTC.

Never delete Redis Cloud or this instance as part of a rollback.

## ElastiCache retirement (2026-10-03)

Replication group `fortexa-redis` (node `fortexa-redis-001`, Valkey 9.1.0, `cache.t4g.small`,
ap-northeast-1a) was deleted after an audit showed 0 processed commands, 0 keys and 0 new
connections since its creation on 2026-06-30. Its ENI and automatic snapshot are gone;
no ElastiCache charges remain (it was ~$29/month of node-hours).

Left in place, free of charge, to be removed only after confirming nothing else uses them:
subnet group `fortexa-redis-subnet`, parameter group `fortexa-valkey9`, and security groups
`fortexa-redis-sg` (sg-04c7c59b9d23a2c6c), `cloudshell-elasticache-fortexa-redis`
(sg-08a55693e70db1456), `elasticache-cloudshell-fortexa-redis` (sg-0283a9ecb5520efe7).

`fortexa-backend-secrets:ELASTICACHE_REDIS_URL` holds the dead endpoint. Production (86) and
the rollback (85) do not reference it. Revisions 80–84 still do, and ECS cannot start a task
whose referenced secret key is missing, so removing the key makes 80–84 unusable.

## Operations

**Shell access** (no SSH): `aws ssm start-session --target i-0ae101f3fba1e6cf5`, then
```bash
sudo -i
export VALKEYCLI_AUTH="$(cat /etc/valkey/ops-admin.pass)"
valkey-cli --no-auth-warning --tls --cacert /etc/valkey/tls/ca.crt --sni redis.fortexa.internal -h 127.0.0.1 --user ops-admin INFO
```

**Patching (monthly):** check no scans are in flight and none is scheduled within an hour →
`dnf -y upgrade --security` (or SSM `AWS-RunPatchBaseline Operation=Install`) → `reboot` →
`vpc-smoke.sh full`. Valkey reloads from AOF; clients reconnect on their own.

**Certificate renewal** (alarm `fortexa-redis-cert-expiring` at < 30 days): re-sign
`server.crt` with the offline CA (same SANs: `DNS:redis.fortexa.internal`, `IP:10.0.128.50`) →
`create-secrets.sh` → `systemctl restart valkey` (the secrets unit re-runs before start).
The CA itself is valid until 2036.

**Password rotation (no downtime, no Valkey restart).** "Reload ACL" below means, on the
instance: `systemctl start fortexa-valkey-secrets` then `valkey-cli … --user ops-admin ACL LOAD`.
1. `passwords.json`: keep `fortexa_app` = OLD, add `fortexa_app_next` = NEW → `create-secrets.sh` → reload ACL (both accepted).
2. Swap them: `fortexa_app` = NEW, `fortexa_app_next` = OLD → `create-secrets.sh` (`fortexa-redis/app` now carries NEW) → reload ACL → redeploy the backend (it reads the secret at task start) and confirm it connects.
3. Remove `fortexa_app_next` → `create-secrets.sh` → reload ACL (only NEW accepted).

**Rebuild / AZ loss:** the instance is fully reproducible from this directory.
Terminate protection off → `launch-instance.sh` with `SUBNET_ID=subnet-053597cd5e8375650`
(1c) and a free `PRIVATE_IP` from 10.0.144.0/20 → update the `redis.fortexa.internal`
record → re-issue the certificate if the IP SAN matters (clients verify the DNS name) →
`create-alarms.sh` with the new instance ID → redeploy the backend. Redis holds only
transient work; MongoDB is the system of record, and stuck scans are failed by the
watchdog without charging quota.

**Alerts:** subscribe someone to SNS `fortexa-redis-alerts`
(`aws sns subscribe --topic-arn arn:aws:sns:ap-northeast-1:459181228792:fortexa-redis-alerts --protocol email --notification-endpoint <address>`)
— until then alarms fire but notify nobody.

**Stage B note:** before enabling idle stop/start, switch `fortexa-redis-valkey-down` to
`--treat-missing-data notBreaching` and follow the Stage B design in the migration plan.
