# ZAP API key rotation and enforcement

Production ZAP (`zap-scanner-task:1–21`, `zap-auth-task:1–12`) has always run with
`api.disablekey=true`: anything that reaches port 8080 can drive it, including reading the
Replacer rules that hold a Basic-auth scan's customer credential. Only `zap-sg` (8080 from
`fortexa-backend-sg` only) protects it. This rollout turns the key on, with a fresh key,
in an order where every step can be checked before the next one and undone.

Everything runs through `zapKeyRollout.js` (AWS CLI, profile `ssdt`). Each step is a **dry
run unless `--apply`**, refuses to run before the step it depends on, and skips work that
is already done, so re-running is always safe.

```bash
node infrastructure/zap-key-rotation/zapKeyRollout.js status          # read-only, names the next step
node infrastructure/zap-key-rotation/zapKeyRollout.js <step>          # dry run: what it would do
node infrastructure/zap-key-rotation/zapKeyRollout.js <step> --apply  # do it
```

The secret value is only ever held in memory: never printed, logged or written to the repo
(only length, format and a sha256 prefix are shown). Local progress is kept in
`.rollout-state.json` (git-ignored).

## Why a new key

| Fact (verified 2026-11-09) | Consequence |
|---|---|
| The repo is public; a hard-coded ZAP key was in `zapService.js` from `943b2cb` (2025-11-26) to `1fbb156` (2026-04-27), plus `docker-compose.yml`, `.env.example`, `README.md`. | That key is public forever. |
| `fortexa-backend-secrets` JSON key `ZAP_API_KEY` **equals that leaked key** and no active revision references it. | Delete it. |
| `fortexa-backend-secrets` JSON key `ZAP_AUTH_API_KEY` (what every backend revision and the keyed ZAP revisions inject) is 25 characters including non-alphanumerics. | Replace it with 64 hex characters (the keyed ZAP start command accepts only `[A-Za-z0-9]`). |
| The production backend image (`v_basicauth`, `:96`/`:97`) still contains `services/zapService.js.backup` with the hard-coded key. | Gone from the next image (`.dockerignore` now has `*.backup*`, `*.bak*`, `*.orig`). |

## Verified before writing this (local, pinned image `ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47…`, ZAP 2.17.0)

- **ZAP logs the key.** Every `-config` and `-configfile` override is logged at INFO:
  `AbstractParam - Setting config api.key = <the key>`. That line would reach CloudWatch on
  every container start. The keyed task definitions therefore write a home
  `log4j2.properties` (the image's own default, extracted from the jar so it always matches
  the version) with `org.parosproxy.paros.common.AbstractParam` at WARN. Result: the key
  appears in neither stdout nor `zap.log`. A pre-seeded `config.xml` was tried and rejected
  (ZAP needs a `<version>` element and silently regenerates a random key).
- The start command **refuses to start** if `ZAP_API_KEY` is empty or not alphanumeric,
  instead of letting ZAP run with a random key nobody holds.
- With the key enforced, the **real backend modules** (`zapService.checkZapHealth`,
  `zapAuthService.checkZapAuthHealth`, `waitForZapApi` with both `probeConfig()`s used by the
  capacity manager and the recycler, the Basic-auth Replacer rule add, `revokeScanCredentials`)
  all succeed over `http://zap-scanner:8080` / `http://zap-auth-scanner:8080`, as in `:97`.
- **A missing or wrong key is not a 401/403.** This ZAP closes the connection without a
  response: `curl` exit 52, axios `socket hang up` / `ECONNRESET`, and readiness probes report
  "did not respond within …". That is the signature of a key mismatch in the backend log.
- The keyed health check (`curl -f -H "X-ZAP-API-Key: $ZAP_API_KEY" …/version/`) passes, so an
  ECS task only turns HEALTHY when the secret was injected and the key is enforced.

Also verified in AWS: both ZAP families use `ecsTaskExecutionRole`, which already reads
`fortexa-backend-secrets` for the backend; the backend only changes ZAP `desiredCount` (never
the revision), and the ephemeral RunTask path is off, so the service's revision is what runs.

## The order

| Step | Changes | Outage | Undo |
|---|---|---|---|
| `status` | nothing | – | – |
| `1-rotate-secret` | `ZAP_AUTH_API_KEY` ← new 64-hex key; `ZAP_API_KEY` key removed (after scanning every active revision of every family for a reference) | none: ZAP is still keyless, the running backend keeps its old value | `AWSPREVIOUS` holds the old version |
| `2-restart-backend` | force-new-deployment of `fortexa-ec2-backend` on its current revision (`:97`) | **~6–7 min** (minimum healthy 0%) | nothing to undo |
| `3-register-zap` | registers `zap-scanner-task` / `zap-auth-task` from `../zap-task-def.json` / `../zap-auth-task-def.json` (next free revisions, expected `:22` / `:13`) | none: services untouched | deregister |
| `4-verify-zap` | starts **one task of each new revision outside its service** (same capacity provider, subnets and SG), requires HEALTHY + "now listening" + no key and no `Setting config api.key` in its log, then stops it | none (needs both ZAP services idle) | – |
| `5-switch-zap` | points `zap-scan-ec2` / `zap-auth-task-ec2` at the verified revisions; desiredCount unchanged (0 when idle) | none when idle; the next scan starts a keyed task | `rollback-zap` |
| — | run a **normal scan, a form-login scan and a Basic-auth scan** | | |
| `6-check-logs` | read-only: `Setting config api.key` lines (must be 0), ZAP starts, backend ZAP refusals, completed scans since the switch | | |

Step 1 is the only one that touches the secret; step 2 is the only one with an outage.
`4-verify-zap` and `5-switch-zap` refuse while a ZAP service is busy (`--force` overrides).

## Rollback

**Roll back ZAP, never the backend.** `rollback-zap --apply` puts both services back on the
keyless revisions they ran before the switch (`:21` / `:12`). Keyless ZAP ignores the key, so
every backend revision works with it again. No secret change is needed.

The backend cannot be the rollback while ZAP enforces the key:

| Backend revision | Can it drive a keyed ZAP? |
|---|---|
| `:98` (`v66`, production since 2026-11-09) | **yes**: `:97` with only the image changed (built from the tree this runbook was written against) |
| `:97` (`v_basicauth`) | **yes**: maps `ZAP_API_KEY` and `ZAP_AUTH_API_KEY`, and its image sends the key on every client and probe (checked inside the image) |
| `:96` | no: same image, but no `ZAP_API_KEY` mapping, so the normal-scan client sends no key |
| `:91–:95` | no: images predate the keyed readiness probes (`d95508b`) |
| `:80–:90` | cannot start at all: their images are no longer in ECR (no lifecycle policy, so they were deleted by hand). This includes `:85`, the Redis Cloud rollback named in CLAUDE.md, and `:86` |

(The reviewed plan proposed registering `:85`/`:86` with a `ZAP_API_KEY` mapping as rollback
targets. Dropped: their image no longer exists, and its readiness probes never send the key.)

## After the rollout

1. ~~Build and deploy a backend image from the current tree~~ — done 2026-11-09: `v66` as
   `fortexa-backend:98` (log redaction, no `*.backup*` files). Step 2 restarts whatever revision
   the service runs, so it now redeploys `:98`.
2. Replace the leaked key in local `backend/.env` / `backend/.env.production` and the root
   `.env` used by `docker-compose.yml` with your own `openssl rand -hex 32`. The production
   values do not belong in a laptop `.env.production` at all.
3. Optional: rotate `ZAP_AUTH_API_KEY` again later with `1-rotate-secret --again`, then steps 2,
   and a recycle of any running ZAP task (keyed ZAP tasks read the secret only at start).
