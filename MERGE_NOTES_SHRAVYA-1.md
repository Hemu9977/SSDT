# Merge Summary: SHRAVYA-1 → main (June 13, 2026)

> **TL;DR:** Shravya's new work (background scan queues, resilience, multi-language UI, AWS infra) is now merged into `main` — **without losing the Stripe payment integration or the Gemini security fixes** that were already on main. Everyone should pull `main` and read the two "Heads-up" items below before running the app.

---

## Why this merge was tricky

Shravya started the `SHRAVYA-1` branch **before** the payment integration and recent security fixes were merged into `main`. So her branch was 18 commits behind, and several files were rewritten on both sides. A naive merge would have silently deleted the payment system and re-introduced a fixed security leak. The merge was done carefully, file by file, with main's payment + security logic always taking priority.

---

## What we gained from SHRAVYA-1

| Area | What's new |
|------|-----------|
| **Scan engine** | Scans no longer run inside the API request. They are queued in **BullMQ (Redis)** and executed by background workers. The API responds instantly and progress streams to the browser over WebSocket. |
| **Reliability** | New resilience utilities: automatic retries, circuit breakers, HTTP connection pooling, concurrency limits. A Gemini "completion orchestrator" guarantees every scan reaches a final state (no more scans stuck forever). |
| **Gemini / AI** | Migrated to the new `@google/genai` SDK with **Vertex AI** support. Two model tiers: `gemini-2.5-pro` for deep reports, `gemini-2.5-flash` for formatting/translation. Hard timeouts and retry/fallback built in. |
| **Multi-language UI** | Full English/Japanese locale system (`frontend/src/locales/`), language toggle, translation hook. |
| **PDF downloads** | PDFs are now generated as **async jobs** (`POST /api/scan/pdf-job` → poll) instead of one long blocking request — no more timeouts on big reports. |
| **AWS deployment** | ECS/Fargate task definitions (separate backend + worker tasks), CloudFront response headers (CSP), health (`/health`) and readiness (`/ready`) probes. |
| **UI refresh** | Updated auth pages, dashboard, profile, scan panels, notification handling. |

## What we protected from main (would have been lost otherwise)

1. **The entire Stripe payment system** — webhook with raw-body signature verification, `/api/stripe` checkout/subscription routes, `/api/org` organization routes, plan models. All byte-identical to before the merge.
2. **Plan enforcement on scans** — the `planCheck` middleware (scan quotas) and quota refund on failed starts had been dropped on her branch; they are restored on `/combined-url-scan`.
3. **Severity gating** — Light-plan users still only see Critical/High vulnerabilities, in API responses, JSON export, PDF export, **and** in the data sent to Gemini.
4. **Gemini data-leak fix** — her new background worker was sending the raw customer URL, IPs, and unfiltered alerts to Gemini. The sanitization layer (`sanitizeScanForLLM`, `assertNoLeakage`) was retrofitted into the new worker path, so the fix from commit `59e9017` still holds.
5. **API route prefix** — her frontend called `/api/vt/...`; main uses `/api/scan/...`. All calls normalized to `/api/scan/`.

---

## ⚠️ Heads-up #1: Local MongoDB no longer works

The new `backend/db.js` **requires a MongoDB Atlas connection string** (`mongodb+srv://...`). It refuses to start with `mongodb://localhost/...`.

**What you need to do:** update `MONGO_URI` in your local `backend/.env` to the team's Atlas cluster URI. If you don't, the server exits at startup with:

```
❌ MONGO_URI must use a MongoDB Atlas connection string (mongodb+srv://...)
```

## ⚠️ Heads-up #2: Redis is now REQUIRED for scans

Scans are executed through a BullMQ queue, which lives in Redis. **No `REDIS_URL` = no scans at all** (the server still boots, but every scan stays queued forever).

**What you need to do:** set `REDIS_URL` in `backend/.env`:

- Local Redis (e.g. Docker): `redis://localhost:6379`
- Redis Cloud (TLS): `rediss://<user>:<password>@<host>:<port>`

Optional: `DISABLE_WORKER=true` makes the API server stop running scans itself — only set this in deployments that run a dedicated worker task (`node workers/startWorker.js`).

---

## After pulling main, everyone should:

1. `cd backend && npm install` (new deps: bullmq, ioredis, @google/genai, cacheable-lookup; removed: @google/generative-ai)
2. `cd frontend && npm install`
3. Update `backend/.env`: Atlas `MONGO_URI` + `REDIS_URL` (see heads-ups above; `backend/.env.example` documents everything, including the Stripe and Redis sections)
4. Start Redis before starting the backend

## Still to verify (needs staging environment)

- One live Stripe **test-mode checkout** end-to-end. Locally we verified the routes mount and load correctly, but no `STRIPE_SECRET_KEY` was available to exercise a real checkout session.
