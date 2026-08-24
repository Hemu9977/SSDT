/**
 * ZAP Recycler — pre-scan container replacement and cross-process serialization.
 *
 * WHY THIS EXISTS
 * ZAP runs as a single long-lived ECS service. Its JVM (-Xms2g -Xmx11g) never returns
 * heap to the OS, so container RSS climbs from ~890MB to ~10.6GB during the first scan
 * and stays there for as long as the task lives (measured: flat ~10,650MB across 11h of
 * idle). The next scan then starts with ~3.4GB of headroom instead of 14GB. newSession
 * clears ZAP's own state but cannot shrink RSS — only a new container does that.
 *
 * So every scan replaces the ZAP task before it runs, and a lock guarantees exactly one
 * scan (and one recycle) per instance at a time.
 *
 * WHY NOT zapContainerManager.js
 * That module implements RunTask-and-discover-private-IP for per-scan Fargate tasks. We
 * need StopTask-and-let-the-service-scheduler-replace, keeping the stable Service Connect
 * alias. Flipping its ZAP_EPHEMERAL_CONTAINERS gate would also activate a RunTask path
 * targeting a Fargate task family that does not exist here. Its gate stays false; the one
 * thing we borrow is waitForZapApi.
 *
 * CAPACITY CONSTRAINT
 * Each t3.xlarge in ASG fortexa-ecs-asg-xlarge registers 15,791MiB and a ZAP task
 * reserves 14,336MiB, leaving ~1,455MiB free (verified live 2026-08-23 via
 * ecs:DescribeContainerInstances). Old and new tasks cannot coexist on one instance, so
 * the old task must reach STOPPED before ECS can place the replacement. That is why
 * step 3 below is mandatory rather than an optimization.
 *
 * SCALE TO ZERO
 * The ASG was pinned min=max=2. Under services/zapCapacityManager.js it can reach 0:
 * the capacity manager drives ecs:UpdateService desiredCount 0<->1 and the ECS capacity
 * provider follows with the instances. Two consequences for this module:
 *   - withZapInstance calls ensureZapCapacity BEFORE recycling. Recycling a service
 *     scaled to zero would find no tasks to stop and then wait out NEW_TASK_WAIT_MS for
 *     a replacement nothing has asked ECS to place.
 *   - A task the capacity manager just cold-started is fresh by construction, so its
 *     recycle is skipped. That decision is ARN-scoped and is NOT made by widening
 *     FRESH_MAX_AGE_MS, which would weaken the guard for genuinely warm scans.
 * All of it is inert unless ZAP_CAPACITY_MANAGED=true.
 */

const os = require('os');
const crypto = require('crypto');
const axios = require('axios');

const { getPublisher } = require('../config/redis');
const { waitForZapApi } = require('./zapContainerManager');
// Per-instance config (service names, base URLs, probe headers, Redis key names) lives
// in config/zapInstances.js so zapCapacityManager can share it without a circular
// require — this module needs ensureZapCapacity, and that module needs the same config.
const { INSTANCES, getInstance } = require('../config/zapInstances');

const CLUSTER = () => process.env.ECS_CLUSTER_NAME || 'fortexa-cluster';

const RECYCLE_TIMEOUT_MS = () => Number(process.env.ZAP_RECYCLE_TIMEOUT_MS) || 480000; // 8 min
const LOCK_WAIT_MS       = () => Number(process.env.ZAP_LOCK_WAIT_MS) || 1800000;      // 30 min
const LOCK_TTL_MS        = 120000; // short on purpose — see acquireZapLock
const LOCK_HEARTBEAT_MS  = 20000;
const POLL_MS            = 5000;
/**
 * Budget for "the service scheduler places a replacement", beyond which the ECS
 * placement events are surfaced and the recycle fails.
 *
 * Deliberately still 150s by default even though a cold start takes 4–8 minutes.
 * This constant only ever governs a *warm* recycle — one where an instance is
 * already registered and the ZAP image is already in its Docker cache, so 150s is
 * generous. The cold-start path never reaches step 4 at all: withZapInstance skips
 * the recycle entirely for a task the capacity manager just started, and the
 * scale-from-zero wait is governed by ZAP_CAPACITY_WAIT_MS instead. Raising this
 * would only delay the detection of a genuine warm-placement fault.
 *
 * Made configurable so that can be revisited from a task-definition change rather
 * than a deploy.
 */
const NEW_TASK_WAIT_MS   = () => Number(process.env.ZAP_NEW_TASK_WAIT_MS) || 150000;

// A task younger than this is treated as already fresh and is never stopped. This is the
// guard that stops a late or duplicate recycle request from killing a replacement that a
// previous recycle just created.
const FRESH_MAX_AGE_MS   = () => Number(process.env.ZAP_FRESH_MAX_AGE_MS) || 120000;

// Held only for the duration of a recycle, never for the duration of a scan. Deliberately
// separate from the scan lock: cancellation and ops paths must be able to recycle without
// waiting on a 12-hour scan lock, and nothing may acquire the scan lock while holding this
// one. Lock ordering is always scan -> recycle, so the two cannot deadlock.
const RECYCLE_LOCK_TTL_MS = () => RECYCLE_TIMEOUT_MS() + 60000;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ============================================================================
// ERRORS
// ============================================================================

/**
 * Typed failure. `code` is what callers branch on and what gets persisted; `message` is
 * English and for server logs only — never put it in an API response (CLAUDE.md).
 */
class ZapRecycleError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'ZapRecycleError';
    this.code = code;
    this.details = details;
  }
}

// ============================================================================
// ECS CLIENT (lazy — avoids ~10MB parse cost when recycling is disabled)
// ============================================================================

let _ecs = null;
let _ecsCommands = null;

function ecs() {
  if (!_ecs) {
    const sdk = require('@aws-sdk/client-ecs');
    _ecsCommands = sdk;
    _ecs = new sdk.ECSClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
  }
  return { client: _ecs, ...(_ecsCommands) };
}

function isAccessDenied(err) {
  return err?.name === 'AccessDeniedException'
    || err?.name === 'AccessDenied'
    || err?.$metadata?.httpStatusCode === 403
    || /not authorized to perform/i.test(err?.message || '');
}

/** Wrap an ECS call so IAM failures surface as a distinct, non-retryable code. */
async function ecsCall(fn, what) {
  try {
    return await fn();
  } catch (err) {
    if (isAccessDenied(err)) {
      throw new ZapRecycleError(
        'ECS_ACCESS_DENIED',
        `${what} denied — IAM policy FortexaZapRecycleAccess missing on fortexa-backend-task-role: ${err.message}`
      );
    }
    throw err;
  }
}

// ============================================================================
// LOCK
// ============================================================================

// Fallback used only when Redis is unreachable. Correct while the backend runs as a
// single task (DISABLE_WORKER=false, worker in-process); best-effort if ever scaled out.
const memoryLocks = new Map(); // lockKey -> token

// Release only if we still own the key. A bare DEL would let a holder whose TTL expired
// delete its successor's lock.
const RELEASE_LUA = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0`;

const RENEW_LUA = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0`;

async function tryAcquire(lockKey, token) {
  try {
    const res = await getPublisher().set(lockKey, token, 'NX', 'PX', LOCK_TTL_MS);
    return res === 'OK';
  } catch (err) {
    console.warn(`[ZapLock] Redis unavailable for ${lockKey}, falling back to in-memory: ${err.message}`);
    if (memoryLocks.has(lockKey)) return false;
    memoryLocks.set(lockKey, token);
    return true;
  }
}

/**
 * Acquire the per-instance lock, waiting up to ZAP_LOCK_WAIT_MS.
 *
 * TTL is deliberately short (120s) with a 20s heartbeat rather than scan-length. A
 * scan-length TTL would wedge ZAP for the rest of the day if the backend is SIGKILLed
 * mid-scan (deploy, OOM, instance replacement); a short TTL self-clears ~2min after the
 * holder dies, which is less than the recycle the next scan performs anyway. Six missed
 * renewals of slack absorbs Redis blips.
 */
async function acquireZapLock(key, scanId, { waitMs } = {}) {
  const inst = getInstance(key);
  const lockKey = inst.lockKey;
  const token = `${os.hostname()}:${process.pid}:${scanId}:${crypto.randomUUID()}`;
  const deadline = Date.now() + (waitMs ?? LOCK_WAIT_MS());

  let waited = false;
  while (Date.now() < deadline) {
    if (await tryAcquire(lockKey, token)) {
      const handle = { key, lockKey, token, scanId, lost: false, timer: null };
      startHeartbeat(handle);
      if (waited) console.log(`[ZapLock] acquired instance=${inst.label} scanId=${scanId} afterWait=true`);
      return handle;
    }
    if (!waited) {
      console.log(`[ZapLock] waiting instance=${inst.label} scanId=${scanId}`);
      waited = true;
    }
    // Jitter so simultaneous waiters do not stampede the same tick.
    await sleep(POLL_MS + Math.floor(Math.random() * 1000));
  }

  throw new ZapRecycleError('LOCK_TIMEOUT', `Timed out waiting for ${lockKey} after ${waitMs ?? LOCK_WAIT_MS()}ms`);
}

function startHeartbeat(handle) {
  handle.timer = setInterval(async () => {
    try {
      if (memoryLocks.get(handle.lockKey) === handle.token) return; // in-memory: no expiry
      const ok = await getPublisher().eval(RENEW_LUA, 1, handle.lockKey, handle.token, String(LOCK_TTL_MS));
      if (ok !== 1) {
        // Someone else owns the key now. Do not abort an in-flight scan over this —
        // killing a hours-old scan is worse than the risk it guards against — but stop
        // renewing and refuse any further recycle under this handle.
        handle.lost = true;
        clearInterval(handle.timer);
        handle.timer = null;
        console.error(`[ZapLock] LOST instance=${handle.key} scanId=${handle.scanId} — lock reacquired elsewhere`);
      }
    } catch (err) {
      console.warn(`[ZapLock] renew failed instance=${handle.key}: ${err.message}`);
    }
  }, LOCK_HEARTBEAT_MS);
  handle.timer.unref();
}

async function releaseZapLock(handle) {
  if (!handle) return;
  if (handle.timer) {
    clearInterval(handle.timer);
    handle.timer = null;
  }
  if (memoryLocks.get(handle.lockKey) === handle.token) {
    memoryLocks.delete(handle.lockKey);
    return;
  }
  try {
    await getPublisher().eval(RELEASE_LUA, 1, handle.lockKey, handle.token);
  } catch (err) {
    console.warn(`[ZapLock] release failed instance=${handle.key} (will expire in ${LOCK_TTL_MS}ms): ${err.message}`);
  }
}

/**
 * Non-blocking recycle mutex. Returns a token on success, null if a recycle is already
 * running for this instance.
 *
 * Non-blocking on purpose: a caller that finds a recycle in progress already gets what it
 * wanted — a fresh container shortly — so queueing behind it would only produce a second,
 * redundant recycle after the first finished.
 */
async function tryAcquireRecycleLock(inst, scanId) {
  const token = `${os.hostname()}:${process.pid}:${scanId}:${crypto.randomUUID()}`;
  try {
    const ok = await getPublisher().set(inst.recycleLockKey, token, 'NX', 'PX', RECYCLE_LOCK_TTL_MS());
    return ok === 'OK' ? token : null;
  } catch (err) {
    console.warn(`[ZapRecycle] Redis unavailable for ${inst.recycleLockKey}, falling back to in-memory: ${err.message}`);
    if (memoryLocks.has(inst.recycleLockKey)) return null;
    memoryLocks.set(inst.recycleLockKey, token);
    return token;
  }
}

async function releaseRecycleLock(inst, token) {
  if (!token) return;
  if (memoryLocks.get(inst.recycleLockKey) === token) { memoryLocks.delete(inst.recycleLockKey); return; }
  try {
    await getPublisher().eval(RELEASE_LUA, 1, inst.recycleLockKey, token);
  } catch (err) {
    console.warn(`[ZapRecycle] recycle-lock release failed for ${inst.label}: ${err.message}`);
  }
}

// ============================================================================
// RECYCLE
// ============================================================================

const remaining = (deadline) => deadline - Date.now();

function assertTime(deadline, step) {
  if (remaining(deadline) <= 0) {
    throw new ZapRecycleError('TIMEOUT', `Recycle exceeded ${RECYCLE_TIMEOUT_MS()}ms during ${step}`);
  }
}

async function listRunningTaskArns(inst) {
  const { client, ListTasksCommand } = ecs();
  const res = await ecsCall(
    () => client.send(new ListTasksCommand({
      cluster: CLUSTER(),
      serviceName: inst.service(),
      desiredStatus: 'RUNNING'
    })),
    'ecs:ListTasks'
  );
  return res.taskArns || [];
}

async function describeTasks(arns) {
  if (!arns.length) return { tasks: [], failures: [] };
  const { client, DescribeTasksCommand } = ecs();
  return ecsCall(
    () => client.send(new DescribeTasksCommand({ cluster: CLUSTER(), tasks: arns })),
    'ecs:DescribeTasks'
  );
}

/** Read the ZAP sites tree. Empty == this daemon has scanned nothing. */
async function readSites(inst) {
  const res = await axios.get(`${inst.baseUrl()}/JSON/core/view/sites/`, {
    timeout: 10000,
    ...inst.probeConfig()
  });
  return res.data?.sites || [];
}

/**
 * Replace the ZAP task for `key` and return once a genuinely fresh daemon answers.
 *
 * @param {'normal'|'auth'} key
 * @param {{scanId?: string, reason?: string, lock?: object}} opts
 */
async function recycleZapInstance(key, { scanId = 'n/a', reason = 'pre-scan', lock = null } = {}) {
  const inst = getInstance(key);
  const started = Date.now();
  const deadline = started + RECYCLE_TIMEOUT_MS();

  if (lock && lock.lost) {
    throw new ZapRecycleError('LOCK_TIMEOUT', 'Refusing to recycle without confirmed lock ownership');
  }

  // Serialise recycles per instance. Without this, concurrent callers each stop whatever
  // task is current, so one caller's replacement becomes the next caller's victim.
  const recycleToken = await tryAcquireRecycleLock(inst, scanId);
  if (!recycleToken) {
    console.log(`[ZapRecycle] instance=${inst.label} scanId=${scanId} result=skip reason=recycle-in-progress`);
    return { taskArn: null, elapsedMs: Date.now() - started, recycled: false, reason: 'recycle-in-progress' };
  }

  try {
  console.log(`[ZapRecycle] start instance=${inst.label} scanId=${scanId} reason=${reason} service=${inst.service()}`);

  // 1. Find the current task(s).
  const oldArns = await listRunningTaskArns(inst);
  if (!oldArns.length) {
    console.warn(`[ZapRecycle] no RUNNING tasks for ${inst.service()} — service may already be replacing one`);
  }

  // 1a. Generation guard: never stop a container that is already fresh. Age comes from
  // the task's own startedAt rather than any state we keep, so it stays correct across a
  // backend restart and cannot drift. This is what makes recycling idempotent — a burst
  // of requests produces one recycle and N cheap no-ops instead of N teardowns.
  if (oldArns.length) {
    const { tasks } = await describeTasks(oldArns);
    const newest = (tasks || [])
      .filter(t => t.startedAt)
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))[0];
    if (newest) {
      const ageMs = Date.now() - new Date(newest.startedAt).getTime();
      if (ageMs < FRESH_MAX_AGE_MS()) {
        console.log(`[ZapRecycle] instance=${inst.label} scanId=${scanId} result=skip reason=already-fresh ` +
                    `ageMs=${ageMs} task=${newest.taskArn}`);
        return { taskArn: newest.taskArn, elapsedMs: Date.now() - started, recycled: false, reason: 'already-fresh' };
      }
    }
  }

  // 2. Stop them. Only ARNs this function just listed are ever passed to StopTask —
  //    ecs:StopTask cannot be IAM-scoped to a single service, so this is the control
  //    that keeps blast radius inside the ZAP service. Never accept an ARN from a
  //    caller, request body, or DB field here.
  const { client, StopTaskCommand, DescribeServicesCommand } = ecs();
  // Re-list immediately before stopping. Between step 1 and here the scheduler may have
  // replaced a task on its own; stopping a vanished ARN is harmless but stopping a
  // successor would not be.
  const stillRunning = new Set(await listRunningTaskArns(inst));
  for (const arn of oldArns) {
    if (!arn.startsWith(`arn:aws:ecs:`) || !arn.includes(`:task/${CLUSTER()}/`)) {
      throw new ZapRecycleError('NOT_FRESH', `Refusing to stop unexpected task ARN: ${arn}`);
    }
    if (!stillRunning.has(arn)) {
      console.log(`[ZapRecycle] task=${arn} already gone — skipping StopTask`);
      continue;
    }
    await ecsCall(
      () => client.send(new StopTaskCommand({
        cluster: CLUSTER(),
        task: arn,
        reason: `ZAP pre-scan recycle (scanId=${scanId})`
      })),
      'ecs:StopTask'
    );
    console.log(`[ZapRecycle] stopped task=${arn}`);
  }

  // 3. Wait for them to actually be gone. Mandatory: 14,336MiB cannot be double-allocated
  //    so the replacement is unplaceable until this releases, and during the ~30s SIGTERM
  //    grace the dying task still answers /JSON/core/view/version/ — polling health here
  //    would happily "succeed" against the container we just killed.
  while (oldArns.length) {
    assertTime(deadline, 'waiting for old task to stop');
    const { tasks, failures } = await describeTasks(oldArns);
    const missing = new Set((failures || []).filter(f => f.reason === 'MISSING').map(f => f.arn));
    const alive = (tasks || []).filter(t => t.lastStatus !== 'STOPPED' && !missing.has(t.taskArn));
    if (!alive.length) break;
    await sleep(POLL_MS);
  }
  if (oldArns.length) console.log(`[ZapRecycle] old task(s) STOPPED after ${Date.now() - started}ms`);

  // 4. Wait for the scheduler to place a replacement.
  const oldSet = new Set(oldArns);
  const newTaskDeadline = Math.min(deadline, Date.now() + NEW_TASK_WAIT_MS());
  let newArn = null;
  while (!newArn) {
    assertTime(deadline, 'waiting for replacement task');
    const arns = (await listRunningTaskArns(inst)).filter(a => !oldSet.has(a));
    if (arns.length) {
      const { tasks } = await describeTasks(arns);
      const dead = (tasks || []).find(t => t.lastStatus === 'STOPPED');
      if (dead) {
        throw new ZapRecycleError('REPLACEMENT_DIED', `Replacement task stopped: ${dead.stoppedReason || 'unknown'}`, {
          taskArn: dead.taskArn
        });
      }
      const running = (tasks || []).find(t => t.lastStatus === 'RUNNING');
      // Not waiting for healthStatus HEALTHY: startPeriod 60 + interval 30 makes it lag
      // usable-API by up to ~30s. Step 5 is the tighter and more truthful readiness signal.
      if (running) { newArn = running.taskArn; break; }
    }
    if (Date.now() > newTaskDeadline) {
      // Almost always a placement failure. Surface the scheduler's own reason — this is
      // where a RESOURCE:CPU/MEMORY shortfall becomes diagnosable instead of a hang.
      let events = [];
      try {
        const svc = await ecsCall(
          () => client.send(new DescribeServicesCommand({ cluster: CLUSTER(), services: [inst.service()] })),
          'ecs:DescribeServices'
        );
        events = (svc.services?.[0]?.events || []).slice(0, 5).map(e => e.message);
      } catch (err) {
        // ecs:DescribeServices is optional — the live FortexaZapRecycleAccess policy grants
        // only ListTasks/DescribeTasks/StopTask. Without it we lose the scheduler's reason
        // for the placement failure but still fail correctly.
        console.warn(`[ZapRecycle] service events unavailable (ecs:DescribeServices not granted?): ${err.message}`);
      }
      events.forEach(m => console.error(`[ZapRecycle] service event: ${m}`));
      throw new ZapRecycleError('PLACEMENT_FAILED', `No replacement task placed within ${NEW_TASK_WAIT_MS()}ms`, { events });
    }
    await sleep(POLL_MS);
  }
  console.log(`[ZapRecycle] replacement RUNNING task=${newArn} after ${Date.now() - started}ms`);

  // 5. Wait for the API to answer through the Service Connect alias.
  assertTime(deadline, 'waiting for ZAP API');
  try {
    await waitForZapApi(inst.baseUrl(), remaining(deadline), inst.probeConfig());
  } catch (err) {
    throw new ZapRecycleError('API_NOT_READY', `ZAP API did not answer after replacement: ${err.message}`, {
      taskArn: newArn
    });
  }

  // 6. Verify it is genuinely fresh. ZAP exposes no uptime or heap endpoint, so an empty
  //    sites tree is the practical assertion — and it doubles as proof the request landed
  //    on the new daemon rather than a stale Envoy endpoint.
  try {
    const sites = await readSites(inst);
    if (sites.length) {
      throw new ZapRecycleError('NOT_FRESH', `Replacement reports ${sites.length} existing site(s)`, {
        siteCount: sites.length,
        taskArn: newArn
      });
    }
  } catch (err) {
    if (err instanceof ZapRecycleError) throw err;
    // A probe failure here is not proof of staleness; step 5 already established the API
    // answers. Log and continue rather than failing a scan on a flaky read.
    console.warn(`[ZapRecycle] freshness probe inconclusive: ${err.message}`);
  }

  const elapsedMs = Date.now() - started;
  console.log(`[ZapRecycle] instance=${inst.label} scanId=${scanId} result=ok taskArn=${newArn} elapsedMs=${elapsedMs}`);
  return { taskArn: newArn, elapsedMs, recycled: true };

  } finally {
    await releaseRecycleLock(inst, recycleToken);
  }
}

// ============================================================================
// ORCHESTRATION
// ============================================================================

/**
 * Decide whether the task currently behind this instance was cold-started by the
 * capacity manager, in which case recycling it is pure cost.
 *
 * Two ways a scan can arrive at an already-fresh cold-started task:
 *   1. This very call scaled it out (`capacity.coldStarted`), or
 *   2. a fire-and-forget warm-up at scan acceptance did, minutes earlier, while the
 *      fast scanners ran. That result is gone by now, so the capacity manager leaves
 *      an ARN-scoped marker in Redis and this consumes it.
 *
 * The ARN scoping is what makes this safe: a stale marker naming a task that is no
 * longer running can never cause a *different* task's recycle to be skipped. The
 * marker is also only ever written after the ZAP API has answered, so "cold started"
 * already implies "was ready".
 */
async function resolveColdStart(key, capacity) {
  const { peekColdStartMarker, consumeColdStartMarker } = require('./zapCapacityManager');

  if (capacity && capacity.coldStarted && capacity.taskArn) {
    await consumeColdStartMarker(key, capacity.taskArn);
    return { skip: true, reason: 'cold-start', taskArn: capacity.taskArn };
  }

  const marker = await peekColdStartMarker(key);
  if (!marker) return { skip: false };

  const arns = await listRunningTaskArns(getInstance(key));
  // Always consume: whether it matched or not, this marker has had its chance.
  await consumeColdStartMarker(key, marker);
  if (arns.includes(marker)) {
    return { skip: true, reason: 'cold-start-warmup', taskArn: marker };
  }
  return { skip: false };
}

/**
 * Hold the instance lock, ensure capacity, recycle, then run `fn`. The recycle always
 * lands before the caller's newSession/context setup, which is required — newSession
 * discards contexts.
 *
 * @param {'normal'|'auth'} key
 * @param {string} scanId
 * @param {Function} fn
 * @param {{recycle?: boolean}} opts
 */
async function withZapInstance(key, scanId, fn, { recycle = true } = {}) {
  const lock = await acquireZapLock(key, scanId);
  try {
    // Capacity before recycle, and inside the lock. Before, because there is nothing
    // to recycle on a service scaled to zero — the recycler's ListTasks would return
    // empty and its step 4 would wait out NEW_TASK_WAIT_MS for a replacement that
    // nothing has asked ECS to place. Inside, because the scan lock already
    // serialises this instance, so two scans cannot both drive a scale-out from here.
    //
    // A no-op (and no ECS call at all) unless ZAP_CAPACITY_MANAGED=true and this key
    // is listed in ZAP_CAPACITY_KEYS.
    let capacity = { managed: false, coldStarted: false };
    try {
      const { ensureZapCapacity } = require('./zapCapacityManager');
      capacity = await ensureZapCapacity(key, { scanId });
    } catch (err) {
      const code = err.code || 'INTERNAL';
      console.error(`[ZapCapacity] instance=${key} scanId=${scanId} result=fail code=${code} — ${err.message}`);
      // Same fail-mode contract as the recycle below: FAIL_MODE=proceed means "try the
      // scan anyway", which is the right call if the service was in fact already up and
      // only our reads failed.
      if (process.env.ZAP_RECYCLE_FAIL_MODE === 'proceed') {
        console.warn('[ZapCapacity] FAIL_MODE=proceed — continuing without confirmed capacity');
      } else {
        throw err;
      }
    }

    let skippedForColdStart = false;
    if (recycle && process.env.ZAP_RECYCLE_ENABLED !== 'false') {
      try {
        const cold = await resolveColdStart(key, capacity);
        if (cold.skip) {
          const inst = getInstance(key);
          console.log(`[ZapRecycle] instance=${key} scanId=${scanId} result=skip reason=${cold.reason} ` +
                      `task=${cold.taskArn} — a cold-started task is already fresh`);
          // Re-verify at the point of use rather than trusting a readiness check that
          // happened minutes ago during the warm-up. One HTTP GET on the happy path.
          // Note this stays inside the try: a readiness failure here is a startup
          // failure and belongs to the fail-mode contract below, whereas fn()'s own
          // errors must NOT be — hence the flag rather than an early return.
          await waitForZapApi(inst.baseUrl(), RECYCLE_TIMEOUT_MS(), inst.probeConfig());
          skippedForColdStart = true;
        }

        const result = skippedForColdStart
          ? null
          : await recycleZapInstance(key, { scanId, lock });
        // A skipped recycle ('already-fresh' or 'recycle-in-progress') never reached the
        // readiness poll inside recycleZapInstance, so the container may be seconds old
        // and not yet listening — ECS sets startedAt when the container starts, but ZAP
        // needs ~10s more to bind :8080. Poll before handing control to the scan, or the
        // first ZAP call fails against a container that was about to be fine.
        if (result && result.recycled === false) {
          const inst = getInstance(key);
          console.log(`[ZapRecycle] instance=${key} scanId=${scanId} recycle skipped (${result.reason}) — verifying readiness`);
          await waitForZapApi(inst.baseUrl(), RECYCLE_TIMEOUT_MS(), inst.probeConfig());
        }
      } catch (err) {
        // err.code covers ZapCapacityError too — resolveColdStart reads Redis and ECS
        // through the capacity manager, so its typed failures surface here as well.
        const code = err.code || 'INTERNAL';
        console.error(`[ZapRecycle] instance=${key} scanId=${scanId} result=fail code=${code} — ${err.message}`);
        if (process.env.ZAP_RECYCLE_FAIL_MODE === 'proceed') {
          console.warn(`[ZapRecycle] FAIL_MODE=proceed — continuing on the existing instance`);
        } else {
          throw err;
        }
      }
    }
    return await fn();
  } finally {
    await releaseZapLock(lock);
  }
}

/**
 * One-shot startup check. Without it, a missing IAM policy only shows up as the first
 * scan of the day failing. Never throws — this must not block boot.
 *
 * Probes with ListTasks rather than DescribeServices, deliberately: ListTasks is the
 * first call a recycle makes, so this tests the permission the hot path actually needs
 * instead of a neighbouring one. It also validates the configured service names — a
 * wrong name raises ServiceNotFoundException here rather than mid-scan. StopTask cannot
 * be probed without stopping something, so it is verified by the first real recycle.
 */
async function preflightEcsAccess() {
  if (process.env.ZAP_RECYCLE_ENABLED === 'false') {
    console.log('[ZapRecycle] preflight skipped — ZAP_RECYCLE_ENABLED=false');
    return { ok: false, skipped: true };
  }

  const results = [];
  for (const key of Object.keys(INSTANCES)) {
    const inst = INSTANCES[key];
    try {
      const arns = await listRunningTaskArns(inst);
      results.push({ key, service: inst.service(), runningTasks: arns.length });
    } catch (err) {
      const code = err instanceof ZapRecycleError ? err.code : (err.name || 'INTERNAL');
      console.error(
        `[ZapRecycle] preflight FAILED instance=${inst.label} service=${inst.service()} ` +
        `code=${code} — recycling will fail: ${err.message}`
      );
      return { ok: false, code, instance: key };
    }
  }

  const summary = results.map(r => `${r.service}(${r.runningTasks} running)`).join(', ');
  console.log(`[ZapRecycle] preflight ok — cluster=${CLUSTER()} services=${summary}`);
  return { ok: true, results };
}

module.exports = {
  recycleZapInstance,
  withZapInstance,
  acquireZapLock,
  releaseZapLock,
  preflightEcsAccess,
  ZapRecycleError
};
