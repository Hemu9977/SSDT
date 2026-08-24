'use strict';

/**
 * ZAP capacity manager — scale-to-zero for the two ZAP ECS services.
 *
 * WHY THIS EXISTS
 * The two t3.xlarge instances in ASG fortexa-ecs-asg-xlarge exist solely to host
 * zap-scan-ec2 and zap-auth-task-ec2. Measured 2026-08-23, they sat at 1.9–2.0% CPU
 * for four days at $317.73/month. This module lets them go away when idle.
 *
 * WHY THE BACKEND HAS TO DRIVE IT
 * ECS capacity-provider managed scaling reacts to *pending tasks*, never to an HTTP
 * request, so there is no AWS-native path from "user clicked Scan" to "launch an
 * instance". Worse, while a ZAP service holds desiredCount 1 the ASG can never reach
 * zero: the unplaceable task pegs CapacityProviderReservation at 200 and managed
 * scaling immediately scales back out. Something must own desiredCount, and the
 * backend is the only component that knows whether a scan is running.
 *
 * So: this module owns ecs:UpdateService desiredCount 0<->1. The existing capacity
 * provider still owns the ASG — we never call autoscaling:SetDesiredCapacity, and we
 * never write a scaling policy. Scaling *in* from a second controller is how you
 * terminate an instance under a live scan.
 *
 * WHY NOT zapContainerManager.js
 * That module runs a fresh Fargate task per scan and discovers its private IP. We
 * need the opposite: keep the stable Service Connect alias (zap-scanner /
 * zap-auth-scanner) and only change how many tasks stand behind it. The one thing we
 * borrow is waitForZapApi, which is already the readiness signal the recycler trusts.
 *
 * RELATIONSHIP TO THE RECYCLER
 * The recycler replaces a *stale* ZAP task because the JVM never returns heap to the
 * OS. A task that was just cold-started is fresh by construction, so recycling it is
 * pure cost and a second chance to fail. This module publishes an ARN-scoped
 * cold-start marker; zapRecycler.withZapInstance consumes it and skips the recycle.
 * The marker is only ever written *after* waitForZapApi has succeeded, so "cold
 * started" and "ready" cannot come apart.
 */

const os = require('os');
const crypto = require('crypto');

const { getPublisher } = require('../config/redis');
const { getInstance, INSTANCE_KEYS } = require('../config/zapInstances');
const { waitForZapApi } = require('./zapContainerManager');

const CLUSTER = () => process.env.ECS_CLUSTER_NAME || 'fortexa-cluster';

// ─── Timeouts ────────────────────────────────────────────────────────────────
// Sized against the measured cold start (see docs): scale-out detection 60–120s,
// EC2 boot + agent registration 60–120s, image pull 90–240s, JVM boot 30–60s.
// p50 ~5 min, p95 ~9 min uncached.

/** Whole scale-from-zero budget. 10 min covers p95 with margin. */
const CAPACITY_WAIT_MS = () => Number(process.env.ZAP_CAPACITY_WAIT_MS) || 600000;

/**
 * Idle period before scaling in. Must exceed the ASG DefaultCooldown (300s) by a
 * wide margin, or a scan arriving just after scale-in stalls waiting for a cooldown
 * that has not expired.
 */
const IDLE_SCALEIN_MS = () => Number(process.env.ZAP_IDLE_SCALEIN_MS) || 1200000;

/**
 * Lock TTL. The guarded operation is itself bounded by CAPACITY_WAIT_MS, so a TTL
 * two minutes beyond that self-clears if the holder is SIGKILLed mid-scale-out
 * without ever expiring under a healthy holder.
 */
const CAPACITY_LOCK_TTL_MS = () => CAPACITY_WAIT_MS() + 120000;

/**
 * Cold-start marker lifetime. Long enough to bridge "warm-up fired at scan
 * acceptance" to "the ZAP job reached withZapInstance" (fast scanners in between),
 * short enough that a marker cannot survive into an unrelated later scan. The
 * ARN scoping is the real guard; this is belt and braces.
 */
const COLD_START_MARKER_TTL_MS = () => Number(process.env.ZAP_COLDSTART_TTL_MS) || 900000;

// Poll interval for the scale-out waits. Configurable mainly so tests do not have to
// sit through real 5-second sleeps; 5s in production matches the recycler's cadence.
const POLL_MS = () => Number(process.env.ZAP_CAPACITY_POLL_MS) || 5000;
// Check for a task that started and died only every Nth poll — a full extra
// ListTasks per 5s would double the API calls to catch a case that is rare but
// needs to fail fast when it happens (CannotPullContainerError on a cold instance).
const DEATH_CHECK_EVERY = 6; // ~30s
// Most tasks one DescribeTasks call accepts. The death check describes up to this many
// STOPPED tasks because ListTasks does not order its results and scale-to-zero leaves a
// stopped task behind on every idle period.
const DESCRIBE_TASKS_MAX = 100;

// Scans whose ZAP leg has not reached a terminal state yet. 'provisioning' is what
// both authenticated entry points write at acceptance (the route's skeleton and the
// scheduler's), so it covers the whole window between accept and startAsyncAuthScan
// — which spans the capacity wait, the recycle and up to ZAP_LOCK_WAIT_MS of queueing
// behind another scan.
const ACTIVE_ZAP_STATUSES = ['pending', 'queued', 'running', 'starting', 'provisioning'];
// Top-level scan states that mean work is still owed.
const IN_FLIGHT_SCAN_STATUSES = ['queued', 'pending', 'combining'];

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const remaining = (deadline) => deadline - Date.now();

// ─── Kill switch ─────────────────────────────────────────────────────────────

/**
 * Master switch. Default false: shipping this module must not change behaviour
 * until it is deliberately turned on, and turning it back off is a one-variable
 * rollback that needs no redeploy of anything else.
 */
function isCapacityManaged() {
  return process.env.ZAP_CAPACITY_MANAGED === 'true';
}

/**
 * Which instances are under capacity management.
 *
 * Defaults to both, which is the point of the feature: the two t3.xlarge instances
 * exist only to host these two services, and leaving either one pinned keeps an
 * instance alive and most of the saving on the table. Set to 'auth' alone for a
 * staged rollout that leaves the busier normal-scan path untouched.
 */
function capacityKeys() {
  const raw = (process.env.ZAP_CAPACITY_KEYS || 'normal,auth').trim();
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(k => INSTANCE_KEYS.includes(k));
}

function isManagedKey(key) {
  return isCapacityManaged() && capacityKeys().includes(key);
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/**
 * Typed failure. `code` is what callers branch on and what gets persisted; `message`
 * is English and for server logs only — never put it in an API response (CLAUDE.md).
 *
 * Deliberately shaped like ZapRecycleError (same `.code` / `.details` contract) so
 * zapWorker's terminal-failure mapping can branch on the code without caring which
 * subsystem raised it.
 */
class ZapCapacityError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'ZapCapacityError';
    this.code = code;
    this.details = details;
  }
}

// ─── ECS client (lazy — avoids ~10MB parse cost when disabled) ───────────────

let _ecs = null;
let _sdk = null;

function ecs() {
  if (!_ecs) {
    _sdk = require('@aws-sdk/client-ecs');
    _ecs = new _sdk.ECSClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
  }
  return { client: _ecs, ..._sdk };
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
      throw new ZapCapacityError(
        'ECS_ACCESS_DENIED',
        `${what} denied — IAM policy FortexaZapRecycleAccess on fortexa-backend-task-role ` +
        `is missing ecs:UpdateService and/or ecs:DescribeServices: ${err.message}`
      );
    }
    throw err;
  }
}

// ─── Redis primitives ────────────────────────────────────────────────────────

// Fallback used only when Redis is unreachable. Correct while the backend runs as a
// single task (DISABLE_WORKER=false, worker in-process); best-effort if scaled out.
const memoryLocks = new Map();
const memoryKv = new Map();

const RELEASE_LUA = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0`;

async function redisSet(key, value, ttlMs) {
  try {
    await getPublisher().set(key, value, 'PX', ttlMs);
  } catch (err) {
    memoryKv.set(key, { value, expires: Date.now() + ttlMs });
  }
}

async function redisGet(key) {
  try {
    return await getPublisher().get(key);
  } catch (err) {
    const hit = memoryKv.get(key);
    if (!hit) return null;
    if (hit.expires < Date.now()) { memoryKv.delete(key); return null; }
    return hit.value;
  }
}

async function redisDel(key) {
  try {
    await getPublisher().del(key);
  } catch {
    memoryKv.delete(key);
  }
}

async function redisExists(key) {
  try {
    return (await getPublisher().exists(key)) === 1;
  } catch {
    const hit = memoryKv.get(key);
    if (hit && hit.expires >= Date.now()) return true;
    return memoryLocks.has(key);
  }
}

/**
 * Non-blocking capacity mutex. Returns a token on success, null if another caller is
 * already scaling this instance out.
 *
 * Non-blocking on purpose, exactly as tryAcquireRecycleLock is: a caller that finds a
 * scale-out already running wants the same thing it would have asked for, so it
 * follows that scale-out instead of queueing to issue a redundant second one.
 */
async function tryAcquireCapacityLock(inst, scanId) {
  const token = `${os.hostname()}:${process.pid}:${scanId}:${crypto.randomUUID()}`;
  try {
    const ok = await getPublisher().set(inst.capacityLockKey, token, 'NX', 'PX', CAPACITY_LOCK_TTL_MS());
    return ok === 'OK' ? token : null;
  } catch (err) {
    console.warn(`[ZapCapacity] Redis unavailable for ${inst.capacityLockKey}, falling back to in-memory: ${err.message}`);
    if (memoryLocks.has(inst.capacityLockKey)) return null;
    memoryLocks.set(inst.capacityLockKey, token);
    return token;
  }
}

async function releaseCapacityLock(inst, token) {
  if (!token) return;
  if (memoryLocks.get(inst.capacityLockKey) === token) {
    memoryLocks.delete(inst.capacityLockKey);
    return;
  }
  try {
    await getPublisher().eval(RELEASE_LUA, 1, inst.capacityLockKey, token);
  } catch (err) {
    console.warn(`[ZapCapacity] lock release failed for ${inst.label} (expires in <=${CAPACITY_LOCK_TTL_MS()}ms): ${err.message}`);
  }
}

// ─── ECS reads ───────────────────────────────────────────────────────────────

async function describeZapService(inst) {
  const { client, DescribeServicesCommand } = ecs();
  const res = await ecsCall(
    () => client.send(new DescribeServicesCommand({ cluster: CLUSTER(), services: [inst.service()] })),
    'ecs:DescribeServices'
  );
  const svc = res.services?.[0];
  if (!svc) {
    throw new ZapCapacityError('SERVICE_NOT_FOUND', `ECS service ${inst.service()} not found in ${CLUSTER()}`);
  }
  return {
    desiredCount: svc.desiredCount ?? 0,
    runningCount: svc.runningCount ?? 0,
    pendingCount: svc.pendingCount ?? 0,
    events: (svc.events || []).slice(0, 5).map(e => e.message)
  };
}

async function listTaskArns(inst, desiredStatus) {
  const { client, ListTasksCommand } = ecs();
  const res = await ecsCall(
    () => client.send(new ListTasksCommand({
      cluster: CLUSTER(),
      serviceName: inst.service(),
      desiredStatus
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

// ─── State / marker helpers ──────────────────────────────────────────────────

async function setState(inst, state, scanId, taskArn = null) {
  await redisSet(
    inst.capacityStateKey,
    JSON.stringify({ state, scanId, taskArn, at: new Date().toISOString() }),
    CAPACITY_LOCK_TTL_MS()
  );
}

/** Record that a scan wants this instance. Read by the idle scale-in check. */
async function markZapDemand(key) {
  if (!isManagedKey(key)) return;
  try {
    const inst = getInstance(key);
    await redisSet(inst.demandKey, String(Date.now()), IDLE_SCALEIN_MS() * 2);
  } catch (err) {
    // Demand marking is an optimisation, never a correctness requirement — the DB
    // and queue guards in releaseZapCapacityIfIdle are what actually protect a scan.
    console.warn(`[ZapCapacity] markZapDemand(${key}) failed: ${err.message}`);
  }
}

async function demandAgeMs(inst) {
  const raw = await redisGet(inst.demandKey);
  if (!raw) return null;
  const at = Number(raw);
  if (!Number.isFinite(at)) return null;
  return Date.now() - at;
}

/** Written only after waitForZapApi has proven this task answers. */
async function setColdStartMarker(inst, taskArn) {
  await redisSet(inst.coldStartKey, taskArn, COLD_START_MARKER_TTL_MS());
}

async function peekColdStartMarker(key) {
  const inst = getInstance(key);
  return redisGet(inst.coldStartKey);
}

/**
 * Clear the marker if it still refers to `taskArn`. Returns true when it matched,
 * i.e. when the caller is entitled to treat the current task as cold-started.
 */
async function consumeColdStartMarker(key, taskArn) {
  const inst = getInstance(key);
  const current = await redisGet(inst.coldStartKey);
  if (!current || current !== taskArn) return false;
  await redisDel(inst.coldStartKey);
  return true;
}

// ─── Scale out ───────────────────────────────────────────────────────────────

function assertTime(deadline, step) {
  if (remaining(deadline) <= 0) {
    throw new ZapCapacityError('CAPACITY_TIMEOUT', `Capacity wait exceeded ${CAPACITY_WAIT_MS()}ms during ${step}`);
  }
}

/**
 * Poll until the service has a RUNNING task, failing fast if a task starts and dies.
 * On a cold instance the most likely death is CannotPullContainerError, which is
 * worth surfacing in ~30s rather than after the full 10-minute budget.
 *
 * @param {number} scaleOutStartedAt epoch ms — only tasks ECS created at or after this
 *   instant belong to the current scale-out. See the death check below; getting this
 *   wrong is how a deliberate scale-in gets reported as a launch failure.
 */
async function waitForRunningTask(inst, deadline, scaleOutStartedAt) {
  let tick = 0;
  for (;;) {
    assertTime(deadline, 'waiting for a RUNNING ZAP task');

    const arns = await listTaskArns(inst, 'RUNNING');
    if (arns.length) {
      const { tasks } = await describeTasks(arns);
      const running = (tasks || []).find(t => t.lastStatus === 'RUNNING');
      // Not waiting for healthStatus HEALTHY: startPeriod 60 + interval 30 makes it
      // lag usable-API by up to ~30s. The waitForZapApi probe below is the tighter
      // and more truthful readiness signal — same reasoning as zapRecycler step 5.
      if (running) return running.taskArn;
    }

    if (tick % DEATH_CHECK_EVERY === (DEATH_CHECK_EVERY - 1)) {
      const stopped = await listTaskArns(inst, 'STOPPED');
      if (stopped.length) {
        // Describe as many as one DescribeTasks call allows rather than an arbitrary
        // handful. Under scale-to-zero every idle period leaves another STOPPED task
        // behind (bounded only by ECS's ~1h retention) and ListTasks ordering is
        // unspecified, so a genuinely dead task can sit well down the list. With the
        // narrow ownership filter below, examining too few would trade this bug for a
        // missed detection.
        const { tasks } = await describeTasks(stopped.slice(0, DESCRIBE_TASKS_MAX));

        // Only tasks ECS created FOR THIS scale-out can evidence its failure.
        //
        // This replaced a "stopped within the last CAPACITY_WAIT_MS" lookback, which
        // is what made every scale-out under scale-to-zero report CAPACITY_TASK_DIED:
        // the task that the PREVIOUS idle scale-in deliberately stopped was still
        // inside that 10-minute window, so it was picked up and blamed on the current
        // scale-out. Observed in production 2026-08-24 — the idle check scaled in at
        // 17:47:41, a scan arrived at 17:58:11, and the death check fired at 17:58:37
        // against the task stopped ten minutes earlier
        // (stopCode ServiceSchedulerInitiated, "Scaling activity initiated by
        // (deployment ecs-svc/...)"), while the real replacement started fine at
        // 17:59:48.
        //
        // createdAt, deliberately, not startedAt: a task that dies on
        // CannotPullContainerError never reaches startedAt, and that is the exact case
        // this check exists to surface in ~30s instead of after the full budget.
        //
        // createdAt, deliberately, not stoppedAt: a previous-generation task still
        // winding down may stop after our scale-out began, but it was never launched
        // for us and its death is not our failure.
        //
        // stopCode is reported for diagnosis but is NOT used to suppress: excluding
        // ServiceSchedulerInitiated would also hide a genuine mid-scale-out stop (an
        // instance terminating under the task, a container the scheduler reaped),
        // turning a fast diagnosable failure into a silent timeout. Ownership by
        // creation time is the honest discriminator, and releaseZapCapacityIfIdle
        // already refuses to scale in while the capacity mutex is held, so our own
        // idle check cannot be the one stopping this task.
        const recent = (tasks || [])
          .filter(t => t.stoppedAt && t.createdAt
                    && new Date(t.createdAt).getTime() >= scaleOutStartedAt)
          .sort((a, b) => new Date(b.stoppedAt) - new Date(a.stoppedAt))[0];
        if (recent) {
          const containerReason = (recent.containers || [])
            .map(c => c.reason).filter(Boolean).join('; ');
          throw new ZapCapacityError(
            'CAPACITY_TASK_DIED',
            `ZAP task stopped while scaling up: ${recent.stoppedReason || 'unknown'}${containerReason ? ` — ${containerReason}` : ''}`,
            { taskArn: recent.taskArn, stoppedReason: recent.stoppedReason, stopCode: recent.stopCode }
          );
        }
      }
    }

    tick++;
    await sleep(POLL_MS());
  }
}

/**
 * Wait out someone else's scale-out.
 *
 * Deliberately polls ECS rather than the state key: if the leader is SIGKILLed
 * mid-scale-out, the state key freezes at 'scaling_up' forever but the UpdateService
 * it already issued still takes effect, and this loop still succeeds. Correctness
 * never depends on a value another process promised to write.
 */
async function followScaleOut(inst, { deadline, started }) {
  for (;;) {
    assertTime(deadline, 'following another scale-out');
    const live = await describeZapService(inst);
    if (live.runningCount >= 1) {
      // Resolve the ARN rather than just reporting coldStarted:true. The leader writes
      // its cold-start marker only after its own waitForZapApi returns, and both sides
      // are polling the same signal — so a follower that reported no ARN would race the
      // marker and, losing, send the recycler after a task that is seconds old.
      // (FRESH_MAX_AGE_MS would then skip it anyway, but by accident rather than by
      // design.) Returning the ARN makes resolveColdStart's first branch hit every
      // time: this call watched the service go 0 -> 1, so the task IS cold-started
      // whether or not the marker has landed yet.
      // `started` is this follower's own entry, not the leader's. It can only matter in
      // the narrow race where the RUNNING task we just observed stops before the poll
      // below sees it; the resulting miss degrades to a timeout, never to a false
      // CAPACITY_TASK_DIED.
      const taskArn = await waitForRunningTask(inst, deadline, started);
      await waitForZapApi(inst.baseUrl(), remaining(deadline), inst.probeConfig());
      return {
        managed: true,
        coldStarted: true,
        reason: 'followed-scale-out',
        taskArn,
        elapsedMs: Date.now() - started
      };
    }
    // Give up only once the leader is demonstrably gone AND desiredCount is still 0.
    //
    // Checking desiredCount alone is wrong and was: between the leader acquiring the
    // mutex and issuing UpdateService there is a window in which followers legitimately
    // observe 0. Bailing out there turned every burst of concurrent scan starts into
    // spurious CAPACITY_SCALE_OUT_FAILED for all but one caller. While the mutex is
    // held, a leader is still working and this must keep waiting.
    if (live.desiredCount === 0 && !(await redisExists(inst.capacityLockKey))) {
      throw new ZapCapacityError('CAPACITY_SCALE_OUT_FAILED',
        `Followed a scale-out for ${inst.service()} that never raised desiredCount`);
    }
    await sleep(POLL_MS());
  }
}

/**
 * Guarantee that `key` has a ZAP task running and answering its API.
 *
 * @param {'normal'|'auth'} key
 * @param {{scanId?: string, waitMs?: number}} opts
 * @returns {Promise<{managed:boolean, coldStarted:boolean, reason:string, taskArn?:string, elapsedMs?:number}>}
 *
 * Fast path (service already running) performs ONE DescribeServices call and no
 * write — it is safe to call on every scan, warm or cold.
 */
async function ensureZapCapacity(key, { scanId = 'n/a', waitMs } = {}) {
  if (!isManagedKey(key)) {
    return { managed: false, coldStarted: false, reason: 'not-managed' };
  }

  const inst = getInstance(key);
  const started = Date.now();
  const deadline = started + (waitMs ?? CAPACITY_WAIT_MS());

  // Fast path. No probe here on purpose: this module owns *capacity*, not health. A
  // service with a running task that has stopped answering is the recycler's problem,
  // and it already has a readiness poll for exactly that.
  const live = await describeZapService(inst);
  if (live.desiredCount >= 1 && live.runningCount >= 1) {
    return { managed: true, coldStarted: false, reason: 'already-running', elapsedMs: Date.now() - started };
  }

  const token = await tryAcquireCapacityLock(inst, scanId);
  if (!token) {
    console.log(`[ZapCapacity] instance=${inst.label} scanId=${scanId} scale-out already in progress — following`);
    return followScaleOut(inst, { deadline, started });
  }

  try {
    // Double-checked: the previous holder may have finished between our fast path
    // read and the lock acquisition.
    const now = await describeZapService(inst);
    if (now.desiredCount >= 1 && now.runningCount >= 1) {
      return { managed: true, coldStarted: false, reason: 'already-running', elapsedMs: Date.now() - started };
    }

    console.log(`[ZapCapacity] start instance=${inst.label} scanId=${scanId} service=${inst.service()} ` +
                `desired=${now.desiredCount} running=${now.runningCount}`);

    // Ownership boundary for the death check: any task ECS creates from here on belongs
    // to this scale-out, and anything created earlier does not. Taken BEFORE the
    // UpdateService call, never after — a task created in the moment between the two
    // would otherwise look older than the scale-out that caused it and its death would
    // be missed. Erring this way costs nothing: the tasks it lets through are ones the
    // previous generation left behind, and those are excluded by creation time anyway.
    const scaleOutStartedAt = Date.now();

    if (now.desiredCount < 1) {
      const { client, UpdateServiceCommand } = ecs();
      await ecsCall(
        () => client.send(new UpdateServiceCommand({
          cluster: CLUSTER(),
          service: inst.service(),
          desiredCount: 1
        })),
        'ecs:UpdateService'
      );
      console.log(`[ZapCapacity] desiredCount=1 requested for ${inst.service()}`);
    }
    await setState(inst, 'scaling_up', scanId);

    let taskArn;
    try {
      taskArn = await waitForRunningTask(inst, deadline, scaleOutStartedAt);
    } catch (err) {
      if (err instanceof ZapCapacityError && err.code === 'CAPACITY_TIMEOUT') {
        // Almost always a placement or launch failure. Surface the scheduler's own
        // reason — this is where a capacity shortfall becomes diagnosable instead of
        // a hang. Needs ecs:DescribeServices, which is why the IAM policy grows.
        const svc = await describeZapService(inst).catch(() => ({ events: [] }));
        svc.events.forEach(m => console.error(`[ZapCapacity] service event: ${m}`));
        throw new ZapCapacityError('CAPACITY_TIMEOUT', err.message, { events: svc.events });
      }
      throw err;
    }
    console.log(`[ZapCapacity] task RUNNING task=${taskArn} after ${Date.now() - started}ms`);

    // Readiness is the ZAP API answering, not ECS saying RUNNING. Nothing downstream
    // may treat this task as usable before this resolves.
    assertTime(deadline, 'waiting for ZAP API');
    try {
      await waitForZapApi(inst.baseUrl(), remaining(deadline), inst.probeConfig());
    } catch (err) {
      throw new ZapCapacityError('CAPACITY_API_NOT_READY',
        `ZAP API did not answer after scale-out: ${err.message}`, { taskArn });
    }

    // Only now is the task both cold-started and ready. Publishing the marker any
    // earlier would let withZapInstance skip a recycle for a task that cannot serve.
    await setColdStartMarker(inst, taskArn);
    await setState(inst, 'ready', scanId, taskArn);

    const elapsedMs = Date.now() - started;
    console.log(`[ZapCapacity] instance=${inst.label} scanId=${scanId} result=ok coldStart=true ` +
                `task=${taskArn} elapsedMs=${elapsedMs}`);
    return { managed: true, coldStarted: true, reason: 'scaled-out', taskArn, elapsedMs };
  } finally {
    await releaseCapacityLock(inst, token);
  }
}

// ─── Scale in ────────────────────────────────────────────────────────────────

/**
 * Is any scan still owed ZAP work on this instance?
 *
 * Queried per-instance so a long normal scan does not pin the auth instance up.
 * Covers scheduled scans for free: they write the same ScanResult fields as
 * interactive ones, so `triggerSource` never needs to be considered here.
 */
async function hasActiveZapScans(key) {
  const ScanResult = require('../models/ScanResult');
  const field = key === 'auth' ? 'authScanResult.status' : 'zapResult.status';

  const active = await ScanResult.countDocuments({
    status: { $in: IN_FLIGHT_SCAN_STATUSES },
    [field]: { $in: ACTIVE_ZAP_STATUSES }
  });
  if (active > 0) return { busy: true, reason: 'active-zap-scan', count: active };

  if (key === 'normal') {
    // A normal scan owes ZAP work long before it has a zapResult to prove it:
    // scanWorker flips the scan to 'combining' and runs PageSpeed, Observatory and
    // urlscan first, writing zapResult only when it enqueues the ZAP job. That
    // window — plus the 'queued' one before the worker picks the job up — is
    // invisible to both the status query above and the BullMQ counts in guard 5.
    //
    // `authScanResult: null` is what keeps this from also matching authenticated
    // scans and pinning the normal instance up for them. It matches an absent field
    // as well as an explicit null, and both auth entry points write an
    // authScanResult at acceptance, so an auth scan is excluded from its first
    // moment.
    const starting = await ScanResult.countDocuments({
      status: { $in: IN_FLIGHT_SCAN_STATUSES },
      authScanResult: null,
      'zapResult.status': { $exists: false }
    });
    if (starting > 0) return { busy: true, reason: 'queued-scan', count: starting };
  }

  return { busy: false };
}

/**
 * Scale `key` back to zero, but only when nothing can possibly need it.
 *
 * Every guard is a veto; the order is cheapest-first. Any error anywhere is treated
 * as "do not scale in" — the cost of staying up one more cycle is a few cents, the
 * cost of a wrong scale-in is a killed multi-hour scan.
 */
async function releaseZapCapacityIfIdle(key) {
  if (!isManagedKey(key)) return { scaledDown: false, reason: 'not-managed' };
  const inst = getInstance(key);

  try {
    // 1. A scan holds the instance lock.
    if (await redisExists(inst.lockKey)) return { scaledDown: false, reason: 'scan-lock-held' };

    // 2. A scale-out is in flight — never fight it.
    if (await redisExists(inst.capacityLockKey)) return { scaledDown: false, reason: 'scaling-up' };

    // 3. A recycle is in flight (ops path, or a scan about to start).
    if (await redisExists(inst.recycleLockKey)) return { scaledDown: false, reason: 'recycling' };

    // 4. A scan was accepted recently and may not have taken the lock yet.
    const age = await demandAgeMs(inst);
    if (age !== null && age < IDLE_SCALEIN_MS()) {
      return { scaledDown: false, reason: 'recent-demand', demandAgeMs: age };
    }

    // 5. Queued or running ZAP jobs. Only the normal instance uses the BullMQ queue;
    //    auth scans are driven straight from the route and the scheduler.
    if (key === 'normal') {
      try {
        const { getZapQueue } = require('../queues/zapQueue');
        const counts = await getZapQueue().getJobCounts('waiting', 'active', 'delayed', 'paused');
        const pending = (counts.waiting || 0) + (counts.active || 0) + (counts.delayed || 0) + (counts.paused || 0);
        if (pending > 0) return { scaledDown: false, reason: 'queue-not-empty', pending };
      } catch (err) {
        return { scaledDown: false, reason: 'queue-check-failed', error: err.message };
      }
    }

    // 6. The database is the authority on in-flight work, scheduled scans included.
    const dbBusy = await hasActiveZapScans(key);
    if (dbBusy.busy) return { scaledDown: false, reason: dbBusy.reason, count: dbBusy.count };

    // 7. Already down?
    const live = await describeZapService(inst);
    if (live.desiredCount === 0) return { scaledDown: false, reason: 'already-zero' };

    const { client, UpdateServiceCommand } = ecs();
    await ecsCall(
      () => client.send(new UpdateServiceCommand({
        cluster: CLUSTER(),
        service: inst.service(),
        desiredCount: 0
      })),
      'ecs:UpdateService'
    );

    await redisDel(inst.coldStartKey);
    await setState(inst, 'scaled_down', 'idle');

    console.log(`[ZapCapacity] instance=${inst.label} scaled to 0 after ${Math.round(IDLE_SCALEIN_MS() / 60000)}min idle`);
    return { scaledDown: true, reason: 'idle' };
  } catch (err) {
    console.error(`[ZapCapacity] idle check failed for ${inst.label} — leaving capacity up: ${err.message}`);
    return { scaledDown: false, reason: 'error', error: err.message };
  }
}

/** Run the idle check for every managed instance. Never throws. */
async function releaseIdleCapacity() {
  if (!isCapacityManaged()) return [];
  const results = [];
  for (const key of capacityKeys()) {
    results.push({ key, ...(await releaseZapCapacityIfIdle(key)) });
  }
  return results;
}

// ─── Preflight ───────────────────────────────────────────────────────────────

/**
 * One-shot startup check for the two permissions this module needs beyond what the
 * recycler already exercises. Without it, a missing ecs:UpdateService grant stays
 * invisible until the first scan after a scale-in fails.
 *
 * UpdateService cannot be probed without changing desiredCount, so only
 * DescribeServices is verified here; UpdateService is proven by the first real
 * scale-out and, if denied, surfaces as ECS_ACCESS_DENIED rather than a hang.
 * Never throws — this must not block boot.
 */
async function preflightCapacityAccess() {
  if (!isCapacityManaged()) {
    console.log('[ZapCapacity] preflight skipped — ZAP_CAPACITY_MANAGED is not true');
    return { ok: false, skipped: true };
  }

  const keys = capacityKeys();
  if (!keys.length) {
    console.warn('[ZapCapacity] enabled but ZAP_CAPACITY_KEYS resolves to nothing — no instance is managed');
    return { ok: false, skipped: true };
  }

  for (const key of keys) {
    const inst = getInstance(key);
    try {
      const live = await describeZapService(inst);
      console.log(`[ZapCapacity] preflight ok instance=${inst.label} service=${inst.service()} ` +
                  `desired=${live.desiredCount} running=${live.runningCount}`);
    } catch (err) {
      console.error(`[ZapCapacity] preflight FAILED instance=${inst.label} service=${inst.service()} ` +
                    `code=${err.code || err.name} — scale-to-zero will fail: ${err.message}`);
      return { ok: false, code: err.code || err.name, instance: key };
    }
  }

  console.log(`[ZapCapacity] managed instances: ${keys.join(', ')} · ` +
              `wait=${CAPACITY_WAIT_MS()}ms idle=${IDLE_SCALEIN_MS()}ms`);
  return { ok: true };
}

module.exports = {
  ensureZapCapacity,
  releaseZapCapacityIfIdle,
  releaseIdleCapacity,
  markZapDemand,
  peekColdStartMarker,
  consumeColdStartMarker,
  preflightCapacityAccess,
  isCapacityManaged,
  isManagedKey,
  capacityKeys,
  ZapCapacityError,
  // exported for tests
  hasActiveZapScans
};
