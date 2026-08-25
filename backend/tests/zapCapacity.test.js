'use strict';

/**
 * ZAP scale-to-zero capacity tests.
 *
 * These EXECUTE the real zapCapacityManager against a stubbed AWS SDK, Redis, model
 * layer and queue — no AWS, no database, no server. They exist because every defect
 * they cover would be invisible to a static check and expensive in production: a
 * duplicate scale-out burns an extra instance, a wrong scale-in kills a multi-hour
 * scan, and a cold-start marker written too early makes the recycler skip a recycle
 * for a task that cannot serve.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');

// ─── Stub the AWS SDK before the module under test requires it ───────────────
// zapCapacityManager caches the client and command classes at module scope on first
// use, so this must be installed before the first require and must stay installed.

const ecsCalls = [];
let ecsHandler = () => ({});

function mkCommand(name) {
  return class {
    constructor(input) { this.__name = name; this.input = input; }
  };
}

const ECS_SDK_PATH = require.resolve('@aws-sdk/client-ecs');
require.cache[ECS_SDK_PATH] = {
  id: ECS_SDK_PATH, filename: ECS_SDK_PATH, loaded: true,
  exports: {
    ECSClient: class {
      async send(cmd) {
        ecsCalls.push({ name: cmd.__name, input: cmd.input });
        return ecsHandler(cmd);
      }
    },
    ListTasksCommand: mkCommand('ListTasks'),
    DescribeTasksCommand: mkCommand('DescribeTasks'),
    DescribeServicesCommand: mkCommand('DescribeServices'),
    UpdateServiceCommand: mkCommand('UpdateService'),
    StopTaskCommand: mkCommand('StopTask')
  }
};

// ─── Stub Redis ──────────────────────────────────────────────────────────────
// A Map with the three semantics the capacity manager actually depends on:
// SET NX (the mutex), plain SET with a TTL, and the compare-and-delete Lua release.

const store = new Map();

const fakeRedis = {
  async set(key, value, ...args) {
    const nx = args.includes('NX');
    if (nx && store.has(key)) return null;
    store.set(key, value);
    return 'OK';
  },
  async get(key) { return store.has(key) ? store.get(key) : null; },
  async del(key) { return store.delete(key) ? 1 : 0; },
  async exists(key) { return store.has(key) ? 1 : 0; },
  // RELEASE_LUA: delete only if we still own the key.
  async eval(_script, _numKeys, key, token) {
    if (store.get(key) === token) { store.delete(key); return 1; }
    return 0;
  }
};

require.cache[path.join(BACKEND, 'config/redis.js')] = {
  id: 'redis', filename: 'redis', loaded: true,
  exports: { getPublisher: () => fakeRedis }
};

// ─── Stub the ZAP readiness probe ────────────────────────────────────────────
let zapApiReady = true;
let zapApiProbes = 0;

require.cache[path.join(BACKEND, 'services/zapContainerManager.js')] = {
  id: 'zcm', filename: 'zcm', loaded: true,
  exports: {
    waitForZapApi: async () => {
      zapApiProbes++;
      if (!zapApiReady) throw new Error('ZAP API did not respond within 90s');
    }
  }
};

// ─── Stub the model layer ────────────────────────────────────────────────────
let dbCounts = {};   // predicate name -> count

// Three shapes are issued. The order matters: the normal-instance
// accepted-but-not-yet-started query also keys on 'zapResult.status', so it is
// matched first by its $exists form before the $in form is considered.
const countDocumentsReal = async (q) => {
  if (q['zapResult.status']?.$exists === false) return dbCounts.queued || 0;
  if (q['zapResult.status']?.$in) return dbCounts.activeNormal || 0;
  if (q['authScanResult.status']?.$in) return dbCounts.activeAuth || 0;
  return 0;
};

// Held as a named object so a test can swap countDocuments out to inspect the exact
// query the capacity manager issues, then put the real stub back.
const ScanResultStub = { countDocuments: countDocumentsReal };

require.cache[path.join(BACKEND, 'models/ScanResult.js')] = {
  id: 'sr', filename: 'sr', loaded: true,
  exports: ScanResultStub
};

// ─── Stub the BullMQ queue ───────────────────────────────────────────────────
let queueCounts = { waiting: 0, active: 0, delayed: 0, paused: 0 };

require.cache[path.join(BACKEND, 'queues/zapQueue.js')] = {
  id: 'zq', filename: 'zq', loaded: true,
  exports: { getZapQueue: () => ({ getJobCounts: async () => queueCounts }) }
};

const cap = require(path.join(BACKEND, 'services/zapCapacityManager.js'));

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** ECS state the stub handler answers from. */
let svc = { desiredCount: 1, runningCount: 1, pendingCount: 0 };
let runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/aaa'];
let stoppedTasks = [];

function installDefaultHandler() {
  ecsHandler = (cmd) => {
    switch (cmd.__name) {
      case 'DescribeServices':
        return { services: [{ ...svc, events: [{ message: 'stub event' }] }] };
      case 'UpdateService':
        // Model ECS: desiredCount takes effect, and for the purposes of these tests a
        // task appears immediately so the happy path does not sleep.
        svc = { ...svc, desiredCount: cmd.input.desiredCount };
        if (cmd.input.desiredCount >= 1) svc.runningCount = 1;
        else { svc.runningCount = 0; runningTaskArns = []; }
        return {};
      case 'ListTasks':
        return {
          taskArns: cmd.input.desiredStatus === 'STOPPED' ? stoppedTasks.map(t => t.taskArn) : runningTaskArns
        };
      case 'DescribeTasks':
        // Answer per-ARN. The old stub returned the entire stoppedTasks array whenever
        // any requested ARN was stopped, which made it impossible to model the case that
        // matters here: a STOPPED task from a previous generation coexisting with a
        // RUNNING replacement.
        return {
          tasks: cmd.input.tasks.map((a) => {
            const hit = stoppedTasks.find(t => t.taskArn === a);
            return hit || { taskArn: a, lastStatus: 'RUNNING' };
          }),
          failures: []
        };
      default:
        return {};
    }
  };
}

function reset(env = {}) {
  ecsCalls.length = 0;
  store.clear();
  dbCounts = {};
  queueCounts = { waiting: 0, active: 0, delayed: 0, paused: 0 };
  zapApiReady = true;
  zapApiProbes = 0;
  svc = { desiredCount: 1, runningCount: 1, pendingCount: 0 };
  runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/aaa'];
  stoppedTasks = [];
  installDefaultHandler();

  process.env.ZAP_CAPACITY_MANAGED = 'true';
  process.env.ZAP_CAPACITY_KEYS = 'normal,auth';
  process.env.ZAP_CAPACITY_WAIT_MS = '600000';
  process.env.ZAP_IDLE_SCALEIN_MS = '1200000';
  process.env.ZAP_CAPACITY_POLL_MS = '5';
  process.env.ECS_ZAP_SERVICE = 'zap-scan-ec2';
  process.env.ECS_ZAP_AUTH_SERVICE = 'zap-auth-task-ec2';
  Object.assign(process.env, env);
}

const countOf = (name) => ecsCalls.filter(c => c.name === name).length;
const updatesTo = (n) => ecsCalls.filter(c => c.name === 'UpdateService' && c.input.desiredCount === n);

// ─── Kill switch ─────────────────────────────────────────────────────────────

test('disabled by default: ensureZapCapacity makes no AWS call at all', async () => {
  reset({ ZAP_CAPACITY_MANAGED: 'false' });
  const r = await cap.ensureZapCapacity('normal', { scanId: 's1' });
  assert.equal(r.managed, false);
  assert.equal(r.coldStarted, false);
  assert.equal(ecsCalls.length, 0, 'the kill switch must short-circuit before any ECS traffic');
});

test('an unlisted key is not managed even when the master switch is on', async () => {
  reset({ ZAP_CAPACITY_KEYS: 'auth' });
  const r = await cap.ensureZapCapacity('normal', { scanId: 's1' });
  assert.equal(r.managed, false);
  assert.equal(ecsCalls.length, 0);
});

// ─── Scale out ───────────────────────────────────────────────────────────────

test('warm path: a running service is not touched', async () => {
  reset();
  const r = await cap.ensureZapCapacity('normal', { scanId: 's1' });
  assert.equal(r.coldStarted, false);
  assert.equal(r.reason, 'already-running');
  assert.equal(countOf('UpdateService'), 0, 'a warm service must never be written to');
  assert.equal(countOf('DescribeServices'), 1, 'the warm path costs exactly one read');
});

test('cold path: scales to 1, waits for the API, and reports coldStarted', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new'];

  const r = await cap.ensureZapCapacity('normal', { scanId: 's1' });

  assert.equal(r.coldStarted, true);
  assert.equal(r.taskArn, 'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new');
  assert.equal(updatesTo(1).length, 1, 'exactly one scale-out');
  assert.ok(zapApiProbes >= 1, 'readiness must be proven by probing the ZAP API');
});

test('cold-start marker is written only after the ZAP API answers', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  zapApiReady = false;

  await assert.rejects(
    () => cap.ensureZapCapacity('normal', { scanId: 's1' }),
    (err) => err.code === 'CAPACITY_API_NOT_READY'
  );

  const marker = await cap.peekColdStartMarker('normal');
  assert.equal(marker, null,
    'a task that never answered must not be marked cold-started — the recycler would skip its recycle');
});

test('concurrent starters produce exactly one scale-out', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new'];

  const results = await Promise.all([
    cap.ensureZapCapacity('normal', { scanId: 'a' }),
    cap.ensureZapCapacity('normal', { scanId: 'b' }),
    cap.ensureZapCapacity('normal', { scanId: 'c' })
  ]);

  assert.equal(updatesTo(1).length, 1,
    'N concurrent scan starts must not produce N UpdateService calls or N ASG scale-outs');
  assert.ok(results.every(r => r.managed), 'every caller still gets capacity');
});

test('a follower reports the task ARN, so the recycle skip is not a race', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new'];

  // The leader writes its cold-start marker only after its own readiness poll, and a
  // follower returns off the same signal (runningCount >= 1). A follower that named no
  // task could not consume that marker, so zapRecycler.resolveColdStart would fall
  // through and send the recycler after a task that is seconds old.
  const results = await Promise.all([
    cap.ensureZapCapacity('normal', { scanId: 'leader' }),
    cap.ensureZapCapacity('normal', { scanId: 'follower' })
  ]);

  const followers = results.filter(r => r.reason === 'followed-scale-out');
  assert.equal(followers.length, 1, 'exactly one caller must have followed');
  assert.equal(followers[0].coldStarted, true);
  assert.equal(followers[0].taskArn, 'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new',
    'a follower must name the task it followed');
});

test('the capacity mutex is released, so a later scan can scale out again', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  await cap.ensureZapCapacity('normal', { scanId: 'a' });
  assert.equal(store.has('zap:capacity:lock:normal'), false, 'the mutex must not leak');
});

test('a timed-out scale-out reports CAPACITY_TIMEOUT and releases the mutex', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = [];   // nothing ever comes up

  await assert.rejects(
    () => cap.ensureZapCapacity('normal', { scanId: 's1', waitMs: 1 }),
    (err) => err.code === 'CAPACITY_TIMEOUT'
  );
  assert.equal(store.has('zap:capacity:lock:normal'), false, 'a failed scale-out must not wedge the mutex');
});

// ─── Cold-start marker ───────────────────────────────────────────────────────

// ═══ CAPACITY_TASK_DIED ownership ════════════════════════════════════════════
//
// Regression cover for the false positive found during the scale-to-zero rollout.
// The death check used to select any task that stopped within the last
// CAPACITY_WAIT_MS, so the task the PREVIOUS idle scale-in deliberately stopped was
// blamed on the NEXT scale-out. Nothing exercised this path before, which is how it
// shipped. Production evidence (2026-08-24): scale-in 17:47:41, scan 17:58:11, death
// check fired 17:58:37 against the already-stopped task, real replacement started
// fine at 17:59:48.
//
// The discriminator is createdAt vs. the instant the scale-out was requested — NOT
// stopCode, so a genuine mid-scale-out stop is still caught whatever stopped it.

/**
 * A STOPPED task shaped like the real DescribeTasks response.
 *
 * `createdDuringScaleOut: true` resolves createdAt lazily, when the death check reads
 * it. That is not a trick — it is the only faithful model. A test arranges its stopped
 * tasks BEFORE calling ensureZapCapacity, but ensureZapCapacity captures its
 * scaleOutStartedAt instant internally and later, so a fixed createdAt stamped at
 * arrange-time would make even "our" task look older than the scale-out that launched
 * it. In production the ordering is the other way round: ECS creates the task after the
 * UpdateService call.
 */
const stoppedTask = (arn, { createdAgoMs, createdDuringScaleOut, stoppedAgoMs, stopCode, stoppedReason, containers }) => {
  const t = {
    taskArn: arn,
    lastStatus: 'STOPPED',
    stoppedAt: new Date(Date.now() - stoppedAgoMs).toISOString(),
    stopCode,
    stoppedReason,
    ...(containers ? { containers } : {})
  };
  if (createdDuringScaleOut) {
    Object.defineProperty(t, 'createdAt', {
      get: () => new Date().toISOString(), enumerable: true
    });
  } else {
    t.createdAt = new Date(Date.now() - createdAgoMs).toISOString();
  }
  return t;
};

/** Cold service that never produces a RUNNING task, so the death check always runs. */
function coldServiceNoTask() {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = [];
  // Short budget: the death check runs on tick 5, and the loop must be allowed to
  // reach it before the deadline. POLL_MS is 5ms under reset().
  process.env.ZAP_CAPACITY_WAIT_MS = '2000';
}

test('a task stopped by the PREVIOUS scale-in is not blamed on this scale-out', async () => {
  coldServiceNoTask();
  // Exactly the production shape: deliberately stopped by ECS ten minutes before this
  // scale-out was ever requested.
  //
  // stoppedAgoMs is scaled to the shortened test budget on purpose. The OLD filter's
  // lookback was `Date.now() - stoppedAt < CAPACITY_WAIT_MS()` — derived from the very
  // constant these tests shrink to 2s for speed. A literal 10-minute stoppedAgoMs would
  // therefore fall OUTSIDE the old window and this test would pass against the buggy
  // code for entirely the wrong reason. 500ms sits inside the 2s window, exactly as
  // production's 10-minute-old task sat inside the real 10-minute window.
  stoppedTasks = [stoppedTask('arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/old', {
    createdAgoMs: 3600000,   // created an hour ago — previous generation
    stoppedAgoMs: 500,       // stopped just before this scale-out, inside the OLD window
    stopCode: 'ServiceSchedulerInitiated',
    stoppedReason: 'Scaling activity initiated by (deployment ecs-svc/3495996395359738480)'
  })];

  const err = await cap.ensureZapCapacity('normal', { scanId: 's1' }).catch(e => e);

  assert.equal(err.code, 'CAPACITY_TIMEOUT',
    'it must time out honestly, not report a task death that did not happen');
  assert.notEqual(err.code, 'CAPACITY_TASK_DIED');
});

test('a task created for THIS scale-out that dies is still CAPACITY_TASK_DIED', async () => {
  coldServiceNoTask();
  // Created after the scale-out began. This is the case the check exists for and it
  // must not be weakened by the ownership filter.
  stoppedTasks = [stoppedTask('arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new', {
    createdDuringScaleOut: true,
    stoppedAgoMs: 0,
    stopCode: 'TaskFailedToStart',
    stoppedReason: 'CannotPullContainerError: ghcr.io rate limit',
    containers: [{ reason: 'CannotPullContainerError' }]
  })];

  const err = await cap.ensureZapCapacity('normal', { scanId: 's1' }).catch(e => e);

  assert.equal(err.code, 'CAPACITY_TASK_DIED');
  assert.match(err.message, /CannotPullContainerError/);
  assert.equal(err.details.stopCode, 'TaskFailedToStart',
    'stopCode is surfaced for diagnosis');
});

test('a scheduler-initiated stop of OUR task is still a failure, not suppressed', async () => {
  coldServiceNoTask();
  // An instance terminating under a task we just launched carries the same stopCode as
  // a deliberate scale-in. Filtering on stopCode instead of ownership would turn this
  // into a silent 10-minute timeout.
  stoppedTasks = [stoppedTask('arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/ours', {
    createdDuringScaleOut: true,
    stoppedAgoMs: 0,
    stopCode: 'ServiceSchedulerInitiated',
    stoppedReason: 'Host EC2 instance terminated'
  })];

  const err = await cap.ensureZapCapacity('normal', { scanId: 's1' }).catch(e => e);

  assert.equal(err.code, 'CAPACITY_TASK_DIED',
    'ownership, not stopCode, decides — genuine failure detection must not weaken');
});

test('a previous-generation task that stops mid-scale-out is not blamed either', async () => {
  coldServiceNoTask();
  // Created before us, still winding down, stops after we began. Never launched for
  // this scale-out, so its death is not this scale-out's failure. This is why the
  // filter keys on createdAt rather than stoppedAt.
  stoppedTasks = [stoppedTask('arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/draining', {
    createdAgoMs: 1800000,
    stoppedAgoMs: 0,
    stopCode: 'ServiceSchedulerInitiated',
    stoppedReason: 'Scaling activity initiated by (deployment ecs-svc/1)'
  })];

  const err = await cap.ensureZapCapacity('normal', { scanId: 's1' }).catch(e => e);

  assert.equal(err.code, 'CAPACITY_TIMEOUT');
});

test('an old stopped task does not stop a healthy scale-out from succeeding', async () => {
  reset();
  // The real-world sequence end to end: idle scale-in left a stopped task behind, then
  // a scan arrives and the replacement comes up fine. Before the fix this returned
  // CAPACITY_TASK_DIED instead of capacity.
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new'];
  stoppedTasks = [stoppedTask('arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/old', {
    createdAgoMs: 3600000,
    stoppedAgoMs: 600000,
    stopCode: 'ServiceSchedulerInitiated',
    stoppedReason: 'Scaling activity initiated by (deployment ecs-svc/3495996395359738480)'
  })];

  const r = await cap.ensureZapCapacity('normal', { scanId: 's1' });

  assert.equal(r.coldStarted, true);
  assert.equal(r.reason, 'scaled-out');
  assert.equal(r.taskArn, 'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new');
  assert.equal(updatesTo(1).length, 1, 'desiredCount 1 requested exactly once');
  // The cold-start marker must still be published for the recycler to skip on.
  assert.equal(await cap.peekColdStartMarker('normal'),
    'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new',
    'cold-start marker behaviour is unchanged');
});

test('the cold-start marker is ARN-scoped', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  runningTaskArns = ['arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new'];
  await cap.ensureZapCapacity('auth', { scanId: 's1' });

  assert.equal(
    await cap.consumeColdStartMarker('auth', 'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/OTHER'),
    false,
    'a marker must never authorise skipping the recycle of a different task'
  );
  assert.equal(
    await cap.peekColdStartMarker('auth'),
    'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new',
    'a non-matching consume must leave the marker intact'
  );
  assert.equal(
    await cap.consumeColdStartMarker('auth', 'arn:aws:ecs:ap-northeast-1:1:task/fortexa-cluster/new'),
    true
  );
  assert.equal(await cap.peekColdStartMarker('auth'), null, 'a matching consume clears it');
});

// ─── Scale in ────────────────────────────────────────────────────────────────

test('idle scale-in writes desiredCount 0 when nothing is running', async () => {
  reset();
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.scaledDown, true);
  assert.equal(updatesTo(0).length, 1);
});

test('never scales in while a scan holds the ZAP lock', async () => {
  reset();
  store.set('zap:lock:normal', 'held-by-a-running-scan');
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.scaledDown, false);
  assert.equal(r.reason, 'scan-lock-held');
  assert.equal(countOf('UpdateService'), 0);
});

test('never scales in while a scale-out is in flight', async () => {
  reset();
  store.set('zap:capacity:lock:normal', 'scaling');
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.reason, 'scaling-up');
  assert.equal(countOf('UpdateService'), 0);
});

test('never scales in while a recycle is in flight', async () => {
  reset();
  store.set('zap:recycle:normal', 'recycling');
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.reason, 'recycling');
  assert.equal(countOf('UpdateService'), 0);
});

test('never scales in within the idle window of a recent scan acceptance', async () => {
  reset();
  await cap.markZapDemand('normal');
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.reason, 'recent-demand');
  assert.equal(countOf('UpdateService'), 0);
});

test('stale demand does not block scale-in', async () => {
  reset({ ZAP_IDLE_SCALEIN_MS: '1000' });
  store.set('zap:capacity:demand:normal', String(Date.now() - 60000));
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.scaledDown, true);
});

test('never scales in while the ZAP queue has work', async () => {
  reset();
  queueCounts = { waiting: 1, active: 0, delayed: 0, paused: 0 };
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.reason, 'queue-not-empty');
  assert.equal(countOf('UpdateService'), 0);
});

test('never scales in while the database shows an active ZAP scan', async () => {
  reset();
  dbCounts.activeNormal = 1;
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.reason, 'active-zap-scan');
  assert.equal(countOf('UpdateService'), 0);
});

test('never scales in while a scan is accepted but not yet enqueued', async () => {
  reset();
  dbCounts.queued = 1;
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.reason, 'queued-scan');
  assert.equal(countOf('UpdateService'), 0);
});

test('the accepted-but-not-yet-enqueued query excludes authenticated scans', async () => {
  reset();
  // The query that catches a normal scan before it has a zapResult must not also
  // catch an authenticated one, or every auth scan would pin the normal instance up
  // and 'normal' could never reach zero while auth work is in flight.
  const seen = [];
  ScanResultStub.countDocuments = async (q) => { seen.push(q); return 0; };
  await cap.releaseZapCapacityIfIdle('normal');
  ScanResultStub.countDocuments = countDocumentsReal;

  const starting = seen.find(q => q['zapResult.status']?.$exists === false);
  assert.ok(starting, 'the normal instance must issue the accepted-but-not-started query');
  assert.equal(starting.authScanResult, null,
    'it must be scoped to scans with no authScanResult, i.e. normal scans only');
});

test('an authenticated scan still in provisioning blocks scale-in of the auth instance', async () => {
  reset();
  // 'provisioning' is what both auth entry points write at acceptance. The scan holds
  // no ZAP lock yet — it is waiting for capacity, a recycle, or zap:lock:auth — so if
  // this status were not counted the instance could be scaled out from under it.
  const seen = [];
  ScanResultStub.countDocuments = async (q) => { seen.push(q); return 0; };
  await cap.releaseZapCapacityIfIdle('auth');
  ScanResultStub.countDocuments = countDocumentsReal;

  const q = seen.find(x => x['authScanResult.status']?.$in);
  assert.ok(q, 'the auth instance must query authScanResult.status');
  assert.ok(q['authScanResult.status'].$in.includes('provisioning'),
    'a scan accepted but not yet started must count as active');
});

test('a scheduled authenticated scan blocks scale-in of the auth instance', async () => {
  reset();
  // Scheduled scans write the same authScanResult.status as interactive ones, so
  // triggerSource never has to be considered — this asserts that stays true.
  dbCounts.activeAuth = 1;
  const r = await cap.releaseZapCapacityIfIdle('auth');
  assert.equal(r.reason, 'active-zap-scan');
  assert.equal(countOf('UpdateService'), 0);
});

test('a busy normal instance does not pin the auth instance up', async () => {
  reset();
  dbCounts.activeNormal = 1;
  const r = await cap.releaseZapCapacityIfIdle('auth');
  assert.equal(r.scaledDown, true, 'the two instances scale independently');
});

test('an error anywhere in the idle check leaves capacity up', async () => {
  reset();
  ecsHandler = () => { throw new Error('ECS is having a day'); };
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.scaledDown, false);
  assert.equal(r.reason, 'error');
});

test('scale-in is a no-op when capacity management is off', async () => {
  reset({ ZAP_CAPACITY_MANAGED: 'false' });
  const r = await cap.releaseZapCapacityIfIdle('normal');
  assert.equal(r.scaledDown, false);
  assert.equal(ecsCalls.length, 0);
});

// ─── IAM ─────────────────────────────────────────────────────────────────────

test('an AccessDenied on UpdateService surfaces as ECS_ACCESS_DENIED', async () => {
  reset();
  svc = { desiredCount: 0, runningCount: 0, pendingCount: 0 };
  const base = ecsHandler;
  ecsHandler = (cmd) => {
    if (cmd.__name === 'UpdateService') {
      const err = new Error('User is not authorized to perform: ecs:UpdateService');
      err.name = 'AccessDeniedException';
      throw err;
    }
    return base(cmd);
  };

  await assert.rejects(
    () => cap.ensureZapCapacity('normal', { scanId: 's1' }),
    // zapWorker turns this code into an UnrecoverableError so BullMQ does not burn
    // 3.5 minutes of backoff re-failing on a missing IAM grant.
    (err) => err.code === 'ECS_ACCESS_DENIED'
  );
});

// ─── Policy: the IAM document must actually grant what the code needs ────────

test('the checked-in IAM policy grants UpdateService and DescribeServices on both ZAP services', () => {
  const fs = require('node:fs');
  const policy = JSON.parse(fs.readFileSync(
    path.join(BACKEND, '..', 'infrastructure', 'fortexa-zap-recycle-policy.json'), 'utf8'));

  const actions = policy.Statement.flatMap(s => [].concat(s.Action));
  for (const needed of ['ecs:UpdateService', 'ecs:DescribeServices', 'ecs:StopTask',
                        'ecs:ListTasks', 'ecs:DescribeTasks']) {
    assert.ok(actions.includes(needed), `policy is missing ${needed}`);
  }

  const scaling = policy.Statement.find(s => [].concat(s.Action).includes('ecs:UpdateService'));
  const resources = [].concat(scaling.Resource);
  assert.ok(resources.some(r => r.endsWith('/zap-scan-ec2')), 'zap-scan-ec2 not covered');
  assert.ok(resources.some(r => r.endsWith('/zap-auth-task-ec2')), 'zap-auth-task-ec2 not covered');
  assert.ok(!resources.includes('*'),
    'UpdateService can be scoped to a service ARN, unlike StopTask — do not widen it to *');
});
