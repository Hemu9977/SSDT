'use strict';

/**
 * Behavioural tests for the admin System Health checks (services/systemHealth.js)
 * and the service inventory (config/healthInventory.js).
 *
 * Every check is EXECUTED against injected fakes — Mongo connection, Valkey
 * publisher, BullMQ queues, HTTP, Stripe, AWS SDK clients — so the tests cover
 * what the code decides from each answer. No network, database, Stripe or AWS
 * access. The fakes record every call, which is how the "read-only" rules are
 * checked.
 *
 * Run with: node --test backend/tests/systemHealth.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const mongoose = require('mongoose');
const { makeModel } = require('./support/fakeMongo');

const BACKEND = path.join(__dirname, '..');
const systemHealth = require(path.join(BACKEND, 'services/systemHealth.js'));
const signals = require(path.join(BACKEND, 'services/healthSignals.js'));
const { INVENTORY, EXCLUDED, SERVICE_IDS, STATUSES } = require(path.join(BACKEND, 'config/healthInventory.js'));

const { summarize, CHECKS } = systemHealth;
const { cleanValue, awsReason } = systemHealth._internals;

// ─── Fakes ───────────────────────────────────────────────────────────────────

// Secret-looking values: the tests assert none of them ever reaches a response.
const SECRETS = {
  STRIPE_SECRET_KEY: 'sk_live_TOPSECRET123',
  STRIPE_WEBHOOK_SECRET: 'whsec_TOPSECRET456',
  URLSCAN_API_KEY: 'urlscan-key-TOPSECRET789',
  REDIS_URL: 'rediss://fortexa-app:redispass@redis.fortexa.internal:6379',
  MONGO_URI: 'mongodb+srv://app:mongopass@cluster0.example.mongodb.net/fortexa',
};

const ACCOUNT = '459181228792';

const baseEnv = () => ({
  ...SECRETS,
  NODE_ENV: 'production',
  PSI_API_KEY: 'psi-key',
  STRIPE_PRICE_LIGHT_MONTHLY: 'price_light',
  USE_AWS_SES: 'true',
  AWS_REGION: 'ap-northeast-1',
  ECS_CLUSTER_NAME: 'fortexa-cluster',
  HEALTH_ECS_SERVICE: 'fortexa-ec2-backend',
  HEALTH_ALB_TARGET_GROUP_ARN: `arn:aws:elasticloadbalancing:ap-northeast-1:${ACCOUNT}:targetgroup/fortexa-tg/6a576c2b619be6c3`,
  HEALTH_ALB_LOAD_BALANCER_ARN: `arn:aws:elasticloadbalancing:ap-northeast-1:${ACCOUNT}:loadbalancer/app/fortexa-alb/96dcec7a7809f822`,
  HEALTH_ALARM_PREFIX: 'fortexa-',
  ECS_CONTAINER_METADATA_URI_V4: 'http://169.254.170.2/v4/abc',
  GIT_SHA: '9dbdeb5c0ffee1234567890abcdef12345678901',
});

const netErr = (code, message) => Object.assign(new Error(message || `connect ${code} 10.0.128.50:6379`), { code });
const awsErr = (name) => Object.assign(new Error(`User: arn:aws:sts::${ACCOUNT}:assumed-role/fortexa-backend-task-role is not authorized`), { name, $metadata: { httpStatusCode: 400 } });
const never = () => new Promise(() => {});
const googleBody = (code, status, reason, message = 'x') => ({
  error: { code, status, message, details: [{ '@type': 'type.googleapis.com/google.rpc.ErrorInfo', reason }] },
});
// @google/genai's ApiError: HTTP status, Google's error JSON as the message.
const apiError = (status, body) => Object.assign(new Error(JSON.stringify(body)), { name: 'ApiError', status });
// What the real API returns for a valid key and the deliberately invalid URL.
const PSI_OK = { status: 400, data: googleBody(400, 'INVALID_ARGUMENT', 'INVALID_PARAMETER', 'Request contains an invalid argument.') };

function fakeQueue(counts = {}, { oldestTs = null, fail = null } = {}) {
  const q = {
    calls: [],
    async getJobCounts(...states) {
      q.calls.push(['getJobCounts', states]);
      if (fail) throw fail;
      return { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0, ...counts };
    },
    async getJobs(types, start, end, asc) {
      q.calls.push(['getJobs', types, start, end, asc]);
      return oldestTs ? [{ timestamp: oldestTs, data: { target: 'https://customer.example', credentials: 'SECRET-PAYLOAD' } }] : [];
    },
  };
  return q;
}

// AWS SDK fakes: command classes record their input; client.send dispatches on name.
function fakeAws(handlers = {}) {
  const sent = [];
  const sdk = {};
  for (const name of ['DescribeServices', 'DescribeTargetHealth', 'GetMetricData', 'DescribeAlarms', 'GetAccountSendingEnabled', 'GetSendQuota']) {
    sdk[`${name}Command`] = class { constructor(input) { this.name = name; this.input = input; } };
  }
  const defaults = {
    DescribeServices: async () => ({ services: [{ desiredCount: 1, runningCount: 1, pendingCount: 0, deployments: [{ status: 'PRIMARY', rolloutState: 'COMPLETED', taskDefinition: `arn:aws:ecs:ap-northeast-1:${ACCOUNT}:task-definition/fortexa-backend:88` }] }] }),
    DescribeTargetHealth: async () => ({ TargetHealthDescriptions: [{ TargetHealth: { State: 'healthy' } }] }),
    GetMetricData: async () => ({ MetricDataResults: [{ Id: 'req', Values: [500] }, { Id: 't5xx', Values: [2] }, { Id: 'e5xx', Values: [] }] }),
    DescribeAlarms: async () => ({ MetricAlarms: [{ AlarmName: 'fortexa-redis-cpu', StateValue: 'OK' }, { AlarmName: 'fortexa-backend-5xx', StateValue: 'OK' }], CompositeAlarms: [] }),
    GetAccountSendingEnabled: async () => ({ Enabled: true }),
    GetSendQuota: async () => ({ Max24HourSend: 50000, SentLast24Hours: 12, MaxSendRate: 14 }),
  };
  const client = {
    async send(cmd) {
      sent.push({ name: cmd.name, input: cmd.input });
      return (handlers[cmd.name] || defaults[cmd.name])(cmd.input);
    },
  };
  const svc = () => ({ sdk, client });
  return { sent, factory: (env) => ({ region: env.AWS_REGION, ecs: svc, elb: svc, cloudwatch: svc, ses: svc }) };
}

const ScanResult = makeModel('ScanResult');
const StripeEvent = makeModel('StripeEvent');

/** A fully healthy production world; each test overrides what it needs. */
function world(over = {}) {
  const env = { ...baseEnv(), ...(over.env || {}) };
  const clock = { t: Date.now() };
  const httpCalls = [];
  const stripeCalls = [];
  const aws = fakeAws(over.aws || {});
  const queues = { scan: over.scanQueue || fakeQueue(), zap: over.zapQueue || fakeQueue() };
  const capacity = { desiredCount: 0, runningCount: 0, pendingCount: 0, ...(over.capacity || {}) };
  const counts = {};
  const count = (k) => { counts[k] = (counts[k] || 0) + 1; };

  const httpRoutes = {
    webcheck: async () => ({ status: 200, data: { status: 'healthy' } }),
    zap: async () => { throw netErr('ECONNREFUSED'); },     // scaled to zero by default
    zap_auth: async () => { throw netErr('ECONNREFUSED'); },
    pagespeed: async () => PSI_OK,
    urlscan: async () => ({ status: 200, data: { scope: 'user', limits: { unlisted: { day: { limit: 5000, remaining: 4990 }, hour: { limit: 500, remaining: 499 } }, retrieve: { day: { remaining: 40000 } } } } }),
    ...(over.http || {}),
  };

  const deps = {
    env,
    now: () => clock.t,
    mongoose: () => ({
      Types: mongoose.Types,
      connection: over.mongoConnection || {
        readyState: 1,
        db: { admin: () => ({ command: async (cmd) => { count('mongoPing'); assert.deepEqual(cmd, { ping: 1 }); return { ok: 1 }; } }) },
      },
    }),
    getPublisher: () => (over.publisher !== undefined ? over.publisher : {
      status: 'ready',
      ping: async () => { count('redisPing'); return 'PONG'; },
      get: async () => over.capacityState || null,
    }),
    getScanQueue: () => queues.scan,
    getZapQueue: () => queues.zap,
    http: () => ({
      async get(url, cfg) {
        httpCalls.push({ url, cfg });
        if (url.startsWith('http://webcheck')) return httpRoutes.webcheck(url, cfg);
        if (url.startsWith('http://zap-normal')) return httpRoutes.zap(url, cfg);
        if (url.startsWith('http://zap-auth')) return httpRoutes.zap_auth(url, cfg);
        if (url.startsWith('https://urlscan.io/')) return httpRoutes.urlscan(url, cfg);
        if (url.startsWith('https://www.googleapis.com/pagespeedonline/')) return httpRoutes.pagespeed(url, cfg);
        throw new Error(`unexpected URL ${url}`);
      },
    }),
    webCheckBaseUrl: () => 'http://webcheck:3000',
    zapInstance: (key) => ({ baseUrl: () => `http://zap-${key}:8080`, probeConfig: () => ({}), capacityStateKey: `zap:capacity:state:${key}` }),
    zapCapacity: () => ({
      isManagedKey: () => over.zapManaged !== false,
      describeCapacity: over.describeCapacity || (async () => ({ ...capacity })),
    }),
    gemini: () => ({
      GEMINI_AUTH_MODE: () => (over.geminiMode !== undefined ? over.geminiMode : 'VERTEX_WIF'),
      probeModelAccess: over.geminiProbe || (async () => ({
        mode: 'VERTEX_WIF',
        location: 'us-central1',
        models: ['gemini-2.5-pro', 'gemini-2.5-flash'].map((model) => (over.geminiModels && over.geminiModels[model]
          ? { model, ok: false, error: over.geminiModels[model] }
          : { model, ok: true })),
      })),
    }),
    signals: () => signals,
    stripe: () => ({
      prices: {
        async retrieve(id, params, opts) {
          stripeCalls.push(['prices.retrieve', id, opts]);
          if (over.stripeError) throw over.stripeError;
          return { id, livemode: over.stripeLivemode !== undefined ? over.stripeLivemode : true, active: true, unit_amount: 5000000 };
        },
        async list(params, opts) {
          stripeCalls.push(['prices.list', params, opts]);
          return { data: [{ livemode: true }] };
        },
      },
    }),
    ScanResult: () => ScanResult,
    StripeEvent: () => StripeEvent,
    aws: aws.factory,
    taskMetadata: async () => ({ taskDefinition: 'fortexa-backend:88', image: 'fortexa-backend:v58' }),
  };
  systemHealth.setDependencies(deps);
  return { env, clock, httpCalls, stripeCalls, awsSent: aws.sent, queues, counts };
}

const byId = (report) => Object.fromEntries(report.services.map((s) => [s.id, s]));

function resetAll() {
  ScanResult._reset();
  StripeEvent._reset();
  signals.resetSignals();
}

test.beforeEach(resetAll);

// ═════════════════════════════════════════════════════════════════════════════
// Inventory
// ═════════════════════════════════════════════════════════════════════════════

test('inventory: every listed service has a check, a documented basis and bounded timeout; no orphan checks', () => {
  assert.deepEqual(Object.keys(CHECKS).sort(), [...SERVICE_IDS].sort());
  for (const s of INVENTORY) {
    for (const k of ['purpose', 'rationale', 'method']) assert.ok(s[k] && s[k].length > 10, `${s.id}.${k}`);
    assert.ok(['live_probe', 'process', 'aws_api', 'credential_check', 'recent_activity', 'app_signal'].includes(s.basis), s.id);
    assert.ok(s.timeoutMs > 0 && s.timeoutMs <= 6000, `${s.id} timeout`);
    assert.ok(['unavailable', 'unknown'].includes(s.onTimeout), s.id);
  }
});

test('inventory: production-only — excluded, retired and development-only services are not checked', () => {
  const ids = new Set(SERVICE_IDS);
  for (const x of EXCLUDED) {
    assert.equal(ids.has(x.id), false, x.id);
    assert.ok(x.reason.length > 20, `${x.id} needs a reason`);
  }
  // Retired / dev-only integrations named explicitly.
  for (const gone of ['elasticache', 'gemini_api_key', 'virustotal']) assert.equal(ids.has(gone), false, gone);
  // The services production verifiably depends on are all present.
  for (const must of ['api', 'mongodb', 'redis', 'queues', 'webcheck', 'zap', 'zap_auth', 'gemini', 'stripe', 'email']) {
    assert.ok(ids.has(must), must);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// Whole report
// ═════════════════════════════════════════════════════════════════════════════

test('healthy production: real statuses for every service, idle scale-to-zero counted as operational', async () => {
  const w = world();
  StripeEvent._insert({ eventId: 'evt_1' });
  const report = await systemHealth.getReport();
  const s = byId(report);
  assert.deepEqual(report.services.map((x) => x.id), SERVICE_IDS);
  for (const id of ['api', 'mongodb', 'redis', 'webcheck', 'gemini', 'pagespeed', 'urlscan', 'stripe', 'stripe_webhooks', 'email', 'aws_backend', 'aws_alarms']) {
    assert.equal(s[id].status, 'healthy', `${id}: ${s[id].status} ${s[id].reason}`);
  }
  assert.equal(s.zap.status, 'idle');
  assert.equal(s.zap_auth.status, 'idle');
  assert.equal(s.queues.status, 'idle', 'no jobs queued is idle, not a failure');
  // No scans in the window and no free live check: not verified, never healthy.
  assert.equal(s.observatory.status, 'unknown');
  assert.equal(report.summary.overall, 'healthy');
  assert.equal(report.summary.operational, SERVICE_IDS.length - 1);
  assert.equal(report.summary.notVerified, 1);
  for (const r of report.services) {
    assert.ok(STATUSES.includes(r.status));
    assert.ok(!Number.isNaN(Date.parse(r.checkedAt)));
  }
  assert.equal(w.counts.mongoPing, 1);
});

test('summary: configured and unknown are never counted as working; critical outage vs degraded', () => {
  const r = (id, status, critical = false) => ({ id, status, critical });
  assert.deepEqual(
    summarize([r('a', 'healthy'), r('b', 'configured'), r('c', 'unknown'), r('d', 'idle')]),
    { overall: 'healthy', total: 4, operational: 2, notVerified: 2, problems: 0,
      counts: { healthy: 1, degraded: 0, unavailable: 0, starting: 0, idle: 1, configured: 1, unknown: 1 } },
  );
  assert.equal(summarize([r('a', 'healthy'), r('b', 'unavailable')]).overall, 'degraded', 'non-critical down');
  assert.equal(summarize([r('a', 'healthy'), r('db', 'unavailable', true)]).overall, 'outage');
  assert.equal(summarize([r('a', 'degraded', true)]).overall, 'degraded');
  assert.equal(summarize([r('a', 'configured'), r('b', 'unknown')]).overall, 'unknown');
  assert.equal(summarize([r('a', 'starting'), r('b', 'healthy')]).operational, 1, 'starting is not yet operational');
});

test('partial failure: dead services are reported without hiding healthy ones; a critical one is an outage', async () => {
  world({
    mongoConnection: { readyState: 0, db: null },
    publisher: { status: 'ready', ping: async () => { throw netErr('ECONNRESET'); }, get: async () => null },
    http: { webcheck: async () => { throw netErr('ECONNREFUSED'); } },
  });
  const report = await systemHealth.getReport();
  const s = byId(report);
  assert.deepEqual([s.mongodb.status, s.mongodb.reason], ['unavailable', 'disconnected']);
  assert.deepEqual([s.redis.status, s.redis.reason], ['unavailable', 'unreachable']);
  assert.deepEqual([s.webcheck.status, s.webcheck.reason], ['unavailable', 'unreachable']);
  assert.equal(s.stripe.status, 'healthy');
  assert.equal(s.aws_backend.status, 'healthy');
  assert.equal(report.summary.overall, 'outage');
  assert.equal(report.summary.problems, 3);
});

test('timeouts: a hanging dependency is cut off at its own timeout and others still report', async () => {
  world({ scanQueue: { getJobCounts: never, getJobs: never } });
  const started = Date.now();
  const report = await systemHealth.getReport();
  const elapsed = Date.now() - started;
  const s = byId(report);
  assert.deepEqual([s.queues.status, s.queues.reason], ['unavailable', 'timeout']);
  assert.ok(elapsed < INVENTORY.find((x) => x.id === 'queues').timeoutMs + 1500, `took ${elapsed} ms`);
  assert.equal(s.mongodb.status, 'healthy');
});

// ═════════════════════════════════════════════════════════════════════════════
// Sanitization and read-only behaviour
// ═════════════════════════════════════════════════════════════════════════════

test('no secret, connection string, internal address, account id, stack or job payload reaches the response', async () => {
  world({
    mongoConnection: { readyState: 1, db: { admin: () => ({ command: async () => { throw new Error(`auth failed for ${SECRETS.MONGO_URI}\n    at Connection.x`); } }) } },
    publisher: { status: 'ready', ping: async () => { throw netErr('ECONNREFUSED', `connect ECONNREFUSED 10.0.128.50:6379 ${SECRETS.REDIS_URL}`); }, get: async () => null },
    stripeError: Object.assign(new Error(`Invalid API Key provided: ${SECRETS.STRIPE_SECRET_KEY}`), { type: 'StripeAuthenticationError' }),
    aws: { DescribeServices: async () => { throw awsErr('AccessDeniedException'); } },
    scanQueue: fakeQueue({ waiting: 1 }, { oldestTs: Date.now() - 1000 }),
  });
  const body = JSON.stringify(await systemHealth.getReport());
  for (const secret of [...Object.values(SECRETS), 'mongopass', 'redispass', '10.0.128.50', ACCOUNT, 'SECRET-PAYLOAD', 'customer.example', 'at Connection']) {
    assert.equal(body.includes(secret), false, `leaked ${secret}`);
  }
});

test('sanitizer: secret-looking strings and unknown reasons are dropped, numbers kept', async () => {
  assert.deepEqual(
    cleanValue({ a: 1, b: 'sk_live_abc', c: 'rediss://x', d: 'fine', e: { f: 'mongodb+srv://u:p@h' }, g: NaN }, 0),
    { a: 1, d: 'fine', e: {}, g: null },
  );
  const saved = CHECKS.webcheck;
  CHECKS.webcheck = async () => ({ status: 'exploded', reason: 'ECONNREFUSED 10.0.0.1', notes: ['raw text'] });
  try {
    world();
    const wc = byId(await systemHealth.getReport()).webcheck;
    assert.deepEqual([wc.status, wc.reason, wc.notes], ['unknown', 'check_failed', []]);
  } finally {
    CHECKS.webcheck = saved;
  }
});

test('read-only: only reads are issued to Mongo, Stripe and AWS during a full report', async () => {
  const w = world();
  ScanResult._insert({ createdAt: new Date(), pagespeedResult: { score: 1 } });
  await systemHealth.getReport();
  for (const model of [ScanResult, StripeEvent]) {
    const writes = model._calls.filter((c) => !['countDocuments', 'find', 'findOne', 'aggregate'].includes(c));
    assert.deepEqual(writes, [], `${model.modelName} writes`);
  }
  assert.deepEqual([...new Set(w.stripeCalls.map((c) => c[0]))], ['prices.retrieve']);
  assert.ok(w.stripeCalls.every((c) => c[2].maxNetworkRetries === 0 && c[2].timeout > 0), 'bounded Stripe call');
  assert.ok(w.awsSent.every((c) => /^(Describe|Get)/.test(c.name)), w.awsSent.map((c) => c.name).join());
  assert.ok(w.httpCalls.every((c) => !c.cfg || !c.cfg.method || c.cfg.method === 'get'));
  // AWS resources come from server config only.
  const ecs = w.awsSent.find((c) => c.name === 'DescribeServices');
  assert.deepEqual(ecs.input, { cluster: 'fortexa-cluster', services: ['fortexa-ec2-backend'] });
});

test('results are cached briefly and concurrent requests share one run; a retry re-runs one service', async () => {
  const w = world();
  await Promise.all([systemHealth.getReport(), systemHealth.getReport()]);
  assert.equal(w.counts.mongoPing, 1, 'concurrent requests coalesce');
  const cached = await systemHealth.getReport();
  assert.equal(w.counts.mongoPing, 1, 'served from cache');
  assert.equal(byId(cached).mongodb.cached, true);

  w.clock.t += 1000;
  await systemHealth.getReport({ retry: 'mongodb' });
  assert.equal(w.counts.mongoPing, 1, 'retries are rate-limited to one per few seconds');
  w.clock.t += 5000;
  const retried = await systemHealth.getReport({ retry: 'mongodb' });
  assert.equal(w.counts.mongoPing, 2);
  assert.equal(w.counts.redisPing, 1, 'other services stay cached');
  assert.equal(byId(retried).mongodb.cached, false);

  await assert.rejects(systemHealth.getReport({ retry: 'arn:aws:ecs:x' }), /unknown service/);
});

// ═════════════════════════════════════════════════════════════════════════════
// Individual services
// ═════════════════════════════════════════════════════════════════════════════

test('api: reports the running release without the registry account id', async () => {
  world();
  const api = byId(await systemHealth.getReport()).api;
  assert.equal(api.status, 'healthy');
  assert.equal(api.metrics.taskDefinition, 'fortexa-backend:88');
  assert.equal(api.metrics.image, 'fortexa-backend:v58');
  assert.equal(api.metrics.gitSha, '9dbdeb5c0ffe');
  assert.ok(api.metrics.heapLimitMB > 0 && api.metrics.eventLoopP99Ms >= 0);
});

test('redis and queues: a missing REDIS_URL is unavailable (required in production), not "not configured = fine"', async () => {
  world({ env: { REDIS_URL: '' } });
  const s = byId(await systemHealth.getReport());
  assert.deepEqual([s.redis.status, s.redis.reason], ['unavailable', 'not_configured']);
  assert.deepEqual([s.queues.status, s.queues.reason], ['unavailable', 'not_configured']);
});

test('queues: work in progress is healthy; failed jobs are a note, not an outage; a backlog or stopped worker degrades', async () => {
  world({ scanQueue: fakeQueue({ active: 1, failed: 3 }) });
  let q = byId(await systemHealth.getReport()).queues;
  assert.equal(q.status, 'healthy');
  assert.deepEqual(q.notes, ['failed_jobs']);
  assert.equal(q.metrics.queues.scan.failed, 3);
  assert.equal(q.metrics.queues.scan.reachable, true);

  world({ zapQueue: fakeQueue({ waiting: 2 }, { oldestTs: Date.now() - 2 * 3600_000 }) });
  q = byId(await systemHealth.getReport()).queues;
  assert.deepEqual([q.status, q.reason], ['degraded', 'queue_backlog']);
  assert.ok(q.metrics.queues.zap.oldestWaitingSec >= 7199);
  assert.equal(JSON.stringify(q).includes('SECRET-PAYLOAD'), false);

  world({ scanQueue: fakeQueue({ waiting: 1 }, { oldestTs: Date.now() }) });
  signals.registerWorker('scan', { isRunning: () => false });
  q = byId(await systemHealth.getReport()).queues;
  assert.deepEqual([q.status, q.reason], ['degraded', 'no_workers']);

  world({ zapQueue: fakeQueue({}, { fail: netErr('ECONNREFUSED') }) });
  q = byId(await systemHealth.getReport()).queues;
  assert.deepEqual([q.status, q.reason], ['unavailable', 'unreachable']);
  assert.equal(q.metrics.queues.zap.reachable, false);
  assert.equal(q.metrics.queues.scan.reachable, true, 'the other queue is still reported');
});

test('ZAP: idle when scaled to zero, starting while ECS brings a task up or ZAP boots, unavailable only when it should be running', async () => {
  world();
  assert.equal(byId(await systemHealth.getReport()).zap.status, 'idle');

  world({ capacity: { desiredCount: 1, runningCount: 0, pendingCount: 1 } });
  assert.equal(byId(await systemHealth.getReport()).zap.status, 'starting');

  world({ capacity: { desiredCount: 1, runningCount: 1 }, capacityState: JSON.stringify({ state: 'scaling_up' }) });
  let z = byId(await systemHealth.getReport()).zap;
  assert.deepEqual([z.status, z.notes], ['starting', ['cold_start']]);

  world({ capacity: { desiredCount: 1, runningCount: 1 } });
  z = byId(await systemHealth.getReport()).zap;
  assert.deepEqual([z.status, z.reason], ['unavailable', 'unreachable']);

  world({ describeCapacity: async () => { throw awsErr('AccessDeniedException'); } });
  z = byId(await systemHealth.getReport()).zap;
  assert.deepEqual([z.status, z.reason], ['unknown', 'capacity_check_failed'], 'cannot tell idle from down');

  world({ zapManaged: false });
  assert.equal(byId(await systemHealth.getReport()).zap.status, 'unavailable', 'unmanaged ZAP has no idle state');

  world({ http: { zap: async () => ({ status: 200, data: { version: '2.16.1' } }) } });
  z = byId(await systemHealth.getReport()).zap;
  assert.deepEqual([z.status, z.metrics.version], ['healthy', '2.16.1']);
});

test('Gemini: healthy only when every configured model answers countTokens on Vertex AI', async () => {
  world();
  let g = byId(await systemHealth.getReport()).gemini;
  assert.equal(g.status, 'healthy');
  assert.equal(g.basis, 'live_probe');
  assert.deepEqual(g.metrics.models, [
    { model: 'gemini-2.5-pro', ok: true, reason: null },
    { model: 'gemini-2.5-flash', ok: true, reason: null },
  ]);
  assert.equal(g.metrics.location, 'us-central1');

  // Repeated fallback reports still degrade a reachable Vertex.
  world();
  ['ok', 'fail', 'fail', 'fail'].forEach((o) => signals.recordOutcome('gemini_report', o === 'ok', 'generation_failed'));
  g = byId(await systemHealth.getReport()).gemini;
  assert.deepEqual([g.status, g.reason], ['degraded', 'recent_failures']);
  assert.deepEqual(g.metrics.reportsSinceStart, { generated: 1, fallback: 3 });

  world({ geminiMode: null });
  assert.deepEqual(byId(await systemHealth.getReport()).gemini.reason, 'not_configured');
});

test('Gemini: authentication, permission, disabled API, missing model, quota, credentials and network are told apart', async () => {
  const both = (err) => ({ 'gemini-2.5-pro': err, 'gemini-2.5-flash': err });
  const cases = [
    [apiError(401, googleBody(401, 'UNAUTHENTICATED', 'ACCESS_TOKEN_TYPE_UNSUPPORTED')), 'unavailable', 'auth_failed'],
    [apiError(403, googleBody(403, 'PERMISSION_DENIED', 'IAM_PERMISSION_DENIED')), 'unavailable', 'permission_denied'],
    [apiError(403, googleBody(403, 'PERMISSION_DENIED', 'SERVICE_DISABLED')), 'unavailable', 'api_disabled'],
    [apiError(404, googleBody(404, 'NOT_FOUND', 'MODEL_NOT_FOUND')), 'unavailable', 'model_unavailable'],
    [apiError(429, googleBody(429, 'RESOURCE_EXHAUSTED', 'RATE_LIMIT_EXCEEDED')), 'degraded', 'rate_limited'],
    // Observed locally: a missing WIF/ADC credentials file.
    [Object.assign(new Error('The file at /app/config/gcp-wif.json does not exist'), { code: 'ENOENT' }), 'unavailable', 'credentials'],
    // WIF token exchange refused by Google STS (gaxios error).
    [Object.assign(new Error('invalid_grant'), { response: { status: 400 } }), 'unavailable', 'auth_failed'],
    [Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } }), 'unavailable', 'unreachable'],
    [Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }), 'unavailable', 'timeout'],
  ];
  for (const [err, status, reason] of cases) {
    world({ geminiModels: both(err) });
    const g = byId(await systemHealth.getReport()).gemini;
    assert.deepEqual([g.status, g.reason], [status, reason], reason);
  }
  // Only the fallback model is reachable: reports still work, but degraded.
  world({ geminiModels: { 'gemini-2.5-pro': apiError(404, googleBody(404, 'NOT_FOUND', 'MODEL_NOT_FOUND')) } });
  const g = byId(await systemHealth.getReport()).gemini;
  assert.deepEqual([g.status, g.reason], ['degraded', 'model_unavailable']);
  assert.deepEqual(g.metrics.models.map((m) => [m.model, m.ok]), [['gemini-2.5-pro', false], ['gemini-2.5-flash', true]]);
});

test('PageSpeed: the key is verified live without running an analysis', async () => {
  const w = world();
  const p = byId(await systemHealth.getReport()).pagespeed;
  assert.deepEqual([p.status, p.basis], ['healthy', 'live_probe']);
  const call = w.httpCalls.find((c) => c.url.includes('pagespeedonline'));
  assert.equal(call.url, 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
  assert.deepEqual(Object.keys(call.cfg.params).sort(), ['key', 'url']);
  assert.equal(call.cfg.params.url, 'not-a-url', 'never a real site: nothing is fetched or audited');
  assert.ok(call.cfg.timeout > 0 && call.cfg.timeout <= 5000);
});

test('PageSpeed: invalid key, disabled API, blocked key, quota, rate limit, timeout and network', async () => {
  const perDay = "Quota exceeded for quota metric 'Queries' and limit 'Queries per day'";
  const cases = [
    [async () => ({ status: 400, data: googleBody(400, 'INVALID_ARGUMENT', 'API_KEY_INVALID', 'API key not valid.') }), 'unavailable', 'auth_failed'],
    [async () => ({ status: 403, data: googleBody(403, 'PERMISSION_DENIED', 'SERVICE_DISABLED') }), 'unavailable', 'api_disabled'],
    [async () => ({ status: 403, data: googleBody(403, 'PERMISSION_DENIED', 'API_KEY_SERVICE_BLOCKED') }), 'unavailable', 'permission_denied'],
    [async () => ({ status: 429, data: googleBody(429, 'RESOURCE_EXHAUSTED', 'RATE_LIMIT_EXCEEDED', perDay) }), 'degraded', 'quota_exhausted'],
    [async () => ({ status: 429, data: googleBody(429, 'RESOURCE_EXHAUSTED', 'RATE_LIMIT_EXCEEDED', 'Queries per 100 seconds') }), 'degraded', 'rate_limited'],
    [async () => ({ status: 500, data: googleBody(500, 'INTERNAL', 'x') }), 'unavailable', 'http_error'],
    [async () => { throw Object.assign(new Error('timeout of 4500ms exceeded'), { code: 'ECONNABORTED' }); }, 'unavailable', 'timeout'],
    [async () => { throw netErr('ENOTFOUND', 'getaddrinfo ENOTFOUND www.googleapis.com'); }, 'unavailable', 'unreachable'],
  ];
  for (const [route, status, reason] of cases) {
    world({ http: { pagespeed: route } });
    const p = byId(await systemHealth.getReport()).pagespeed;
    assert.deepEqual([p.status, p.reason], [status, reason], reason);
  }
  const w = world({ env: { PSI_API_KEY: '' } });
  assert.deepEqual(byId(await systemHealth.getReport()).pagespeed.reason, 'not_configured');
  assert.equal(w.httpCalls.some((c) => c.url.includes('pagespeedonline')), false, 'no call without a key');
});

test('urlscan: rate limit, timeout and network failures', async () => {
  const cases = [
    [async () => ({ status: 429, data: {} }), 'degraded', 'rate_limited'],
    [async () => { throw Object.assign(new Error('timeout of 4500ms exceeded'), { code: 'ECONNABORTED' }); }, 'unavailable', 'timeout'],
    [async () => { throw netErr('ECONNRESET', 'socket hang up'); }, 'unavailable', 'unreachable'],
    [async () => ({ status: 503, data: {} }), 'unavailable', 'http_error'],
  ];
  for (const [route, status, reason] of cases) {
    world({ http: { urlscan: route } });
    const u = byId(await systemHealth.getReport()).urlscan;
    assert.deepEqual([u.status, u.reason], [status, reason], reason);
  }
});

test('API keys never reach the response or the logs, even when the provider echoes them', async () => {
  const PSI_KEY = 'AIzaSy-psi-TOPSECRET-0123456789abcdef';
  const logged = [];
  const warn = console.warn;
  console.warn = (...a) => logged.push(a.join(' '));
  try {
    world({
      env: { PSI_API_KEY: PSI_KEY },
      http: {
        pagespeed: async () => ({ status: 400, data: googleBody(400, 'INVALID_ARGUMENT', 'API_KEY_INVALID', `API key ${PSI_KEY} not valid`) }),
        urlscan: async () => ({ status: 401, data: { message: `API key ${SECRETS.URLSCAN_API_KEY} not found` } }),
      },
    });
    const body = JSON.stringify(await systemHealth.getReport());
    for (const secret of [PSI_KEY, SECRETS.URLSCAN_API_KEY]) {
      assert.equal(body.includes(secret), false, 'in response');
      assert.equal(logged.join('\n').includes(secret), false, 'in logs');
    }
  } finally {
    console.warn = warn;
  }
});

test('quota protection: a healthy third-party result is reused for 5 min, a failure is re-checked after 1 min', async () => {
  let psiCalls = 0;
  let answer = PSI_OK;
  const w = world({ http: { pagespeed: async () => { psiCalls += 1; return answer; } } });
  await systemHealth.getReport();
  w.clock.t += 4 * 60_000;
  await systemHealth.getReport();
  assert.equal(psiCalls, 1, 'healthy result reused within 5 min');
  w.clock.t += 2 * 60_000;
  answer = { status: 400, data: googleBody(400, 'INVALID_ARGUMENT', 'API_KEY_INVALID') };
  let p = byId(await systemHealth.getReport()).pagespeed;
  assert.equal(psiCalls, 2);
  assert.equal(p.reason, 'auth_failed');
  w.clock.t += 30_000;
  await systemHealth.getReport();
  assert.equal(psiCalls, 2, 'failure still cached at 30 s');
  answer = PSI_OK;
  w.clock.t += 31_000;
  p = byId(await systemHealth.getReport()).pagespeed;
  assert.equal(psiCalls, 3, 'failure re-checked after a minute');
  assert.equal(p.status, 'healthy');
  // A forced re-check of a quota-limited service runs at most every 30 s.
  await systemHealth.getReport({ retry: 'pagespeed' });
  assert.equal(psiCalls, 3);
  w.clock.t += 31_000;
  await systemHealth.getReport({ retry: 'pagespeed' });
  assert.equal(psiCalls, 4);
});

test('scanners without a free check: judged from recent customer scans, never "unavailable" from that signal', async () => {
  world();
  const since = Date.now() - 3600_000;
  ScanResult._insert(
    { createdAt: new Date(since), pagespeedResult: { error: 'PageSpeed API error: 403' }, observatoryResult: { grade: 'B' } },
    { createdAt: new Date(since), pagespeedResult: { error: 'PageSpeed API error: 403' }, observatoryResult: { grade: 'A' } },
    { createdAt: new Date(since), pagespeedResult: { error: 'PageSpeed API error: 403' }, observatoryResult: { error: 'x' } },
    // Outside the 24 h window: ignored.
    { createdAt: new Date(Date.now() - 3 * 86400_000), pagespeedResult: { score: 1 } },
  );
  const s = byId(await systemHealth.getReport());
  assert.deepEqual([s.pagespeed.status, s.pagespeed.reason], ['degraded', 'recent_failures']);
  assert.deepEqual(s.pagespeed.metrics.recentScans, { ok: 0, failed: 3, windowHours: 24 });
  assert.equal(s.observatory.status, 'healthy');
  assert.deepEqual(s.observatory.metrics.recentScans, { ok: 2, failed: 1, windowHours: 24 });

  world({ env: { PSI_API_KEY: '' } });
  assert.deepEqual(byId(await systemHealth.getReport()).pagespeed.reason, 'not_configured');
});

test('urlscan: the quota endpoint authenticates the key without spending a scan', async () => {
  let w = world();
  let u = byId(await systemHealth.getReport()).urlscan;
  assert.equal(u.status, 'healthy');
  assert.equal(u.metrics.quota.unlistedDayRemaining, 4990);
  const call = w.httpCalls.find((c) => c.url.startsWith('https://urlscan.io/'));
  assert.equal(call.url, 'https://urlscan.io/user/quotas/');
  assert.equal(call.cfg.headers['API-Key'], SECRETS.URLSCAN_API_KEY, 'key goes only to urlscan, in its header');

  world({ http: { urlscan: async () => ({ status: 401, data: {} }) } });
  u = byId(await systemHealth.getReport()).urlscan;
  assert.deepEqual([u.status, u.reason], ['unavailable', 'auth_failed']);

  world({ http: { urlscan: async () => ({ status: 200, data: { scope: 'ip-address', limits: {} } }) } });
  assert.equal(byId(await systemHealth.getReport()).urlscan.reason, 'auth_failed', 'key not recognised');

  world({ http: { urlscan: async () => ({ status: 200, data: { scope: 'user', limits: { unlisted: { day: { remaining: 0 }, hour: { remaining: 0 } } } } }) } });
  u = byId(await systemHealth.getReport()).urlscan;
  assert.deepEqual([u.status, u.reason], ['degraded', 'quota_exhausted']);

  w = world({ env: { URLSCAN_API_KEY: '' } });
  assert.equal(byId(await systemHealth.getReport()).urlscan.reason, 'not_configured');
  assert.equal(w.httpCalls.some((c) => c.url.includes('urlscan')), false);
});

test('Stripe: authentication, permission, connectivity and configuration failures are told apart', async () => {
  const cases = [
    [{ type: 'StripeAuthenticationError' }, 'unavailable', 'auth_failed'],
    [{ type: 'StripePermissionError' }, 'unavailable', 'permission_denied'],
    [{ type: 'StripeConnectionError' }, 'unavailable', 'unreachable'],
    [{ type: 'StripeRateLimitError' }, 'degraded', 'rate_limited'],
    [{ type: 'StripeInvalidRequestError', code: 'resource_missing' }, 'degraded', 'misconfigured'],
  ];
  for (const [err, status, reason] of cases) {
    world({ stripeError: Object.assign(new Error('x'), err) });
    const s = byId(await systemHealth.getReport()).stripe;
    assert.deepEqual([s.status, s.reason], [status, reason], err.type);
  }
  world({ stripeLivemode: false });
  const s = byId(await systemHealth.getReport()).stripe;
  assert.deepEqual([s.status, s.reason, s.metrics.livemode], ['degraded', 'test_mode_in_production', false]);
  assert.equal('unit_amount' in s.metrics, false, 'no price data passed through');

  world({ env: { STRIPE_SECRET_KEY: '' } });
  assert.deepEqual(byId(await systemHealth.getReport()).stripe.reason, 'not_configured');
});

test('Stripe webhooks: processed events, failures since start and a missing secret are reported separately from the API', async () => {
  world();
  let h = byId(await systemHealth.getReport()).stripe_webhooks;
  assert.equal(h.status, 'idle', 'no events yet is not a failure');

  world();
  StripeEvent._insert({ eventId: 'evt_A' }, { eventId: 'evt_B' }, { eventId: 'checkout:cs_1' });
  signals.recordOutcome('stripe_webhook', true);
  h = byId(await systemHealth.getReport()).stripe_webhooks;
  assert.equal(h.status, 'healthy');
  assert.equal(h.metrics.processedLast7d, 2, 'checkout claims excluded');
  assert.ok(h.metrics.lastProcessedAt);

  world();
  signals.recordOutcome('stripe_webhook', false, 'processing_failed');
  h = byId(await systemHealth.getReport()).stripe_webhooks;
  assert.deepEqual([h.status, h.reason, h.metrics.lastFailureCode], ['degraded', 'webhook_failures', 'processing_failed']);

  world({ env: { STRIPE_WEBHOOK_SECRET: '' } });
  h = byId(await systemHealth.getReport()).stripe_webhooks;
  assert.deepEqual([h.status, h.reason], ['unavailable', 'not_configured']);
});

test('email: SES sending paused is unavailable; near quota is degraded; SMTP is only configured', async () => {
  world({ aws: { GetAccountSendingEnabled: async () => ({ Enabled: false }) } });
  let e = byId(await systemHealth.getReport()).email;
  assert.deepEqual([e.status, e.reason], ['unavailable', 'sending_paused']);

  world({ aws: { GetSendQuota: async () => ({ Max24HourSend: 200, SentLast24Hours: 190, MaxSendRate: 1 }) } });
  e = byId(await systemHealth.getReport()).email;
  assert.deepEqual([e.status, e.reason, e.notes], ['degraded', 'quota_nearly_used', ['possible_sandbox']]);

  world({ env: { USE_AWS_SES: '', EMAIL_USER: 'dev@example.com' } });
  e = byId(await systemHealth.getReport()).email;
  assert.deepEqual([e.status, e.notes], ['configured', ['smtp_not_verified']]);

  world({ aws: { GetSendQuota: async () => { throw awsErr('AccessDenied'); } } });
  e = byId(await systemHealth.getReport()).email;
  assert.deepEqual([e.status, e.reason], ['unknown', 'permission_denied']);
});

test('AWS: a failed monitoring call is "unknown", never mistaken for an unhealthy resource', async () => {
  world({ aws: {
    DescribeServices: async () => { throw awsErr('AccessDeniedException'); },
    DescribeTargetHealth: async () => { throw awsErr('AccessDenied'); },
    GetMetricData: async () => { throw awsErr('AccessDenied'); },
    DescribeAlarms: async () => { throw awsErr('AccessDenied'); },
  } });
  const s = byId(await systemHealth.getReport());
  assert.deepEqual([s.aws_backend.status, s.aws_backend.reason], ['unknown', 'permission_denied']);
  assert.equal(s.aws_backend.metrics.http15m, null, 'missing metric is null, not 0');
  assert.deepEqual([s.aws_alarms.status, s.aws_alarms.reason], ['unknown', 'permission_denied']);

  // One part denied, the rest fine: the card does not claim success.
  world({ aws: { DescribeTargetHealth: async () => { throw awsErr('AccessDenied'); } } });
  const b = byId(await systemHealth.getReport()).aws_backend;
  assert.deepEqual([b.status, b.reason], ['unknown', 'partial_check']);
  assert.deepEqual(b.metrics.parts.targets, { status: 'unknown', reason: 'permission_denied' });

  assert.equal(awsReason(Object.assign(new Error('x'), { name: 'ThrottlingException' })), 'rate_limited');
  assert.equal(awsReason(Object.assign(new Error('x'), { name: 'CredentialsProviderError' })), 'credentials');
  // What AWS really returns for a bad key: HTTP 403, but it is not a permission problem.
  assert.equal(awsReason(Object.assign(new Error('x'), { name: 'InvalidClientTokenId', $metadata: { httpStatusCode: 403 } })), 'credentials');
  assert.equal(awsReason(Object.assign(new Error('x'), { name: 'AccessDeniedException', $metadata: { httpStatusCode: 400 } })), 'permission_denied');
  assert.equal(awsReason(Object.assign(new Error('x'), { name: 'ServiceNotFoundException' })), 'misconfigured');
});

test('AWS: genuinely unhealthy resources are reported as such', async () => {
  const cases = [
    [{ DescribeServices: async () => ({ services: [{ desiredCount: 1, runningCount: 0, deployments: [] }] }) }, 'unavailable', 'no_running_tasks'],
    [{ DescribeServices: async () => ({ services: [{ desiredCount: 2, runningCount: 1, deployments: [{ status: 'PRIMARY', rolloutState: 'IN_PROGRESS' }] }] }) }, 'degraded', 'tasks_below_desired'],
    [{ DescribeServices: async () => ({ services: [{ desiredCount: 1, runningCount: 1, deployments: [{ status: 'PRIMARY', rolloutState: 'FAILED' }] }] }) }, 'degraded', 'deployment_failed'],
    [{ DescribeTargetHealth: async () => ({ TargetHealthDescriptions: [{ TargetHealth: { State: 'unhealthy' } }] }) }, 'unavailable', 'no_healthy_targets'],
    [{ DescribeTargetHealth: async () => ({ TargetHealthDescriptions: [{ TargetHealth: { State: 'healthy' } }, { TargetHealth: { State: 'unhealthy' } }] }) }, 'degraded', 'targets_unhealthy'],
    [{ GetMetricData: async () => ({ MetricDataResults: [{ Id: 'req', Values: [100] }, { Id: 't5xx', Values: [9] }, { Id: 'e5xx', Values: [1] }] }) }, 'degraded', 'http_5xx'],
  ];
  for (const [aws, status, reason] of cases) {
    world({ aws });
    const b = byId(await systemHealth.getReport()).aws_backend;
    assert.deepEqual([b.status, b.reason], [status, reason], reason);
  }
  // No datapoints from a successful query is a real zero.
  world({ aws: { GetMetricData: async () => ({ MetricDataResults: [{ Id: 'req', Values: [] }, { Id: 't5xx', Values: [] }, { Id: 'e5xx', Values: [] }] }) } });
  assert.deepEqual(byId(await systemHealth.getReport()).aws_backend.metrics.http15m, { requests: 0, target5xx: 0, lb5xx: 0 });
});

test('AWS alarms: a firing alarm degrades and is named; missing backend alarms are flagged; none at all is unknown', async () => {
  world({ aws: { DescribeAlarms: async () => ({ MetricAlarms: [
    { AlarmName: 'fortexa-redis-memory', StateValue: 'ALARM' },
    { AlarmName: 'fortexa-redis-cpu', StateValue: 'OK' },
  ] }) } });
  let a = byId(await systemHealth.getReport()).aws_alarms;
  assert.deepEqual([a.status, a.reason], ['degraded', 'alarm']);
  assert.deepEqual(a.metrics.firing, ['fortexa-redis-memory']);
  assert.ok(a.notes.includes('backend_alarms_missing'));

  world({ aws: { DescribeAlarms: async () => ({ MetricAlarms: [] }) } });
  a = byId(await systemHealth.getReport()).aws_alarms;
  assert.deepEqual([a.status, a.reason], ['unknown', 'no_alarms']);
});

test('local development: unset AWS monitoring config reads "unknown / not configured", and no AWS call is made', async () => {
  const w = world({ env: {
    HEALTH_ECS_SERVICE: '', HEALTH_ALB_TARGET_GROUP_ARN: '', HEALTH_ALB_LOAD_BALANCER_ARN: '', HEALTH_ALARM_PREFIX: '', USE_AWS_SES: '',
  } });
  const s = byId(await systemHealth.getReport());
  assert.deepEqual([s.aws_backend.status, s.aws_backend.reason], ['unknown', 'not_configured']);
  assert.deepEqual([s.aws_alarms.status, s.aws_alarms.reason], ['unknown', 'not_configured']);
  assert.deepEqual(w.awsSent, []);
});
