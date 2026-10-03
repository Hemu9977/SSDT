#!/usr/bin/env node
'use strict';

/**
 * Redis/Valkey compatibility smoke test for Fortexa.
 *
 * Exercises, against the Redis pointed to by REDIS_URL (+ REDIS_TLS_CA /
 * REDIS_TLS_SERVERNAME), every Redis feature the backend depends on — through the
 * backend's own connection factory (config/redis.js), so TLS, ACL and retry options
 * are exactly what production uses.
 *
 * Safe against a live server: BullMQ keys use the prefix "smoke" (production uses
 * "bull"), plain keys use "smoke:", and everything it creates is removed at the end.
 *
 *   node scripts/redisMigrationSmoke.js                  full suite (~30 s)
 *   node scripts/redisMigrationSmoke.js --phase=write    leave persistence probes behind
 *   node scripts/redisMigrationSmoke.js --phase=verify   check they survived a restart, then clean up
 *
 * Exit code 0 = every check passed.
 */

const crypto = require('crypto');
const { Queue, Worker, QueueEvents } = require('bullmq');
const { createRedisClient, createDedicatedConnection, disconnectAll } = require('../config/redis');

const PREFIX = 'smoke';
const RUN = crypto.randomBytes(4).toString('hex');
const phase = (process.argv.find(a => a.startsWith('--phase=')) || '--phase=full').split('=')[1];

const results = [];
const closers = [];
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function check(name, fn) {
  const started = Date.now();
  try {
    const detail = await fn();
    results.push({ name, ok: true, ms: Date.now() - started, detail: detail || '' });
  } catch (err) {
    results.push({ name, ok: false, ms: Date.now() - started, detail: err.message });
  }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }
function infoField(info, key) {
  const m = info.match(new RegExp(`^${key}:(.*)$`, 'm'));
  return m ? m[1].trim() : undefined;
}
function conn(purpose) {
  const c = createDedicatedConnection(`smoke-${purpose}`);
  closers.push(() => c.quit().catch(() => {}));
  return c;
}
function track(x) { closers.push(() => x.close().catch(() => {})); return x; }
function waitFor(pred, timeoutMs, label) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = async () => {
      try { if (await pred()) return resolve(); } catch (_) { /* keep polling */ }
      if (Date.now() - t0 > timeoutMs) return reject(new Error(`timeout waiting for ${label}`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

// Copied verbatim from services/zapRecycler.js — the scripts the ZAP lock relies on.
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

async function serverChecks(r) {
  await check('server: PING over the configured transport', async () => {
    assert((await r.ping()) === 'PONG', 'no PONG');
    return process.env.REDIS_URL.startsWith('rediss://') ? 'TLS' : 'PLAINTEXT';
  });
  await check('server: engine version >= 6.2 (BullMQ recommendation)', async () => {
    const info = await r.info('server');
    const v = infoField(info, 'valkey_version') || infoField(info, 'redis_version');
    const [maj, min] = v.split('.').map(Number);
    assert(maj > 6 || (maj === 6 && min >= 2), `version ${v}`);
    return `${infoField(info, 'valkey_version') ? 'valkey' : 'redis'} ${v}`;
  });
  await check('server: maxmemory-policy is noeviction (BullMQ requirement)', async () => {
    const policy = infoField(await r.info('memory'), 'maxmemory_policy');
    assert(policy === 'noeviction', `policy=${policy}`);
    return policy;
  });
  await check('server: AOF persistence enabled', async () => {
    const aof = infoField(await r.info('persistence'), 'aof_enabled');
    assert(aof === '1', `aof_enabled=${aof}`);
    return 'aof_enabled=1';
  });
  await check('acl: authenticated as the application user', async () => {
    const who = await r.call('ACL', 'WHOAMI');
    return `user=${who}`;
  });
  await check('acl: destructive admin commands are denied to the app user', async () => {
    for (const cmd of [['FLUSHALL'], ['CONFIG', 'SET', 'maxmemory-policy', 'allkeys-lru'], ['DEBUG', 'SLEEP', '0']]) {
      try {
        await r.call(...cmd);
        throw new Error(`${cmd[0]} was ALLOWED`);
      } catch (err) {
        if (err.message.includes('was ALLOWED')) throw err;
        // NOPERM = ACL denial; DEBUG is also disabled server-wide (enable-debug-command no).
        assert(/NOPERM|no permissions|command not allowed/i.test(err.message), `${cmd[0]}: unexpected error ${err.message}`);
      }
    }
    return 'FLUSHALL / CONFIG SET / DEBUG denied';
  });
}

async function fortexaPrimitiveChecks(r) {
  const lockKey = `smoke:${RUN}:lock`;
  await check('locks: SET NX PX acquire / contention (zap:lock, capacity, recycle)', async () => {
    assert((await r.set(lockKey, 'tokenA', 'NX', 'PX', 120000)) === 'OK', 'first acquire failed');
    assert((await r.set(lockKey, 'tokenB', 'NX', 'PX', 120000)) === null, 'second acquire succeeded');
    const pttl = await r.pttl(lockKey);
    assert(pttl > 100000 && pttl <= 120000, `pttl=${pttl}`);
  });
  await check('locks: Lua compare-and-PEXPIRE renew (zapRecycler heartbeat)', async () => {
    assert((await r.eval(RENEW_LUA, 1, lockKey, 'tokenA', '120000')) === 1, 'owner renew failed');
    assert((await r.eval(RENEW_LUA, 1, lockKey, 'tokenB', '120000')) === 0, 'non-owner renewed');
  });
  await check('locks: Lua compare-and-DEL release', async () => {
    assert((await r.eval(RELEASE_LUA, 1, lockKey, 'tokenB')) === 0, 'non-owner released');
    assert((await r.eval(RELEASE_LUA, 1, lockKey, 'tokenA')) === 1, 'owner release failed');
    assert((await r.exists(lockKey)) === 0, 'key still exists');
  });
  await check('state: SET EX / GET / EXISTS / DEL (progress, Gemini flags, PDF jobs)', async () => {
    const k = `smoke:${RUN}:state`;
    await r.set(k, JSON.stringify({ progress: 42 }), 'EX', 3600);
    assert(JSON.parse(await r.get(k)).progress === 42, 'roundtrip');
    const ttl = await r.ttl(k);
    assert(ttl > 3500, `ttl=${ttl}`);
    assert((await r.del(k)) === 1, 'del');
  });
  await check('pub/sub: PUBLISH reaches a SUBSCRIBE client (scan_progress)', async () => {
    const sub = createRedisClient('smoke-sub');
    closers.push(() => sub.quit().catch(() => {}));
    const channel = `smoke:${RUN}:progress`;
    const got = new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('no message')), 5000);
      sub.on('message', (ch, msg) => { if (ch === channel) { clearTimeout(t); resolve(msg); } });
    });
    await sub.subscribe(channel);
    await r.publish(channel, 'hello');
    assert((await got) === 'hello', 'payload');
  });
}

async function bullmqChecks() {
  const qname = `q-${RUN}`;
  const queue = track(new Queue(qname, { connection: conn('queue'), prefix: PREFIX }));
  const events = track(new QueueEvents(qname, { connection: conn('events'), prefix: PREFIX }));
  await events.waitUntilReady();

  const processed = [];
  const attemptTimes = {};
  const worker = track(new Worker(qname, async job => {
    (attemptTimes[job.id] ||= []).push(Date.now());
    if (job.name === 'flaky' && job.attemptsMade < 2) throw new Error('planned failure');
    processed.push({ id: job.id, at: Date.now() });
    return { ok: true, id: job.id };
  }, { connection: conn('worker'), prefix: PREFIX, concurrency: 3 }));
  await worker.waitUntilReady();

  await check('bullmq: job with custom jobId is processed (scan-queue: jobId = scanId)', async () => {
    const id = `scan-${RUN}`;
    const done = new Promise(res => events.on('completed', ({ jobId }) => { if (jobId === id) res(); }));
    await queue.add('run-scan', { scanId: id }, { jobId: id, removeOnComplete: { count: 200, age: 3600 } });
    await Promise.race([done, sleep(10000).then(() => { throw new Error('not completed in 10 s'); })]);
    return 'completed + QueueEvents delivered';
  });
  await check('bullmq: duplicate add with the same jobId is a no-op', async () => {
    const id = `dupe-${RUN}`;
    const a = await queue.add('run-scan', { n: 1 }, { jobId: id });
    const b = await queue.add('run-scan', { n: 2 }, { jobId: id });
    assert(a.id === b.id, 'different ids');
    await waitFor(() => processed.some(p => p.id === id), 10000, 'dupe processed');
    await sleep(500);
    assert(processed.filter(p => p.id === id).length === 1, 'processed twice');
  });
  await check('bullmq: retries with exponential backoff (attempts 3)', async () => {
    const job = await queue.add('flaky', {}, { attempts: 3, backoff: { type: 'exponential', delay: 300 } });
    await waitFor(() => processed.some(p => p.id === job.id), 15000, 'flaky completed');
    const t = attemptTimes[job.id];
    assert(t.length === 3, `attempts=${t.length}`);
    const g1 = t[1] - t[0], g2 = t[2] - t[1];
    assert(g1 >= 250 && g2 >= 550, `gaps ${g1}ms, ${g2}ms`);
    return `gaps ${g1}ms, ${g2}ms (delayed set)`;
  });
  await check('bullmq: delayed job fires after its delay', async () => {
    const t0 = Date.now();
    const job = await queue.add('later', {}, { delay: 1500 });
    await waitFor(() => processed.some(p => p.id === job.id), 10000, 'delayed processed');
    const waited = processed.find(p => p.id === job.id).at - t0;
    assert(waited >= 1400, `fired after ${waited}ms`);
    return `fired after ${waited}ms`;
  });
  await check('bullmq: getJobCounts / getJob / remove (admin health, stop endpoints)', async () => {
    const counts = await queue.getJobCounts('waiting', 'active', 'delayed', 'paused', 'completed', 'failed');
    assert(typeof counts.completed === 'number', 'counts');
    const job = await queue.add('to-remove', {}, { delay: 60000 });
    assert((await queue.getJob(job.id)) !== undefined, 'getJob');
    await job.remove();
    assert((await queue.getJob(job.id)) === undefined, 'still present');
    return JSON.stringify(counts);
  });
  await worker.close();

  await check('bullmq: rate limiter (scan-worker limiter)', async () => {
    const lq = `lim-${RUN}`;
    const lqueue = track(new Queue(lq, { connection: conn('lq'), prefix: PREFIX }));
    const times = [];
    const lw = track(new Worker(lq, async () => { times.push(Date.now()); }, {
      connection: conn('lw'), prefix: PREFIX, limiter: { max: 2, duration: 1000 }
    }));
    await lw.waitUntilReady();
    for (let i = 0; i < 4; i++) await lqueue.add('j', { i });
    await waitFor(() => times.length === 4, 10000, 'limited jobs');
    const span = times[3] - times[0];
    await lw.close();
    assert(span >= 900, `4 jobs in ${span}ms`);
    return `4 jobs spread over ${span}ms`;
  });

  await check('bullmq: long lockDuration holds the lock (zap-worker 14 h)', async () => {
    const zq = `zap-${RUN}`;
    const zqueue = track(new Queue(zq, { connection: conn('zq'), prefix: PREFIX }));
    const lockKeyTtl = [];
    const r = createRedisClient('smoke-zq');
    closers.push(() => r.quit().catch(() => {}));
    const zw = track(new Worker(zq, async job => {
      lockKeyTtl.push(await r.pttl(`${PREFIX}:${zq}:${job.id}:lock`));
    }, { connection: conn('zw'), prefix: PREFIX, lockDuration: 14 * 3600 * 1000 }));
    await zw.waitUntilReady();
    await zqueue.add('run-zap-scan', {}, { jobId: `zap-${RUN}` });
    await waitFor(() => lockKeyTtl.length === 1, 10000, 'zap job ran');
    await zw.close();
    assert(lockKeyTtl[0] > 13 * 3600 * 1000, `lock pttl ${lockKeyTtl[0]}`);
    return `lock pttl ${(lockKeyTtl[0] / 3600000).toFixed(2)} h`;
  });

  await check('bullmq: stalled job is recovered by another worker after a crash', async () => {
    const sq = `stall-${RUN}`;
    const squeue = track(new Queue(sq, { connection: conn('sq'), prefix: PREFIX }));
    let started = false;
    const crashed = new Worker(sq, async () => { started = true; await new Promise(() => {}); }, {
      connection: conn('sw1'), prefix: PREFIX, lockDuration: 1000, stalledInterval: 500
    });
    await crashed.waitUntilReady();
    const job = await squeue.add('hang', {});
    await waitFor(() => started, 10000, 'first worker picked the job');
    await crashed.close(true); // force-close = process died: no lock renewal, no completion
    let recovered = false;
    const rescuer = track(new Worker(sq, async () => { recovered = true; }, {
      connection: conn('sw2'), prefix: PREFIX, lockDuration: 1000, stalledInterval: 500, maxStalledCount: 1
    }));
    await rescuer.waitUntilReady();
    await waitFor(() => recovered, 15000, 'stalled job recovered');
    const final = await squeue.getJob(job.id);
    return `recovered; state=${await final.getState()}`;
  });

  await check('bullmq: obliterate (cleanup Lua) is permitted by the ACL', async () => {
    for (const name of [qname, `lim-${RUN}`, `zap-${RUN}`, `stall-${RUN}`]) {
      const q = track(new Queue(name, { connection: conn(`ob-${name}`), prefix: PREFIX }));
      await q.obliterate({ force: true });
    }
  });
}

async function persistenceWrite(r) {
  await check('persistence: write probes (key with TTL, waiting job, delayed job)', async () => {
    await r.set('smoke:persist:key', 'v1', 'EX', 86400);
    const q = track(new Queue('persist', { connection: conn('pq'), prefix: PREFIX }));
    await q.add('waiting', { v: 1 }, { jobId: 'persist-waiting' });
    await q.add('delayed', { v: 2 }, { jobId: 'persist-delayed', delay: 60 * 60 * 1000 });
    return 'now restart Valkey / reboot / stop+start EC2, then run --phase=verify';
  });
}

async function persistenceVerify(r) {
  await check('persistence: probes survived the restart', async () => {
    assert((await r.get('smoke:persist:key')) === 'v1', 'plain key lost');
    assert((await r.ttl('smoke:persist:key')) > 0, 'TTL lost');
    const q = track(new Queue('persist', { connection: conn('pq'), prefix: PREFIX }));
    const w = await q.getJob('persist-waiting');
    const d = await q.getJob('persist-delayed');
    assert(w && (await w.getState()) === 'waiting', 'waiting job lost');
    assert(d && (await d.getState()) === 'delayed', 'delayed job lost');
    await q.obliterate({ force: true });
    await r.del('smoke:persist:key');
    return 'key + TTL + waiting job + delayed job intact';
  });
}

async function main() {
  if (!process.env.REDIS_URL) {
    console.error('REDIS_URL is not set');
    process.exit(2);
  }
  const r = createRedisClient('smoke');
  closers.push(() => r.quit().catch(() => {}));
  await r.ping().catch(err => { console.error('cannot connect:', err.message); process.exit(2); });

  try {
    if (phase === 'write') await persistenceWrite(r);
    else if (phase === 'verify') await persistenceVerify(r);
    else {
      await serverChecks(r);
      await fortexaPrimitiveChecks(r);
      await bullmqChecks();
    }
  } finally {
    for (const close of closers.reverse()) await close();
    await disconnectAll().catch(() => {});
  }

  const width = Math.max(...results.map(x => x.name.length));
  console.log('\nFortexa Redis smoke test —', phase, '—', new Date().toISOString());
  for (const x of results) {
    console.log(`${x.ok ? 'PASS' : 'FAIL'}  ${x.name.padEnd(width)}  ${String(x.ms).padStart(5)}ms  ${x.detail}`);
  }
  const failed = results.filter(x => !x.ok).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
