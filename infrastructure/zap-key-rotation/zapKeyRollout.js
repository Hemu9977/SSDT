#!/usr/bin/env node
'use strict';

/**
 * ZAP API key rotation and enforcement rollout — the reviewed order, one step at a time.
 * Runbook, evidence and rollback: README.md in this folder.
 *
 *   node infrastructure/zap-key-rotation/zapKeyRollout.js <step> [--apply] [--profile ssdt]
 *
 *   status              read-only: where the rollout stands, and the next step
 *   1-rotate-secret     new random ZAP_AUTH_API_KEY; drop the unused ZAP_API_KEY key
 *   2-restart-backend   redeploy the backend on its current revision so it loads the key
 *   3-register-zap      register the keyed ZAP revisions from the repo task definitions
 *   4-verify-zap        start one task of each new revision outside its service: it must
 *                       turn HEALTHY (the keyed health check) and never log the key
 *   5-switch-zap        point both ZAP services at the verified revisions (only when idle)
 *   6-check-logs        read-only: ZAP/backend logs since the switch
 *   rollback-zap        point both ZAP services back at the keyless revisions
 *
 * Every step is a dry run unless --apply is given, refuses to run before the step it
 * depends on, and can be re-run (finished work is detected and skipped).
 *
 * Secret handling: the secret value is read into memory only. It is never printed,
 * logged or written to the repo; the one write to Secrets Manager goes through a
 * private temp file that is overwritten and deleted straight after. Only lengths,
 * formats and sha256 prefixes are shown.
 */

const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const argv = process.argv.slice(2);
const STEP = argv.find(a => !a.startsWith('--'));
const APPLY = argv.includes('--apply');
const AGAIN = argv.includes('--again');
const FORCE = argv.includes('--force');
const opt = (name, dflt) => { const i = argv.indexOf(`--${name}`); return i !== -1 && argv[i + 1] ? argv[i + 1] : dflt; };
const PROFILE = opt('profile', process.env.AWS_PROFILE || 'ssdt');
const REGION = opt('region', 'ap-northeast-1');

const CLUSTER = 'fortexa-cluster';
const SECRET_ID = 'fortexa-backend-secrets';
const KEY_NAME = 'ZAP_AUTH_API_KEY';   // what every keyed revision injects
const UNUSED_KEY = 'ZAP_API_KEY';      // a JSON key no active revision references
// sha256 of the key that was hard-coded in zapService.js (public git history,
// 943b2cb..1fbb156). Lets the tool say whether a stored value is that key.
const LEAKED_SHA256 = '0a88ca64a902b43bb650e23b6e9202dac43619f2c76ddfc29bdfb1bcb6e8f2e9';
const BACKEND_SERVICE = 'fortexa-ec2-backend';
const ZAP = {
  normal: { service: 'zap-scan-ec2', family: 'zap-scanner-task', file: '../zap-task-def.json', keylessRevision: 21 },
  auth: { service: 'zap-auth-task-ec2', family: 'zap-auth-task', file: '../zap-auth-task-def.json', keylessRevision: 12 },
};
const STATE_FILE = path.join(__dirname, '.rollout-state.json');
const VERIFY_STARTED_BY = 'zap-key-verify';

// ── Plumbing ───────────────────────────────────────────────────────────────────

function aws(args, { json = true } = {}) {
  const r = spawnSync('aws', [...args, '--profile', PROFILE, '--region', REGION, ...(json ? ['--output', 'json'] : [])], {
    encoding: 'utf8', maxBuffer: 256 << 20,
    env: { ...process.env, AWS_PAGER: '', PYTHONUTF8: '1', MSYS_NO_PATHCONV: '1' },
  });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    // CLI error text names the operation and resource, never a secret value.
    throw new Error(`aws ${args.slice(0, 2).join(' ')} failed: ${(r.stderr || '').trim().split('\n').pop()}`);
  }
  if (!json) return r.stdout;
  return r.stdout.trim() ? JSON.parse(r.stdout) : {};
}

/** Run `aws` with a JSON parameter document written to a private temp file. */
function awsWithInput(args, input) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zapkey-'));
  const file = path.join(dir, 'input.json');
  const body = JSON.stringify(input);
  try {
    fs.writeFileSync(file, body, { mode: 0o600, flag: 'wx' });
    return aws([...args, '--cli-input-json', `file://${file}`]);
  } finally {
    try { fs.writeFileSync(file, '0'.repeat(body.length)); } catch { /* already gone */ }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const sha = v => crypto.createHash('sha256').update(v).digest('hex');
const fp = v => (typeof v === 'string' ? `len ${v.length}, sha256 ${sha(v).slice(0, 8)}…` : 'absent');
const fmt = v => (typeof v !== 'string' ? 'absent' : /^[0-9a-f]{64}$/.test(v) ? '64 hex chars'
  : /^[A-Za-z0-9]+$/.test(v) ? `${v.length} alphanumeric chars` : `${v.length} chars incl. non-alphanumeric`);
const leaked = v => typeof v === 'string' && sha(v) === LEAKED_SHA256;

function loadState() { try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return {}; } }
function saveState(patch) { const s = { ...loadState(), ...patch }; fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2) + '\n'); return s; }

function header(title) { console.log(`\n== ${title} ${APPLY ? '' : '(dry run — add --apply to execute)'}`); }
function refuse(msg) { console.error(`\n✋ ${msg}`); process.exit(2); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── AWS reads ──────────────────────────────────────────────────────────────────

function readSecret() {
  const raw = aws(['secretsmanager', 'get-secret-value', '--secret-id', SECRET_ID, '--query', 'SecretString', '--output', 'text'], { json: false }).replace(/\r?\n$/, '');
  let obj;
  try { obj = JSON.parse(raw); } catch { refuse(`${SECRET_ID} is not a JSON object — nothing here knows how to edit it.`); }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) refuse(`${SECRET_ID} is not a JSON object.`);
  return obj;
}

function secretMeta() {
  return aws(['secretsmanager', 'describe-secret', '--secret-id', SECRET_ID]);
}

function service(name) {
  const s = aws(['ecs', 'describe-services', '--cluster', CLUSTER, '--services', name]).services[0];
  if (!s) refuse(`service ${name} not found`);
  return s;
}

function taskDef(ref) { return aws(['ecs', 'describe-task-definition', '--task-definition', ref]).taskDefinition; }
const tdRef = arn => arn.replace(/^.*task-definition\//, '');

function serviceTasks(name) {
  const arns = aws(['ecs', 'list-tasks', '--cluster', CLUSTER, '--service-name', name, '--desired-status', 'RUNNING']).taskArns || [];
  return arns.length ? aws(['ecs', 'describe-tasks', '--cluster', CLUSTER, '--tasks', ...arns]).tasks : [];
}

/** Does this revision run ZAP with the API key enforced? */
function isKeyed(td) {
  const cmd = (td.containerDefinitions[0].command || []).join(' ');
  return /api\.key=/.test(cmd) && !/api\.disablekey=true/.test(cmd);
}

/** valueFrom suffixes `<secret>:<JSON key>::` of a container's secrets, by env name. */
function secretMap(td) {
  return Object.fromEntries((td.containerDefinitions[0].secrets || []).map(s => [s.name, s.valueFrom]));
}

/** Every ACTIVE revision of every family whose secrets reference `${SECRET_ID}…:<jsonKey>::`. */
function activeReferencesTo(jsonKey) {
  const families = aws(['ecs', 'list-task-definition-families', '--status', 'ACTIVE']).families || [];
  const hits = [];
  let scanned = 0;
  for (const family of families) {
    const arns = aws(['ecs', 'list-task-definitions', '--family-prefix', family, '--status', 'ACTIVE']).taskDefinitionArns || [];
    for (const arn of arns) {
      const td = taskDef(arn);
      if (td.family !== family) continue; // --family-prefix also matches longer names
      scanned++;
      for (const c of td.containerDefinitions) {
        for (const s of c.secrets || []) {
          if (s.valueFrom.includes(`:secret:${SECRET_ID}`) && s.valueFrom.endsWith(`:${jsonKey}::`)) hits.push(`${tdRef(arn)} (${c.name}.${s.name})`);
        }
      }
    }
  }
  return { hits, scanned, families };
}

/** Step 1 is finished: the unused key is gone and the live key is one ZAP will start with. */
function requireRotated(secret = readSecret()) {
  if (secret[UNUSED_KEY] !== undefined || leaked(secret[KEY_NAME])) refuse('run 1-rotate-secret first.');
  if (!/^[A-Za-z0-9]{32,}$/.test(secret[KEY_NAME] || '')) {
    refuse(`${KEY_NAME} is ${fmt(secret[KEY_NAME])}: the keyed ZAP start command refuses anything but 32+ alphanumeric characters. Run 1-rotate-secret --again.`);
  }
  return secret;
}

function backendState() {
  const svc = service(BACKEND_SERVICE);
  const td = taskDef(svc.taskDefinition);
  const map = secretMap(td);
  const keyedClient = [UNUSED_KEY, KEY_NAME].every(n => (map[n] || '').endsWith(`:${KEY_NAME}::`));
  const tasks = serviceTasks(BACKEND_SERVICE);
  return { svc, td, keyedClient, tasks };
}

function zapState(which) {
  const z = ZAP[which];
  const svc = service(z.service);
  const td = taskDef(svc.taskDefinition);
  return { z, svc, td, keyed: isKeyed(td), idle: svc.desiredCount === 0 && svc.runningCount === 0 && svc.pendingCount === 0 };
}

/** The repo task definition, checked for every property the rollout depends on. */
function repoTaskDef(which, secretArn) {
  const z = ZAP[which];
  const td = JSON.parse(fs.readFileSync(path.join(__dirname, z.file), 'utf8'));
  const c = td.containerDefinitions[0];
  const cmd = (c.command || []).join(' ');
  const problems = [];
  if (td.family !== z.family) problems.push(`family is ${td.family}`);
  if (!/@sha256:[0-9a-f]{64}$/.test(c.image)) problems.push('image is not pinned by digest');
  if (!cmd.includes('-config api.key="$ZAP_API_KEY"')) problems.push('command does not set api.key from $ZAP_API_KEY');
  if (/disablekey/.test(cmd)) problems.push('command still disables the key');
  if (!cmd.includes('logger.abstractparam.level = warn')) problems.push('command does not silence the config logger (ZAP would log the key)');
  if (!/\*\[!A-Za-z0-9\]\*\) .*exit 1/.test(cmd)) problems.push('command does not refuse a missing/malformed key');
  const sec = (c.secrets || []).find(s => s.name === 'ZAP_API_KEY');
  if (!sec || sec.valueFrom !== `${secretArn}:${KEY_NAME}::`) problems.push(`secret ZAP_API_KEY must come from ${SECRET_ID}:${KEY_NAME}`);
  if (!(c.healthCheck?.command || []).join(' ').includes('X-ZAP-API-Key: $ZAP_API_KEY')) problems.push('health check does not send the key');
  if (problems.length) refuse(`${z.file}: ${problems.join('; ')}`);
  return td;
}

/** Comparable form of a task definition (registration output adds read-only fields). */
function canonical(td) {
  const c = td.containerDefinitions[0];
  return JSON.stringify({
    family: td.family, cpu: String(td.cpu), memory: String(td.memory), networkMode: td.networkMode,
    exec: td.executionRoleArn, role: td.taskRoleArn, image: c.image, command: c.command, entryPoint: c.entryPoint,
    secrets: c.secrets, health: c.healthCheck, ports: (c.portMappings || []).map(p => ({ ...p, hostPort: p.hostPort ?? p.containerPort })),
    log: c.logConfiguration, mem: c.memory, memRes: c.memoryReservation,
  });
}

function latestRegistered(which, repoTd) {
  const arns = aws(['ecs', 'list-task-definitions', '--family-prefix', ZAP[which].family, '--status', 'ACTIVE', '--sort', 'DESC', '--max-items', '5']).taskDefinitionArns || [];
  for (const arn of arns) {
    const td = taskDef(arn);
    if (td.family === ZAP[which].family && canonical(td) === canonical(repoTd)) return td.revision;
  }
  return null;
}

// ── Steps ──────────────────────────────────────────────────────────────────────

async function status() {
  header('status (read-only)');
  const meta = secretMeta();
  const secret = readSecret();
  console.log(`secret ${SECRET_ID}: ${Object.keys(secret).length} keys, last changed ${meta.LastChangedDate}`);
  console.log(`  ${KEY_NAME}: ${fmt(secret[KEY_NAME])}${leaked(secret[KEY_NAME]) ? '  ⚠ EQUALS THE LEAKED KEY' : ''}`);
  console.log(`  ${UNUSED_KEY}: ${fmt(secret[UNUSED_KEY])}${leaked(secret[UNUSED_KEY]) ? '  ⚠ EQUALS THE LEAKED KEY' : ''}`);
  const b = backendState();
  const changed = new Date(meta.LastChangedDate);
  const fresh = b.tasks.length > 0 && b.tasks.every(t => new Date(t.startedAt) > changed);
  console.log(`backend ${BACKEND_SERVICE}: ${tdRef(b.svc.taskDefinition)}, ${b.svc.runningCount}/${b.svc.desiredCount} running, `
    + `sends key to both ZAPs: ${b.keyedClient ? 'yes' : 'NO'}, tasks started after the secret changed: ${fresh ? 'yes' : 'no'}`);
  for (const which of Object.keys(ZAP)) {
    const s = zapState(which);
    console.log(`zap ${which} ${s.z.service}: ${tdRef(s.svc.taskDefinition)} (${s.keyed ? 'KEY ENFORCED' : 'keyless'}), ${s.svc.runningCount}/${s.svc.desiredCount} running`);
  }
  const st = loadState();
  if (Object.keys(st).length) console.log(`local state: ${JSON.stringify(st)}`);
  const next = secret[UNUSED_KEY] !== undefined || leaked(secret[KEY_NAME]) ? '1-rotate-secret'
    : !fresh ? '2-restart-backend'
      : !(st.registered?.normal && st.registered?.auth) ? '3-register-zap'
        : !(st.verified?.normal === st.registered.normal && st.verified?.auth === st.registered.auth) ? '4-verify-zap'
          : !st.switchedAt ? '5-switch-zap' : '6-check-logs';
  console.log(`\nnext step: ${next}`);
}

async function rotateSecret() {
  header('1-rotate-secret');
  const { hits, scanned, families } = activeReferencesTo(UNUSED_KEY);
  console.log(`active revisions scanned: ${scanned} across ${families.join(', ')}`);
  if (hits.length) refuse(`${UNUSED_KEY} is still referenced — removing it would stop these from starting: ${hits.join(', ')}`);
  console.log(`no active revision references ${SECRET_ID}:${UNUSED_KEY} ✔`);

  const before = readSecret();
  console.log(`current ${KEY_NAME}: ${fmt(before[KEY_NAME])}${leaked(before[KEY_NAME]) ? ' — EQUALS THE LEAKED KEY' : ''}`);
  console.log(`current ${UNUSED_KEY}: ${fmt(before[UNUSED_KEY])}${leaked(before[UNUSED_KEY]) ? ' — EQUALS THE LEAKED KEY' : ''}`);
  if (before[UNUSED_KEY] === undefined && !leaked(before[KEY_NAME]) && !AGAIN) {
    console.log(`\nAlready rotated (${UNUSED_KEY} is gone). Pass --again to generate yet another key.`);
    return;
  }
  const newKey = crypto.randomBytes(32).toString('hex'); // 64 hex chars: ZAP's start guard accepts only [A-Za-z0-9]
  const next = { ...before, [KEY_NAME]: newKey };
  delete next[UNUSED_KEY];
  const untouched = Object.keys(before).filter(k => k !== KEY_NAME && k !== UNUSED_KEY);
  console.log(`plan: replace ${KEY_NAME} with a new 64-hex key; remove ${UNUSED_KEY}; keep the other ${untouched.length} keys unchanged.`);
  console.log('effect now: none — production ZAP still runs keyless (api.disablekey=true); the backend keeps its old value until step 2.');
  if (!APPLY) return;

  awsWithInput(['secretsmanager', 'put-secret-value'], { SecretId: SECRET_ID, ClientRequestToken: crypto.randomUUID(), SecretString: JSON.stringify(next) });
  const after = readSecret();
  const ok = after[KEY_NAME] === newKey && after[UNUSED_KEY] === undefined
    && untouched.every(k => JSON.stringify(after[k]) === JSON.stringify(before[k])) && Object.keys(after).length === untouched.length + 1;
  if (!ok) refuse('read-back does not match what was written — inspect the secret versions (AWSCURRENT / AWSPREVIOUS) before going on.');
  saveState({ rotatedAt: new Date().toISOString(), keyFingerprint: sha(newKey).slice(0, 8) });
  console.log(`\n✅ rotated. New ${KEY_NAME}: ${fp(newKey)}. ${UNUSED_KEY} removed. AWSPREVIOUS holds the old version.`);
  console.log('next: 2-restart-backend');
}

async function restartBackend() {
  header('2-restart-backend');
  requireRotated();
  const changed = new Date(secretMeta().LastChangedDate);
  const b = backendState();
  if (!b.keyedClient) refuse(`${tdRef(b.svc.taskDefinition)} does not map both ZAP_API_KEY and ZAP_AUTH_API_KEY to ${SECRET_ID}:${KEY_NAME}; it could not talk to a keyed ZAP.`);
  if (b.tasks.length && b.tasks.every(t => new Date(t.startedAt) > changed)) {
    console.log(`already done: every running backend task started after the secret changed (${changed.toISOString()}).`);
    return;
  }
  console.log(`plan: force a new deployment of ${BACKEND_SERVICE} on ${tdRef(b.svc.taskDefinition)} (same revision, same image).`);
  console.log('⚠ minimum healthy is 0%: the API is down ~6–7 min while the old task drains and the new one starts. Pick a quiet window.');
  if (!APPLY) return;
  aws(['ecs', 'update-service', '--cluster', CLUSTER, '--service', BACKEND_SERVICE, '--force-new-deployment']);
  console.log('deployment started; waiting for it to finish (up to 20 min)…');
  const deadline = Date.now() + 20 * 60_000;
  while (Date.now() < deadline) {
    await sleep(20_000);
    const svc = service(BACKEND_SERVICE);
    const primary = svc.deployments.find(d => d.status === 'PRIMARY');
    const tasks = serviceTasks(BACKEND_SERVICE);
    const fresh = tasks.length > 0 && tasks.every(t => new Date(t.startedAt) > changed && t.lastStatus === 'RUNNING');
    process.stdout.write(`  ${primary?.rolloutState} running=${svc.runningCount}/${svc.desiredCount} deployments=${svc.deployments.length}\n`);
    if (primary?.rolloutState === 'COMPLETED' && svc.deployments.length === 1 && fresh) {
      saveState({ backendRestartedAt: new Date().toISOString() });
      console.log('\n✅ backend runs with the new key. Check a normal scan still works (ZAP is still keyless). next: 3-register-zap');
      return;
    }
    if (primary?.rolloutState === 'FAILED') refuse('the deployment FAILED — see the service events; the previous task definition is unchanged.');
  }
  refuse('timed out waiting; re-run this step to re-check (it does not redeploy once the new task is up).');
}

async function registerZap() {
  header('3-register-zap');
  requireRotated();
  const changed = new Date(secretMeta().LastChangedDate);
  const b = backendState();
  if (!(b.tasks.length && b.tasks.every(t => new Date(t.startedAt) > changed))) refuse('run 2-restart-backend first (the backend still holds the old key).');
  const secretArn = secretMeta().ARN;
  const registered = { ...(loadState().registered || {}) };
  for (const which of Object.keys(ZAP)) {
    const repo = repoTaskDef(which, secretArn);
    const existing = latestRegistered(which, repo);
    if (existing) { registered[which] = existing; console.log(`${ZAP[which].family}: already registered as :${existing}`); continue; }
    console.log(`${ZAP[which].family}: register ${ZAP[which].file} (image ${repo.containerDefinitions[0].image.split('@')[1].slice(0, 19)}…, api.key from ${SECRET_ID}:${KEY_NAME})`);
    if (!APPLY) continue;
    const out = aws(['ecs', 'register-task-definition', '--cli-input-json', `file://${path.join(__dirname, ZAP[which].file)}`]);
    registered[which] = out.taskDefinition.revision;
    console.log(`  → :${registered[which]}`);
  }
  if (APPLY || (registered.normal && registered.auth)) saveState({ registered });
  console.log('registering changes nothing that runs: both services stay on their current revisions. next: 4-verify-zap');
}

async function verifyZap() {
  header('4-verify-zap');
  const st = loadState();
  if (!(st.registered?.normal && st.registered?.auth)) refuse('run 3-register-zap first.');
  const key = requireRotated()[KEY_NAME];
  const verified = { ...(st.verified || {}) };
  for (const which of Object.keys(ZAP)) {
    const s = zapState(which);
    const ref = `${s.z.family}:${st.registered[which]}`;
    if (verified[which] === st.registered[which] && !AGAIN) { console.log(`${ref}: already verified`); continue; }
    if (!s.idle && !FORCE) refuse(`${s.z.service} is not idle (${s.svc.runningCount}/${s.svc.desiredCount}) — a scan may need that capacity. Retry when idle, or --force.`);
    const net = s.svc.networkConfiguration;
    const cap = s.svc.capacityProviderStrategy;
    console.log(`${ref}: one task outside the service (${cap.map(c => c.capacityProvider).join(',')}, same subnets/SG); expect HEALTHY, "now listening", no key in its log; then stopped.`);
    if (!APPLY) continue;
    const run = awsWithInput(['ecs', 'run-task'], {
      cluster: CLUSTER, taskDefinition: ref, count: 1, startedBy: VERIFY_STARTED_BY,
      capacityProviderStrategy: cap, networkConfiguration: net,
    });
    if (run.failures?.length) refuse(`run-task failed: ${JSON.stringify(run.failures)}`);
    const taskArn = run.tasks[0].taskArn;
    const taskId = taskArn.split('/').pop();
    let result = 'timeout';
    try {
      const deadline = Date.now() + 20 * 60_000; // includes an instance scale-out
      while (Date.now() < deadline) {
        await sleep(15_000);
        const t = aws(['ecs', 'describe-tasks', '--cluster', CLUSTER, '--tasks', taskArn]).tasks[0];
        process.stdout.write(`  ${t.lastStatus} health=${t.healthStatus}\n`);
        if (t.lastStatus === 'STOPPED') { result = `stopped: ${t.stoppedReason} / ${t.containers?.[0]?.reason || ''}`; break; }
        if (t.healthStatus === 'UNHEALTHY') { result = 'UNHEALTHY'; break; }
        if (t.lastStatus === 'RUNNING' && t.healthStatus === 'HEALTHY') { result = 'healthy'; break; }
      }
      const td = taskDef(ref);
      const c = td.containerDefinitions[0];
      const lo = c.logConfiguration.options;
      let messages = [];
      try {
        const ev = aws(['logs', 'get-log-events', '--log-group-name', lo['awslogs-group'], '--log-stream-name', `${lo['awslogs-stream-prefix']}/${c.name}/${taskId}`, '--start-from-head', '--limit', '10000']);
        messages = (ev.events || []).map(e => e.message);
      } catch (e) { console.log(`  could not read the task log: ${e.message}`); }
      const listening = messages.some(m => m.includes('now listening'));
      const keyLogged = messages.some(m => m.includes(key));
      const configLines = messages.filter(m => /Setting config api\.key/.test(m)).length;
      console.log(`  result=${result} listening=${listening} log lines=${messages.length} key in log=${keyLogged ? 'YES ⚠' : 'no'} "Setting config api.key" lines=${configLines}`);
      if (result !== 'healthy' || !listening || keyLogged || configLines) refuse(`${ref} failed verification — the services were not touched. Fix, re-register (3) and re-verify.`);
      verified[which] = st.registered[which];
      saveState({ verified });
      console.log(`  ✅ ${ref} verified`);
    } finally {
      try { aws(['ecs', 'stop-task', '--cluster', CLUSTER, '--task', taskArn, '--reason', 'zap key rollout verification finished']); } catch { /* already stopped */ }
    }
  }
  if (APPLY) console.log('next: 5-switch-zap');
}

async function switchZap() {
  header('5-switch-zap');
  const st = loadState();
  for (const which of Object.keys(ZAP)) {
    if (!st.registered?.[which] || st.verified?.[which] !== st.registered[which]) refuse(`run 4-verify-zap first (${which} not verified).`);
  }
  const b = backendState();
  if (!b.keyedClient) refuse(`backend ${tdRef(b.svc.taskDefinition)} does not send the key to both ZAPs.`);
  const previous = { ...(st.previous || {}) };
  for (const which of Object.keys(ZAP)) {
    const s = zapState(which);
    const target = `${s.z.family}:${st.registered[which]}`;
    if (tdRef(s.svc.taskDefinition) === target) { console.log(`${s.z.service}: already on ${target}`); continue; }
    if (!s.idle && !FORCE) refuse(`${s.z.service} is busy (${s.svc.runningCount}/${s.svc.desiredCount}); switching would replace a task under a running scan. Retry when idle.`);
    if (!s.keyed) previous[which] = tdRef(s.svc.taskDefinition);
    console.log(`${s.z.service}: ${tdRef(s.svc.taskDefinition)} → ${target} (desiredCount stays ${s.svc.desiredCount}; the next scan starts the keyed task)`);
    if (APPLY) aws(['ecs', 'update-service', '--cluster', CLUSTER, '--service', s.z.service, '--task-definition', target]);
  }
  if (APPLY) {
    saveState({ previous, switchedAt: new Date().toISOString() });
    console.log('\n✅ switched. Now run a normal scan, a form-login scan and a Basic-auth scan, then 6-check-logs.');
    console.log(`   rollback: node ${path.relative(process.cwd(), __filename)} rollback-zap --apply`);
  }
}

async function checkLogs() {
  header('6-check-logs (read-only)');
  const st = loadState();
  const since = Math.floor(new Date(st.switchedAt || Date.now() - 86400_000).getTime() / 1000);
  const now = Math.floor(Date.now() / 1000);
  const groups = Object.keys(ZAP).map(w => taskDef(`${ZAP[w].family}:${st.registered?.[w] || ZAP[w].keylessRevision}`).containerDefinitions[0].logConfiguration.options['awslogs-group']);
  const queries = [
    ['ZAP: "Setting config api.key" lines (must be 0)', groups, 'filter @message like /Setting config api.key/ | stats count(*) as n'],
    ['ZAP: containers that started', groups, 'filter @message like /now listening/ | stats count(*) as n'],
    ['backend: ZAP refusals (socket hang up / did not respond / ECONNRESET)', ['/ecs/fortexa-backend'],
      'filter @message like /(?i)zap/ and @message like /(socket hang up|did not respond|ECONNRESET)/ | stats count(*) as n'],
    ['backend: scans completed', ['/ecs/fortexa-backend'], 'filter @message like /Scan completed with AI report/ | stats count(*) as n'],
  ];
  for (const [label, logGroups, q] of queries) {
    const existing = logGroups.filter(g => (aws(['logs', 'describe-log-groups', '--log-group-name-prefix', g]).logGroups || []).some(x => x.logGroupName === g));
    if (!existing.length) { console.log(`${label}: (no log group yet)`); continue; }
    const id = aws(['logs', 'start-query', '--log-group-names', ...existing, '--start-time', String(since), '--end-time', String(now), '--query-string', q]).queryId;
    let r;
    for (let i = 0; i < 60; i++) { await sleep(2000); r = aws(['logs', 'get-query-results', '--query-id', id]); if (r.status === 'Complete') break; }
    const n = r.results?.[0]?.find(f => f.field === 'n')?.value || '0';
    console.log(`${label}: ${n}`);
  }
  console.log(`window: since ${new Date(since * 1000).toISOString()}`);
}

async function rollbackZap() {
  header('rollback-zap');
  const st = loadState();
  for (const which of Object.keys(ZAP)) {
    const s = zapState(which);
    const target = st.previous?.[which] || `${s.z.family}:${s.z.keylessRevision}`;
    const td = taskDef(target);
    if (isKeyed(td)) refuse(`${target} is keyed; refusing to "roll back" to it.`);
    if (tdRef(s.svc.taskDefinition) === target) { console.log(`${s.z.service}: already on ${target}`); continue; }
    if (!s.idle && !FORCE) refuse(`${s.z.service} is busy (${s.svc.runningCount}/${s.svc.desiredCount}); --force interrupts the running scan.`);
    console.log(`${s.z.service}: ${tdRef(s.svc.taskDefinition)} → ${target} (keyless: accepts every backend revision)`);
    if (APPLY) aws(['ecs', 'update-service', '--cluster', CLUSTER, '--service', s.z.service, '--task-definition', target]);
  }
  if (APPLY) { saveState({ rolledBackAt: new Date().toISOString(), switchedAt: null }); console.log('\n✅ ZAP is keyless again. The backend needs no change.'); }
}

const STEPS = {
  status, '1-rotate-secret': rotateSecret, '2-restart-backend': restartBackend, '3-register-zap': registerZap,
  '4-verify-zap': verifyZap, '5-switch-zap': switchZap, '6-check-logs': checkLogs, 'rollback-zap': rollbackZap,
};

if (!STEPS[STEP]) {
  console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0].replace(/^#!.*\n'use strict';\n\n\/\*\*\n/, '').replace(/^ \* ?/gm, ''));
  process.exit(STEP ? 1 : 0);
}
STEPS[STEP]().catch(err => { console.error(`\n❌ ${err.message}`); process.exit(1); });
