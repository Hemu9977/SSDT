'use strict';

/**
 * Scan orchestration: a non-blocking starter's placeholder must never overwrite results.
 *
 * ZAP and WebCheck are started with `startAsyncZapScan` / `startAsyncWebCheckScan`,
 * which return IMMEDIATELY with a `{status:'running'}` placeholder and do the real work
 * in the background. Each of those services owns its own slice of the ScanResult
 * document: it writes an init (zapService.js, webCheckService.js) and then keeps it
 * current with dotted-path updates.
 *
 * Every orchestrator therefore has the same hazard. If it launches those alongside the
 * blocking scanners (PageSpeed / Observatory / urlscan) and persists everything after a
 * single Promise.allSettled, the write lands only once the SLOWEST leg resolves.
 * urlscan alone polls for 20-30s while WebCheck finishes in ~18s, so the placeholder
 * routinely landed on top of 29 completed sub-scans — and reverted the status from a
 * terminal completed_with_errors back to 'running', so the Gemini completion check
 * never fired and the scan sat in 'combining' until the watchdog failed it.
 *
 * ZAP masked the symptom: it finishes minutes later and rewrites itself, so only
 * WebCheck visibly lost data. A production document showed exactly that fingerprint —
 * a rich zapResult beside a bare five-key webCheckResult placeholder.
 *
 * It has now been fixed in three files:
 *
 *   - workers/scanWorker.js            — re-reads and only fills unset legs
 *   - services/authFastScanService.js  — starts WebCheck last, after the others persist
 *   - services/schedulerService.js     — no longer writes those two legs at all
 *
 * Nothing caught any of the three. These tests are that guard.
 *
 * Run with: node --test backend/tests/scanOrchestrationRace.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

// Deliberately not require()'d — loading these modules opens database handles,
// Redis connections and cron timers.

/** Strip line comments so prose about a symbol is not mistaken for code using it. */
const stripComments = (text) =>
  text.split('\n').filter(line => !line.trim().startsWith('//')).join('\n');

// ──────────────────────────────────────────────────────────────────────────────
// The premise the guards rest on
// ──────────────────────────────────────────────────────────────────────────────

test('the async starters still return a non-terminal placeholder', () => {
  const webCheck = src('services/webCheckService.js');
  const starter = webCheck.slice(webCheck.indexOf('const startAsyncWebCheckScan'));

  assert.match(
    starter,
    /status:\s*'running',\s*\n\s*message:\s*'WebCheck scan started in background'/,
    'startAsyncWebCheckScan must still return a running placeholder - if it ever became '
      + 'blocking and returned real results, the reasoning below would need revisiting '
      + 'rather than being silently kept'
  );
});

test('the async services still own their own document state', () => {
  // The orchestrator can only stop writing these legs because the services write them.
  assert.match(
    src('services/zapService.js'),
    /zapResult:\s*\{\s*status:\s*'initializing'/,
    'zapService must keep writing its own init row'
  );
  assert.match(
    src('services/webCheckService.js'),
    /webCheckResult:\s*\{\s*\n\s*status:\s*'running'/,
    'webCheckService must keep writing its own init row'
  );
});

// ──────────────────────────────────────────────────────────────────────────────
// The scheduled public scan — the flow that was losing results in production
// ──────────────────────────────────────────────────────────────────────────────

function triggerPublicScanBody() {
  const scheduler = src('services/schedulerService.js');
  const start = scheduler.indexOf('async function triggerPublicScan');
  assert.notEqual(start, -1, 'triggerPublicScan not found in schedulerService.js');
  const end = scheduler.indexOf('async function triggerAuthenticatedScan', start);
  return scheduler.slice(start, end === -1 ? undefined : end);
}

/** The object literal of the first $set after the scanners settle. */
function postScannerSetBlock() {
  const body = stripComments(triggerPublicScanBody());
  const settleAt = body.indexOf('Promise.allSettled');
  assert.notEqual(settleAt, -1, 'expected the scanners to be launched together');

  const setAt = body.indexOf('$set', settleAt);
  assert.notEqual(setAt, -1, 'expected the blocking scanners to be persisted');

  const open = body.indexOf('{', setAt);
  let depth = 0;
  for (let i = open; i < body.length; i++) {
    if (body[i] === '{') depth++;
    else if (body[i] === '}') {
      depth--;
      if (depth === 0) return body.slice(open + 1, i);
    }
  }
  assert.fail('could not find the end of the $set object');
}

test('a scheduled scan persists only the scanners it actually owns', () => {
  const keys = postScannerSetBlock()
    .split('\n')
    .map(line => (line.match(/^\s*([A-Za-z_$][\w$]*)\s*[:,]/) || [])[1])
    .filter(Boolean);

  assert.deepEqual(
    keys.sort(),
    ['observatoryResult', 'pagespeedResult', 'updatedAt', 'urlscanResult'],
    'the orchestrator owns PageSpeed, Observatory and urlscan and nothing else. '
      + 'zapResult and webCheckResult are written by the services that run them - '
      + 'persisting them here writes a start placeholder over real results'
  );
});

test('a scheduled scan still records a leg that failed to start', () => {
  const body = stripComments(triggerPublicScanBody());

  // Dropping the placeholder write must not leave a leg that never started with no
  // status at all - the scan would then hang in 'combining' until the watchdog, which
  // is the same user-visible symptom by a different route. Dotted paths only: they
  // cannot clobber a leg that did start.
  for (const leg of ['zapResult', 'webCheckResult']) {
    assert.ok(
      body.includes(`${leg}.status`) || body.includes(`\${leg}.status`),
      `a ${leg} leg that failed to start must still be recorded, via a dotted path`
    );
  }
  assert.match(
    body,
    /recordFailedStart\(\s*'zapResult'/,
    'the ZAP leg must be checked for a failed start'
  );
  assert.match(
    body,
    /recordFailedStart\(\s*'webCheckResult'/,
    'the WebCheck leg must be checked for a failed start'
  );
});

test('a scheduled scan does not resurrect a stopped or cancelled scan', () => {
  const body = stripComments(triggerPublicScanBody());
  const writeAt = body.indexOf('ScanResult.updateOne', body.indexOf('Promise.allSettled'));
  const write = body.slice(writeAt, writeAt + 300);

  assert.match(
    write,
    /status:\s*\{\s*\$nin:\s*\[\s*'stopped',\s*'cancelled'\s*\]/,
    'the post-scanner write must skip scans the user stopped or the quota cancelled, '
      + 'matching scanWorker.js'
  );
});

// ──────────────────────────────────────────────────────────────────────────────
// Every other orchestrator that starts these non-blocking
// ──────────────────────────────────────────────────────────────────────────────

test('every flow that starts WebCheck non-blocking guards its own write', () => {
  // scanWorker re-reads; authFastScanService orders WebCheck last instead. Both are
  // valid answers to the same race - what is not valid is neither.
  assert.match(
    src('workers/scanWorker.js'),
    /fresh\?\.webCheckResult\?\.status/,
    'scanWorker.js must keep its "only if not already set by racing background" guard'
  );

  const authFast = src('services/authFastScanService.js');
  const webCheckAt = authFast.indexOf('startAsyncWebCheckScan(');
  const urlscanAt = authFast.indexOf('runUrlScan');
  assert.notEqual(webCheckAt, -1, 'authFastScanService must still start WebCheck');
  if (urlscanAt !== -1) {
    assert.ok(
      urlscanAt < webCheckAt,
      'authFastScanService starts WebCheck LAST on purpose - moving it back alongside '
        + 'the blocking scanners reintroduces the race its docblock describes'
    );
  }
});
