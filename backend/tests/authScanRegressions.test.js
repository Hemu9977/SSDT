'use strict';

/**
 * Regression guards for the authenticated-scan verification work.
 *
 * Each test here pins one bug found during review. They survived a full manual
 * read-through once already, so reading is demonstrably not enough to keep them
 * away — these are the tripwires.
 *
 * Several are source-shape assertions rather than behavioural ones, because the
 * defects live inside long orchestration functions that need a browser, a
 * database and a ZAP instance to execute. That is the same idiom the repo
 * already uses for its `jwt.sign` census in adminApiInvariants.test.js.
 *
 * Run with: node --test backend/tests/authScanRegressions.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const src = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

const zapAuthService = src('services/zapAuthService.js');
const zapAuthRoutes = src('routes/zapAuthRoutes.js');
const loginTestService = src('services/loginTestService.js');
const revealLoginPanel = src('utils/revealLoginPanel.js');
const scheduler = src('services/schedulerService.js');

// ─────────────────────────────────────────────────────────────────────────────
// F1 / F8 — a wholesale write must not erase the sign-in record
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Find every place a whole object literal is assigned to `authScanResult`, and
 * classify it by the nearest enclosing construct.
 *
 * Classifying by a fixed character window does not work — a long comment above
 * the write pushes `new ScanResult(` out of range and the site looks like a
 * replacement when it is a creation. Nearest-marker wins instead.
 */
function wholesaleAuthWrites(source, file) {
  const hits = [];
  // Both spellings matter. The completion write assigns a variable
  // (`authScanResult: authScanResultObj`), and an earlier version of this test
  // only matched inline object literals — so it silently skipped the single
  // site whose wholesale replacement caused the bug it was meant to guard.
  const re = /authScanResult:\s*(\{|(\w+))/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    let body;
    if (m[2]) {
      // Assigned from a variable: audit where that variable is built.
      const decl = source.indexOf(`const ${m[2]} = {`);
      if (decl === -1) continue; // Not a literal we can follow (e.g. a copy).
      body = source.slice(decl, decl + 1400);
    } else {
      body = source.slice(m.index, m.index + 900);
    }

    // `authScanResult: { $ne: null }` and friends are query filters, not writes.
    const literal = body.slice(body.indexOf('{'), body.indexOf('}') + 1);
    if (/\$(ne|eq|exists|in|nin|gt|lt)\b/.test(literal)) continue;

    // `authScanResult: null` is a query predicate, never a write.
    if (m[2] === 'null') continue;

    const before = source.slice(0, m.index);
    const markers = {
      setOnInsert: before.lastIndexOf('$setOnInsert'),
      create: before.lastIndexOf('new ScanResult('),
      set: before.lastIndexOf('$set:')
    };
    // No enclosing update or create at all means this is not a write. Falling
    // through to the reduce below would silently label it a creation and exempt
    // it — an exemption that would be accidental rather than reasoned.
    if (Math.max(...Object.values(markers)) < 0) continue;

    const nearest = Object.keys(markers).reduce((a, b) => (markers[b] > markers[a] ? b : a));

    hits.push({
      file,
      line: before.split('\n').length,
      kind: nearest,
      after: body
    });
  }
  return hits;
}

test('every wholesale authScanResult write either creates the document or carries the sign-in record forward', () => {
  // The bug: `$set: { authScanResult: {...} }` replaced the whole subdocument,
  // wiping `loginOutcome` — which both callers write into the skeleton record
  // moments earlier. The report could then never say the sign-in was confirmed.
  const writes = [
    ...wholesaleAuthWrites(zapAuthService, 'zapAuthService.js'),
    ...wholesaleAuthWrites(zapAuthRoutes, 'zapAuthRoutes.js'),
    ...wholesaleAuthWrites(scheduler, 'schedulerService.js')
  ];

  assert.ok(writes.length > 0, 'expected to find authScanResult writes to audit');

  const offenders = [];
  for (const w of writes) {
    // A creation write establishes the record; a replacement must carry the
    // previously recorded verification fields across.
    const isCreation = w.kind === 'setOnInsert' || w.kind === 'create';
    const carriesForward = /\.\.\.carriedAuth/.test(w.after);
    if (!isCreation && !carriesForward) {
      offenders.push(`${w.file}:${w.line}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    'a wholesale authScanResult write that neither creates the document nor spreads carriedAuth will erase the sign-in record'
  );
});

test('the scan-start update uses dotted paths so it cannot clobber siblings', () => {
  assert.match(
    zapAuthService,
    /'authScanResult\.status':\s*'running'/,
    'startAsyncAuthScan must set individual paths, not replace the object'
  );
});

test('the carried-forward key list covers every field the verification writes', () => {
  // If a new `authScanResult.<field>` is recorded during a scan but not listed
  // in AUTH_HEALTH_KEYS, the final write silently drops it — which is exactly
  // how the scheduler's degraded flag was lost.
  const listed = new Set(
    (zapAuthService.match(/const AUTH_HEALTH_KEYS = \[([^\]]*)\]/) || [, ''])[1]
      .split(',')
      .map((s) => s.trim().replace(/^'|'$/g, ''))
      .filter(Boolean)
  );

  const written = new Set(
    [...zapAuthService.matchAll(/'authScanResult\.(\w+)'/g)].map((m) => m[1])
  );

  // Progress/plumbing fields are re-set by the completion write itself.
  const setByCompletion = new Set([
    'status', 'phase', 'progress', 'authenticated', 'loginUrl', 'urlsFound',
    'alerts', 'startedAt', 'lastUpdate', 'error', 'completedAt', 'errorCode',
    'failedAt', 'message', 'riskCounts', 'totalAlerts', 'totalOccurrences',
    'reportFiles', 'sessionResetFailed'
  ]);

  const dropped = [...written].filter((f) => !listed.has(f) && !setByCompletion.has(f));
  assert.deepEqual(dropped, [], 'these fields would be lost by the final write');
});

// ─────────────────────────────────────────────────────────────────────────────
// F3 — the failure branch must never report a confirmed sign-in
// ─────────────────────────────────────────────────────────────────────────────

test('test-login cannot answer "confirmed" on a request it is refusing', () => {
  // A site that authenticates but issues no cookies used to produce
  // authConfirmed:'confirmed' with authenticated:false and no session id — a
  // green tick on a flow that then silently refused to advance.
  const elseBranch = zapAuthRoutes.slice(
    zapAuthRoutes.indexOf('Cannot proceed — there is no session'),
    zapAuthRoutes.indexOf('Cannot proceed — there is no session') + 1200
  );
  assert.ok(elseBranch.length > 100, 'could not locate the refusal branch');
  assert.match(elseBranch, /authConfirmed:\s*'failed'/);
  assert.ok(
    !/authConfirmed:\s*result\.authConfirmed/.test(elseBranch),
    'the refusal branch must not pass the login verdict through'
  );
  assert.match(elseBranch, /NO_SESSION_COOKIES/);
});

// ─────────────────────────────────────────────────────────────────────────────
// F4 — detection must not click indefinitely
// ─────────────────────────────────────────────────────────────────────────────

test('revealing a hidden login panel is bounded', () => {
  assert.match(revealLoginPanel, /const MAX_TOGGLE_CLICKS = \d+/);
  assert.match(revealLoginPanel, /clicks >= MAX_TOGGLE_CLICKS/);
  const cap = Number(revealLoginPanel.match(/const MAX_TOGGLE_CLICKS = (\d+)/)[1]);
  assert.ok(cap > 0 && cap <= 12, `click cap ${cap} is not a sane bound`);
});

// ─────────────────────────────────────────────────────────────────────────────
// F6 — a customer typo must not discard a derived marker
// ─────────────────────────────────────────────────────────────────────────────

test('an unmatched customer marker falls back instead of nulling', () => {
  const block = loginTestService.slice(
    loginTestService.indexOf('A marker the customer gave us'),
    loginTestService.indexOf('const verdict = scoreLoginAttempt')
  );
  assert.ok(block.length > 100, 'could not locate the supplied-marker block');
  assert.ok(
    !/marker:\s*null,\s*alternates:\s*\[\],\s*checkableInBody:\s*false/.test(block),
    'an unmatched supplied marker must not discard the derived one'
  );
  assert.match(block, /using the derived marker/);
});

// ─────────────────────────────────────────────────────────────────────────────
// F7 — retries must not inherit the full navigation budget
// ─────────────────────────────────────────────────────────────────────────────

test('submit retries use a shorter budget than the first attempt', () => {
  const block = loginTestService.slice(
    loginTestService.indexOf('async function submitLogin'),
    loginTestService.indexOf('async function fetchAnonymousText')
  );
  assert.ok(block.length > 100, 'could not locate submitLogin');
  const nav = block.match(/const navTimeout = index === 0 \? (\d+) : (\d+);/);
  assert.ok(nav, 'retries must use their own navigation timeout');
  assert.ok(Number(nav[2]) < Number(nav[1]), 'retry timeout must be shorter than the first attempt');
});

// ─────────────────────────────────────────────────────────────────────────────
// Credentials must never leave the server
// ─────────────────────────────────────────────────────────────────────────────

test('the login recipe is never persisted or returned to the browser', () => {
  // `authState.recipe` holds the customer's password in memory for the life of
  // a manual scan. It must not reach MongoDB or any response body.
  assert.ok(
    !/\$set[^]{0,400}recipe/.test(zapAuthService),
    'the login recipe must never be written to the database'
  );
  assert.ok(
    !/res\.json\([^)]*recipe/.test(zapAuthRoutes),
    'the login recipe must never be sent to the browser'
  );
  // The marker is text from the customer's own page; only its presence is sent.
  assert.match(zapAuthRoutes, /markerFound: Boolean\(result\.marker\)/);
  assert.ok(
    !/res\.json\(\{[^}]*\bmarker:/.test(zapAuthRoutes),
    'the marker itself must not be returned to the browser'
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// The scheduled path must apply the same rules as the interactive one
//
// Two entry points reach the same scan. Anything enforced in the route and not
// in the scheduler is a rule that silently stops applying the moment a customer
// schedules the scan instead of clicking it.
// ─────────────────────────────────────────────────────────────────────────────

test('a scheduled login with no cookies is refused, exactly as the route refuses it', () => {
  // A login that "worked" but issued no cookies leaves nothing for the scan to
  // carry. The route already refuses this; without the same check the scheduler
  // would run the whole scan anonymously and label it authenticated.
  const block = scheduler.slice(
    scheduler.indexOf('let cookies = []'),
    scheduler.indexOf('const { v4: uuidv4 }')
  );
  assert.ok(block.length > 100, 'could not locate the scheduled login block');
  assert.match(block, /cookies\.length === 0/);
  assert.match(block, /loginResult\.authenticated && !noSession/);
});

test('the scheduled path passes the sign-in state through to the scan', () => {
  // Without this the marker re-check and the mid-scan re-login simply never run
  // for a scheduled scan — the feature would look present but be inert.
  assert.match(scheduler, /authState\s*(\/\/.*)?$/m);
  assert.match(scheduler, /marker: loginResult\.marker/);
  assert.match(scheduler, /recipe: \{/);
});

test('the scheduled path derives its outcome from the verdict, not from a marker', () => {
  // A weak marker is returned for change-detection only. Reading its presence as
  // a confirmed sign-in is the bug the confidence gate exists to prevent.
  assert.match(scheduler, /loginOutcome = loginResult\.authConfirmed \|\| 'unconfirmed'/);
  assert.ok(
    !/loginOutcome\s*=\s*loginResult\.marker/.test(scheduler),
    'outcome must not be derived from marker presence'
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// The mid-scan re-login is a third entry point and obeys the same rules
//
// This is where the parity blind spot kept biting: rules were enforced where
// they were first written and quietly skipped everywhere else the same work
// happens. Three places call testLogin; all three must agree.
// ─────────────────────────────────────────────────────────────────────────────

test('a re-login never feeds a weak marker back in as proof', () => {
  // `expectedMarker` is the human-vouched path — testLogin treats whatever
  // arrives there as high confidence. Passing a weak auto-derived marker would
  // promote it to proof on the retry, confirming a sign-in on evidence that was
  // explicitly not good enough the first time.
  assert.match(
    zapAuthService,
    /expectedMarker:\s*authState\.markerConfidence === 'high' \? authState\.marker : null/
  );
});

test('a re-login is only a repair when the sign-in could be confirmed', () => {
  // Getting a fresh session back is necessary but not sufficient. Reporting an
  // unverified re-login as repaired would let the report assert signed-in
  // coverage it cannot stand behind.
  assert.match(zapAuthService, /repair\.ok && repair\.confirmed/);
  assert.match(zapAuthService, /!repair\.ok \|\| !repair\.confirmed/);
  assert.match(zapAuthService, /relogin_unconfirmed/);
});

test('every entry point that logs in also requires a usable session', () => {
  // The gap that started this: the route refused a cookie-less login, the
  // scheduler did not, and a scheduled scan would have run anonymously while
  // being labelled authenticated.
  const entryPoints = [
    ['zapAuthRoutes.js', zapAuthRoutes],
    ['schedulerService.js', scheduler],
    ['zapAuthService.js', zapAuthService]
  ];
  for (const [name, source] of entryPoints) {
    assert.ok(
      /cookies\.length === 0|cookies\.length > 0/.test(source),
      `${name} calls testLogin but never checks that a session came back`
    );
  }
});

test('marker confidence reaches every place that stores sign-in state', () => {
  // If any entry point drops it, `reAuthenticate` reads undefined, the
  // high-confidence branch is never taken, and the guard above silently becomes
  // a no-op rather than failing loudly.
  for (const [name, source] of [
    ['loginTestService.js', loginTestService],
    ['zapAuthRoutes.js', zapAuthRoutes],
    ['schedulerService.js', scheduler]
  ]) {
    assert.match(source, /markerConfidence/, `${name} must carry markerConfidence`);
  }
});
