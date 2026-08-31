'use strict';

/**
 * Schedule time invariants.
 *
 * Two production defects motivated this file, both in the scheduled-scan feature and
 * both invisible to every existing test:
 *
 *  1. `POST /api/schedules` returned 500 on every call:
 *
 *       TypeError: Can't set option timeZoneName when dateStyle is used
 *         at Date.toLocaleString (<anonymous>)
 *         at /app/routes/scheduleRoutes.js:186:26
 *
 *     Intl refuses `dateStyle`/`timeStyle` alongside any individual component option.
 *     The throw happened AFTER `await schedule.save()`, inside the same try, so the
 *     handler's catch reported failure for a schedule that was already committed —
 *     users retried and created duplicates. The identical option pair also sat in
 *     `emailService.js` on the scan-completion path, where `handleScanComplete`
 *     swallows it, so completion emails were being lost silently instead.
 *
 *  2. `computeNextRun()` built candidates with `new Date(y, m, d, h, min)`, which
 *     resolves in the *server's* zone, and never read the schedule's `timezone`.
 *     The container sets no TZ, so it ran as UTC: a customer asking for 10:00 was
 *     scanned at 15:30 IST / 19:00 JST.
 *
 * The census below would have caught (1) with no database, SMTP server or ZAP, and
 * the behavioural tests pin (2). Neither needs a running service.
 *
 * Run with: node --test backend/tests/scheduleTimeInvariants.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  isValidTimeZone,
  zonedTimeToUtc,
  zonedDateParts,
  formatInTimeZone
} = require('../utils/timezone');

const repoRoot = path.join(__dirname, '..', '..');
const src = (p) => fs.readFileSync(path.join(repoRoot, p), 'utf8');

// Walk a tree collecting .js/.jsx, skipping dependency and build output.
function collectSources(dir, acc = []) {
  const SKIP = new Set(['node_modules', 'build', 'dist', 'coverage', '.git']);
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectSources(full, acc);
    else if (/\.(js|jsx)$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

// ──────────────────────────────────────────────────────────────────────────────
// Census — the Intl option combination that took schedule creation down
// ──────────────────────────────────────────────────────────────────────────────

// Anything that is NOT one of the seven options Intl permits beside the style
// shorthands. Everything else throws when paired with dateStyle/timeStyle.
const COMPONENT_OPTIONS = [
  'timeZoneName', 'weekday', 'era', 'year', 'month', 'day',
  'hour', 'minute', 'second', 'fractionalSecondDigits', 'dayPeriod'
];

test('no date format pairs dateStyle/timeStyle with a component option', () => {
  const files = [
    ...collectSources(path.join(repoRoot, 'backend')),
    ...collectSources(path.join(repoRoot, 'frontend', 'src'))
    // This file is excluded: the guard test below holds the illegal combination
    // on purpose, to prove the census can still see it.
  ].filter((f) => f !== __filename);

  const offenders = [];

  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    // Each toLocale*/DateTimeFormat call, then the brace-balanced options object.
    const call = /(?:toLocaleString|toLocaleDateString|toLocaleTimeString|Intl\.DateTimeFormat)\s*\(/g;
    let match;
    while ((match = call.exec(text)) !== null) {
      const open = text.indexOf('{', match.index);
      if (open === -1) continue;
      // Bail if that brace belongs to a later statement rather than this call.
      if (text.slice(match.index, open).includes(';')) continue;

      let depth = 0;
      let close = -1;
      for (let i = open; i < text.length; i++) {
        if (text[i] === '{') depth++;
        else if (text[i] === '}') {
          depth--;
          if (depth === 0) { close = i; break; }
        }
      }
      if (close === -1) continue;

      const options = text.slice(open, close + 1);
      const usesStyle = /\b(dateStyle|timeStyle)\s*:/.test(options);
      if (!usesStyle) continue;

      const conflicts = COMPONENT_OPTIONS.filter(
        (opt) => new RegExp(`\\b${opt}\\s*:`).test(options)
      );
      if (conflicts.length > 0) {
        offenders.push(
          `${path.relative(repoRoot, file)}: dateStyle/timeStyle with ${conflicts.join(', ')}`
        );
      }
    }
  }

  assert.deepEqual(
    offenders,
    [],
    'Intl throws TypeError on these combinations - use component options throughout:\n'
      + offenders.join('\n')
  );
});

test('the census actually detects the combination that shipped', () => {
  // Guards the regex above: if it silently stops matching, the census passes
  // vacuously and the next occurrence of this bug ships again.
  const shipped = "{ timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short', timeZoneName: 'short' }";
  assert.ok(/\b(dateStyle|timeStyle)\s*:/.test(shipped));
  assert.ok(COMPONENT_OPTIONS.some((opt) => new RegExp(`\\b${opt}\\s*:`).test(shipped)));

  // And that Node still rejects it, i.e. the invariant is real and not folklore.
  // Only the type is pinned: the wording differs by ICU build - production said
  // "Can't set option timeZoneName when dateStyle is used", other builds say
  // "Invalid option : option".
  assert.throws(
    () => new Date().toLocaleString('en-US', {
      dateStyle: 'medium', timeStyle: 'short', timeZoneName: 'short'
    }),
    TypeError
  );
});

// ──────────────────────────────────────────────────────────────────────────────
// utils/timezone — the wall-clock conversion computeNextRun now depends on
// ──────────────────────────────────────────────────────────────────────────────

test('a wall-clock time resolves against its own zone, not the servers', () => {
  // 10:00 in Tokyo is 01:00Z; 10:00 in Kolkata is 04:30Z. Before the fix both
  // produced whatever 10:00 meant to the container, which was 10:00Z.
  assert.equal(
    zonedTimeToUtc(2026, 8, 15, 10, 0, 'Asia/Tokyo').toISOString(),
    '2026-09-15T01:00:00.000Z'
  );
  assert.equal(
    zonedTimeToUtc(2026, 8, 15, 10, 0, 'Asia/Kolkata').toISOString(),
    '2026-09-15T04:30:00.000Z'
  );
});

test('a zone that observes DST resolves on the correct side of the transition', () => {
  // New York is UTC-4 in September and UTC-5 in January. A single-pass offset
  // correction gets one of these wrong.
  assert.equal(
    zonedTimeToUtc(2026, 8, 15, 10, 0, 'America/New_York').toISOString(),
    '2026-09-15T14:00:00.000Z'
  );
  assert.equal(
    zonedTimeToUtc(2026, 0, 15, 10, 0, 'America/New_York').toISOString(),
    '2026-01-15T15:00:00.000Z'
  );
});

test('midnight is not rendered as hour 24', () => {
  // hour12:false yields '24' for midnight on some ICU builds; unhandled, the
  // offset maths lands a full day out.
  assert.equal(
    zonedTimeToUtc(2026, 5, 1, 0, 0, 'Asia/Tokyo').toISOString(),
    '2026-05-31T15:00:00.000Z'
  );
});

test('an unrecognised zone is refused rather than stored', () => {
  assert.equal(isValidTimeZone('Asia/Tokyo'), true);
  assert.equal(isValidTimeZone('UTC'), true);
  assert.equal(isValidTimeZone('Mars/Olympus'), false);
  assert.equal(isValidTimeZone(''), false);
  assert.equal(isValidTimeZone(null), false);
  assert.equal(isValidTimeZone(undefined), false);
});

test('the calendar date is read in the schedules zone', () => {
  // 2026-09-15T23:30Z is already the 16th in Tokyo. Searching from the server's
  // month near a boundary skips or repeats a day.
  const parts = zonedDateParts(new Date('2026-09-15T23:30:00Z'), 'Asia/Tokyo');
  assert.deepEqual(parts, { year: 2026, month: 8, day: 16 });
});

test('formatting never throws and never returns a raw Invalid Date', () => {
  const at = new Date('2026-08-31T06:57:00Z');
  assert.match(formatInTimeZone(at, 'Asia/Kolkata'), /Aug 31, 2026/);
  // withZoneName:false is what keeps the email from reading "GMT+5:30 IST".
  assert.doesNotMatch(formatInTimeZone(at, 'Asia/Tokyo', { withZoneName: false }), /GMT/);
  // A bad zone must degrade, not throw - this runs after the row is committed.
  assert.doesNotThrow(() => formatInTimeZone(at, 'Mars/Olympus'));
  assert.equal(formatInTimeZone(new Date('nonsense'), 'UTC'), null);
  assert.equal(formatInTimeZone(null, 'UTC'), null);
});

// ──────────────────────────────────────────────────────────────────────────────
// Source shape — the two structural fixes, asserted statically
// ──────────────────────────────────────────────────────────────────────────────

test('computeNextRun builds candidates in the schedules zone', () => {
  const model = src('backend/models/ScheduledScan.js');
  const body = model.slice(model.indexOf('computeNextRun = function'));

  assert.ok(
    body.includes('zonedTimeToUtc('),
    'computeNextRun must convert wall-clock times through utils/timezone'
  );
  assert.doesNotMatch(
    body,
    /new Date\(\s*candidateMonth/,
    'the local-time Date constructor ignored the schedule timezone - do not reintroduce it'
  );
});

test('nothing after the schedule is saved can turn the create into a 500', () => {
  const route = src('backend/routes/scheduleRoutes.js');
  const post = route.slice(0, route.indexOf("router.get('/'"));

  const saveAt = post.indexOf('await schedule.save()');
  const notifyAt = post.indexOf('handleScheduleCreated(');
  const catchAt = post.indexOf('} catch (error) {', saveAt);

  assert.ok(saveAt !== -1 && notifyAt !== -1 && catchAt !== -1);
  assert.ok(
    catchAt < notifyAt,
    'the notification and its time formatting must sit outside the try that wraps the save - '
      + 'a throw there reported failure for a schedule that was already committed'
  );
});

test('schedule routes never return raw server text to the client', () => {
  const route = src('backend/routes/scheduleRoutes.js');
  assert.doesNotMatch(
    route,
    /details:\s*error\.message/,
    'English server-log text must not reach the UI (CLAUDE.md) - send a stable code instead'
  );
});

test('every code the schedule routes emit is translatable', () => {
  const route = src('backend/routes/scheduleRoutes.js');
  const mapping = src('frontend/src/utils/apiErrors.js');
  const en = src('frontend/src/locales/en.js');
  const ja = src('frontend/src/locales/ja.js');

  const codes = new Set(
    [...route.matchAll(/code:\s*'([A-Z_]+)'/g)].map((m) => m[1])
  );
  assert.ok(codes.size > 0, 'expected the schedule routes to emit stable codes');

  for (const code of codes) {
    const row = mapping.match(new RegExp(`\\b${code}:\\s*'([A-Za-z0-9_]+)'`));
    assert.ok(row, `${code} has no row in utils/apiErrors.js`);
    const key = row[1];
    assert.match(en, new RegExp(`\\b${key}:`), `${key} missing from locales/en.js`);
    assert.match(ja, new RegExp(`\\b${key}:`), `${key} missing from locales/ja.js`);
  }
});
