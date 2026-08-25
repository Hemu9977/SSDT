'use strict';

/**
 * Every named import must actually be exported.
 *
 * This exists because of a four-month outage nobody noticed. The migration to
 * organisation-level billing deleted `validatePlanLimits` from schedulerService
 * — definition and export — but left two `require`s of it in scheduleRoutes.
 * The import resolved to `undefined`, calling it threw a TypeError, and
 * POST /api/schedules answered 500 from April until this audit. Creating a
 * scheduled scan was impossible the entire time.
 *
 * Nothing caught it: it is not a syntax error, the file loads fine, and no test
 * touched that route. A census does catch it, cheaply, forever.
 *
 * Run with: node --test backend/tests/moduleContracts.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SKIP_DIRS = new Set(['node_modules', '.git', 'tests', 'coverage', 'build']);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), out);
    } else if (entry.name.endsWith('.js')) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/**
 * What a module exports, read statically. Deliberately not `require()` — loading
 * a module runs it, and these open database handles and timers.
 */
function exportedNames(file) {
  let src;
  try {
    src = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }

  const names = new Set();

  // module.exports = { a, b, c: d, async e() {} }
  const block = src.match(/module\.exports\s*=\s*\{([\s\S]*?)\n\};/);
  if (block) {
    // Strip trailing line comments first: `runUrlScan  // for combined scans`
    // is a perfectly ordinary export and must not be missed.
    const body = block[1].replace(/\/\/.*$/gm, '');
    for (const m of body.matchAll(/^\s*(?:async\s+)?(\w+)\s*[,:(]/gm)) names.add(m[1]);
    for (const m of body.matchAll(/^\s*(\w+)\s*$/gm)) names.add(m[1]);
  }

  // module.exports = someIdentifier   → treat as opaque, cannot verify members
  if (/module\.exports\s*=\s*\w+\s*;/.test(src) && !block) return null;

  // exports.foo = ... / module.exports.foo = ...
  for (const m of src.matchAll(/(?:module\.)?exports\.(\w+)\s*=/g)) names.add(m[1]);

  return names.size > 0 ? names : null;
}

test('every named import from a local module is actually exported by it', () => {
  const failures = [];

  for (const file of walk(ROOT)) {
    // Comments document imports too ("const { addScanJob } = require(...)" in a
    // usage example). Only real code counts.
    const src = fs.readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');

    // const { a, b } = require('./x')  — local paths only; node_modules are not ours.
    const re = /const\s*\{([^}]+)\}\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      const names = m[1]
        .split(',')
        .map(s => s.trim().split(':')[0].trim())
        .filter(n => /^\w+$/.test(n));

      let target = path.resolve(path.dirname(file), m[2]);
      if (!fs.existsSync(target)) target += '.js';
      if (!fs.existsSync(target)) {
        failures.push(`${path.relative(ROOT, file)} requires missing module ${m[2]}`);
        continue;
      }

      const exported = exportedNames(target);
      if (exported === null) continue; // Shape we cannot read statically; skip rather than guess.

      for (const name of names) {
        if (!exported.has(name)) {
          failures.push(
            `${path.relative(ROOT, file)} imports { ${name} } from ${m[2]}, which does not export it`
          );
        }
      }
    }
  }

  assert.deepEqual(failures, [], `broken imports resolve to undefined and throw only when called:\n  ${failures.join('\n  ')}`);
});

test('the specific import that was broken for four months stays fixed', () => {
  const scheduler = require('../services/schedulerService');
  assert.equal(
    typeof scheduler.validatePlanLimits,
    'function',
    'scheduleRoutes imports this; without it POST /api/schedules answers 500'
  );
});
