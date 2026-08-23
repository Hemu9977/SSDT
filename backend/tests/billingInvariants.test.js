'use strict';

/**
 * Quota and billing tests.
 *
 * These EXECUTE the real planService functions against a stubbed model layer —
 * no database, no scanners, no server. They exist because every defect they
 * cover shipped and went unnoticed: a scan billed twice, a scan never billed at
 * all, and concurrent scans collectively exceeding a paid plan. All three are
 * invisible to a static check and to any test that only reads source text.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BACKEND = path.join(__dirname, '..');

// ─── Stub the model layer before planService requires it ─────────────────────
const state = {
  scan: null,          // the single ScanResult document under test
  org: null,           // the Organization document under test
  user: null,
  consumeCalls: 0,     // how many times the org was actually charged
  claimAttempts: 0,    // how many callers reached the atomic claim
  inFlight: [],        // other ScanResults for the countDocuments rank query
};

/**
 * Stand-in for ScanResult.findOneAndUpdate on `{ quotaConsumed: false }`.
 * Mongo applies a single-document update atomically, so exactly one concurrent
 * caller can observe the un-consumed document. Node is single-threaded between
 * awaits, so a synchronous test-and-set models that faithfully.
 */
function claimQuota(filter) {
  state.claimAttempts++;
  const s = state.scan;
  if (!s || s.analysisId !== filter.analysisId) return null;
  if (filter.quotaConsumed === false && s.quotaConsumed !== false) return null;
  const before = { ...s };
  s.quotaConsumed = true;
  return before;
}

require.cache[path.join(BACKEND, 'models/ScanResult.js')] = {
  id: 'sr', filename: 'sr', loaded: true,
  exports: {
    findOne: async (q) => {
      if (q.analysisId && state.scan && state.scan.analysisId === q.analysisId) return state.scan;
      return null;
    },
    findOneAndUpdate: async (filter, update) => {
      if (Object.prototype.hasOwnProperty.call(filter, 'quotaConsumed')) return claimQuota(filter);
      Object.assign(state.scan, update.$set || {});
      return state.scan;
    },
    updateOne: async (filter, update) => {
      if (state.scan && state.scan.analysisId === filter.analysisId) {
        Object.assign(state.scan, update.$set || {});
      }
      return { modifiedCount: 1 };
    },
    countDocuments: async (q) => state.inFlight.filter((s) =>
      String(s.organizationId) === String(q.organizationId) &&
      q.status.$in.includes(s.status) &&
      s._id < q._id.$lt
    ).length,
  },
};

require.cache[path.join(BACKEND, 'models/Organization.js')] = {
  id: 'org', filename: 'org', loaded: true,
  exports: {
    findById: async () => state.org,
    updateOne: async () => ({ modifiedCount: 1 }),
    findOneAndUpdate: async (filter, update) => {
      // Only the subscription path is exercised here; it is the one with a
      // capacity predicate, and the credit path has its own $elemMatch guard.
      if (filter.scansUsed && state.org.scansUsed >= filter.scansUsed.$lt) return null;
      state.consumeCalls++;
      state.org.scansUsed += (update.$inc && update.$inc.scansUsed) || 0;
      return state.org;
    },
  },
};

require.cache[path.join(BACKEND, 'models/User.js')] = {
  id: 'usr', filename: 'usr', loaded: true,
  exports: { findById: async () => state.user },
};

const planService = require(path.join(BACKEND, 'services/planService.js'));
const { finalizeSuccessfulScan, claimScanSlot, availableCapacity } = planService;

function reset({ scansUsed = 0, scanLimit = 3, credits = [] } = {}) {
  state.consumeCalls = 0;
  state.claimAttempts = 0;
  state.inFlight = [];
  state.org = {
    _id: 'org-1',
    subscriptionStatus: 'active',
    billingCycle: 'monthly',
    planType: 'light',
    scanLimit,
    scansUsed,
    targetsUsed: 0,
    targetScanCounts: new Map(),
    scanCredits: credits,
    oneTimeRemainingScans: 0,
    lastScanReset: new Date(),
  };
  state.user = {
    _id: 'user-1',
    organizationId: 'org-1',
    getAccountLimits: () => ({ scansPerTarget: null, targetsPerMonth: 3 }),
  };
  state.scan = {
    _id: 'aaa',
    analysisId: 'scan-1',
    target: 'https://example.com',
    userId: 'user-1',
    organizationId: 'org-1',
    status: 'completed',
    quotaConsumed: false,
  };
}

const future = () => new Date(Date.now() + 86400000);
const past = () => new Date(Date.now() - 86400000);

// ─── finalizeSuccessfulScan: charge exactly once ─────────────────────────────

test('finalizeSuccessfulScan charges the org once', async () => {
  reset();
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.consumeCalls, 1);
  assert.equal(state.scan.quotaConsumed, true);
  assert.equal(state.org.scansUsed, 1);
});

test('two concurrent finalize calls charge exactly once', async () => {
  reset();
  // Several components can reach finalize for the same scan. Before the atomic
  // claim, both passed a plain `if (scan.quotaConsumed) return` read and both
  // charged the customer for one scan.
  await Promise.all([
    finalizeSuccessfulScan('scan-1'),
    finalizeSuccessfulScan('scan-1'),
  ]);
  assert.equal(state.consumeCalls, 1, 'org must be charged exactly once');
  assert.equal(state.org.scansUsed, 1);
});

test('five concurrent finalize calls still charge exactly once', async () => {
  reset();
  await Promise.all(Array.from({ length: 5 }, () => finalizeSuccessfulScan('scan-1')));
  assert.equal(state.consumeCalls, 1);
});

test('a scan already marked consumed is not charged again', async () => {
  reset();
  state.scan.quotaConsumed = true;
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.consumeCalls, 0);
});

test('the claim is released when the charge cannot be taken', async () => {
  // Allowance already exhausted: consumeScan declines. Leaving quotaConsumed set
  // would deliver the scan free AND hide the fact that it was never billed.
  reset({ scansUsed: 3, scanLimit: 3 });
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.consumeCalls, 0);
  assert.equal(state.scan.quotaConsumed, false, 'claim must be given back so a retry can charge');
});

test('records which pool paid for the scan', async () => {
  reset();
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.scan.quotaSource, 'subscription');
});

// ─── finalizeSuccessfulScan: what must never be billed ───────────────────────

for (const status of ['combining', 'pending', 'queued', 'failed', 'cancelled', 'stopped']) {
  test(`a scan in "${status}" is not billed`, async () => {
    reset();
    state.scan.status = status;
    await finalizeSuccessfulScan('scan-1');
    assert.equal(state.consumeCalls, 0);
    assert.equal(state.scan.quotaConsumed, false);
  });
}

test('a scan whose vulnerability phase failed is not billed', async () => {
  reset();
  state.scan.zapResult = { status: 'failed' };
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.consumeCalls, 0);
});

test('a scan whose authenticated phase failed is not billed', async () => {
  reset();
  state.scan.authScanResult = { status: 'failed' };
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.consumeCalls, 0);
});

test('a completed scan with a FAILED WebCheck is still billed', async () => {
  // geminiCompletionService treats a failed WebCheck as non-fatal: the scan
  // completes and the customer receives the report with that section rendering
  // N/A. Billing used to refuse the charge anyway, so every such scan was
  // delivered for free. Billing follows the completion policy, it does not
  // second-guess it.
  reset();
  state.scan.webCheckResult = { status: 'failed' };
  await finalizeSuccessfulScan('scan-1');
  assert.equal(state.consumeCalls, 1, 'a delivered report must be charged');
  assert.equal(state.scan.quotaConsumed, true);
});

for (const status of ['completed_partial', 'completed_with_errors']) {
  test(`a completed scan with WebCheck "${status}" is billed`, async () => {
    reset();
    state.scan.webCheckResult = { status };
    await finalizeSuccessfulScan('scan-1');
    assert.equal(state.consumeCalls, 1);
  });
}

test('billing eligibility is no stricter than the completion policy', () => {
  // The defect this pins: the two policies lived in different files and drifted.
  // geminiCompletionService fails a scan ONLY on a failed vulnerability phase;
  // finalizeSuccessfulScan must refuse a charge on no more than that.
  const gemini = fs.readFileSync(path.join(BACKEND, 'services/geminiCompletionService.js'), 'utf8');
  const plan = fs.readFileSync(path.join(BACKEND, 'services/planService.js'), 'utf8');

  // Substring checks on the raw source. These exact expressions appear only in
  // code, never in the surrounding prose, so no comment-stripping is needed.
  assert.ok(
    gemini.includes("if (zapStatus === 'failed')"),
    'a failed vulnerability phase must still be fatal to completion'
  );
  assert.ok(
    !gemini.includes("webCheckStatus === 'failed'"),
    'completion must still treat a failed WebCheck as non-fatal'
  );
  assert.ok(
    !plan.includes("scan.webCheckResult.status === 'failed'"),
    'billing must not refuse a charge for a phase the pipeline completes anyway'
  );
});

// ─── claimScanSlot: concurrency cannot exceed the plan ───────────────────────

/** Register N in-flight scans ahead of `scan-1`, then one for `scan-1` itself. */
function withInFlight(count) {
  state.inFlight = [];
  for (let i = 0; i < count; i++) {
    state.inFlight.push({ _id: `a${i}`, organizationId: 'org-1', status: 'combining' });
  }
  state.scan.status = 'queued';
  state.scan._id = 'zzz'; // sorts after every 'a*' id
}

test('claimScanSlot admits a scan when the plan has room', async () => {
  reset({ scansUsed: 0, scanLimit: 3 });
  withInFlight(0);
  assert.equal(await claimScanSlot('org-1', 'scan-1'), true);
});

test('claimScanSlot refuses when in-flight scans already cover the remaining quota', async () => {
  // One slot left, one scan already running: this second one would be free.
  reset({ scansUsed: 2, scanLimit: 3 });
  withInFlight(1);
  assert.equal(await claimScanSlot('org-1', 'scan-1'), false);
});

test('claimScanSlot admits up to capacity and no further', async () => {
  reset({ scansUsed: 0, scanLimit: 3 });
  withInFlight(2);
  assert.equal(await claimScanSlot('org-1', 'scan-1'), true, '3rd of 3 is fine');

  withInFlight(3);
  assert.equal(await claimScanSlot('org-1', 'scan-1'), false, '4th of 3 is not');
});

test('rank ignores scans that already finished', async () => {
  reset({ scansUsed: 2, scanLimit: 3 });
  state.inFlight = [
    { _id: 'a0', organizationId: 'org-1', status: 'completed' },
    { _id: 'a1', organizationId: 'org-1', status: 'failed' },
  ];
  state.scan._id = 'zzz';
  assert.equal(await claimScanSlot('org-1', 'scan-1'), true);
});

test('rank ignores other organizations', async () => {
  reset({ scansUsed: 2, scanLimit: 3 });
  state.inFlight = [{ _id: 'a0', organizationId: 'org-2', status: 'combining' }];
  state.scan._id = 'zzz';
  assert.equal(await claimScanSlot('org-1', 'scan-1'), true);
});

test('concurrent starters get distinct ranks, so exactly capacity survive', async () => {
  // The property that makes this race-free: rank counts only LOWER _ids, so
  // three simultaneous starters with one slot left do not all reject each other.
  reset({ scansUsed: 2, scanLimit: 3 });
  const starters = ['a1', 'a2', 'a3'];
  state.inFlight = starters.map((id) => ({ _id: id, organizationId: 'org-1', status: 'queued' }));

  const verdicts = [];
  for (const id of starters) {
    state.scan._id = id;
    verdicts.push(await claimScanSlot('org-1', 'scan-1'));
  }
  assert.deepEqual(verdicts, [true, false, false], 'exactly one wins the last slot');
});

test('claimScanSlot fails open when the database errors', async () => {
  reset();
  const saved = state.org;
  state.org = null;
  Object.defineProperty(state, 'org', { get() { throw new Error('mongo down'); }, configurable: true });
  const allowed = await claimScanSlot('org-1', 'scan-1');
  delete state.org;
  state.org = saved;
  assert.equal(allowed, true, 'a Mongo blip must not stop every customer scanning');
});

// ─── availableCapacity: credits count toward concurrency ─────────────────────

test('live credits add to capacity', () => {
  reset({ scansUsed: 3, scanLimit: 3, credits: [{ scansRemaining: 2, expiresAt: future() }] });
  assert.equal(availableCapacity(state.org), 2);
});

test('expired credits do not', () => {
  reset({ scansUsed: 3, scanLimit: 3, credits: [{ scansRemaining: 5, expiresAt: past() }] });
  assert.equal(availableCapacity(state.org), 0);
});

test('subscription allowance and credits are additive', () => {
  reset({ scansUsed: 1, scanLimit: 3, credits: [{ scansRemaining: 2, expiresAt: future() }] });
  assert.equal(availableCapacity(state.org), 4);
});

test('an inactive subscription contributes nothing', () => {
  reset({ scansUsed: 0, scanLimit: 3 });
  state.org.subscriptionStatus = 'canceled';
  assert.equal(availableCapacity(state.org), 0);
});

test('a legacy one-time balance counts only when no batches exist', () => {
  reset({ scansUsed: 0, scanLimit: 0 });
  state.org.subscriptionStatus = null;
  state.org.billingCycle = 'onetime';
  state.org.oneTimeRemainingScans = 4;
  assert.equal(availableCapacity(state.org), 4);

  // Once migrated, the batch is authoritative and the scalar is just a mirror —
  // counting both would let the same scan be spent twice.
  state.org.scanCredits = [{ scansRemaining: 1, expiresAt: future() }];
  assert.equal(availableCapacity(state.org), 1);
});

// ─── Census: one billing site ────────────────────────────────────────────────

test('finalizeSuccessfulScan is called from exactly one service', () => {
  // Three call sites used to bill under three different conditions: one worked,
  // one fired while the scan was still "combining" (a silent no-op), and the
  // authenticated status route completed scans without billing at all. A future
  // scanner path re-introducing a second site is what this catches.
  const callers = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'tests') continue;
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name.endsWith('.js')) {
        const src = fs.readFileSync(p, 'utf8')
          .replace(/\/\*[\s\S]*?\*\//g, '')                       // comments explain it
          .replace(/^\s*\/\/.*$/gm, '')                           // without calling it
          .replace(/async function finalizeSuccessfulScan\s*\(/g, ''); // nor does the definition
        if (/finalizeSuccessfulScan\s*\(/.test(src)) {
          callers.push(path.relative(BACKEND, p).replace(/\\/g, '/'));
        }
      }
    }
  };
  walk(BACKEND);

  assert.deepEqual(
    callers.sort(),
    ['services/geminiCompletionService.js'],
    'quota must be charged from the completion service only'
  );
});

test('the scan-start routes take an authoritative slot claim', () => {
  // planCheck reserves nothing, so without this call concurrency defeats the cap.
  for (const f of ['routes/virustotalRoutes.js', 'routes/zapAuthRoutes.js', 'services/schedulerService.js']) {
    const src = fs.readFileSync(path.join(BACKEND, f), 'utf8');
    assert.match(src, /claimScanSlot\s*\(/, `${f} must claim a slot after creating its ScanResult`);
  }
});

test('every scan-creating path stamps organizationId', () => {
  // claimScanSlot counts in-flight scans by organizationId. The field was
  // declared and indexed on the model but written by nothing, so the rank query
  // would silently have matched zero documents and admitted everything.
  for (const f of ['routes/virustotalRoutes.js', 'routes/zapAuthRoutes.js', 'services/schedulerService.js']) {
    const src = fs.readFileSync(path.join(BACKEND, f), 'utf8');
    assert.match(src, /organizationId:/, `${f} must set organizationId on the ScanResult it creates`);
  }
});
