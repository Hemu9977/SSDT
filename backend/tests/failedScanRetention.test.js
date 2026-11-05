'use strict';

/**
 * L9 — failed and stopped scans stay diagnosable.
 *
 * The hourly cleanup used to delete every failed/stopped scan outright, so a
 * failure vanished within the hour (reproduced locally: deleted seconds after
 * server start). It now purges only the heavy artifacts and keeps a lightweight
 * record until the normal 7-day TTL. These tests execute the real
 * services/cleanupService.js against an in-memory model layer.
 *
 * Run with: node --test backend/tests/failedScanRetention.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeModel, stubModule } = require('./support/fakeMongo');

const BACKEND = path.join(__dirname, '..');

const ScanResult = makeModel('ScanResult');
const ZapAlert = makeModel('ZapAlert');
const deletedFiles = [];
const bucketFiles = {}; // bucket name -> GridFS file documents
stubModule(BACKEND, 'models/ScanResult.js', ScanResult);
stubModule(BACKEND, 'models/ZapAlert.js', ZapAlert);
stubModule(BACKEND, 'services/gridfsService.js', {
  deleteFile: async (id, bucket) => { deletedFiles.push([String(id), bucket]); },
  initialize: (bucket) => ({
    find: (q) => ({
      toArray: async () => (bucketFiles[bucket] || []).filter((f) => f.uploadDate < q.uploadDate.$lt),
    }),
  }),
});

const cleanup = require(path.join(BACKEND, 'services/cleanupService.js'));

function failedScan(over = {}) {
  return ScanResult._insert({
    analysisId: 'scan-1',
    userId: 'user-1',
    target: 'https://broken.example',
    status: 'failed',
    failureReason: 'vulnerability_scan_failed',
    createdAt: new Date(Date.now() - 3600000),
    zapResult: {
      status: 'failed', error: 'spider timed out',
      alerts: new Array(500).fill({ name: 'x' }),
      reportFiles: [{ fileId: 'zap-file-1' }],
    },
    webCheckResult: { status: 'completed', resultsFileId: 'wc-file-1', fullResults: { big: true }, completedScans: 29, totalScans: 29 },
    pagespeedResult: { lighthouse: 'huge' },
    refinedReport: 'long AI text',
    artifactsPurgedAt: null,
    ...over,
  });
}

function reset() {
  ScanResult._reset(); ZapAlert._reset(); deletedFiles.length = 0;
  for (const b of Object.keys(bucketFiles)) delete bucketFiles[b];
}

const DAY = 24 * 3600000;
const gridFile = (id, scanId, ageDays, metaKey = 'scanId') =>
  ({ _id: id, uploadDate: new Date(Date.now() - ageDays * DAY), metadata: { [metaKey]: scanId } });

test('a failed scan keeps its diagnostic record while its heavy artifacts are purged', async () => {
  reset();
  failedScan();
  ZapAlert._insert({ scanId: 'scan-1' }, { scanId: 'scan-1' }, { scanId: 'other' });

  const res = await cleanup.purgeFailedScanArtifacts('scan-1');
  assert.equal(res.success, true);

  const kept = ScanResult._store.find((s) => s.analysisId === 'scan-1');
  assert.ok(kept, 'the scan record must survive');
  assert.deepEqual(
    [kept.status, kept.target, kept.failureReason],
    ['failed', 'https://broken.example', 'vulnerability_scan_failed']
  );
  assert.ok(kept.artifactsPurgedAt instanceof Date);
  assert.deepEqual(kept.zapResult, { status: 'failed', error: 'spider timed out' }, 'only whitelisted ZAP fields remain');
  assert.deepEqual(kept.webCheckResult, { status: 'completed', completedScans: 29, totalScans: 29 });
  assert.equal(kept.pagespeedResult, null);
  assert.equal(kept.refinedReport, null);

  assert.deepEqual(deletedFiles.map((f) => f[0]).sort(), ['wc-file-1', 'zap-file-1']);
  assert.deepEqual(ZapAlert._store.map((a) => a.scanId), ['other'], "only this scan's alerts are deleted");
});

test('purging is idempotent and never touches a scan that did not fail', async () => {
  reset();
  failedScan({ artifactsPurgedAt: new Date() });
  ScanResult._insert({ analysisId: 'ok-1', status: 'completed', zapResult: { alerts: [1, 2] } });

  assert.equal((await cleanup.purgeFailedScanArtifacts('scan-1')).skipped, 'already_purged');
  assert.equal((await cleanup.purgeFailedScanArtifacts('ok-1')).skipped, 'not_failed');
  assert.deepEqual(ScanResult._store.find((s) => s.analysisId === 'ok-1').zapResult, { alerts: [1, 2] });
  assert.equal(deletedFiles.length, 0);
});

test("a failed authenticated scan's reports are deleted from the authenticated bucket", async () => {
  reset();
  // zapAuthService writes the same reportFiles to authScanResult and zapResult.
  const reportFiles = [
    { fileId: 'auth-html-1', filename: 'zap_auth_report_zap-auth-1.html' },
    { fileId: 'auth-json-1', filename: 'zap_auth_detailed_alerts_zap-auth-1.json' },
  ];
  failedScan({
    analysisId: 'zap-auth-1',
    zapResult: { status: 'failed', reportFiles },
    authScanResult: { status: 'failed', reportFiles },
    webCheckResult: { status: 'failed' },
  });

  assert.equal((await cleanup.purgeFailedScanArtifacts('zap-auth-1')).success, true);
  assert.deepEqual(
    deletedFiles.sort(),
    [['auth-html-1', 'zap_auth_reports'], ['auth-json-1', 'zap_auth_reports']],
    'each file once, from the bucket it was written to'
  );
});

test('orphaned authenticated reports are swept exactly like public ones', async () => {
  reset();
  ScanResult._insert({ analysisId: 'live-public', status: 'completed' });
  ScanResult._insert({ analysisId: 'zap-auth-live', status: 'completed' });
  bucketFiles.zap_reports = [
    gridFile('pub-orphan', 'gone-public', 8),
    gridFile('pub-live', 'live-public', 8),
    gridFile('pub-recent', 'gone-public', 1),
  ];
  bucketFiles.zap_auth_reports = [
    gridFile('auth-orphan', 'zap-auth-gone', 8),
    gridFile('auth-live', 'zap-auth-live', 8),
    gridFile('auth-recent', 'zap-auth-gone', 1),
  ];
  bucketFiles.webcheck_results = [gridFile('wc-orphan', 'gone-public', 8, 'analysisId')];

  const res = await cleanup.cleanupOrphanedGridFSFiles();
  assert.equal(res.success, true);
  assert.deepEqual(deletedFiles.sort(), [
    ['auth-orphan', 'zap_auth_reports'],
    ['pub-orphan', 'zap_reports'],
    ['wc-orphan', 'webcheck_results'],
  ], 'only files older than 7 days whose scan record is gone');
  assert.deepEqual(
    [res.stats.zapFilesChecked, res.stats.zapFilesDeleted, res.stats.zapAuthFilesChecked, res.stats.zapAuthFilesDeleted],
    [2, 1, 2, 1]
  );
});

test('every scan-report bucket written to is covered by the orphan sweep', () => {
  // A bucket nobody sweeps grows forever: zap_auth_reports did, reaching 332 MB.
  // pdf_reports is bounded separately (24h, jobs/cleanupJob.js).
  const cleanupSrc = fs.readFileSync(path.join(BACKEND, 'services/cleanupService.js'), 'utf8');
  const constants = Object.fromEntries([...cleanupSrc.matchAll(/^const (\w+_BUCKET) = '([a-z_]+)';/gm)].map((m) => [m[1], m[2]]));
  const sweepBlock = cleanupSrc.slice(cleanupSrc.indexOf('const ORPHAN_SWEEP'), cleanupSrc.indexOf('];', cleanupSrc.indexOf('const ORPHAN_SWEEP')));
  const swept = new Set([...sweepBlock.matchAll(/bucket: (\w+)/g)].map((m) => constants[m[1]]));

  const used = new Set();
  for (const dir of ['services', 'routes', 'workers', 'queues', 'jobs']) {
    const abs = path.join(BACKEND, dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs).filter((n) => n.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(abs, name), 'utf8');
      for (const [, bucket] of src.matchAll(/'((?:zap_auth|zap|webcheck)_(?:reports|results))'/g)) used.add(bucket);
    }
  }

  assert.ok(used.has('zap_auth_reports') && used.has('zap_reports') && used.has('webcheck_results'), 'census found the buckets');
  for (const bucket of used) assert.ok(swept.has(bucket), `${bucket} is written to but never swept for orphans`);
});

test('the hourly job purges artifacts instead of deleting failed scans', () => {
  const job = fs.readFileSync(path.join(BACKEND, 'jobs/cleanupJob.js'), 'utf8');
  const step = job.slice(job.indexOf('// 1. Failed/stopped scans'), job.indexOf('// 2. Clean up orphaned GridFS'));
  assert.match(step, /purgeFailedScanArtifacts/);
  assert.doesNotMatch(step, /cleanupFailedScan\(/, 'the job must not delete failed scan documents');
  assert.match(step, /artifactsPurgedAt: null/, 'already-purged scans are not reprocessed every hour');
});
