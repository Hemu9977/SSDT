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
stubModule(BACKEND, 'models/ScanResult.js', ScanResult);
stubModule(BACKEND, 'models/ZapAlert.js', ZapAlert);
stubModule(BACKEND, 'services/gridfsService.js', {
  deleteFile: async (id, bucket) => { deletedFiles.push([String(id), bucket]); },
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

function reset() { ScanResult._reset(); ZapAlert._reset(); deletedFiles.length = 0; }

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

test('the hourly job purges artifacts instead of deleting failed scans', () => {
  const job = fs.readFileSync(path.join(BACKEND, 'jobs/cleanupJob.js'), 'utf8');
  const step = job.slice(job.indexOf('// 1. Failed/stopped scans'), job.indexOf('// 2. Clean up orphaned GridFS'));
  assert.match(step, /purgeFailedScanArtifacts/);
  assert.doesNotMatch(step, /cleanupFailedScan\(/, 'the job must not delete failed scan documents');
  assert.match(step, /artifactsPurgedAt: null/, 'already-purged scans are not reprocessed every hour');
});
