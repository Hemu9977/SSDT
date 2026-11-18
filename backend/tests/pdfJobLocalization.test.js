'use strict';

/**
 * PDF jobs when localization cannot complete (POST /api/scan/pdf-job + polling).
 *
 * These EXECUTE the real route handlers and the real pdfService / localization
 * engine; Redis, GridFS, the model layer and Gemini are stubbed. They pin that a
 * report whose prose could not be fully localized:
 *   - never reaches GridFS and never marks the job completed;
 *   - fails the job with errorCode REPORT_LOCALIZATION_INCOMPLETE, or
 *     REPORT_TRANSLATION_UNAVAILABLE when the service is down (503 on poll);
 *   - is retried as a NEW job that reuses every translation already finished;
 * and that a finished report built by different report code (an older deploy) is
 * never handed out as the newly requested one.
 *
 * Run with: node --test backend/tests/pdfJobLocalization.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Readable } = require('node:stream');

const BACKEND = path.join(__dirname, '..');
const stubModule = (mod, exports) => {
  const file = path.join(BACKEND, mod);
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};

const { memoryTranslationModel, fakeJapanese } = require('./support/localizationStubs');
const translationModel = memoryTranslationModel();
stubModule('models/ReportTranslation.js', translationModel);

// Gemini: `failWhen(text)` decides which units fail, with `failCategory`
// (invalid_json: a content failure, split and retried; transient: the service is down).
const gemini = { sent: [], failWhen: () => false, failCategory: 'invalid_json' };
stubModule('services/geminiService.js', {
  translateReportUnits: async (units, lang) => {
    gemini.sent.push(...units.map(u => u.text));
    if (units.some(u => gemini.failWhen(u.text))) {
      throw Object.assign(new Error('report translation failed'), { category: gemini.failCategory });
    }
    return { translations: new Map(units.map(u => [u.id, lang === 'ja' ? fakeJapanese(u.text) : u.text])) };
  },
  translateText: async (texts) => texts,
  formatAiAnalysisForPdf: async () => null,
});

// Redis: an in-memory publisher (patched before the routes destructure it).
const redisData = new Map();
const redis = require('../config/redis');
redis.getPublisher = () => ({
  get: async (k) => (redisData.has(k) ? redisData.get(k) : null),
  set: async (k, v) => { redisData.set(k, v); return 'OK'; },
  del: async (k) => { redisData.delete(k); return 1; },
});
redis.executeWithRetry = (fn) => fn();

for (const k of ['log', 'warn', 'error']) console[k] = () => {};

const ScanResult = require('../models/ScanResult');
const User = require('../models/User');
const gridfsService = require('../services/gridfsService');
const router = require('../routes/virustotalRoutes');
const { reportVersion } = require('../services/pdfService');
const { shouldReuseJob, resolvePdfJobResponse } = require('../services/pdfJobStore');
const { _cache: alertsCache } = require('../services/zapDetailedAlerts');
const fixture = require('./fixtures/zapAlerts/stgEbx8.en.json');

const handlerFor = (method, p) => {
  const layer = router.stack.find(l => l.route?.path === p && l.route.methods[method]);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle; // after `auth`
};
const startJob = handlerFor('post', '/pdf-job');
const pollJob = handlerFor('get', '/pdf-job/:jobId');

function call(handler, req) {
  return new Promise((resolve) => {
    const res = {
      statusCode: 200, headers: {},
      status(c) { this.statusCode = c; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      json(body) { resolve({ status: this.statusCode, body }); return this; },
      send(body) { resolve({ status: this.statusCode, body }); return this; },
      end() { resolve({ status: this.statusCode }); return this; },
    };
    handler(req, res);
  });
}

const scan = {
  analysisId: 'zap-auth-1794152897672-jobtest', userId: 'u1', target: 'https://stg.example.jp/', status: 'completed',
  createdAt: new Date('2026-11-08T15:48:00Z'),
  observatoryResult: { grade: 'B', score: 70, tests_passed: 8, tests_failed: 2 },
  zapResult: { status: 'completed', authMethod: 'basic', riskCounts: { High: 1, Medium: 1, Low: 1, Informational: 5 },
    reportFiles: [{ filename: 'zap_auth_detailed_alerts_jobtest.json', fileId: 'file-job' }] },
  authScanResult: { status: 'completed', authMethod: 'basic' },
};
// The scanner's standard text is answered by its own Japanese catalog; this alert
// type is unknown to it, so its prose always needs the translation model. High: the
// test user has no plan, so the report shows High findings only.
const CUSTOM = { alert: 'Custom Header Reflection Detected', pluginId: '99999', risk: 'High', confidence: 'Medium',
  description: 'The application reflects a custom request header in the response body.',
  solution: 'Do not reflect request headers in responses.', reference: 'https://example.org/guidance', cweid: '79', wascid: '8' };
const alertsFile = [...fixture, CUSTOM].map(a => ({ ...a, totalOccurrences: 1, occurrences: [{ url: 'https://stg.example.jp/', method: 'GET',
  request: { header: 'GET https://stg.example.jp/ HTTP/1.1\r\n\r\n', body: '' }, response: { header: 'HTTP/1.1 200 OK\r\n\r\n', body: 'ok' } }] }));

let uploads;
test.beforeEach(() => {
  uploads = [];
  gemini.sent = [];
  gemini.failWhen = () => false;
  gemini.failCategory = 'invalid_json';
  redisData.clear();
  translationModel.rows.clear();
  alertsCache.clear();
  ScanResult.findOne = async (q) => (q.analysisId === scan.analysisId ? JSON.parse(JSON.stringify(scan)) : null);
  ScanResult.find = () => { const c = { sort: () => c, limit: () => c, select: () => c, populate: () => c, lean: async () => [] }; return c; };
  User.findById = () => ({ select: async () => null });
  gridfsService.downloadFileStream = () => Readable.from([Buffer.from(JSON.stringify(alertsFile))]);
  gridfsService.uploadFile = async (buffer, filename, meta) => { uploads.push({ bytes: buffer.length, meta }); return `pdf-${uploads.length}`; };
  gridfsService.fileExists = async () => true;
  gridfsService.downloadFile = async () => Buffer.from('%PDF-1.3 stored');
});

async function waitForJob(jobId) {
  for (let i = 0; i < 2400; i++) {
    const meta = JSON.parse(redisData.get(`pdf:job:${jobId}`) || 'null');
    if (meta && (meta.status === 'failed' || meta.status === 'completed')) return meta;
    await new Promise(r => setTimeout(r, 25));
  }
  throw new Error('job did not finish');
}

const req = (lang) => ({ body: { analysisId: scan.analysisId, lang }, user: { id: 'u1' } });

test('localization failure: job failed with the code, nothing stored in GridFS, poll answers 503 with the code', async () => {
  gemini.failWhen = () => true; // every reply unusable (invalid JSON): the content cannot be localized
  const started = await call(startJob, req('ja'));
  assert.equal(started.status, 200);
  const meta = await waitForJob(started.body.jobId);
  assert.equal(meta.status, 'failed');
  assert.equal(meta.errorCode, 'REPORT_LOCALIZATION_INCOMPLETE');
  assert.equal(meta.bufferFileId, undefined);
  assert.deepEqual(uploads, [], 'a partial or mixed-language PDF reached GridFS');

  const polled = await call(pollJob, { params: { jobId: started.body.jobId }, user: { id: 'u1' } });
  assert.equal(polled.status, 503);
  assert.equal(polled.body.errorCode, 'REPORT_LOCALIZATION_INCOMPLETE');
});

test('retry after a partial failure: a new job, only the missing units are translated, then it completes', async () => {
  // First attempt: invalid JSON for any request carrying the custom alert's
  // description; everything else succeeds after splitting.
  gemini.failCategory = 'invalid_json';
  gemini.failWhen = (text) => /reflects a custom request header/.test(text);
  const first = await call(startJob, req('ja'));
  const failed = await waitForJob(first.body.jobId);
  assert.equal(failed.errorCode, 'REPORT_LOCALIZATION_INCOMPLETE');
  const storedAfterFirst = translationModel.rows.size;
  assert.ok(storedAfterFirst > 0, 'completed translations were stored before the job failed');

  gemini.failWhen = () => false;
  gemini.sent = [];
  alertsCache.clear();
  const second = await call(startJob, req('ja'));
  assert.notEqual(second.body.jobId, first.body.jobId, 'a failed job is never reused');
  const done = await waitForJob(second.body.jobId);
  assert.equal(done.status, 'completed');
  assert.equal(done.reportVersion, reportVersion());
  assert.equal(uploads.length, 1);
  assert.ok(gemini.sent.length > 0 && gemini.sent.every(t => /reflects a custom request header/.test(t)),
    'the retry re-sent only what was missing');
});

test('translation service unavailable: job fails with REPORT_TRANSLATION_UNAVAILABLE, nothing stored, poll answers 503', async () => {
  gemini.failCategory = 'transient';
  gemini.failWhen = () => true;
  const started = await call(startJob, req('ja'));
  const meta = await waitForJob(started.body.jobId);
  assert.equal(meta.status, 'failed');
  assert.equal(meta.errorCode, 'REPORT_TRANSLATION_UNAVAILABLE');
  assert.deepEqual(uploads, [], 'no PDF reached GridFS');
  const polled = await call(pollJob, { params: { jobId: started.body.jobId }, user: { id: 'u1' } });
  assert.equal(polled.status, 503);
  assert.equal(polled.body.errorCode, 'REPORT_TRANSLATION_UNAVAILABLE');
  // English is unaffected by the outage.
  const en = await call(startJob, req('en'));
  assert.equal((await waitForJob(en.body.jobId)).status, 'completed');
});

test('repeated and concurrent requests: EN and JA jobs for one scan run side by side; a repeat reuses the finished job', async () => {
  const [ja, en] = await Promise.all([call(startJob, req('ja')), call(startJob, req('en'))]);
  assert.notEqual(ja.body.jobId, en.body.jobId);
  const [jaMeta, enMeta] = await Promise.all([waitForJob(ja.body.jobId), waitForJob(en.body.jobId)]);
  assert.equal(jaMeta.status, 'completed');
  assert.equal(enMeta.status, 'completed');
  assert.equal(uploads.length, 2);
  assert.notEqual(jaMeta.bufferFileId, enMeta.bufferFileId);
  const again = await call(startJob, req('ja'));
  assert.equal(again.body.jobId, ja.body.jobId, 'the finished JA report is reused, not regenerated');
});

test('a completed report from older report code is not reused; one from this code is', async () => {
  const oldJob = 'old-job';
  redisData.set(`pdf:active:${scan.analysisId}:ja`, oldJob);
  redisData.set(`pdf:job:${oldJob}`, JSON.stringify({ jobId: oldJob, status: 'completed', userId: 'u1', bufferFileId: 'old-file',
    reportVersion: 'r1-previousdeploy', createdAt: Date.now(), lastUpdated: Date.now() }));
  const fresh = await call(startJob, req('ja'));
  assert.notEqual(fresh.body.jobId, oldJob, 'an old-version report was handed out as new');
  await waitForJob(fresh.body.jobId);

  const again = await call(startJob, req('ja'));
  assert.equal(again.body.jobId, fresh.body.jobId, 'a finished report from this version is reused');
});

test('shouldReuseJob / resolvePdfJobResponse: version-aware reuse, failed jobs never reused, 503 for the code', () => {
  const v = 'r2-abc';
  assert.equal(shouldReuseJob({ status: 'completed', reportVersion: v }, true, v), true);
  assert.equal(shouldReuseJob({ status: 'completed', reportVersion: 'r1-old' }, true, v), false);
  assert.equal(shouldReuseJob({ status: 'completed' }, true, v), false, 'jobs recorded before versions existed');
  assert.equal(shouldReuseJob({ status: 'processing', reportVersion: 'r1-old' }, false, v), false);
  assert.equal(shouldReuseJob({ status: 'failed', reportVersion: v }, false, v), false);
  assert.equal(shouldReuseJob({ status: 'completed', reportVersion: v }, false, v), false, 'file gone');
  for (const code of ['REPORT_LOCALIZATION_INCOMPLETE', 'REPORT_TRANSLATION_UNAVAILABLE']) {
    const r = resolvePdfJobResponse({ status: 'failed', errorCode: code, lastUpdated: Date.now() }, false);
    assert.equal(r.code, 503);
    assert.equal(r.body.errorCode, code);
  }
});
