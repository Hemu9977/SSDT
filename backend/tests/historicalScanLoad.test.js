'use strict';

/**
 * Opening a scan from Profile → Recent Scans (GET /api/scan/scan/:analysisId).
 *
 * These EXECUTE the real route handler with the model layer and GridFS stubbed.
 * The handler used to download the scan's ZAP detailed-alerts file from GridFS,
 * parse it and inline every occurrence into the response. In production one
 * authenticated scan's file was 287.59 MB: the backend logged "Loaded scan …
 * (status: completed)" within seconds, but the browser then had to download and
 * parse the whole body, so the page sat on its spinner for minutes and opened by
 * itself. ZapReportEnhanced already loads that file on demand from
 * /api/zap/detailed-report/:scanId when an alert is expanded.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const ScanResult = require('../models/ScanResult');
const User = require('../models/User');
const gridfsService = require('../services/gridfsService');
const router = require('../routes/virustotalRoutes');

const handler = (() => {
  const layer = router.stack.find((l) => l.route?.path === '/scan/:analysisId' && l.route.methods.get);
  const stack = layer.route.stack;
  return stack[stack.length - 1].handle; // after `auth`
})();

function call(req) {
  return new Promise((resolve) => {
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { resolve({ status: this.statusCode, body }); return this; },
    };
    handler(req, res);
  });
}

const alerts = [
  { alert: 'SQL Injection', risk: 'High', count: 3 },
  { alert: 'Missing Header', risk: 'Low', count: 1 },
];

function authScan(overrides = {}) {
  const zap = {
    status: 'completed',
    riskCounts: { High: 1, Medium: 0, Low: 1, Informational: 0 },
    alerts,
    totalAlerts: 2,
    reportFiles: [
      { fileId: 'html-1', filename: 'zap_auth_report_zap-auth-1.html' },
      { fileId: 'json-1', filename: 'zap_auth_detailed_alerts_zap-auth-1.json' },
    ],
  };
  return {
    analysisId: 'zap-auth-1',
    userId: 'u1',
    target: 'https://example.test/',
    status: 'completed',
    authScanResult: zap,
    zapResult: zap,
    refinedReport: { summary: 'ok' },
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

let downloads;
let lastQuery;
let stored;
test.beforeEach(() => {
  downloads = [];
  lastQuery = null;
  stored = authScan();
  ScanResult.findOne = async (q) => {
    lastQuery = q;
    return q.analysisId === stored.analysisId && q.userId === stored.userId ? stored : null;
  };
  User.findById = () => ({ select: async () => null }); // → 'critical-high'
  gridfsService.downloadFile = async (fileId, bucket) => {
    downloads.push({ fileId, bucket });
    throw new Error('the historical loader must not download GridFS files for ZAP');
  };
});

test('a completed scan opens without downloading the ZAP detailed-alerts file', async () => {
  const { status, body } = await call({ params: { analysisId: 'zap-auth-1' }, user: { id: 'u1' } });

  assert.equal(status, 200);
  assert.deepEqual(downloads, []);
  assert.equal(body.status, 'completed');
  assert.equal(body.hasZapResult, true);
  assert.equal(body.zapData.detailedAlerts, undefined);
  // The summary alerts the score cards and report list need are still there…
  assert.ok(Array.isArray(body.zapData.alerts) && body.zapData.alerts.length > 0);
  // …and still plan-filtered (no plan → critical-high → no Low findings).
  assert.ok(body.zapData.alerts.every((a) => a.risk !== 'Low'));
  // ZapReportEnhanced needs the file references to fetch the evidence on demand.
  assert.equal(body.analysisId, 'zap-auth-1');
  assert.deepEqual(body.aiReport, { summary: 'ok' });
});

test('the response stays small however large the detailed-alerts file is', async () => {
  // The production file was 287.59 MB; the response must not scale with it.
  // ~2 MB of High findings, which the plan filter would keep.
  const big = Array.from({ length: 2000 }, (_, i) => ({
    alert: `Finding ${i}`, risk: 'High', occurrences: [{ request: 'x'.repeat(500), response: 'y'.repeat(500) }],
  }));
  gridfsService.downloadFile = async (fileId, bucket) => {
    downloads.push({ fileId, bucket });
    return Buffer.from(JSON.stringify(big));
  };
  const { body } = await call({ params: { analysisId: 'zap-auth-1' }, user: { id: 'u1' } });
  assert.ok(JSON.stringify(body).length < 10_000);
});

test('another user cannot open the scan', async () => {
  const { status } = await call({ params: { analysisId: 'zap-auth-1' }, user: { id: 'someone-else' } });
  assert.equal(status, 404);
  assert.deepEqual(lastQuery, { analysisId: 'zap-auth-1', userId: 'someone-else' });
});

test('the on-demand evidence endpoint still serves an authenticated scan', async () => {
  // Hero mounts ZapReportEnhanced with the default /api/zap prefix even for an
  // authenticated scan; that works because zapAuthService copies the result,
  // reportFiles included, into zapResult.
  const { downloadDetailedReport } = require('../services/zapService');
  const raw = [{ alert: 'SQL Injection', risk: 'High', occurrences: [{ request: 'GET /', response: '200' }] }];
  gridfsService.downloadFile = async (fileId, bucket) => {
    downloads.push({ fileId, bucket });
    return Buffer.from(JSON.stringify(raw));
  };
  const { status, body } = await new Promise((resolve) => {
    const res = {
      statusCode: 200,
      setHeader() {},
      status(code) { this.statusCode = code; return this; },
      json(b) { resolve({ status: this.statusCode, body: b }); return this; },
    };
    downloadDetailedReport({ params: { scanId: 'zap-auth-1' }, user: { id: 'u1' } }, res);
  });
  assert.equal(status, 200);
  assert.deepEqual(downloads, [{ fileId: 'json-1', bucket: 'zap_auth_reports' }]);
  assert.equal(body[0].alert, 'SQL Injection');
});

test('the evidence panel gets the first pairs per finding, streamed, never the whole file', async () => {
  // The panel's ?view=evidence request: a 287 MB file must not be parsed whole or
  // sent to the browser, and the plan filter still applies.
  const { downloadDetailedReport } = require('../services/zapService');
  const { _cache } = require('../services/zapDetailedAlerts');
  const { Readable } = require('node:stream');
  _cache.clear();
  const pair = (i) => ({ url: `https://example.test/${i}`, request: { header: 'GET / HTTP/1.1\r\n', body: '' },
    response: { header: 'HTTP/1.1 200 OK\r\n', body: 'y'.repeat(100000) } });
  const raw = [
    { alert: 'SQL Injection', risk: 'High', occurrences: Array.from({ length: 500 }, (_, i) => pair(i)) },
    { alert: 'Missing Header', risk: 'Low', occurrences: [pair(0)] },
  ];
  const streamed = [];
  gridfsService.downloadFileStream = (fileId, bucket) => {
    streamed.push({ fileId, bucket });
    return Readable.from([Buffer.from(JSON.stringify(raw))]);
  };
  const { status, body } = await new Promise((resolve) => {
    const res = {
      statusCode: 200,
      setHeader() {},
      status(code) { this.statusCode = code; return this; },
      json(b) { resolve({ status: this.statusCode, body: b }); return this; },
    };
    downloadDetailedReport({ params: { scanId: 'zap-auth-1' }, query: { view: 'evidence' }, user: { id: 'u1' } }, res);
  });
  assert.equal(status, 200);
  assert.deepEqual(downloads, [], 'the whole-file download is not used');
  assert.deepEqual(streamed, [{ fileId: 'json-1', bucket: 'zap_auth_reports' }]);
  assert.deepEqual(body.map((a) => a.alert), ['SQL Injection'], 'plan filter: no Low findings');
  assert.equal(body[0].occurrences.length, 10);
  assert.equal(body[0].rawOccurrenceCount, 500);
  assert.ok(body[0].occurrences.every((o) => o.response.bodyTruncated));
  assert.ok(JSON.stringify(body).length < 400_000, 'about 50 MB of evidence comes back as a few hundred KB');
  _cache.clear();
});
