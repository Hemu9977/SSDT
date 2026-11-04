'use strict';

/**
 * Streaming read of the ZAP detailed-alerts file (services/zapDetailedAlerts.js).
 *
 * The PDF used to download this file into one Buffer and JSON.parse it. A
 * production scan's file was 287 MB; a PDF and a JSON export parsing it at once
 * took the backend past its 2 GB heap and the load balancer replaced the task
 * mid-PDF (26 Oct 2026), leaving that PDF job to time out. These check that the
 * streaming parser reads exactly what JSON.parse would, whatever the chunking,
 * and that a report keeps only what it draws.
 *
 * Run with: node --test backend/tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { Readable } = require('node:stream');

const gridfsFile = path.join(__dirname, '..', 'services', 'gridfsService.js');
require.cache[gridfsFile] = { id: gridfsFile, filename: gridfsFile, loaded: true, exports: {} };
console.log = () => {};

const {
  createDetailedAlertsParser, readReportAlerts, loadReportAlerts, loadEvidenceAlerts, _cache,
  REPORT_LIMITS, EVIDENCE_LIMITS
} = require('../services/zapDetailedAlerts');

// Deterministic pseudo-random fixtures (mulberry32).
function rng(seed) {
  return () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
// Strings that stress a byte-level JSON scanner: escapes, brackets and quotes in
// text, multi-byte UTF-8, a surrogate pair, line separators, and text that looks
// like the key it is looking for.
const TRICKY = ['a"b', 'c\\d', '日本語のテキスト', '[{]}', ',:', ' ', '😀', '\\"q\\"', '"occurrences": [', '\u0000\u001f'];

function makeAlerts(rand) {
  const pick = () => TRICKY[Math.floor(rand() * TRICKY.length)] + Math.floor(rand() * 1000);
  return Array.from({ length: Math.floor(rand() * 5) }, (_, a) => {
    const alert = { alert: `A${a}${pick()}`, risk: 'High', description: pick(), nested: { occurrences: [1, 2], x: [pick()] } };
    if (rand() > 0.2) {
      alert.occurrences = Array.from({ length: Math.floor(rand() * 20) }, (_, i) => {
        const r = rand();
        if (r < 0.1) return pick();               // primitives, in case one ever appears
        if (r < 0.15) return Math.floor(rand() * 100);
        return {
          url: `https://e.jp/${pick()}`, evidence: pick(), messageId: i,
          ...(rand() > 0.3 ? { request: { header: pick(), body: pick().repeat(Math.floor(rand() * 50)) },
                               response: { header: pick(), body: pick() } } : {})
        };
      });
    }
    alert.after = pick();
    return alert;
  });
}

function parseInChunks(text, size, select = (o) => o) {
  const buf = Buffer.from(text);
  const parser = createDetailedAlertsParser(select);
  for (let i = 0; i < buf.length; i += size) parser.write(buf.subarray(i, i + size));
  return parser.end();
}

test('reads exactly what JSON.parse reads, at every chunk size', () => {
  const rand = rng(42);
  for (let t = 0; t < 300; t++) {
    const data = makeAlerts(rand);
    const text = JSON.stringify(data, null, t % 2 ? 2 : 0);
    const got = parseInChunks(text, [1, 2, 3, 7, 64, 1024, 65536][t % 7]);
    assert.equal(got.length, data.length);
    got.forEach((alert, i) => {
      const { occurrences, occurrenceCount, ...rest } = alert;
      const { occurrences: expected = [], ...expectedRest } = data[i];
      assert.deepEqual(rest, expectedRest);
      assert.deepEqual(occurrences, expected);
      assert.equal(occurrenceCount, expected.length);
    });
  }
});

test('a truncated or non-array file is an error, not a silently short list', () => {
  const text = JSON.stringify([{ alert: 'A', occurrences: [{ url: 'u' }] }]);
  assert.throws(() => parseInChunks(text.slice(0, -3), 5), /ended before/);
  assert.throws(() => parseInChunks('{"alerts": []}', 5), /not a JSON array/);
  assert.deepEqual(parseInChunks('[]', 1), []);
});

const raw = (i, body = 'b') => ({
  url: `https://e.jp/${i}`, request: { header: 'GET / HTTP/1.1\r\n', body: '' },
  response: { header: 'HTTP/1.1 200 OK\r\n', body }
});

test('a report keeps the sample URLs and the first evidence, and counts all of it', async () => {
  const occurrences = [
    ...Array.from({ length: 12 }, (_, i) => ({ url: `https://e.jp/plain${i}` })), // no raw evidence
    ...Array.from({ length: 30 }, (_, i) => raw(i, 'x'.repeat(REPORT_LIMITS.bodyMaxChars * 3)))
  ];
  const text = JSON.stringify([{ alert: 'A', totalOccurrences: 42, occurrences }]);
  const [alert] = await readReportAlerts(Readable.from([Buffer.from(text)]));

  assert.equal(alert.occurrenceCount, 42);
  assert.equal(alert.rawOccurrenceCount, 30);
  // First 10 in file order (the sample URLs), then the first 3 with evidence.
  assert.deepEqual(alert.occurrences.map(o => o.url), [
    ...Array.from({ length: REPORT_LIMITS.sampleUrls }, (_, i) => `https://e.jp/plain${i}`),
    'https://e.jp/0', 'https://e.jp/1', 'https://e.jp/2'
  ]);
  assert.equal(alert.occurrences.filter(o => o.request).length, REPORT_LIMITS.evidence);
  assert.equal(alert.occurrences[10].response.body.length, REPORT_LIMITS.bodyMaxChars, 'bodies trimmed past what the PDF can use');
  assert.equal(alert.occurrences[10].response.bodyTruncated, true);
  assert.equal(alert.occurrences[10].response.header, 'HTTP/1.1 200 OK\r\n');
});

test('an alert without occurrences reads as zero of each', async () => {
  const [a, b] = await readReportAlerts(Readable.from([Buffer.from(JSON.stringify([{ alert: 'A' }, { alert: 'B', occurrences: [] }]))]));
  assert.deepEqual([a.occurrenceCount, a.rawOccurrenceCount, a.occurrences], [0, 0, []]);
  assert.deepEqual([b.occurrenceCount, b.rawOccurrenceCount, b.occurrences], [0, 0, []]);
});

test('concurrent loads of one file share a single read; a failed read is retried next time', async () => {
  _cache.clear();
  const opened = [];
  let fail = true;
  const openStream = (id) => {
    opened.push(id);
    if (fail) return Readable.from([Buffer.from('[{"alert": "A", "occ')]); // truncated
    return Readable.from([Buffer.from(JSON.stringify([{ alert: 'A', occurrences: [raw(1)] }]))]);
  };

  await assert.rejects(loadReportAlerts('f1', 'zap_reports', { openStream }));
  fail = false;
  const [x, y] = await Promise.all([
    loadReportAlerts('f1', 'zap_reports', { openStream }),
    loadReportAlerts('f1', 'zap_reports', { openStream })
  ]);
  assert.equal(x, y);
  assert.equal(x[0].rawOccurrenceCount, 1);
  assert.deepEqual(opened, ['f1', 'f1'], 'one read for the failure, one shared by both later loads');
  _cache.clear();
});

test('the scan page evidence view: first pairs only, no URL sample, counted in full', async () => {
  _cache.clear();
  const occurrences = [{ url: 'https://e.jp/plain' }, ...Array.from({ length: 40 }, (_, i) => raw(i))];
  const openStream = () => Readable.from([Buffer.from(JSON.stringify([{ alert: 'A', occurrences }]))]);
  const [alert] = await loadEvidenceAlerts('f2', 'zap_reports', { openStream });
  assert.equal(alert.occurrences.length, EVIDENCE_LIMITS.evidence);
  assert.ok(alert.occurrences.every(o => o.request), 'only occurrences with evidence');
  assert.equal(alert.rawOccurrenceCount, 40);
  // Report and evidence views of one file are cached separately.
  const [report] = await loadReportAlerts('f2', 'zap_reports', { openStream });
  assert.equal(report.occurrences.length, REPORT_LIMITS.sampleUrls);
  _cache.clear();
});
