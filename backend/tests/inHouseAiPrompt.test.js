'use strict';

/**
 * The AI report for a scan whose performance / header-grade / page-analysis
 * results came from the in-house fallbacks (services/inHouse/), i.e. a target
 * that only admits Fortexa's egress IP.
 *
 * Gemini never contacts the target: the call is a plain generateContent with a
 * text prompt (no tools, URL context or grounding). So the target's IP allowlist
 * cannot affect it — what matters is that the fallback results feed the prompt
 * like the external ones did, and that the extra fields they carry
 * (`diagnosticSource`, `fallbackReason`, the screenshot path, `page.url`, ...)
 * never put the client's identity in front of the LLM.
 *
 * Runs the real sanitizer and refineReport and captures the exact HTTP request
 * the Gemini SDK sends. Its own file: the SDK client is built when
 * geminiService loads, so the key and fetch stub must be in place first.
 *
 * Run with: node --test backend/tests/
 */

process.env.GEMINI_API_KEY = 'AIza-test-capture-only';
const sent = [];
globalThis.fetch = async (url, init) => {
  sent.push({ url: String(url), body: String(init?.body || '') });
  const body = JSON.stringify({ candidates: [{ content: { role: 'model', parts: [{ text: '## Security report\nOK' }] }, finishReason: 'STOP' }] });
  return new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } });
};

const test = require('node:test');
const assert = require('node:assert/strict');

const { sanitizeScanForLLM } = require('../services/geminiSanitizer');
const { refineReport } = require('../services/geminiService');
const { _toPsiShape } = require('../services/inHouse/lighthouseAudit');

const HOST = 'secret-client.example.co.jp';
const TARGET = `https://${HOST}/members/login`;
const TOKEN = 'a'.repeat(64);

function fallbackScan() {
  return {
    target: TARGET,
    analysisId: 'scan-123',
    pagespeedResult: Object.assign(_toPsiShape({
      lighthouseVersion: '13.6.0', fetchTime: '2026-11-05T00:00:00.000Z', configSettings: { formFactor: 'desktop' },
      categories: { performance: { score: 0.81 }, accessibility: { score: 0.9 }, 'best-practices': { score: 0.96 }, seo: { score: 0.85 } },
    }), { diagnosticSource: 'in-house', fallbackReason: `PageSpeed API error: 400 - Lighthouse returned error: ERRORED_DOCUMENT_REQUEST (${TARGET})` }),
    observatoryResult: {
      grade: 'C', score: 50, tests_passed: 8, tests_failed: 4, tests_quantity: 12, status_code: 200, error: null,
      diagnosticSource: 'in-house', fallbackReason: 'http_403',
    },
    urlscanResult: {
      uuid: 'u1', url: TARGET, task: { time: '2026-11-05T00:00:00.000Z', url: TARGET },
      page: { url: TARGET, domain: HOST, ip: '203.0.113.7', country: 'JP', server: 'nginx', tlsIssuer: 'R11', tlsValidDays: 90, status: 200 },
      stats: { uniqIPs: 3, uniqCountries: 1, dataLength: 1000, requests: 40 },
      lists: { ips: ['203.0.113.7'], countries: ['JP'], domains: [HOST], urls: [TARGET] },
      verdicts: { overall: { score: 0, malicious: false }, urlscan: { score: 0 }, engines: { malicious: 0 }, community: { score: 0 } },
      screenshot: `/api/scan/screenshot/${TOKEN}.jpg`,
      diagnosticSource: 'in-house', fallbackReason: `timeout for ${TARGET}`,
    },
  };
}

test('fallback results reach the AI prompt like external ones, without the client identity', async () => {
  sent.length = 0;
  // Same derivation as geminiCompletionService.js before it calls refineReport.
  const llmSafeScan = sanitizeScanForLLM(fallbackScan());
  const psiReport = llmSafeScan.pagespeedResult?.error ? null : llmSafeScan.pagespeedResult;
  const obsReport = llmSafeScan.observatoryResult?.error ? null : llmSafeScan.observatoryResult;
  const urlscanReport = llmSafeScan.urlscanResult?.error ? null : llmSafeScan.urlscanResult;
  const report = await refineReport(null, psiReport, obsReport, llmSafeScan.target, null, urlscanReport, null);

  const calls = sent.filter((s) => s.url.includes('generativelanguage') || s.url.includes('aiplatform'));
  assert.equal(calls.length, 1, 'one Gemini request; nothing else is fetched');
  assert.ok(report, 'a report is produced');
  const prompt = calls[0].body;

  // The data is there…
  for (const expected of ['Performance Score: 81/100', 'Security Grade: C', 'Tests Passed: 8', 'Malicious Verdict', 'Server: nginx', 'Total Requests: 40']) {
    assert.ok(prompt.includes(expected), `prompt includes "${expected}"`);
  }
  // …the client is not.
  for (const secret of [HOST, '/members/login', '203.0.113.7', TOKEN, 'in-house', 'ERRORED_DOCUMENT_REQUEST', 'http_403']) {
    assert.equal(prompt.includes(secret), false, `prompt must not contain "${secret}"`);
  }
});
