'use strict';

/**
 * Focused tests for the two gemini-masking branch fixes:
 *   1. HTTP header-value sanitization (sanitizeHeadersForLLM / sanitizeScanForLLM)
 *   2. Production leakage guardrail (_guardrailMode / assertNoLeakage)
 *
 * Run with: node --test backend/tests/geminiSanitizer.test.js
 * (or `npm test` from backend/, see package.json)
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  sanitizeScanForLLM,
  sanitizeHeadersForLLM,
  assertNoLeakage,
  _guardrailMode,
  REDACTED,
} = require('../services/geminiSanitizer');

// ─────────────────────────────────────────────────────────────────────────────
// 1. Header-value sanitization
// ─────────────────────────────────────────────────────────────────────────────

test('sanitizeHeadersForLLM: Set-Cookie value is fully redacted', () => {
  const out = sanitizeHeadersForLLM({
    'set-cookie': 'sessionid=abc123; Domain=example.com; Path=/; HttpOnly',
  });
  assert.equal(out['set-cookie'], REDACTED);
});

test('sanitizeHeadersForLLM: Set-Cookie is redacted regardless of header-name casing', () => {
  const out = sanitizeHeadersForLLM({
    'Set-Cookie': 'sid=xyz; Domain=corp-internal.example.com',
  });
  assert.equal(out['Set-Cookie'], REDACTED);
});

test('sanitizeHeadersForLLM: array Set-Cookie (multiple cookies) is fully redacted', () => {
  const out = sanitizeHeadersForLLM({
    'set-cookie': ['a=1; Domain=example.com', 'b=2; Domain=example.com'],
  });
  assert.deepEqual(out['set-cookie'], [REDACTED]);
});

test('sanitizeHeadersForLLM: Location redirect target is fully redacted', () => {
  const out = sanitizeHeadersForLLM({ Location: 'https://example.com/internal/dashboard' });
  assert.equal(out.Location, REDACTED);
});

test('sanitizeHeadersForLLM: Content-Location and Refresh are fully redacted', () => {
  const out = sanitizeHeadersForLLM({
    'content-location': 'https://example.com/page',
    refresh: '5; url=https://example.com/next',
  });
  assert.equal(out['content-location'], REDACTED);
  assert.equal(out.refresh, REDACTED);
});

test('sanitizeHeadersForLLM: CSP domain is scrubbed but directive structure is preserved', () => {
  const out = sanitizeHeadersForLLM({
    'content-security-policy':
      "default-src 'self' https://cdn.example.com; script-src 'self' 'unsafe-inline'; img-src data:;",
  });
  const v = out['content-security-policy'];
  assert.ok(!v.includes('example.com'), `domain should be scrubbed, got: ${v}`);
  assert.ok(v.includes("default-src 'self'"), 'directive keywords must survive');
  assert.ok(v.includes("script-src 'self' 'unsafe-inline'"), 'CSP flags must survive');
  assert.ok(v.includes('img-src data:'), 'data: scheme token must survive');
  assert.ok(v.includes(REDACTED), 'redaction marker must be present where the domain was');
});

test('sanitizeHeadersForLLM: header value containing a bare IPv4 is scrubbed', () => {
  const out = sanitizeHeadersForLLM({ 'x-forwarded-for': '203.0.113.42, 10.0.0.5' });
  assert.ok(!/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(out['x-forwarded-for'].replace(REDACTED, '')),
    `IP should be scrubbed, got: ${out['x-forwarded-for']}`);
});

test('sanitizeHeadersForLLM: header value containing a full URL is scrubbed', () => {
  const out = sanitizeHeadersForLLM({ link: '<https://example.com/style.css>; rel=preload' });
  assert.ok(!out.link.includes('example.com'), `URL should be scrubbed, got: ${out.link}`);
  assert.ok(out.link.includes('rel=preload'), 'non-identifying structure must survive');
});

test('sanitizeHeadersForLLM: version-number-bearing Server header is NOT over-redacted', () => {
  const out = sanitizeHeadersForLLM({ server: 'nginx/1.19.0' });
  assert.equal(out.server, 'nginx/1.19.0');
});

test('sanitizeHeadersForLLM: HSTS / X-Frame-Options values pass through unchanged (no embedded identity)', () => {
  const out = sanitizeHeadersForLLM({
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'x-frame-options': 'SAMEORIGIN',
  });
  assert.equal(out['strict-transport-security'], 'max-age=31536000; includeSubDomains; preload');
  assert.equal(out['x-frame-options'], 'SAMEORIGIN');
});

test('sanitizeHeadersForLLM: header NAMES are always preserved', () => {
  const out = sanitizeHeadersForLLM({
    'content-security-policy': 'default-src https://example.com',
    'set-cookie': 'a=1; Domain=example.com',
  });
  assert.deepEqual(Object.keys(out).sort(), ['content-security-policy', 'set-cookie']);
});

test('sanitizeHeadersForLLM: non-object / null input passes through', () => {
  assert.equal(sanitizeHeadersForLLM(null), null);
  assert.equal(sanitizeHeadersForLLM(undefined), undefined);
});

test('sanitizeHeadersForLLM: non-string values (e.g. an .error flag) pass through untouched', () => {
  const out = sanitizeHeadersForLLM({ error: true, count: 3 });
  assert.equal(out.error, true);
  assert.equal(out.count, 3);
});

// ─────────────────────────────────────────────────────────────────────────────
// 1b. Full data-flow: sanitizeScanForLLM must sanitize headers in both shapes
// ─────────────────────────────────────────────────────────────────────────────

test('sanitizeScanForLLM: sanitizes webCheckResult.fullResults.headers (geminiCompletionService / zapAuthRoutes shape)', () => {
  const scan = {
    target: 'https://example.com',
    webCheckResult: {
      status: 'completed',
      fullResults: {
        headers: {
          'set-cookie': 'sid=1; Domain=example.com',
          'content-security-policy': "default-src 'self' https://example.com",
          server: 'nginx/1.19.0',
        },
        dns: { a: ['203.0.113.10'] },
      },
    },
  };
  const safe = sanitizeScanForLLM(scan);
  assert.equal(safe.webCheckResult.fullResults.headers['set-cookie'], REDACTED);
  assert.ok(!safe.webCheckResult.fullResults.headers['content-security-policy'].includes('example.com'));
  assert.equal(safe.webCheckResult.fullResults.headers.server, 'nginx/1.19.0');
  assert.deepEqual(safe.webCheckResult.fullResults.dns.a, [REDACTED]);
  // original must not be mutated
  assert.equal(scan.webCheckResult.fullResults.headers['set-cookie'], 'sid=1; Domain=example.com');
});

test('sanitizeScanForLLM: sanitizes top-level webCheckResult.headers (scheduler-service shape)', () => {
  const scan = {
    target: 'https://example.com',
    webCheckResult: {
      headers: { location: 'https://example.com/dashboard' },
    },
  };
  const safe = sanitizeScanForLLM(scan);
  assert.equal(safe.webCheckResult.headers.location, REDACTED);
});

test('sanitizeScanForLLM: pre-existing redactions (target, DNS, urlscan, ZAP urls) are unchanged', () => {
  const scan = {
    target: 'https://example.com',
    analysisId: 'abc-123',
    urlscanResult: { page: { domain: 'example.com', ip: '203.0.113.10', country: 'US', server: 'nginx' } },
    zapResult: { alerts: [{ alert: 'XSS', risk: 'High', url: 'https://example.com/login' }] },
  };
  const safe = sanitizeScanForLLM(scan);
  assert.equal(safe.target, REDACTED);
  assert.equal(safe.analysisId, REDACTED);
  assert.equal(safe.urlscanResult.page.domain, REDACTED);
  assert.equal(safe.urlscanResult.page.ip, REDACTED);
  assert.equal(safe.urlscanResult.page.server, 'nginx'); // technology info preserved
  assert.equal(safe.zapResult.alerts[0].url, REDACTED);
  assert.equal(safe.zapResult.alerts[0].alert, 'XSS'); // alert name preserved
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Production leakage guardrail
// ─────────────────────────────────────────────────────────────────────────────

function withEnv(vars, fn) {
  const prev = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  try {
    for (const [k, v] of Object.entries(vars)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    return fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('_guardrailMode: defaults to "warn" in production when unset (the fixed gap)', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: undefined }, () => {
    assert.equal(_guardrailMode(), 'warn');
  });
});

test('_guardrailMode: defaults to "warn" outside production too (dev/test unchanged)', () => {
  withEnv({ NODE_ENV: 'test', GEMINI_STRICT_GUARDRAIL: undefined }, () => {
    assert.equal(_guardrailMode(), 'warn');
  });
  withEnv({ NODE_ENV: undefined, GEMINI_STRICT_GUARDRAIL: undefined }, () => {
    assert.equal(_guardrailMode(), 'warn');
  });
});

test('_guardrailMode: GEMINI_STRICT_GUARDRAIL=true forces "throw" even in production', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    assert.equal(_guardrailMode(), 'throw');
  });
});

test('_guardrailMode: GEMINI_STRICT_GUARDRAIL=false forces "off" even in production', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: 'false' }, () => {
    assert.equal(_guardrailMode(), 'off');
  });
});

test('assertNoLeakage: a clean (REDACTED) prompt never throws or logs, in any mode', () => {
  const cleanPrompt = 'Target: REDACTED\nServer IP: REDACTED\nGrade: A+';
  for (const mode of ['true', 'false', undefined]) {
    withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: mode }, () => {
      const originalError = console.error;
      let logged = false;
      console.error = () => { logged = true; };
      try {
        assert.doesNotThrow(() => assertNoLeakage(cleanPrompt, 'test'));
        assert.equal(logged, false);
      } finally {
        console.error = originalError;
      }
    });
  }
});

test('assertNoLeakage: "off" mode does not detect or log a real leak', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: 'false' }, () => {
    const originalError = console.error;
    let logged = false;
    console.error = () => { logged = true; };
    try {
      assert.doesNotThrow(() => assertNoLeakage('Server IP: 203.0.113.10', 'test'));
      assert.equal(logged, false);
    } finally {
      console.error = originalError;
    }
  });
});

test('assertNoLeakage: default production mode ("warn") detects a leak, logs it, and does NOT block the call', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: undefined }, () => {
    const originalError = console.error;
    let loggedMsg = null;
    console.error = (msg) => { loggedMsg = msg; };
    let generateContentCalled = false;
    try {
      assertNoLeakage('Domain: https://leaky-example.com/internal', 'refineReport');
      generateContentCalled = true; // simulates _generate() proceeding to call Gemini after assertNoLeakage returns
    } finally {
      console.error = originalError;
    }
    assert.ok(loggedMsg, 'a warning must be logged');
    assert.ok(loggedMsg.includes('GEMINI GUARDRAIL'));
    assert.ok(generateContentCalled, 'warn mode must not block the caller from proceeding');
  });
});

test('assertNoLeakage: "throw" mode blocks BEFORE any Gemini call is simulated', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    const originalError = console.error;
    console.error = () => {};
    let generateContentCalled = false;
    try {
      assertNoLeakage('Domain: https://leaky-example.com/internal', 'refineReport');
      generateContentCalled = true; // must never reach here
    } catch (err) {
      assert.ok(err instanceof Error);
    } finally {
      console.error = originalError;
    }
    assert.equal(generateContentCalled, false, 'throw mode must prevent the caller from reaching the Gemini call');
  });
});

test('assertNoLeakage: the leaked value itself is never written into the thrown error message', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    const secretDomain = 'super-secret-client-domain.example';
    try {
      assertNoLeakage(`Site: https://${secretDomain}/dashboard`, 'refineReport');
      assert.fail('expected assertNoLeakage to throw');
    } catch (err) {
      assert.ok(!err.message.includes(secretDomain), `Error message leaked the domain: ${err.message}`);
    }
  });
});

test('assertNoLeakage: the leaked value itself is never written to console.error in "warn" mode', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: undefined }, () => {
    const secretIp = '198.51.100.77';
    const originalError = console.error;
    let loggedMsg = '';
    console.error = (msg) => { loggedMsg = String(msg); };
    try {
      assertNoLeakage(`Server: ${secretIp}`, 'refineReport');
    } finally {
      console.error = originalError;
    }
    assert.ok(!loggedMsg.includes(secretIp), `log line leaked the IP: ${loggedMsg}`);
  });
});

test('assertNoLeakage: a REDACTED IP does not falsely trigger the IP check', () => {
  withEnv({ NODE_ENV: 'production', GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    assert.doesNotThrow(() => assertNoLeakage('Server IP: REDACTED, Country: REDACTED', 'test'));
  });
});
