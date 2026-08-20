'use strict';

/**
 * Leak-vector regression tests for geminiSanitizer.
 *
 * Every case below was demonstrated to LEAK against the previous
 * implementation before these fixes landed. The original suite passed 27/27
 * while all of this got through, because it never exercised compressed IPv6,
 * email addresses, or single-label internal hostnames — so these are written
 * as explicit regressions rather than folded into the existing file.
 *
 * The over-redaction cases matter just as much: the old IPv6 pattern matched
 * any `h:h:h` sequence and so destroyed clock times and HTTP `Date` values.
 *
 * Run with: node --test backend/tests/geminiSanitizerLeakVectors.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  sanitizeHeadersForLLM,
  sanitizeTextsForLLM,
  sanitizeRefinedReportForLLM,
  assertNoLeakage,
  _guardrailMode,
  REDACTED,
} = require('../services/geminiSanitizer');

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

const scrubHeader = (value) => sanitizeHeadersForLLM({ 'X-Probe': value })['X-Probe'];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Compressed IPv6 — every one of these passed through untouched before
// ─────────────────────────────────────────────────────────────────────────────

const COMPRESSED_IPV6 = [
  '::1',                                    // loopback
  'fe80::1',                                // link-local
  '2001:db8::1',
  'fd00::dead:beef',                        // unique-local
  '2001:db8:85a3::8a2e:370:7334',           // previously mangled to REDACTED::REDACTED
  '::ffff:192.0.2.1',                       // IPv4-mapped
  '2001:db8::',
  'fe80::1%eth0',                           // zone index
];

for (const addr of COMPRESSED_IPV6) {
  test(`IPv6 leak vector: header value "${addr}" is fully redacted`, () => {
    const out = scrubHeader(addr);
    assert.equal(out, REDACTED, `expected full redaction, got "${out}"`);
  });
}

test('IPv6 leak vector: fully expanded form still redacted (no regression)', () => {
  assert.equal(scrubHeader('2001:0db8:0000:0000:0000:0000:0000:0001'), REDACTED);
});

test('IPv6 leak vector: address embedded in prose is redacted, surrounding text kept', () => {
  assert.equal(sanitizeTextsForLLM(['Host fe80::1 is exposed'])[0], `Host ${REDACTED} is exposed`);
});

test('IPv6 leak vector: IPv4-mapped address is not half-eaten by the IPv4 pass', () => {
  // Order regression: with IPv4 scrubbed first this produced "::ffff:REDACTED".
  const out = sanitizeTextsForLLM(['Mapped ::ffff:192.0.2.1 here'])[0];
  assert.equal(out, `Mapped ${REDACTED} here`);
  assert.ok(!out.includes('ffff'), `dangling IPv6 prefix survived: ${out}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Over-redaction guard — the old pattern ate these
// ─────────────────────────────────────────────────────────────────────────────

test('over-redaction: an HTTP Date header value survives intact', () => {
  const value = 'Mon, 01 Jan 2024 10:20:30 GMT';
  assert.equal(scrubHeader(value), value);
});

test('over-redaction: a clock time in prose survives intact', () => {
  assert.equal(sanitizeTextsForLLM(['Scan finished at 12:30:45 today'])[0],
    'Scan finished at 12:30:45 today');
});

test('over-redaction: technology/version info is preserved', () => {
  assert.equal(scrubHeader('nginx/1.19.0'), 'nginx/1.19.0');
  assert.equal(scrubHeader('max-age=31536000; includeSubDomains'),
    'max-age=31536000; includeSubDomains');
  assert.equal(scrubHeader('text/html; charset=utf-8'), 'text/html; charset=utf-8');
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Email addresses — the local part used to survive as "admin@REDACTED"
// ─────────────────────────────────────────────────────────────────────────────

test('email leak vector: whole address is redacted, not just the domain', () => {
  const out = scrubHeader('admin@internal-corp.example.com');
  assert.equal(out, REDACTED);
  assert.ok(!out.includes('admin'), `local part survived: ${out}`);
});

test('email leak vector: address embedded in freeform text is redacted', () => {
  const out = sanitizeTextsForLLM(['Contact ops-lead@corp.example.com for access'])[0];
  assert.ok(!out.includes('ops-lead'), `local part survived: ${out}`);
  assert.ok(!out.includes('corp.example.com'), `domain survived: ${out}`);
});

test('email leak vector: address in a stored refined report is redacted', () => {
  const out = sanitizeRefinedReportForLLM('Reported by admin@corp.example.com in Q1.');
  assert.ok(!out.includes('admin@'), `email survived: ${out}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Single-label internal hostnames via host-bearing headers
// ─────────────────────────────────────────────────────────────────────────────

test('hostname leak vector: Host header carrying a dotless internal name is redacted', () => {
  // BARE_DOMAIN_PATTERN needs a dot, so this can only be caught by treating the
  // whole header value as identity-bearing.
  for (const name of ['host', 'X-Forwarded-Host', 'x-real-ip', 'X-Backend-Server']) {
    const out = sanitizeHeadersForLLM({ [name]: 'backend-prod-01' });
    assert.equal(out[name], REDACTED, `${name} was not redacted`);
  }
});

test('hostname leak vector: Server header is NOT redacted (tech info is preserved)', () => {
  // The counterpart to the above: a blanket single-word rule would strip this.
  assert.equal(sanitizeHeadersForLLM({ Server: 'nginx' }).Server, 'nginx');
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Guardrail must see what the sanitizer sees
// ─────────────────────────────────────────────────────────────────────────────

test('guardrail: a leaked compressed IPv6 is blocked in throw mode', () => {
  withEnv({ GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    // Previously this passed the guardrail even in throw mode.
    assert.throws(() => assertNoLeakage('Server at fe80::1 is vulnerable', 'test'));
  });
});

test('guardrail: a leaked email is blocked in throw mode', () => {
  withEnv({ GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    assert.throws(() => assertNoLeakage('Owner admin@corp.example.com', 'test'));
  });
});

test('guardrail: a bare "::" is not treated as a leak', () => {
  withEnv({ GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    assert.doesNotThrow(() => assertNoLeakage('The C++ :: operator is unrelated', 'test'));
  });
});

test('guardrail: the leaked IPv6/email value never appears in the thrown message', () => {
  withEnv({ GEMINI_STRICT_GUARDRAIL: 'true' }, () => {
    for (const secret of ['fe80::dead:beef', 'admin@corp.example.com']) {
      try {
        assertNoLeakage(`Leak ${secret} here`, 'test');
        assert.fail('expected a throw');
      } catch (err) {
        assert.ok(!err.message.includes(secret), `error message leaked the value: ${err.message}`);
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Guardrail flag parsing
// ─────────────────────────────────────────────────────────────────────────────

test('guardrail flag: common casing/whitespace variants are honoured, not silently ignored', () => {
  for (const value of ['true', 'TRUE', 'True', ' true ']) {
    withEnv({ GEMINI_STRICT_GUARDRAIL: value }, () => {
      assert.equal(_guardrailMode(), 'throw', `${JSON.stringify(value)} should mean throw`);
    });
  }
  for (const value of ['false', 'FALSE', ' False ']) {
    withEnv({ GEMINI_STRICT_GUARDRAIL: value }, () => {
      assert.equal(_guardrailMode(), 'off', `${JSON.stringify(value)} should mean off`);
    });
  }
});

test('guardrail flag: an unrecognised value falls back to warn and says so once', () => {
  const originalError = console.error;
  const logged = [];
  console.error = (msg) => logged.push(String(msg));
  try {
    withEnv({ GEMINI_STRICT_GUARDRAIL: 'yes-please' }, () => {
      assert.equal(_guardrailMode(), 'warn');
    });
  } finally {
    console.error = originalError;
  }
  // The warning is emitted once per process; if an earlier test already
  // triggered it, the important assertion is still that we resolved to 'warn'.
  if (logged.length) {
    assert.ok(logged.some((l) => l.includes('Unrecognised GEMINI_STRICT_GUARDRAIL')),
      `expected an unrecognised-flag warning, got: ${logged.join(' | ')}`);
  }
});

test('guardrail flag: unset and empty string both mean warn', () => {
  withEnv({ GEMINI_STRICT_GUARDRAIL: undefined }, () => {
    assert.equal(_guardrailMode(), 'warn');
  });
  withEnv({ GEMINI_STRICT_GUARDRAIL: '' }, () => {
    assert.equal(_guardrailMode(), 'warn');
  });
});
