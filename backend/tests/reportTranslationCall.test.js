'use strict';

/**
 * geminiService.translateReportUnits — the one model call report localization
 * makes. Runs the real @google/genai SDK (1.52.0) against a stubbed fetch, so the
 * request it actually sends and the handling of every response shape are pinned.
 *
 * The config is the combination verified against the deployed model on Vertex AI
 * on 2026-11-09 (see the comment above REPORT_TRANSLATION_SCHEMA): no `seed` (it
 * did not make output deterministic), no SDK `retryOptions` (the engine owns
 * retries), `httpOptions` always present with `abortSignal`.
 *
 * Run with: node --test backend/tests/reportTranslationCall.test.js
 */

process.env.GEMINI_API_KEY = 'AIza-test-capture-only';
const sent = [];
let respond = null;
globalThis.fetch = async (url, init) => {
  sent.push({ url: String(url), body: JSON.parse(String(init?.body || '{}')), signal: init?.signal });
  return respond(init);
};
const reply = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
const modelText = (text, finishReason = 'STOP', extra = {}) => reply({
  candidates: [{ content: { role: 'model', parts: [{ text }] }, finishReason }],
  usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 50 }, ...extra,
});

const test = require('node:test');
const assert = require('node:assert/strict');
for (const k of ['log', 'warn', 'error']) console[k] = () => {};
const { translateReportUnits, buildReportTranslationConfig, ReportTranslationError } = require('../services/geminiService');

const UNITS = [{ id: 'u0', text: 'Enable HSTS on all responses.' }, { id: 'u1:title', text: 'Path Traversal' }];
const good = () => JSON.stringify({ translations: [{ id: 'u0', text: 'すべてのレスポンスで HSTS を有効にしてください。' }, { id: 'u1:title', text: 'パストラバーサル' }] });

test('request: schema-constrained JSON, temperature 0, thinking off, system instruction separate from the units', async () => {
  sent.length = 0;
  respond = () => modelText(good());
  const out = await translateReportUnits(UNITS, 'ja', { timeoutMs: 5000 });
  assert.equal(out.translations.get('u1:title'), 'パストラバーサル');
  const body = sent[0].body;
  const gc = body.generationConfig;
  assert.equal(gc.responseMimeType, 'application/json');
  assert.ok(gc.responseSchema, 'responseSchema sent');
  assert.equal(gc.temperature, 0);
  assert.equal(gc.candidateCount, 1);
  assert.ok(gc.maxOutputTokens > 0);
  assert.deepEqual(gc.thinkingConfig, { thinkingBudget: 0 });
  assert.equal(gc.seed, undefined, 'seed is not used (it did not make output deterministic)');
  const system = JSON.stringify(body.systemInstruction);
  assert.match(system, /untrusted data/);
  assert.ok(!system.includes('Enable HSTS'), 'units are never spliced into the instruction');
  const user = JSON.parse(body.contents[0].parts[0].text);
  assert.deepEqual(user, { targetLang: 'ja', units: UNITS });
  assert.ok(sent[0].signal, 'the request is abortable');
});

test('config shape: exactly the verified options, httpOptions always with abortSignal, no SDK retries', () => {
  const signal = new AbortController().signal;
  const c = buildReportTranslationConfig('ja', { timeoutMs: 1234, signal, maxOutputTokens: 2048, model: 'gemini-2.5-flash' });
  assert.deepEqual(Object.keys(c).sort(), ['abortSignal', 'candidateCount', 'httpOptions', 'maxOutputTokens',
    'responseMimeType', 'responseSchema', 'systemInstruction', 'temperature', 'thinkingConfig'].sort());
  assert.deepEqual(c.httpOptions, { timeout: 1234 });
  assert.equal(c.httpOptions.retryOptions, undefined);
  const pro = buildReportTranslationConfig('en', { timeoutMs: 1, signal, maxOutputTokens: 1, model: 'gemini-2.5-pro' });
  // 2.5 Pro cannot turn thinking off: a small fixed budget instead of 0.
  assert.ok(pro.thinkingConfig.thinkingBudget > 0, 'thinkingBudget 0 is only sent to Flash models');
  assert.equal(pro.temperature, 0);
  assert.ok(!/Repair mode/.test(pro.systemInstruction), 'no repair note by default');
});

test('repair attempt: the chosen model, temperature, a repair note in the system instruction, and the per-unit problem in the data', async () => {
  sent.length = 0;
  respond = () => modelText(good());
  await translateReportUnits(UNITS.map(u => ({ ...u, problem: 'The previous translation left these English words untranslated: Prevention, Cheat, Sheet. Translate them into Japanese.' })),
    'ja', { timeoutMs: 5000, model: 'pro', temperature: 0.3, repair: true });
  const body = sent[0].body;
  assert.match(sent[0].url, /gemini-2\.5-pro/);
  assert.equal(body.generationConfig.temperature, 0.3);
  assert.ok(body.generationConfig.thinkingConfig.thinkingBudget > 0);
  assert.match(JSON.stringify(body.systemInstruction), /Repair mode/);
  const user = JSON.parse(body.contents[0].parts[0].text);
  assert.match(user.units[0].problem, /Prevention, Cheat, Sheet/);

  // Without repair, a stray `problem` field is never sent.
  sent.length = 0;
  await translateReportUnits(UNITS.map(u => ({ ...u, problem: 'x' })), 'ja', { timeoutMs: 5000 });
  assert.deepEqual(JSON.parse(sent[0].body.contents[0].parts[0].text).units, UNITS);
  assert.match(sent[0].url, /gemini-2\.5-flash/);
});

const expectCategory = async (category, fn) => {
  respond = fn;
  await assert.rejects(translateReportUnits(UNITS, 'ja', { timeoutMs: 2000 }),
    (e) => e instanceof ReportTranslationError && e.category === category);
};

test('responses are classified, never parsed loosely', async () => {
  // The production failure: the model's reply is not valid JSON.
  await expectCategory('invalid_json', () => modelText('{"translations": [{"id": "u0", "text": "壊れた "引用" です"}]}'));
  await expectCategory('truncated', () => modelText(good(), 'MAX_TOKENS'));
  await expectCategory('blocked', () => modelText(good(), 'SAFETY'));
  await expectCategory('blocked', () => modelText(good(), 'RECITATION'));
  await expectCategory('blocked', () => modelText('', 'STOP', { promptFeedback: { blockReason: 'PROHIBITED_CONTENT' } }));
  await expectCategory('schema_mismatch', () => modelText(JSON.stringify({ translations: [{ id: 'u0', text: 'x' }] })));
  await expectCategory('schema_mismatch', () => modelText(JSON.stringify({ translations: [
    { id: 'u0', text: 'a' }, { id: 'u1:title', text: 'b' }, { id: 'u9', text: 'extra' }] })));
  await expectCategory('schema_mismatch', () => modelText(JSON.stringify([{ id: 'u0', text: 'a' }])));
  await expectCategory('quota', () => reply({ error: { code: 429, message: 'RESOURCE_EXHAUSTED', status: 'RESOURCE_EXHAUSTED' } }, 429));
  await expectCategory('transient', () => reply({ error: { code: 503, message: 'UNAVAILABLE', status: 'UNAVAILABLE' } }, 503));
  await expectCategory('auth', () => reply({ error: { code: 403, message: 'PERMISSION_DENIED', status: 'PERMISSION_DENIED' } }, 403));
});

test('timeout: the request is aborted and reported as a timeout', async () => {
  respond = (init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' })));
  });
  const t0 = Date.now();
  await assert.rejects(translateReportUnits(UNITS, 'ja', { timeoutMs: 50 }), (e) => e.category === 'timeout');
  assert.ok(Date.now() - t0 < 2000, 'aborted promptly');
});

test('errors carry a category, never the model\'s or the request\'s text', async () => {
  respond = () => modelText('{"translations": [ "すべてのレスポンスで HSTS を有効に');
  try { await translateReportUnits(UNITS, 'ja', { timeoutMs: 2000 }); assert.fail('should throw'); }
  catch (e) {
    const dump = `${e.message} ${JSON.stringify(e)}`;
    assert.ok(!dump.includes('HSTS') && !dump.includes('すべて'), 'error exposes text');
  }
});
