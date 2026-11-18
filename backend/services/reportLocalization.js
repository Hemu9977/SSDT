'use strict';

/**
 * Report localization: the single place that turns a report's prose into the
 * report language, for both PDF generators (pdfService.generateSingleLanguagePdf
 * and generateZapPdf) and every scan type (public, form-login, HTTP Basic).
 *
 * Contract
 *  - Returns a localized copy of the report model, or throws
 *    LocalizationIncompleteError with code
 *      REPORT_TRANSLATION_UNAVAILABLE — the translation service could not be
 *        reached (outage, rate limit exhausted, credentials, deadline) and some
 *        prose has no Japanese yet; or
 *      REPORT_LOCALIZATION_INCOMPLETE — anything else left unresolved.
 *    A report with untranslated prose is never returned, so it can never be
 *    rendered, stored or offered as a completed report; no finding is ever dropped.
 *  - Only PROSE is translated or judged: finding titles, descriptions, solutions,
 *    the AI analysis, static labels and template text. DATA is never translated
 *    or sent anywhere: occurrences (raw request/response, evidence), sample URLs,
 *    references, CWE/WASC/plugin ids, risk/confidence enums, counts, scan values,
 *    target and scan history.
 *
 * Pipeline
 *  1. Prose is split into units (one per non-empty line). A unit that already
 *     passes the language audit for the target language is kept as is. JA titles
 *     come from the reviewed catalog (i18n/zapAlertNames.ja.js) when listed.
 *  2. Each remaining unit is scrubbed (i18n/protectTokens.js): secrets, identity
 *     and technical literals become {{Tn}} placeholders, restored locally later.
 *  3. JA: the scanner's own reviewed Japanese text for its alerts
 *     (i18n/zapJaCatalog.js), validated like any translation — no model call.
 *  4. Stored translations (models/ReportTranslation.js) are reused after being
 *     re-validated. Units already being translated by another job in this process
 *     are joined (single-flight). This does not coordinate across backend tasks;
 *     the store's immutable first-writer-wins rows make that safe (see the model).
 *  5. The rest is translated in batches (geminiService.translateReportUnits). A
 *     batch that fails as a whole is split in half, recursively, down to single
 *     units; a unit whose translation is rejected goes straight to single-unit
 *     attempts. Single-unit attempts climb a ladder — Flash, Flash in repair mode
 *     (told why the previous answer was rejected, temperature > 0), then Pro in
 *     repair mode — because repeating the identical temperature-0 request returns
 *     the identical rejected text (production 2026-11-17: one XSS solution line
 *     refused every JA report that had an XSS finding). Rate limits are retried
 *     with backoff, without splitting. All inside one deadline. Completed units are
 *     validated, stored immediately and re-read (so concurrent writers converge),
 *     and are kept even when other units fail, so a retried job only translates
 *     what is still missing.
 *  6. JA, last resort: a unit with no clean translation after the ladder uses its
 *     best rejected candidate IF it passes every hard check (placeholders exact, no
 *     new URL/host/email, no Markdown, complete length, enough Japanese) and fails
 *     only the wording rules (an English run, share or function word, e.g. a kept
 *     document title). Such units are counted (`softAccepted`), never stored.
 *  7. Gate: every prose field of the final model is audited (best-Japanese lines
 *     must still contain Japanese). Anything unresolved or failing throws, with
 *     counts per field / category / reason — never text.
 *
 * Logging: structured `[Localization] {json}` lines with counts, categories,
 * finish reasons and short unit hashes only. Source and translated text are never
 * logged.
 */

const crypto = require('crypto');
const { protect, restore, placeholderList, PROTECT_VERSION, PATTERN_FINGERPRINT } = require('../i18n/protectTokens');
const { auditProse, englishLetterCount, japaneseCharCount, unapprovedWords } = require('../i18n/languageAudit');
const { t } = require('../i18n/reportStrings');
const { curatedJapaneseTitle } = require('../i18n/zapAlertNames.ja');
const { catalogTranslation } = require('../i18n/zapJaCatalog');
const { redactHeaderBlock } = require('../utils/credentialRedaction');

const REPORT_LOCALIZATION_INCOMPLETE = 'REPORT_LOCALIZATION_INCOMPLETE';
const REPORT_TRANSLATION_UNAVAILABLE = 'REPORT_TRANSLATION_UNAVAILABLE';
const LOCALIZATION_ERROR_CODES = new Set([REPORT_LOCALIZATION_INCOMPLETE, REPORT_TRANSLATION_UNAVAILABLE]);

const DEFAULTS = {
  deadlineMs: 200_000,      // whole stage; the PDF job allows 300 s
  callTimeoutMs: 90_000,    // one model call
  minCallMs: 5_000,         // do not start a call with less time than this left
  batchMaxUnits: 40,
  batchMaxChars: 6_000,
  concurrency: 3,
  maxSingleTries: 3,        // attempts for a unit on its own (the model ladder)
  // Outage: this many consecutive failed calls with no successful call at all in
  // this run means the model is unavailable — the rest fails at once instead of
  // retrying every unit until the deadline (a user would wait minutes for an error).
  outageAfterFailures: 6,
  backoffMs: [0, 2_000, 5_000],
  quotaBackoffMs: [2_000, 5_000, 10_000], // rate limit: same batch again, not split
  repairTemperature: 0.3,
};

// Call failures that mean the model service is unavailable (outage detection).
const AVAILABILITY_FAILURES = new Set(['transient', 'timeout', 'error', 'quota']);
// Unresolved categories that mean "the translation service could not be used",
// i.e. REPORT_TRANSLATION_UNAVAILABLE rather than a content problem.
const UNAVAILABLE_CATEGORIES = new Set(['outage', 'transient', 'timeout', 'error', 'quota', 'auth',
  'deadline', 'joined_unavailable']);
// Audit reasons a best-Japanese candidate may still have (wording, not safety).
const SOFT_AUDIT_REASONS = new Set(['en_run', 'en_share', 'en_function_word', 'en_word_in_short_field']);

// Placeholder text older code stored for a finding with no description/solution.
const LEGACY_PLACEHOLDERS = new Set(['No description available', 'No solution provided']);

class LocalizationIncompleteError extends Error {
  constructor(detail, code = REPORT_LOCALIZATION_INCOMPLETE) {
    super(code);
    this.name = 'LocalizationIncompleteError';
    this.code = code;
    this.detail = detail;
  }
}

/** True for either localization failure code (both mean: nothing was rendered). */
const isLocalizationErrorCode = (code) => LOCALIZATION_ERROR_CODES.has(code);

// ─── Engine version (cache invalidation) ─────────────────────────────────────

let engineVersionMemo = null;
/**
 * sha256 of everything that shapes a stored translation. The language audit is
 * deliberately NOT part of it: every stored row is re-validated against the
 * current audit when read, so an allowlist fix keeps every stored translation
 * instead of discarding them all (a stricter audit simply rejects the old row).
 */
function engineVersion() {
  if (engineVersionMemo) return engineVersionMemo;
  let spec = {};
  try { spec = require('./geminiService').REPORT_TRANSLATION_SPEC || {}; } catch { spec = {}; }
  engineVersionMemo = crypto.createHash('sha256').update(JSON.stringify({
    engine: 2, spec, protect: PROTECT_VERSION, patterns: PATTERN_FINGERPRINT,
  })).digest('hex');
  return engineVersionMemo;
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const shortHash = (key) => key.slice(0, 10);

// ─── Validation of one translation ───────────────────────────────────────────

const count = (s, needle) => String(s).split(needle).length - 1;

/**
 * Why a translation of `masked` (null when it is acceptable). Applied to fresh
 * model output, catalog lines and every stored row before it is used.
 */
function validateTranslation(masked, out, lang, kind) {
  const hard = hardCheck(masked, out, lang, kind);
  if (hard) return hard;
  const audit = auditProse(out, lang, { short: kind === 'title' });
  if (!audit.ok) return `audit_${audit.issues[0].reason}`;
  return null;
}

/**
 * The checks no translation may ever fail, not even as a last resort: it is
 * complete, keeps every placeholder exactly, adds no URL/host/email, no Markdown,
 * no extra REDACTED, and carries the target language in proportion to the source.
 */
function hardCheck(masked, out, lang, kind) {
  if (typeof out !== 'string' || !out.trim()) return 'empty';
  if (out.includes('```')) return 'markdown';
  const want = placeholderList(masked).sort();
  const got = placeholderList(out).sort();
  if (want.length !== got.length || want.some((p, i) => p !== got[i])) return 'placeholders';
  if (count(out, 'REDACTED') > count(masked, 'REDACTED')) return 'redacted';
  // Every URL/email/host in the source was masked, so any in the output is new.
  if (/https?:\/\/|\bwww\.|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}/i.test(out)) return 'new_identity';
  const ratio = (out.length + 10) / (masked.length + 10);
  if (lang === 'ja' ? (ratio < 0.15 || ratio > 3.5) : (ratio < 0.3 || ratio > 6)) return 'length';
  // The output must carry the target language in proportion to the source prose:
  // a one-word or off-topic reply (e.g. to an injected instruction) is rejected.
  // Kanji are dense (Recommendations → 推奨, 2 characters for 15 letters), so the
  // floor is low for titles; real prose translations run at ~0.4.
  if (lang === 'ja') {
    const src = englishLetterCount(masked);
    if (src >= 8 && japaneseCharCount(out) < src * (kind === 'title' ? 0.1 : 0.15)) return 'too_short';
  } else {
    const src = japaneseCharCount(masked);
    if (src >= 4 && (out.match(/[A-Za-z]/g) || []).length < src * 0.5) return 'too_short';
  }
  return null;
}

/**
 * A rejected JA translation that may still be used as a last resort: every hard
 * check passes, it contains Japanese, and it fails only wording rules.
 */
function isBestJapaneseCandidate(masked, out, lang, kind) {
  if (lang !== 'ja' || hardCheck(masked, out, lang, kind)) return false;
  if (japaneseCharCount(out) === 0) return false;
  const audit = auditProse(out, lang, { short: kind === 'title' });
  return audit.issues.every(i => SOFT_AUDIT_REASONS.has(i.reason));
}

/**
 * A short line that is notation, not prose: at most 6 words, no English function
 * word, no sentence punctuation — e.g. the Apache directive "Options Indexes
 * FollowSymLinks Includes" quoted on its own line in a scanner solution. Used only
 * as a last resort, after the model returned it unchanged even in repair mode.
 */
function isLiteralLine(masked, kind) {
  const s = String(masked ?? '').trim();
  if (!s || s.length > 80 || /[.!?。]$/.test(s) || kind === 'title') return false;
  const words = s.replace(/\{\{T\d+\}\}/g, ' ').match(/[A-Za-z][A-Za-z'’-]*/g) || [];
  if (words.length > 6) return false;
  return !auditProse(s, 'ja').issues.some(i => i.reason === 'en_function_word');
}

/**
 * What to tell the model on a repair attempt: a fixed template per rejection
 * reason, plus (for wording) the plain English words its answer kept. Built from
 * the masked text only — placeholders, never literals or identity.
 */
function problemNote(reason, out, lang) {
  if (/^audit_/.test(reason)) {
    if (lang !== 'ja') return 'The previous translation still contained Japanese text. Translate everything into English.';
    const words = unapprovedWords(out);
    return words.length
      ? `The previous translation left these English words untranslated: ${words.join(', ')}. Translate them into Japanese.`
      : 'The previous translation was not fully Japanese. Translate every sentence into Japanese.';
  }
  if (reason === 'placeholders') return 'The previous translation did not keep every placeholder such as {{T0}} exactly once. Keep each placeholder exactly as written, exactly once.';
  if (reason === 'markdown') return 'The previous translation used Markdown or code fences. Return plain text only.';
  if (reason === 'new_identity' || reason === 'redacted') return 'The previous translation added a URL, address or value that is not in the text. Translate only the text.';
  return 'The previous translation was incomplete. Translate every sentence completely.';
}

// ─── Store (MongoDB) ─────────────────────────────────────────────────────────

function isDuplicateKeyOnly(err) {
  if (err?.code === 11000) return true;
  const errors = err?.writeErrors || err?.result?.result?.writeErrors || [];
  return Array.isArray(errors) && errors.length > 0 && errors.every(e => (e.code ?? e.err?.code) === 11000);
}

function mongoStore(log) {
  const Model = require('../models/ReportTranslation');
  return {
    async getMany(ids) {
      if (!ids.length) return new Map();
      try {
        const rows = await Model.find({ _id: { $in: ids } }).select('_id translation').maxTimeMS(5000).lean();
        return new Map(rows.map(r => [r._id, r.translation]));
      } catch (e) {
        log('warn', { event: 'store_read_failed', error: e?.name || 'Error' });
        return new Map();
      }
    },
    async putIfAbsent(rows, engineVer) {
      if (!rows.length) return;
      const now = new Date();
      try {
        await Model.bulkWrite(rows.map(r => ({
          updateOne: {
            filter: { _id: r.id },
            update: { $setOnInsert: { lang: r.lang, translation: r.translation, engineVersion: engineVer, createdAt: now, lastUsedAt: now } },
            upsert: true,
          },
        })), { ordered: false });
      } catch (e) {
        if (isDuplicateKeyOnly(e)) return; // a concurrent writer inserted first — fine
        log('warn', { event: 'store_write_failed', error: e?.name || 'Error', rows: rows.length });
      }
    },
    touch(ids) {
      if (!ids.length) return;
      const now = Date.now();
      Model.updateMany({ _id: { $in: ids }, lastUsedAt: { $lt: new Date(now - 24 * 60 * 60 * 1000) } },
        { $set: { lastUsedAt: new Date(now) } }).catch(() => {});
    },
  };
}

// ─── Slots: every prose field of the report model ────────────────────────────

/**
 * Collect the report's prose. `translate: false` slots are audited only (static
 * catalog text, template text, scan labels) — they are never sent anywhere.
 */
function collectSlots(model, lang) {
  const slots = [];
  const add = (field, kind, get, set, translate = true, owner = null) => slots.push({ field, kind, get, set, translate, owner });

  (model.findings || []).forEach((f) => {
    add('finding.title', 'title', () => f.name, (s) => { f.name = s; }, true, f);
    if (!f.descriptionUnavailable) add('finding.description', 'prose', () => f.description, (s) => { f.description = s; });
    else add('finding.description', 'prose', () => f.description, () => {}, false);
    if (!f.solutionUnavailable) add('finding.solution', 'prose', () => f.solution, (s) => { f.solution = s; });
    else add('finding.solution', 'prose', () => f.solution, () => {}, false);
  });

  const ai = model.aiAnalysis;
  if (ai) {
    add('ai.title', 'title', () => ai.title, () => {}, false);
    (ai.sections || []).forEach((sec) => {
      if (sec.heading) add('ai.heading', 'title', () => sec.heading, (s) => { sec.heading = s; });
      (sec.content || []).forEach((b) => {
        if (!b) return;
        if (b.type === 'bullets') {
          (b.items || []).forEach((_, i) => add('ai.bullet', 'prose', () => b.items[i], (s) => { b.items[i] = s; }));
        } else if (b.type === 'bold_text') {
          if (b.label) add('ai.label', 'title', () => b.label, (s) => { b.label = s; });
          if (b.text) add('ai.text', 'prose', () => b.text, (s) => { b.text = s; });
        } else if (b.text) {
          add('ai.paragraph', 'prose', () => b.text, (s) => { b.text = s; });
        }
      });
    });
  }

  // Audited only.
  const pickLang = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v[lang] : v);
  const sd = model.scanData;
  if (sd) {
    const label = (field, v, kind = 'title') => { const s = pickLang(v); if (s) add(field, kind, () => s, () => {}, false); };
    label('scan.title', sd.header?.title);
    label('scan.summary', sd.summary?.title);
    label('scan.summary', sd.summary?.riskLabel);
    label('scan.summary', sd.summary?.riskLevel);
    (sd.sections || []).forEach((sec) => {
      label('scan.section', sec.title);
      (sec.items || []).forEach((it) => {
        label('scan.label', it.label);
        if (it.value && typeof it.value === 'object') label('scan.value', it.value);
      });
    });
  }
  const tpl = model.template;
  if (tpl) {
    const text = (field, s, kind = 'prose') => { if (s) add(field, kind, () => String(s), () => {}, false); };
    text('template.disclaimer', tpl.disclaimerTitle, 'title');
    text('template.disclaimer', tpl.disclaimerBody);
    text('template.history', tpl.diagnosisTitle, 'title');
    (tpl.diagnosisHeaders || []).forEach((h) => text('template.history', h, 'title'));
    (tpl.finalPageLines || []).forEach((l) => text('template.final', l));
  }
  (model.labels || []).forEach((s) => add('label', 'title', () => s, () => {}, false));
  return slots;
}

// ─── Engine ──────────────────────────────────────────────────────────────────

function createLocalizer(deps = {}) {
  const opts = { ...DEFAULTS, ...deps };
  const inflight = new Map(); // key -> Promise<string|null>, this process only
  const logFn = deps.logger || ((level, obj) => {
    const line = `[Localization] ${JSON.stringify(obj)}`;
    if (level === 'warn') console.warn(line); else console.log(line);
  });
  const translate = deps.translate || ((units, lang, o) => require('./geminiService').translateReportUnits(units, lang, o));
  // The scanner's reviewed Japanese (null: none). Injectable so tests can exercise the model path alone.
  const catalogLookup = deps.catalogLookup === undefined ? catalogTranslation : (deps.catalogLookup || (() => null));
  const now = deps.now || (() => Date.now());
  const sleep = deps.sleep || ((ms) => new Promise(r => setTimeout(r, ms)));
  // Resolves to the promise's value, or null after `ms`; the timer never outlives it.
  const withTimeout = (promise, ms) => new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    promise.then((v) => { clearTimeout(timer); resolve(v); }, () => { clearTimeout(timer); resolve(null); });
  });
  let store = deps.store || null;
  const getStore = () => store || (store = mongoStore(logFn));

  /**
   * @param {{ findings?: object[], aiAnalysis?: object|null, scanData?: object,
   *           template?: object, labels?: string[] }} input
   * @param {'ja'|'en'} lang
   * @param {{ logLabel?: string }} [ctx]
   */
  async function localizeReport(input, lang, ctx = {}) {
    const started = now();
    const deadline = started + opts.deadlineMs;
    const ev = engineVersion();
    const log = (level, obj) => logFn(level, { label: ctx.logLabel, lang, ...obj });

    // Copies: inputs (e.g. the cached detailed-alerts findings) are never mutated.
    const model = {
      findings: (input.findings || []).map(f => normalizeFinding(f, lang)),
      aiAnalysis: input.aiAnalysis ? { ...JSON.parse(JSON.stringify(input.aiAnalysis)), title: t(lang, 'aiSectionTitle') } : null,
      scanData: input.scanData || null,
      template: input.template || null,
      labels: input.labels || [],
    };

    const slots = collectSlots(model, lang);
    const stats = { units: 0, catalog: 0, cached: 0, joined: 0, translated: 0, curated: 0, calls: 0,
      repairCalls: 0, proCalls: 0, softAccepted: 0, failed: 0, byCategory: {}, promptTokens: 0, outputTokens: 0 };
    const bump = (k) => { stats.byCategory[k] = (stats.byCategory[k] || 0) + 1; };

    // 1. Units.
    const units = [];      // { slot, lines, li, lead, trail, tokens, key }
    const entries = new Map(); // key -> { key, masked, kind }
    for (const slot of slots) {
      if (!slot.translate) continue;
      const text = slot.get();
      if (typeof text !== 'string' || !text) continue;
      if (lang === 'ja' && slot.field === 'finding.title') {
        const f = slot.owner;
        const curated = curatedJapaneseTitle(f?.originalName ?? text, f?.pluginId);
        if (curated) { slot.set(curated); stats.curated++; continue; }
      }
      const lines = text.split('\n');
      lines.forEach((line, li) => {
        const core = line.trim();
        if (!core) return;
        if (auditProse(core, lang, { short: slot.kind === 'title' }).ok) return;
        const { masked, tokens } = protect(core);
        const key = sha256(`${ev}\u0000${lang}\u0000${slot.kind}\u0000${masked}`);
        const start = line.length - line.trimStart().length;
        units.push({ slot, lines, li, lead: line.slice(0, start), trail: line.slice(start + core.length), tokens, key });
        if (!entries.has(key)) entries.set(key, { key, masked, kind: slot.kind });
      });
    }
    stats.units = units.length;

    const results = new Map();  // key -> masked translation
    const failures = new Map(); // key -> category
    const softKeys = new Set(); // keys resolved by a best-Japanese candidate
    const literalKeys = new Set(); // keys kept as their source literal (isLiteralLine)
    const softReasons = {};

    if (entries.size && lang === 'ja') {
      // 2. The scanner's own reviewed Japanese, validated like any translation.
      for (const e of entries.values()) {
        const ja = catalogLookup(e.kind, e.masked);
        if (ja != null && !validateTranslation(e.masked, ja, lang, e.kind)) { results.set(e.key, ja); stats.catalog++; }
      }
    }

    if (entries.size > results.size) {
      // 3. Stored translations, re-validated.
      const keys = [...entries.keys()].filter(k => !results.has(k));
      const stored = await getStore().getMany(keys);
      const hits = [];
      for (const [key, tr] of stored) {
        const e = entries.get(key);
        if (e && !validateTranslation(e.masked, tr, lang, e.kind)) { results.set(key, tr); hits.push(key); }
        else if (e) bump('store_row_rejected');
      }
      stats.cached = hits.length;
      getStore().touch(hits);

      // 3. Join units another job in this process is already translating.
      const joined = [];
      const todo = [];
      for (const e of entries.values()) {
        if (results.has(e.key)) continue;
        if (inflight.has(e.key)) joined.push({ e, promise: inflight.get(e.key) });
        else {
          let resolve;
          const p = new Promise(r => { resolve = r; });
          inflight.set(e.key, p);
          todo.push({ ...e, resolve, singleTries: 0, problem: null, candidates: [] });
        }
      }

      // 4. Translate.
      const abort = new AbortController();
      const abortTimer = setTimeout(() => abort.abort(), Math.max(0, deadline - now()));
      abortTimer.unref?.();
      // Joined jobs receive { tr, soft } (or null) through the single-flight promise.
      const finish = (e, value, category) => {
        if (value != null) {
          results.set(e.key, value); stats.translated++;
          inflight.delete(e.key);
          e.resolve({ tr: value, soft: false });
          return;
        }
        // Last resort (JA): the best rejected candidate that passes every hard check.
        const best = e.candidates
          .slice()
          .sort((a, b) => englishLetterCount(a.out) - englishLetterCount(b.out))[0];
        if (best) {
          results.set(e.key, best.out);
          softKeys.add(e.key);
          stats.softAccepted++;
          softReasons[best.reason] = (softReasons[best.reason] || 0) + 1;
          log('warn', { event: 'translation_best_japanese_used', unit: shortHash(e.key), reason: best.reason,
            after: category, attempts: e.singleTries });
          inflight.delete(e.key);
          e.resolve({ tr: best.out, soft: true });
          return;
        }
        // Last resort (JA): a short literal with nothing to translate — e.g. the
        // Apache directive "Options Indexes FollowSymLinks Includes" — that the model
        // returned unchanged twice, once even when told to translate it.
        if (lang === 'ja' && e.verbatim >= 2 && e.verbatimAfterRepair && isLiteralLine(e.masked, e.kind)) {
          results.set(e.key, e.masked);
          literalKeys.add(e.key);
          stats.softAccepted++;
          softReasons.verbatim_literal = (softReasons.verbatim_literal || 0) + 1;
          log('warn', { event: 'translation_literal_kept', unit: shortHash(e.key), after: category, attempts: e.singleTries });
          inflight.delete(e.key);
          e.resolve({ tr: e.masked, soft: true, literal: true });
          return;
        }
        failures.set(e.key, category);
        inflight.delete(e.key);
        e.resolve(null);
      };

      const queue = makeBatches(todo, opts).map(entriesInBatch => ({ entries: entriesInBatch }));
      let consecutiveFailures = 0, anySuccess = false, outage = false;
      const retrySingle = (e, category) => {
        if (outage) { finish(e, null, 'outage'); return; }
        if (e.singleTries >= opts.maxSingleTries) { finish(e, null, category); return; }
        queue.push({ entries: [e], delayMs: opts.backoffMs[Math.min(e.singleTries, opts.backoffMs.length - 1)] });
      };
      const requeue = (list, category) => {
        if (outage) { list.forEach(e => finish(e, null, 'outage')); return; }
        if (list.length > 1) {
          const mid = Math.ceil(list.length / 2);
          queue.push({ entries: list.slice(0, mid) }, { entries: list.slice(mid) });
          return;
        }
        retrySingle(list[0], category);
      };

      const processBatch = async (batch) => {
        if (outage) { batch.entries.forEach(e => finish(e, null, 'outage')); return; }
        if (batch.delayMs) await sleep(Math.min(batch.delayMs, Math.max(0, deadline - now() - opts.minCallMs)));
        if (outage) { batch.entries.forEach(e => finish(e, null, 'outage')); return; }
        const remaining = deadline - now();
        if (remaining < opts.minCallMs) { batch.entries.forEach(e => finish(e, null, 'deadline')); return; }
        // The ladder (single units only): attempt n climbs one rung, and a unit whose
        // translation was rejected starts one rung up — repeating the identical
        // temperature-0 request would return the identical rejected text.
        //   rung 1: Flash, temperature 0 (the verified default call)
        //   rung 2: Flash, repair mode (told why), temperature > 0
        //   rung 3+: Pro, repair mode, temperature > 0
        const single = batch.entries.length === 1;
        if (single && !batch.quotaRetry) batch.entries[0].singleTries++;
        const rung = single ? batch.entries[0].singleTries + (batch.entries[0].problem ? 1 : 0) : 1;
        const callOpts = { timeoutMs: Math.min(opts.callTimeoutMs, remaining), signal: abort.signal };
        if (rung >= 2) {
          callOpts.temperature = opts.repairTemperature;
          if (batch.entries[0].problem) callOpts.repair = true;
        }
        if (rung >= 3) callOpts.model = 'pro';
        const req = batch.entries.map((e, i) => ({ id: `u${i}${e.kind === 'title' ? ':title' : ''}`, text: e.masked,
          ...(callOpts.repair && e.problem ? { problem: e.problem } : {}) }));
        let res;
        stats.calls++;
        if (callOpts.repair) stats.repairCalls++;
        if (callOpts.model === 'pro') stats.proCalls++;
        try {
          res = await translate(req, lang, callOpts);
        } catch (err) {
          const category = err?.category || 'error';
          bump(category);
          log('warn', { event: 'translation_batch_failed', category, finishReason: err?.finishReason,
            httpStatus: err?.httpStatus, batchSize: batch.entries.length, rung, units: batch.entries.map(e => shortHash(e.key)) });
          if (category === 'auth') { batch.entries.forEach(e => finish(e, null, category)); return; }
          // Only availability failures count: a reply that is invalid JSON, truncated or
          // blocked means the model is up — splitting is the cure for those.
          if (AVAILABILITY_FAILURES.has(category)) consecutiveFailures++;
          if (!anySuccess && !outage && consecutiveFailures >= opts.outageAfterFailures) {
            outage = true;
            bump('outage');
            log('warn', { event: 'translation_outage_detected', consecutiveFailures, lastCategory: category });
          }
          if (category === 'quota') {
            // Rate limited: the same batch again after a pause — splitting would only
            // multiply the requests the limiter is refusing.
            const n = batch.quotaRetries || 0;
            if (!outage && n < opts.quotaBackoffMs.length) {
              queue.push({ entries: batch.entries, delayMs: opts.quotaBackoffMs[n], quotaRetries: n + 1, quotaRetry: true });
            } else batch.entries.forEach(e => finish(e, null, outage ? 'outage' : 'quota'));
            return;
          }
          requeue(batch.entries, category);
          return;
        }
        anySuccess = true;
        consecutiveFailures = 0;
        stats.promptTokens += res?.usage?.promptTokens || 0;
        stats.outputTokens += res?.usage?.outputTokens || 0;
        const accepted = [], rejected = [], reasons = {};
        batch.entries.forEach((e, i) => {
          const out = res?.translations?.get(req[i].id);
          const reason = validateTranslation(e.masked, out, lang, e.kind);
          if (reason) {
            rejected.push(e); reasons[reason] = (reasons[reason] || 0) + 1; bump(`validation_${reason}`);
            if (typeof out === 'string' && out.trim() === e.masked.trim()) {
              e.verbatim = (e.verbatim || 0) + 1;
              if (callOpts.repair) e.verbatimAfterRepair = true;
            }
            e.problem = problemNote(reason, out, lang);
            if (isBestJapaneseCandidate(e.masked, out, lang, e.kind)) e.candidates.push({ out, reason });
          } else accepted.push({ e, out });
        });
        if (rejected.length) {
          log('warn', { event: 'translation_units_rejected', count: rejected.length, reasons,
            units: rejected.map(e => shortHash(e.key)) });
        }
        if (accepted.length) {
          // Store first, then re-read: concurrent writers (other tasks) converge on
          // the stored row. Done per batch so progress survives later failures.
          const rows = accepted.map(({ e, out }) => ({ id: e.key, lang, translation: out }));
          await getStore().putIfAbsent(rows, ev);
          const winners = await getStore().getMany(rows.map(r => r.id));
          for (const { e, out } of accepted) {
            const w = winners.get(e.key);
            finish(e, w && !validateTranslation(e.masked, w, lang, e.kind) ? w : out);
          }
        }
        // A rejected unit goes straight to the ladder on its own: re-sending it in a
        // smaller batch at temperature 0 would only return the same text.
        rejected.forEach(e => retrySingle(e, 'validation'));
      };

      await runQueue(queue, async (b) => {
        try { await processBatch(b); }
        catch (err) { // never let one batch take the stage down
          bump('internal');
          log('warn', { event: 'translation_batch_internal_error', error: err?.name || 'Error' });
          b.entries.forEach(e => { if (!results.has(e.key) && !failures.has(e.key)) finish(e, null, 'internal'); });
        }
      }, opts.concurrency);
      clearTimeout(abortTimer);

      // Joined units: wait for the other job, but not past our deadline.
      for (const { e, promise } of joined) {
        const v = await withTimeout(promise, Math.max(0, deadline - now()));
        const ok = v != null && (v.literal
          ? v.tr === e.masked && isLiteralLine(e.masked, e.kind)
          : v.soft
            ? isBestJapaneseCandidate(e.masked, v.tr, lang, e.kind)
            : !validateTranslation(e.masked, v.tr, lang, e.kind));
        if (ok) {
          results.set(e.key, v.tr); stats.joined++;
          if (v.literal) { literalKeys.add(e.key); stats.softAccepted++; }
          else if (v.soft) { softKeys.add(e.key); stats.softAccepted++; }
        } else failures.set(e.key, v == null ? 'joined_unavailable' : 'joined_invalid');
      }
    }

    // 5. Apply translations.
    const unresolved = { byField: {}, byCategory: {} };
    const touched = new Set();
    for (const u of units) {
      const tr = results.get(u.key);
      if (tr == null) {
        stats.failed++;
        unresolved.byField[u.slot.field] = (unresolved.byField[u.slot.field] || 0) + 1;
        const c = failures.get(u.key) || 'unresolved';
        unresolved.byCategory[c] = (unresolved.byCategory[c] || 0) + 1;
        continue;
      }
      u.lines[u.li] = u.lead + restore(tr, u.tokens) + u.trail;
      if (softKeys.has(u.key)) (u.slot.softLines || (u.slot.softLines = new Set())).add(u.li);
      if (literalKeys.has(u.key)) (u.slot.literalLines || (u.slot.literalLines = new Set())).add(u.li);
      touched.add(u);
    }
    for (const u of touched) u.slot.set(u.lines.join('\n'));

    // 6. Gate: audit every prose field of the final model. A best-Japanese line
    // (step 6 of the pipeline) passed every hard check when it was chosen; here it
    // must still contain Japanese.
    const gate = { byField: {}, byReason: {} };
    let auditFailures = 0;
    const gateFail = (slot, reasons) => {
      auditFailures++;
      gate.byField[slot.field] = (gate.byField[slot.field] || 0) + 1;
      for (const r of reasons) gate.byReason[r] = (gate.byReason[r] || 0) + 1;
    };
    for (const slot of slots) {
      const text = slot.get();
      if (typeof text !== 'string' || !text.trim()) continue;
      text.split('\n').forEach((line, li) => {
        if (!line.trim()) return;
        if (slot.literalLines?.has(li)) return; // the source literal itself (see isLiteralLine)
        if (slot.softLines?.has(li)) {
          if (japaneseCharCount(line) === 0) gateFail(slot, ['no_japanese']);
          return;
        }
        const r = auditProse(line.trim(), lang, { short: slot.kind === 'title' });
        if (!r.ok) gateFail(slot, r.issues.map(i => i.reason));
      });
    }

    const summary = { event: 'report_localization', engine: ev.slice(0, 12), ...stats,
      auditFailures, durationMs: now() - started };
    if (stats.softAccepted) summary.softReasons = softReasons;
    if (stats.failed || auditFailures) {
      // Unavailable = some prose is missing because the service could not be used
      // (outage, rate limit, credentials, deadline): worth retrying later. Otherwise
      // the content itself could not be localized.
      const unavailable = Object.keys(unresolved.byCategory).some(c => UNAVAILABLE_CATEGORIES.has(c));
      const code = unavailable ? REPORT_TRANSLATION_UNAVAILABLE : REPORT_LOCALIZATION_INCOMPLETE;
      log('warn', { ...summary, outcome: unavailable ? 'unavailable' : 'incomplete', code, unresolved, gate });
      throw new LocalizationIncompleteError({ lang, unresolvedUnits: stats.failed, auditFailures, unresolved, gate }, code);
    }
    log('info', { ...summary, outcome: 'complete' });
    return { findings: model.findings, aiAnalysis: model.aiAnalysis, stats };
  }

  return { localizeReport, _inflight: inflight };
}

/** A copy of one finding with prose normalized; data fields are shared, never mutated. */
function normalizeFinding(f, lang) {
  const out = { ...f, originalName: f.originalName ?? f.name ?? f.alert ?? '' };
  out.name = out.name ?? f.alert ?? '';
  const usable = (s) => typeof s === 'string' && s.trim() && !LEGACY_PLACEHOLDERS.has(s.trim());
  // Prose is drawn, so a credential header line quoted in it (legacy data stored
  // before capture-time scrubbing) is redacted here as evidence is — never drawn.
  if (!usable(f.description)) { out.description = t(lang, 'descriptionUnavailable'); out.descriptionUnavailable = true; }
  else out.description = redactHeaderBlock(f.description);
  if (!usable(f.solution)) { out.solution = t(lang, 'solutionUnavailable'); out.solutionUnavailable = true; }
  else out.solution = redactHeaderBlock(f.solution);
  return out;
}

function makeBatches(list, opts) {
  const batches = [];
  let cur = [], chars = 0;
  for (const e of list) {
    if (cur.length && (cur.length >= opts.batchMaxUnits || chars + e.masked.length > opts.batchMaxChars)) {
      batches.push(cur); cur = []; chars = 0;
    }
    cur.push(e); chars += e.masked.length;
  }
  if (cur.length) batches.push(cur);
  return batches;
}

async function runQueue(queue, worker, concurrency) {
  const active = new Set();
  while (queue.length || active.size) {
    while (queue.length && active.size < concurrency) {
      const item = queue.shift();
      const p = worker(item).finally(() => active.delete(p));
      active.add(p);
    }
    if (active.size) await Promise.race(active);
  }
}

let defaultLocalizer = null;
/** The process-wide localizer (shared single-flight map and store). */
function localizeReport(input, lang, ctx) {
  if (!defaultLocalizer) defaultLocalizer = createLocalizer();
  return defaultLocalizer.localizeReport(input, lang, ctx);
}

module.exports = {
  localizeReport,
  createLocalizer,
  validateTranslation,
  hardCheck,
  isBestJapaneseCandidate,
  isLiteralLine,
  problemNote,
  engineVersion,
  collectSlots,
  LocalizationIncompleteError,
  isLocalizationErrorCode,
  REPORT_LOCALIZATION_INCOMPLETE,
  REPORT_TRANSLATION_UNAVAILABLE,
  DEFAULTS,
};
