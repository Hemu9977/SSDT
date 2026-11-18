'use strict';

/**
 * Sweep every alert text the pinned scanner can report through the REAL
 * localization engine (Vertex AI via ambient gcloud ADC, like
 * scripts/pdfLocalizationSmoke.js), to find text that the language audit rejects
 * before a customer's report does (local use only).
 *
 *   node scripts/zapCatalogSweep.js <zap plugin dir> <outFile.json> [--limit N]
 *
 * <zap plugin dir>: /zap/plugin copied out of the pinned image (see
 * scripts/buildZapJaCatalog.js). Only the scanner's public message bundles are
 * sent — no customer data. Translations go to an in-memory store (nothing is
 * written to any database).
 *
 * Writes <outFile.json>: totals, and every line that needed a repair attempt or
 * was rendered with its best Japanese, with the rejection reasons — the input for
 * reviewing technicalTerms.js / languageAudit.js (add proper names only, never
 * ordinary English words).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BACKEND = path.join(__dirname, '..');
require('dotenv').config({ path: path.join(BACKEND, '.env') });
require('../utils/logRedaction').install(); // before anything that logs (utils/logRedaction.js)
delete process.env.GEMINI_API_KEY;
delete process.env.GOOGLE_API_KEY;
delete process.env.GOOGLE_APPLICATION_CREDENTIALS;

const JSZip = require('jszip');
const { parseProperties, parseVulnerabilitiesXml } = require('../i18n/zapCatalogBuild');
const { protect } = require('../i18n/protectTokens');
const { auditProse } = require('../i18n/languageAudit');
const { createLocalizer, engineVersion } = require('../services/reportLocalization');

const out = (s) => process.stdout.write(`${s}\n`);
const PROSE_KEY_RE = /\.(desc|soln|solution|otherinfo)$/i;
const TITLE_KEY_RE = /\.name$/i;

async function collectTexts(dir) {
  const prose = new Set(), titles = new Set();
  const files = fs.readdirSync(dir).filter(f => /(ascanrules|pscanrules|commonlib|retire|domxss|graphql|openapi|soap|wappalyzer|oast)/.test(f) && f.endsWith('.zap'));
  for (const f of files) {
    const zip = await JSZip.loadAsync(fs.readFileSync(path.join(dir, f)));
    for (const name of Object.keys(zip.files)) {
      if (/(^|\/)vulnerabilities\.xml$/.test(name)) {
        for (const item of parseVulnerabilitiesXml(await zip.file(name).async('string')).values()) {
          if (item.alert) titles.add(item.alert.trim());
          for (const t of [item.desc, item.solution]) if (t) t.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => prose.add(l));
        }
      } else if (/(^|\/)Messages\.properties$/.test(name)) {
        const m = parseProperties(Buffer.from(await zip.file(name).async('uint8array')).toString('latin1'));
        for (const [k, v] of m) {
          if (/\{\d\}/.test(v)) continue; // message templates, not alert text
          if (PROSE_KEY_RE.test(k)) v.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => prose.add(l));
          else if (TITLE_KEY_RE.test(k) && /\b(ascanrules|pscanrules)\b/.test(k) && v.trim()) titles.add(v.trim());
        }
      }
    }
  }
  return { prose: [...prose], titles: [...titles] };
}

async function main() {
  const [dir, outFile] = process.argv.slice(2).filter(a => !a.startsWith('--'));
  if (!dir || !outFile) { process.stderr.write('usage: node scripts/zapCatalogSweep.js <zap plugin dir> <outFile.json> [--limit N]\n'); process.exit(2); }
  const limitAt = process.argv.indexOf('--limit');
  const limit = limitAt > 0 ? Number(process.argv[limitAt + 1]) : Infinity;

  const { prose, titles } = await collectTexts(dir);
  const lines = prose.filter(l => !auditProse(l, 'ja').ok).slice(0, limit);
  const titleList = titles.slice(0, Math.min(limit, titles.length));
  out(`prose lines needing translation: ${lines.length}, titles: ${titleList.length}`);

  const ev = engineVersion();
  const byHash = new Map();
  const hashOf = (kind, line) => crypto.createHash('sha256').update(`${ev}\u0000ja\u0000${kind}\u0000${protect(line).masked}`).digest('hex').slice(0, 10);
  lines.forEach(l => byHash.set(hashOf('prose', l), { kind: 'prose', text: l }));
  titleList.forEach(l => byHash.set(hashOf('title', l), { kind: 'title', text: l }));

  const rejected = new Map(); // hash -> { reasons }
  const best = new Map();
  const totals = { reports: 0, completed: 0, refused: 0, calls: 0, repairCalls: 0, proCalls: 0, catalog: 0,
    translated: 0, softAccepted: 0, failed: 0, byCategory: {} };
  const rows = new Map();
  const store = {
    async getMany(ids) { return new Map(ids.filter(i => rows.has(i)).map(i => [i, rows.get(i)])); },
    async putIfAbsent(list) { for (const r of list) if (!rows.has(r.id)) rows.set(r.id, r.translation); },
    touch() {},
  };
  const logger = (level, o) => {
    if (o.event === 'translation_units_rejected') {
      for (const u of o.units) {
        const r = rejected.get(u) || { reasons: {} };
        for (const k of Object.keys(o.reasons)) r.reasons[k] = (r.reasons[k] || 0) + 1;
        rejected.set(u, r);
      }
    } else if (o.event === 'translation_best_japanese_used') best.set(o.unit, o.reason);
    else if (o.event === 'report_localization') {
      for (const k of ['calls', 'repairCalls', 'proCalls', 'catalog', 'translated', 'softAccepted', 'failed']) totals[k] += o[k] || 0;
      for (const [k, n] of Object.entries(o.byCategory || {})) totals.byCategory[k] = (totals.byCategory[k] || 0) + n;
    }
  };
  const loc = createLocalizer({ logger, store });

  const CHUNK = 120;
  const n = Math.max(lines.length, titleList.length);
  for (let i = 0; i < n; i += CHUNK) {
    const findings = [];
    for (let j = i; j < Math.min(i + CHUNK, n); j++) {
      findings.push({ name: titleList[j] || '', pluginId: null, description: lines[j] || 'x', solution: '', occurrences: [] });
    }
    totals.reports++;
    const t0 = Date.now();
    try {
      await loc.localizeReport({ findings }, 'ja', { logLabel: `sweep-${i}` });
      totals.completed++;
    } catch (e) {
      totals.refused++;
      out(`chunk ${i}: refused ${e.code} ${JSON.stringify(e.detail?.unresolved?.byCategory || {})}`);
    }
    out(`chunk ${i}/${n} done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  }

  const report = {
    engine: ev.slice(0, 12), totals,
    neededRepair: [...rejected].map(([h, r]) => ({ ...byHash.get(h), reasons: r.reasons, bestJapanese: best.get(h) || null })),
  };
  fs.writeFileSync(outFile, `${JSON.stringify(report, null, 2)}\n`);
  out(JSON.stringify(totals));
  out(`lines that needed a repair attempt: ${report.neededRepair.length}; rendered with best Japanese: ${best.size}`);
}

main().catch((err) => { process.stderr.write(`failed: ${err?.name || 'Error'} ${err?.code || ''}\n`); process.exit(1); });
