'use strict';

/**
 * Builds i18n/zapCatalog.ja.json: the scanner's OWN reviewed Japanese text for its
 * alerts, aligned line by line with the English text the scanner reports.
 *
 * The pinned ZAP image ships Japanese translations of every alert it can raise:
 *  - commonlib's vulnerabilities_ja_JP.xml (the shared WASC catalog: XSS, SQL
 *    injection, path traversal…, 104 entries, all Japanese), and
 *  - each scan-rule add-on's Messages_ja_JP.properties (rule-specific text).
 * These are used before the translation model (services/reportLocalization.js), so
 * the standard scanner text in a JA report never depends on the model.
 *
 * A pair is kept only if it is safe to substitute with no human in the loop:
 *  - English and Japanese have the same number of non-empty lines (line i ↔ line i);
 *  - protect() finds the same literals (URLs, code, paths…) on both sides, so the
 *    Japanese can be stored in masked form with the English token numbering;
 *  - the Japanese passes validateTranslation() — the same checks a model
 *    translation must pass (placeholders, no new identity, length, language audit).
 *
 * Pure functions only (no I/O except the jszip archive passed in); the CLI is
 * scripts/buildZapJaCatalog.js.
 */

const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');
const { protect, placeholderList } = require('./protectTokens');

const CATALOG_FORMAT = 1;

// Property keys whose value is alert prose. References (.refs) are data.
const PROSE_KEY_RE = /\.(desc|soln|solution|otherinfo|other|extrainfo)$/i;
const TITLE_KEY_RE = /\.(name|alert\.name|title)$/i;

/** Lookup key used at build time and at run time. */
function catalogKey(kind, masked) {
  return crypto.createHash('sha256').update(`${kind}\u0000${masked}`).digest('hex');
}

/** Java .properties → Map (escapes, continuation lines, ':' / '=' / space separators). */
function parseProperties(text) {
  const out = new Map();
  const lines = String(text).split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].replace(/^[ \t\f]+/, '');
    if (!line || line[0] === '#' || line[0] === '!') continue;
    // Continuation: an odd number of trailing backslashes.
    while (/(^|[^\\])(\\\\)*\\$/.test(line) && i + 1 < lines.length) {
      line = line.slice(0, -1) + lines[++i].replace(/^[ \t\f]+/, '');
    }
    let k = 0;
    while (k < line.length) {
      const c = line[k];
      if (c === '\\') { k += 2; continue; }
      if (c === '=' || c === ':' || c === ' ' || c === '\t' || c === '\f') break;
      k++;
    }
    const rawKey = line.slice(0, k);
    let rest = line.slice(k).replace(/^[ \t\f]*/, '');
    if (rest[0] === '=' || rest[0] === ':') rest = rest.slice(1).replace(/^[ \t\f]*/, '');
    out.set(unescapeProp(rawKey), unescapeProp(rest));
  }
  return out;
}

function unescapeProp(s) {
  return s.replace(/\\(u[0-9a-fA-F]{4}|.)/g, (m, e) => {
    if (e[0] === 'u' && e.length === 5) return String.fromCharCode(parseInt(e.slice(1), 16));
    return { n: '\n', t: '\t', r: '\r', f: '\f' }[e] ?? e;
  });
}

/** vulnerabilities*.xml → Map(itemName → { alert, desc, solution }). */
function parseVulnerabilitiesXml(xml) {
  const doc = new DOMParser({ onError: () => {} }).parseFromString(String(xml), 'text/xml');
  const out = new Map();
  const root = doc.documentElement;
  if (!root) return out;
  for (let n = root.firstChild; n; n = n.nextSibling) {
    if (n.nodeType !== 1 || !/^vuln_item_/.test(n.nodeName)) continue;
    const item = {};
    for (let c = n.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === 1 && ['alert', 'desc', 'solution'].includes(c.nodeName)) item[c.nodeName] = c.textContent || '';
    }
    out.set(n.nodeName, item);
  }
  return out;
}

const nonEmptyLines = (s) => String(s ?? '').split('\n').map(l => l.trim()).filter(Boolean);

/**
 * Japanese line in masked form, numbered like the English line's tokens.
 * null when the two lines do not carry exactly the same literals.
 */
function maskLike(enTokens, jaLine) {
  const { masked, tokens } = protect(jaLine);
  if (tokens.length !== enTokens.length) return null;
  const remaining = enTokens.map((t, i) => ({ t, i }));
  const mapping = [];
  for (const t of tokens) {
    const at = remaining.findIndex(r => r.t === t);
    if (at < 0) return null;
    mapping.push(remaining[at].i);
    remaining.splice(at, 1);
  }
  return masked.replace(/\{\{T(\d+)\}\}/g, (m, j) => `{{T${mapping[Number(j)]}}}`);
}

/**
 * Align one English text with its Japanese counterpart.
 * @returns {{ pairs: Array<{kind, enMasked, jaMasked}>, rejected: Record<string, number> }}
 */
function alignText(en, ja, kind, validate) {
  const rejected = {};
  const bump = (r) => { rejected[r] = (rejected[r] || 0) + 1; };
  const enLines = nonEmptyLines(en);
  const jaLines = nonEmptyLines(ja);
  if (!enLines.length || !jaLines.length) { bump('empty'); return { pairs: [], rejected }; }
  if (enLines.length !== jaLines.length) { bump('line_structure'); return { pairs: [], rejected }; }
  const pairs = [];
  enLines.forEach((enLine, i) => {
    const { masked: enMasked, tokens } = protect(enLine);
    const jaMasked = maskLike(tokens, jaLines[i]);
    if (jaMasked == null) { bump('literals_differ'); return; }
    if (placeholderList(jaMasked).length !== placeholderList(enMasked).length) { bump('literals_differ'); return; }
    const reason = validate(enMasked, jaMasked, 'ja', kind);
    if (reason) { bump(`invalid_${reason}`); return; }
    pairs.push({ kind, enMasked, jaMasked });
  });
  return { pairs, rejected };
}

/** "ascanrules-release-83.zap" → { id: 'ascanrules', version: [83] }. */
function addOnVersion(fileName) {
  const m = /^(.+?)-(?:release|beta|alpha)-([\d.]+)\.zap$/.exec(fileName);
  if (!m) return null;
  return { id: m[1], version: m[2].split('.').map(Number) };
}

const compareVersions = (a, b) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d) return d;
  }
  return 0;
};

/**
 * @param {Array<{ name: string, zip: import('jszip') }>} addOns every .zap file
 * @param {{ validate: Function, source?: object }} opts
 * @returns {Promise<{ catalog: object, report: object }>}
 */
async function buildCatalog(addOns, { validate, source = {} }) {
  // Newest version of each add-on last, so its pairs win (ZAP loads the newest).
  const sorted = addOns
    .map(a => ({ ...a, v: addOnVersion(a.name) }))
    .filter(a => a.v)
    .sort((a, b) => (a.v.id === b.v.id ? compareVersions(a.v.version, b.v.version) : a.v.id.localeCompare(b.v.id)));

  const entries = new Map();
  const report = { addOns: 0, texts: 0, pairs: 0, rejected: {} };
  const take = (en, ja, kind) => {
    report.texts++;
    const { pairs, rejected } = alignText(en, ja, kind, validate);
    for (const [r, n] of Object.entries(rejected)) report.rejected[r] = (report.rejected[r] || 0) + n;
    for (const p of pairs) entries.set(catalogKey(p.kind, p.enMasked), p.jaMasked);
  };

  for (const { zip } of sorted) {
    let used = false;
    const files = Object.keys(zip.files);
    for (const enPath of files.filter(f => /(^|\/)vulnerabilities\.xml$/.test(f))) {
      const jaFile = zip.file(enPath.replace(/vulnerabilities\.xml$/, 'vulnerabilities_ja_JP.xml'));
      if (!jaFile) continue;
      const en = parseVulnerabilitiesXml(await zip.file(enPath).async('string'));
      const ja = parseVulnerabilitiesXml(await jaFile.async('string'));
      for (const [name, item] of en) {
        const jaItem = ja.get(name);
        if (!jaItem) continue;
        used = true;
        if (item.alert && jaItem.alert) take(item.alert, jaItem.alert, 'title');
        if (item.desc && jaItem.desc) take(item.desc, jaItem.desc, 'prose');
        if (item.solution && jaItem.solution) take(item.solution, jaItem.solution, 'prose');
      }
    }
    for (const enPath of files.filter(f => /(^|\/)Messages\.properties$/.test(f))) {
      const jaFile = zip.file(enPath.replace(/Messages\.properties$/, 'Messages_ja_JP.properties'));
      if (!jaFile) continue;
      // .properties files are ISO-8859-1 with \u escapes.
      const en = parseProperties(Buffer.from(await zip.file(enPath).async('uint8array')).toString('latin1'));
      const ja = parseProperties(Buffer.from(await jaFile.async('uint8array')).toString('latin1'));
      for (const [key, enText] of en) {
        const kind = PROSE_KEY_RE.test(key) ? 'prose' : TITLE_KEY_RE.test(key) ? 'title' : null;
        if (!kind || !ja.has(key)) continue;
        used = true;
        take(enText, ja.get(key), kind);
      }
    }
    if (used) report.addOns++;
  }
  report.pairs = entries.size;
  const sortedEntries = Object.fromEntries([...entries].sort(([a], [b]) => a.localeCompare(b)));
  return {
    catalog: { format: CATALOG_FORMAT, source, entries: sortedEntries },
    report,
  };
}

module.exports = {
  buildCatalog,
  alignText,
  parseProperties,
  parseVulnerabilitiesXml,
  catalogKey,
  maskLike,
  addOnVersion,
  CATALOG_FORMAT,
};
