'use strict';

/**
 * Regenerate i18n/zapCatalog.ja.json from the pinned ZAP image (local use only).
 *
 *   # 1. copy the add-ons out of the pinned image
 *   cid=$(docker create ghcr.io/zaproxy/zaproxy@sha256:<digest from infrastructure/zap-task-def.json>)
 *   docker cp $cid:/zap/plugin <dir> && docker rm $cid
 *   # 2. build
 *   node scripts/buildZapJaCatalog.js <dir>/plugin [--check]
 *
 * --check: build in memory and exit 1 if the checked-in file differs (no write).
 *
 * Reads only the scanner's public message bundles; no network, no database, no
 * model. Prints counts only. See i18n/zapCatalogBuild.js for what is kept.
 */

const fs = require('fs');
const path = require('path');

require('../utils/logRedaction').install(); // before anything that logs (utils/logRedaction.js)

const JSZip = require('jszip');
const { buildCatalog } = require('../i18n/zapCatalogBuild');
const { validateTranslation } = require('../services/reportLocalization');

const BACKEND = path.join(__dirname, '..');
const OUT = path.join(BACKEND, 'i18n/zapCatalog.ja.json');

async function main() {
  const dir = process.argv[2];
  const check = process.argv.includes('--check');
  if (!dir) { process.stderr.write('usage: node scripts/buildZapJaCatalog.js <zap plugin dir> [--check]\n'); process.exit(2); }

  let image = null;
  try {
    const td = JSON.parse(fs.readFileSync(path.join(BACKEND, '../infrastructure/zap-task-def.json'), 'utf8'));
    image = td.containerDefinitions?.[0]?.image || null;
  } catch { image = null; }

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.zap'));
  const addOns = [];
  for (const name of files) {
    addOns.push({ name, zip: await JSZip.loadAsync(fs.readFileSync(path.join(dir, name))) });
  }
  const { catalog, report } = await buildCatalog(addOns, { validate: validateTranslation, source: { image } });
  const text = `${JSON.stringify(catalog, null, 1)}\n`;

  process.stdout.write(`add-on files: ${files.length}, add-ons with Japanese: ${report.addOns}, texts: ${report.texts}, ` +
    `catalog lines: ${report.pairs}\nrejected: ${JSON.stringify(report.rejected)}\n`);

  if (check) {
    const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
    if (current !== text) { process.stdout.write('zapCatalog.ja.json is out of date\n'); process.exit(1); }
    process.stdout.write('zapCatalog.ja.json is up to date\n');
    return;
  }
  fs.writeFileSync(OUT, text);
  process.stdout.write(`wrote ${path.relative(BACKEND, OUT)} (${Buffer.byteLength(text)} bytes)\n`);
}

main().catch((err) => { process.stderr.write(`failed: ${err?.name || 'Error'}\n`); process.exit(1); });
