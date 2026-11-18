'use strict';

/**
 * Run-time lookup into i18n/zapCatalog.ja.json — the scanner's own reviewed
 * Japanese text for its alerts, aligned line by line with the English text
 * (built by scripts/buildZapJaCatalog.js from the pinned ZAP image; see
 * i18n/zapCatalogBuild.js for what is kept).
 *
 * Lookup is by (kind, masked English line): the value is the Japanese line in the
 * same masked form, so the caller restores the literals exactly as for a model
 * translation. The caller still validates every hit (validateTranslation), so a
 * stricter language audit later can never let a catalog line through unchecked.
 */

const { catalogKey } = require('./zapCatalogBuild');

let entries = null;
function load() {
  if (entries) return entries;
  try {
    entries = require('./zapCatalog.ja.json').entries || {};
  } catch {
    entries = {};
  }
  return entries;
}

/** Masked Japanese line for a masked English line, or null. */
function catalogTranslation(kind, masked) {
  const e = load();
  return Object.prototype.hasOwnProperty.call(e, catalogKey(kind, masked)) ? e[catalogKey(kind, masked)] : null;
}

module.exports = { catalogTranslation, catalogSize: () => Object.keys(load()).length };
