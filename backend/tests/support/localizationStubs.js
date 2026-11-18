'use strict';

/**
 * Test doubles for report localization (no network, no database).
 *
 *  - memoryTranslationModel(): stands in for models/ReportTranslation.js with the
 *    query shapes the engine uses (find/select/maxTimeMS/lean, bulkWrite with
 *    $setOnInsert first-writer-wins semantics, updateMany). Rows are inspectable.
 *  - fakeJapanese(text): a deterministic "translation" into Japanese — every
 *    ordinary English word becomes Japanese, placeholders and approved technical
 *    terms are kept — so pipelines can be exercised without a model.
 *  - memoryStore(): the engine's store interface over a Map, for createLocalizer.
 */

const { isApprovedWord } = require('../../i18n/languageAudit');

function fakeJapanese(text) {
  return String(text).split(/(\{\{T\d+\}\})/).map(part => (/^\{\{T\d+\}\}$/.test(part) ? part
    : part.replace(/[A-Za-z][A-Za-z'’-]*/g, w => (isApprovedWord(w) ? w : '訳語'))
          .replace(/\.(\s|$)/g, '。$1'))).join('');
}

function memoryTranslationModel() {
  const rows = new Map();
  const model = {
    rows,
    writes: 0,
    find(filter) {
      const ids = filter?._id?.$in || [];
      const result = ids.filter(id => rows.has(id)).map(id => ({ _id: id, translation: rows.get(id).translation }));
      const chain = { select: () => chain, maxTimeMS: () => chain, lean: async () => result };
      return chain;
    },
    async bulkWrite(ops) {
      for (const op of ops) {
        const { filter, update } = op.updateOne;
        model.writes++;
        if (!rows.has(filter._id)) rows.set(filter._id, { ...update.$setOnInsert });
      }
      return { ok: 1 };
    },
    updateMany() { return Promise.resolve({ ok: 1 }); },
  };
  return model;
}

function memoryStore() {
  const rows = new Map();
  return {
    rows,
    async getMany(ids) { return new Map(ids.filter(id => rows.has(id)).map(id => [id, rows.get(id)])); },
    async putIfAbsent(list) { for (const r of list) if (!rows.has(r.id)) rows.set(r.id, r.translation); },
    touch() {},
  };
}

module.exports = { fakeJapanese, memoryTranslationModel, memoryStore };
