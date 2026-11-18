'use strict';

/**
 * Persistent store of validated report translations (services/reportLocalization.js).
 *
 * What a row holds
 *  - `_id`: sha256(ENGINE_VERSION ‖ lang ‖ kind ‖ masked source), kind = title | prose.
 *    The source text itself is NOT stored, and the source is masked before hashing
 *    (i18n/protectTokens.js), so no URL, host, email, credential or other scan value
 *    is ever persisted.
 *  - `translation`: the validated translation of the masked text. It contains
 *    {{Tn}} placeholders, never the values they stand for; those are put back in
 *    memory for each report.
 *
 * Writes are immutable and atomic
 *  - A row is written only after it passed validation, with
 *    updateOne({ _id }, { $setOnInsert }, { upsert: true }). The first writer wins
 *    and a row is never overwritten. Concurrent upserts of the same _id (two
 *    backend tasks, or two PDF jobs) can raise E11000; that is treated as success.
 *  - After writing, the engine re-reads the stored rows and uses them, so every
 *    task converges on the same text even when two tasks translated the same unit
 *    at once (the only cost is a duplicate model call).
 *  - A reader therefore sees either no row or a complete, validated row. The engine
 *    also re-validates every row it reads, and ignores one that no longer passes.
 *
 * Invalidation
 *  - ENGINE_VERSION hashes the model id, system instructions, glossary, response
 *    schema, scrubber patterns and audit allowlist. Changing any of them changes
 *    every _id, so old rows are never read again; they age out through the TTL.
 *    During a rolling deploy old and new tasks never read each other's rows.
 *
 * Retention (MongoDB TTL)
 *  - TTL index on `lastUsedAt`, 180 days. A cache hit refreshes `lastUsedAt` at most
 *    once a day (fire-and-forget), so a row is kept at least ~179 days after it was
 *    last used.
 *  - MongoDB's TTL monitor runs about every 60 seconds and deletes in batches, so a
 *    row can outlive its expiry by minutes (longer under load). Expiry is a lower
 *    bound on retention, never an exact time.
 *  - Correctness never depends on a row being present: a missing row only means the
 *    unit is translated again.
 */

const mongoose = require('mongoose');

const RETENTION_DAYS = 180;

const reportTranslationSchema = new mongoose.Schema({
  _id:           { type: String, required: true },
  lang:          { type: String, required: true, enum: ['en', 'ja'] },
  translation:   { type: String, required: true },
  engineVersion: { type: String, required: true },
  createdAt:     { type: Date, default: Date.now },
  lastUsedAt:    { type: Date, default: Date.now },
}, { versionKey: false, collection: 'report_translations' });

reportTranslationSchema.index({ lastUsedAt: 1 }, { expireAfterSeconds: RETENTION_DAYS * 24 * 60 * 60 });

const ReportTranslation = mongoose.models.ReportTranslation
  || mongoose.model('ReportTranslation', reportTranslationSchema);

module.exports = ReportTranslation;
module.exports.RETENTION_DAYS = RETENTION_DAYS;
