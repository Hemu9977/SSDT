'use strict';

/**
 * A small in-memory stand-in for Mongoose models, for tests that EXECUTE route
 * handlers. Query matching is done by `sift` (MongoDB query semantics; it is a
 * dependency of mongoose itself), so filters such as $in/$nin/$or/$regex/$exists
 * behave as they would against MongoDB. Only the API surface the admin routes,
 * auth middleware, subscription lifecycle and cleanup service use is modelled.
 *
 * Not a database: no indexes, no transactions, single process. Good enough to
 * prove what a handler reads, writes and returns.
 */

const path = require('node:path');
const mongoose = require('mongoose');
const sift = require('sift').default || require('sift');

const isObjectId = (v) => v instanceof mongoose.Types.ObjectId || (v && v._bsontype === 'ObjectId');

/** ObjectIds → hex strings, recursively, so sift compares ids by value. */
function norm(v) {
  if (isObjectId(v)) return v.toHexString();
  if (Array.isArray(v)) return v.map(norm);
  if (v instanceof Date || v instanceof RegExp || v === null || typeof v !== 'object') return v;
  const out = {};
  for (const [k, val] of Object.entries(v)) out[k] = norm(val);
  return out;
}

const matcher = (filter) => {
  const test = sift(norm(filter || {}));
  return (doc) => test(norm(doc));
};

const getPath = (obj, p) => p.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
const setPath = (obj, p, value) => {
  const keys = p.split('.');
  let o = obj;
  keys.slice(0, -1).forEach((k) => { if (o[k] == null || typeof o[k] !== 'object') o[k] = {}; o = o[k]; });
  o[keys[keys.length - 1]] = value;
};
const unsetPath = (obj, p) => {
  const keys = p.split('.');
  const parent = keys.slice(0, -1).reduce((o, k) => (o == null ? undefined : o[k]), obj);
  if (parent) delete parent[keys[keys.length - 1]];
};

function applyUpdate(doc, update) {
  const ops = Object.keys(update).some((k) => k.startsWith('$')) ? update : { $set: update };
  for (const [k, v] of Object.entries(ops.$set || {})) setPath(doc, k, v);
  for (const [k, v] of Object.entries(ops.$inc || {})) setPath(doc, k, (getPath(doc, k) || 0) + v);
  for (const k of Object.keys(ops.$unset || {})) unsetPath(doc, k);
}

function project(doc, selection) {
  if (!selection) return { ...doc };
  let include = [];
  let exclude = [];
  if (typeof selection === 'string') {
    selection.split(/\s+/).filter(Boolean).forEach((f) => (f.startsWith('-') ? exclude.push(f.slice(1)) : include.push(f)));
  } else {
    Object.entries(selection).forEach(([f, on]) => (on ? include.push(f) : exclude.push(f)));
  }
  if (include.length) {
    const out = { _id: doc._id };
    include.forEach((f) => { if (doc[f] !== undefined) out[f] = doc[f]; });
    return out;
  }
  const out = { ...doc };
  exclude.forEach((f) => delete out[f]);
  return out;
}

function evalExpr(expr, doc) {
  if (expr === null || expr === undefined) return null;
  if (typeof expr === 'string' && expr.startsWith('$')) return getPath(doc, expr.slice(1)) ?? null;
  if (typeof expr === 'object' && expr.$dateToString) {
    const d = getPath(doc, expr.$dateToString.date.slice(1));
    return d ? new Date(d).toISOString().slice(0, 10) : null;
  }
  if (typeof expr === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(expr)) out[k] = evalExpr(v, doc);
    return out;
  }
  return expr;
}

function makeModel(name, { defaults = () => ({}), refs = {} } = {}) {
  const store = [];
  const failures = new Set(); // method names that throw (simulated DB error)
  const calls = [];

  const fail = (method) => {
    calls.push(method);
    if (failures.has(method) || failures.has('*')) throw new Error(`${name}.${method}: simulated database failure`);
  };

  const wrap = (stored) => {
    if (!stored) return null;
    const doc = { ...stored };
    Object.defineProperty(doc, 'id', { get() { return String(doc._id); }, enumerable: false });
    Object.defineProperty(doc, 'save', {
      enumerable: false,
      value: async () => {
        fail('save');
        const target = store.find((d) => String(d._id) === String(doc._id));
        Object.keys(doc).forEach((k) => { target[k] = doc[k]; });
        return doc;
      },
    });
    return doc;
  };

  class Query {
    constructor(filter, projection, single) {
      this.filter = filter; this.selection = projection; this.single = single;
      this.sorting = null; this.skipN = 0; this.limitN = null; this.pops = []; this.isLean = false;
    }
    sort(s) { this.sorting = s; return this; }
    skip(n) { this.skipN = n; return this; }
    limit(n) { this.limitN = n; return this; }
    select(s) { this.selection = s; return this; }
    populate(p, fields) { this.pops.push([p, fields]); return this; }
    lean() { this.isLean = true; return this; }
    async exec() {
      fail(this.single ? 'findOne' : 'find');
      let rows = store.filter(matcher(this.filter));
      if (this.sorting) {
        const [[field, dir]] = Object.entries(this.sorting);
        rows = [...rows].sort((a, b) => ((getPath(a, field) > getPath(b, field) ? 1 : -1) * dir));
      }
      rows = rows.slice(this.skipN, this.limitN == null ? undefined : this.skipN + this.limitN);
      let out = rows.map((d) => project(d, this.selection));
      for (const [p, fields] of this.pops) {
        const ref = refs[p] && refs[p]();
        out = out.map((d) => {
          if (!ref || d[p] == null) return d;
          const hit = ref._store.find((r) => String(r._id) === String(d[p]));
          return { ...d, [p]: hit ? project(hit, fields) : null };
        });
      }
      if (this.single) {
        const first = out[0] || null;
        return this.isLean ? first : wrap(first);
      }
      return this.isLean ? out : out.map(wrap);
    }
    then(res, rej) { return this.exec().then(res, rej); }
    catch(f) { return this.exec().catch(f); }
  }

  const model = {
    modelName: name,
    _store: store,
    _failures: failures,
    _calls: calls,
    _reset() { store.length = 0; failures.clear(); calls.length = 0; },
    _insert(...docs) {
      docs.forEach((d) => store.push({ _id: new mongoose.Types.ObjectId(), ...defaults(), ...d }));
      return store[store.length - 1];
    },
    _get(id) { return store.find((d) => String(d._id) === String(id)); },

    find: (filter, projection) => new Query(filter, projection, false),
    findOne: (filter, projection) => new Query(filter, projection, true),
    findById: (id, projection) => new Query({ _id: id }, projection, true),
    async countDocuments(filter) { fail('countDocuments'); return store.filter(matcher(filter)).length; },
    async create(obj) {
      fail('create');
      const doc = { _id: new mongoose.Types.ObjectId(), ...defaults(), ...obj };
      store.push(doc);
      return wrap(doc);
    },
    async updateOne(filter, update) {
      fail('updateOne');
      const doc = store.find(matcher(filter));
      if (!doc) return { matchedCount: 0, modifiedCount: 0 };
      applyUpdate(doc, update);
      return { matchedCount: 1, modifiedCount: 1 };
    },
    async updateMany(filter, update) {
      fail('updateMany');
      const docs = store.filter(matcher(filter));
      docs.forEach((d) => applyUpdate(d, update));
      return { matchedCount: docs.length, modifiedCount: docs.length };
    },
    async findOneAndUpdate(filter, update) {
      fail('findOneAndUpdate');
      const doc = store.find(matcher(filter));
      if (!doc) return null;
      applyUpdate(doc, update);
      return wrap(doc);
    },
    async deleteOne(filter) {
      fail('deleteOne');
      const i = store.findIndex(matcher(filter));
      if (i >= 0) store.splice(i, 1);
      return { deletedCount: i >= 0 ? 1 : 0 };
    },
    async deleteMany(filter) {
      fail('deleteMany');
      const keep = store.filter((d) => !matcher(filter)(d));
      const n = store.length - keep.length;
      store.length = 0; store.push(...keep);
      return { deletedCount: n };
    },
    async aggregate(pipeline) {
      fail('aggregate');
      let rows = [...store];
      for (const stage of pipeline) {
        if (stage.$match) rows = rows.filter(matcher(stage.$match));
        else if (stage.$group) {
          const { _id: keyExpr, ...accs } = stage.$group;
          const groups = new Map();
          for (const d of rows) {
            const key = evalExpr(keyExpr, d);
            const k = JSON.stringify(key);
            if (!groups.has(k)) groups.set(k, { _id: key, ...Object.fromEntries(Object.keys(accs).map((a) => [a, 0])) });
            const g = groups.get(k);
            for (const [a, spec] of Object.entries(accs)) g[a] += spec.$sum === 1 ? 1 : Number(evalExpr(spec.$sum, d) || 0);
          }
          rows = [...groups.values()];
        } else if (stage.$sort) {
          const [[field, dir]] = Object.entries(stage.$sort);
          rows.sort((a, b) => ((a[field] > b[field] ? 1 : -1) * dir));
        }
      }
      return rows;
    },
  };
  return model;
}

/** Register `exports` as the module at backend/<rel> before anything requires it. */
function stubModule(backendDir, rel, exportsValue) {
  const file = path.join(backendDir, rel);
  require.cache[file] = { id: file, filename: file, loaded: true, exports: exportsValue };
}

/** Pull the terminal handler for METHOD path off an Express router. */
function handlerFor(router, method, routePath) {
  const layer = router.stack.find((l) => l.route && l.route.path === routePath && l.route.methods[method]);
  if (!layer) throw new Error(`route ${method.toUpperCase()} ${routePath} not registered`);
  return layer.route.stack[layer.route.stack.length - 1].handle;
}

/** Invoke a handler and capture its response. */
async function invoke(handler, req) {
  let status = 200;
  let body = null;
  const res = {
    status(c) { status = c; return this; },
    json(b) { body = b; return this; },
  };
  await handler({ params: {}, query: {}, body: {}, ip: '127.0.0.1', get: () => 'node-test', ...req }, res, () => {});
  return { status, body };
}

module.exports = { makeModel, stubModule, handlerFor, invoke, norm };
