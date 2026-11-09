'use strict';

/**
 * In-memory store for HTTP Basic Auth credentials, for the life of one scan.
 *
 * WHY IN MEMORY ONLY
 * Basic Auth scans are manual-only, so nothing ever needs the credential after
 * the scan ends. It is never written to MongoDB, Redis, GridFS or a log. A process
 * restart loses it — and the scan then fails closed rather than continuing
 * unauthenticated (zapAuthService / authFastScanService check for it).
 *
 * WHY HOLDERS
 * Two independent parts of a scan use the credential: the ZAP leg (Replacer rule)
 * and the fast scanners (in-house page capture and performance audit). Either can
 * finish first. The entry is removed when the last holder releases it, on
 * `purge` (cancellation, provisioning failure, watchdog), or when its TTL expires.
 *
 * Single process: the backend runs one ECS task with no autoscaling (verified
 * 2026-11-08). The existing `authSessions` map in zapAuthRoutes makes the same
 * assumption. A second backend task would need sticky routing or a shared store.
 */

const util = require('util');
const { secretVariants } = require('../utils/credentialRedaction');

const DEFAULT_HOLDERS = ['zap', 'fast'];
// Longer than the 24 h ZAP stale-scan watchdog, so the watchdog — not the TTL —
// is what normally ends a hung scan; the TTL is the backstop.
const DEFAULT_TTL_MS = 25 * 60 * 60 * 1000;
const SWEEP_MS = 5 * 60 * 1000;

let now = () => Date.now();
const entries = new Map();

/** A credential that refuses to be printed. */
class BasicCredential {
  #username; #password;
  constructor({ username, password, origin }) {
    this.#username = username;
    this.#password = password;
    this.origin = origin;
    Object.freeze(this);
  }
  get username() { return this.#username; }
  get password() { return this.#password; }
  /** `Basic <base64(user:password)>` */
  get authorization() { return `Basic ${Buffer.from(`${this.#username}:${this.#password}`, 'utf8').toString('base64')}`; }
  /** Every form of the secret, for scrubbing scanner output. */
  get secrets() { return secretVariants({ username: this.#username, password: this.#password }); }
  toJSON() { return { origin: this.origin, credential: '[REDACTED]' }; }
  [util.inspect.custom]() { return `BasicCredential { origin: ${this.origin}, credential: [REDACTED] }`; }
  toString() { return '[BasicCredential REDACTED]'; }
}

function expired(e) { return e.expiresAt <= now(); }

/**
 * Store a scan's credential.
 * @param {string} scanId
 * @param {{username:string, password:string, origin:string}} cred
 * @param {{holders?: string[], ttlMs?: number}} [opts]
 */
function put(scanId, cred, { holders = DEFAULT_HOLDERS, ttlMs = DEFAULT_TTL_MS } = {}) {
  if (!scanId) throw new Error('scanId required');
  if (!cred || typeof cred.username !== 'string' || typeof cred.password !== 'string' || !cred.origin) {
    throw new Error('username, password and origin required');
  }
  entries.set(String(scanId), {
    credential: new BasicCredential(cred),
    holders: new Set(holders),
    expiresAt: now() + ttlMs
  });
}

/** @returns {BasicCredential|null} */
function get(scanId) {
  const e = entries.get(String(scanId));
  if (!e) return null;
  if (expired(e)) { entries.delete(String(scanId)); return null; }
  return e.credential;
}

function has(scanId) { return get(scanId) !== null; }

/** Drop one holder; the entry goes when the last holder is released. */
function release(scanId, holder) {
  const key = String(scanId);
  const e = entries.get(key);
  if (!e) return false;
  e.holders.delete(holder);
  if (e.holders.size === 0 || expired(e)) entries.delete(key);
  return true;
}

/** Remove the entry regardless of holders (cancel, failure, watchdog). */
function purge(scanId) { return entries.delete(String(scanId)); }

function sweep() {
  let removed = 0;
  for (const [k, e] of entries) if (expired(e)) { entries.delete(k); removed++; }
  return removed;
}

const timer = setInterval(sweep, SWEEP_MS);
if (typeof timer.unref === 'function') timer.unref();

module.exports = {
  put, get, has, release, purge, sweep,
  size: () => entries.size,
  DEFAULT_TTL_MS,
  // Tests only.
  _setClock(fn) { now = fn || (() => Date.now()); },
  _clear() { entries.clear(); },
};
