/**
 * backend/utils/monthlyUsage.js
 *
 * An organization's subscription usage for the current billing month.
 *
 * services/planService.js resets `scansUsed` lazily — only when the org next
 * scans, if `lastScanReset` falls in an earlier UTC month. Until then the stored
 * figure is last month's. Displays must use this instead of the raw field; it
 * applies the same UTC-month rule, so it is exactly what planService would read
 * if the org scanned now. Pure and dependency-free.
 */

const startOfUtcMonth = (now = new Date()) =>
  new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));

/** True when the org's counters were last reset in the current UTC month. */
function countersAreCurrent(org, now = new Date()) {
  if (!org || !org.lastScanReset) return false;
  const last = new Date(org.lastScanReset);
  return last.getUTCFullYear() === now.getUTCFullYear() && last.getUTCMonth() === now.getUTCMonth();
}

function scansUsedThisMonth(org, now = new Date()) {
  return countersAreCurrent(org, now) ? (org.scansUsed || 0) : 0;
}

module.exports = { startOfUtcMonth, countersAreCurrent, scansUsedThisMonth };
