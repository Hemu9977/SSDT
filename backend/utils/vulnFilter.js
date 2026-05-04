'use strict';

/**
 * vulnFilter.js — Centralized plan-based vulnerability filter.
 *
 * DESIGN PRINCIPLES
 *  - Pure function: no DB calls, no side-effects, deterministic.
 *  - Single source of truth: every report surface (API, PDF, AI, export)
 *    MUST call getSanitizedAlerts() before touching alert arrays.
 *  - Default to MOST RESTRICTIVE when plan is unknown/missing.
 *
 * PLAN → ALLOWED SEVERITIES (source of truth from User.js PLAN_LIMITS)
 *
 *   'critical-high'  →  High only
 *                        (ZAP has no "Critical" label; High is the highest)
 *   'all'            →  High, Medium, Low, Informational
 *
 * Called with a vulnerabilityAccessLevel string that comes from
 * User.getAccountLimits().vulnerabilityAccessLevel.
 */

// Canonical severity labels as produced by OWASP ZAP (case-sensitive).
// ZAP never emits "Critical", so the "critical-high" tier maps to "High" only.
const ALLOWED_SEVERITIES = {
  'all':           ['High', 'Medium', 'Low', 'Informational'],
  'critical-high': ['High'],
};

// Default when the access level is unknown / missing — most restrictive.
const DEFAULT_LEVEL = 'critical-high';

/**
 * Normalise an access-level string so minor casing/whitespace differences
 * don't accidentally bypass the filter.
 * @param {*} level
 * @returns {'all'|'critical-high'}
 */
function normaliseAccessLevel(level) {
  if (typeof level !== 'string') return DEFAULT_LEVEL;
  const l = level.trim().toLowerCase();
  if (l === 'all') return 'all';
  if (l === 'critical-high' || l === 'criticalhigh' || l === 'critical_high') return 'critical-high';
  // Unknown value → default to most restrictive
  return DEFAULT_LEVEL;
}

/**
 * Normalise a single alert's risk string to a canonical ZAP label so that
 * casing variants ("high", "HIGH", "High") are handled correctly.
 * @param {string|*} risk
 * @returns {string}
 */
function normaliseRisk(risk) {
  if (!risk) return '';
  const r = String(risk).trim().toLowerCase();
  if (r === 'high')          return 'High';
  if (r === 'medium')        return 'Medium';
  if (r === 'low')           return 'Low';
  if (r === 'informational' || r === 'info') return 'Informational';
  return String(risk).trim(); // pass through unchanged (will not match any ALLOWED list)
}

/**
 * Filter an alert array to only those allowed by the given access level.
 *
 * @param {Array}   alerts      — raw ZAP alert objects
 * @param {string}  accessLevel — vulnerabilityAccessLevel from getAccountLimits()
 * @returns {Array}             — filtered copy (never mutates input)
 */
function getSanitizedAlerts(alerts, accessLevel) {
  if (!Array.isArray(alerts)) return [];
  const level   = normaliseAccessLevel(accessLevel);
  const allowed = ALLOWED_SEVERITIES[level];
  return alerts.filter(a => allowed.includes(normaliseRisk(a?.risk)));
}

/**
 * Filter a complete zapData response object (as built by the route handlers)
 * and return a new object with alerts, riskCounts, and totalAlerts recalculated.
 *
 * Mirrors the shape expected by both the frontend and the PDF generator.
 *
 * @param {object|null} zapData     — the zapData object built for the response
 * @param {string}      accessLevel — vulnerabilityAccessLevel
 * @returns {object|null}
 */
function getSanitizedZapData(zapData, accessLevel) {
  if (!zapData) return null;

  const level = normaliseAccessLevel(accessLevel);
  // No filtering needed for full-access plans
  if (level === 'all') return zapData;

  const allowed          = ALLOWED_SEVERITIES[level];
  const filteredAlerts   = (zapData.alerts || []).filter(a => allowed.includes(normaliseRisk(a?.risk)));

  // Rebuild riskCounts to reflect only the allowed severities
  const riskCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const a of filteredAlerts) {
    const r = normaliseRisk(a?.risk);
    if (r in riskCounts) riskCounts[r]++;
  }

  return {
    ...zapData,
    alerts:       filteredAlerts,
    totalAlerts:  filteredAlerts.length,
    riskCounts,
    _filtered:    true, // flag so the frontend can display a plan-restriction note
  };
}

/**
 * Convenience: Given a raw DB zapResult (e.g. scan.zapResult), extract a
 * plan-compliant zapReport object ready to pass to refineReport() or the
 * PDF generator.
 *
 * @param {object|null} zapResult   — scan.zapResult from MongoDB
 * @param {string}      accessLevel — vulnerabilityAccessLevel
 * @param {string}      [target]    — scan target URL (for the 'site' field)
 * @returns {object|null}
 */
function getSanitizedZapReport(zapResult, accessLevel, target = '') {
  if (!zapResult) return null;

  const rawAlerts = Array.isArray(zapResult.alerts) ? zapResult.alerts : [];
  const safe      = getSanitizedAlerts(rawAlerts, accessLevel);

  // Rebuild riskCounts
  const riskCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const a of safe) {
    const r = normaliseRisk(a?.risk);
    if (r in riskCounts) riskCounts[r]++;
  }

  return {
    site:              target || zapResult.site || '',
    riskCounts,
    alerts:            safe,
    totalAlerts:       safe.length,
    totalOccurrences:  safe.reduce((n, a) => n + (a.totalOccurrences || 0), 0),
  };
}

module.exports = {
  getSanitizedAlerts,
  getSanitizedZapData,
  getSanitizedZapReport,
  normaliseAccessLevel,
  normaliseRisk,
  ALLOWED_SEVERITIES,
  DEFAULT_LEVEL,
};
