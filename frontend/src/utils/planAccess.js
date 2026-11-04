// frontend/src/utils/planAccess.js
//
// Whether an organization (as returned by GET /api/profile) has a paid plan right
// now, and whether it can scan at all. The backend decides the plan part
// (`organization.entitled`: subscription status AND paid period — see
// backend/utils/entitlement.js), so a cancelled plan stops counting at the exact
// end of its period. Always advisory: the server enforces every limit itself.

/** True while the org's plan grants paid access. */
export const isPlanEntitled = (org) => {
  if (!org || !org.planType) return false;
  // Fallback for a backend that predates `entitled` — the frontend deploys on its own.
  return typeof org.entitled === 'boolean' ? org.entitled : org.subscriptionStatus === 'active';
};

/**
 * True for an account with no scan limit at all — the backend sends
 * `limits.scansPerMonth: -1` only for superadmins (backend/utils/quotaExemption.js),
 * who may scan with no plan and no organization.
 */
export const hasUnlimitedScans = (limits) => Boolean(limits && limits.scansPerMonth === -1);

/**
 * True when the account can start a scan: unlimited, a live plan, or purchased
 * scan credits. `limits` is GET /api/profile's `limits`.
 */
export const hasScanAccess = (org, limits = null) =>
  hasUnlimitedScans(limits) || isPlanEntitled(org) || Boolean(org && org.extraScansRemaining > 0);
