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

/** True when the org can start a scan: a live plan, or purchased scan credits. */
export const hasScanAccess = (org) =>
  isPlanEntitled(org) || Boolean(org && org.extraScansRemaining > 0);
