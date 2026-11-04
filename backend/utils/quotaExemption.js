'use strict';

/**
 * Platform superadmins scan without plan restrictions: no quota check, no
 * charge, no organization required, every severity shown, no schedule cap and
 * no scan-start rate limit.
 *
 * Keyed on User.systemRole, never on the org-level `role`: an org owner is a
 * customer, and only grantSystemRole.js (audited) can make a superadmin.
 * Plain `admin` accounts are deliberately NOT exempt.
 *
 * Every place that limits scans asks this one function, so the rule cannot
 * drift between the interactive routes, the scheduler and billing.
 *
 * @param {{systemRole?: string}|null|undefined} user
 * @returns {boolean}
 */
function isQuotaExempt(user) {
  return Boolean(user && user.systemRole === 'superadmin');
}

module.exports = { isQuotaExempt };
