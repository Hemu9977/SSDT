// frontend/src/utils/authRedirect.js
// Shared post-authentication routing rules.
//
// Both the login flows and the /admin route guard need the same notion of "is
// this a platform administrator". Keeping it here means the role list is
// defined once — a fourth copy drifting out of sync is exactly how a user ends
// up with a nav link to a page that then bounces them.

export const ADMIN_ROLES = ['admin', 'superadmin'];

/** True when the user holds a platform-level admin role. */
export const isSystemAdmin = (user) =>
  Boolean(user && ADMIN_ROLES.includes(user.systemRole));

/**
 * Where to send a user immediately after a successful login.
 * Administrators land on the admin dashboard; everyone else goes to the
 * landing page, which is where login has always sent them.
 */
export const postLoginTarget = (user) => (isSystemAdmin(user) ? '/admin' : '/');
