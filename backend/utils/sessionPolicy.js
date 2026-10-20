/**
 * backend/utils/sessionPolicy.js
 *
 * Session rules that depend on the account's platform role. Every jwt.sign in
 * the app takes its lifetime from tokenLifetimeFor(), so an administrator's
 * session is never minted with the 7-day customer lifetime.
 */

const ADMIN_ROLES = ['admin', 'superadmin'];

const isPlatformAdmin = (user) => !!user && ADMIN_ROLES.includes(user.systemRole);

// An admin token is a bearer credential for every customer's account and billing,
// so it lives for a working day rather than a week.
const ADMIN_TOKEN_TTL = process.env.ADMIN_TOKEN_TTL || '8h';
const USER_TOKEN_TTL = '7d';

/** `expiresIn` for a token issued to this user. */
function tokenLifetimeFor(user) {
  return isPlatformAdmin(user) ? ADMIN_TOKEN_TTL : USER_TOKEN_TTL;
}

// Destructive admin actions (deleting accounts or organizations, cancelling
// billing, changing admin rights) need a sign-in this recent.
const RECENT_AUTH_MAX_AGE_MS = (Number(process.env.ADMIN_REAUTH_MINUTES) || 15) * 60 * 1000;

module.exports = { ADMIN_ROLES, isPlatformAdmin, tokenLifetimeFor, RECENT_AUTH_MAX_AGE_MS };
