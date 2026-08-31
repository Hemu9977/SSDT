// frontend/src/utils/apiErrors.js
//
// Backend `message`/`error` strings are English-only server-log text and must
// never be rendered (CLAUDE.md). Every API response carries a stable `code`
// instead; this is the single place that turns one into a user-facing string.
//
// Same rule and shape as pages/Admin/adminLabels.js, which does this for the
// admin API — this generalises it to the rest of the app.

const CODE_KEYS = {
  // ── Session / account ──────────────────────────────────────────────────────
  ACCOUNT_DISABLED: 'errAccountDisabled',
  SESSION_REVOKED: 'errSessionRevoked',
  AUTH_RESET_TOKEN_INVALID: 'errAuthResetTokenInvalid',
  TOO_MANY_REQUESTS: 'errTooManyRequests',
  UNAUTHORIZED: 'errUnauthorized',
  FORBIDDEN: 'errForbidden',
  SERVER_ERROR: 'errServer',

  // ── Authentication ─────────────────────────────────────────────────────────
  AUTH_NO_TOKEN: 'errAuthNoToken',
  AUTH_GOOGLE_FAILED: 'errAuthGoogleFailed',
  AUTH_GOOGLE_SUCCESS: 'errAuthGoogleSuccess',
  AUTH_NAME_REQUIRED: 'errAuthNameRequired',
  AUTH_EMAIL_INVALID: 'errAuthEmailInvalid',
  AUTH_PASSWORD_REQUIRED: 'errAuthPasswordRequired',
  AUTH_PASSWORD_TOO_SHORT: 'errAuthPasswordTooShort',
  AUTH_USER_EXISTS: 'errAuthUserExists',
  AUTH_REGISTERED: 'errAuthRegistered',
  AUTH_INVALID_CREDENTIALS: 'errAuthInvalidCredentials',
  AUTH_LOGIN_SUCCESS: 'errAuthLoginSuccess',
  AUTH_OTP_SENT: 'errAuthOtpSent',
  AUTH_OTP_FORMAT: 'errAuthOtpFormat',
  AUTH_OTP_INVALID: 'errAuthOtpInvalid',
  AUTH_RESET_EMAIL_SENT: 'errAuthResetEmailSent',
  AUTH_PASSWORD_RESET: 'errAuthPasswordReset',

  // ── Plan / quota (middleware/planCheck.js) ─────────────────────────────────
  // A 401 here means the account row is gone: treat it as a dead session.
  USER_NOT_FOUND: 'errUnauthorized',
  ORG_CREATING: 'errOrgCreating',
  PLAN_CHECK_ERROR: 'errPlanCheckFailed',
  // These two already have long-standing keys; map them so call sites can drop
  // their hand-rolled if-chains and go through this table instead.
  PLAN_LIMIT_EXCEEDED: 'planLimitReached',
  NO_ORGANIZATION: 'organizationRequired',

  // ── Billing (routes/stripeRoutes.js) ───────────────────────────────────────
  INSUFFICIENT_ROLE: 'errInsufficientRole',
  ALREADY_SUBSCRIBED: 'errAlreadySubscribed',
  TAX_NOT_CONFIGURED: 'billingUnavailable',

  // ── Authenticated scanning (routes/zapAuthRoutes.js) ───────────────────────
  SESSION_EXPIRED: 'sessionExpiredTestAgain',

  // ── Organizations & invites ────────────────────────────────────────────────
  ORG_NOT_FOUND: 'errOrgNotFound',
  ORG_NO_MEMBERSHIP: 'errOrgNoMembership',
  ORG_EMAIL_REQUIRED: 'errOrgEmailRequired',
  ORG_ROLE_INVALID: 'errOrgRoleInvalid',
  ORG_INVITE_FORBIDDEN: 'errOrgInviteForbidden',
  ORG_INVITE_ADMIN_FORBIDDEN: 'errOrgInviteAdminForbidden',
  ORG_INVITE_CANCEL_FORBIDDEN: 'errOrgInviteCancelForbidden',
  ORG_INVITE_INVALID: 'errOrgInviteInvalid',
  ORG_INVITE_USED: 'errOrgInviteUsed',
  ORG_INVITE_EXPIRED: 'errOrgInviteExpired',
  ORG_INVITE_NOT_FOUND: 'errOrgInviteNotFound',
  ORG_INVITE_INACTIVE: 'errOrgInviteInactive',
  ORG_INVITE_CANCELLED: 'errOrgInviteCancelled',
  ORG_INVITE_TOKEN_REQUIRED: 'errOrgInviteTokenRequired',
  ORG_INVITE_EMAIL_MISMATCH: 'errOrgInviteEmailMismatch',
  ORG_SEAT_LIMIT: 'errOrgSeatLimit',
  ORG_ALREADY_MEMBER: 'errOrgAlreadyMember',
  ORG_OTHER_ORG_MEMBER: 'errOrgOtherOrgMember',
  ORG_ACCOUNT_EXISTS: 'errOrgAccountExists',
  ORG_SIGNUP_FIELDS_REQUIRED: 'errOrgSignupFieldsRequired',

  // ── Scheduled scans (routes/scheduleRoutes.js) ─────────────────────────────
  INVALID_TIMEZONE: 'errInvalidTimezone',
  NO_UPCOMING_OCCURRENCE: 'errNoUpcomingOccurrence',
  SCHEDULE_CREATE_FAILED: 'failedSaveSchedule',
  SCHEDULE_UPDATE_FAILED: 'failedSaveSchedule',
};

/**
 * Resolve an API response (or a thrown error carrying `.code`) to a translated
 * string.
 *
 * @param {Function} t           translation function
 * @param {Object} source        response body or Error with a `code` property
 * @param {string} fallbackKey   used for network failures and unmapped codes —
 *                               the raw server text is never shown either way
 */
export const getApiErrorLabel = (t, source, fallbackKey = 'errUnexpected') => {
  const code = source && source.code;
  return t((code && CODE_KEYS[code]) || fallbackKey);
};

/** True when the response says this session can never succeed again. */
export const isSessionDead = (status, code) =>
  status === 401 ||
  (status === 403 && (code === 'ACCOUNT_DISABLED' || code === 'SESSION_REVOKED'));

export default getApiErrorLabel;
