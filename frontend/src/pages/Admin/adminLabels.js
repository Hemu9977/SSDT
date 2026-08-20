// frontend/src/pages/Admin/adminLabels.js
// Single source of truth for mapping backend enum values (plan type, scan status,
// subscription status, system role, health status) to translation keys.
// AdminUsers, AdminOrganizations, AdminScans, AdminOverview, and AdminSystemHealth
// all render the same enums — centralizing this here means a translator only has
// to update one place, and no component can silently render a raw English enum
// value instead of going through t().

const PLAN_KEYS = {
  free: 'adminFree',
  light: 'adminLight',
  basic: 'adminBasic',
  pro: 'adminPro',
  trial1: 'adminTrial1',
  trial2: 'adminTrial2',
};

export const getPlanLabel = (t, plan) => t(PLAN_KEYS[plan] || PLAN_KEYS.free);

const SCAN_STATUS_KEYS = {
  queued: 'adminQueuedStatus',
  pending: 'adminPendingStatus',
  combining: 'adminCombiningStatus',
  completed: 'adminCompletedStatus',
  failed: 'adminFailedStatus',
  stopped: 'adminStoppedStatus',
};

export const getScanStatusLabel = (t, status) => (
  SCAN_STATUS_KEYS[status] ? t(SCAN_STATUS_KEYS[status]) : (status || '—')
);

const SUBSCRIPTION_STATUS_KEYS = {
  active: 'adminActive',
  canceled: 'adminCanceled',
  past_due: 'adminPastDue',
  trialing: 'adminTrialing',
};

export const getSubscriptionStatusLabel = (t, status) => (
  SUBSCRIPTION_STATUS_KEYS[status] ? t(SUBSCRIPTION_STATUS_KEYS[status]) : null
);

const SYSTEM_ROLE_KEYS = {
  admin: 'adminRoleAdmin',
  superadmin: 'adminRoleSuperadmin',
};

export const getSystemRoleLabel = (t, systemRole) => (
  SYSTEM_ROLE_KEYS[systemRole] ? t(SYSTEM_ROLE_KEYS[systemRole]) : systemRole
);

// Organization-level role (owner/admin/member) — a separate concept from the
// platform-level systemRole above, but "Admin" reads the same in either context.
const ORG_ROLE_KEYS = {
  owner: 'adminOwner',
  admin: 'adminRoleAdmin',
  member: 'adminMember',
};

export const getOrgRoleLabel = (t, role) => (
  ORG_ROLE_KEYS[role] ? t(ORG_ROLE_KEYS[role]) : (role || '—')
);

const HEALTH_STATUS_KEYS = {
  online: 'adminOnline',
  configured: 'adminConfigured',
  offline: 'adminOffline',
  not_configured: 'adminNotConfigured',
};

export const getHealthStatusLabel = (t, status) => (
  HEALTH_STATUS_KEYS[status] ? t(HEALTH_STATUS_KEYS[status]) : (status || '—')
);

const CONNECTION_STATE_KEYS = {
  connected: 'adminConnected',
  disconnected: 'adminDisconnected',
  connecting: 'adminConnecting',
  disconnecting: 'adminDisconnecting',
};

export const getConnectionStateLabel = (t, state) => (
  CONNECTION_STATE_KEYS[state] ? t(CONNECTION_STATE_KEYS[state]) : state
);

// ── Backend error codes → translation keys ───────────────────────────────────
// Same rule as the enums above, applied to failures: the API's `error`/`message`
// strings are English-only server-log text (and name internal concepts), so they
// must never reach the UI. Every admin endpoint returns a stable `code`; this is
// the only place that maps one to a user-facing string.
const ERROR_KEYS = {
  ACCOUNT_DISABLED:          'adminErrAccountDisabled',
  UNAUTHORIZED:              'adminErrUnauthorized',
  FORBIDDEN:                 'adminErrForbidden',
  SERVER_ERROR:              'adminErrServer',
  ADMIN_SUPERADMIN_REQUIRED: 'adminErrSuperadminRequired',
  ADMIN_INVALID_ID:          'adminErrInvalidId',
  ADMIN_USER_NOT_FOUND:      'adminErrUserNotFound',
  ADMIN_ORG_NOT_FOUND:       'adminErrOrgNotFound',
  ADMIN_INVALID_ROLE:        'adminErrInvalidRole',
  ADMIN_INVALID_PAYLOAD:     'adminErrInvalidPayload',
  ADMIN_SELF_ROLE:           'adminErrSelfRole',
  ADMIN_SELF_DISABLE:        'adminErrSelfDisable',
  ADMIN_SELF_DELETE:         'adminErrSelfDelete',
  ADMIN_LAST_ADMIN:          'adminErrLastAdmin',
  ADMIN_NO_ORG:              'adminErrNoOrg',
  ADMIN_OWNER_PROTECTED:     'adminErrOwnerProtected',
  ADMIN_NO_SUBSCRIPTION:     'adminErrNoSubscription',
  ADMIN_FETCH_FAILED:        'adminFetchError',
  ADMIN_ACTION_FAILED:       'adminActionFailed',
};

/**
 * Resolve a thrown adminService error to a translated string.
 * `fallbackKey` covers network failures and any code not yet mapped — the raw
 * server text is never used, only logged by the caller if needed.
 */
export const getAdminErrorLabel = (t, err, fallbackKey = 'adminFetchError') => {
  const key = err && err.code && ERROR_KEYS[err.code];
  return t(key || fallbackKey);
};
