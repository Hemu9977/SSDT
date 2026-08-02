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
