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
  // Plan distributions only: a plan is still stored but no longer grants
  // access (expired, past due, canceled — backend planBucket in routes/admin.js).
  lapsed: 'adminPlanLapsed',
};

export const getPlanLabel = (t, plan) => t(PLAN_KEYS[plan] || PLAN_KEYS.free);

const SCAN_STATUS_KEYS = {
  queued: 'adminQueuedStatus',
  pending: 'adminPendingStatus',
  combining: 'adminCombiningStatus',
  completed: 'adminCompletedStatus',
  failed: 'adminFailedStatus',
  stopped: 'adminStoppedStatus',
  cancelled: 'adminCancelledStatus',
};

export const getScanStatusLabel = (t, status) => (
  SCAN_STATUS_KEYS[status] ? t(SCAN_STATUS_KEYS[status]) : (status || '—')
);

// Computed subscription states from the backend (utils/subscriptionState.js),
// which apply the entitlement rules — e.g. 'expired' when the stored status
// still says active but the paid period has passed.
const SUBSCRIPTION_STATUS_KEYS = {
  none: 'adminSubNone',
  onetime: 'adminSubOnetime',
  active: 'adminActive',
  trialing: 'adminTrialing',
  cancelling: 'adminSubCancelling',
  expired: 'adminSubExpired',
  past_due: 'adminPastDue',
  unpaid: 'adminSubUnpaid',
  canceled: 'adminCanceled',
  incomplete: 'adminSubIncomplete',
  incomplete_expired: 'adminSubIncompleteExpired',
  paused: 'adminSubPaused',
};

export const getSubscriptionStatusLabel = (t, status) => (
  SUBSCRIPTION_STATUS_KEYS[status] ? t(SUBSCRIPTION_STATUS_KEYS[status]) : null
);

// Badge class per state, reusing the existing .scan-status palette.
export const SUBSCRIPTION_STATE_CLASS = {
  active: 'completed',
  trialing: 'combining',
  cancelling: 'pending',
  onetime: 'combining',
  expired: 'failed',
  past_due: 'pending',
  unpaid: 'failed',
  canceled: 'failed',
  incomplete: 'pending',
  incomplete_expired: 'failed',
  paused: 'pending',
};

const FAILURE_REASON_KEYS = {
  vulnerability_scan_failed: 'adminFailureVulnScan',
  scan_data_unavailable: 'adminFailureNoData',
  internal_error: 'adminFailureInternal',
};

export const getFailureReasonLabel = (t, reason) => (
  FAILURE_REASON_KEYS[reason] ? t(FAILURE_REASON_KEYS[reason]) : null
);

const AUDIT_ACTION_KEYS = {
  'user.disable': 'adminAuditUserDisable',
  'user.enable': 'adminAuditUserEnable',
  'user.role_change': 'adminAuditUserRoleChange',
  'user.remove_from_org': 'adminAuditUserRemoveFromOrg',
  'user.delete': 'adminAuditUserDelete',
  'org.disable': 'adminAuditOrgDisable',
  'org.enable': 'adminAuditOrgEnable',
  'org.cancel_subscription': 'adminAuditOrgCancelSubscription',
  'org.delete': 'adminAuditOrgDelete',
};

export const getAuditActionLabel = (t, action) => (
  AUDIT_ACTION_KEYS[action] ? t(AUDIT_ACTION_KEYS[action]) : action
);

const AUDIT_RESULT_KEYS = {
  pending: 'adminAuditPending',
  success: 'adminAuditSuccess',
  failure: 'adminAuditFailure',
  denied: 'adminAuditDenied',
};

export const getAuditResultLabel = (t, result) => (
  AUDIT_RESULT_KEYS[result] ? t(AUDIT_RESULT_KEYS[result]) : result
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

// ── System Health ────────────────────────────────────────────────────────────
// The backend (config/healthInventory.js) decides which services exist and what
// each status means; these maps only turn its stable codes into text. An id or
// code without an entry renders as a neutral fallback, never as raw server text.

// Statuses, in the meaning defined by the backend inventory.
const HEALTH_STATUS_KEYS = {
  healthy: 'adminHealthHealthy',
  degraded: 'adminHealthDegraded',
  unavailable: 'adminHealthUnavailable',
  starting: 'adminHealthStarting',
  // Scaled to zero, or nothing queued — on purpose, not a fault.
  idle: 'adminHealthIdle',
  // Configuration present, nothing verified it. Never counted as working.
  configured: 'adminHealthConfigured',
  unknown: 'adminHealthUnknown',
};

export const getHealthStatusLabel = (t, status) => t(HEALTH_STATUS_KEYS[status] || 'adminHealthUnknown');

// Vendor names are kept on purpose: this is internal operator tooling and an
// on-call engineer needs to know which service is down (see N14 in
// docs/ADMIN_PRODUCTION_READINESS_PLAN.md).
const HEALTH_SERVICE_KEYS = {
  api: 'adminHealthSvcApi',
  mongodb: 'adminHealthSvcMongodb',
  redis: 'adminHealthSvcRedis',
  queues: 'adminHealthSvcQueues',
  webcheck: 'adminHealthSvcWebcheck',
  zap: 'adminHealthSvcZap',
  zap_auth: 'adminHealthSvcZapAuth',
  gemini: 'adminHealthSvcGemini',
  pagespeed: 'adminHealthSvcPagespeed',
  observatory: 'adminHealthSvcObservatory',
  urlscan: 'adminHealthSvcUrlscan',
  stripe: 'adminHealthSvcStripe',
  stripe_webhooks: 'adminHealthSvcStripeWebhooks',
  email: 'adminHealthSvcEmail',
  aws_backend: 'adminHealthSvcAwsBackend',
  aws_alarms: 'adminHealthSvcAwsAlarms',
};

export const getHealthServiceLabel = (t, id) => (HEALTH_SERVICE_KEYS[id] ? t(HEALTH_SERVICE_KEYS[id]) : id);

// Reason codes: the server never sends raw error text, only one of these.
const HEALTH_REASON_KEYS = {
  timeout: 'adminHealthReasonTimeout',
  unreachable: 'adminHealthReasonUnreachable',
  http_error: 'adminHealthReasonHttpError',
  auth_failed: 'adminHealthReasonAuthFailed',
  permission_denied: 'adminHealthReasonPermissionDenied',
  credentials: 'adminHealthReasonCredentials',
  not_configured: 'adminHealthReasonNotConfigured',
  misconfigured: 'adminHealthReasonMisconfigured',
  disconnected: 'adminHealthReasonDisconnected',
  not_connected: 'adminHealthReasonNotConnected',
  slow: 'adminHealthReasonSlow',
  event_loop_lag: 'adminHealthReasonEventLoopLag',
  memory_pressure: 'adminHealthReasonMemoryPressure',
  queue_backlog: 'adminHealthReasonQueueBacklog',
  no_workers: 'adminHealthReasonNoWorkers',
  capacity_check_failed: 'adminHealthReasonCapacityCheckFailed',
  no_recent_activity: 'adminHealthReasonNoRecentActivity',
  recent_failures: 'adminHealthReasonRecentFailures',
  quota_exhausted: 'adminHealthReasonQuotaExhausted',
  rate_limited: 'adminHealthReasonRateLimited',
  test_mode_in_production: 'adminHealthReasonTestMode',
  price_inactive: 'adminHealthReasonPriceInactive',
  webhook_failures: 'adminHealthReasonWebhookFailures',
  sending_paused: 'adminHealthReasonSendingPaused',
  quota_nearly_used: 'adminHealthReasonQuotaNearlyUsed',
  no_running_tasks: 'adminHealthReasonNoRunningTasks',
  tasks_below_desired: 'adminHealthReasonTasksBelowDesired',
  deployment_failed: 'adminHealthReasonDeploymentFailed',
  no_healthy_targets: 'adminHealthReasonNoHealthyTargets',
  targets_unhealthy: 'adminHealthReasonTargetsUnhealthy',
  no_targets: 'adminHealthReasonNoTargets',
  http_5xx: 'adminHealthReasonHttp5xx',
  partial_check: 'adminHealthReasonPartialCheck',
  alarm: 'adminHealthReasonAlarm',
  no_alarms: 'adminHealthReasonNoAlarms',
  aws_error: 'adminHealthReasonAwsError',
  aws_unreachable: 'adminHealthReasonAwsUnreachable',
  check_failed: 'adminHealthReasonCheckFailed',
  api_disabled: 'adminHealthReasonApiDisabled',
  model_unavailable: 'adminHealthReasonModelUnavailable',
};

export const getHealthReasonLabel = (t, reason) => t(HEALTH_REASON_KEYS[reason] || 'adminHealthReasonCheckFailed');

const HEALTH_NOTE_KEYS = {
  failed_jobs: 'adminHealthNoteFailedJobs',
  small_sample: 'adminHealthNoteSmallSample',
  last_report_fallback: 'adminHealthNoteLastReportFallback',
  deployment_in_progress: 'adminHealthNoteDeploymentInProgress',
  backend_alarms_missing: 'adminHealthNoteBackendAlarmsMissing',
  possible_sandbox: 'adminHealthNotePossibleSandbox',
  not_on_ecs: 'adminHealthNoteNotOnEcs',
  insufficient_data_alarms: 'adminHealthNoteInsufficientData',
  smtp_not_verified: 'adminHealthNoteSmtpNotVerified',
  no_recent_activity: 'adminHealthNoteNoRecentActivity',
  since_task_start: 'adminHealthNoteSinceTaskStart',
  cold_start: 'adminHealthNoteColdStart',
};

/** Null for an unmapped note: dropped rather than shown as a raw code. */
export const getHealthNoteLabel = (t, note) => (HEALTH_NOTE_KEYS[note] ? t(HEALTH_NOTE_KEYS[note]) : null);

// Stripe webhook failure codes recorded by routes/stripeRoutes.js.
const WEBHOOK_FAILURE_KEYS = {
  misconfigured: 'adminHealthWhMisconfigured',
  signature_invalid: 'adminHealthWhSignatureInvalid',
  store_failed: 'adminHealthWhStoreFailed',
  processing_failed: 'adminHealthWhProcessingFailed',
};

export const getWebhookFailureLabel = (t, code) => t(WEBHOOK_FAILURE_KEYS[code] || 'adminHealthWhProcessingFailed');

const CONNECTION_STATE_KEYS = {
  connected: 'adminConnected',
  // Valkey client state (ioredis) for an open connection.
  ready: 'adminConnected',
  disconnected: 'adminDisconnected',
  connecting: 'adminConnecting',
  disconnecting: 'adminDisconnecting',
};

// Any other client state (e.g. ioredis 'reconnecting') reads as not connected.
export const getConnectionStateLabel = (t, state) => (
  t(CONNECTION_STATE_KEYS[state] || 'adminDisconnected')
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
  ADMIN_LAST_ADMIN_ORG:      'adminErrLastAdminOrg',
  ADMIN_LAST_SUPERADMIN:     'adminErrLastSuperadmin',
  ADMIN_SELF_ORG:            'adminErrSelfOrg',
  ADMIN_NO_ORG:              'adminErrNoOrg',
  ADMIN_OWNER_PROTECTED:     'adminErrOwnerProtected',
  ADMIN_NO_SUBSCRIPTION:     'adminErrNoSubscription',
  ADMIN_FETCH_FAILED:        'adminFetchError',
  ADMIN_ACTION_FAILED:       'adminActionFailed',
  ADMIN_REAUTH_REQUIRED:     'adminErrReauthRequired',
  ADMIN_AUDIT_FAILED:        'adminErrAuditFailed',
  ADMIN_STRIPE_FAILED:       'adminErrStripeFailed',
  ADMIN_DELETE_INCOMPLETE:   'adminErrDeleteIncomplete',
  AUTH_UNAVAILABLE:          'adminErrAuthUnavailable',
  // Raised by adminService itself, never by the server.
  ADMIN_TIMEOUT:             'adminErrTimeout',
  ADMIN_NETWORK:             'adminErrNetwork',
  TOO_MANY_REQUESTS:         'adminErrTooManyRequests',
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
