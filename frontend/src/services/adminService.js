// frontend/src/services/adminService.js
// All admin API calls are centralized here.
// Follows the same API abstraction pattern used throughout the app.

import { API_BASE } from '../config/api';

// The System Health checks are each time-boxed server-side (at most 6 s, in
// parallel); everything else is a database read. 20 s is far beyond either.
const REQUEST_TIMEOUT_MS = 20000;

// Dispatched when the server says this session can no longer act as an admin
// (expired/revoked token, disabled account, admin role removed). UserContext
// listens and re-reads the profile, which clears a dead session — RequireAdmin
// then routes the user to /login or /profile instead of leaving every tab on an
// error with a Retry button that can never succeed.
export const SESSION_INVALID_EVENT = 'fortexa:session-invalid';
const SESSION_ENDING_CODES = ['ACCOUNT_DISABLED', 'SESSION_REVOKED', 'FORBIDDEN', 'UNAUTHORIZED'];

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    'x-auth-token': token,
  };
};

const clientError = (code) => {
  const err = new Error(code);
  err.status = 0;
  err.code = code;
  return err;
};

const handleResponse = async (res) => {
  // A non-JSON body (proxy error page, dropped connection) must not throw a
  // SyntaxError that masks the real HTTP failure.
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // The Error message stays English on purpose — it is for the console only.
    // Callers must render `err.code` through getAdminErrorLabel(), never this.
    const err = new Error(data.error || data.message || `Request failed (${res.status})`);
    err.status = res.status;
    err.code = data.code || (res.status === 429 ? 'TOO_MANY_REQUESTS' : null);
    err.data = data;
    if (res.status === 401 || (res.status === 403 && SESSION_ENDING_CODES.includes(err.code))) {
      window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
    }
    throw err;
  }
  return data;
};

/** fetch with a timeout; network failures and timeouts get their own codes. */
const request = async (path, options = {}) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: getAuthHeaders(),
      signal: controller.signal,
    });
  } catch (e) {
    throw clientError(e && e.name === 'AbortError' ? 'ADMIN_TIMEOUT' : 'ADMIN_NETWORK');
  } finally {
    clearTimeout(timer);
  }
  return handleResponse(res);
};

const withQuery = (path, params = {}) => {
  const clean = Object.fromEntries(
    Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
  );
  const query = new URLSearchParams(clean).toString();
  return query ? `${path}?${query}` : path;
};

export const adminService = {
  /** GET /api/admin/kpis */
  getKpis: () => request('/api/admin/kpis'),

  /** GET /api/admin/users */
  getUsers: (params = {}) => request(withQuery('/api/admin/users', params)),

  /** GET /api/admin/organizations */
  getOrganizations: (params = {}) => request(withQuery('/api/admin/organizations', params)),

  /** GET /api/admin/scans */
  getScans: (params = {}) => request(withQuery('/api/admin/scans', params)),

  /** GET /api/admin/system-health — `service` re-checks one inventory service now */
  getSystemHealth: (service) => request(withQuery('/api/admin/system-health', { service })),

  /** GET /api/admin/analytics */
  getAnalytics: () => request('/api/admin/analytics'),

  /** GET /api/admin/audit-log (superadmin only) */
  getAuditLog: (params = {}) => request(withQuery('/api/admin/audit-log', params)),

  /** PATCH /api/admin/users/:id — body: { systemRole } or { isDisabled } */
  updateUser: (id, updates) =>
    request(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(updates) }),

  /** DELETE /api/admin/users/:id */
  deleteUser: (id) => request(`/api/admin/users/${id}`, { method: 'DELETE' }),

  /** DELETE /api/admin/users/:id/organization */
  removeUserFromOrganization: (id) =>
    request(`/api/admin/users/${id}/organization`, { method: 'DELETE' }),

  /** PATCH /api/admin/organizations/:id — body: { isDisabled } */
  updateOrganization: (id, updates) =>
    request(`/api/admin/organizations/${id}`, { method: 'PATCH', body: JSON.stringify(updates) }),

  /** DELETE /api/admin/organizations/:id (superadmin only) */
  deleteOrganization: (id) => request(`/api/admin/organizations/${id}`, { method: 'DELETE' }),

  /** POST /api/admin/organizations/:id/cancel-subscription (superadmin only) */
  cancelOrganizationSubscription: (id) =>
    request(`/api/admin/organizations/${id}/cancel-subscription`, { method: 'POST' }),
};
