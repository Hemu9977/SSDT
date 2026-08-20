// frontend/src/services/adminService.js
// All admin API calls are centralized here.
// Follows the same API abstraction pattern used throughout the app.

import { API_BASE } from '../config/api';

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    'x-auth-token': token,
  };
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
    err.code = data.code || null;
    err.data = data;
    throw err;
  }
  return data;
};

export const adminService = {
  /** GET /api/admin/kpis */
  getKpis: () =>
    fetch(`${API_BASE}/api/admin/kpis`, { headers: getAuthHeaders() }).then(handleResponse),

  /** GET /api/admin/users */
  getUsers: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return fetch(`${API_BASE}/api/admin/users${query ? `?${query}` : ''}`, {
      headers: getAuthHeaders(),
    }).then(handleResponse);
  },

  /** GET /api/admin/organizations */
  getOrganizations: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return fetch(`${API_BASE}/api/admin/organizations${query ? `?${query}` : ''}`, {
      headers: getAuthHeaders(),
    }).then(handleResponse);
  },

  /** GET /api/admin/scans */
  getScans: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return fetch(`${API_BASE}/api/admin/scans${query ? `?${query}` : ''}`, {
      headers: getAuthHeaders(),
    }).then(handleResponse);
  },

  /** GET /api/admin/system-health */
  getSystemHealth: () =>
    fetch(`${API_BASE}/api/admin/system-health`, { headers: getAuthHeaders() }).then(handleResponse),

  /** GET /api/admin/analytics */
  getAnalytics: () =>
    fetch(`${API_BASE}/api/admin/analytics`, { headers: getAuthHeaders() }).then(handleResponse),

  /** PATCH /api/admin/users/:id — body: { systemRole?, isDisabled? } */
  updateUser: (id, updates) =>
    fetch(`${API_BASE}/api/admin/users/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(updates),
    }).then(handleResponse),

  /** DELETE /api/admin/users/:id */
  deleteUser: (id) =>
    fetch(`${API_BASE}/api/admin/users/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    }).then(handleResponse),

  /** DELETE /api/admin/users/:id/organization */
  removeUserFromOrganization: (id) =>
    fetch(`${API_BASE}/api/admin/users/${id}/organization`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    }).then(handleResponse),

  /** PATCH /api/admin/organizations/:id — body: { isDisabled } */
  updateOrganization: (id, updates) =>
    fetch(`${API_BASE}/api/admin/organizations/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(updates),
    }).then(handleResponse),

  /** DELETE /api/admin/organizations/:id */
  deleteOrganization: (id) =>
    fetch(`${API_BASE}/api/admin/organizations/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    }).then(handleResponse),

  /** POST /api/admin/organizations/:id/cancel-subscription */
  cancelOrganizationSubscription: (id) =>
    fetch(`${API_BASE}/api/admin/organizations/${id}/cancel-subscription`, {
      method: 'POST',
      headers: getAuthHeaders(),
    }).then(handleResponse),
};
