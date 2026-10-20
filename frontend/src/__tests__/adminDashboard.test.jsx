/**
 * Behavioural tests for the admin dashboard UI.
 *
 * The tab components are RENDERED with a mocked adminService and user context:
 * these check what an administrator actually sees (which controls exist for
 * which role, how health states read), plus the adminService error handling and
 * that every translation key reachable through the admin label maps exists.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';

// ── Mocks ────────────────────────────────────────────────────────────────────
let mockUser = { id: 'me', systemRole: 'admin' };
jest.mock('../contexts/UserContext', () => ({ useUser: () => ({ user: mockUser, loading: false }) }));
// t() returns the key plus its interpolation values, so assertions can name keys.
jest.mock('../contexts/TranslationContext', () => ({
  useTranslation: () => ({
    t: (key, vars) => (vars ? `${key}${JSON.stringify(vars)}` : key),
    currentLang: 'en',
  }),
}));
jest.mock('../services/adminService', () => ({
  adminService: {
    getOrganizations: jest.fn(),
    getUsers: jest.fn(),
    getSystemHealth: jest.fn(),
    getKpis: jest.fn(),
    getAnalytics: jest.fn(),
    getAuditLog: jest.fn(),
  },
}));

// eslint-disable-next-line import/first
import { adminService } from '../services/adminService';
// eslint-disable-next-line import/first
import AdminOrganizations from '../pages/Admin/AdminOrganizations';
// eslint-disable-next-line import/first
import AdminUsers from '../pages/Admin/AdminUsers';
// eslint-disable-next-line import/first
import AdminSystemHealth from '../pages/Admin/AdminSystemHealth';
// eslint-disable-next-line import/first
import AdminOverview from '../pages/Admin/AdminOverview';
// eslint-disable-next-line import/first
import AdminAnalytics from '../pages/Admin/AdminAnalytics';

const page = (rows, key) => ({ [key]: rows, pagination: { page: 1, pages: 1, total: rows.length } });

const ORGS = [
  {
    _id: 'o1', name: 'Live Co', planType: 'basic', subscriptionState: 'active', cancellable: true,
    expiresAt: '2026-11-20T00:00:00Z', seatsUsed: 1, seatsAllowed: 3, scansUsed: 1, scanLimit: 5,
    owner: { email: 'owner@example.com' }, isDisabled: false,
  },
  {
    _id: 'o2', name: 'Lapsed Co', planType: 'basic', subscriptionState: 'expired', cancellable: false,
    expiresAt: '2026-10-01T00:00:00Z', seatsUsed: 1, seatsAllowed: 3, scansUsed: 0, scanLimit: 5,
    owner: null, isDisabled: false,
  },
];

const rowOf = (text) => screen.getByText(text).closest('tr');

describe('Organizations tab', () => {
  beforeEach(() => adminService.getOrganizations.mockResolvedValue(page(ORGS, 'organizations')));

  it('hides billing cancellation and deletion from a plain admin', async () => {
    mockUser = { id: 'me', systemRole: 'admin' };
    render(<AdminOrganizations />);
    await screen.findByText('Live Co');
    expect(screen.queryByText('adminCancelSubscription')).toBeNull();
    expect(screen.queryByText('delete')).toBeNull();
    expect(within(rowOf('Live Co')).getByText('adminDisable')).toBeTruthy();
  });

  it('offers them to a superadmin, and cancellation only where it applies', async () => {
    mockUser = { id: 'me', systemRole: 'superadmin' };
    render(<AdminOrganizations />);
    await screen.findByText('Live Co');
    expect(within(rowOf('Live Co')).getByText('adminCancelSubscription')).toBeTruthy();
    expect(within(rowOf('Lapsed Co')).queryByText('adminCancelSubscription')).toBeNull();
    expect(screen.getAllByText('delete')).toHaveLength(2);
  });

  it('shows the computed subscription state, not the raw Stripe status', async () => {
    mockUser = { id: 'me', systemRole: 'admin' };
    render(<AdminOrganizations />);
    await screen.findByText('Lapsed Co');
    expect(within(rowOf('Lapsed Co')).getByText('adminSubExpired')).toBeTruthy();
    expect(within(rowOf('Live Co')).getByText('adminActive')).toBeTruthy();
  });
});

describe('Users tab', () => {
  const USERS = [
    { _id: 'u1', name: 'Customer', email: 'c@example.com', systemRole: 'user', role: 'member', isVerified: true,
      isDisabled: false, organizationId: 'o1', organization: { _id: 'o1', name: 'Live Co', planType: 'basic', subscriptionState: 'active' },
      createdAt: '2026-09-01T00:00:00Z', lastLoginAt: null },
    { _id: 'u2', name: 'Other Admin', email: 'a@example.com', systemRole: 'admin', role: 'owner', isVerified: true,
      isDisabled: false, organizationId: null, organization: null, createdAt: '2026-09-01T00:00:00Z', lastLoginAt: null },
  ];
  beforeEach(() => adminService.getUsers.mockResolvedValue(page(USERS, 'users')));

  it('a plain admin gets no controls on another admin, but can manage customers', async () => {
    mockUser = { id: 'me', systemRole: 'admin' };
    render(<AdminUsers />);
    await screen.findByText('Customer');
    const adminRow = rowOf('Other Admin');
    expect(within(adminRow).getByText('adminSuperadminOnly')).toBeTruthy();
    expect(within(adminRow).queryByText('delete')).toBeNull();
    expect(within(rowOf('Customer')).getByText('adminDisable')).toBeTruthy();
    // Permanent deletion is superadmin-only, even for ordinary accounts.
    expect(within(rowOf('Customer')).queryByText('delete')).toBeNull();
  });

  it('a superadmin can delete an ordinary account', async () => {
    mockUser = { id: 'me', systemRole: 'superadmin' };
    render(<AdminUsers />);
    await screen.findByText('Customer');
    expect(within(rowOf('Customer')).getByText('delete')).toBeTruthy();
  });

  it('shows the organization, and no last-login date when there has been none', async () => {
    mockUser = { id: 'me', systemRole: 'superadmin' };
    render(<AdminUsers />);
    await screen.findByText('Customer');
    const row = rowOf('Customer');
    expect(within(row).getByText('Live Co')).toBeTruthy();
    const cells = within(row).getAllByRole('cell');
    expect(cells[6].textContent).toBe('—'); // Last login column
    expect(within(rowOf('Other Admin')).getByText('adminNoOrganization')).toBeTruthy();
  });
});

describe('System Health tab', () => {
  const svc = (id, status, extra = {}) => ({
    id, category: 'core', critical: false, basis: 'live_probe', status, reason: null, notes: [],
    latencyMs: 5, metrics: {}, checkedAt: '2026-10-20T00:00:00Z', cached: false, ...extra,
  });
  const REPORT = {
    generatedAt: '2026-10-20T00:00:00Z',
    refreshIntervalSec: 60,
    services: [
      svc('mongodb', 'healthy', { critical: true }),
      svc('zap', 'idle', { category: 'scanner', metrics: { desiredCount: 0, runningCount: 0, pendingCount: 0 } }),
      svc('pagespeed', 'configured', { category: 'scanner', basis: 'recent_activity', notes: ['no_recent_activity'], latencyMs: null }),
      svc('aws_alarms', 'unknown', { category: 'infrastructure', basis: 'aws_api', reason: 'permission_denied' }),
      svc('stripe', 'unavailable', { category: 'billing', reason: 'auth_failed' }),
      svc('queues', 'healthy', { metrics: { queues: {
        scan: { reachable: true, waiting: 1, active: 0, delayed: 0, failed: 2, oldestWaitingSec: null, workerRunning: true },
        zap: { reachable: false, workerRunning: null },
      } } }),
      // A service this build has no label for is still shown.
      svc('new_thing', 'healthy', { category: 'mystery' }),
    ],
    summary: { overall: 'degraded', total: 7, operational: 4, notVerified: 2, problems: 1,
      counts: { healthy: 3, idle: 1, configured: 1, unknown: 1, unavailable: 1, degraded: 0, starting: 0 } },
  };
  const card = (name) => screen.getByText(name).closest('.admin-health-card');

  beforeEach(() => adminService.getSystemHealth.mockReset());

  it('renders the server’s services in the existing cards; only verified ones count as online', async () => {
    adminService.getSystemHealth.mockResolvedValue(REPORT);
    render(<AdminSystemHealth />);
    await screen.findByText('adminHealthSvcMongodb');

    // The count is the server's: configured and unknown are not "online".
    expect(screen.getByText(/adminOnlineCount.*"online":"4".*"total":"7"/)).toBeTruthy();
    expect(within(card('adminHealthSvcPagespeed')).getByText('adminHealthConfigured')).toBeTruthy();
    expect(within(card('adminHealthSvcPagespeed')).getByText('adminHealthNoteNoRecentActivity')).toBeTruthy();
    expect(within(card('adminHealthSvcAwsAlarms')).getByText('adminHealthUnknown')).toBeTruthy();
    expect(within(card('adminHealthSvcAwsAlarms')).getByText('adminHealthReasonPermissionDenied')).toBeTruthy();
    expect(within(card('adminHealthSvcZap')).getByText('adminHealthIdle')).toBeTruthy();
    expect(within(card('adminHealthSvcStripe')).getByText('adminHealthReasonAuthFailed')).toBeTruthy();

    // Card colours: working = green border, failing = red, not verified = neither.
    expect(card('adminHealthSvcMongodb').className).toMatch(/admin-health-card--ok/);
    expect(card('adminHealthSvcZap').className).toMatch(/admin-health-card--ok/);
    expect(card('adminHealthSvcStripe').className).toMatch(/admin-health-card--err/);
    expect(card('adminHealthSvcPagespeed').className).not.toMatch(/--ok|--err/);

    expect(screen.getByText('new_thing')).toBeTruthy();
    expect(document.querySelectorAll('.admin-health-card')).toHaveLength(REPORT.services.length);
  });

  it('still draws every card for an older backend’s `checks` response, without counting "configured" as online', async () => {
    adminService.getSystemHealth.mockResolvedValue({
      success: true,
      timestamp: '2026-10-20T00:00:00Z',
      checks: {
        server: { status: 'online', uptimeSeconds: 10, memoryMB: 50, memoryTotalMB: 80, nodeVersion: 'v20.0.0' },
        mongodb: { status: 'online', state: 'connected' },
        redis: { status: 'online', latencyMs: 1 },
        bullmq: { status: 'online', queues: { scan: { status: 'online', waiting: 0, active: 0, failed: 2 }, zap: { status: 'offline' } } },
        webcheck: { status: 'offline', reason: 'unreachable' },
        zap: { status: 'idle', desiredCount: 0, runningCount: 0 },
        zapAuth: { status: 'idle', desiredCount: 0, runningCount: 0 },
        gemini: { status: 'online', authMode: 'vertex' },
        pagespeed: { status: 'configured' },
        urlscan: { status: 'not_configured' },
      },
    });
    render(<AdminSystemHealth />);
    await screen.findByText('adminHealthSvcMongodb');
    expect(document.querySelectorAll('.admin-health-card')).toHaveLength(10);
    // server, mongodb, redis, bullmq, gemini healthy + zap ×2 idle = 7; webcheck,
    // pagespeed (configured) and urlscan (not configured) are not online.
    expect(screen.getByText(/adminOnlineCount.*"online":"7".*"total":"10"/)).toBeTruthy();
    expect(within(card('adminHealthSvcWebcheck')).getByText('adminHealthReasonUnreachable')).toBeTruthy();
    expect(within(card('adminHealthSvcPagespeed')).getByText('adminHealthConfigured')).toBeTruthy();
    expect(within(card('adminHealthSvcUrlscan')).getByText('adminHealthReasonNotConfigured')).toBeTruthy();
    expect(within(card('adminHealthSvcQueues')).getByText(/adminHealthQueueLine.*"failed":"2"/)).toBeTruthy();
    expect(within(card('adminHealthSvcQueues')).getByText(/adminHealthQueueUnreachable/)).toBeTruthy();
  });

  it('shows each Gemini model’s result, the reason, and when it was checked', async () => {
    adminService.getSystemHealth.mockResolvedValue({
      ...REPORT,
      services: [
        svc('gemini', 'degraded', {
          category: 'scanner', reason: 'model_unavailable',
          metrics: { authMode: 'vertex', location: 'us-central1', models: [
            { model: 'gemini-2.5-pro', ok: false, reason: 'model_unavailable' },
            { model: 'gemini-2.5-flash', ok: true, reason: null },
          ] },
        }),
        svc('pagespeed', 'unavailable', { category: 'scanner', reason: 'api_disabled' }),
      ],
    });
    render(<AdminSystemHealth />);
    await screen.findByText('adminHealthSvcGemini');
    const gemini = within(card('adminHealthSvcGemini'));
    expect(gemini.getByText(/adminHealthModelFailed.*gemini-2\.5-pro.*adminHealthReasonModelUnavailable/)).toBeTruthy();
    expect(gemini.getByText(/adminHealthModelOk.*gemini-2\.5-flash/)).toBeTruthy();
    expect(gemini.getByText(/adminHealthRegion.*us-central1/)).toBeTruthy();
    expect(gemini.getByText(/adminHealthChecked/)).toBeTruthy();
    expect(within(card('adminHealthSvcPagespeed')).getByText('adminHealthReasonApiDisabled')).toBeTruthy();
  });

  it('says so instead of showing a blank page when no services come back', async () => {
    adminService.getSystemHealth.mockResolvedValue({ success: true });
    render(<AdminSystemHealth />);
    expect(await screen.findByText('adminNoData')).toBeTruthy();
  });

  it('shows queue failures and an unreachable queue as such, not as zeros', async () => {
    adminService.getSystemHealth.mockResolvedValue(REPORT);
    render(<AdminSystemHealth />);
    await screen.findByText('adminHealthSvcQueues');
    const box = within(card('adminHealthSvcQueues'));
    expect(box.getByText(/adminHealthQueueLine.*"failed":"2"/)).toBeTruthy();
    expect(box.getByText(/adminHealthQueueUnreachable/)).toBeTruthy();
    expect(box.queryByText(/adminHealthQueueLine.*adminQueueZap/)).toBeNull();
  });

  it('keeps the last results after a failed refresh, marked as out of date', async () => {
    adminService.getSystemHealth
      .mockResolvedValueOnce(REPORT)
      .mockRejectedValueOnce(Object.assign(new Error('x'), { code: 'ADMIN_TIMEOUT' }));
    render(<AdminSystemHealth />);
    await screen.findByText('adminHealthSvcMongodb');
    fireEvent.click(screen.getByRole('button', { name: 'adminRefresh' }));
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toMatch(/adminHealthStale.*adminErrTimeout/);
    expect(screen.getByText('adminHealthSvcMongodb')).toBeTruthy();
    expect(adminService.getSystemHealth).toHaveBeenCalledTimes(2);
  });

  it('holds no service list, status or count of its own', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'pages/Admin/AdminSystemHealth.jsx'), 'utf8');
    expect(src).not.toMatch(/SERVICE_DEFS|totalCount|onlineCount|HEALTHY_STATUSES/);
    expect(src).toMatch(/data\.services/);
    expect(src).toMatch(/data\.summary/);
  });
});

describe('Overview and Analytics: missing figures are not zeros', () => {
  it('Overview shows "—" and "unavailable" for a figure the server could not load', async () => {
    adminService.getKpis.mockResolvedValue({
      kpis: { totalUsers: null, verifiedUsers: 4, activeOrgs: 0, totalOrgs: 2, totalScansAllTime: 9, runningScans: 0 },
      planDistribution: [{ _id: 'pro', count: 1 }, { _id: 'lapsed', count: 1 }],
      recentUsers: null,
      unavailable: ['totalUsers', 'recentUsers'],
    });
    render(<AdminOverview />);
    const label = await screen.findByText('adminTotalUsers');
    const tile = label.closest('.stat-card');
    expect(within(tile).getByText('—')).toBeTruthy();
    expect(within(tile).getByText('adminUnavailable')).toBeTruthy();
    // A real zero is still a zero.
    expect(within(screen.getByText('adminActiveOrgs').closest('.stat-card')).getByText('0')).toBeTruthy();
    expect(screen.getByText('adminPartialData')).toBeTruthy();
    expect(screen.getByText('adminPlanLapsed')).toBeTruthy();
    expect(screen.getAllByText('adminMetricUnavailable')).toHaveLength(1); // recent users
  });

  it('Analytics marks an unavailable section and ranks usage by this month', async () => {
    adminService.getAnalytics.mockResolvedValue({
      userGrowth: [{ date: '2026-10-20', count: 1 }],
      organizationGrowth: [{ date: '2026-10-20', count: 0 }],
      subscriptionStatusDistribution: [{ _id: 'active', count: 1 }],
      estimatedRecurringValue: { total: 0, byPlan: {}, activeOrgCount: 0 },
      scanActivity: null,
      topOrgsByUsage: [{ _id: 'o1', name: 'Busy Co', planType: 'pro', scansUsed: 7, scansUsedThisMonth: 7, scanLimit: 10, seatsUsed: 1, seatsAllowed: 5 }],
      unavailable: ['scanActivity'],
    });
    render(<AdminAnalytics />);
    await screen.findByText('Busy Co');
    expect(screen.getByText('adminMetricUnavailable')).toBeTruthy();
    expect(screen.getByText(/adminScansThisWeek.*"count":"—"/)).toBeTruthy();
    expect(rowOf('Busy Co').textContent).toMatch(/7 \/ 10/);
  });
});

describe('adminService', () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });
  const { adminService: real } = jest.requireActual('../services/adminService');

  it('turns a 401 into a session re-check event and a coded error', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({ code: 'UNAUTHORIZED' }) });
    const seen = jest.fn();
    window.addEventListener('fortexa:session-invalid', seen);
    await expect(real.getKpis()).rejects.toMatchObject({ status: 401, code: 'UNAUTHORIZED' });
    window.removeEventListener('fortexa:session-invalid', seen);
    expect(seen).toHaveBeenCalledTimes(1);
  });

  it('does not end the session for an ordinary permission refusal', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 403, json: async () => ({ code: 'ADMIN_SUPERADMIN_REQUIRED' }) });
    const seen = jest.fn();
    window.addEventListener('fortexa:session-invalid', seen);
    await expect(real.deleteOrganization('x')).rejects.toMatchObject({ code: 'ADMIN_SUPERADMIN_REQUIRED' });
    window.removeEventListener('fortexa:session-invalid', seen);
    expect(seen).not.toHaveBeenCalled();
  });

  it('reports network failures and timeouts with their own codes', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(real.getKpis()).rejects.toMatchObject({ code: 'ADMIN_NETWORK' });
    global.fetch = jest.fn().mockRejectedValue(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    await expect(real.getKpis()).rejects.toMatchObject({ code: 'ADMIN_TIMEOUT' });
  });

  it('maps a 429 without a code to TOO_MANY_REQUESTS', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({ error: 'Too many requests' }) });
    await expect(real.getKpis()).rejects.toMatchObject({ code: 'TOO_MANY_REQUESTS' });
  });
});

describe('admin label maps', () => {
  it('every translation key the admin label maps can produce exists in both locales', () => {
    const SRC = path.join(__dirname, '..');
    const labels = fs.readFileSync(path.join(SRC, 'pages/Admin/adminLabels.js'), 'utf8');
    const keys = [...new Set([...labels.matchAll(/:\s*'(admin[A-Za-z0-9]+|err[A-Za-z0-9]+)'/g)].map((m) => m[1]))];
    expect(keys.length).toBeGreaterThan(60);
    const en = fs.readFileSync(path.join(SRC, 'locales/en.js'), 'utf8');
    const ja = fs.readFileSync(path.join(SRC, 'locales/ja.js'), 'utf8');
    const missing = keys.filter((k) => !new RegExp(`^  ${k}:`, 'm').test(en) || !new RegExp(`^  ${k}:`, 'm').test(ja));
    expect(missing).toEqual([]);
  });

  it('keys chosen inside expressions in admin pages exist too', () => {
    const SRC = path.join(__dirname, '..');
    const en = fs.readFileSync(path.join(SRC, 'locales/en.js'), 'utf8');
    const ja = fs.readFileSync(path.join(SRC, 'locales/ja.js'), 'utf8');
    const dir = path.join(SRC, 'pages/Admin');
    const keys = new Set();
    for (const f of fs.readdirSync(dir)) {
      const src = fs.readFileSync(path.join(dir, f), 'utf8');
      for (const m of src.matchAll(/'(admin[A-Z][A-Za-z0-9]+)'/g)) keys.add(m[1]);
    }
    const missing = [...keys].filter((k) => !new RegExp(`^  ${k}:`, 'm').test(en) || !new RegExp(`^  ${k}:`, 'm').test(ja));
    expect(missing).toEqual([]);
  });
});
