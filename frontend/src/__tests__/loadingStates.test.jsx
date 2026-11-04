/**
 * Loading states that must always end, and report downloads per language.
 *
 * Regression tests for two customer reports:
 *  - Recent Scans: a page could sit on its loading state for minutes, because no
 *    request on it had a deadline, and the list labelled an unfinished scan with
 *    the raw backend enum ("Combining").
 *  - Report download: one request the server never answered kept the button on
 *    "Generating" forever (the overall deadline was only checked between polls),
 *    and a 200 that was not a PDF was saved as the report.
 *
 * Every network call is a mocked fetch; time is jest's fake clock.
 */
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';

// ── Mocks ────────────────────────────────────────────────────────────────────
// Jest 27 cannot resolve react-router v7 (exports-only package), and these pages
// only use its hooks, so they are mocked. The navigate mock must be stable:
// ScanViewer's load effect depends on it.
const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
  useParams: () => ({ analysisId: 'scan-1' }),
  useNavigate: () => mockNavigate,
  useLocation: () => ({ search: '' }),
}), { virtual: true });
const mockRefreshUser = jest.fn();
jest.mock('../contexts/UserContext', () => ({ useUser: () => ({ refreshUser: mockRefreshUser }) }));
// t() returns the key plus its interpolation values, so assertions can name keys.
jest.mock('../contexts/TranslationContext', () => ({
  useTranslation: () => ({
    t: (key, vars) => (vars ? `${key}${JSON.stringify(vars)}` : key),
    currentLang: 'en',
  }),
}));
jest.mock('../components/header', () => () => null);
jest.mock('../components/ParticleBackground', () => () => null);
jest.mock('../components/ConfirmDialog', () => () => null);
jest.mock('../pages/LandingPage', () => ({ historicalScan }) => <div>landing:{historicalScan.target}</div>);

// eslint-disable-next-line import/first
import { requestTimeout } from '../utils/requestTimeout';
// eslint-disable-next-line import/first
import { downloadPdfReport } from '../utils/pdfDownload';
// eslint-disable-next-line import/first
import ScanViewer from '../pages/ScanViewer';
// eslint-disable-next-line import/first
import Profile from '../pages/Profile';
// eslint-disable-next-line import/first
import ZapReportEnhanced from '../components/ZapReportEnhanced';

// ── Helpers ──────────────────────────────────────────────────────────────────
const realSetImmediate = jest.requireActual('timers').setImmediate;
const flush = () => new Promise((resolve) => realSetImmediate(resolve));

/** Advance the fake clock in steps, letting promises settle between them. */
async function advance(ms, step = 1000) {
  for (let elapsed = 0; elapsed < ms; elapsed += step) {
    await act(async () => {
      jest.advanceTimersByTime(step);
      await flush();
    });
  }
}

const abortError = () => Object.assign(new Error('aborted'), { name: 'AbortError' });
/** A request the server never answers; it only ends when aborted. */
const hang = (url, init) => new Promise((_, reject) => {
  init?.signal?.addEventListener('abort', () => reject(abortError()));
});
const json = (status, body) => Promise.resolve({
  ok: status >= 200 && status < 300, status,
  json: async () => body,
  blob: async () => new Blob([JSON.stringify(body)], { type: 'application/json' }),
});
const pdf = () => Promise.resolve({
  ok: true, status: 200,
  json: async () => ({}),
  blob: async () => new Blob(['%PDF-1.7 report'], { type: 'application/pdf' }),
});

beforeEach(() => {
  jest.useFakeTimers();
  localStorage.setItem('token', 'tok');
  mockRefreshUser.mockClear();
  mockNavigate.mockClear();
  window.URL.createObjectURL = jest.fn(() => 'blob:report');
  window.URL.revokeObjectURL = jest.fn();
  jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
  delete global.fetch;
  localStorage.clear();
});

// ── requestTimeout ───────────────────────────────────────────────────────────
describe('requestTimeout', () => {
  it('aborts at the deadline and says it was the deadline', () => {
    const d = requestTimeout(1000);
    jest.advanceTimersByTime(999);
    expect(d.signal.aborted).toBe(false);
    jest.advanceTimersByTime(1);
    expect(d.signal.aborted).toBe(true);
    expect(d.timedOut).toBe(true);
  });

  it("follows the caller's abort without calling it a timeout", () => {
    const parent = new AbortController();
    const d = requestTimeout(1000, parent.signal);
    parent.abort();
    expect(d.signal.aborted).toBe(true);
    expect(d.timedOut).toBe(false);
  });

  it('does nothing once cleared', () => {
    const d = requestTimeout(1000);
    d.clear();
    jest.advanceTimersByTime(5000);
    expect(d.signal.aborted).toBe(false);
  });
});

// ── Report download ──────────────────────────────────────────────────────────
describe('downloadPdfReport', () => {
  const run = (lang) => downloadPdfReport({
    analysisId: 'scan-1', target: 'https://example.co.jp', lang, apiBase: '', token: 'tok',
  });
  const settle = (promise) => promise.then(() => 'downloaded', (err) => err.messageKey);

  it('downloads JA then EN for the same scan as two independent jobs', async () => {
    const jobs = [];
    global.fetch = jest.fn((url, init) => {
      if (url.endsWith('/pdf-job')) {
        jobs.push(JSON.parse(init.body));
        return json(200, { jobId: `job-${jobs.length}` });
      }
      return pdf();
    });

    for (const lang of ['ja', 'en']) {
      const result = settle(run(lang));
      await advance(6000);
      expect(await result).toBe('downloaded');
    }
    expect(jobs).toEqual([{ analysisId: 'scan-1', lang: 'ja' }, { analysisId: 'scan-1', lang: 'en' }]);
    const names = HTMLAnchorElement.prototype.click.mock.instances.map((a) => a.download);
    expect(names[0]).toMatch(/^security_report_JA_/);
    expect(names[1]).toMatch(/^security_report_EN_/);
  });

  it('gives up on a start request that is never answered', async () => {
    global.fetch = jest.fn(hang);
    const result = settle(run('en'));
    await advance(61000);
    expect(await result).toBe('pdfGenerationFailed');
  });

  it('ends at the overall deadline when every poll hangs', async () => {
    global.fetch = jest.fn((url, init) => (url.endsWith('/pdf-job') ? json(200, { jobId: 'j' }) : hang(url, init)));
    const result = settle(run('en'));
    await advance(11 * 60 * 1000, 5000);
    expect(await result).toBe('pdfGenerationTimedOut');
  });

  it('rejects a 200 that is not a PDF instead of saving it', async () => {
    global.fetch = jest.fn((url) => (url.endsWith('/pdf-job')
      ? json(200, { jobId: 'j' })
      : Promise.resolve({ ok: true, status: 200, blob: async () => new Blob(['<html>error</html>'], { type: 'text/html' }) })));
    const result = settle(run('en'));
    await advance(6000);
    expect(await result).toBe('pdfGenerationFailed');
    expect(HTMLAnchorElement.prototype.click).not.toHaveBeenCalled();
  });

  it('reports a failed job by its error code, not the backend message', async () => {
    global.fetch = jest.fn((url) => (url.endsWith('/pdf-job')
      ? json(200, { jobId: 'j' })
      : json(500, { status: 'failed', error: 'ZAP blew up' })));
    const result = settle(run('en'));
    await advance(6000);
    expect(await result).toBe('pdfGenerationFailed');
  });
});

// ── Scan viewer (opened from Recent Scans) ───────────────────────────────────
describe('ScanViewer', () => {
  const renderViewer = () => render(<ScanViewer />);

  it('ends an unanswered load with an error and a working retry', async () => {
    global.fetch = jest.fn(hang);
    renderViewer();
    expect(screen.getByText('loadingScanResults')).toBeTruthy();

    await advance(91000, 5000);
    expect(screen.getByText('scanLoadTimedOut')).toBeTruthy();

    global.fetch = jest.fn(() => json(200, { target: 'https://example.co.jp', status: 'completed' }));
    fireEvent.click(screen.getByText('retryLoad'));
    await advance(1000);
    expect(screen.getByText('landing:https://example.co.jp')).toBeTruthy();
  });

  it('explains an expired scan without offering a pointless retry', async () => {
    global.fetch = jest.fn(() => json(404, { error: 'Scan not found' }));
    renderViewer();
    await advance(1000);
    expect(screen.getByText('scanNotFoundExpired')).toBeTruthy();
    expect(screen.queryByText('retryLoad')).toBeNull();
  });

  it('never shows the backend error string', async () => {
    global.fetch = jest.fn(() => json(500, { error: 'Failed to load scan', details: 'GridFS exploded' }));
    renderViewer();
    await advance(1000);
    expect(screen.getByText('failedLoadScan')).toBeTruthy();
    expect(screen.queryByText(/GridFS|Failed to load scan/)).toBeNull();
  });

  it('sends a rejected session to sign-in', async () => {
    global.fetch = jest.fn(() => json(401, {}));
    renderViewer();
    await advance(1000);
    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });
});

// ── Profile → Recent Scans ───────────────────────────────────────────────────
describe('Profile recent scans', () => {
  const PROFILE = {
    success: true,
    user: { id: 'u1', name: 'Yamada', email: 'y@example.co.jp', organization: null, createdAt: '2026-10-01T00:00:00Z' },
    limits: {},
    recentScans: [
      { _id: 's1', analysisId: 'a1', target: 'https://new.example.co.jp', status: 'combining', createdAt: '2026-10-27T00:00:00Z' },
      { _id: 's2', analysisId: 'a2', target: 'https://old.example.co.jp', status: 'completed', createdAt: '2026-10-26T00:00:00Z' },
    ],
  };
  const renderProfile = () => render(<Profile />);

  it('lists scans with translated states and makes one profile request', async () => {
    global.fetch = jest.fn(() => json(200, PROFILE));
    renderProfile();
    await advance(1000);

    expect(screen.getByText('https://new.example.co.jp')).toBeTruthy();
    expect(screen.getByText('recentScanInProgress')).toBeTruthy();
    expect(screen.getByText('completed')).toBeTruthy();
    expect(screen.queryByText(/Combining/i)).toBeNull();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(mockRefreshUser).not.toHaveBeenCalled();
  });

  it('shows the empty state when there are no scans', async () => {
    global.fetch = jest.fn(() => json(200, { ...PROFILE, recentScans: [] }));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('noScansYet')).toBeTruthy();
  });

  it('ends an unanswered load with a timeout message and a retry', async () => {
    global.fetch = jest.fn(hang);
    renderProfile();
    expect(screen.getByText('loadingProfile')).toBeTruthy();

    await advance(31000);
    expect(screen.getByText('profileLoadTimedOut')).toBeTruthy();

    global.fetch = jest.fn(() => json(200, PROFILE));
    fireEvent.click(screen.getByText('retryLoad'));
    await advance(1000);
    expect(screen.getByText('https://old.example.co.jp')).toBeTruthy();
  });

  it('shows a translated error for a server failure, never its message', async () => {
    global.fetch = jest.fn(() => json(500, { message: 'Server error', error: 'Mongo timeout' }));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('failedFetchProfile')).toBeTruthy();
    expect(screen.queryByText(/Server error|Mongo/)).toBeNull();
  });

  it('shows a translated error when the network fails', async () => {
    global.fetch = jest.fn(() => Promise.reject(new TypeError('Failed to fetch')));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('failedLoadProfile')).toBeTruthy();
  });

  it('treats a rejected session as expired', async () => {
    global.fetch = jest.fn(() => json(401, {}));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('sessionExpiredLoginAgain')).toBeTruthy();
    expect(localStorage.getItem('token')).toBeNull();
  });

  // Superadmins scan without limits (backend sends scansPerMonth: -1), so the
  // page offers them nothing to buy.
  const SUPERADMIN = {
    ...PROFILE,
    user: { ...PROFILE.user, systemRole: 'superadmin' },
    limits: { scansPerMonth: -1, maxSchedules: -1 },
  };

  it('offers plans to an account without one', async () => {
    global.fetch = jest.fn(() => json(200, PROFILE));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('choosePlan')).toBeTruthy();
  });

  it('shows a superadmin "Unlimited" and no plan picker', async () => {
    global.fetch = jest.fn(() => json(200, SUPERADMIN));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('unlimitedScanLimit')).toBeTruthy();
    expect(screen.queryByText('choosePlan')).toBeNull();
    expect(screen.queryByText('selectPlan')).toBeNull();
  });

  it('offers a superadmin who owns a paid org no extra-scan top-up', async () => {
    const org = {
      id: 'o1', name: 'Fortexa', role: 'owner', planType: 'pro', billingCycle: 'monthly',
      subscriptionStatus: 'active', entitled: true, seatsAllowed: 1, seatsUsed: 1,
      scanLimit: 10, scansUsed: 10, members: [], pendingInvites: [],
    };
    global.fetch = jest.fn(() => json(200, { ...SUPERADMIN, user: { ...SUPERADMIN.user, organization: org } }));
    renderProfile();
    await advance(1000);
    expect(screen.getByText('currentPlanTitle')).toBeTruthy();
    expect(screen.queryByText('topUpSectionTitle')).toBeNull();
    expect(screen.queryByText('buyExtraScans')).toBeNull();
    expect(screen.queryByText('planLimitExhaustedHint')).toBeNull();
  });
});

// ── Scan page evidence panel (opened from Recent Scans, alert expanded) ─────
describe('ZapReportEnhanced evidence', () => {
  const zapData = { alerts: [{
    alert: 'SQL Injection', risk: 'High', confidence: 'High', totalOccurrences: 500,
    description: 'd', solution: 's', sampleUrls: ['https://example.co.jp/0'], hasMoreUrls: true,
  }] };
  const evidence = (n, total) => [{
    alert: 'SQL Injection', rawOccurrenceCount: total,
    occurrences: Array.from({ length: n }, (_, i) => ({
      url: `https://example.co.jp/${i}`,
      request: { header: 'GET / HTTP/1.1\r\n', body: '' },
      response: { header: 'HTTP/1.1 200 OK\r\n', body: 'x', bodyTruncated: true },
    })),
  }];
  const routed = (onEvidence) => jest.fn((url, init) => (
    url.includes('/detailed-report/') ? onEvidence(url, init) : json(200, {})
  ));
  const expand = () => {
    render(<ZapReportEnhanced zapData={zapData} scanId="scan-1" currentLang="en" />);
    fireEvent.click(screen.getByText('SQL Injection'));
  };

  it('asks for the first pairs only, and says when there are more', async () => {
    // A production scan's full file was 287 MB; the panel must never fetch it.
    global.fetch = routed(() => json(200, evidence(10, 500)));
    expand();
    await advance(1000);
    const urls = global.fetch.mock.calls.map(([u]) => u);
    expect(urls).toEqual(expect.arrayContaining([expect.stringMatching(/\/api\/zap\/detailed-report\/scan-1\?view=evidence$/)]));
    expect(urls.filter((u) => u.includes('/detailed-report/'))).toHaveLength(1);
    expect(screen.getByText('showFirstEvidence{"count":10,"total":500}')).toBeTruthy();
    expect(screen.getAllByText('evidenceBodyTruncated')).toHaveLength(3); // 3 pairs shown
  });

  it('ends an unanswered evidence load with a message and a working retry', async () => {
    global.fetch = routed(hang);
    expand();
    expect(screen.getByText('loadingEvidence')).toBeTruthy();

    await advance(121000, 5000);
    expect(screen.queryByText('loadingEvidence')).toBeNull();
    expect(screen.getByText('evidenceLoadFailed', { exact: false })).toBeTruthy();

    global.fetch = routed(() => json(200, evidence(2, 2)));
    fireEvent.click(screen.getByText('retryLoad'));
    await advance(1000);
    expect(screen.queryByText('evidenceLoadFailed', { exact: false })).toBeNull();
    expect(screen.getByText('https://example.co.jp/1')).toBeTruthy();
    expect(screen.queryByText(/showFirstEvidence|showAllEvidence/)).toBeNull(); // 2 pairs: nothing to expand
  });
});
