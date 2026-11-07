/**
 * Report loading states shared by the normal and authenticated scan pages.
 *
 *  - The state of each tool card and of the AI summary comes only from fields the
 *    scan endpoints already return: no invented progress, nothing marked complete
 *    before its result is here, and nothing left animating after the scan ended.
 *  - Pending, loading and failed render differently; a result renders only once
 *    completed (its render function is never called before then).
 *  - Both pages use the same components, so they cannot drift apart.
 */
import fs from 'fs';
import path from 'path';
import React from 'react';
import { act, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

jest.mock('../contexts/TranslationContext', () => ({
  useTranslation: () => ({
    t: (key, vars) => (vars ? `${key}${JSON.stringify(vars)}` : key),
    currentLang: 'en',
  }),
}));

// eslint-disable-next-line import/first
import {
  TOOL_STATE,
  AI_INPUT_COUNT,
  getVulnerabilityState,
  getPerformanceState,
  getSecurityConfigState,
  getThreatIntelState,
  getAiSummaryState,
} from '../utils/scanToolState';
// eslint-disable-next-line import/first
import { ScanToolCard, AiSummaryLoader } from '../components/ScanLoadingStates';

const { LOADING, PENDING, COMPLETED, FAILED } = TOOL_STATE;
const SRC = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

// ── State derivation ─────────────────────────────────────────────────────────

describe('vulnerability card state', () => {
  it.each([
    ['no report yet', null, LOADING],
    ['scan queued, nothing started', { status: 'queued' }, PENDING],
    ['scan running, no vulnerability data yet', { status: 'pending' }, LOADING],
    ['queued for the vulnerability engine', { status: 'pending', zapData: { status: 'pending', progress: 0 } }, PENDING],
    ['running', { status: 'pending', zapData: { status: 'running', progress: 0 } }, LOADING],
    ['completed', { status: 'pending', zapData: { status: 'completed', alerts: [] } }, COMPLETED],
    ['completed partially', { status: 'pending', zapData: { status: 'completed_partial', alerts: [] } }, COMPLETED],
    ['failed', { status: 'pending', zapData: { status: 'failed' } }, FAILED],
    ['errored before reporting', { status: 'pending', zapResult: { error: 'x' } }, FAILED],
    ['scan completed without it', { status: 'completed', hasZapResult: false }, FAILED],
    ['still "running" after the scan was stopped', { status: 'stopped', zapData: { status: 'running', progress: 40 } }, FAILED],
  ])('%s', (_, report, expected) => {
    expect(getVulnerabilityState(report).state).toBe(expected);
  });

  it('reports only real progress, clamped, and none at 0', () => {
    const at = (progress) => getVulnerabilityState({ zapData: { status: 'running', progress } }).progress;
    expect(at(0)).toBeNull();
    expect(at(undefined)).toBeNull();
    expect(at('nope')).toBeNull();
    expect(at(42.4)).toBe(42);
    expect(at(140)).toBe(100);
  });

  it('distinguishes a reported failure from a missing result', () => {
    expect(getVulnerabilityState({ zapData: { status: 'failed' } }).reason).toBe('failed');
    expect(getVulnerabilityState({ status: 'completed' }).reason).toBe('unavailable');
  });
});

describe('performance / security configuration / threat intelligence state', () => {
  it.each([
    ['performance: score present', getPerformanceState, { psiScores: { performance: 0 } }, COMPLETED],
    ['performance: waiting', getPerformanceState, { status: 'pending' }, LOADING],
    ['performance: queued', getPerformanceState, { status: 'queued' }, PENDING],
    ['performance: errored', getPerformanceState, { pagespeedResult: { error: 'x' } }, FAILED],
    ['performance: answered with no score', getPerformanceState, { psiScores: { performance: null } }, FAILED],
    ['performance: scan ended without it', getPerformanceState, { status: 'completed' }, FAILED],
    ['security config: grade present', getSecurityConfigState, { observatoryData: { grade: 'B' } }, COMPLETED],
    ['security config: waiting', getSecurityConfigState, { status: 'pending' }, LOADING],
    ['security config: errored', getSecurityConfigState, { observatoryResult: { error: 'x' } }, FAILED],
    ['security config: scan failed', getSecurityConfigState, { status: 'failed' }, FAILED],
    ['threat intel: verdict present', getThreatIntelState, { hasUrlscanResult: true, urlscanData: {} }, COMPLETED],
    ['threat intel: flag without data is not complete', getThreatIntelState, { status: 'pending', hasUrlscanResult: true }, LOADING],
    ['threat intel: errored', getThreatIntelState, { urlscanResult: { error: 'x' } }, FAILED],
    ['threat intel: scan completed without it', getThreatIntelState, { status: 'completed' }, FAILED],
  ])('%s', (_, fn, report, expected) => {
    expect(fn(report).state).toBe(expected);
  });
});

describe('AI summary state', () => {
  const allSettled = {
    status: 'pending',
    zapData: { status: 'completed' },
    psiScores: { performance: 90 },
    observatoryData: { grade: 'A' },
    hasUrlscanResult: true,
    urlscanData: {},
    webCheckData: { status: 'completed' },
  };

  it('is ready once the summary text is here', () => {
    expect(getAiSummaryState({ refinedReport: '# ok' }).stage).toBe('ready');
  });

  it('counts settled inputs, including failed ones', () => {
    expect(getAiSummaryState({ status: 'pending' })).toEqual({ stage: 'collecting', settled: 0, total: AI_INPUT_COUNT });
    const two = getAiSummaryState({ status: 'pending', psiScores: { performance: 50 }, zapData: { status: 'failed' } });
    expect(two).toEqual({ stage: 'collecting', settled: 2, total: AI_INPUT_COUNT });
  });

  it('is composing once every input settled, or the backend says it is combining', () => {
    expect(getAiSummaryState(allSettled).stage).toBe('composing');
    expect(getAiSummaryState({ status: 'combining' }).stage).toBe('composing');
    expect(getAiSummaryState({ status: 'completed', hasRefinedReport: true }).stage).toBe('composing');
  });

  it('stops animating when the scan ended without a summary', () => {
    for (const status of ['failed', 'stopped', 'cancelled']) {
      expect(getAiSummaryState({ status }).stage).toBe('unavailable');
    }
    expect(getAiSummaryState({ status: 'completed' }).stage).toBe('unavailable');
  });
});

// ── Rendering ────────────────────────────────────────────────────────────────

describe('ScanToolCard', () => {
  const renderCard = (status, renderResult = jest.fn(() => <span>RESULT</span>)) => {
    const utils = render(
      <ScanToolCard tool="performance" title="Performance" status={status}>{renderResult}</ScanToolCard>,
    );
    return { ...utils, renderResult };
  };

  it('loading: tool message, busy, indeterminate bar, result never rendered', () => {
    const { container, renderResult } = renderCard({ state: LOADING, progress: null });
    expect(screen.getByText('toolLoadingPerformance')).toBeInTheDocument();
    expect(container.firstChild).toHaveAttribute('aria-busy', 'true');
    expect(container.querySelector('.tool-status__bar--indeterminate')).not.toBeNull();
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(renderResult).not.toHaveBeenCalled();
  });

  it('loading with real progress: determinate bar and percentage', () => {
    renderCard({ state: LOADING, progress: 37 });
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '37');
    expect(screen.getByText('37%')).toBeInTheDocument();
  });

  it('pending: queue wording, not an error', () => {
    const { container } = renderCard({ state: PENDING });
    expect(screen.getByText('toolPendingQueued')).toBeInTheDocument();
    expect(container.querySelector('.tool-status--pending')).not.toBeNull();
    expect(container.querySelector('.tool-status--error, .tool-status--warning')).toBeNull();
  });

  it('failed: the existing labels, error vs unavailable', () => {
    const { rerender, container } = renderCard({ state: FAILED, reason: 'failed' });
    expect(screen.getByText('scanFailed')).toBeInTheDocument();
    expect(container.querySelector('.tool-status--error')).not.toBeNull();
    rerender(<ScanToolCard tool="performance" title="Performance" status={{ state: FAILED, reason: 'unavailable' }}>{() => null}</ScanToolCard>);
    expect(screen.getByText('unavailable')).toBeInTheDocument();
  });

  it('completed: renders the result and drops the loading UI', () => {
    const { container, renderResult } = renderCard({ state: COMPLETED });
    expect(renderResult).toHaveBeenCalled();
    expect(screen.getByText('RESULT')).toBeInTheDocument();
    expect(container.querySelector('.tool-status')).toBeNull();
    expect(container.firstChild).not.toHaveAttribute('aria-busy');
  });

  it('every tool has its own message', () => {
    const msgs = ['vulnerability', 'performance', 'securityConfig', 'threatIntel'].map((tool) => {
      const { container, unmount } = render(
        <ScanToolCard tool={tool} title={tool} status={{ state: LOADING }}>{() => null}</ScanToolCard>,
      );
      const text = container.querySelector('.tool-status__message').textContent;
      unmount();
      return text;
    });
    expect(new Set(msgs).size).toBe(4);
  });
});

describe('AiSummaryLoader', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('collecting: real count, rotating wording, stable text for screen readers', () => {
    render(<AiSummaryLoader state={{ stage: 'collecting', settled: 3, total: 5 }} />);
    expect(screen.getByText('aiLoadingInputs{"completed":3,"total":5}')).toBeInTheDocument();
    expect(document.querySelectorAll('.ai-loader__segment.is-done')).toHaveLength(3);
    expect(document.querySelector('.ai-loader__message').textContent).toBe('aiLoadingAnalyzing');
    act(() => { jest.advanceTimersByTime(4000); });
    expect(document.querySelector('.ai-loader__message').textContent).toBe('aiLoadingCorrelating');
    expect(document.querySelector('.scan-loading-sr').textContent).toBe('aiLoadingAnalyzing');
  });

  it('composing: no count, preparing wording', () => {
    render(<AiSummaryLoader state={{ stage: 'composing', settled: 5, total: 5 }} />);
    expect(screen.getAllByText('aiLoadingPreparing').length).toBeGreaterThan(0);
    expect(document.querySelector('.ai-loader__segments')).toBeNull();
  });

  it('translating and unavailable', () => {
    const { rerender } = render(<AiSummaryLoader translating />);
    expect(screen.getAllByText('translatingReportToJapanese').length).toBeGreaterThan(0);
    rerender(<AiSummaryLoader state={{ stage: 'unavailable' }} />);
    expect(screen.getByText('aiSummaryUnavailable')).toBeInTheDocument();
    expect(document.querySelector('.ai-loader__ring')).toBeNull();
  });
});

// ── Parity between the two report pages ──────────────────────────────────────

describe('both report pages share the loading UI', () => {
  const pages = ['components/Hero.jsx', 'components/AuthenticatedScanPanel.jsx'];

  it.each(pages)('%s renders the four tool cards and the AI loader through the shared components', (file) => {
    const src = read(file);
    for (const tool of ['vulnerability', 'performance', 'securityConfig', 'threatIntel']) {
      expect(src).toContain(`<ScanToolCard tool="${tool}"`);
    }
    expect(src).toContain('<AiSummaryLoader state=');
    expect(src).toContain('<AiSummaryLoader translating />');
    expect(src).toMatch(/getReportToolStates\(report\)/);
    expect(src).not.toMatch(/LoadingPlaceholder|loading-placeholder/);
  });

  it.each(pages)('%s has exactly one Stop Scan button, with the shared markup and handler', (file) => {
    const src = read(file);
    const buttons = src.match(/<button[^>]*className="stop-button"[^>]*>/g) || [];
    expect(buttons).toHaveLength(1);
    expect(buttons[0]).toContain('onClick={handleStopScan}');
    expect(src).toContain(`<span className="button-text">{t('stopScan')}</span>`);
    expect(src).not.toMatch(/stop-btn/);
  });

  it('auth scan buttons are drawn by the very rules that draw the public Stop Scan and the navbar', () => {
    const neon = read('styles/NeonButtons.scss');
    // Every rule (selector list) that styles X must also style Y.
    const rulesFor = (sel) => [...neon.matchAll(/([^{}]+)\{/g)]
      .map((m) => m[1].split(',').map((s) => s.replace(/\/\*.*?\*\//g, '').trim()))
      .filter((list) => list.some((s) => s.replace(/^body\.(light|dark)\s+/, '').split(':')[0] === sel));
    const pairs = [
      ['.analyze-form button', '.auth-scan-panel .step-header .stop-button'],
      ['.signup-button', '.auth-scan-panel .primary-btn'],
      ['.signup-button', '.auth-scan-panel .secondary-btn'],
      ['.signup-button', '.auth-scan-panel .download-section .download-btn'],
    ];
    for (const [reference, auth] of pairs) {
      const lists = rulesFor(reference);
      expect(lists.length).toBeGreaterThanOrEqual(4); // base, hover, light, dark (+active)
      for (const list of lists) {
        expect(list.some((s) => s.replace(/^body\.(light|dark)\s+/, '').split(':')[0] === auth)).toBe(true);
      }
    }
    // Nothing on the auth page restyles them behind those rules' back.
    expect(read('styles/AuthenticatedScan.scss')).not.toMatch(/\.(primary|secondary)-btn\s*\{[^}]*background/);
  });

  it('the new copy never names a scan engine', () => {
    const en = read('locales/en.js');
    const keys = [...read('components/ScanLoadingStates.jsx').matchAll(/\bt\('([A-Za-z0-9_]+)'/g)].map((m) => m[1]);
    for (const key of keys) {
      const line = en.split('\n').find((l) => l.startsWith(`  ${key}:`)) || '';
      expect(line).not.toMatch(/zap|webcheck|urlscan|observatory|pagespeed|lighthouse|gemini/i);
    }
  });
});
