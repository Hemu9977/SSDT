// frontend/src/pages/Admin/AdminSystemHealth.jsx
// System Health Monitor — shows status of the production services Fortexa runs on.
// Uses existing badge/card patterns and CSS custom properties for dark/light mode.
//
// The list of services, their statuses and the summary all come from
// GET /api/admin/system-health (backend config/healthInventory.js). This page
// keeps only a label and icon per service id, so it cannot show a service as
// working that the server did not verify.

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  FaBell,
  FaBolt,
  FaCamera,
  FaCloud,
  FaCreditCard,
  FaDatabase,
  FaEnvelope,
  FaExchangeAlt,
  FaHeartbeat,
  FaLock,
  FaMemory,
  FaRobot,
  FaServer,
  FaShieldAlt,
  FaSpinner,
  FaSyncAlt,
  FaTachometerAlt,
} from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { adminService } from '../../services/adminService';
import {
  getAdminErrorLabel,
  getConnectionStateLabel,
  getHealthNoteLabel,
  getHealthReasonLabel,
  getHealthServiceLabel,
  getHealthStatusLabel,
  getWebhookFailureLabel,
} from './adminLabels';
import { formatAdminDateTime, formatAdminTime, formatAdminNumber } from './adminFormat';

const DEFAULT_REFRESH_SEC = 60;

const formatUptime = (t, secs) => {
  if (secs === undefined || secs === null) return '—';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return t('adminUptimeFormat', { h, m, s });
};

// Badge colours reuse the .scan-status palette. Idle (scaled to zero on
// purpose) and starting are not faults. Configured and unknown are not
// verified, so they never get the green "working" colour.
const STATUS_CLASS = {
  healthy: 'completed',
  idle: 'combining',
  starting: 'combining',
  degraded: 'pending',
  configured: 'pending',
  unknown: 'pending',
  unavailable: 'failed',
};

// Card border: green when working as designed, red when failing, plain when
// the status could not be verified.
const CARD_CLASS = {
  healthy: 'admin-health-card--ok',
  idle: 'admin-health-card--ok',
  starting: 'admin-health-card--ok',
  degraded: 'admin-health-card--err',
  unavailable: 'admin-health-card--err',
};

const ICONS = {
  api: <FaServer />,
  mongodb: <FaDatabase />,
  redis: <FaBolt />,
  queues: <FaMemory />,
  webcheck: <FaShieldAlt />,
  zap: <FaShieldAlt />,
  zap_auth: <FaShieldAlt />,
  gemini: <FaRobot />,
  pagespeed: <FaTachometerAlt />,
  observatory: <FaLock />,
  urlscan: <FaCamera />,
  stripe: <FaCreditCard />,
  stripe_webhooks: <FaExchangeAlt />,
  email: <FaEnvelope />,
  aws_backend: <FaCloud />,
  aws_alarms: <FaBell />,
};

// ── Older backends ───────────────────────────────────────────────────────────
// A backend that predates the service inventory (production `fortexa-backend:88`,
// or a local server not restarted since) answers `{ checks: { server: {...}, ... } }`.
// The frontend deploys on its own, so it must still draw cards for that shape.
// Statuses are mapped conservatively: the old "configured" (key present) stays
// "configured" and is never counted as online.
const LEGACY_IDS = {
  server: 'api', mongodb: 'mongodb', redis: 'redis', bullmq: 'queues', webcheck: 'webcheck',
  zap: 'zap', zapAuth: 'zap_auth', gemini: 'gemini', pagespeed: 'pagespeed', urlscan: 'urlscan',
};
const LEGACY_STATUS = {
  online: 'healthy', offline: 'unavailable', not_configured: 'unavailable', configured: 'configured',
  idle: 'idle', starting: 'starting', unknown: 'unknown',
};
const LEGACY_REASON = { timeout: 'timeout', unreachable: 'unreachable', credentials: 'auth_failed', error: 'check_failed' };

const legacyQueue = (q) => (q ? {
  reachable: q.status === 'online', waiting: q.waiting, active: q.active, delayed: q.delayed, failed: q.failed,
  oldestWaitingSec: null, workerRunning: null,
} : undefined);

export const fromLegacyChecks = (checks, timestamp) => {
  const services = Object.entries(checks || {}).map(([key, c]) => {
    const status = LEGACY_STATUS[c && c.status] || 'unknown';
    const reason = c && c.status === 'not_configured' ? 'not_configured' : (c && LEGACY_REASON[c.reason]) || null;
    const metrics = {
      connectionState: c.state,
      uptimeSec: c.uptimeSeconds,
      heapUsedMB: c.memoryMB,
      nodeVersion: c.nodeVersion,
      version: c.version,
      desiredCount: c.desiredCount,
      runningCount: c.runningCount,
      authMode: c.authMode,
      queues: c.queues ? { scan: legacyQueue(c.queues.scan), zap: legacyQueue(c.queues.zap) } : undefined,
    };
    return {
      id: LEGACY_IDS[key] || key,
      status,
      reason,
      notes: [],
      latencyMs: c.latencyMs ?? null,
      metrics,
    };
  });
  const operational = services.filter((s) => s.status === 'healthy' || s.status === 'idle').length;
  return { generatedAt: timestamp, services, summary: { operational, total: services.length } };
};

/** Both response shapes → { generatedAt, services, summary, refreshIntervalSec }. */
const normalizeReport = (result) => {
  if (result && Array.isArray(result.services)) return result;
  if (result && result.checks) return fromLegacyChecks(result.checks, result.timestamp);
  return { generatedAt: null, services: [], summary: { operational: 0, total: 0 } };
};

const StatusBadge = ({ status, t }) => (
  <span className={`scan-status ${STATUS_CLASS[status] || 'pending'}`}>{getHealthStatusLabel(t, status)}</span>
);

/** Service-specific detail chips. A missing value renders as "—", never as 0. */
const detailsFor = (svc, t, lang) => {
  const m = svc.metrics || {};
  const n = (v) => formatAdminNumber(lang, v);
  const out = [];
  const add = (key, content, isError) => out.push([key, content, isError]);

  switch (svc.id) {
    case 'api':
      if (m.taskDefinition || m.image) add('release', [m.taskDefinition, m.image].filter(Boolean).join(' · '));
      if (m.gitSha) add('sha', m.gitSha);
      add('uptime', <>⏱ {formatUptime(t, m.uptimeSec)}</>);
      add('heap', <><FaMemory /> {t('adminHealthHeap', { used: n(m.heapUsedMB), limit: n(m.heapLimitMB) })}</>);
      add('loop', t('adminHealthEventLoop', { ms: n(m.eventLoopP99Ms) }));
      if (m.nodeVersion) add('node', `Node ${m.nodeVersion}`);
      break;
    case 'mongodb':
    case 'redis':
      if (m.connectionState) add('conn', getConnectionStateLabel(t, m.connectionState));
      break;
    case 'queues':
      ['scan', 'zap'].forEach((name) => {
        const q = m.queues && m.queues[name];
        if (!q) return;
        const label = t(name === 'scan' ? 'adminQueueScan' : 'adminQueueZap');
        if (!q.reachable) {
          add(name, t('adminHealthQueueUnreachable', { name: label }), true);
          return;
        }
        add(name, t('adminHealthQueueLine', {
          name: label, waiting: n(q.waiting), active: n(q.active), delayed: n(q.delayed), failed: n(q.failed),
        }));
        if (q.oldestWaitingSec !== null && q.oldestWaitingSec !== undefined) {
          add(`${name}-age`, t('adminHealthOldestWaiting', { name: label, age: formatUptime(t, q.oldestWaitingSec) }));
        }
        if (q.workerRunning === false) {
          add(`${name}-worker`, t('adminHealthWorker', { name: label, state: t('adminHealthWorkerStopped') }), true);
        }
      });
      break;
    case 'zap':
    case 'zap_auth':
      if (m.version) add('version', `v${m.version}`);
      if (m.desiredCount !== undefined && svc.status !== 'idle') {
        add('tasks', t('adminHealthTasks', { running: n(m.runningCount), desired: n(m.desiredCount) }));
      }
      break;
    case 'gemini':
      if (m.authMode) add('auth', t(m.authMode === 'vertex' ? 'adminHealthAuthVertex' : 'adminHealthAuthApiKey'));
      if (m.location) add('location', t('adminHealthRegion', { region: m.location }));
      (m.models || []).forEach((model) => add(`model-${model.model}`, model.ok
        ? t('adminHealthModelOk', { model: model.model })
        : t('adminHealthModelFailed', { model: model.model, reason: getHealthReasonLabel(t, model.reason) }), !model.ok));
      if (m.reportsSinceStart) {
        add('reports', t('adminHealthReports', { generated: n(m.reportsSinceStart.generated), fallback: n(m.reportsSinceStart.fallback) }));
      }
      if (m.lastFallbackAt) add('fallback', t('adminHealthLastFallback', { time: formatAdminDateTime(lang, m.lastFallbackAt) }));
      break;
    case 'pagespeed':
    case 'observatory':
    case 'urlscan':
      if (m.quota) {
        add('quota', t('adminHealthQuotaDay', { remaining: n(m.quota.unlistedDayRemaining), limit: n(m.quota.unlistedDayLimit) }));
      }
      if (m.recentScans) {
        add('recent', t('adminHealthRecentScans', { hours: n(m.recentScans.windowHours), ok: n(m.recentScans.ok), failed: n(m.recentScans.failed) }));
      }
      break;
    case 'stripe':
      if (m.livemode === true) add('mode', t('adminHealthStripeLive'));
      if (m.livemode === false) add('mode', t('adminHealthStripeTest'), true);
      break;
    case 'stripe_webhooks':
      add('7d', t('adminHealthWebhooks7d', { count: n(m.processedLast7d) }));
      if (m.lastProcessedAt) add('last', t('adminHealthLastWebhook', { time: formatAdminDateTime(lang, m.lastProcessedAt) }));
      if (m.sinceStart) add('since', t('adminHealthSinceStart', { ok: n(m.sinceStart.processed), failed: n(m.sinceStart.failed) }));
      if (m.lastFailureCode) {
        add('failure', t('adminHealthLastFailure', {
          reason: getWebhookFailureLabel(t, m.lastFailureCode), time: formatAdminDateTime(lang, m.lastFailureAt),
        }), true);
      }
      break;
    case 'email':
      if (m.transport === 'smtp') add('transport', t('adminHealthSmtp'));
      if (m.transport === 'ses' && m.max24h !== undefined) add('sent', t('adminHealthSesSent', { sent: n(m.sentLast24h), max: n(m.max24h) }));
      break;
    case 'aws_backend':
      if (m.ecs) add('ecs', t('adminHealthEcs', { running: n(m.ecs.runningCount), desired: n(m.ecs.desiredCount) }));
      if (m.ecs && m.ecs.taskDefinition) add('taskdef', m.ecs.taskDefinition);
      if (m.targets) add('targets', t('adminHealthTargets', { healthy: n(m.targets.healthy), unhealthy: n(m.targets.unhealthy) }));
      if (m.http15m) add('http', t('adminHealthHttp15m', { requests: n(m.http15m.requests), errors: n(m.http15m.target5xx + m.http15m.lb5xx) }));
      else if (m.parts && m.parts.http) add('http', t('adminHealthHttpUnavailable'));
      break;
    case 'aws_alarms':
      if (m.total !== undefined) add('counts', t('adminHealthAlarms', { alarm: n(m.alarm), ok: n(m.ok), insufficient: n(m.insufficientData) }));
      if (m.firing && m.firing.length) add('firing', t('adminHealthFiring', { names: m.firing.join(', ') }), true);
      break;
    default:
      break;
  }
  return out;
};

const HealthCard = ({ svc, t, currentLang }) => {
  const notes = (svc.notes || []).map((note) => [note, getHealthNoteLabel(t, note)]).filter(([, label]) => label);
  return (
    <div className={`admin-health-card ${CARD_CLASS[svc.status] || ''}`}>
      <div className="admin-health-card-header">
        <span className="admin-health-service-icon">{ICONS[svc.id] || <FaHeartbeat />}</span>
        <span className="admin-health-service-name">{getHealthServiceLabel(t, svc.id)}</span>
        <StatusBadge status={svc.status} t={t} />
      </div>
      <div className="admin-health-details">
        {svc.latencyMs !== undefined && svc.latencyMs !== null && (
          <span className="admin-health-detail">
            <FaBolt /> {formatAdminNumber(currentLang, svc.latencyMs)}{t('adminMs')}
          </span>
        )}
        {detailsFor(svc, t, currentLang).map(([key, content, isError]) => (
          <span key={key} className={`admin-health-detail${isError ? ' admin-health-error' : ''}`}>{content}</span>
        ))}
        {notes.map(([note, label]) => (
          <span key={note} className="admin-health-detail">{label}</span>
        ))}
        {svc.reason && (
          // The server sends a fixed reason code, never raw error text; it is
          // translated here.
          <span className="admin-health-detail admin-health-error">
            {getHealthReasonLabel(t, svc.reason)}
          </span>
        )}
        {svc.checkedAt && (
          <span className="admin-health-detail">
            {t('adminHealthChecked', { time: formatAdminTime(currentLang, svc.checkedAt) })}
          </span>
        )}
      </div>
    </div>
  );
};

const AdminSystemHealth = () => {
  const { t, currentLang } = useTranslation();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const busy = useRef(false);

  // The error is kept as the thrown object and translated at render time, so
  // this callback has no dependencies and a language switch does not refetch.
  const fetchHealth = useCallback(async (isRefresh = false) => {
    if (busy.current) return;
    busy.current = true;
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    try {
      const result = await adminService.getSystemHealth();
      setData(normalizeReport(result));
      setError(null);
    } catch (err) {
      // Earlier results stay on screen, marked as out of date below.
      setError(err);
    } finally {
      busy.current = false;
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { fetchHealth(); }, [fetchHealth]);

  // Auto-refresh at the interval the server asks for, skipped while the
  // browser tab is hidden so an idle tab does not keep calling Stripe and AWS.
  const intervalSec = (data && data.refreshIntervalSec) || DEFAULT_REFRESH_SEC;
  useEffect(() => {
    const interval = setInterval(() => {
      if (typeof document === 'undefined' || !document.hidden) fetchHealth(true);
    }, intervalSec * 1000);
    return () => clearInterval(interval);
  }, [fetchHealth, intervalSec]);

  if (loading && !data) {
    return (
      <div className="admin-section-loading">
        <div className="admin-spinner" />
        <p>{t('adminLoading')}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="admin-error-state">
        <p>{getAdminErrorLabel(t, error)}</p>
        <button type="button" className="btn-edit" onClick={() => fetchHealth()}>{t('adminRetry')}</button>
      </div>
    );
  }

  const services = data.services || [];
  const summary = data.summary || { operational: 0, total: services.length };
  const allOperational = summary.total > 0 && summary.operational === summary.total;

  return (
    <div className="admin-page">
      <section className="profile-section">
        <div className="section-header">
          <h2 className="admin-section-title">
            {t('adminSystemHealth')}
            <span className={`admin-count-badge ${allOperational ? 'admin-count-badge--green' : 'admin-count-badge--yellow'}`}>
              {t('adminOnlineCount', { online: formatAdminNumber(currentLang, summary.operational), total: formatAdminNumber(currentLang, summary.total) })}
            </span>
          </h2>
          <button
            type="button"
            className="btn-edit"
            onClick={() => fetchHealth(true)}
            disabled={refreshing}
            aria-label={t('adminRefresh')}
          >
            {refreshing ? <FaSpinner className="admin-spin" /> : <FaSyncAlt />}
            {' '}{t('adminRefresh')}
          </button>
        </div>

        {data.generatedAt && (
          <p className="admin-timestamp">
            {t('adminLastUpdated', { time: formatAdminTime(currentLang, data.generatedAt) })}
          </p>
        )}
        {error && (
          <p className="admin-timestamp" role="alert">
            {t('adminHealthStale', { error: getAdminErrorLabel(t, error), time: formatAdminTime(currentLang, data.generatedAt) })}
          </p>
        )}

        {services.length === 0 ? (
          // Never a silent blank page: say that nothing came back.
          <p className="admin-empty">{t('adminNoData')}</p>
        ) : (
          <div className="admin-health-grid">
            {services.map((svc) => (
              <HealthCard key={svc.id} svc={svc} t={t} currentLang={currentLang} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

export default AdminSystemHealth;
