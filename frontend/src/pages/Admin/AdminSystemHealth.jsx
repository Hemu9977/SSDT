// frontend/src/pages/Admin/AdminSystemHealth.jsx
// System Health Monitor — shows status of all integrated services.
// Uses existing badge/card patterns and CSS custom properties for dark/light mode.

import React, { useState, useEffect, useCallback } from 'react';
import {
  FaDatabase,
  FaServer,
  FaMemory,
  FaShieldAlt,
  FaRobot,
  FaBolt,
  FaSpinner,
  FaSyncAlt,
} from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { adminService } from '../../services/adminService';
import { getHealthStatusLabel, getConnectionStateLabel, getAdminErrorLabel } from './adminLabels';
import { formatAdminTime, formatAdminNumber } from './adminFormat';

const formatUptime = (t, secs) => {
  if (secs === undefined || secs === null) return '—';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return t('adminUptimeFormat', { h, m, s });
};

const StatusBadge = ({ status, t }) => {
  const isOnline = status === 'online' || status === 'configured';
  const isOffline = status === 'offline' || status === 'not_configured';
  const cls = isOnline ? 'completed' : isOffline ? 'failed' : 'pending';
  return <span className={`scan-status ${cls}`}>{getHealthStatusLabel(t, status)}</span>;
};

const HealthCard = ({ icon, title, check, t, currentLang }) => {
  if (!check) return null;
  const isOnline = check.status === 'online' || check.status === 'configured';
  if (check.error) {
    // Diagnostics belong in the console, not on the page — see the render below.
    console.warn(`[health] ${title}: ${check.error}`);
  }
  return (
    <div className={`admin-health-card ${isOnline ? 'admin-health-card--ok' : 'admin-health-card--err'}`}>
      <div className="admin-health-card-header">
        <span className="admin-health-service-icon">{icon}</span>
        <span className="admin-health-service-name">{title}</span>
        <StatusBadge status={check.status} t={t} />
      </div>
      <div className="admin-health-details">
        {check.latencyMs !== undefined && check.latencyMs !== null && (
          <span className="admin-health-detail">
            <FaBolt /> {formatAdminNumber(currentLang, check.latencyMs)}{t('adminMs')}
          </span>
        )}
        {check.version && (
          <span className="admin-health-detail">v{check.version}</span>
        )}
        {check.uptimeSeconds !== undefined && (
          <span className="admin-health-detail">
            ⏱ {formatUptime(t, check.uptimeSeconds)}
          </span>
        )}
        {check.memoryMB !== undefined && (
          <span className="admin-health-detail">
            <FaMemory /> {formatAdminNumber(currentLang, check.memoryMB)}{t('adminMB')} / {formatAdminNumber(currentLang, check.memoryTotalMB)}{t('adminMB')}
          </span>
        )}
        {check.rssMB !== undefined && (
          <span className="admin-health-detail">{t('adminRss')} {formatAdminNumber(currentLang, check.rssMB)}{t('adminMB')}</span>
        )}
        {check.state && (
          <span className="admin-health-detail">{getConnectionStateLabel(t, check.state)}</span>
        )}
        {check.collections !== undefined && (
          <span className="admin-health-detail">{t('adminCollections')} {formatAdminNumber(currentLang, check.collections)}</span>
        )}
        {check.storageMB !== undefined && (
          <span className="admin-health-detail">{t('adminStorage')} {formatAdminNumber(currentLang, check.storageMB)}{t('adminMB')}</span>
        )}
        {check.nodeVersion && (
          <span className="admin-health-detail">Node {check.nodeVersion}</span>
        )}
        {check.waiting !== undefined && (
          <span className="admin-health-detail">{t('adminWaiting')} {formatAdminNumber(currentLang, check.waiting)}</span>
        )}
        {check.active !== undefined && (
          <span className="admin-health-detail">{t('adminJobsActive')} {formatAdminNumber(currentLang, check.active)}</span>
        )}
        {check.completed !== undefined && (
          <span className="admin-health-detail">{t('adminJobsCompleted')} {formatAdminNumber(currentLang, check.completed)}</span>
        )}
        {check.failed !== undefined && (
          <span className="admin-health-detail">{t('adminJobsFailed')} {formatAdminNumber(currentLang, check.failed)}</span>
        )}
        {check.error && (
          // The backend's `error` is a raw driver/axios string ("connect
          // ECONNREFUSED 127.0.0.1:8081") — English-only and full of internal
          // detail, so it must not reach the UI. Operators still need it, so it
          // goes to the console; the card shows a translated reason instead.
          <span className="admin-health-detail admin-health-error">
            {t('adminHealthUnreachable')}
          </span>
        )}
      </div>
    </div>
  );
};

// Titles resolve through t() like every other string in the panel — hardcoding
// them left these nine cards in English on the Japanese UI. Vendor names are
// deliberately kept: this panel is internal operator tooling, and an on-call
// engineer needs to know *which* service is down. Port numbers are dropped —
// they were fixed to the old docker-compose layout and are wrong under ECS
// Service Connect.
const SERVICE_DEFS = [
  { key: 'server',    labelKey: 'adminHealthServer',    icon: <FaServer /> },
  { key: 'mongodb',   labelKey: 'adminHealthMongodb',   icon: <FaDatabase /> },
  { key: 'redis',     labelKey: 'adminHealthRedis',     icon: <FaBolt /> },
  { key: 'bullmq',    labelKey: 'adminHealthQueue',     icon: <FaMemory /> },
  { key: 'webcheck',  labelKey: 'adminHealthWebcheck',  icon: <FaShieldAlt /> },
  { key: 'zap',       labelKey: 'adminHealthZap',       icon: <FaShieldAlt /> },
  { key: 'zapAuth',   labelKey: 'adminHealthZapAuth',   icon: <FaShieldAlt /> },
  { key: 'gemini',    labelKey: 'adminHealthGemini',    icon: <FaRobot /> },
  { key: 'pagespeed', labelKey: 'adminHealthPagespeed', icon: <FaRobot /> },
  { key: 'urlscan',   labelKey: 'adminHealthUrlscan',   icon: <FaRobot /> },
];

const AdminSystemHealth = () => {
  const { t, currentLang } = useTranslation();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchHealth = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const result = await adminService.getSystemHealth();
      setData(result);
    } catch (err) {
      setError(getAdminErrorLabel(t, err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [t]);

  useEffect(() => { fetchHealth(); }, [fetchHealth]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => fetchHealth(true), 30000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  if (loading) {
    return (
      <div className="admin-section-loading">
        <div className="admin-spinner" />
        <p>{t('adminLoading')}</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="admin-error-state">
        <p>{error}</p>
        <button type="button" className="btn-edit" onClick={() => fetchHealth()}>{t('adminRetry')}</button>
      </div>
    );
  }

  const checks = data?.checks || {};
  const onlineCount = Object.values(checks).filter(
    (c) => c?.status === 'online' || c?.status === 'configured'
  ).length;
  const totalCount = SERVICE_DEFS.length;

  return (
    <div className="admin-page">
      <section className="profile-section">
        <div className="section-header">
          <h2 className="admin-section-title">
            {t('adminSystemHealth')}
            <span className={`admin-count-badge ${onlineCount === totalCount ? 'admin-count-badge--green' : 'admin-count-badge--yellow'}`}>
              {t('adminOnlineCount', { online: formatAdminNumber(currentLang, onlineCount), total: formatAdminNumber(currentLang, totalCount) })}
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

        {data?.timestamp && (
          <p className="admin-timestamp">
            {t('adminLastUpdated', { time: formatAdminTime(currentLang, data.timestamp) })}
          </p>
        )}

        <div className="admin-health-grid">
          {SERVICE_DEFS.map((svc) => (
            <HealthCard
              key={svc.key}
              icon={svc.icon}
              title={t(svc.labelKey)}
              check={checks[svc.key]}
              t={t}
              currentLang={currentLang}
            />
          ))}
        </div>
      </section>
    </div>
  );
};

export default AdminSystemHealth;
