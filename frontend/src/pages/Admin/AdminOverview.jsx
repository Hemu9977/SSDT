// frontend/src/pages/Admin/AdminOverview.jsx
// Admin Dashboard Overview — KPIs and recent activity.
// Uses existing SSDT CSS variables and design language (stat-card, profile-section, scan-status).

import React, { useState, useEffect, useCallback } from 'react';
import { FaUsers, FaBuilding, FaShieldAlt, FaCheckCircle, FaClock, FaChartBar, FaHistory } from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { useUser } from '../../contexts/UserContext';
import { adminService } from '../../services/adminService';
import { getPlanLabel, getAdminErrorLabel, getAuditActionLabel, getAuditResultLabel } from './adminLabels';
import { formatAdminDate, formatAdminDateTime, formatAdminNumber } from './adminFormat';
import { DistributionBars, PLAN_COLOR } from './adminCharts';

const AUDIT_RESULT_CLASS = { success: 'completed', failure: 'failed', denied: 'failed', pending: 'pending' };

// Superadmin-only: the last admin actions from the audit log (backend
// models/AdminAuditLog.js). Every sensitive mutation writes one row.
const RecentAdminActions = ({ t, currentLang }) => {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await adminService.getAuditLog({ limit: 10 });
      setEntries(res.entries || []);
    } catch (err) {
      setError(getAdminErrorLabel(t, err));
    }
  }, [t]);

  useEffect(() => { load(); }, [load]);

  return (
    <section className="profile-section admin-recent-users">
      <h2 className="admin-section-title">
        <FaHistory /> {t('adminRecentAdminActions')}
      </h2>
      {error ? (
        <div className="admin-error-state">
          <p>{error}</p>
          <button type="button" className="btn-edit" onClick={load}>{t('adminRetry')}</button>
        </div>
      ) : entries === null ? (
        <div className="admin-section-loading"><div className="admin-spinner" /></div>
      ) : entries.length === 0 ? (
        <p className="admin-empty">{t('adminNoAdminActions')}</p>
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table admin-table--compact">
            <thead>
              <tr>
                <th>{t('adminWhen')}</th>
                <th>{t('adminActor')}</th>
                <th>{t('adminAction')}</th>
                <th>{t('adminTargetColumn')}</th>
                <th>{t('adminResult')}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e._id}>
                  <td>{formatAdminDateTime(currentLang, e.createdAt)}</td>
                  <td className="admin-td-email" title={e.actorType === 'script' ? (e.ticket || undefined) : (e.actorEmail || undefined)}>
                    {/* Role changes made by an operator with scripts/grantSystemRole.js have no account. */}
                    {e.actorType === 'script'
                      ? t('adminAuditScriptActor', { operator: e.operator || '—' })
                      : (e.actorEmail || '—')}
                  </td>
                  <td>{getAuditActionLabel(t, e.action)}</td>
                  <td className="admin-td-email" title={e.targetLabel || undefined}>{e.targetLabel || '—'}</td>
                  <td>
                    <span className={`scan-status ${AUDIT_RESULT_CLASS[e.result] || 'pending'}`}>
                      {getAuditResultLabel(t, e.result)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};

const AdminOverview = () => {
  const { t, currentLang } = useTranslation();
  const { user: currentUser } = useUser();
  const isSuperadmin = currentUser?.systemRole === 'superadmin';
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await adminService.getKpis();
      setData(result);
    } catch (err) {
      setError(getAdminErrorLabel(t, err));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { fetchData(); }, [fetchData]);

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
        <button type="button" className="btn-edit" onClick={fetchData}>{t('adminRetry')}</button>
      </div>
    );
  }

  // A figure the server could not load is null (named in `unavailable`) and
  // renders as "—" with a note — never as 0, which would look like a real count.
  const { kpis = {}, planDistribution = null, recentUsers = null, unavailable = [], generatedAt } = data || {};

  const statCards = [
    { label: t('adminTotalUsers'),    value: kpis.totalUsers,        icon: <FaUsers />,    color: 'orange' },
    { label: t('adminVerifiedUsers'), value: kpis.verifiedUsers,     icon: <FaCheckCircle />, color: 'green' },
    { label: t('adminActiveOrgs'),    value: kpis.activeOrgs,        icon: <FaBuilding />, color: 'blue' },
    { label: t('adminTotalOrgs'),     value: kpis.totalOrgs,         icon: <FaBuilding />, color: 'purple' },
    { label: t('adminRunningScans'),  value: kpis.runningScans,      icon: <FaClock />,    color: 'yellow' },
    { label: t('adminTotalScans'),    value: kpis.totalScansAllTime, icon: <FaShieldAlt />,color: 'cyan' },
  ];
  const planTotal = (planDistribution || []).reduce((acc, p) => acc + p.count, 0);

  return (
    <div className="admin-page">
      {/* KPI Grid — reuses .stats-grid and .stat-card from Profile.scss */}
      <section className="profile-section admin-kpi-section">
        <h2 className="admin-section-title">{t('adminOverview')}</h2>
        {unavailable.length > 0 && <p className="admin-partial-data" role="status">{t('adminPartialData')}</p>}
        <div className="stats-grid admin-stats-grid">
          {statCards.map((card) => (
            <div key={card.label} className={`stat-card admin-stat-card admin-stat-card--${card.color}`}>
              <div className="admin-stat-icon">{card.icon}</div>
              <div className="stat-value">{formatAdminNumber(currentLang, card.value)}</div>
              <div className="stat-label">{card.label}</div>
              {(card.value === null || card.value === undefined) && (
                <div className="admin-stat-unavailable">{t('adminUnavailable')}</div>
              )}
            </div>
          ))}
        </div>
        {generatedAt && (
          <p className="admin-timestamp">{t('adminLastUpdated', { time: formatAdminDateTime(currentLang, generatedAt) })}</p>
        )}
      </section>

      <div className="admin-two-col">
        {/* Plan Distribution */}
        <section className="profile-section admin-plan-dist">
          <h2 className="admin-section-title">
            <FaChartBar /> {t('adminPlanDistribution')}
          </h2>
          {planDistribution === null ? (
            <p className="admin-empty">{t('adminMetricUnavailable')}</p>
          ) : (
            <DistributionBars
              rows={planDistribution.map((p) => ({ key: p._id || 'null', count: p.count, planId: p._id, displayValue: formatAdminNumber(currentLang, p.count) }))}
              total={planTotal}
              renderLabel={(row) => getPlanLabel(t, row.planId)}
              renderColor={(row) => PLAN_COLOR[row.planId] || PLAN_COLOR['null']}
              emptyText={t('adminNoData')}
            />
          )}
          <p className="admin-explain">{t('adminPlanDistributionExplain')}</p>
        </section>

        {/* Recent Registrations */}
        <section className="profile-section admin-recent-users">
          <h2 className="admin-section-title">
            <FaUsers /> {t('adminRecentUsers')}
          </h2>
          {recentUsers === null ? (
            <p className="admin-empty">{t('adminMetricUnavailable')}</p>
          ) : recentUsers.length === 0 ? (
            <p className="admin-empty">{t('adminNoData')}</p>
          ) : (
            <div className="admin-table-wrap">
              <table className="admin-table admin-table--compact">
                <colgroup>
                  <col style={{ width: '35%' }} />
                  <col style={{ width: '40%' }} />
                  <col style={{ width: '25%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>{t('adminName')}</th>
                    <th>{t('adminEmail')}</th>
                    <th>{t('adminJoined')}</th>
                  </tr>
                </thead>
                <tbody>
                  {recentUsers.map((u) => (
                    <tr key={u._id}>
                      <td className="admin-td-name-cell"><div className="admin-td-name">
                        <span className="admin-td-name-text" title={u.name || u.email}>
                          {u.name || '—'}
                        </span>
                      </div></td>
                      <td className="admin-td-email" title={u.email}>{u.email}</td>
                      <td>{formatAdminDate(currentLang, u.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {isSuperadmin && <RecentAdminActions t={t} currentLang={currentLang} />}
    </div>
  );
};

export default AdminOverview;
