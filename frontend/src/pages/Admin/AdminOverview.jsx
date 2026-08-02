// frontend/src/pages/Admin/AdminOverview.jsx
// Admin Dashboard Overview — KPIs and recent activity.
// Uses existing SSDT CSS variables and design language (stat-card, profile-section, scan-status).

import React, { useState, useEffect, useCallback } from 'react';
import { FaUsers, FaBuilding, FaShieldAlt, FaCheckCircle, FaClock, FaChartBar } from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { adminService } from '../../services/adminService';
import { getPlanLabel } from './adminLabels';
import { formatAdminDate, formatAdminNumber } from './adminFormat';
import { DistributionBars, PLAN_COLOR } from './adminCharts';

const AdminOverview = () => {
  const { t, currentLang } = useTranslation();
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
      setError(err.message || t('adminFetchError'));
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

  const { kpis, planDistribution = [], recentUsers = [] } = data || {};

  const statCards = [
    { label: t('adminTotalUsers'),    value: kpis?.totalUsers ?? 0,         icon: <FaUsers />,    color: 'orange' },
    { label: t('adminVerifiedUsers'), value: kpis?.verifiedUsers ?? 0,      icon: <FaCheckCircle />, color: 'green' },
    { label: t('adminActiveOrgs'),    value: kpis?.activeOrgs ?? 0,         icon: <FaBuilding />, color: 'blue' },
    { label: t('adminTotalOrgs'),     value: kpis?.totalOrgs ?? 0,          icon: <FaBuilding />, color: 'purple' },
    { label: t('adminRunningScans'),  value: kpis?.runningScans ?? 0,       icon: <FaClock />,    color: 'yellow' },
    { label: t('adminTotalScans'),    value: kpis?.totalScansAllTime ?? 0,  icon: <FaShieldAlt />,color: 'cyan' },
  ];

  return (
    <div className="admin-page">
      {/* KPI Grid — reuses .stats-grid and .stat-card from Profile.scss */}
      <section className="profile-section admin-kpi-section">
        <h2 className="admin-section-title">{t('adminOverview')}</h2>
        <div className="stats-grid admin-stats-grid">
          {statCards.map((card) => (
            <div key={card.label} className={`stat-card admin-stat-card admin-stat-card--${card.color}`}>
              <div className="admin-stat-icon">{card.icon}</div>
              <div className="stat-value">{formatAdminNumber(currentLang, card.value)}</div>
              <div className="stat-label">{card.label}</div>
            </div>
          ))}
        </div>
      </section>

      <div className="admin-two-col">
        {/* Plan Distribution */}
        <section className="profile-section admin-plan-dist">
          <h2 className="admin-section-title">
            <FaChartBar /> {t('adminPlanDistribution')}
          </h2>
          <DistributionBars
            rows={planDistribution.map((p) => ({ key: p._id || 'null', count: p.count, planId: p._id, displayValue: formatAdminNumber(currentLang, p.count) }))}
            total={kpis?.totalOrgs || 0}
            renderLabel={(row) => getPlanLabel(t, row.planId)}
            renderColor={(row) => PLAN_COLOR[row.planId] || PLAN_COLOR['null']}
            emptyText={t('adminNoData')}
          />
        </section>

        {/* Recent Registrations */}
        <section className="profile-section admin-recent-users">
          <h2 className="admin-section-title">
            <FaUsers /> {t('adminRecentUsers')}
          </h2>
          {recentUsers.length === 0 ? (
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
                      <td className="admin-td-name">
                        <span className="admin-td-name-text" title={u.name || u.email}>
                          {u.name || '—'}
                        </span>
                      </td>
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
    </div>
  );
};

export default AdminOverview;
