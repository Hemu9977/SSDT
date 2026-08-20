// frontend/src/pages/Admin/AdminAnalytics.jsx
// Executive Analytics — growth trends, subscription health, an explicitly
// labeled recurring-value estimate, 7-day scan activity, and a usage
// leaderboard. Every section carries a visible caption explaining exactly
// what it measures and, where relevant, why it's bounded the way it is
// (no revenue table exists; ScanResult has a 7-day TTL). See the backend
// comment block at the top of GET /api/admin/analytics for the full source
// mapping per metric.

import React, { useState, useEffect, useCallback } from 'react';
import { FaChartLine, FaBuilding, FaCoins, FaShieldAlt } from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { adminService } from '../../services/adminService';
import { getPlanLabel, getSubscriptionStatusLabel, getAdminErrorLabel } from './adminLabels';
import { formatAdminNumber, formatAdminYen } from './adminFormat';
import { TrendLine, DistributionBars, PLAN_COLOR, SUBSCRIPTION_STATUS_COLOR } from './adminCharts';

const sum = (series, key = 'count') => series.reduce((acc, d) => acc + (d[key] || 0), 0);

const AdminAnalytics = () => {
  const { t, currentLang } = useTranslation();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await adminService.getAnalytics();
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

  const {
    userGrowth = [],
    organizationGrowth = [],
    subscriptionStatusDistribution = [],
    estimatedRecurringValue = { total: 0, byPlan: {}, activeOrgCount: 0 },
    scanActivity = [],
    topOrgsByUsage = [],
  } = data || {};

  const newUsers30d = sum(userGrowth);
  const newOrgs30d = sum(organizationGrowth);
  const scansThisWeek = sum(scanActivity, 'total');
  const estimatedByPlanRows = Object.entries(estimatedRecurringValue.byPlan || {})
    .map(([planId, value]) => ({ key: planId, count: value, planId, displayValue: formatAdminYen(currentLang, value) }))
    .sort((a, b) => b.count - a.count);
  const estimatedByPlanTotal = estimatedByPlanRows.reduce((acc, r) => acc + r.count, 0);

  const subscriptionRows = subscriptionStatusDistribution.map((s) => ({
    key: s._id || 'null',
    count: s.count,
    statusId: s._id,
    displayValue: formatAdminNumber(currentLang, s.count),
  }));
  const subscriptionTotal = subscriptionRows.reduce((acc, r) => acc + r.count, 0);

  return (
    <div className="admin-page">
      {/* ── Estimated Recurring Value ── */}
      <section className="profile-section admin-kpi-section">
        <h2 className="admin-section-title">
          <FaCoins /> {t('adminEstimatedValue')}
          <span className="admin-estimate-badge">{t('adminEstimateBadge')}</span>
        </h2>
        <p className="admin-explain">{t('adminEstimatedValueExplain')}</p>

        <div className="stats-grid admin-stats-grid">
          <div className="stat-card admin-stat-card admin-stat-card--yellow">
            <div className="admin-stat-icon"><FaCoins /></div>
            <div className="stat-value">{formatAdminYen(currentLang, estimatedRecurringValue.total)}</div>
            <div className="stat-label">{t('adminEstimatedValueTotal')}</div>
          </div>
          <div className="stat-card admin-stat-card admin-stat-card--blue">
            <div className="admin-stat-icon"><FaBuilding /></div>
            <div className="stat-value">{formatAdminNumber(currentLang, estimatedRecurringValue.activeOrgCount)}</div>
            <div className="stat-label">{t('adminActiveOrgs')}</div>
          </div>
        </div>

        {estimatedByPlanRows.length > 0 && (
          <>
            <h3 className="admin-section-title" style={{ fontSize: '0.9rem', marginTop: '1.5rem' }}>
              {t('adminEstimatedValueByPlan')}
            </h3>
            <DistributionBars
              rows={estimatedByPlanRows}
              total={estimatedByPlanTotal}
              renderLabel={(row) => getPlanLabel(t, row.planId)}
              renderColor={(row) => PLAN_COLOR[row.planId] || PLAN_COLOR['null']}
            />
          </>
        )}
      </section>

      {/* ── Growth trends ── */}
      <div className="admin-two-col">
        <section className="profile-section">
          <h2 className="admin-section-title"><FaChartLine /> {t('adminUserGrowth')}</h2>
          <p className="admin-explain">{t('adminUserGrowthExplain')}</p>
          <TrendLine data={userGrowth} />
          <div className="admin-trend-summary">
            <span>{t('adminLast30Days')}</span>
            <strong>{t('adminNewInPeriod', { count: formatAdminNumber(currentLang, newUsers30d) })}</strong>
          </div>
        </section>

        <section className="profile-section">
          <h2 className="admin-section-title"><FaBuilding /> {t('adminOrgGrowth')}</h2>
          <p className="admin-explain">{t('adminOrgGrowthExplain')}</p>
          <TrendLine data={organizationGrowth} />
          <div className="admin-trend-summary">
            <span>{t('adminLast30Days')}</span>
            <strong>{t('adminNewInPeriod', { count: formatAdminNumber(currentLang, newOrgs30d) })}</strong>
          </div>
        </section>
      </div>

      {/* ── Subscription health + scan activity ── */}
      <div className="admin-two-col">
        <section className="profile-section">
          <h2 className="admin-section-title">{t('adminSubscriptionHealth')}</h2>
          <p className="admin-explain">{t('adminSubscriptionHealthExplain')}</p>
          <DistributionBars
            rows={subscriptionRows}
            total={subscriptionTotal}
            renderLabel={(row) => getSubscriptionStatusLabel(t, row.statusId) || t('adminFree')}
            renderColor={(row) => SUBSCRIPTION_STATUS_COLOR[row.statusId] || SUBSCRIPTION_STATUS_COLOR['null']}
            emptyText={t('adminNoData')}
          />
        </section>

        <section className="profile-section">
          <h2 className="admin-section-title"><FaShieldAlt /> {t('adminScanActivity')}</h2>
          <p className="admin-explain">{t('adminScanActivityExplain')}</p>
          <TrendLine data={scanActivity} valueKey="total" />
          <div className="admin-trend-summary">
            <span>{t('adminLast7Days')}</span>
            <strong>{t('adminScansThisWeek', { count: formatAdminNumber(currentLang, scansThisWeek) })}</strong>
          </div>
        </section>
      </div>

      {/* ── Top organizations by usage ── */}
      <section className="profile-section">
        <h2 className="admin-section-title">{t('adminTopOrgsByUsage')}</h2>
        <p className="admin-explain">{t('adminTopOrgsByUsageExplain')}</p>
        {topOrgsByUsage.length === 0 ? (
          <p className="admin-empty no-scans">{t('adminNoData')}</p>
        ) : (
          <div className="admin-table-wrap">
            <table className="admin-table admin-table--compact">
              <colgroup>
                <col style={{ width: '40%' }} />
                <col style={{ width: '20%' }} />
                <col style={{ width: '20%' }} />
                <col style={{ width: '20%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th>{t('adminOrganizations')}</th>
                  <th>{t('adminPlan')}</th>
                  <th>{t('adminUsage')}</th>
                  <th>{t('adminSeats')}</th>
                </tr>
              </thead>
              <tbody>
                {topOrgsByUsage.map((org) => (
                  <tr key={org._id}>
                    <td className="admin-td-name">
                      <span className="admin-td-name-text" title={org.name}>
                        {org.name || <span className="admin-muted">—</span>}
                      </span>
                    </td>
                    <td>
                      <span className={`account-type ${org.planType ? org.planType.replace(/\d/g, '') : 'free'}`}>
                        {getPlanLabel(t, org.planType)}
                      </span>
                    </td>
                    <td>
                      <span className="admin-seats">
                        {formatAdminNumber(currentLang, org.scansUsed ?? 0)} / {org.scanLimit != null ? formatAdminNumber(currentLang, org.scanLimit) : '∞'}
                      </span>
                    </td>
                    <td>
                      <span className="admin-seats">
                        {formatAdminNumber(currentLang, org.seatsUsed ?? 0)} / {formatAdminNumber(currentLang, org.seatsAllowed ?? 1)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default AdminAnalytics;
