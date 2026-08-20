// frontend/src/pages/Admin/AdminScans.jsx
// Admin Scans Monitor — all scans across all users, with status filter and pagination.

import React, { useState, useEffect, useCallback } from 'react';
import { FaShieldAlt } from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { adminService } from '../../services/adminService';
import { getPlanLabel, getScanStatusLabel, getAdminErrorLabel } from './adminLabels';
import { formatAdminDateTime, formatAdminNumber } from './adminFormat';

const formatDuration = (t, secs) => {
  if (secs === null || secs === undefined) return '—';
  if (secs < 60) return t('adminDurationSeconds', { s: secs });
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return t('adminDurationMinutes', { m, s });
};

const ScanStatusBadge = ({ status, t }) => {
  const statusMap = {
    completed: 'completed',
    failed:    'failed',
    stopped:   'failed',
    pending:   'pending',
    queued:    'queued',
    combining: 'combining',
  };
  const cls = statusMap[status] || 'pending';
  return <span className={`scan-status ${cls}`}>{status ? getScanStatusLabel(t, status) : '—'}</span>;
};

const STATUS_OPTIONS = ['', 'queued', 'pending', 'combining', 'completed', 'failed', 'stopped'];

const AdminScans = () => {
  const { t, currentLang } = useTranslation();
  const [scans, setScans]           = useState([]);
  const [pagination, setPagination] = useState({ page: 1, pages: 1, total: 0 });
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage]             = useState(1);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);

  const fetchScans = useCallback(async (currentPage, currentStatus) => {
    setLoading(true);
    setError(null);
    try {
      const res = await adminService.getScans({ page: currentPage, limit: 20, status: currentStatus });
      setScans(res.scans || []);
      setPagination(res.pagination || { page: 1, pages: 1, total: 0 });
    } catch (err) {
      setError(getAdminErrorLabel(t, err));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    fetchScans(page, statusFilter);
  }, [page, statusFilter, fetchScans]);

  const handleStatusChange = (e) => {
    setStatusFilter(e.target.value);
    setPage(1);
  };

  return (
    <div className="admin-page">
      <section className="profile-section">
        <div className="section-header">
          <h2 className="admin-section-title">
            <FaShieldAlt style={{ marginRight: '0.5rem' }} />
            {t('adminScans')}
            <span className="admin-count-badge">{formatAdminNumber(currentLang, pagination.total)}</span>
          </h2>
        </div>

        {/* Status filter */}
        <div className="admin-filter-bar">
          <select
            className="admin-select"
            value={statusFilter}
            onChange={handleStatusChange}
            aria-label={t('adminFilter')}
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s ? getScanStatusLabel(t, s) : t('adminAllStatuses')}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <div className="admin-section-loading">
            <div className="admin-spinner" />
            <p>{t('adminLoading')}</p>
          </div>
        ) : error ? (
          <div className="admin-error-state">
            <p>{error}</p>
            <button type="button" className="btn-edit" onClick={() => fetchScans(page, statusFilter)}>{t('adminRetry')}</button>
          </div>
        ) : scans.length === 0 ? (
          <p className="admin-empty no-scans">{t('adminNoData')}</p>
        ) : (
          <>
            <div className="admin-table-wrap">
              <table className="admin-table admin-table--scans">
                <colgroup>
                  <col style={{ width: '28%' }} />
                  <col style={{ width: '22%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '18%' }} />
                  <col style={{ width: '10%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>{t('adminTarget')}</th>
                    <th>{t('adminUser')}</th>
                    <th>{t('adminPlan')}</th>
                    <th>{t('adminStatus')}</th>
                    <th>{t('adminStarted')}</th>
                    <th>{t('adminDuration')}</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s._id}>
                      <td className="admin-td-url" title={s.target}>
                        {s.target ? (
                          <span className="admin-target-cell">{s.target}</span>
                        ) : (
                          <span className="admin-muted">—</span>
                        )}
                      </td>
                      <td className="admin-td-email" title={s.user?.email || undefined}>{s.user?.email || <span className="admin-muted">—</span>}</td>
                      <td>
                        <span className={`account-type ${(s.user?.plan || 'free').replace(/\d/g, '')}`}>
                          {getPlanLabel(t, s.user?.plan)}
                        </span>
                      </td>
                      <td><ScanStatusBadge status={s.status} t={t} /></td>
                      <td>{formatAdminDateTime(currentLang, s.createdAt)}</td>
                      <td>{formatDuration(t, s.duration)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="admin-pagination">
              <button
                type="button"
                className="btn-edit"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                {t('adminPrevious')}
              </button>
              <span className="admin-page-info">
                {t('adminPaginationInfo', { page: pagination.page, pages: pagination.pages, total: formatAdminNumber(currentLang, pagination.total) })}
              </span>
              <button
                type="button"
                className="btn-edit"
                disabled={page >= pagination.pages}
                onClick={() => setPage((p) => p + 1)}
              >
                {t('adminNext')}
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
};

export default AdminScans;
