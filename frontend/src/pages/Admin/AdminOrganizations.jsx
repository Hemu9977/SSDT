// frontend/src/pages/Admin/AdminOrganizations.jsx
// Admin Organizations Table — paginated, searchable, with plan/status filters
// and lifecycle actions (disable/enable, cancel subscription, delete).

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { FaSearch, FaBuilding } from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { useUser } from '../../contexts/UserContext';
import { adminService } from '../../services/adminService';
import { getPlanLabel, getSubscriptionStatusLabel, getAdminErrorLabel, SUBSCRIPTION_STATE_CLASS } from './adminLabels';
import { formatAdminDate, formatAdminNumber } from './adminFormat';
import { signInAgain } from '../../utils/authRedirect';
import ConfirmDialog from '../../components/ConfirmDialog';

const PlanBadge = ({ plan, t }) => {
  const cls = plan ? `account-type ${plan.replace(/\d/g, '')}` : 'account-type free';
  return <span className={cls}>{getPlanLabel(t, plan)}</span>;
};

// The state is computed server-side with the entitlement rules
// (backend utils/subscriptionState.js), so an expired period reads as expired
// even while Stripe's stored status still says 'active'.
const SubStatusBadge = ({ org, t, currentLang }) => {
  if (org.isDisabled) {
    return <span className="scan-status failed">{t('adminDisabled')}</span>;
  }
  const state = org.subscriptionState;
  if (!state || state === 'none') return <span className="admin-muted">{t('adminSubNone')}</span>;
  const cls = SUBSCRIPTION_STATE_CLASS[state] || 'pending';
  const label = getSubscriptionStatusLabel(t, state);
  const showDate = org.expiresAt && ['active', 'trialing', 'cancelling', 'expired'].includes(state);
  return (
    <>
      <span className={`scan-status ${cls}`}>{label || state}</span>
      {showDate && (
        <span className="admin-muted admin-cell-sub">
          {t(state === 'active' || state === 'trialing' ? 'adminRenewsOn' : 'adminEndsOn', { date: formatAdminDate(currentLang, org.expiresAt) })}
        </span>
      )}
    </>
  );
};

const buildConfirmConfig = (t, action, org) => {
  const name = org.name;
  switch (action) {
    case 'delete':
      return {
        title: t('adminDeleteOrgTitle'),
        message: t('adminDeleteOrgMessage', { name }),
        confirmText: t('adminDeleteOrgConfirm'),
        type: 'downgrade',
      };
    case 'disable':
      return {
        title: t('adminDisableOrgTitle'),
        message: t('adminDisableOrgMessage', { name }),
        confirmText: t('adminDisable'),
        type: 'downgrade',
      };
    case 'cancelSubscription':
      return {
        title: t('adminCancelSubscriptionTitle'),
        message: t('adminCancelSubscriptionMessage', { name }),
        confirmText: t('adminCancelSubscriptionConfirm'),
        type: 'downgrade',
      };
    default:
      return null;
  }
};

const AdminOrganizations = () => {
  const { t, currentLang } = useTranslation();
  const { user: currentUser } = useUser();
  // Cancelling billing and deleting organizations are superadmin-only on the
  // server (routes/admin.js); a plain admin is not shown those controls.
  const isSuperadmin = currentUser?.systemRole === 'superadmin';
  const [orgs, setOrgs]           = useState([]);
  const [pagination, setPagination] = useState({ page: 1, pages: 1, total: 0 });
  const [search, setSearch]       = useState('');
  const [planFilter, setPlanFilter] = useState('');
  const [page, setPage]           = useState(1);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [pendingAction, setPendingAction] = useState(null); // { action, org }
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);
  const messageTimer              = useRef(null);

  const fetchOrgs = useCallback(async (currentPage, currentSearch, currentPlan) => {
    setLoading(true);
    setError(null);
    try {
      const res = await adminService.getOrganizations({
        page: currentPage,
        limit: 20,
        search: currentSearch,
        plan: currentPlan,
      });
      if ((res.organizations || []).length === 0 && currentPage > 1) {
        setPage(currentPage - 1);
        return;
      }
      setOrgs(res.organizations || []);
      setPagination(res.pagination || { page: 1, pages: 1, total: 0 });
    } catch (err) {
      setError(getAdminErrorLabel(t, err));
    } finally {
      setLoading(false);
    }
  }, [t]);

  // See AdminUsers: this effect owns the debounce so a keystroke cannot trigger
  // both an immediate fetch (via the page reset) and a debounced one.
  useEffect(() => {
    const id = setTimeout(() => fetchOrgs(page, search, planFilter), search ? 400 : 0);
    return () => clearTimeout(id);
  }, [page, search, planFilter, fetchOrgs]);

  useEffect(() => () => clearTimeout(messageTimer.current), []);

  const showMessage = (type, text, reauth = false) => {
    setActionMessage({ type, text, reauth });
    clearTimeout(messageTimer.current);
    messageTimer.current = setTimeout(() => setActionMessage(null), reauth ? 20000 : 5000);
  };

  const showError = (err) =>
    showMessage('error', getAdminErrorLabel(t, err, 'adminActionFailed'), err && err.code === 'ADMIN_REAUTH_REQUIRED');

  const handleSearchChange = (e) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const handlePlanChange = (e) => {
    setPlanFilter(e.target.value);
    setPage(1);
  };

  const requestAction = (action, org) => setPendingAction({ action, org });
  const cancelAction = () => setPendingAction(null);

  const confirmAction = async () => {
    if (!pendingAction) return;
    const { action, org } = pendingAction;
    setActionLoadingId(org._id);
    try {
      switch (action) {
        case 'delete':
          await adminService.deleteOrganization(org._id);
          showMessage('success', t('adminOrgDeleted'));
          break;
        case 'disable':
          await adminService.updateOrganization(org._id, { isDisabled: true });
          showMessage('success', t('adminOrgUpdated'));
          break;
        case 'cancelSubscription': {
          const result = await adminService.cancelOrganizationSubscription(org._id);
          // Stripe accepted the cancellation; if our copy could not be updated
          // the webhook reconciles it shortly — say so rather than claim more.
          showMessage('success', t(result && result.synced === false ? 'adminSubscriptionCanceledPendingSync' : 'adminSubscriptionCanceled'));
          break;
        }
        default:
          break;
      }
      fetchOrgs(page, search, planFilter);
    } catch (err) {
      showError(err);
    } finally {
      setActionLoadingId(null);
      setPendingAction(null);
    }
  };

  const handleEnable = async (org) => {
    setActionLoadingId(org._id);
    try {
      await adminService.updateOrganization(org._id, { isDisabled: false });
      showMessage('success', t('adminOrgUpdated'));
      fetchOrgs(page, search, planFilter);
    } catch (err) {
      showError(err);
    } finally {
      setActionLoadingId(null);
    }
  };

  const dialogConfig = pendingAction ? buildConfirmConfig(t, pendingAction.action, pendingAction.org) : null;

  return (
    <div className="admin-page">
      <section className="profile-section">
        <div className="section-header">
          <h2 className="admin-section-title">
            <FaBuilding style={{ marginRight: '0.5rem' }} />
            {t('adminOrganizations')}
            <span className="admin-count-badge">{formatAdminNumber(currentLang, pagination.total)}</span>
          </h2>
        </div>

        {actionMessage && (
          <div className={`save-message ${actionMessage.type}`}>
            {actionMessage.text}
            {actionMessage.reauth && (
              <button type="button" className="admin-action-btn admin-reauth-btn" onClick={signInAgain}>
                {t('adminSignInAgain')}
              </button>
            )}
          </div>
        )}

        {/* Search + Filter bar */}
        <div className="admin-filter-bar">
          <div className="admin-search-bar">
            <span className="admin-search-icon"><FaSearch /></span>
            <input
              type="text"
              className="admin-search-input"
              placeholder={t('adminSearch')}
              value={search}
              onChange={handleSearchChange}
              aria-label={t('adminSearch')}
            />
          </div>
          <select
            className="admin-select"
            value={planFilter}
            onChange={handlePlanChange}
            aria-label={t('adminFilter')}
          >
            <option value="">{t('adminAllPlans')}</option>
            <option value="pro">{t('adminPro')}</option>
            <option value="basic">{t('adminBasic')}</option>
            <option value="light">{t('adminLight')}</option>
            <option value="trial1">{t('adminTrial1')}</option>
            <option value="trial2">{t('adminTrial2')}</option>
            <option value="free">{t('adminFree')}</option>
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
            <button type="button" className="btn-edit" onClick={() => fetchOrgs(page, search, planFilter)}>{t('adminRetry')}</button>
          </div>
        ) : orgs.length === 0 ? (
          <p className="admin-empty no-scans">{t('adminNoData')}</p>
        ) : (
          <>
            <div className="admin-table-wrap">
              <table className="admin-table admin-table--orgs">
                <colgroup>
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '18%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '9%' }} />
                  <col style={{ width: '21%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>{t('adminOrganizations')}</th>
                    <th>{t('adminOwner')}</th>
                    <th>{t('adminPlan')}</th>
                    <th>{t('adminSeats')}</th>
                    <th>{t('adminUsage')}</th>
                    <th>{t('adminSubscription')}</th>
                    <th>{t('adminJoined')}</th>
                    <th>{t('adminActions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {orgs.map((org) => {
                    const isBusy = actionLoadingId === org._id;
                    // `cancellable` is computed server-side (a live subscription
                    // that is not already ending); superadmin only.
                    const canCancelSubscription = isSuperadmin && org.cancellable;
                    return (
                      <tr key={org._id}>
                        <td className="admin-td-name-cell"><div className="admin-td-name">
                          <span className="admin-td-name-text" title={org.name}>
                            {org.name || <span className="admin-muted">—</span>}
                          </span>
                        </div></td>
                        <td className="admin-td-email" title={org.owner ? org.owner.email : undefined}>
                          {org.owner ? (
                            org.owner.email
                          ) : (
                            <span className="admin-muted">—</span>
                          )}
                        </td>
                        <td><PlanBadge plan={org.planType} t={t} /></td>
                        <td>
                          <span className="admin-seats">
                            {formatAdminNumber(currentLang, org.seatsUsed ?? 0)} / {formatAdminNumber(currentLang, org.seatsAllowed ?? 1)}
                          </span>
                        </td>
                        <td>
                          <span className="admin-seats">
                            {/* This UTC billing month (server-computed): the stored
                                scansUsed is reset only when the org next scans. */}
                            {formatAdminNumber(currentLang, org.scansUsedThisMonth)} / {org.scanLimit != null ? formatAdminNumber(currentLang, org.scanLimit) : '∞'}
                          </span>
                        </td>
                        <td><SubStatusBadge org={org} t={t} currentLang={currentLang} /></td>
                        <td>{formatAdminDate(currentLang, org.createdAt)}</td>
                        <td>
                          <div className="admin-row-actions">
                            {canCancelSubscription && (
                              <button
                                type="button"
                                className="admin-action-btn"
                                disabled={isBusy}
                                onClick={() => requestAction('cancelSubscription', org)}
                              >
                                {t('adminCancelSubscription')}
                              </button>
                            )}

                            {org.isDisabled ? (
                              <button
                                type="button"
                                className="admin-action-btn"
                                disabled={isBusy}
                                onClick={() => handleEnable(org)}
                              >
                                {t('adminEnable')}
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="admin-action-btn"
                                disabled={isBusy}
                                onClick={() => requestAction('disable', org)}
                              >
                                {t('adminDisable')}
                              </button>
                            )}

                            {isSuperadmin && (
                              <button
                                type="button"
                                className="admin-action-btn admin-action-btn--danger"
                                disabled={isBusy}
                                onClick={() => requestAction('delete', org)}
                              >
                                {t('delete')}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
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

      {dialogConfig && (
        <ConfirmDialog
          isOpen={!!pendingAction}
          onConfirm={confirmAction}
          onCancel={cancelAction}
          title={dialogConfig.title}
          message={dialogConfig.message}
          confirmText={dialogConfig.confirmText}
          cancelText={t('cancel')}
          type={dialogConfig.type}
        />
      )}
    </div>
  );
};

export default AdminOrganizations;
