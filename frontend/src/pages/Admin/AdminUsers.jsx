// frontend/src/pages/Admin/AdminUsers.jsx
// Admin Users Table — paginated, searchable, filterable, with lifecycle actions.
// Reuses .scan-status, .account-type, and table patterns from the existing codebase.
// Destructive/sensitive actions (delete, disable, role change, remove from org)
// go through the shared ConfirmDialog component — no bespoke confirmation UI.

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { FaSearch, FaUser } from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { useUser } from '../../contexts/UserContext';
import { adminService } from '../../services/adminService';
import { getPlanLabel, getSystemRoleLabel, getOrgRoleLabel, getAdminErrorLabel } from './adminLabels';
import { formatAdminDate, formatAdminNumber } from './adminFormat';
import ConfirmDialog from '../../components/ConfirmDialog';

const PlanBadge = ({ plan, t }) => {
  const cls = plan ? `account-type ${plan.replace(/\d/g, '')}` : 'account-type free';
  return <span className={cls}>{getPlanLabel(t, plan)}</span>;
};

const StatusBadge = ({ user, t }) => {
  if (user.isDisabled) {
    return <span className="scan-status failed">{t('adminDisabled')}</span>;
  }
  return (
    <span className={`scan-status ${user.isVerified ? 'completed' : 'pending'}`}>
      {user.isVerified ? t('adminVerified') : t('adminUnverified')}
    </span>
  );
};

// Describes each pending confirmation so a single ConfirmDialog instance can
// serve every destructive/sensitive action in this table.
const buildConfirmConfig = (t, action, targetUser) => {
  const name = targetUser.name || targetUser.email;
  switch (action) {
    case 'delete':
      return {
        title: t('adminDeleteUserTitle'),
        message: t('adminDeleteUserMessage', { name }),
        confirmText: t('adminDeleteUserConfirm'),
        type: 'downgrade',
      };
    case 'disable':
      return {
        title: t('adminDisableUserTitle'),
        message: t('adminDisableUserMessage', { name }),
        confirmText: t('adminDisable'),
        type: 'downgrade',
      };
    case 'removeFromOrg':
      return {
        title: t('adminRemoveFromOrgTitle'),
        message: t('adminRemoveFromOrgMessage', { name }),
        confirmText: t('adminRemoveFromOrg'),
        type: 'downgrade',
      };
    case 'removeAdmin':
      return {
        title: t('adminRevokeAdminTitle'),
        message: t('adminRevokeAdminMessage', { name }),
        confirmText: t('adminRemoveAdmin'),
        type: 'downgrade',
      };
    default:
      return null;
  }
};

const AdminUsers = () => {
  const { t, currentLang } = useTranslation();
  const { user: currentUser } = useUser();
  const [users, setUsers]         = useState([]);
  const [pagination, setPagination] = useState({ page: 1, pages: 1, total: 0 });
  const [search, setSearch]       = useState('');
  const [page, setPage]           = useState(1);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [pendingAction, setPendingAction] = useState(null); // { action, targetUser }
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [actionMessage, setActionMessage] = useState(null); // { type, text }
  const messageTimer              = useRef(null);

  const fetchUsers = useCallback(async (currentPage, currentSearch) => {
    setLoading(true);
    setError(null);
    try {
      const res = await adminService.getUsers({ page: currentPage, limit: 20, search: currentSearch });
      setUsers(res.users || []);
      setPagination(res.pagination || { page: 1, pages: 1, total: 0 });
    } catch (err) {
      setError(getAdminErrorLabel(t, err));
    } finally {
      setLoading(false);
    }
  }, [t]);

  // Single owner of search/page fetching. Debouncing lives here rather than in
  // the change handler: with the handler owning it, typing while on page >= 2
  // also reset `page`, which fired this effect immediately in addition to the
  // debounced timer — two identical requests for one keystroke.
  useEffect(() => {
    const id = setTimeout(() => fetchUsers(page, search), search ? 400 : 0);
    return () => clearTimeout(id);
  }, [page, search, fetchUsers]);

  useEffect(() => () => clearTimeout(messageTimer.current), []);

  const showMessage = (type, text) => {
    setActionMessage({ type, text });
    clearTimeout(messageTimer.current);
    messageTimer.current = setTimeout(() => setActionMessage(null), 5000);
  };

  const handleSearchChange = (e) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const requestAction = (action, targetUser) => setPendingAction({ action, targetUser });
  const cancelAction = () => setPendingAction(null);

  const confirmAction = async () => {
    if (!pendingAction) return;
    const { action, targetUser } = pendingAction;
    setActionLoadingId(targetUser._id);
    try {
      switch (action) {
        case 'delete':
          await adminService.deleteUser(targetUser._id);
          showMessage('success', t('adminUserDeleted'));
          break;
        case 'disable':
          await adminService.updateUser(targetUser._id, { isDisabled: true });
          showMessage('success', t('adminUserUpdated'));
          break;
        case 'removeFromOrg':
          await adminService.removeUserFromOrganization(targetUser._id);
          showMessage('success', t('adminUserRemovedFromOrg'));
          break;
        case 'removeAdmin':
          await adminService.updateUser(targetUser._id, { systemRole: 'user' });
          showMessage('success', t('adminUserUpdated'));
          break;
        default:
          break;
      }
      fetchUsers(page, search);
    } catch (err) {
      showMessage('error', getAdminErrorLabel(t, err, 'adminActionFailed'));
    } finally {
      setActionLoadingId(null);
      setPendingAction(null);
    }
  };

  // Enabling is a restorative action — no confirmation needed, matches the
  // convention that "undo"-type actions don't require a dialog while the
  // action they reverse does.
  const handleEnable = async (targetUser) => {
    setActionLoadingId(targetUser._id);
    try {
      await adminService.updateUser(targetUser._id, { isDisabled: false });
      showMessage('success', t('adminUserUpdated'));
      fetchUsers(page, search);
    } catch (err) {
      showMessage('error', getAdminErrorLabel(t, err, 'adminActionFailed'));
    } finally {
      setActionLoadingId(null);
    }
  };

  const dialogConfig = pendingAction ? buildConfirmConfig(t, pendingAction.action, pendingAction.targetUser) : null;

  return (
    <div className="admin-page">
      <section className="profile-section">
        <div className="section-header">
          <h2 className="admin-section-title">
            <FaUser style={{ marginRight: '0.5rem' }} />
            {t('adminUsers')}
            <span className="admin-count-badge">{formatAdminNumber(currentLang, pagination.total)}</span>
          </h2>
        </div>

        {actionMessage && (
          <div className={`save-message ${actionMessage.type}`}>{actionMessage.text}</div>
        )}

        {/* Search */}
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

        {loading ? (
          <div className="admin-section-loading">
            <div className="admin-spinner" />
            <p>{t('adminLoading')}</p>
          </div>
        ) : error ? (
          <div className="admin-error-state">
            <p>{error}</p>
            <button type="button" className="btn-edit" onClick={() => fetchUsers(page, search)}>{t('adminRetry')}</button>
          </div>
        ) : users.length === 0 ? (
          <p className="admin-empty no-scans">{t('adminNoData')}</p>
        ) : (
          <>
            <div className="admin-table-wrap">
              <table className="admin-table admin-table--users">
                <colgroup>
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '19%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '21%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>{t('adminName')}</th>
                    <th>{t('adminEmail')}</th>
                    <th>{t('adminRole')}</th>
                    <th>{t('adminPlan')}</th>
                    <th>{t('adminStatus')}</th>
                    <th>{t('adminJoined')}</th>
                    <th>{t('adminLastLogin')}</th>
                    <th>{t('adminActions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => {
                    const isSelf = currentUser && String(currentUser.id) === String(u._id);
                    const isBusy = actionLoadingId === u._id;
                    const canRemoveFromOrg = u.organizationId && u.role !== 'owner';
                    return (
                      <tr key={u._id}>
                        <td className="admin-td-name">
                          <span className="admin-td-name-text" title={u.name || u.email}>
                            {u.name || <span className="admin-muted">—</span>}
                          </span>
                          {u.systemRole !== 'user' && (
                            <span className={`admin-role-badge ${u.systemRole}`}>
                              {getSystemRoleLabel(t, u.systemRole)}
                            </span>
                          )}
                        </td>
                        <td className="admin-td-email" title={u.email}>{u.email}</td>
                        <td>
                          <span className={`scan-tag ${u.role === 'owner' ? 'scheduled' : ''}`}>
                            {getOrgRoleLabel(t, u.role)}
                          </span>
                        </td>
                        <td><PlanBadge plan={u.organizationId?.planType || u.planType} t={t} /></td>
                        <td><StatusBadge user={u} t={t} /></td>
                        <td>{formatAdminDate(currentLang, u.createdAt)}</td>
                        <td>{formatAdminDate(currentLang, u.lastLoginAt)}</td>
                        <td>
                          {isSelf ? (
                            <span className="admin-muted admin-row-actions-placeholder">{t('adminYou')}</span>
                          ) : (
                            <div className="admin-row-actions">
                              {u.systemRole === 'admin' && (
                                <button
                                  type="button"
                                  className="admin-action-btn"
                                  disabled={isBusy}
                                  onClick={() => requestAction('removeAdmin', u)}
                                >
                                  {t('adminRemoveAdmin')}
                                </button>
                              )}

                              {u.isDisabled ? (
                                <button
                                  type="button"
                                  className="admin-action-btn"
                                  disabled={isBusy}
                                  onClick={() => handleEnable(u)}
                                >
                                  {t('adminEnable')}
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  className="admin-action-btn"
                                  disabled={isBusy}
                                  onClick={() => requestAction('disable', u)}
                                >
                                  {t('adminDisable')}
                                </button>
                              )}

                              {canRemoveFromOrg && (
                                <button
                                  type="button"
                                  className="admin-action-btn"
                                  disabled={isBusy}
                                  onClick={() => requestAction('removeFromOrg', u)}
                                >
                                  {t('adminRemoveFromOrg')}
                                </button>
                              )}

                              <button
                                type="button"
                                className="admin-action-btn admin-action-btn--danger"
                                disabled={isBusy}
                                onClick={() => requestAction('delete', u)}
                              >
                                {t('delete')}
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
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

export default AdminUsers;
