// frontend/src/pages/Admin/AdminPanel.jsx
// Global Admin Dashboard — SSDT Platform
// Uses the exact same page shell as every other page (ParticleBackground + Header +
// profile-container), so it inherits theme, translation, logout, and profile
// navigation from the single shared implementation instead of duplicating them.
// Only accessible to users with systemRole 'admin' or 'superadmin'.

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  FaTachometerAlt,
  FaChartLine,
  FaUsers,
  FaBuilding,
  FaShieldAlt,
  FaHeartbeat,
} from 'react-icons/fa';
import { useTranslation } from '../../contexts/TranslationContext';
import { useUser } from '../../contexts/UserContext';
import Header from '../../components/header';
import ParticleBackground from '../../components/ParticleBackground';
import { getSystemRoleLabel } from './adminLabels';
import AdminOverview from './AdminOverview';
import AdminAnalytics from './AdminAnalytics';
import AdminUsers from './AdminUsers';
import AdminOrganizations from './AdminOrganizations';
import AdminScans from './AdminScans';
import AdminSystemHealth from './AdminSystemHealth';
import '../../styles/Admin.scss';

const ADMIN_ROLES = ['admin', 'superadmin'];

const ADMIN_NAV = [
  { key: 'overview', labelKey: 'adminOverview', icon: <FaTachometerAlt />, component: AdminOverview },
  { key: 'analytics', labelKey: 'adminAnalytics', icon: <FaChartLine />, component: AdminAnalytics },
  { key: 'users', labelKey: 'adminUsers', icon: <FaUsers />, component: AdminUsers },
  { key: 'organizations', labelKey: 'adminOrganizations', icon: <FaBuilding />, component: AdminOrganizations },
  { key: 'scans', labelKey: 'adminScans', icon: <FaShieldAlt />, component: AdminScans },
  { key: 'system-health', labelKey: 'adminSystemHealth', icon: <FaHeartbeat />, component: AdminSystemHealth },
];

const AdminPanel = () => {
  const { t } = useTranslation();
  const { user, loading } = useUser();
  const navigate = useNavigate();
  const location = useLocation();
  const [activeTab, setActiveTab] = useState('overview');

  // Derive active tab from URL hash for direct linking
  useEffect(() => {
    const hash = location.hash.replace('#', '');
    const validTabs = ADMIN_NAV.map((n) => n.key);
    if (validTabs.includes(hash)) setActiveTab(hash);
  }, [location.hash]);

  // Access control — redirect non-admins
  useEffect(() => {
    if (loading) return;
    if (!user) {
      navigate('/login');
      return;
    }
    if (!ADMIN_ROLES.includes(user.systemRole)) {
      navigate('/profile');
    }
  }, [user, loading, navigate]);

  const handleTabChange = useCallback((key) => {
    setActiveTab(key);
    navigate(`/admin#${key}`, { replace: true });
  }, [navigate]);

  // The redirect above runs after render, so without this a non-admin would get
  // one frame of the admin shell — long enough for the active tab to mount and
  // fire admin API calls that can only come back 403.
  const isAdmin = Boolean(user && ADMIN_ROLES.includes(user.systemRole));

  if (loading || !user || !isAdmin) {
    return (
      <div className="profile-page">
        <ParticleBackground />
        <Header />
        <main>
          <div className="profile-container">
            <div className="loading">{t('adminLoading')}</div>
          </div>
        </main>
      </div>
    );
  }

  const ActiveComponent = ADMIN_NAV.find((n) => n.key === activeTab)?.component || AdminOverview;

  return (
    <div className="profile-page">
      <ParticleBackground />
      <Header />
      <main>
        <div className="profile-container admin-wide">
          <div className="profile-header">
            <h1>{t('adminDashboard')}</h1>
            {user.systemRole === 'superadmin' && (
              <span className="admin-role-badge superadmin">{getSystemRoleLabel(t, 'superadmin')}</span>
            )}
            {user.systemRole === 'admin' && (
              <span className="admin-role-badge admin-badge">{getSystemRoleLabel(t, 'admin')}</span>
            )}
          </div>

          <nav className="admin-tabs" aria-label={t('adminPanel')}>
            {ADMIN_NAV.map((item) => (
              <button
                key={item.key}
                type="button"
                onClick={() => handleTabChange(item.key)}
                className={`admin-tab ${activeTab === item.key ? 'active' : ''}`}
              >
                <span className="admin-tab-icon">{item.icon}</span>
                <span className="admin-tab-label">{t(item.labelKey)}</span>
              </button>
            ))}
          </nav>

          <ActiveComponent />
        </div>
      </main>
    </div>
  );
};

export default AdminPanel;
