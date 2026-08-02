import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { FaShieldAlt, FaHistory, FaUser, FaCog, FaSignOutAlt, FaChartBar, FaUserShield } from 'react-icons/fa';
import { useTranslation } from '../contexts/TranslationContext';
import { useUser } from '../contexts/UserContext';
import '../styles/Sidebar.scss';


const Sidebar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { t } = useTranslation();
  const { user } = useUser();
  const isSystemAdmin = user && ['admin', 'superadmin'].includes(user.systemRole);


  const menuItems = [
    { path: '/scan', icon: <FaShieldAlt />, label: t('securityScan') },
    { path: '/reports', icon: <FaChartBar />, label: t('reports') },
    { path: '/history', icon: <FaHistory />, label: t('scanHistory') },
    { path: '/profile', icon: <FaUser />, label: t('profile') },
    { path: '/settings', icon: <FaCog />, label: t('settings') },
    ...(isSystemAdmin ? [{ path: '/admin', icon: <FaUserShield />, label: t('adminPanel') }] : []),
  ];


  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('activeScan');
    navigate('/login');
  };

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <h2 className="sidebar-title">SSDT</h2>
        <p className="sidebar-subtitle">{t('securityScanner')}</p>
      </div>

      <nav className="sidebar-nav">
        {menuItems.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={`sidebar-item ${location.pathname === item.path ? 'active' : ''}`}
            type="button"
          >
            <span className="sidebar-icon">{item.icon}</span>
            <span className="sidebar-label">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <button onClick={handleLogout} className="sidebar-item logout" type="button">
          <span className="sidebar-icon"><FaSignOutAlt /></span>
          <span className="sidebar-label">{t('logout')}</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
