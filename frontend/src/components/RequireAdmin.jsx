// frontend/src/components/RequireAdmin.jsx
// Route-level authorization guard for the admin dashboard.
//
// Redirecting from a useEffect inside the page (the previous approach) runs
// AFTER the first render: the admin shell mounted for a frame, the active tab
// fired admin API calls that could only come back 403, and only then did the
// redirect happen. Deciding during render with <Navigate> means an
// unauthorized visitor never mounts the page at all.

import React from 'react';
import { Navigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import { useTranslation } from '../contexts/TranslationContext';
import Header from './header';
import ParticleBackground from './ParticleBackground';
import { isSystemAdmin } from '../utils/authRedirect';

const RequireAdmin = ({ children }) => {
  const { user, loading } = useUser();
  const { t } = useTranslation();

  // The profile fetch is still in flight — deciding now would bounce a valid
  // admin, since `user` is not populated yet.
  if (loading) {
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

  if (!user) return <Navigate to="/login" replace />;
  if (!isSystemAdmin(user)) return <Navigate to="/profile" replace />;

  return children;
};

export default RequireAdmin;
