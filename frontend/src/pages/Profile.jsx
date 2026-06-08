import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import ConfirmDialog from '../components/ConfirmDialog';
import { useTranslation } from '../contexts/TranslationContext';
import '../styles/Profile.scss';

import { API_BASE } from '../config/api';

const Profile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({ name: '', bio: '' });
  const [saveMessage, setSaveMessage] = useState('');
  const [upgradeDialogOpen, setUpgradeDialogOpen] = useState(false);
  const [downgradeDialogOpen, setDowngradeDialogOpen] = useState(false);
  const navigate = useNavigate();
  const { t, currentLang } = useTranslation();

  const fetchProfile = async () => {
    const token = localStorage.getItem('token');
    console.log('🔍 Profile: Token exists?', !!token);

    if (!token) {
      console.log('❌ Profile: No token found, redirecting to login');
      navigate('/login');
      return;
    }

    try {
      console.log('📡 Profile: Fetching from', `${API_BASE}/api/profile`);
      const res = await fetch(`${API_BASE}/api/profile`, {
        headers: {
          'x-auth-token': token
        }
      });

      console.log('📡 Profile: Response status:', res.status);

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        console.error('❌ Profile: Error response:', errorData);

        if (res.status === 401) {
          // Token is invalid or expired - clear it and redirect to login
          console.log('🔑 Profile: Token invalid/expired, clearing and redirecting...');
          localStorage.removeItem('token');
          setError(t('sessionExpiredLoginAgain'));
          setTimeout(() => navigate('/login'), 2000);
          setLoading(false);
          return;
        }

        throw new Error(errorData.message || t('failedFetchProfile'));
      }

      const data = await res.json();
      console.log('✅ Profile: Data received', data.user?.name);
      setProfile(data);
      setFormData({ name: data.user.name, bio: data.user.bio || '' });
      setLoading(false);
    } catch (err) {
      console.error('❌ Profile fetch error:', err);
      setError(err.message || t('failedLoadProfile'));
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleEdit = () => {
    setEditing(true);
    setSaveMessage('');
  };

  const handleCancel = () => {
    setEditing(false);
    setFormData({ name: profile.user.name, bio: profile.user.bio || '' });
    setSaveMessage('');
  };

  const handleSave = async () => {
    const token = localStorage.getItem('token');

    try {
      const res = await fetch(`${API_BASE}/api/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        },
        body: JSON.stringify(formData)
      });

      if (!res.ok) {
        throw new Error(t('failedUpdateProfile'));
      }

      const data = await res.json();

      // Update profile state
      setProfile(prev => ({
        ...prev,
        user: { ...prev.user, name: data.user.name, bio: data.user.bio }
      }));

      setEditing(false);
      setSaveMessage(t('profileUpdated'));

      // Clear success message after 3 seconds
      setTimeout(() => setSaveMessage(''), 3000);
    } catch (err) {
      console.error('Profile update error:', err);
      setSaveMessage(t('failedUpdateProfile'));
    }
  };

  const handleUpgradeToPro = () => {
    setUpgradeDialogOpen(true);
  };

  const confirmUpgrade = async () => {
    setUpgradeDialogOpen(false);
    const token = localStorage.getItem('token');

    try {
      const res = await fetch(`${API_BASE}/api/profile/upgrade-to-pro`, {
        method: 'POST',
        headers: {
          'x-auth-token': token
        }
      });

      const data = await res.json();

      if (data.success) {
        console.log('Successfully upgraded to Pro:', data.message);
        // Hard refresh the page to reflect changes immediately
        window.location.reload();
      } else {
        console.log('Upgrade failed:', data.message || 'Failed to upgrade to Pro');
      }
    } catch (err) {
      console.error('Upgrade error:', err);
    }
  };

  const handleDowngradeToFree = () => {
    setDowngradeDialogOpen(true);
  };

  const confirmDowngrade = async () => {
    setDowngradeDialogOpen(false);
    const token = localStorage.getItem('token');

    try {
      const res = await fetch(`${API_BASE}/api/profile/downgrade-to-free`, {
        method: 'POST',
        headers: {
          'x-auth-token': token
        }
      });

      const data = await res.json();

      if (data.success) {
        console.log('Successfully downgraded to Free account:', data.message);
        // Hard refresh the page to reflect changes immediately
        window.location.reload();
      } else {
        console.log('Downgrade failed:', data.message || 'Failed to downgrade to Free');
      }
    } catch (err) {
      console.error('Downgrade error:', err);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString(currentLang === 'ja' ? 'ja-JP' : 'en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  if (loading) {
    return (
      <div className="profile-page">
        <ParticleBackground />
        <Header />
        <main>
          <div className="profile-container">
            <div className="loading">{t('loadingProfile')}</div>
          </div>
        </main>
      </div>
    );
  }

  if (error) {
    return (
      <div className="profile-page">
        <ParticleBackground />
        <Header />
        <main>
          <div className="profile-container">
            <div className="error">{error}</div>
          </div>
        </main>
      </div>
    );
  }

  const { user, limits, recentScans } = profile;

  return (
    <div className="profile-page">
      <ParticleBackground />
      <Header />
      <main>
        <div className="profile-container">
          <div className="profile-header">
            <h1>{t('myProfile')}</h1>
            {user.isPro && (
              <span className="pro-badge">{t('pro')}</span>
            )}
          </div>

          {saveMessage && (
            <div className={`save-message ${saveMessage.includes('Failed') ? 'error' : 'success'}`}>
              {saveMessage}
            </div>
          )}

          {/* Account Information */}
          <div className="profile-section">
            <div className="section-header">
              <h2>{t('accountInformation')}</h2>
              {!editing ? (
                <button onClick={handleEdit} className="btn-edit">{t('editProfile')}</button>
              ) : (
                <div className="edit-buttons">
                  <button onClick={handleSave} className="btn-save">{t('save')}</button>
                  <button onClick={handleCancel} className="btn-cancel">{t('cancel')}</button>
                </div>
              )}
            </div>

            <div className="profile-info">
              <div className="info-row">
                <label>{t('name')}:</label>
                {editing ? (
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="edit-input"
                  />
                ) : (
                  <span>{user.name}</span>
                )}
              </div>

              <div className="info-row">
                <label>{t('email')}:</label>
                <span>{user.email}</span>
              </div>

              <div className="info-row">
                <label>{t('bio')}:</label>
                {editing ? (
                  <textarea
                    value={formData.bio}
                    onChange={(e) => setFormData({ ...formData, bio: e.target.value })}
                    className="edit-textarea"
                    placeholder={t('bioPlaceholder')}
                    maxLength={500}
                  />
                ) : (
                  <span>{user.bio || t('noBioAdded')}</span>
                )}
              </div>

              <div className="info-row">
                <label>{t('accountType')}:</label>
                <span className={`account-type ${user.accountType}`}>
                  {user.accountType.toUpperCase()}
                </span>
              </div>

              <div className="info-row">
                <label>{t('memberSince')}:</label>
                <span>{formatDate(user.createdAt)}</span>
              </div>

              <div className="info-row">
                <label>{t('lastLogin')}:</label>
                <span>{formatDate(user.lastLoginAt)}</span>
              </div>
            </div>
          </div>

          {/* Statistics */}
          <div className="profile-section">
            <h2>{t('statistics')}</h2>
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-value">{user.totalScans}</div>
                <div className="stat-label">{t('totalScans')}</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{user.scansThisMonth}</div>
                <div className="stat-label">{t('thisMonth')}</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{limits.scansPerDay === -1 ? '∞' : limits.scansPerDay}</div>
                <div className="stat-label">{t('dailyLimit')}</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{(limits.maxFileSize / (1024 * 1024)).toFixed(0)}MB</div>
                <div className="stat-label">{t('maxFileSize')}</div>
              </div>
            </div>
          </div>

          {/* Recent Scans */}
          <div className="profile-section">
            <h2>{t('recentScans')}</h2>
            {recentScans.length > 0 ? (
              <div className="recent-scans">
                {recentScans.map((scan) => (
                  <div
                    key={scan._id}
                    className="scan-item clickable"
                    onClick={() => navigate(`/scan/${scan.analysisId}`)}
                    style={{
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                    title={t('clickViewScanResults', { status: scan.status })}
                  >
                    <div className="scan-target">{scan.target}</div>
                    <div className="scan-details">
                      {scan.triggerSource === 'scheduled' && (
                        <span className="scan-tag scheduled">{t('scheduledScan')}</span>
                      )}
                      <span className={`scan-status ${scan.status}`}>
                        {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                      </span>
                      <span className="scan-date">{formatDate(scan.createdAt)}</span>
                      <span className="view-scan-icon" style={{ marginLeft: '0.5rem', opacity: 0.7 }}>→</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-scans">{t('noScansYet')}</p>
            )}
          </div>

          {/* Upgrade to Pro (only for free users) */}
          {!user.isPro && (
            <div className="profile-section pro-upgrade-section">
              <h2>{t('upgradeToPro')}</h2>
              <div className="pro-features">
                <p>{t('unlockPremiumFeatures')}</p>
                <ul>
                  <li>{t('unlimitedScans')}</li>
                  <li>{t('largerFileLimit')}</li>
                  <li>{t('priorityQueue')}</li>
                  <li>{t('advancedAnalyticsReports')}</li>
                  <li>{t('apiAccessComingSoon')}</li>
                </ul>
                <button onClick={handleUpgradeToPro} className="btn-upgrade">
                  {t('upgradePrice')}
                </button>
                <p className="upgrade-note">
                  {t('paymentComingSoon')}
                </p>
              </div>
            </div>
          )}

          {/* Pro Account Info (only for pro users) */}
          {user.isPro && user.proExpiresAt && (
            <div className="profile-section pro-info-section">
              <h2>{t('proSubscription')}</h2>
              <div className="pro-info">
                <p>{t('proActiveUntil')}</p>
                <p className="expiry-date">{formatDate(user.proExpiresAt)}</p>
                <button onClick={handleDowngradeToFree} className="btn-downgrade">
                  {t('cancelProReturnFree')}
                </button>
                <p className="downgrade-note">
                  {t('prototypeNote')}
                </p>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Upgrade Confirmation Dialog */}
      <ConfirmDialog
        isOpen={upgradeDialogOpen}
        onConfirm={confirmUpgrade}
        onCancel={() => setUpgradeDialogOpen(false)}
        title={t('upgradeToPro')}
        message={t('upgradeConfirmMessage')}
        confirmText={t('upgradeNow')}
        cancelText={t('cancel')}
        type="upgrade"
      />

      {/* Downgrade Confirmation Dialog */}
      <ConfirmDialog
        isOpen={downgradeDialogOpen}
        onConfirm={confirmDowngrade}
        onCancel={() => setDowngradeDialogOpen(false)}
        title={t('cancelProSubscription')}
        message={t('downgradeConfirmMessage')}
        confirmText={t('cancelSubscription')}
        cancelText={t('keepPro')}
        type="downgrade"
      />
    </div>
  );
};

export default Profile;
