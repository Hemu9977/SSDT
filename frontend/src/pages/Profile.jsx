import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import ConfirmDialog from '../components/ConfirmDialog';
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
          setError('Session expired. Please log in again.');
          setTimeout(() => navigate('/login'), 2000);
          setLoading(false);
          return;
        }

        throw new Error(errorData.message || 'Failed to fetch profile');
      }

      const data = await res.json();
      console.log('✅ Profile: Data received', data.user?.name);
      setProfile(data);
      setFormData({ name: data.user.name, bio: data.user.bio || '' });
      setLoading(false);
    } catch (err) {
      console.error('❌ Profile fetch error:', err);
      setError(err.message || 'Failed to load profile. Check console for details.');
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
        throw new Error('Failed to update profile');
      }

      const data = await res.json();

      // Update profile state
      setProfile(prev => ({
        ...prev,
        user: { ...prev.user, name: data.user.name, bio: data.user.bio }
      }));

      setEditing(false);
      setSaveMessage('Profile updated successfully!');

      // Clear success message after 3 seconds
      setTimeout(() => setSaveMessage(''), 3000);
    } catch (err) {
      console.error('Profile update error:', err);
      setSaveMessage('Failed to update profile');
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
    return new Date(dateString).toLocaleDateString('en-US', {
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
            <div className="loading">Loading profile...</div>
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
            <h1>My Profile</h1>
            {user.isPro && (
              <span className="pro-badge">PRO</span>
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
              <h2>Account Information</h2>
              {!editing ? (
                <button onClick={handleEdit} className="btn-edit">Edit Profile</button>
              ) : (
                <div className="edit-buttons">
                  <button onClick={handleSave} className="btn-save">Save</button>
                  <button onClick={handleCancel} className="btn-cancel">Cancel</button>
                </div>
              )}
            </div>

            <div className="profile-info">
              <div className="info-row">
                <label>Name:</label>
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
                <label>Email:</label>
                <span>{user.email}</span>
              </div>

              <div className="info-row">
                <label>Bio:</label>
                {editing ? (
                  <textarea
                    value={formData.bio}
                    onChange={(e) => setFormData({ ...formData, bio: e.target.value })}
                    className="edit-textarea"
                    placeholder="Tell us about yourself (max 500 characters)"
                    maxLength={500}
                  />
                ) : (
                  <span>{user.bio || 'No bio added yet'}</span>
                )}
              </div>

              <div className="info-row">
                <label>Account Type:</label>
                <span className={`account-type ${user.accountType}`}>
                  {user.accountType.toUpperCase()}
                </span>
              </div>

              <div className="info-row">
                <label>Member Since:</label>
                <span>{formatDate(user.createdAt)}</span>
              </div>

              <div className="info-row">
                <label>Last Login:</label>
                <span>{formatDate(user.lastLoginAt)}</span>
              </div>
            </div>
          </div>

          {/* Statistics */}
          <div className="profile-section">
            <h2>Statistics</h2>
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-value">{user.totalScans}</div>
                <div className="stat-label">Total Scans</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{user.scansThisMonth}</div>
                <div className="stat-label">This Month</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{limits.scansPerDay === -1 ? '∞' : limits.scansPerDay}</div>
                <div className="stat-label">Daily Limit</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{(limits.maxFileSize / (1024 * 1024)).toFixed(0)}MB</div>
                <div className="stat-label">Max File Size</div>
              </div>
            </div>
          </div>

          {/* Recent Scans */}
          <div className="profile-section">
            <h2>Recent Scans</h2>
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
                    title={`Click to view scan results (Status: ${scan.status})`}
                  >
                    <div className="scan-target">{scan.target}</div>
                    <div className="scan-details">
                      {scan.triggerSource === 'scheduled' && (
                        <span className="scan-tag scheduled">Scheduled Scan</span>
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
              <p className="no-scans">No scans yet. Start by analyzing a URL!</p>
            )}
          </div>

          {/* Upgrade to Pro (only for free users) */}
          {!user.isPro && (
            <div className="profile-section pro-upgrade-section">
              <h2>Upgrade to Pro</h2>
              <div className="pro-features">
                <p>Unlock premium features:</p>
                <ul>
                  <li>✨ Unlimited scans per day</li>
                  <li>📦 Larger file size limit (100MB)</li>
                  <li>⚡ Priority scanning queue</li>
                  <li>📊 Advanced analytics reports</li>
                  <li>🔌 API access (coming soon)</li>
                </ul>
                <button onClick={handleUpgradeToPro} className="btn-upgrade">
                  Upgrade to Pro - $9.99/month
                </button>
                <p className="upgrade-note">
                  Note: Payment integration coming soon. This is a preview of Pro features.
                </p>
              </div>
            </div>
          )}

          {/* Pro Account Info (only for pro users) */}
          {user.isPro && user.proExpiresAt && (
            <div className="profile-section pro-info-section">
              <h2>Pro Subscription</h2>
              <div className="pro-info">
                <p>Your Pro subscription is active until:</p>
                <p className="expiry-date">{formatDate(user.proExpiresAt)}</p>
                <button onClick={handleDowngradeToFree} className="btn-downgrade">
                  Cancel Pro & Return to Free
                </button>
                <p className="downgrade-note">
                  Note: This is a prototype build for testing purposes.
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
        title="Upgrade to Pro"
        message="Are you sure you want to upgrade to Pro for $9.99/month? You'll unlock unlimited scans, larger file uploads (100MB), priority scanning queue, and advanced analytics reports."
        confirmText="Upgrade Now"
        cancelText="Cancel"
        type="upgrade"
      />

      {/* Downgrade Confirmation Dialog */}
      <ConfirmDialog
        isOpen={downgradeDialogOpen}
        onConfirm={confirmDowngrade}
        onCancel={() => setDowngradeDialogOpen(false)}
        title="Cancel Pro Subscription"
        message="Are you sure you want to cancel your Pro subscription? You'll lose access to Pro features immediately, including unlimited scans, larger file uploads, and advanced analytics."
        confirmText="Cancel Subscription"
        cancelText="Keep Pro"
        type="downgrade"
      />
    </div>
  );
};

export default Profile;
