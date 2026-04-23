import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import ConfirmDialog from '../components/ConfirmDialog';
import '../styles/Profile.scss';

const API_BASE = 'http://localhost:3001';

// Plan metadata for display
const PLAN_META = {
  light_monthly:  { label: 'Light',  cycle: 'Monthly',  price: '$9/mo',   scans: 3,  targets: 3 },
  basic_monthly:  { label: 'Basic',  cycle: 'Monthly',  price: '$19/mo',  scans: 5,  targets: 5 },
  pro_monthly:    { label: 'Pro',    cycle: 'Monthly',  price: '$39/mo',  scans: 10, targets: 10 },
  light_annual:   { label: 'Light',  cycle: 'Annual',   price: '$89/yr',  scans: 3,  targets: 3 },
  basic_annual:   { label: 'Basic',  cycle: 'Annual',   price: '$179/yr', scans: 5,  targets: 5 },
  pro_annual:     { label: 'Pro',    cycle: 'Annual',   price: '$349/yr', scans: 10, targets: 10 },
  trial1_onetime: { label: 'Trial 1',cycle: 'One-time', price: '$5',      scans: 1,  targets: 1 },
  trial2_onetime: { label: 'Trial 2',cycle: 'One-time', price: '$9',      scans: 2,  targets: 1 },
};

const Profile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({ name: '', bio: '' });
  const [saveMessage, setSaveMessage] = useState('');
  const [upgradeDialogOpen, setUpgradeDialogOpen] = useState(false);
  const [downgradeDialogOpen, setDowngradeDialogOpen] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState({ planType: 'pro', billingCycle: 'monthly' });
  const [checkoutLoading, setCheckoutLoading] = useState(false);
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

  // ─── Stripe: open checkout session for selected plan ──────────────────────
  const handleUpgradeToPro = () => {
    setUpgradeDialogOpen(true);
  };

  const confirmUpgrade = async () => {
    setUpgradeDialogOpen(false);
    setCheckoutLoading(true);
    const token = localStorage.getItem('token');

    try {
      const res = await fetch(`${API_BASE}/api/stripe/create-checkout-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        },
        body: JSON.stringify({
          planType:     selectedPlan.planType,
          billingCycle: selectedPlan.billingCycle
        })
      });

      const data = await res.json();

      if (data.url) {
        // Redirect to Stripe Checkout
        window.location.href = data.url;
      } else {
        setSaveMessage('Failed to start checkout: ' + (data.error || 'Unknown error'));
      }
    } catch (err) {
      console.error('Checkout error:', err);
      setSaveMessage('Failed to start checkout. Please try again.');
    } finally {
      setCheckoutLoading(false);
    }
  };

  const handleDowngradeToFree = () => {
    setDowngradeDialogOpen(true);
  };

  const confirmDowngrade = async () => {
    setDowngradeDialogOpen(false);
    const token = localStorage.getItem('token');

    try {
      const res = await fetch(`${API_BASE}/api/stripe/cancel-subscription`, {
        method: 'POST',
        headers: { 'x-auth-token': token }
      });

      const data = await res.json();

      if (data.success) {
        setSaveMessage('Subscription cancellation scheduled — you keep access until the end of the billing period.');
        setTimeout(() => window.location.reload(), 3000);
      } else {
        setSaveMessage('Cancellation failed: ' + (data.error || 'Please try again'));
      }
    } catch (err) {
      console.error('Downgrade error:', err);
      setSaveMessage('Failed to cancel subscription.');
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

          {/* Upgrade / Plan Selection (only for users without an active paid plan) */}
          {!user.isPro && !user.planType && (
            <div className="profile-section pro-upgrade-section">
              <h2>Choose a Plan</h2>

              {/* Billing cycle toggle */}
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                {['monthly', 'annual', 'onetime'].map(cycle => (
                  <button
                    key={cycle}
                    onClick={() => setSelectedPlan(p => ({ ...p, billingCycle: cycle }))}
                    className={selectedPlan.billingCycle === cycle ? 'btn-save' : 'btn-cancel'}
                    style={{ textTransform: 'capitalize' }}
                  >
                    {cycle === 'onetime' ? 'One-Time' : cycle.charAt(0).toUpperCase() + cycle.slice(1)}
                  </button>
                ))}
              </div>

              {/* Plan cards */}
              <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1rem' }}>
                {(() => {
                  const plans = selectedPlan.billingCycle === 'onetime'
                    ? ['trial1', 'trial2']
                    : ['light', 'basic', 'pro'];
                  return plans.map(pt => {
                    const key = `${pt}_${selectedPlan.billingCycle}`;
                    const meta = PLAN_META[key];
                    if (!meta) return null;
                    const isActive = selectedPlan.planType === pt;
                    return (
                      <div
                        key={key}
                        className="stat-card"
                        onClick={() => setSelectedPlan(p => ({ ...p, planType: pt }))}
                        style={{
                          cursor: 'pointer',
                          border: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                          transition: 'border 0.2s'
                        }}
                      >
                        <div className="stat-value" style={{ fontSize: '1rem' }}>{meta.label}</div>
                        <div className="stat-label">{meta.price}</div>
                        <div className="stat-label" style={{ marginTop: '0.3rem' }}>{meta.scans} scan{meta.scans > 1 ? 's' : ''} / {meta.targets} target{meta.targets > 1 ? 's' : ''}</div>
                      </div>
                    );
                  });
                })()}
              </div>

              <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <button
                  id="btn-checkout"
                  onClick={handleUpgradeToPro}
                  className="btn-upgrade"
                  disabled={checkoutLoading}
                >
                  {checkoutLoading
                    ? 'Redirecting to Checkout...'
                    : `Get ${PLAN_META[`${selectedPlan.planType}_${selectedPlan.billingCycle}`]?.label || 'Plan'} — ${PLAN_META[`${selectedPlan.planType}_${selectedPlan.billingCycle}`]?.price || ''}`}
                </button>
                <p className="upgrade-note">
                  Powered by Stripe. You will be redirected to a secure payment page.
                </p>
              </div>
            </div>
          )}

          {/* Active Plan Info (pro/paid users) */}
          {(user.isPro || user.planType) && (
            <div className="profile-section pro-info-section">
              <h2>Active Plan</h2>
              <div className="pro-info">
                {user.planType && (
                  <p>
                    <strong>
                      {PLAN_META[`${user.planType}_${user.billingCycle}`]?.label || user.planType}
                    </strong>
                    {' '}({user.billingCycle})
                  </p>
                )}
                {user.billingCycle !== 'onetime' && user.proExpiresAt && (
                  <p>Active until: <strong>{formatDate(user.proExpiresAt)}</strong></p>
                )}
                {user.billingCycle === 'onetime' && (
                  <p>Remaining scans: <strong>{user.oneTimeRemainingScans}</strong></p>
                )}
                <p style={{ marginTop: '0.75rem' }}>
                  Scans used this month: <strong>{user.monthlyScansUsed || 0}</strong>
                  {' / '}
                  {profile.limits.scansPerMonth === -1 ? '∞' : profile.limits.scansPerMonth}
                </p>
                <p>Targets used this month: <strong>{user.totalTargetsUsed || 0}</strong>
                  {' / '}
                  {profile.limits.targetsPerMonth === -1 ? '∞' : profile.limits.targetsPerMonth}
                </p>
                {user.billingCycle !== 'onetime' && (
                  <button onClick={handleDowngradeToFree} className="btn-downgrade" style={{ marginTop: '1rem' }}>
                    Cancel Subscription
                  </button>
                )}
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
        title={`Subscribe to ${PLAN_META[`${selectedPlan.planType}_${selectedPlan.billingCycle}`]?.label || 'Plan'}`}
        message={`You will be redirected to Stripe to complete payment for the ${PLAN_META[`${selectedPlan.planType}_${selectedPlan.billingCycle}`]?.label || ''} plan (${PLAN_META[`${selectedPlan.planType}_${selectedPlan.billingCycle}`]?.price || ''}). Continue?`}
        confirmText={checkoutLoading ? 'Loading...' : 'Continue to Checkout'}
        cancelText="Cancel"
        type="upgrade"
      />

      {/* Downgrade / Cancel Dialog */}
      <ConfirmDialog
        isOpen={downgradeDialogOpen}
        onConfirm={confirmDowngrade}
        onCancel={() => setDowngradeDialogOpen(false)}
        title="Cancel Subscription"
        message="Are you sure you want to cancel? Your plan stays active until the end of the current billing period. After that, your account reverts to free."
        confirmText="Yes, Cancel"
        cancelText="Keep Plan"
        type="downgrade"
      />
    </div>
  );
};

export default Profile;
