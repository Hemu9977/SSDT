import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import ConfirmDialog from '../components/ConfirmDialog';
import { useUser } from '../contexts/UserContext';
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
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteMessage, setInviteMessage] = useState({ text: '', type: '' });
  const navigate = useNavigate();
  const { refreshUser } = useUser();

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

  // --- PAYMENT ACTIVATION POLLING LOGIC ---
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const isPaymentSuccess = urlParams.get('payment') === 'success';

    if (!isPaymentSuccess) return;

    let attempts = 0;
    const maxAttempts = 15;
    let pollInterval;

    const checkPlanStatus = async () => {
      // If user logs out during polling, stop immediately
      const currentToken = localStorage.getItem('token');
      if (!currentToken) {
        clearInterval(pollInterval);
        return;
      }

      attempts++;
      console.log(`🔄 Polling for active plan... Attempt ${attempts}/${maxAttempts}`);

      try {
        const res = await fetch(`${API_BASE}/api/profile`, {
          headers: { 'x-auth-token': currentToken }
        });

        if (!res.ok) {
          if (res.status === 401) {
            clearInterval(pollInterval);
          }
          return;
        }

        const data = await res.json();
        
        // Check if plan is active
        const org = data.user?.organization;
        const planIsActive = (org && org.subscriptionStatus === 'active') || (data.user && data.user.planType);

        if (planIsActive) {
          console.log('✅ Payment Activation Polling: Active plan detected!');
          clearInterval(pollInterval);
          
          // Immediately update frontend state
          setProfile(data);
          setFormData({ name: data.user.name, bio: data.user.bio || '' });

          setSaveMessage('✅ Payment successful! Your plan is now active.');
          
          // Remove ?payment=success from URL to prevent re-polling on refresh
          window.history.replaceState({}, document.title, window.location.pathname);

          // Force global context sync before redirecting
          console.log('🔄 Profile: Refreshing global UserContext state...');
          await refreshUser();
          console.log('✅ Profile: Global context refreshed.');

          // Handle pending scan redirect
          const pendingActionRaw = localStorage.getItem('pendingAction');
          if (pendingActionRaw) {
            try {
              const pendingAction = JSON.parse(pendingActionRaw);
              const isRecent = (Date.now() - pendingAction.timestamp) < 30 * 60 * 1000; // 30 min window
              
              if (isRecent && pendingAction.type === 'scan') {
                localStorage.removeItem('pendingAction');
                setSaveMessage('✅ Payment successful! Returning to scan in 2 seconds...');
                setTimeout(() => {
                  navigate('/?type=normal');
                }, 2000);
              }
            } catch (e) {
              localStorage.removeItem('pendingAction');
            }
          }
        } else if (attempts >= maxAttempts) {
          console.log('⚠️ Payment Activation Polling: Max attempts reached.');
          clearInterval(pollInterval);
          setSaveMessage('Activating your plan, please refresh in a moment');
        } else {
          // Keep polling, notify user on first attempt
          if (attempts === 1) {
             setSaveMessage('Processing payment and activating plan...');
          }
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    };

    // Start polling every 2 seconds
    pollInterval = setInterval(checkPlanStatus, 2000);
    // Execute immediately on mount
    checkPlanStatus();

    // Cleanup on unmount
    return () => clearInterval(pollInterval);
  }, [navigate]);
  // --- END PAYMENT ACTIVATION POLLING LOGIC ---

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

    // Store pending scan intent before Stripe redirect so we can restore it after payment
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('redirect') === 'scan') {
      localStorage.setItem('pendingAction', JSON.stringify({
        type: 'scan',
        url: '',  // URL will be re-entered after return
        timestamp: Date.now()
      }));
    }
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

  const handleSendInvite = async (e) => {
    e.preventDefault();
    if (!inviteEmail) return;

    setInviteLoading(true);
    setInviteMessage({ text: '', type: '' });
    const token = localStorage.getItem('token');

    try {
      const res = await fetch(`${API_BASE}/api/org/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-auth-token': token },
        body: JSON.stringify({ email: inviteEmail })
      });
      const data = await res.json();

      if (res.ok) {
        const msg = data.emailDelivered
          ? `Invite sent to ${inviteEmail}!`
          : `Invite created. Email delivery failed — share link manually: ${data.joinLink}`;
        setInviteMessage({ text: msg, type: data.emailDelivered ? 'success' : 'warning' });
        setInviteEmail('');
        fetchProfile();
      } else {
        setInviteMessage({ text: data.error || 'Failed to send invite', type: 'error' });
      }
    } catch (err) {
      setInviteMessage({ text: 'Network error. Please try again.', type: 'error' });
    } finally {
      setInviteLoading(false);
    }
  };

  const handleCancelInvite = async (inviteToken) => {
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API_BASE}/api/org/invite/${inviteToken}`, {
        method: 'DELETE',
        headers: { 'x-auth-token': token }
      });
      const data = await res.json();
      if (res.ok) {
        fetchProfile();
      } else {
        setInviteMessage({ text: data.error || 'Failed to cancel invite', type: 'error' });
      }
    } catch (err) {
      setInviteMessage({ text: 'Network error. Please try again.', type: 'error' });
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
              <span className="pro-badge">
                {user.planType ? user.planType.toUpperCase() : 'PRO'}
              </span>
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
                <span className={`account-type ${user.organization?.planType || user.accountType}`}>
                  {(user.organization?.planType || user.accountType).toUpperCase()}
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

            {/* Usage Information Note */}
            <div className="usage-info-card">
              <h4>
                <span>ℹ️</span> Usage Information
              </h4>
              <ul>
                <li><strong>Scans Used:</strong> Total scans executed by your team this month.</li>
                <li><strong>Targets Used:</strong> Total scan executions across your organization. Targets currently map 1:1 with scans.</li>
              </ul>
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
          {/* Show upgrade panel only when user has no active paid plan */}
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
          {/* Show active plan section when user has any active paid plan */}
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
                {(() => {
                  const used = user.organization?.scansUsed ?? user.monthlyScansUsed ?? 0;
                  const limit = user.organization?.scanLimit || profile.limits.scansPerMonth;
                  const hasLimit = limit !== -1 && limit > 0;
                  const percent = hasLimit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
                  
                  return (
                    <div className="limit-progress-container">
                      <p className="limit-progress-text">
                        Scans used this month: <strong>{used}</strong>
                        {' / '}
                        <strong>{hasLimit ? limit : '∞'}</strong>
                      </p>
                      {hasLimit && (
                        <div className="limit-progress-track">
                          <div className="limit-progress-fill" style={{ width: `${percent}%` }}></div>
                        </div>
                      )}
                    </div>
                  );
                })()}
                <p>Targets used this month: <strong>{user.organization?.targetsUsed ?? user.totalTargetsUsed ?? 0}</strong>
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

          {/* Team Management Section */}
          {(user.isPro || user.planType) && profile.user.organization && (
            <div className="profile-section pro-info-section" style={{ marginTop: '2rem' }}>
              <h2>Team Management</h2>
              <div className="pro-info">
                <p style={{ marginBottom: '1rem' }}>
                  Seats used: <strong>{profile.user.organization.seatsUsed} / {profile.user.organization.seatsAllowed}</strong>
                </p>

                {profile.user.organization.seatsAllowed > 1 ? (
                  <>
                    <form onSubmit={handleSendInvite} className="invite-form">
                      <input 
                        type="email" 
                        value={inviteEmail} 
                        onChange={(e) => setInviteEmail(e.target.value)} 
                        placeholder="Email address" 
                        required 
                        className="invite-input"
                      />
                      <button 
                        type="submit" 
                        disabled={inviteLoading || profile.user.organization.seatsUsed >= profile.user.organization.seatsAllowed}
                        className="btn-invite"
                      >
                        {inviteLoading ? 'Sending...' : 'Send Invite'}
                      </button>
                    </form>
                    {inviteMessage.text && (
                      <div className={`invite-message ${inviteMessage.type}`}>
                        {inviteMessage.text}
                      </div>
                    )}
                  </>
                ) : (
                  <p style={{ color: '#a0aec0', marginBottom: '1.5rem', fontStyle: 'italic' }}>
                    Your current plan does not support team members. Upgrade to a plan with more seats to invite others.
                  </p>
                )}

                {/* Member List */}
                <h3 style={{ fontSize: '1.1rem', marginTop: '1rem', marginBottom: '0.5rem' }}>Active Members</h3>
                {profile.user.organization.members?.length > 0 ? (
                  <ul className="member-list">
                    {profile.user.organization.members.map((m, i) => (
                      <li key={i} className="member-item">
                        <div className="member-info">
                          <strong>{m.name || 'User'}</strong> <span className="member-email">({m.email})</span>
                        </div>
                        <span className="member-role">{m.role}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p style={{ color: 'var(--foreground-darker)' }}>No active members found.</p>
                )}

                {/* Pending Invites */}
                {profile.user.organization.pendingInvites?.length > 0 && (
                  <>
                    <h3 style={{ fontSize: '1.1rem', marginTop: '1.5rem', marginBottom: '0.5rem' }}>Pending Invites</h3>
                    <ul className="member-list">
                      {profile.user.organization.pendingInvites.map((inv, i) => (
                        <li key={i} className="member-item invite-item">
                          <div className="member-info">
                            <span className="invite-email">{inv.email}</span>
                            <span className="invite-role">({inv.role})</span>
                          </div>
                          <div className="invite-status-group">
                            <span className="invite-status">Pending</span>
                            {['owner', 'admin'].includes(profile.user.organization.role) && (
                              <button
                                onClick={() => handleCancelInvite(inv.token)}
                                className="btn-revoke"
                                title="Cancel this invite"
                              >
                                Revoke
                              </button>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </>
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
