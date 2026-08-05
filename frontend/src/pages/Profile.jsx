import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import ConfirmDialog from '../components/ConfirmDialog';
import { useTranslation } from '../contexts/TranslationContext';
import { useUser } from '../contexts/UserContext';
import '../styles/Profile.scss';

import { API_BASE } from '../config/api';

// Plan definitions — source of truth for the UI
const PLANS = {
  monthly: [
    { planType: 'light',  billingCycle: 'monthly', price: '¥30,000',   period: 'periodMonth', accounts: 1, totalScans: 3,  severity: 'critical-high' },
    { planType: 'basic',  billingCycle: 'monthly', price: '¥50,000',   period: 'periodMonth', accounts: 3, totalScans: 5,  severity: 'all' },
    { planType: 'pro',    billingCycle: 'monthly', price: '¥100,000',  period: 'periodMonth', accounts: 5, totalScans: 10, severity: 'all' },
  ],
  annual: [
    { planType: 'light',  billingCycle: 'annual', price: '¥300,000',   period: 'periodYear', accounts: 1, totalScans: 3,  severity: 'critical-high' },
    { planType: 'basic',  billingCycle: 'annual', price: '¥500,000',   period: 'periodYear', accounts: 3, totalScans: 5,  severity: 'all' },
    { planType: 'pro',    billingCycle: 'annual', price: '¥1,000,000', period: 'periodYear', accounts: 5, totalScans: 10, severity: 'all' },
  ],
  onetime: [
    { planType: 'trial1', billingCycle: 'onetime', price: '¥20,000', period: '', accounts: 1, totalScans: 1, severity: 'critical-high' },
    { planType: 'trial2', billingCycle: 'onetime', price: '¥30,000', period: '', accounts: 1, totalScans: 2, severity: 'all' },
  ],
};

const PLAN_NAMES = { light: 'planLight', basic: 'planBasic', pro: 'planPro', trial1: 'planTrial1', trial2: 'planTrial2' };
const BILLING_LABELS = { monthly: 'billingMonthly', annual: 'billingAnnual', onetime: 'billingOneTime' };
const PAYMENT_POLL_MAX_ATTEMPTS = 12;
const PAYMENT_POLL_INTERVAL_MS = 2000;

// Display-only 10% tax calculation. PLANS[...].price remains the
// tax-excluded amount actually sent to Stripe via startCheckout() — this
// only derives what to show alongside it.
const TAX_RATE = 0.1;
const parsePriceYen = (priceStr) => Number(String(priceStr).replace(/[^\d.]/g, '')) || 0;
const formatPriceYen = (amount) => `¥${Math.round(amount).toLocaleString('en-US')}`;
const priceIncludingTax = (priceStr) => formatPriceYen(parsePriceYen(priceStr) * (1 + TAX_RATE));

// Shared plan-card markup — used by both the full plan chooser (no active
// plan) and the top-up section (subscribed users buying extra scans).
const PlanCard = ({ plan, onSelect, loading, buttonLabel, t }) => (
  <div key={plan.planType} style={{
    border: plan.planType === 'basic' ? '2px solid var(--accent)' : '1px solid rgba(255,107,0,0.25)',
    borderRadius: '1.5rem',
    padding: '2rem 1.5rem',
    background: plan.planType === 'basic' ? 'rgba(255,107,0,0.08)' : 'rgba(255,107,0,0.03)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
    position: 'relative',
    boxShadow: plan.planType === 'basic' ? '0 0 20px rgba(255,107,0,0.15)' : 'none'
  }}>
    {plan.planType === 'basic' && (
      <div style={{
        position: 'absolute', top: '-1px', left: '50%', transform: 'translateX(-50%)',
        background: 'var(--accent)', color: 'var(--background)',
        fontSize: '0.7rem', fontWeight: 800, padding: '0.2rem 0.8rem',
        borderRadius: '0 0 8px 8px', textTransform: 'uppercase', letterSpacing: '1px',
        whiteSpace: 'nowrap'
      }}>{t('mostPopular')}</div>
    )}

    <div style={{ fontSize: '1rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--accent-light)', letterSpacing: '2px', marginTop: plan.planType === 'basic' ? '0.5rem' : 0 }}>
      {PLAN_NAMES[plan.planType] ? t(PLAN_NAMES[plan.planType]) : plan.planType}
    </div>

    <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--accent)', lineHeight: 1 }}>
      {plan.price}
      <span style={{ fontSize: '0.85rem', fontWeight: 400, color: 'var(--foreground-darker)' }}>{plan.period ? t(plan.period) : ''}</span>
    </div>
    <div style={{ fontSize: '0.7rem', color: 'var(--foreground-darker)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
      {t('priceExcludingTax')}
    </div>
    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--foreground-darker)' }}>
      {t('priceIncludingTaxAmount', { amount: priceIncludingTax(plan.price) })}
    </div>

    <ul style={{ listStyle: 'none', padding: 0, margin: '0.5rem 0', fontSize: '0.88rem', color: 'var(--foreground-darker)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      <li>・{t('planAccounts', { count: plan.accounts, plural: plan.accounts === 1 ? '' : 's' })}</li>
      <li>
        ・{plan.planType === 'trial1'
          ? t('trial1ScansAndDevice')
          : plan.planType === 'trial2'
          ? t('trial2ScansAndDevice')
          : plan.billingCycle === 'onetime'
          ? t('planScansForTarget', { count: plan.totalScans, plural: plan.totalScans === 1 ? '' : 's' })
          : t('planScansPerMonth', { count: plan.totalScans, plural: plan.totalScans === 1 ? '' : 's' })}
      </li>
      {plan.billingCycle === 'onetime' && (
        <li>・{t('validityPeriod')}</li>
      )}
      <li style={{ color: plan.severity === 'all' ? '#00d084' : 'var(--foreground-darker)' }}>
        ・{plan.severity === 'all' ? t('severityAllLevels') : t('severityCriticalHighOnly')}
      </li>
    </ul>

    <button
      onClick={() => onSelect(plan.planType, plan.billingCycle)}
      disabled={loading}
      className="btn-upgrade"
      style={{ marginTop: 'auto', opacity: loading ? 0.7 : 1 }}
    >
      {loading ? t('startingCheckout') : buttonLabel}
    </button>
  </div>
);

const Profile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({ name: '', bio: '' });
  const [saveMessage, setSaveMessage] = useState('');
  const [selectedBilling, setSelectedBilling] = useState('monthly');
  const [paymentLoading, setPaymentLoading] = useState(false);
  const [paymentMessage, setPaymentMessage] = useState(null);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteMessage, setInviteMessage] = useState(null);
  // True only while we are handing off to Stripe. Distinguishes that from the
  // post-payment activation flow, which also raises paymentLoading but must NOT be
  // cancelled when the tab regains focus. See the bfcache effect below.
  const awaitingCheckoutRedirectRef = useRef(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { t, currentLang } = useTranslation();
  const { refreshUser } = useUser();

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const isPlanActive = (data) => {
    const org = data?.user?.organization;
    return Boolean(org && org.subscriptionStatus === 'active' && org.planType);
  };

  const fetchProfile = async () => {
    const token = localStorage.getItem('token');

    if (!token) {
      navigate('/login');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/profile`, {
        headers: { 'x-auth-token': token }
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        if (res.status === 401) {
          localStorage.removeItem('token');
          setError(t('sessionExpiredLoginAgain'));
          setTimeout(() => navigate('/login'), 2000);
          setLoading(false);
          return;
        }
        throw new Error(errorData.message || t('failedFetchProfile'));
      }

      const data = await res.json();
      setProfile(data);
      setFormData({ name: data.user.name, bio: data.user.bio || '' });
      refreshUser();
      setLoading(false);
      return data;
    } catch (err) {
      setError(err.message || t('failedLoadProfile'));
      setLoading(false);
      return null;
    }
  };

  const refreshActivationStatus = async () => {
    setPaymentLoading(true);
    setPaymentMessage({ type: 'info', text: t('checkingPlanStatus') });

    const data = await fetchProfile();
    const activated = isPlanActive(data);

    setPaymentMessage({
      type: activated ? 'success' : 'info',
      text: activated ? t('paymentSuccess') : t('paymentPendingActivation')
    });
    setPaymentLoading(false);
  };

  const waitForPlanActivation = async () => {
    const token = localStorage.getItem('token');
    if (!token) return false;

    for (let attempt = 1; attempt <= PAYMENT_POLL_MAX_ATTEMPTS; attempt++) {
      try {
        const res = await fetch(`${API_BASE}/api/profile`, {
          headers: { 'x-auth-token': token }
        });

        if (res.ok) {
          const data = await res.json();
          if (isPlanActive(data)) return true;
        }
      } catch (err) {
        // Ignore transient polling errors and continue retrying.
      }

      if (attempt < PAYMENT_POLL_MAX_ATTEMPTS) {
        await sleep(PAYMENT_POLL_INTERVAL_MS);
      }
    }

    return false;
  };

  const syncCheckoutSession = async (sessionId) => {
    const token = localStorage.getItem('token');
    if (!token || !sessionId) return false;

    try {
      const res = await fetch(`${API_BASE}/api/stripe/sync-checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-auth-token': token },
        body: JSON.stringify({ sessionId })
      });

      return res.ok;
    } catch (err) {
      return false;
    }
  };

  useEffect(() => {
    fetchProfile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle Stripe return — ?payment=success or ?payment=cancelled
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const payment = params.get('payment');
    const sessionId = params.get('session_id');
    if (payment === 'success') {
      window.history.replaceState({}, '', '/profile');

      const activatePlan = async () => {
        setPaymentLoading(true);
        setPaymentMessage({ type: 'info', text: t('paymentProcessing') });

        const synced = await syncCheckoutSession(sessionId);
        let latestProfile = await fetchProfile();
        let activated = isPlanActive(latestProfile);

        if (!activated && !synced) {
          activated = await waitForPlanActivation();
          latestProfile = await fetchProfile();
          activated = activated || isPlanActive(latestProfile);
        }

        setPaymentMessage({
          type: activated ? 'success' : 'info',
          text: activated ? t('paymentSuccess') : t('paymentPendingActivation')
        });
        setPaymentLoading(false);
      };

      activatePlan();
    } else if (payment === 'cancelled') {
      setPaymentMessage({ type: 'info', text: t('paymentCancelled') });
      window.history.replaceState({}, '', '/profile');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.search]);

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
        headers: { 'Content-Type': 'application/json', 'x-auth-token': token },
        body: JSON.stringify(formData)
      });
      if (!res.ok) throw new Error(t('failedUpdateProfile'));
      const data = await res.json();
      setProfile(prev => ({ ...prev, user: { ...prev.user, name: data.user.name, bio: data.user.bio } }));
      setEditing(false);
      setSaveMessage(t('profileUpdated'));
      setTimeout(() => setSaveMessage(''), 3000);
    } catch (err) {
      setSaveMessage(t('failedUpdateProfile'));
    }
  };

  const startCheckout = async (planType, billingCycle) => {
    setPaymentLoading(true);
    setPaymentMessage(null);
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API_BASE}/api/stripe/create-checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-auth-token': token },
        body: JSON.stringify({ planType, billingCycle })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || t('checkoutFailed'));
      // Deliberately leave paymentLoading true — the page is navigating away. It is
      // reset if the user comes back without paying (see the bfcache effect below).
      awaitingCheckoutRedirectRef.current = true;
      window.location.href = data.url;
    } catch (err) {
      awaitingCheckoutRedirectRef.current = false;
      setPaymentMessage({ type: 'error', text: err.message || t('checkoutFailed') });
      setPaymentLoading(false);
    }
  };

  // Recover from a Stripe hand-off the user backed out of.
  //
  // startCheckout leaves paymentLoading true on purpose, because window.location.href
  // is about to unload the page. But pressing the browser Back button restores this
  // page from the back/forward cache with React state exactly as it was, so every
  // purchase button stays disabled on "Redirecting to checkout..." with no way back.
  //
  // Both events are needed: pageshow+persisted is the real bfcache restore signal,
  // while visibilitychange covers tab and mobile app switches where no restore fires.
  // The ref guard keeps this from cancelling the ?payment=success activation poll,
  // which legitimately holds paymentLoading while the webhook lands.
  useEffect(() => {
    const clearStaleRedirect = () => {
      if (!awaitingCheckoutRedirectRef.current) return;
      awaitingCheckoutRedirectRef.current = false;
      setPaymentLoading(false);
    };
    const onPageShow = (event) => { if (event.persisted) clearStaleRedirect(); };
    const onVisibility = () => { if (document.visibilityState === 'visible') clearStaleRedirect(); };

    window.addEventListener('pageshow', onPageShow);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.removeEventListener('pageshow', onPageShow);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  const cancelSubscription = async () => {
    setCancelDialogOpen(false);
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API_BASE}/api/stripe/cancel-subscription`, {
        method: 'POST',
        headers: { 'x-auth-token': token }
      });
      const data = await res.json();
      if (data.success) {
        setPaymentMessage({ type: 'success', text: t('subscriptionCancelled') });
        fetchProfile();
      } else {
        throw new Error(data.error || t('failedCancelSubscription'));
      }
    } catch (err) {
      setPaymentMessage({ type: 'error', text: err.message });
    }
  };

  const handleSendInvite = async (e) => {
    e.preventDefault();
    if (!inviteEmail) return;
    
    setInviteLoading(true);
    setInviteMessage(null);
    const token = localStorage.getItem('token');
    const submittedEmail = inviteEmail;

    try {
      const res = await fetch(`${API_BASE}/api/org/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-auth-token': token },
        body: JSON.stringify({ email: submittedEmail, role: 'member' })
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || t('failedSendInvite'));

      if (data.emailDelivered === false) {
        // Invite created in DB but SMTP delivery failed — show warning with manual share link
        setInviteMessage({
          type: 'warning',
          text: t('inviteEmailFailed', { link: data.joinLink })
        });
      } else {
        setInviteMessage({ type: 'success', text: t('inviteSentSuccess', { email: submittedEmail }) });
      }
      setInviteEmail('');
      fetchProfile(); // Refresh pending invites list
    } catch (err) {
      setInviteMessage({ type: 'error', text: err.message });
    } finally {
      setInviteLoading(false);
    }
  };

  const handleCancelInvite = async (tokenStr) => {
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API_BASE}/api/org/invite/${tokenStr}`, {
        method: 'DELETE',
        headers: { 'x-auth-token': token }
      });
      if (!res.ok) throw new Error('revoke failed');
      fetchProfile();
    } catch (err) {
      setInviteMessage({ type: 'error', text: t('inviteRevokeFailed') });
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString(currentLang === 'ja' ? 'ja-JP' : 'en-US', {
      year: 'numeric', month: 'long', day: 'numeric'
    });
  };

  if (loading) {
    return (
      <div className="profile-page">
        <ParticleBackground />
        <Header />
        <main><div className="profile-container"><div className="loading">{t('loadingProfile')}</div></div></main>
      </div>
    );
  }

  if (error) {
    return (
      <div className="profile-page">
        <ParticleBackground />
        <Header />
        <main><div className="profile-container"><div className="error">{error}</div></div></main>
      </div>
    );
  }

  const { user, recentScans } = profile;
  const org = user.organization;
  const hasPlan = org && org.subscriptionStatus === 'active' && org.planType;
  const accountTypeClass = hasPlan ? 'paid' : user.accountType;
  // Plan display is derived from the organization's real plan, never from
  // user.accountType. accountType feeds nothing in the quota system (getAccountLimits
  // keys off planType_billingCycle) and a legacy 'pro' value there would otherwise be
  // shown as if the user had bought the Pro tier.
  const accountTypeLabel = hasPlan
    ? `${PLAN_NAMES[org.planType] ? t(PLAN_NAMES[org.planType]) : org.planType} (${BILLING_LABELS[org.billingCycle] ? t(BILLING_LABELS[org.billingCycle]) : org.billingCycle})`
    : t('planFree');

  return (
    <div className="profile-page">
      <ParticleBackground />
      <Header />
      <main>
        <div className="profile-container">
          <div className="profile-header">
            <h1>{t('myProfile')}</h1>
            {/* Only badge a real, named plan. `isPro` means "has any paid plan", so on
                its own it would fall through to the literal word "PRO" for an account
                that has bought nothing. */}
            {hasPlan && PLAN_NAMES[org.planType] && (
              <span className="pro-badge">{t(PLAN_NAMES[org.planType])}</span>
            )}
          </div>

          {/* Profile save feedback */}
          {saveMessage && (
            <div className={`save-message ${saveMessage.includes('Failed') ? 'error' : 'success'}`}>
              {saveMessage}
            </div>
          )}

          {/* Payment feedback banner */}
          {paymentMessage && (
            <div className={`save-message ${paymentMessage.type === 'success' ? 'success' : paymentMessage.type === 'error' ? 'error' : 'info'}`}
              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>{paymentMessage.text}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {paymentMessage.type === 'info' && (
                  <button
                    onClick={refreshActivationStatus}
                    disabled={paymentLoading}
                    className="payment-refresh-btn"
                  >
                    {paymentLoading ? t('checkingPlanStatus') : t('refreshPlanStatus')}
                  </button>
                )}
                <button
                  onClick={() => setPaymentMessage(null)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontSize: '1.2rem', lineHeight: 1, padding: '0 0.25rem' }}
                >×</button>
              </div>
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
                  <input type="text" value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="edit-input" />
                ) : <span>{user.name}</span>}
              </div>
              <div className="info-row">
                <label>{t('email')}:</label>
                <span>{user.email}</span>
              </div>
              <div className="info-row">
                <label>{t('bio')}:</label>
                {editing ? (
                  <textarea value={formData.bio}
                    onChange={(e) => setFormData({ ...formData, bio: e.target.value })}
                    className="edit-textarea" placeholder={t('bioPlaceholder')} maxLength={500} />
                ) : <span>{user.bio || t('noBioAdded')}</span>}
              </div>
              <div className="info-row">
                <label>{t('accountType')}:</label>
                <span className={`account-type ${accountTypeClass}`}>{accountTypeLabel}</span>
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
                <div className="stat-value">{user.totalScansAllTime}</div>
                <div className="stat-label">{t('totalScans')}</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{org ? org.scansUsed : 0}</div>
                <div className="stat-label">{t('scansUsedLabel')}</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{org && org.scanLimit > 0 ? org.scanLimit : t('noPlanScanLimit')}</div>
                <div className="stat-label">{t('planScanLimitLabel')}</div>
              </div>
              {org && org.extraScansRemaining > 0 && (
                <div className="stat-card">
                  <div className="stat-value">{org.extraScansRemaining}</div>
                  <div className="stat-label">{t('extraScansRemainingLabel')}</div>
                  {org.extraScansExpiresAt && (
                    <div className="stat-sublabel">{t('extraScansExpireOn', { date: formatDate(org.extraScansExpiresAt) })}</div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Recent Scans */}
          <div className="profile-section">
            <h2>{t('recentScans')}</h2>
            {recentScans.length > 0 ? (
              <div className="recent-scans">
                {recentScans.map((scan) => (
                  <div key={scan._id} className="scan-item clickable"
                    onClick={() => navigate(`/scan/${scan.analysisId}`)}
                    style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
                    title={t('clickViewScanResults', { status: scan.status })}>
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

          {/* ── Active Plan Section ─────────────────────────────────────────── */}
          {hasPlan && (
            <div className="profile-section pro-info-section">
              <h2>{t('currentPlanTitle')}</h2>
              <div className="pro-info">
                {/* Plan name + status row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.5rem' }}>
                  <div>
                    <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '2px' }}>
                      {PLAN_NAMES[org.planType] ? t(PLAN_NAMES[org.planType]) : org.planType}
                    </div>
                    <div style={{ color: 'var(--foreground-darker)', textTransform: 'capitalize', marginTop: '0.25rem' }}>
                      {BILLING_LABELS[org.billingCycle] ? t(BILLING_LABELS[org.billingCycle]) : org.billingCycle}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.8rem', color: 'var(--foreground-darker)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.25rem' }}>
                      {t('planStatus')}
                    </div>
                    <div style={{
                      fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px',
                      color: org.subscriptionStatus === 'active' ? '#00d084' : org.subscriptionStatus === 'past_due' ? '#ffb900' : '#e81123'
                    }}>
                      {org.subscriptionStatus === 'active' ? t('planStatusActive')
                        : org.subscriptionStatus === 'past_due' ? t('planStatusPastDue')
                        : org.subscriptionStatus}
                    </div>
                  </div>
                </div>

                {/* Scan usage progress bar */}
                {org.scanLimit > 0 && (
                  <div className="limit-progress-container">
                    <div className="limit-progress-text">
                      {t('scansUsedLabel')}: <strong>{org.scansUsed} / {org.scanLimit}</strong>
                    </div>
                    <div className="limit-progress-track">
                      <div className="limit-progress-fill"
                        style={{ width: `${Math.min(100, (org.scansUsed / org.scanLimit) * 100)}%` }} />
                    </div>
                  </div>
                )}

                {/* One-time scans remaining */}
                {org.extraScansRemaining > 0 && (
                  <>
                    <p style={{ margin: '1rem 0 0.5rem 0', color: 'var(--foreground-darker)' }}>
                      {t('oneTimeScansRemaining')}: <strong style={{ color: 'var(--foreground)' }}>{org.extraScansRemaining}</strong>
                    </p>
                    <p style={{ margin: '0.5rem 0', color: 'var(--foreground-darker)' }}>
                      {t('extraScansExpireOn', { date: formatDate(org.extraScansExpiresAt) })}
                    </p>
                  </>
                )}

                {/* Seats */}
                {org.seatsAllowed > 1 && (
                  <p style={{ margin: '0.5rem 0', color: 'var(--foreground-darker)' }}>
                    {t('seatsUsedLabel')}: <strong style={{ color: 'var(--foreground)' }}>{org.seatsUsed} / {org.seatsAllowed}</strong>
                  </p>
                )}

                {/* Expiry */}
                {org.expiresAt && (
                  <p className="expiry-date" style={{ fontSize: '1rem', margin: '1rem 0' }}>
                    {t('planExpiresLabel')}: <strong>{formatDate(org.expiresAt)}</strong>
                  </p>
                )}

                {/* Cancel button — only for recurring subscriptions */}
                {org.billingCycle !== 'onetime' && (
                  <>
                    <button onClick={() => setCancelDialogOpen(true)} className="btn-downgrade">
                      {t('cancelProSubscription')}
                    </button>
                    <p className="downgrade-note">{t('cancelSubscriptionNote')}</p>
                  </>
                )}
              </div>

              {/* ── Top-Up: extra scans, purchasable any time while subscribed ────── */}
              {['owner', 'admin'].includes(org.role) && (
                <div style={{ marginTop: '2.5rem', borderTop: '1px solid rgba(255,107,0,0.3)', paddingTop: '2.5rem' }}>
                  <h2 style={{ marginBottom: '1rem', fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-light)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                    {t('topUpSectionTitle')}
                  </h2>
                  <p style={{ color: 'var(--foreground-darker)', marginBottom: '1.5rem' }}>
                    {t('topUpSectionDescription')}
                  </p>
                  {org.scanLimit > 0 && org.scansUsed >= org.scanLimit && (
                    <p className="save-message info" style={{ marginBottom: '1.5rem' }}>
                      {t('planLimitExhaustedHint')}
                    </p>
                  )}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                    {PLANS.onetime.map(plan => (
                      <PlanCard
                        key={plan.planType}
                        plan={plan}
                        onSelect={startCheckout}
                        loading={paymentLoading}
                        buttonLabel={t('buyExtraScans')}
                        t={t}
                      />
                    ))}
                  </div>
                </div>
              )}

              {/* ── Team Management Section ─────────────────────────────────────────── */}
              {org.seatsAllowed > 1 && (
                <div style={{ marginTop: '2.5rem', borderTop: '1px solid rgba(255,107,0,0.3)', paddingTop: '2.5rem' }}>
                  <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-light)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                    {t('teamManagement')}
                  </h2>

                  <div style={{ marginBottom: '2rem' }}>
                    <p style={{ margin: '0 0 1rem 0', color: 'var(--foreground-darker)' }}>
                      {t('seatsUsedLabel')}: <strong style={{ color: 'var(--foreground)' }}>{org.seatsUsed} / {org.seatsAllowed}</strong>
                    </p>

                    <form className="invite-form" onSubmit={handleSendInvite}>
                      <input
                        type="email"
                        className="invite-input"
                        placeholder={t('emailAddress')}
                        value={inviteEmail}
                        onChange={(e) => setInviteEmail(e.target.value)}
                        required
                      />
                      <button
                        type="submit"
                        className="btn-invite"
                        disabled={inviteLoading || org.seatsUsed + (org.pendingInvites?.length || 0) >= org.seatsAllowed}
                      >
                        {inviteLoading ? t('sending') : t('sendInvite')}
                      </button>
                    </form>
                    {inviteMessage && (
                      <div className={`invite-message ${inviteMessage.type}`}>
                        {inviteMessage.text}
                      </div>
                    )}
                  </div>

                  {/* Active Members */}
                  {org.members && org.members.length > 0 && (
                    <div style={{ marginBottom: '1.5rem' }}>
                      <h3 style={{ fontSize: '1rem', color: 'var(--accent)', marginBottom: '0.75rem', textTransform: 'uppercase' }}>
                        {t('activeMembers')}
                      </h3>
                      <ul className="member-list">
                        {org.members.map(member => (
                          <li key={member._id || member.email} className="member-item">
                            <div className="member-info">
                              <strong>{member.name}</strong>
                              <span className="member-email">{member.email}</span>
                            </div>
                            <span className="member-role">{member.role}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Pending Invites */}
                  {org.pendingInvites && org.pendingInvites.length > 0 && (
                    <div>
                      <h3 style={{ fontSize: '1rem', color: 'var(--accent)', marginBottom: '0.75rem', textTransform: 'uppercase' }}>
                        {t('pendingInvites')}
                      </h3>
                      <ul className="member-list">
                        {org.pendingInvites.map(invite => (
                          <li key={invite.token} className="member-item invite-item">
                            <div className="member-info">
                              <span className="invite-email">{invite.email}</span>
                              <span className="invite-role">{invite.role}</span>
                            </div>
                            <div className="invite-status-group">
                              <span className="invite-status">{t('pending')}</span>
                              {['owner', 'admin'].includes(org.role) && (
                                <button 
                                  onClick={() => handleCancelInvite(invite.token)}
                                  className="btn-revoke"
                                  title={t('revokeInvite')}
                                >
                                  {t('revoke')}
                                </button>
                              )}
                            </div>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── Plan Selection (for users without an active plan) ────────────── */}
          {!hasPlan && (
            <div className="profile-section pro-upgrade-section">
              <h2>{t('choosePlan')}</h2>

              {/* Billing cycle tabs */}
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
                {['monthly', 'annual', 'onetime'].map(bc => (
                  <button key={bc} onClick={() => setSelectedBilling(bc)} style={{
                    padding: '0.5rem 1.25rem',
                    borderRadius: '2rem',
                    border: selectedBilling === bc ? '2px solid var(--accent)' : '1px solid rgba(255,255,255,0.2)',
                    background: selectedBilling === bc ? 'var(--accent)' : 'transparent',
                    color: selectedBilling === bc ? 'var(--background)' : 'var(--foreground)',
                    cursor: 'pointer',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    fontSize: '0.8rem',
                    letterSpacing: '1px',
                    transition: 'all 0.2s',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem'
                  }}>
                    {BILLING_LABELS[bc] ? t(BILLING_LABELS[bc]) : bc}
                    {bc === 'annual' && (
                      <span style={{
                        fontSize: '0.7rem', fontWeight: 800,
                        color: selectedBilling === bc ? 'rgba(0,0,0,0.6)' : '#00d084',
                        background: selectedBilling === bc ? 'rgba(0,0,0,0.15)' : 'rgba(0,208,132,0.15)',
                        padding: '0.1rem 0.4rem', borderRadius: '4px'
                      }}>{t('discount17Percent')}</span>
                    )}
                  </button>
                ))}
              </div>

              {/* Plan cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                {PLANS[selectedBilling].map(plan => (
                  <PlanCard
                    key={plan.planType}
                    plan={plan}
                    onSelect={startCheckout}
                    loading={paymentLoading}
                    buttonLabel={t('selectPlan')}
                    t={t}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Cancel subscription confirmation dialog */}
      <ConfirmDialog
        isOpen={cancelDialogOpen}
        onConfirm={cancelSubscription}
        onCancel={() => setCancelDialogOpen(false)}
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
