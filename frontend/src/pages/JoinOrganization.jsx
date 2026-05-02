import { useUser } from '../contexts/UserContext';
import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import ParticleBackground from '../components/ParticleBackground';
import '../styles/JoinOrganization.scss';

const API_BASE = 'http://10.60.227.82:3001';


const JoinOrganization = () => {
  const { refreshUser } = useUser(); // ✅ MOVE HERE
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token');

  // Invite validation state
  const [inviteInfo, setInviteInfo] = useState(null);
  const [validating, setValidating] = useState(true);
  const [validationError, setValidationError] = useState('');

  // UI mode: 'choose' | 'register' | 'login'
  const [mode, setMode] = useState('choose');

  // Form fields
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginOtp, setLoginOtp] = useState('');
  const [loginStep, setLoginStep] = useState('credentials'); // 'credentials' | 'otp'

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // ── Step 1: Validate the token on mount ────────────────────────────────────
  useEffect(() => {
    if (!token) {
      setValidating(false);
      setValidationError('No invite token found in URL. Please check your invite link.');
      return;
    }

    const validateToken = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/org/invite/${token}`);
        const data = await res.json();

        if (!res.ok) {
          setValidationError(data.error || 'Invalid invite link');
        } else {
          setInviteInfo(data.invite);
          // Pre-fill email for both forms
          setEmail(data.invite.email);
          setLoginEmail(data.invite.email);
        }
      } catch (_) {
        setValidationError('Could not connect to the server. Please try again later.');
      } finally {
        setValidating(false);
      }
    };

    validateToken();
  }, [token]);

  // ── Shared: persist JWT and redirect ──────────────────────────────────────
  const finalizeLogin = async (jwt, message) => {
    localStorage.setItem('token', jwt);

    await refreshUser(); // ✅ now valid

    setSuccess(message || `Welcome to ${inviteInfo?.orgName}! Redirecting...`);
    setTimeout(() => navigate('/profile'), 2000);
  };

  // ── Accept invite (works for both new and existing logged-in users) ────────
  const acceptInvite = async (jwt) => {
    const headers = { 'Content-Type': 'application/json' };
    if (jwt) headers['x-auth-token'] = jwt;

    const res = await fetch(`${API_BASE}/api/org/accept-invite`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ token })
    });
    return res.json();
  };

  // ── REGISTER flow ──────────────────────────────────────────────────────────
  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/org/accept-invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, name, password })
      });
      const data = await res.json();

      if (!res.ok) {
        if (data.requiresLogin) {
          setError(data.error);
          setLoginEmail(inviteInfo.email);
          setMode('login');
        } else {
          setError(data.error || 'Registration failed');
        }
        return;
      }

      finalizeLogin(data.token, data.message);
    } catch (_) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // ── LOGIN flow ─────────────────────────────────────────────────────────────
  const handleLoginCredentials = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password: loginPassword })
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.message || 'Invalid credentials');
        return;
      }

      // Login sends OTP — move to OTP step
      if (data.message && data.message.toLowerCase().includes('otp')) {
        setLoginStep('otp');
      } else if (data.token) {
        // Directly logged in (Google or password-reset bypass)
        await handleAcceptAfterLogin(data.token);
      }
    } catch (_) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoginOtp = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, otp: loginOtp })
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.message || 'Invalid OTP');
        return;
      }

      await handleAcceptAfterLogin(data.token);
    } catch (_) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleAcceptAfterLogin = async (jwt) => {
    const data = await acceptInvite(jwt);
    if (data.success) {
      finalizeLogin(data.token || jwt, data.message);
    } else {
      // Already a member or other non-fatal issue
      setError(data.error || 'Could not accept invite');
      if (data.error?.toLowerCase().includes('already a member')) {
        localStorage.setItem('token', jwt);
        setTimeout(() => navigate('/profile'), 2000);
      }
    }
  };

  // ── RENDER ─────────────────────────────────────────────────────────────────

  if (validating) {
    return (
      <div className="join-page">
        <ParticleBackground />
        <div className="join-card">
          <div className="join-logo">FORTEXA</div>
          <div className="join-loading">
            <div className="spinner" />
            <p>Validating invite link...</p>
          </div>
        </div>
      </div>
    );
  }

  if (validationError) {
    return (
      <div className="join-page">
        <ParticleBackground />
        <div className="join-card">
          <div className="join-logo">FORTEXA</div>
          <div className="join-error-box">
            <div className="join-error-icon">✕</div>
            <h2>Invite Invalid</h2>
            <p>{validationError}</p>
            <button className="join-btn" onClick={() => navigate('/')}>Go to Homepage</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="join-page">
      <ParticleBackground />
      <div className="join-card">
        <div className="join-logo">FORTEXA</div>

        {/* Invite Summary Banner */}
        <div className="join-invite-banner">
          <p className="join-invite-label">You're invited to join</p>
          <h2 className="join-org-name">{inviteInfo.orgName}</h2>
          <span className="join-role-badge">{inviteInfo.role.toUpperCase()}</span>
        </div>

        {success && <div className="join-success">{success}</div>}
        {error && <div className="join-error">{error}</div>}

        {/* ── Mode: Choose ── */}
        {mode === 'choose' && (
          <div className="join-choose">
            <p className="join-subtitle">How would you like to join?</p>
            <button className="join-btn join-btn--primary" onClick={() => setMode('register')}>
              Create New Account
            </button>
            <button className="join-btn join-btn--secondary" onClick={() => setMode('login')}>
              Log In to Existing Account
            </button>
          </div>
        )}

        {/* ── Mode: Register ── */}
        {mode === 'register' && (
          <form className="join-form" onSubmit={handleRegister}>
            <h3>Create Your Account</h3>
            <p className="join-email-notice">Joining as: <strong>{inviteInfo.email}</strong></p>

            <div className="join-field">
              <label>Full Name</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Your full name"
                required
                autoFocus
              />
            </div>
            <div className="join-field">
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Create a password"
                required
              />
            </div>
            <div className="join-field">
              <label>Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                placeholder="Repeat password"
                required
              />
            </div>

            <button type="submit" className="join-btn join-btn--primary" disabled={loading}>
              {loading ? 'Creating Account...' : 'Create Account & Join'}
            </button>
            <button type="button" className="join-btn--link" onClick={() => setMode('choose')}>
              ← Back
            </button>
          </form>
        )}

        {/* ── Mode: Login ── */}
        {mode === 'login' && loginStep === 'credentials' && (
          <form className="join-form" onSubmit={handleLoginCredentials}>
            <h3>Log In to Join</h3>
            <div className="join-field">
              <label>Email</label>
              <input
                type="email"
                value={loginEmail}
                onChange={e => setLoginEmail(e.target.value)}
                placeholder="your@email.com"
                required
              />
            </div>
            <div className="join-field">
              <label>Password</label>
              <input
                type="password"
                value={loginPassword}
                onChange={e => setLoginPassword(e.target.value)}
                placeholder="Your password"
                required
              />
            </div>

            <button type="submit" className="join-btn join-btn--primary" disabled={loading}>
              {loading ? 'Logging in...' : 'Log In & Join'}
            </button>
            <button type="button" className="join-btn--link" onClick={() => setMode('choose')}>
              ← Back
            </button>
          </form>
        )}

        {/* ── Mode: Login OTP ── */}
        {mode === 'login' && loginStep === 'otp' && (
          <form className="join-form" onSubmit={handleLoginOtp}>
            <h3>Enter Verification Code</h3>
            <p className="join-subtitle">We sent a code to <strong>{loginEmail}</strong></p>
            <div className="join-field">
              <label>OTP Code</label>
              <input
                type="text"
                value={loginOtp}
                onChange={e => setLoginOtp(e.target.value)}
                placeholder="6-digit code"
                maxLength={6}
                required
                autoFocus
              />
            </div>
            <button type="submit" className="join-btn join-btn--primary" disabled={loading}>
              {loading ? 'Verifying...' : 'Verify & Join'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

export default JoinOrganization;
