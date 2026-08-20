// frontend/src/pages/auth/LoginPage.jsx

import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useGoogleLogin } from '@react-oauth/google';
import { FcGoogle } from 'react-icons/fc';
import Header from '../../components/header';
import ParticleBackground from '../../components/ParticleBackground';
import EyeIcon from '../../components/EyeIcon';
import { useTranslation } from '../../contexts/TranslationContext';
import { useUser } from '../../contexts/UserContext';
import { postLoginTarget } from '../../utils/authRedirect';
import '../../styles/Auth.scss';
import { API_BASE } from '../../config/api';

const LoginPage = () => {
  const { refreshUser } = useUser();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { t, syncLanguage } = useTranslation();

  const googleLogin = useGoogleLogin({
    onSuccess: async (tokenResponse) => {
      setLoading(true);
      setMessage('');
      setError('');
      try {
        const response = await fetch(`${API_BASE}/auth/google`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ googleAccessToken: tokenResponse.access_token }),
        });

        const data = await response.json();

        if (response.ok) {
          localStorage.setItem('token', data.token);
          syncLanguage();
          setMessage(t('googleLoginSuccessful'));
          // UserProvider fetches the profile only on mount and sits above
          // BrowserRouter, so a client-side navigate() would land on the route
          // guard with user still null. Refresh the context before moving.
          await refreshUser();
          const target = postLoginTarget(data.user);
          setTimeout(() => navigate(target), 2000);
        } else {
          setError(data.message || t('googleLoginFailed'));
        }
      } catch (err) {
        console.error('Google Login Error:', err);
        setError(t('googleLoginFailed'));
      } finally {
        setLoading(false);
      }
    },
    onError: () => setError(t('googleLoginFailedShort')),
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (response.ok) {
        if (data.token) {
          localStorage.setItem('token', data.token);
          syncLanguage();
          setMessage(data.message);
          // UserProvider fetches the profile only on mount and sits above
          // BrowserRouter, so a client-side navigate() would land on the route
          // guard with user still null. Refresh the context before moving.
          await refreshUser();
          const target = postLoginTarget(data.user);
          setTimeout(() => navigate(target), 2000);
        } else {
          setMessage(data.message);
          setTimeout(() => navigate('/verify-otp', { state: { email } }), 2000);
        }
      } else {
        setError(data.message);
      }
    } catch (error) {
      console.error('Login failed:', error);
      setError(t('loginFailedLater'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <ParticleBackground />
      <Header />
      <main>
        <div className="auth-container">
          <div className="auth-content">
            <h1 className="auth-title">{t('loginTitle')}</h1>
            <form className="auth-form" onSubmit={handleSubmit}>
              <div className="input-wrapper">
                <input
                  type="email"
                  name="email"
                  placeholder={t('email')}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div className="input-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  placeholder={t('password')}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <EyeIcon isVisible={showPassword} onClick={() => setShowPassword(!showPassword)} />
              </div>
              <button type="submit" disabled={loading}>
                {loading ? t('loggingIn') : t('login')}
              </button>
            </form>

            <div className="auth-separator">
              <span>{t('or')}</span>
            </div>
            
            <button 
              className="google-btn" 
              onClick={() => googleLogin()}
              disabled={loading}
              style={{ width: '100%' }}
            >
              <FcGoogle size={22} />
              <span>{t('loginWithGoogle')}</span>
            </button>

            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            
            <p className="auth-switch-link">
              {t('newUser')} <Link to="/register">{t('registerNow')}</Link>
            </p>
            <p className="auth-switch-link">
              <Link to="/forgot-password">{t('forgotPassword')}</Link>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default LoginPage;
