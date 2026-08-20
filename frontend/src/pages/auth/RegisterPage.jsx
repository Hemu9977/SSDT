// frontend/src/pages/auth/RegisterPage.jsx

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

const RegisterPage = () => {
  const { refreshUser } = useUser();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { t, language } = useTranslation();

  const googleSignup = useGoogleLogin({
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
          setMessage(t('googleSignupSuccessful'));
          // UserProvider fetches the profile only on mount and sits above
          // BrowserRouter, so a client-side navigate() would land on the route
          // guard with user still null. Refresh the context before moving.
          await refreshUser();
          const target = postLoginTarget(data.user);
          setTimeout(() => navigate(target), 2000);
        } else {
          setError(data.message || t('googleSignupFailed'));
        }
      } catch (err) {
        console.error('Google Sign Up Error:', err);
        setError(t('googleSignupFailed'));
      } finally {
        setLoading(false);
      }
    },
    onError: () => setError(t('googleSignupFailedShort')),
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, language }),
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setTimeout(() => {
          navigate('/verify-otp', { state: { email } });
        }, 2000);
      } else {
        setError(data.message);
      }
    } catch (error) {
      console.error('Registration failed:', error);
      setError(t('registrationFailedLater'));
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
            <h1 className="auth-title">{t('registerTitle')}</h1>
            <form className="auth-form" onSubmit={handleSubmit}>
              <div className="input-wrapper">
                <input
                  type="text"
                  name="name"
                  placeholder={t('name')}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>
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
                {loading ? t('registering') : t('register')}
              </button>
            </form>

            <div className="auth-separator">
              <span>{t('or')}</span>
            </div>

            <button 
              className="google-btn" 
              onClick={() => googleSignup()}
              disabled={loading}
              style={{ width: '100%' }}
            >
              <FcGoogle size={22} />
              <span>{t('signUpWithGoogle')}</span>
            </button>

            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            
            <p className="auth-switch-link">
              {t('haveAccount')} <Link to="/login">{t('logIn')}</Link>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default RegisterPage;
