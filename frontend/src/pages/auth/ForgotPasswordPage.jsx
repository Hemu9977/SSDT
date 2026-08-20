import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import Header from '../../components/header';
import ParticleBackground from '../../components/ParticleBackground';
import { useTranslation } from '../../contexts/TranslationContext';
import { API_BASE } from '../../config/api';
import { getApiErrorLabel } from '../../utils/apiErrors';

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { t } = useTranslation();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();

      if (response.ok) {
        setMessage(getApiErrorLabel(t, data));
      } else {
        setError(getApiErrorLabel(t, data));
      }
    } catch (error) {
      console.error('Forgot password failed:', error);
      setError(t('genericErrorLater'));
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
            <h1 className="auth-title">{t('forgotPassword')}</h1>
            <p className="auth-description">
              {t('forgotPasswordDescription')}
            </p>
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
              <button type="submit" disabled={loading}>
                {loading ? t('sending') : t('sendResetLink')}
              </button>
            </form>
            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <p className="auth-switch-link">
              {t('rememberPassword')} <Link to="/login">{t('login')}</Link>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default ForgotPasswordPage;
