import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import Header from '../../components/header';
import ParticleBackground from '../../components/ParticleBackground';
import { useTranslation } from '../../contexts/TranslationContext';
import '../../styles/Auth.scss';
import { API_BASE } from '../../config/api';

const OTPVerification = () => {
  const [otp, setOtp] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const { t } = useTranslation();

  // Get email from location state (passed from register/login)
  const email = location.state?.email;

  if (!email) {
    // Redirect back to login if no email
    navigate('/login');
    return null;
  }

  const handleVerify = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage('');
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp }),
      });
      const data = await response.json();

      if (response.ok) {
        localStorage.setItem('token', data.token);
        setMessage(t('otpVerificationSuccess'));
        setTimeout(() => {
          navigate('/'); // Redirect to dashboard/home
        }, 2000);
      } else {
        setError(data.message);
      }
    } catch (error) {
      console.error('OTP verification failed:', error);
      setError(t('verificationFailed'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    setResendLoading(true);
    setMessage('');
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/resend-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();

      if (response.ok) {
        setMessage(t('otpSentSuccess'));
      } else {
        setError(data.message);
      }
    } catch (error) {
      console.error('Resend OTP failed:', error);
      setError(t('resendOtpFailed'));
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <ParticleBackground />
      <Header />
      <main>
        <div className="auth-container">
          <div className="auth-content">
            <h1 className="auth-title">{t('verifyEmail')}</h1>
            <p className="auth-subtitle">
              {t('otpSentTo')} <strong>{email}</strong>
            </p>
            <form className="auth-form" onSubmit={handleVerify}>
              <div className="input-wrapper">
                <input
                  type="text"
                  placeholder={t('enterOtp')}
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength="6"
                  required
                />
              </div>
              <button type="submit" disabled={isLoading || otp.length !== 6}>
                {isLoading ? t('verifying') : t('verify')}
              </button>
            </form>
            <div className="auth-links">
              <button
                type="button"
                className="resend-button"
                onClick={handleResend}
                disabled={resendLoading}
              >
                {resendLoading ? t('sending') : t('resendCode')}
              </button>
            </div>
            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <p className="auth-switch-link">
              {t('wrongEmail')} <a href="/login">{t('goBackToLogin')}</a>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default OTPVerification;
