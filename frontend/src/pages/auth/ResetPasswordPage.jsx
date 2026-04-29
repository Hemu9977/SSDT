import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Header from '../../components/header';
import ParticleBackground from '../../components/ParticleBackground';
import EyeIcon from '../../components/EyeIcon';
import { API_BASE } from '../../config/api';

const ResetPasswordPage = () => {
  const { token } = useParams();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      setError('Invalid reset link');
    }
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      });
      const data = await response.json();

      if (response.ok) {
        setMessage(data.message);
        setTimeout(() => {
          navigate('/login');
        }, 3000);
      } else {
        setError(data.message);
      }
    } catch (error) {
      console.error('Reset password failed:', error);
      setError('An error occurred. Please try again later.');
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
            <h1 className="auth-title">Reset Password</h1>
            <p className="auth-description">
              Enter your new password below.
            </p>
            <form className="auth-form" onSubmit={handleSubmit}>
              <div className="input-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  placeholder="New Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength="6"
                />
                <EyeIcon isVisible={showPassword} onClick={() => setShowPassword(!showPassword)} />
              </div>
              <div className="input-wrapper">
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  name="confirmPassword"
                  placeholder="Confirm New Password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  minLength="6"
                />
                <EyeIcon isVisible={showConfirmPassword} onClick={() => setShowConfirmPassword(!showConfirmPassword)} />
              </div>
              <button type="submit" disabled={loading || !token}>
                {loading ? 'Resetting...' : 'Reset Password'}
              </button>
            </form>
            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
          </div>
        </div>
      </main>
    </div>
  );
};

export default ResetPasswordPage;