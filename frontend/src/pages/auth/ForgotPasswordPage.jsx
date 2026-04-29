import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import Header from '../../components/header';
import ParticleBackground from '../../components/ParticleBackground';
import { API_BASE } from '../../config/api';

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

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
        setMessage(data.message);
      } else {
        setError(data.message);
      }
    } catch (error) {
      console.error('Forgot password failed:', error);
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
            <h1 className="auth-title">Forgot Password</h1>
            <p className="auth-description">
              Enter your email address and we'll send you a link to reset your password.
            </p>
            <form className="auth-form" onSubmit={handleSubmit}>
              <div className="input-wrapper">
                <input
                  type="email"
                  name="email"
                  placeholder="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <button type="submit" disabled={loading}>
                {loading ? 'Sending...' : 'Send Reset Link'}
              </button>
            </form>
            {message && <p className="success-message">{message}</p>}
            {error && <p className="error-message">{error}</p>}
            <p className="auth-switch-link">
              Remember your password? <Link to="/login">Login</Link>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default ForgotPasswordPage;