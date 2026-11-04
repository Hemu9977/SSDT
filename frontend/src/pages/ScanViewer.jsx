import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import LandingPage from './LandingPage';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import { useTranslation } from '../contexts/TranslationContext';
import { requestTimeout } from '../utils/requestTimeout';
import '../styles/Hero.scss';

import { API_BASE } from '../config/api';

// The response can carry the full stored findings, so this is generous; it exists
// so a request the server never answers ends in an error with a retry instead of
// an endless spinner.
const SCAN_LOAD_TIMEOUT_MS = 90000;

/**
 * ScanViewer - Loads a historical scan and displays it using the same UI as fresh scans.
 * This is just a data loader wrapper around LandingPage/Hero.
 */
const ScanViewer = () => {
  const { analysisId } = useParams();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [historicalScan, setHistoricalScan] = useState(null);
  const [loading, setLoading] = useState(true);
  // An i18n key, never a backend string: those are English-only and for logs.
  const [errorKey, setErrorKey] = useState(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    const loadScan = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/login');
        return;
      }

      const deadline = requestTimeout(SCAN_LOAD_TIMEOUT_MS, controller.signal);
      try {
        console.log(`Loading historical scan: ${analysisId}`);
        const response = await fetch(`${API_BASE}/api/scan/scan/${analysisId}`, {
          headers: { 'x-auth-token': token },
          signal: deadline.signal
        });

        if (cancelled) return;

        if (!response.ok) {
          if (response.status === 401) {
            localStorage.removeItem('token');
            navigate('/login');
            return;
          }
          setErrorKey(response.status === 404 ? 'scanNotFoundExpired' : 'failedLoadScan');
          setLoading(false);
          return;
        }

        const data = await response.json();
        if (cancelled) return;
        console.log('Historical scan loaded:', data.target);
        setHistoricalScan(data);
        setLoading(false);
      } catch (err) {
        if (cancelled) return; // unmounted or analysisId changed
        console.error('Load scan error:', err);
        setErrorKey(deadline.timedOut ? 'scanLoadTimedOut' : 'failedLoadScan');
        setLoading(false);
      } finally {
        deadline.clear();
      }
    };

    loadScan();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [analysisId, navigate, attempt]);

  const retry = () => {
    setErrorKey(null);
    setLoading(true);
    setAttempt((n) => n + 1);
  };

  // Loading state
  if (loading) {
    return (
      <div className="landing-page">
        <ParticleBackground />
        <Header />
        <div className="hero-section">
          <div className="hero-content">
            <div style={{ textAlign: 'center', padding: '3rem' }}>
              <div className="spinner" style={{ margin: '0 auto 1rem' }}></div>
              <p>{t('loadingScanResults')}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (errorKey) {
    return (
      <div className="landing-page">
        <ParticleBackground />
        <Header />
        <div className="hero-section">
          <div className="hero-content">
            <div style={{ textAlign: 'center', padding: '3rem' }}>
              <h2 style={{ color: '#e81123', marginBottom: '1rem' }}>{t('unableToLoadScan')}</h2>
              <p style={{ marginBottom: '2rem' }}>{t(errorKey)}</p>
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                {errorKey !== 'scanNotFoundExpired' && (
                  <button className="scan-button" onClick={retry} style={{ maxWidth: '200px' }}>
                    {t('retryLoad')}
                  </button>
                )}
                <button
                  className="scan-button"
                  onClick={() => navigate('/profile')}
                  style={{ maxWidth: '200px' }}
                >
                  {t('backToProfile')}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Success - render LandingPage with historical scan data
  // Hero component will handle displaying it in the exact same format as fresh scans
  return <LandingPage historicalScan={historicalScan} />;
};

export default ScanViewer;
