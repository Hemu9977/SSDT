import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import LandingPage from './LandingPage';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import '../styles/Hero.scss';

import { API_BASE } from '../config/api';

/**
 * ScanViewer - Loads a historical scan and displays it using the same UI as fresh scans.
 * This is just a data loader wrapper around LandingPage/Hero.
 */
const ScanViewer = () => {
  const { analysisId } = useParams();
  const navigate = useNavigate();
  const [historicalScan, setHistoricalScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    const loadScan = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/login');
        return;
      }

      try {
        console.log(`Loading historical scan: ${analysisId}`);
        const response = await fetch(`${API_BASE}/api/scan/scan/${analysisId}`, {
          headers: { 'x-auth-token': token },
          signal: controller.signal
        });

        if (cancelled) return;

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          if (response.status === 404) {
            setError('Scan not found or has expired. Scans are automatically deleted after 7 days.');
          } else if (response.status === 401) {
            localStorage.removeItem('token');
            navigate('/login');
            return;
          } else {
            setError(errorData.error || 'Failed to load scan');
          }
          setLoading(false);
          return;
        }

        const data = await response.json();
        if (cancelled) return;
        console.log('Historical scan loaded:', data.target);
        setHistoricalScan(data);
        setLoading(false);
      } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Load scan error:', err);
        if (!cancelled) {
          setError('Failed to load scan. Please try again.');
          setLoading(false);
        }
      }
    };

    loadScan();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [analysisId, navigate]);

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
              <p>Loading scan results...</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="landing-page">
        <ParticleBackground />
        <Header />
        <div className="hero-section">
          <div className="hero-content">
            <div style={{ textAlign: 'center', padding: '3rem' }}>
              <h2 style={{ color: '#e81123', marginBottom: '1rem' }}>Unable to Load Scan</h2>
              <p style={{ marginBottom: '2rem' }}>{error}</p>
              <button
                className="scan-button"
                onClick={() => navigate('/profile')}
                style={{ maxWidth: '200px', margin: '0 auto' }}
              >
                Back to Profile
              </button>
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
