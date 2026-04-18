import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import '../styles/ScanTypeSelector.scss';

const ScanTypeSelector = () => {
  const navigate = useNavigate();
  const { isPro } = useUser();

  const handleScanTypeSelection = (scanType) => {
    // 🧹 PREVENT WORKFLOW TANGLE: Clear any pending schedule intent
    // when a user explicitly chooses "Start Scan"
    sessionStorage.removeItem('pendingScheduleConfig');
    
    if (scanType === 'normal') {
      navigate('/?type=normal');
    } else {
      navigate('/?type=auth');
    }
  };

  return (
    <div className="scan-type-selector-container">
      <div className="scan-type-content">
        <h1 className="scan-type-title">
          Choose Your <span className="highlight">Scan Type</span>
        </h1>
        <p className="scan-type-subtitle">
          Select the type of security scan you want to perform
        </p>
        
        <div className="scan-type-cards">
          {/* Normal Scan Card */}
          <div
            className="scan-type-card"
            onClick={() => handleScanTypeSelection('normal')}
          >
            <div className="card-icon">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth={1.5}
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
                />
              </svg>
            </div>
            <h2 className="card-title">Public Website Scan</h2>
            <p className="card-description">
              Comprehensive security analysis for publicly accessible websites. Includes deep vulnerability scanning,
              performance optimization checks, and security metadata analysis.
            </p>
            <ul className="card-features">
              <li>
                <span className="feature-icon">✓</span>
                <span>Comprehensive Vulnerability Scan</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>Site Performance Analysis</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>Security Header Analysis</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>Website Health Check</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>No Login Required</span>
              </li>
            </ul>
            <div className="card-actions">
              <div 
                className="card-button"
                onClick={(e) => {
                  e.stopPropagation();
                  navigate('/schedules?type=public');
                }}
              >
                <span>Schedule Scan</span>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                </svg>
              </div>
              <div 
                className="card-button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleScanTypeSelection('normal');
                }}
              >
                <span>Start Public Scan</span>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                </svg>
              </div>
            </div>
          </div>

          {/* Authenticated Scan Card */}
          <div
            className={`scan-type-card scan-type-card--auth ${isPro ? 'pro-mode' : ''}`}
            onClick={() => handleScanTypeSelection('auth')}
          >
            <div className={`card-icon card-icon--auth ${isPro ? 'pro-mode' : ''}`}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth={1.5}
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
                />
              </svg>
            </div>
            <h2 className="card-title">Authenticated Website Scan</h2>
            <p className="card-description">
              Deep security analysis for login-protected areas. Automatically detects login interfaces,
              validates credentials, and performs in-depth scans on authenticated areas.
            </p>
            <ul className="card-features">
              <li>
                <span className="feature-icon">✓</span>
                <span>Auto-Detect Login Forms</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>Credential Validation</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>In-Depth Authenticated Scan</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>Cookie-Based Session Management</span>
              </li>
              <li>
                <span className="feature-icon">✓</span>
                <span>Server-Side Credential Handling</span>
              </li>
            </ul>
            <div className="card-actions">
              <div 
                className="card-button"
                onClick={(e) => {
                  e.stopPropagation();
                  navigate('/schedules?type=authenticated');
                }}
              >
                <span>Schedule Scan</span>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                </svg>
              </div>
              <div 
                className="card-button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleScanTypeSelection('auth');
                }}
              >
                <span>Start Authenticated Scan</span>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        <div className="scan-type-note">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            strokeWidth={1.5}
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"
            />
          </svg>
          <span>Your credentials are never stored and are handled securely in-memory during the scan</span>
        </div>
      </div>
    </div>
  );
};

export default ScanTypeSelector;
