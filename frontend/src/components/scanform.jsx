import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/ScanForm.scss';

import { API_BASE } from '../config/api';

const ScanForm = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState('');
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  // Poll scan status - defined with useCallback to avoid hoisting issues
  const pollScanStatus = useCallback(async (currentScanId) => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/scan/combined-analysis/${currentScanId}`, {
        headers: { 'x-auth-token': token }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      // Update progress based on scan phases
      if (data.zapData) {
        const zapPhase = data.zapData.phase || 'scanning';
        const zapProgress = data.zapData.progress || 0;

        // Show URL count during spider phases
        if (zapPhase === 'spidering' || zapPhase === 'ajax_spider') {
          const urlsFound = data.zapData.urlsFound || 0;
          setScanStage(`${zapPhase === 'ajax_spider' ? 'Deep Web Crawling' : 'Web Crawling'}: ${urlsFound} URLs found (${zapProgress}%)`);
        } else {
          setScanStage(`Vulnerability Analysis: ${zapPhase} (${zapProgress}%)`);
        }

        setScanProgress(zapProgress);
      } else if (data.status === 'queued' || data.status === 'pending') {
        setScanStage('Initializing scan...');
        setScanProgress(5);
      } else if (data.status === 'combining') {
        setScanStage('Running security scans...');
        setScanProgress(10);
      }

      if (data.status === 'completed') {
        setLoading(false);
        setScanId(null);
        localStorage.removeItem('activeScan');
        // Trigger report display in parent component
        window.dispatchEvent(new CustomEvent('scanCompleted', { detail: data }));
      } else if (data.status === 'failed' || data.status === 'stopped') {
        if (data.status === 'stopped') {
          setError('Scan was stopped');
        } else {
          setError('Scan failed: ' + (data.error || 'Unknown error'));
        }
        setLoading(false);
        setScanId(null);
        localStorage.removeItem('activeScan');
      } else {
        // Continue polling
        setTimeout(() => pollScanStatus(currentScanId), 2000);
      }
    } catch (err) {
      console.error('Polling error:', err);
      // Continue polling on transient errors
      setTimeout(() => pollScanStatus(currentScanId), 5000);
    }
  }, [navigate]);

  // Load persisted scan from localStorage on mount
  useEffect(() => {
    const resumeScan = async () => {
      const persistedScan = localStorage.getItem('activeScan');
      if (!persistedScan) return;

      const { scanId: persistedScanId, url: persistedUrl, timestamp } = JSON.parse(persistedScan);

      // Check if scan is less than 1 hour old
      const scanAge = Date.now() - timestamp;
      if (scanAge >= 3600000) {
        // Clear old scan data
        localStorage.removeItem('activeScan');
        return;
      }

      const token = localStorage.getItem('token');
      if (!token) {
        localStorage.removeItem('activeScan');
        return;
      }

      // Check current scan status from server before resuming
      try {
        const response = await fetch(`${API_BASE}/api/scan/combined-analysis/${persistedScanId}`, {
          headers: { 'x-auth-token': token }
        });

        if (!response.ok) {
          // Scan not found or error - clear and don't resume
          localStorage.removeItem('activeScan');
          return;
        }

        const data = await response.json();

        // Only resume if scan is still in progress
        if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
          // Scan already finished - clear localStorage
          localStorage.removeItem('activeScan');

          // If completed, show the results
          if (data.status === 'completed') {
            window.dispatchEvent(new CustomEvent('scanCompleted', { detail: data }));
          }
          return;
        }

        // Scan is still in progress - resume it
        console.log('Resuming scan:', persistedScanId);
        setScanId(persistedScanId);
        setUrl(persistedUrl);
        setLoading(true);
        setScanStage('Resuming scan...');
        pollScanStatus(persistedScanId);

      } catch (err) {
        console.error('Error checking scan status:', err);
        localStorage.removeItem('activeScan');
      }
    };

    resumeScan();
  }, [pollScanStatus]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(true);
    setScanProgress(0);
    setScanStage('Initializing scan...');
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/api/scan/combined-url-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      const analysisId = data.analysisId || data.data?.id;

      if (!analysisId) {
        throw new Error("No analysisId in response");
      }

      setScanId(analysisId);

      // Persist scan to localStorage
      localStorage.setItem('activeScan', JSON.stringify({
        scanId: analysisId,
        url,
        timestamp: Date.now()
      }));

      // Start polling
      pollScanStatus(analysisId);

    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message);
      setLoading(false);
    }
  };

  const handleStop = async () => {
    if (!scanId) return;

    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    setScanStage('Stopping scan and restarting containers...');

    try {
      // Call combined scan stop endpoint - stops ZAP & WebCheck, restarts both containers
      const response = await fetch(`${API_BASE}/api/scan/stop-scan/${scanId}`, {
        method: 'POST',
        headers: {
          'x-auth-token': token
        }
      });

      const data = await response.json();

      if (data.success) {
        setScanStage('Scan stopped - containers restarting for fresh environment');
      }

      // Short delay to show the message before clearing
      setTimeout(() => {
        setLoading(false);
        setScanId(null);
        setScanProgress(0);
        setScanStage('');
        localStorage.removeItem('activeScan');
      }, 2000);

    } catch (err) {
      console.error('Stop error:', err);
      setError('Failed to stop scan');
      setLoading(false);
    }
  };

  return (
    <div className="scan-form-container">
      <form onSubmit={handleSubmit} className="scan-form">
        <div className="input-group">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL to scan (e.g., https://example.com)"
            required
            disabled={loading}
            className="url-input"
          />
          {!loading ? (
            <button type="submit" className="scan-button">
              Start Scan
            </button>
          ) : (
            <button type="button" onClick={handleStop} className="stop-button">
              Stop Scan
            </button>
          )}
        </div>
      </form>

      {loading && (
        <div className="scan-progress">
          <div className="progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
          <p className="progress-text">{scanStage}</p>
        </div>
      )}

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}
    </div>
  );
};

export default ScanForm;
