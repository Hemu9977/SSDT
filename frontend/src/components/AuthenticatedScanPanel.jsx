import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { useTranslation } from '../contexts/TranslationContext';
import { useTheme } from '../context/ThemeContext';
import ZapReportEnhanced from './ZapReportEnhanced';
import WebCheckDetails from './WebCheckDetails';
import '../styles/AuthenticatedScan.scss';
import '../styles/HeroReport.scss';
import '../styles/ScoreCards.scss';

// Loading placeholder for progressive loading (same as Hero.jsx)
const LoadingPlaceholder = ({ height = '1.5rem', width = '100%', style = {} }) => (
  <div
    className="loading-placeholder"
    style={{ height, width, minHeight: height, ...style }}
  />
);

const API_BASE = 'http://localhost:3001';

const STEPS = [
  { id: 1, label: 'Configure' },
  { id: 2, label: 'Credentials' },
  { id: 3, label: 'Verify' },
  { id: 4, label: 'Scanning' },
  { id: 5, label: 'Results' }
];

const AuthenticatedScanPanel = () => {
  const navigate = useNavigate();
  const { currentLang, setHasReport } = useTranslation();
  const { theme } = useTheme();

  // Wizard state
  const [step, setStep] = useState(1);
  const [pendingSchedule, setPendingSchedule] = useState(null);

  // Step 1: URL configuration
  const [targetUrl, setTargetUrl] = useState('');
  const [loginUrl, setLoginUrl] = useState('');

  // Step 1-2: Detection
  const [detecting, setDetecting] = useState(false);
  const [detectedFields, setDetectedFields] = useState(null);
  const [detectionError, setDetectionError] = useState(null);

  // Step 2: Dynamic credentials
  const [selectedFields, setSelectedFields] = useState([]); // Array of selected field objects
  const [credentials, setCredentials] = useState({}); // Map: { [selector]: value }
  const [showPasswords, setShowPasswords] = useState({}); // Map: { [selector]: boolean }
  const [selectedSubmitButton, setSelectedSubmitButton] = useState(null);

  // Step 2-3: Login test
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [tempSessionId, setTempSessionId] = useState(null);

  // Step 4: Scan
  const [scanId, setScanId] = useState(null);
  const [scanPhase, setScanPhase] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanning, setScanning] = useState(false);

  // Progressive scan data (all scanners)
  const [report, setReport] = useState(null);

  // Translation state (same as Hero.jsx)
  const [translatedReport, setTranslatedReport] = useState(null);
  const [isTranslatingReport, setIsTranslatingReport] = useState(false);

  // PDF download state
  const [pdfDownloading, setPdfDownloading] = useState(false);
  const [pdfProgress, setPdfProgress] = useState(0);
  const [pdfProgressMessage, setPdfProgressMessage] = useState('');
  const [pdfDropdownOpen, setPdfDropdownOpen] = useState(false);

  // General UI
  const [error, setError] = useState(null);

  // Polling refs
  const pollingIntervalRef = useRef(null);
  const isPollingRef = useRef(false);

  // Get headers with auth token
  const getHeaders = () => {
    const token = localStorage.getItem('token');
    return {
      'Content-Type': 'application/json',
      'x-auth-token': token
    };
  };

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
    };
  }, []);

  // Close PDF dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (pdfDropdownOpen && !e.target.closest('.pdf-dropdown-container')) {
        setPdfDropdownOpen(false);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [pdfDropdownOpen]);

  // Resume scan on page refresh (like normal scan)
  useEffect(() => {
    const resumeScan = () => {
      const persisted = localStorage.getItem('activeAuthScan');
      if (!persisted) return;

      try {
        const { scanId: savedScanId, url } = JSON.parse(persisted);
        if (!savedScanId) return;

        console.log('[AUTH] Resuming scan from localStorage:', savedScanId);
        setScanId(savedScanId);
        setTargetUrl(url || '');
        setStep(4);
        setScanning(true);
        startPolling(savedScanId);
      } catch (e) {
        localStorage.removeItem('activeAuthScan');
      }
    };

    resumeScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Notify TranslationContext when report is available
  useEffect(() => {
    if (report?.refinedReport) {
      setHasReport(true);
    }
    return () => setHasReport(false);
  }, [report?.refinedReport, setHasReport]);

  // Check for pending schedule on mount
  useEffect(() => {
    const pendingJson = sessionStorage.getItem('pendingScheduleConfig');
    if (pendingJson) {
      try {
        const parsed = JSON.parse(pendingJson);
        if (parsed.scanType === 'authenticated') {
          setPendingSchedule(parsed);
        }
      } catch (err) {
        console.error('Failed to parse pending schedule config', err);
      }
    }
  }, []);

  // Auto-translate AI report when language changes to Japanese (same as Hero.jsx)
  useEffect(() => {
    const translateReport = async () => {
      const refinedReport = report?.refinedReport;
      if (!refinedReport) return;
      if (currentLang !== 'ja') return;
      if (translatedReport) return; // Already cached

      setIsTranslatingReport(true);
      try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${API_BASE}/api/translate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-auth-token': token
          },
          body: JSON.stringify({ texts: [refinedReport], targetLang: 'ja' })
        });

        if (response.ok) {
          const data = await response.json();
          setTranslatedReport(data.translated[0]);
        }
      } catch (err) {
        console.error('Translation failed:', err);
      } finally {
        setIsTranslatingReport(false);
      }
    };

    translateReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report?.refinedReport, currentLang]);

  // ========== Step 1: Detect Login Fields ==========
  const handleDetectFields = async () => {
    if (!loginUrl) return;

    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    setDetecting(true);
    setDetectionError(null);
    setDetectedFields(null);

    try {
      const res = await fetch(`${API_BASE}/api/zap-auth/detect-login-fields`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ loginUrl })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Detection failed');
      }

      if (!data.success) {
        setDetectionError(data.error || 'Could not analyze the login page');
        return;
      }

      // Prefer the form that has a password field (language-agnostic: type="password" is universal)
      // Only reorders when forms[0] lacks a password field (e.g. search bar before login form)
      // If forms[0] already has password field (all normal cases), this is a no-op
      if (data.forms && data.forms.length > 1) {
        const passwordFormIndex = data.forms.findIndex(f => f.passwordField);
        if (passwordFormIndex > 0) {
          const promoted = data.forms[passwordFormIndex];
          data.forms = [promoted, ...data.forms.filter((_, i) => i !== passwordFormIndex)];
        }
      }

      setDetectedFields(data);

      // Auto-select fields from first form
      if (data.forms && data.forms.length > 0) {
        const form = data.forms[0];

        // Auto-select input fields (not buttons)
        const inputFields = form.fields.filter(f =>
          f.tagName === 'INPUT' &&
          f.inputType !== 'submit' &&
          f.inputType !== 'button'
        );

        setSelectedFields(inputFields);

        // Initialize credentials object
        const initialCreds = {};
        inputFields.forEach(field => {
          initialCreds[field.selector] = '';
        });
        setCredentials(initialCreds);

        // Auto-select submit button
        if (form.submitButton) {
          setSelectedSubmitButton(form.submitButton);
        }

        setStep(2);
      } else {
        setDetectionError('No login forms detected on this page.');
      }
    } catch (err) {
      setDetectionError(err.message);
    } finally {
      setDetecting(false);
    }
  };

  // Handle field selection toggle
  const handleFieldToggle = (field) => {
    const isSelected = selectedFields.some(f => f.selector === field.selector);

    if (isSelected) {
      // Remove field
      setSelectedFields(selectedFields.filter(f => f.selector !== field.selector));
      const newCreds = { ...credentials };
      delete newCreds[field.selector];
      setCredentials(newCreds);
    } else {
      // Add field
      setSelectedFields([...selectedFields, field]);
      setCredentials({ ...credentials, [field.selector]: '' });
    }
  };

  // Update credential value
  const handleCredentialChange = (selector, value) => {
    setCredentials({ ...credentials, [selector]: value });
  };

  // Toggle password visibility for a field
  const togglePasswordVisibility = (selector) => {
    setShowPasswords({ ...showPasswords, [selector]: !showPasswords[selector] });
  };

  // ========== Step 2: Test Login ==========
  const handleTestLogin = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    // Check if all selected fields have values
    const hasEmptyFields = selectedFields.some(field => !credentials[field.selector]);
    if (hasEmptyFields) {
      setError('Please fill in all credential fields');
      return;
    }

    setTesting(true);
    setTestResult(null);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/api/zap-auth/test-login`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          loginUrl,
          credentials: selectedFields.map(field => ({
            selector: field.selector,
            value: credentials[field.selector],
            inputType: field.inputType
          })),
          submitButton: selectedSubmitButton
        })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Login test failed');
      }

      setTestResult(data);

      if (data.authenticated && data.tempSessionId) {
        setTempSessionId(data.tempSessionId);
        // Clear sensitive credentials from state
        const clearedCreds = {};
        Object.keys(credentials).forEach(key => {
          clearedCreds[key] = '';
        });
        setCredentials(clearedCreds);
        setStep(3);
      }
    } catch (err) {
      setTestResult({ authenticated: false, errorMessage: err.message });
    } finally {
      setTesting(false);
    }
  };

  // ========== Step 3: Start Scan ==========
  const submitSchedule = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    setScanning(true);
    setError(null);

    const authConfigObj = {
      loginUrl,
      credentials: selectedFields.map(field => ({
        selector: field.selector,
        value: credentials[field.selector],
        inputType: field.inputType
      })),
      submitButton: selectedSubmitButton
    };

    try {
      const res = await fetch(`${API_BASE}/api/schedules`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          scanType: 'authenticated',
          targetUrl: targetUrl,
          scheduleType: pendingSchedule.scheduleType || (pendingSchedule.recurring ? 'recurring' : 'one-time'),
          scheduledAt: pendingSchedule.scheduledAt,
          recurring: pendingSchedule.recurring,
          timezone: pendingSchedule.timezone || 'Asia/Kolkata',
          authConfig: authConfigObj
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create schedule');

      sessionStorage.removeItem('pendingScheduleConfig');
      setPendingSchedule(null);
      alert('Authenticated Schedule created successfully!');
      navigate('/schedules');
    } catch (err) {
      setError(err.message);
      setScanning(false);
    }
  };

  const handleStartScan = async () => {
    if (pendingSchedule) {
      return submitSchedule();
    }

    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    if (!tempSessionId) {
      setError('Session expired. Please test login again.');
      return;
    }

    setError(null);
    setScanning(true);

    try {
      const res = await fetch(`${API_BASE}/api/zap-auth/scan`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          targetUrl,
          loginUrl,
          tempSessionId
        })
      });

      const data = await res.json();

      if (!res.ok) {
        if (data.code === 'SESSION_EXPIRED') {
          setError('Session expired. Please test login again.');
          setStep(2);
          setScanning(false);
          return;
        }
        throw new Error(data.error || 'Failed to start scan');
      }

      setScanId(data.scanId);
      setStep(4);

      // Persist scan to localStorage for resume on page refresh
      localStorage.setItem('activeAuthScan', JSON.stringify({
        scanId: data.scanId,
        url: targetUrl,
        timestamp: Date.now()
      }));

      // Start polling for progress
      startPolling(data.scanId);
    } catch (err) {
      setError(err.message);
      setScanning(false);
    }
  };

  // ========== Step 4: Poll Scan Status ==========
  const startPolling = useCallback((scanId) => {
    if (isPollingRef.current) return;

    isPollingRef.current = true;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/zap-auth/status/${scanId}`, {
          headers: getHeaders()
        });

        if (!res.ok) {
          throw new Error('Failed to get scan status');
        }

        const data = await res.json();

        setScanPhase(data.phase || '');
        setScanProgress(data.progress || 0);

        // Progressive loading: update report with all scan data
        setReport(prevReport => ({
          ...prevReport,
          ...data,
          isPartial: data.status !== 'completed'
        }));

        if (data.status === 'completed') {
          clearInterval(pollingIntervalRef.current);
          isPollingRef.current = false;
          localStorage.removeItem('activeAuthScan');
          setScanning(false);
          setStep(5);
        } else if (data.status === 'failed') {
          clearInterval(pollingIntervalRef.current);
          isPollingRef.current = false;
          localStorage.removeItem('activeAuthScan');
          setError(data.error || 'Scan failed');
          setScanning(false);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    };

    // Poll immediately then every 3 seconds
    poll();
    pollingIntervalRef.current = setInterval(poll, 3000);
  }, []);

  // ========== Stop Scan ==========
  const handleStopScan = async () => {
    if (!scanId) return;

    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    try {
      await fetch(`${API_BASE}/api/zap-auth/stop/${scanId}`, {
        method: 'POST',
        headers: getHeaders()
      });

      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      isPollingRef.current = false;

      localStorage.removeItem('activeAuthScan');
      setError('Scan stopped by user');
      setScanning(false);
    } catch (err) {
      console.error('Failed to stop scan:', err);
    }
  };

  // ========== New Scan ==========
  const handleNewScan = () => {
    // Reset all state
    setStep(1);
    setTargetUrl('');
    setLoginUrl('');
    setDetectedFields(null);
    setDetectionError(null);
    setSelectedFields([]);
    setCredentials({});
    setShowPasswords({});
    setSelectedSubmitButton(null);
    setTestResult(null);
    setTempSessionId(null);
    setScanId(null);
    setScanPhase('');
    setScanProgress(0);
    setScanning(false);
    setReport(null);
    setError(null);

    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
    }
    isPollingRef.current = false;
  };

  // Get field label for display
  const getFieldLabel = (field) => {
    if (field.label) return field.label;
    if (field.placeholder) return field.placeholder;
    if (field.name) return field.name;
    if (field.id) return field.id;
    return field.inputType || 'Field';
  };

  // Render field selector helper
  const renderFieldSelector = (label, options, selected, onChange) => {
    if (!options || options.length === 0) return null;

    return (
      <div className="field-selector">
        <label>{label}</label>
        <select value={selected || ''} onChange={(e) => onChange(e.target.value)}>
          <option value="">-- Select {label} --</option>
          {options.map((field, idx) => (
            <option key={idx} value={field.selector}>
              {getFieldLabel(field)} [{field.inputType || field.tagName.toLowerCase()}]
            </option>
          ))}
        </select>
      </div>
    );
  };

  return (
    <div className="auth-scan-panel">
      <div className="panel-content">
        {/* Security Disclaimer */}
        <div className="security-disclaimer">
          🔒 Your credentials are never stored and are handled securely in-memory during the scan
        </div>

        {/* Step Indicators */}
        <div className="step-indicators">
          {STEPS.map((s, idx) => (
            <div
              key={s.id}
              className={`step-indicator ${s.id <= step ? 'active' : ''} ${s.id === step ? 'current' : ''}`}
            >
              <div className="step-circle">{s.id}</div>
              <div className="step-label">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Error Banner */}
        {error && (
          <div className="error-banner">
            <span>{error}</span>
            <button className="dismiss-btn" onClick={() => setError(null)}>
              Dismiss
            </button>
          </div>
        )}

        {pendingSchedule && (
          <div className="scheduling-mode-banner" style={{ background: 'rgba(0, 176, 198, 0.1)', border: '1px solid var(--accent)', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', textAlign: 'center', color: 'var(--accent)' }}>
            <strong>Scheduling Mode Active</strong><br/>
            Setting up an authenticated scan for {pendingSchedule.date} at {pendingSchedule.time}
          </div>
        )}

        {/* Step 1: Configure URLs */}
        {step === 1 && (
          <div className="step-content">
            <h2>Configure Scan</h2>
            <p className="step-description">
              Enter the target URL to scan and the login page URL
            </p>

            <div className="form-group">
              <label htmlFor="targetUrl">Target URL</label>
              <input
                id="targetUrl"
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className="url-input"
              />
              <span className="help-text">The main URL you want to scan for vulnerabilities</span>
            </div>

            <div className="form-group">
              <label htmlFor="loginUrl">Login Page URL</label>
              <input
                id="loginUrl"
                type="text"
                value={loginUrl}
                onChange={(e) => setLoginUrl(e.target.value)}
                placeholder="https://example.com/login"
                className="url-input"
              />
              <span className="help-text">The URL of the login page (can be the same as target URL)</span>
            </div>

            <div className="step-actions">
              <button
                className="primary-btn"
                onClick={handleDetectFields}
                disabled={!targetUrl || !loginUrl || detecting}
              >
                {detecting && <span className="spinner" />}
                <span>{detecting ? 'Detecting Fields...' : 'Detect Login Fields'}</span>
              </button>
            </div>

            {detectionError && (
              <div className="detection-error">
                <strong>Detection Error:</strong> {detectionError}
              </div>
            )}
          </div>
        )}

        {/* Step 2: Enter Credentials */}
        {step === 2 && detectedFields && (
          <div className="step-content">
            <h2>Enter Credentials</h2>
            <p className="step-description">
              Select the login fields and enter your credentials
            </p>

            {/* Detection Summary */}
            <div className="detection-summary">
              <h3>Detected Login Form</h3>
              <p className="page-title">Page: {detectedFields.pageTitle}</p>

              {/* Warnings */}
              {detectedFields.warnings && detectedFields.warnings.length > 0 && (
                <div className="warnings">
                  {detectedFields.warnings.map((warning, idx) => (
                    <div key={idx} className="warning-item">
                      ⚠️ {warning}
                    </div>
                  ))}
                </div>
              )}

              {/* Field Selection */}
              {detectedFields.forms && detectedFields.forms[0] && (
                <div className="field-selection">
                  <h4>Available Fields:</h4>
                  {detectedFields.forms[0].fields
                    .filter(f => f.tagName === 'INPUT' && f.inputType !== 'submit' && f.inputType !== 'button')
                    .map((field, idx) => (
                      <label key={idx} className="field-checkbox">
                        <input
                          type="checkbox"
                          checked={selectedFields.some(f => f.selector === field.selector)}
                          onChange={() => handleFieldToggle(field)}
                        />
                        <span className="field-label">
                          {getFieldLabel(field)}
                          <span className="field-type"> [{field.inputType}]</span>
                        </span>
                      </label>
                    ))}
                </div>
              )}

              {/* Submit Button Selector */}
              {detectedFields.forms && detectedFields.forms[0] && (
                <div className="field-selectors">
                  {renderFieldSelector(
                    'Submit Button',
                    detectedFields.forms[0].fields.filter(f =>
                      f.tagName === 'BUTTON' || f.inputType === 'submit'
                    ),
                    selectedSubmitButton,
                    setSelectedSubmitButton
                  )}
                  <div className="submit-button-hint">
                    💡 <strong>Tip:</strong> If login fails, try selecting a different submit button from the dropdown above and test again.
                  </div>
                </div>
              )}
            </div>

            {/* Dynamic Credential Inputs */}
            <div className="credential-inputs">
              {selectedFields.map((field, idx) => (
                <div key={idx} className="form-group">
                  <label htmlFor={`cred-${idx}`}>
                    {getFieldLabel(field)}
                  </label>

                  {field.inputType === 'password' ? (
                    <div className="password-wrapper">
                      <input
                        id={`cred-${idx}`}
                        type={showPasswords[field.selector] ? 'text' : 'password'}
                        value={credentials[field.selector] || ''}
                        onChange={(e) => handleCredentialChange(field.selector, e.target.value)}
                        placeholder={`Enter ${getFieldLabel(field)}`}
                        className="url-input"
                        autoComplete="off"
                      />
                      <button
                        type="button"
                        className="toggle-password"
                        onClick={() => togglePasswordVisibility(field.selector)}
                      >
                        {showPasswords[field.selector] ? 'Hide' : 'Show'}
                      </button>
                    </div>
                  ) : (
                    <input
                      id={`cred-${idx}`}
                      type="text"
                      value={credentials[field.selector] || ''}
                      onChange={(e) => handleCredentialChange(field.selector, e.target.value)}
                      placeholder={`Enter ${getFieldLabel(field)}`}
                      className="url-input"
                      autoComplete="off"
                    />
                  )}
                </div>
              ))}
            </div>

            <div className="step-actions">
              <button className="secondary-btn" onClick={() => setStep(1)}>
                Back
              </button>
              <button
                className="primary-btn"
                onClick={handleTestLogin}
                disabled={testing || selectedFields.length === 0}
              >
                {testing && <span className="spinner" />}
                <span>{testing ? 'Testing Login...' : 'Test Login'}</span>
              </button>
            </div>

            {/* Test Result */}
            {testResult && (
              <div className={`test-result ${testResult.authenticated ? 'test-success' : 'test-fail'}`}>
                {testResult.authenticated ? (
                  <>
                    <strong>✅ Login Successful!</strong>
                    <p>Credentials verified. Session cookies captured.</p>
                    {testResult.postLoginUrl && (
                      <p>
                        Redirected to: <span className="post-login-url">{testResult.postLoginUrl}</span>
                      </p>
                    )}
                  </>
                ) : (
                  <>
                    <strong>❌ Login Failed</strong>
                    <p>{testResult.errorMessage || 'Could not authenticate with provided credentials'}</p>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {/* Step 3: Verify & Start Scan */}
        {step === 3 && (
          <div className="step-content">
            <h2>Verify Configuration</h2>
            <p className="step-description">
              Review your configuration and start the authenticated security scan
            </p>

            {/* Test Result */}
            {testResult && testResult.authenticated && (
              <div className="test-result test-success">
                <strong>✅ Authentication Verified</strong>
                <p>Ready to start authenticated security scan</p>
              </div>
            )}

            {/* Scan Summary */}
            <div className="scan-summary">
              <div className="summary-item">
                <span className="summary-label">Target:</span>
                <span className="summary-value">{targetUrl}</span>
              </div>
              <div className="summary-item">
                <span className="summary-label">Login URL:</span>
                <span className="summary-value">{loginUrl}</span>
              </div>
              <div className="summary-item">
                <span className="summary-label">Fields:</span>
                <span className="summary-value">{selectedFields.length} credential field(s)</span>
              </div>
            </div>

            <div className="step-actions">
              <button className="secondary-btn" onClick={() => setStep(2)}>
                Back
              </button>
              <button
                className="primary-btn start-scan-btn"
                onClick={handleStartScan}
                disabled={scanning}
              >
                {scanning && <span className="spinner" />}
                <span>{pendingSchedule ? "Save Scheduled Scan" : "Start Authenticated Scan"}</span>
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Scanning  +  Step 5: Results — unified progressive view */}
        {(step === 4 || step === 5) && (
          <div className="step-content">
            <h2>{step === 5 ? 'Scan Complete' : 'Scanning in Progress'}</h2>
            <p className="step-description">
              {step === 5
                ? 'Security scan completed. Review the findings below.'
                : 'Running all security scanners on the authenticated website'}
            </p>

            {/* Progress Bar (only during scanning) */}
            {step === 4 && (
              <div className="scan-progress-section">
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${scanProgress}%` }} />
                </div>
                <div className="progress-info">
                  <span className="progress-percent">{scanProgress}%</span>
                  <span className="progress-phase">
                    {(() => {
                      if (!report?.hasPsiResult || !report?.hasObservatoryResult) return 'Fetching PageSpeed & Observatory...';
                      if (report?.zapPending) return `ZAP Auth Scan: ${scanPhase} (${scanProgress}%)...`;
                      if (!report?.hasZapResult) return 'Running authenticated ZAP scan...';
                      if (!report?.hasRefinedReport) return 'Generating AI report...';
                      return 'Finalizing...';
                    })()}
                  </span>
                </div>
              </div>
            )}

            {/* AI Report Section */}
            <div className="ai-report-section" style={{
              background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)',
              padding: '1.5rem',
              marginBottom: '2rem',
              borderRadius: '8px',
              border: '2px solid var(--accent)',
              lineHeight: '1.6',
              fontSize: '0.95rem'
            }}>
              <h4 style={{ marginTop: 0, color: 'var(--accent)' }}>AI-Generated Analysis Summary</h4>
              {report?.refinedReport ? (
                isTranslatingReport ? (
                  <div style={{ textAlign: 'center', padding: '1rem' }}>
                    <p style={{ color: 'var(--accent)' }}>Translating report to Japanese...</p>
                  </div>
                ) : (
                  <ReactMarkdown>
                    {currentLang === 'ja' && translatedReport ? translatedReport : report.refinedReport}
                  </ReactMarkdown>
                )
              ) : (
                <div className="loading-pulse">
                  <LoadingPlaceholder height="1rem" style={{ marginBottom: '0.5rem' }} />
                  <LoadingPlaceholder height="1rem" width="95%" style={{ marginBottom: '0.5rem' }} />
                  <LoadingPlaceholder height="1rem" width="88%" style={{ marginBottom: '0.5rem' }} />
                  <LoadingPlaceholder height="1rem" width="92%" style={{ marginBottom: '0.5rem' }} />
                  <LoadingPlaceholder height="1rem" width="75%" style={{ marginBottom: '0.5rem' }} />
                  <p style={{ color: 'var(--accent)', marginTop: '1rem', textAlign: 'center' }}>
                    Generating AI analysis... (waiting for all scan data)
                  </p>
                </div>
              )}
            </div>

            {/* Score Cards Grid — matches Hero.jsx exactly */}
            {(() => {
              // Helper functions (same as Hero.jsx)
              const getScoreClass = (score) => score >= 90 ? 'score-good' : score >= 50 ? 'score-medium' : 'score-poor';
              const getObservatoryGradeColor = (grade) => {
                if (!grade) return '#888';
                const map = { 'A': '#00d084', 'B': '#7fba00', 'C': '#ffb900', 'D': '#ff8c00', 'F': '#e81123' };
                return map[grade[0]] || '#888';
              };

              // Observatory
              const observatoryData = report?.observatoryData || null;

              // ZAP data
              const backendZapData = report?.zapData;
              let zapRiskLabel = 'Passed'; let zapRiskColor = '#00d084'; let zapPendingMessage = null;
              if (backendZapData) {
                if (backendZapData.status === 'pending' || backendZapData.status === 'running') {
                  zapRiskLabel = 'Scanning...'; zapRiskColor = '#ffb900';
                  zapPendingMessage = `${backendZapData.phase || 'starting'}: ${backendZapData.progress || 0}%`;
                } else if (backendZapData.status === 'completed' && backendZapData.riskCounts) {
                  if (backendZapData.riskCounts.High > 0) { zapRiskLabel = 'High Risk'; zapRiskColor = '#e81123'; }
                  else if (backendZapData.riskCounts.Medium > 0) { zapRiskLabel = 'Medium Risk'; zapRiskColor = '#ff8c00'; }
                  else if (backendZapData.riskCounts.Low > 0) { zapRiskLabel = 'Low Risk'; zapRiskColor = '#ffb900'; }
                } else if (backendZapData.status === 'failed') {
                  zapRiskLabel = 'Failed'; zapRiskColor = '#e81123';
                  zapPendingMessage = backendZapData.message || 'Scan failed';
                }
              }

              // WebCheck data
              const backendWebCheckData = report?.webCheckData;
              const webCheckCompleted = backendWebCheckData?.status === 'completed' ||
                                        backendWebCheckData?.status === 'completed_with_errors' ||
                                        backendWebCheckData?.status === 'completed_partial';
              const webCheckReport = webCheckCompleted
                ? backendWebCheckData.results
                : (backendWebCheckData?.partialResults || {});
              const webCheckLoading = backendWebCheckData?.status === 'running' || backendWebCheckData?.status === 'uploading';
              const webCheckUploading = backendWebCheckData?.status === 'uploading';
              const webCheckUploadProgress = backendWebCheckData?.uploadProgress || 0;
              const webCheckError = backendWebCheckData?.status === 'failed';

              // PSI
              const psiScores = report?.psiScores || {};

              return (
                <>
                  <h3 className="report-title">Combined Scan Report {report?.target ? `for ${report.target}` : ''}</h3>

                  <div className="score-cards-grid">
                    {/* OWASP ZAP (Authenticated) */}
                    <div className="score-card">
                      <h4 className="score-card__title">OWASP ZAP (Auth)</h4>
                      {backendZapData ? (
                        <>
                          <span className="score-card__value" style={{ color: zapRiskColor }}>{zapRiskLabel}</span>
                          {zapPendingMessage ? (
                            <p className="score-card__label" style={{ color: '#ffb900' }}>{zapPendingMessage}</p>
                          ) : backendZapData.status === 'completed' ? (
                            <p className="score-card__label">{backendZapData.alerts ? backendZapData.alerts.length : 0} Alerts</p>
                          ) : backendZapData.status === 'completed_partial' ? (
                            <p className="score-card__label" style={{ color: '#ffb900' }}>{backendZapData.alerts ? backendZapData.alerts.length : 0} Alerts (Partial)</p>
                          ) : null}
                        </>
                      ) : report?.zapResult?.error || (report?.status === 'completed' && !report?.hasZapResult) ? (
                        <div style={{ color: '#ffb900', marginTop: '10px' }}>Unavailable</div>
                      ) : (
                        <div className="score-card__loading loading-pulse">
                          <LoadingPlaceholder height="1.5rem" width="60%" style={{ marginBottom: '0.5rem' }} />
                          <LoadingPlaceholder height="0.85rem" width="40%" />
                        </div>
                      )}
                    </div>

                    {/* Performance (PSI) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Performance</h4>
                      {psiScores?.performance != null ? (
                        <>
                          <span className={`score-card__value ${getScoreClass(psiScores.performance)}`}>{psiScores.performance}</span>
                          <p className="score-card__label">out of 100</p>
                        </>
                      ) : (
                        <div className="score-card__loading loading-pulse">
                          <LoadingPlaceholder height="1.5rem" width="50%" style={{ marginBottom: '0.5rem' }} />
                          <LoadingPlaceholder height="0.85rem" width="40%" />
                        </div>
                      )}
                    </div>

                    {/* Security Config (Observatory) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Security Config</h4>
                      {observatoryData?.grade ? (
                        <>
                          <span className="score-card__value" style={{ color: getObservatoryGradeColor(observatoryData.grade) }}>{observatoryData.grade}</span>
                          <p className="score-card__label">Mozilla Observatory</p>
                        </>
                      ) : (
                        <div className="score-card__loading loading-pulse">
                          <LoadingPlaceholder height="1.5rem" width="40%" style={{ marginBottom: '0.5rem' }} />
                          <LoadingPlaceholder height="0.85rem" width="60%" />
                        </div>
                      )}
                    </div>

                    {/* URLScan.io */}
                    <div className="score-card">
                      <h4 className="score-card__title">URLScan.io</h4>
                      {report?.hasUrlscanResult && report?.urlscanData ? (
                        <>
                          <span className="score-card__value" style={{ color: report.urlscanData.verdicts?.overall?.malicious ? '#e81123' : '#00d084' }}>
                            {report.urlscanData.verdicts?.overall?.malicious ? 'Malicious' : 'Clean'}
                          </span>
                          <p className="score-card__label">{report.urlscanData.verdicts?.overall?.score || 0} threat score</p>
                        </>
                      ) : report?.urlscanResult?.error || (report?.status === 'completed' && !report?.hasUrlscanResult) ? (
                        <div style={{ color: '#ffb900', marginTop: '10px' }}>Unavailable</div>
                      ) : (
                        <div className="score-card__loading loading-pulse">
                          <LoadingPlaceholder height="1.5rem" width="50%" style={{ marginBottom: '0.5rem' }} />
                          <LoadingPlaceholder height="0.85rem" width="40%" />
                        </div>
                      )}
                    </div>

                    {/* SSL Certificate (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">SSL Certificate</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.ssl && !webCheckReport.ssl.error ? (
                        <>
                          <span className="score-card__value score-card__value--safe">Valid</span>
                          <p className="score-card__label">{webCheckReport.ssl.issuer?.O || 'Unknown Issuer'}</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{webCheckError ? 'Failed' : 'Pending'}</div>
                      )}
                    </div>

                    {/* Security Headers (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Security Headers</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['http-security'] && !webCheckReport['http-security'].error ? (
                        <>
                          {(() => {
                            const sec = webCheckReport['http-security'];
                            const passed = [sec.strictTransportPolicy, sec.xFrameOptions, sec.xContentTypeOptions, sec.xXSSProtection, sec.contentSecurityPolicy].filter(Boolean).length;
                            const color = passed >= 4 ? '#00d084' : passed >= 2 ? '#ffb900' : '#e81123';
                            return <span className="score-card__value" style={{ color }}>{passed}/5</span>;
                          })()}
                          <p className="score-card__label">Headers Present</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Tech Stack (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Tech Stack</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : (() => {
                        const techData = webCheckReport?.['tech-stack'];
                        const techArray = techData?.technologies || (Array.isArray(techData) ? techData : null) || (techData && !techData.error && typeof techData === 'object' ? Object.keys(techData) : null);
                        if (techArray && techArray.length > 0) {
                          return (<><span className="score-card__value score-card__value--safe">{techArray.length}</span><p className="score-card__label">Technologies Detected</p></>);
                        } else if (techData && !techData.error) {
                          return <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>No technologies detected</div>;
                        } else {
                          return <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{techData?.error ? 'Scan Failed' : 'Pending'}</div>;
                        }
                      })()}
                    </div>

                    {/* Firewall/WAF (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Firewall</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.firewall && !webCheckReport.firewall.error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport.firewall.hasWaf ? 'safe' : 'medium'}`}>
                            {webCheckReport.firewall.hasWaf ? webCheckReport.firewall.waf : 'None Detected'}
                          </span>
                          <p className="score-card__label">WAF Status</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* TLS Grade (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">TLS Grade</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.tls && !webCheckReport.tls.error ? (
                        <>
                          <span className="score-card__value" style={{ color: getObservatoryGradeColor(webCheckReport.tls.tlsInfo?.grade) }}>
                            {webCheckReport.tls.tlsInfo?.grade || 'N/A'}
                          </span>
                          <p className="score-card__label">Score: {webCheckReport.tls.tlsInfo?.score || 0}/100</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Quality (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Quality</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.quality && !webCheckReport.quality.error ? (
                        (() => {
                          const perfScore = Math.round((webCheckReport.quality.lighthouseResult?.categories?.performance?.score || 0) * 100);
                          return (<><span className={`score-card__value score-card__value--${perfScore >= 90 ? 'safe' : perfScore >= 50 ? 'medium' : 'high'}`}>{perfScore}</span><p className="score-card__label">Lighthouse Score</p></>);
                        })()
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Mail Config (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Mail Config</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['mail-config'] && !webCheckReport['mail-config'].error && !webCheckReport['mail-config'].skipped ? (
                        <>
                          <span className="score-card__value score-card__value--safe">{webCheckReport['mail-config'].mxRecords?.length || 0}</span>
                          <p className="score-card__label">MX Records Found</p>
                        </>
                      ) : webCheckReport?.['mail-config']?.skipped ? (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>No Mail Server</div>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* WHOIS (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">WHOIS</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.whois && !webCheckReport.whois.error ? (
                        <>
                          <span className="score-card__value score-card__value--safe" style={{ fontSize: '0.9rem' }}>{webCheckReport.whois.registrar?.substring(0, 20) || 'Found'}</span>
                          <p className="score-card__label">Domain Registered</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* HSTS (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">HSTS</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.hsts && !webCheckReport.hsts.error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport.hsts.hstsEnabled ? 'safe' : 'high'}`}>
                            {webCheckReport.hsts.hstsEnabled ? 'Enabled' : 'Disabled'}
                          </span>
                          <p className="score-card__label">{webCheckReport.hsts.hstsPreloaded ? 'Preloaded' : 'Not Preloaded'}</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Block Lists (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Block Lists</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['block-lists'] && !webCheckReport['block-lists'].error ? (
                        (() => {
                          const blocklists = webCheckReport['block-lists'].blocklists || [];
                          const blockedCount = blocklists.filter(b => b.isBlocked).length;
                          return (<><span className={`score-card__value score-card__value--${blockedCount === 0 ? 'safe' : 'high'}`}>{blockedCount === 0 ? 'Clean' : `${blockedCount} Found`}</span><p className="score-card__label">{blocklists.length} Lists Checked</p></>);
                        })()
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Carbon (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Carbon</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.carbon && !webCheckReport.carbon.error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport.carbon.isGreen ? 'safe' : 'medium'}`}>{webCheckReport.carbon.isGreen ? 'Green' : 'Standard'}</span>
                          <p className="score-card__label">{webCheckReport.carbon.co2?.grid?.grams ? `${webCheckReport.carbon.co2.grid.grams.toFixed(2)}g CO2` : 'Hosting'}</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Archives (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Archives</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.archives?.skipped ? (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Not Archived</div>
                      ) : webCheckReport?.archives?.totalScans ? (
                        <><span className="score-card__value score-card__value--safe">{webCheckReport.archives.totalScans}</span><p className="score-card__label">Wayback Snapshots</p></>
                      ) : webCheckReport?.archives?.error ? (
                        <div className="score-card__label" style={{ color: '#ffb900', marginTop: '10px' }}>Timeout</div>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Sitemap (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Sitemap</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.sitemap?.skipped || webCheckReport?.sitemap?.error ? (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Not Found</div>
                      ) : webCheckReport?.sitemap?.urlset ? (
                        <><span className="score-card__value score-card__value--safe">{webCheckReport.sitemap.urlset?.url?.length || 'Found'}</span><p className="score-card__label">URLs in Sitemap</p></>
                      ) : webCheckReport?.sitemap ? (
                        <div className="score-card__value score-card__value--safe" style={{ fontSize: '1.2rem' }}>Found</div>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Social Tags (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Social Tags</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['social-tags'] && !webCheckReport['social-tags'].error ? (
                        (() => {
                          const tags = webCheckReport['social-tags'];
                          const hasOg = tags.ogTitle || tags.openGraph?.title;
                          const hasTwitter = tags.twitterCard || tags.twitter?.card;
                          return (<><span className={`score-card__value score-card__value--${(hasOg || hasTwitter) ? 'safe' : 'medium'}`}>{(hasOg && hasTwitter) ? 'Complete' : (hasOg || hasTwitter) ? 'Partial' : 'Missing'}</span><p className="score-card__label">{hasOg ? 'OG' : ''}{hasOg && hasTwitter ? ' + ' : ''}{hasTwitter ? 'Twitter' : ''}</p></>);
                        })()
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Links (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Links</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['linked-pages'] && !webCheckReport['linked-pages'].error ? (
                        <><span className="score-card__value score-card__value--safe">{webCheckReport['linked-pages'].internal?.length || webCheckReport['linked-pages'].links?.length || 0}</span><p className="score-card__label">Links Found</p></>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Redirects (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Redirects</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.redirects && !webCheckReport.redirects.error ? (
                        <>
                          <span className={`score-card__value score-card__value--${(webCheckReport.redirects.redirects?.length || 0) <= 2 ? 'safe' : 'medium'}`}>{webCheckReport.redirects.redirects?.length || 0}</span>
                          <p className="score-card__label">Redirect Hops</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* DNS Server (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">DNS Server</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['dns-server'] && !webCheckReport['dns-server'].error ? (
                        <><span className="score-card__value score-card__value--safe" style={{ fontSize: '1.2rem' }}>{webCheckReport['dns-server'].dns?.length || 1}</span><p className="score-card__label">Servers Found</p></>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* DNSSEC (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">DNSSEC</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.dnssec && !webCheckReport.dnssec.error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport.dnssec.isValid || webCheckReport.dnssec.enabled ? 'safe' : 'medium'}`} style={{ fontSize: '1.2rem' }}>{webCheckReport.dnssec.isValid || webCheckReport.dnssec.enabled ? 'Valid' : 'Not Set'}</span>
                          <p className="score-card__label">DNSSEC Status</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Security.txt (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Security.txt</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['security-txt'] && !webCheckReport['security-txt'].error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport['security-txt'].isPresent || webCheckReport['security-txt'].found ? 'safe' : 'medium'}`} style={{ fontSize: '1.2rem' }}>{webCheckReport['security-txt'].isPresent || webCheckReport['security-txt'].found ? 'Found' : 'Missing'}</span>
                          <p className="score-card__label">Security Policy</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Robots.txt (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Robots.txt</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['robots-txt'] && !webCheckReport['robots-txt'].error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport['robots-txt'].exists || webCheckReport['robots-txt'].isPresent ? 'safe' : 'medium'}`} style={{ fontSize: '1.2rem' }}>{webCheckReport['robots-txt'].exists || webCheckReport['robots-txt'].isPresent ? 'Found' : 'Missing'}</span>
                          <p className="score-card__label">Crawler Rules</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Status (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Status</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.status && !webCheckReport.status.error ? (
                        <>
                          <span className={`score-card__value score-card__value--${webCheckReport.status.isUp || webCheckReport.status.statusCode === 200 ? 'safe' : 'high'}`}>{webCheckReport.status.statusCode || (webCheckReport.status.isUp ? '200' : 'Down')}</span>
                          <p className="score-card__label">{webCheckReport.status.responseTime ? `${webCheckReport.status.responseTime}ms` : 'HTTP Status'}</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>

                    {/* Rank (WebCheck) */}
                    <div className="score-card">
                      <h4 className="score-card__title">Rank</h4>
                      {webCheckLoading ? (
                        <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? `Uploading ${webCheckUploadProgress}%` : 'Scanning...'}</div>
                      ) : webCheckReport?.['legacy-rank'] && !webCheckReport['legacy-rank'].error ? (
                        <>
                          <span className="score-card__value score-card__value--safe" style={{ fontSize: '1rem' }}>#{webCheckReport['legacy-rank'].rank || webCheckReport['legacy-rank'].globalRank || 'N/A'}</span>
                          <p className="score-card__label">Global Rank</p>
                        </>
                      ) : (
                        <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>Pending</div>
                      )}
                    </div>
                  </div>

                  {/* Screenshot Preview */}
                  {(() => {
                    const webCheckScreenshot = webCheckReport?.screenshot?.image && !webCheckReport?.screenshot?.error
                      ? `data:image/png;base64,${webCheckReport.screenshot.image}` : null;
                    const urlscanScreenshot = report?.urlscanData?.screenshot || null;
                    const screenshotSrc = webCheckScreenshot || urlscanScreenshot;
                    const screenshotSource = webCheckScreenshot ? 'WebCheck' : (urlscanScreenshot ? 'URLScan.io' : null);
                    if (!screenshotSrc) return null;
                    return (
                      <div className="screenshot-preview">
                        <h4>Website Screenshot <span>({screenshotSource})</span></h4>
                        <img src={screenshotSrc} alt="Website Screenshot" />
                      </div>
                    );
                  })()}

                  {/* OWASP ZAP Enhanced Results */}
                  {backendZapData && backendZapData.status === 'completed' && backendZapData.alerts && (
                    <ZapReportEnhanced
                      zapData={backendZapData}
                      scanId={report?.scanId || report?.analysisId}
                      apiPrefix="/api/zap-auth"
                    />
                  )}

                  {/* ZAP Pending/Running Status */}
                  {backendZapData && (backendZapData.status === 'pending' || backendZapData.status === 'running') && (
                    <div className="zap-progress-card">
                      <h3>OWASP ZAP Authenticated Scan in Progress</h3>
                      <p className="zap-status">{backendZapData.phase || 'Scanning'}: {backendZapData.progress || 0}%</p>
                      <p className="zap-details">{backendZapData.message || 'Running comprehensive security tests...'}</p>
                      {backendZapData.urlsFound > 0 && (
                        <p className="zap-stats">Found {backendZapData.urlsFound} URLs - {backendZapData.alertsFound || 0} alerts so far</p>
                      )}
                      <p className="zap-details" style={{ marginTop: '1rem', fontSize: '0.8rem' }}>This page will automatically update when the scan completes.</p>
                    </div>
                  )}

                  {/* WebCheck Detailed Results */}
                  <WebCheckDetails webCheckReport={webCheckReport} theme={theme} />

                  {/* URLScan.io Detailed Results */}
                  {report?.hasUrlscanResult && report?.urlscanData && (
                    <details style={{ marginBottom: '2rem' }}>
                      <summary style={{ cursor: 'pointer', fontWeight: 'bold', padding: '1rem', background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', borderRadius: '8px', border: '1px solid #00d084' }}>
                        View URLScan.io Analysis
                      </summary>
                      <div style={{ marginTop: '1rem', display: 'grid', gap: '1rem' }}>
                        <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px' }}>
                          <h5 style={{ margin: '0 0 0.5rem 0', color: 'var(--accent)' }}>Security Verdict</h5>
                          <p><b>Overall:</b> <span style={{ color: report.urlscanData.verdicts?.overall?.malicious ? '#e81123' : '#00d084', fontWeight: 'bold' }}>{report.urlscanData.verdicts?.overall?.malicious ? 'MALICIOUS' : 'CLEAN'}</span></p>
                          <p><b>Threat Score:</b> {report.urlscanData.verdicts?.overall?.score || 0}</p>
                          {report.urlscanData.verdicts?.urlscan?.score > 0 && (<p><b>URLScan Score:</b> {report.urlscanData.verdicts.urlscan.score}</p>)}
                          {report.urlscanData.verdicts?.engines?.malicious > 0 && (<p><b>Engine Detections:</b> <span style={{ color: '#e81123' }}>{report.urlscanData.verdicts.engines.malicious} malicious</span></p>)}
                          {report.urlscanData.verdicts?.community?.score > 0 && (<p><b>Community Score:</b> {report.urlscanData.verdicts.community.score}</p>)}
                        </div>
                        {report.urlscanData.page && (
                          <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px' }}>
                            <h5 style={{ margin: '0 0 0.5rem 0', color: 'var(--accent)' }}>Page Information</h5>
                            <p><b>Domain:</b> {report.urlscanData.page.domain || 'N/A'}</p>
                            <p><b>IP Address:</b> {report.urlscanData.page.ip || 'N/A'}</p>
                            <p><b>Country:</b> {report.urlscanData.page.country || 'N/A'}</p>
                            <p><b>Server:</b> {report.urlscanData.page.server || 'N/A'}</p>
                            {report.urlscanData.page.tlsIssuer && (<p><b>TLS Issuer:</b> {report.urlscanData.page.tlsIssuer}</p>)}
                            {report.urlscanData.page.tlsValidDays && (<p><b>TLS Valid Days:</b> {report.urlscanData.page.tlsValidDays}</p>)}
                          </div>
                        )}
                        {report.urlscanData.stats && (
                          <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px' }}>
                            <h5 style={{ margin: '0 0 0.5rem 0', color: 'var(--accent)' }}>Network Statistics</h5>
                            <p><b>HTTP Requests:</b> {report.urlscanData.stats.requests || 0}</p>
                            <p><b>Unique IPs:</b> {report.urlscanData.stats.uniqIPs || 0}</p>
                            <p><b>Unique Countries:</b> {report.urlscanData.stats.uniqCountries || 0}</p>
                            <p><b>Data Transferred:</b> {report.urlscanData.stats.dataLength ? `${(report.urlscanData.stats.dataLength / 1024).toFixed(1)} KB` : 'N/A'}</p>
                          </div>
                        )}
                        {report.urlscanData.reportUrl && (
                          <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px', textAlign: 'center' }}>
                            <a href={report.urlscanData.reportUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'underline', fontWeight: 'bold', fontSize: '1rem' }}>View Full URLScan.io Report</a>
                          </div>
                        )}
                      </div>
                    </details>
                  )}

                  {/* Observatory Summary */}
                  {observatoryData ? (
                    <div className="report-summary" style={{ marginTop: '2rem' }}>
                      <h4>Mozilla Observatory Security Configuration</h4>
                      <p><b>Security Grade:</b> <span style={{ color: getObservatoryGradeColor(observatoryData.grade), fontWeight: 'bold', fontSize: '1.2rem' }}>{observatoryData.grade}</span></p>
                      <p><b>Score:</b> {observatoryData.score}/100</p>
                      <p><b>Tests Passed:</b> {observatoryData.tests_passed}/{observatoryData.tests_quantity}</p>
                      <p><b>Tests Failed:</b> {observatoryData.tests_failed}/{observatoryData.tests_quantity}</p>
                      <p><b>View Full Report:</b>{' '}<a href={`https://developer.mozilla.org/en-US/observatory/analyze?host=${report?.target ? encodeURIComponent(new URL(report.target).hostname) : ''}`} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'underline', fontWeight: 'bold' }}>Mozilla Observatory Report</a></p>
                    </div>
                  ) : (
                    <div className="report-summary" style={{ marginTop: '2rem', opacity: 0.7 }}>
                      <h4>Mozilla Observatory Security Configuration</h4>
                      <p style={{ color: '#888' }}><i>Observatory scan data not available for this URL.</i></p>
                      <p><b>Manual Scan:</b>{' '}<a href={`https://developer.mozilla.org/en-US/observatory/analyze?host=${report?.target ? encodeURIComponent(new URL(report.target).hostname) : ''}`} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'underline', fontWeight: 'bold' }}>Run Mozilla Observatory Scan</a></p>
                    </div>
                  )}

                  {/* Download Reports Section */}
                  {report?.analysisId && report?.status === 'completed' && (
                    <div className="download-section">
                      <h4>Download Scan Reports</h4>
                      <p>Download your complete security scan results in your preferred format</p>
                      <div className="download-buttons">
                        {/* PDF Download Dropdown */}
                        <div className="pdf-dropdown-container">
                          <button
                            className="download-btn download-btn--pdf"
                            disabled={pdfDownloading}
                            onClick={() => !pdfDownloading && setPdfDropdownOpen(!pdfDropdownOpen)}
                          >
                            {pdfDownloading ? 'Generating...' : 'Download PDF Report'}
                          </button>
                          {pdfDropdownOpen && !pdfDownloading && (
                            <div className="pdf-dropdown-menu">
                              <button
                                className="pdf-dropdown-item"
                                onClick={async () => {
                                  setPdfDropdownOpen(false);
                                  setPdfDownloading(true);
                                  setPdfProgress(0);
                                  setPdfProgressMessage('Initializing English PDF...');
                                  const progressSteps = [
                                    { progress: 15, message: 'Formatting scan data...' },
                                    { progress: 35, message: 'Waiting for API rate limit...' },
                                    { progress: 55, message: 'Formatting AI analysis...' },
                                    { progress: 80, message: 'Rendering PDF document...' },
                                    { progress: 95, message: 'Finalizing...' },
                                  ];
                                  let currentStep = 0;
                                  const progressInterval = setInterval(() => {
                                    if (currentStep < progressSteps.length) {
                                      setPdfProgress(progressSteps[currentStep].progress);
                                      setPdfProgressMessage(progressSteps[currentStep].message);
                                      currentStep++;
                                    }
                                  }, 6000);
                                  try {
                                    const token = localStorage.getItem('token');
                                    const response = await fetch(`${API_BASE}/api/vt/download-pdf/${report.analysisId}?lang=en`, {
                                      headers: { 'x-auth-token': token }
                                    });
                                    clearInterval(progressInterval);
                                    if (!response.ok) throw new Error('PDF download failed');
                                    setPdfProgress(100);
                                    setPdfProgressMessage('Download complete!');
                                    const blob = await response.blob();
                                    const url = window.URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = `security_report_EN_${(report.target || '').replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;
                                    document.body.appendChild(a);
                                    a.click();
                                    window.URL.revokeObjectURL(url);
                                    document.body.removeChild(a);
                                    setTimeout(() => { setPdfDownloading(false); setPdfProgress(0); setPdfProgressMessage(''); }, 2000);
                                  } catch (err) {
                                    clearInterval(progressInterval);
                                    console.error('PDF download failed:', err);
                                    setPdfProgressMessage(`Error: ${err.message}`);
                                    setTimeout(() => { setPdfDownloading(false); setPdfProgress(0); setPdfProgressMessage(''); }, 3000);
                                  }
                                }}
                              >
                                English Version
                              </button>
                              <button
                                className="pdf-dropdown-item"
                                onClick={async () => {
                                  setPdfDropdownOpen(false);
                                  setPdfDownloading(true);
                                  setPdfProgress(0);
                                  setPdfProgressMessage('Initializing Japanese PDF...');
                                  const progressSteps = [
                                    { progress: 10, message: 'Formatting scan data...' },
                                    { progress: 25, message: 'Waiting for API rate limit...' },
                                    { progress: 40, message: 'Formatting AI analysis...' },
                                    { progress: 55, message: 'Waiting for API rate limit...' },
                                    { progress: 70, message: 'Translating to Japanese...' },
                                    { progress: 85, message: 'Rendering PDF document...' },
                                    { progress: 95, message: 'Finalizing...' },
                                  ];
                                  let currentStep = 0;
                                  const progressInterval = setInterval(() => {
                                    if (currentStep < progressSteps.length) {
                                      setPdfProgress(progressSteps[currentStep].progress);
                                      setPdfProgressMessage(progressSteps[currentStep].message);
                                      currentStep++;
                                    }
                                  }, 8000);
                                  try {
                                    const token = localStorage.getItem('token');
                                    const response = await fetch(`${API_BASE}/api/vt/download-pdf/${report.analysisId}?lang=ja`, {
                                      headers: { 'x-auth-token': token }
                                    });
                                    clearInterval(progressInterval);
                                    if (!response.ok) throw new Error('PDF download failed');
                                    setPdfProgress(100);
                                    setPdfProgressMessage('Download complete!');
                                    const blob = await response.blob();
                                    const url = window.URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = `security_report_JA_${(report.target || '').replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;
                                    document.body.appendChild(a);
                                    a.click();
                                    window.URL.revokeObjectURL(url);
                                    document.body.removeChild(a);
                                    setTimeout(() => { setPdfDownloading(false); setPdfProgress(0); setPdfProgressMessage(''); }, 2000);
                                  } catch (err) {
                                    clearInterval(progressInterval);
                                    console.error('PDF download failed:', err);
                                    setPdfProgressMessage(`Error: ${err.message}`);
                                    setTimeout(() => { setPdfDownloading(false); setPdfProgress(0); setPdfProgressMessage(''); }, 3000);
                                  }
                                }}
                              >
                                Japanese Version
                              </button>
                            </div>
                          )}
                        </div>
                        <button
                          className="download-btn download-btn--json"
                          disabled={pdfDownloading}
                          onClick={async () => {
                            try {
                              const token = localStorage.getItem('token');
                              const response = await fetch(`${API_BASE}/api/vt/download-complete-json/${report.analysisId}`, {
                                headers: { 'x-auth-token': token }
                              });
                              if (!response.ok) throw new Error('Download failed');
                              const blob = await response.blob();
                              const url = window.URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = `scan_report_${(report.target || '').replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
                              document.body.appendChild(a);
                              a.click();
                              window.URL.revokeObjectURL(url);
                              document.body.removeChild(a);
                            } catch (err) {
                              console.error('JSON download failed:', err);
                              alert('Failed to download report. Please try again.');
                            }
                          }}
                        >
                          Download JSON Data
                        </button>
                      </div>

                      {/* PDF Download Progress Bar */}
                      {pdfDownloading && (
                        <div className="pdf-progress-container">
                          <div className="pdf-progress-bar">
                            <div className="pdf-progress-fill" style={{ width: `${pdfProgress}%` }} />
                          </div>
                          <p className="pdf-progress-message">{pdfProgressMessage}</p>
                          <p className="pdf-progress-note">PDF generation includes AI formatting and Japanese translation. This may take up to 2 minutes.</p>
                        </div>
                      )}

                      <p className="download-note">PDF: Professional bilingual report (EN + JA) | JSON: Raw data for analysis</p>
                    </div>
                  )}
                </>
              );
            })()}

            {/* Action Buttons */}
            <div className="step-actions" style={{ marginTop: '2rem' }}>
              {step === 4 && (
                <button className="stop-btn" onClick={handleStopScan}>
                  Stop Scan
                </button>
              )}
              {step === 5 && (
                <button className="primary-btn new-scan-btn" onClick={handleNewScan}>
                  Start New Scan
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuthenticatedScanPanel;
