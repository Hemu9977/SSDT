import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from '../contexts/TranslationContext';
import { useTheme } from '../context/ThemeContext';
import { useUser } from '../contexts/UserContext';
import { useNotifications } from '../contexts/NotificationContext';
import ReactMarkdown from 'react-markdown';
import ZapReportEnhanced from './ZapReportEnhanced';
import WebCheckDetails from './WebCheckDetails';
import '../styles/Hero.scss';
import '../styles/HeroReport.scss';
import '../styles/ScoreCards.scss';

import { API_BASE } from '../config/api';

// 🔄 Loading Placeholder Component for progressive loading
const LoadingPlaceholder = ({ height = '1.5rem', width = '100%', style = {} }) => (
  <div
    className="loading-placeholder"
    style={{
      height,
      width,
      minHeight: height,
      ...style
    }}
  />
);

const Hero = ({ historicalScan }) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [loadingStage, setLoadingStage] = useState('');
  const [error, setError] = useState(null);
  const [isHistorical, setIsHistorical] = useState(false);
  const [pendingSchedule, setPendingSchedule] = useState(null);

  // 🔄 Active scan tracking for stop/resume functionality
  const [activeScanId, setActiveScanId] = useState(null);
  const [scanUrl, setScanUrl] = useState('');
  const stopPollingRef = useRef(false);
  // Legacy: kept only to guard against accidental duplicate polling calls in older code paths.
  // Polling fallback is effectively disabled (no watchdog triggers it).
  const isPollingRef = useRef(false);
  const abortControllerRef = useRef(null);

  // ⚡ WebSocket-first scan progress path with HTTP polling fallback.
  const wsListeningRef   = useRef(false); // prevents duplicate WS listener registration
  const activeScanIdRef  = useRef(null);  // mirror of activeScanId for use inside closures
  const wsWatchdogRef    = useRef(null);  // timer: activates polling if WS is silent for 15s
  const pollRef          = useRef(null);  // stable ref to latest pollAnalysis closure

  // ⚡ ZAP is handled by backend; kept for backward compat with useEffect
  const [zapReport] = useState(null);

  const navigate = useNavigate();
  const { currentLang, setHasReport, t } = useTranslation();
  const { addScanListener, removeScanListener } = useNotifications();
  const { theme } = useTheme();
  const { user, organization } = useUser();

  // 🌐 Report Translation State
  const [translatedReport, setTranslatedReport] = useState(null);
  const [isTranslatingReport, setIsTranslatingReport] = useState(false);
  const [pdfDownloading, setPdfDownloading] = useState(false);
  const [pdfProgress, setPdfProgress] = useState(0);
  const [pdfProgressMessage, setPdfProgressMessage] = useState('');
  const [pdfDropdownOpen, setPdfDropdownOpen] = useState(false);

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

  // Reset AI report translation when a new scan begins
  useEffect(() => {
    setTranslatedReport(null);
    setIsTranslatingReport(false);
    reportTranslateFetchedRef.current = false;
  }, [report?.analysisId]);

  // Translate the AI-generated security report when the user switches to Japanese.
  // Uses Gemini via POST /api/translate because the report is dynamic markdown content.
  // ref guard avoids stale closure — translatedReport never needs to be in the dep array.
  const reportTranslateFetchedRef = React.useRef(false);
  useEffect(() => {
    if (currentLang !== 'ja') return; // don't clear translatedReport — keep cache for next JA toggle
    if (!report?.refinedReport) return;
    if (reportTranslateFetchedRef.current) return; // already fetching or fetched

    reportTranslateFetchedRef.current = true;
    const controller = new AbortController();
    setIsTranslatingReport(true);

    fetch(`${API_BASE}/api/translate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-auth-token': localStorage.getItem('token'),
      },
      body: JSON.stringify({ texts: [report.refinedReport], targetLang: 'ja' }),
      signal: controller.signal,
    })
      .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); })
      .then(data => { if (data.translated?.[0]) setTranslatedReport(data.translated[0]); })
      .catch(err => { if (err.name !== 'AbortError') console.error('[AI Report] Translation failed:', err.message); })
      .finally(() => setIsTranslatingReport(false));

    return () => { controller.abort(); reportTranslateFetchedRef.current = false; };
  }, [currentLang, report?.refinedReport]);

  // Handle historical scan data passed as prop
  useEffect(() => {
    if (historicalScan) {
      console.log('Loading historical scan data:', historicalScan.target);
      // Transform historical scan data to match the report structure Hero expects
      // Hero uses specific property names - must match exactly!
      const transformedReport = {
        target: historicalScan.target,
        status: historicalScan.status,
        analysisId: historicalScan.analysisId,
        triggerSource: historicalScan.triggerSource,
        createdAt: historicalScan.createdAt,

        // PSI data - extract scores from raw pagespeedResult structure
        // Raw structure: psiData.lighthouseResult.categories.performance.score (0-1)
        hasPsiResult: !!historicalScan.psiData,
        psiScores: (() => {
          const categories = historicalScan.psiData?.lighthouseResult?.categories || {};
          if (!historicalScan.psiData || historicalScan.psiData.error) return {};
          return {
            performance: categories.performance?.score != null ? Math.round(categories.performance.score * 100) : null,
            accessibility: categories.accessibility?.score != null ? Math.round(categories.accessibility.score * 100) : null,
            bestPractices: categories['best-practices']?.score != null ? Math.round(categories['best-practices'].score * 100) : null,
            seo: categories.seo?.score != null ? Math.round(categories.seo.score * 100) : null
          };
        })(),

        // Observatory data - extract relevant fields, skip if error
        hasObservatoryResult: !!historicalScan.obsData && !historicalScan.obsData.error,
        observatoryData: (historicalScan.obsData && !historicalScan.obsData.error) ? {
          grade: historicalScan.obsData.grade,
          score: historicalScan.obsData.score,
          tests_passed: historicalScan.obsData.tests_passed,
          tests_failed: historicalScan.obsData.tests_failed,
          tests_quantity: historicalScan.obsData.tests_quantity
        } : null,

        // ZAP data - Hero uses zapData with alerts array
        hasZapResult: !!historicalScan.zapData,
        zapData: historicalScan.zapData ? {
          ...historicalScan.zapData,
          status: historicalScan.zapData.status || 'completed',
          alerts: historicalScan.zapData.alerts || historicalScan.zapData.detailedAlerts || []
        } : null,

        // URLScan data
        hasUrlscanResult: !!historicalScan.urlscanData,
        urlscanData: historicalScan.urlscanData,

        // WebCheck data - transform fullResults to results for Hero compatibility
        webCheckData: historicalScan.webCheckData ? {
          ...historicalScan.webCheckData,
          status: historicalScan.webCheckData.status || 'completed',
          results: historicalScan.webCheckData.fullResults || historicalScan.webCheckData.results || {}
        } : null,

        // AI Report
        hasRefinedReport: !!historicalScan.aiReport,
        refinedReport: historicalScan.aiReport,
        isPartial: false
      };

      console.log('Transformed report:', {
        hasPsi: !!transformedReport.psiScores?.performance,
        hasObs: !!transformedReport.observatoryData?.grade,
        hasZap: !!transformedReport.zapData,
        zapAlerts: transformedReport.zapData?.alerts?.length
      });

      setReport(transformedReport);
      setIsHistorical(true);
      
      // If scan is still in progress, resume polling
      if (!['completed', 'failed', 'stopped'].includes(historicalScan.status)) {
        console.log(`🔄 Historical scan ${historicalScan.analysisId} is still ${historicalScan.status} - resuming`);
        setLoading(true);
        setLoadingStage(t('resumingScan'));
        stopPollingRef.current = false;

        const token = localStorage.getItem('token');
        activeScanIdRef.current = historicalScan.analysisId;
        // eslint-disable-next-line no-use-before-define
        startWebSocketListener(historicalScan.analysisId, token);
      } else {
        setLoading(false);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historicalScan]);

  // Cleanup WS listener on unmount
  useEffect(() => {
    return () => {
      if (activeScanIdRef.current) {
        removeScanListener(activeScanIdRef.current);
      }
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Check for pending schedule on mount
  useEffect(() => {
    const pendingJson = sessionStorage.getItem('pendingScheduleConfig');
    if (pendingJson) {
      try {
        const parsed = JSON.parse(pendingJson);
        if (parsed.scanType === 'public') {
          setPendingSchedule(parsed);
        }
      } catch (err) {
        console.error('Failed to parse pending schedule config', err);
      }
    }
  }, []);

  // Restore pending scan intent after payment redirect
  useEffect(() => {
    const pending = JSON.parse(localStorage.getItem('pendingAction') || 'null');
    if (pending?.type === 'scan' && pending?.url) {
      setScanUrl(pending.url);
      localStorage.removeItem('pendingAction');
    }
  }, []);

  // Translate entire report when language changes
  useEffect(() => {
    if (report || zapReport) {
      setHasReport(true);
    } else {
      setHasReport(false);
    }
  }, [report, zapReport, setHasReport]);

  // 🔄 Resume scan from database on page load
  // This handles: page refresh, browser tab killed, user returning hours later
  // The backend runs scans independently, so we just need to check the database
  useEffect(() => {
    // Skip active scan check if viewing historical scan
    if (historicalScan) return;

    const checkForActiveScan = async () => {
      const token = localStorage.getItem('token');
      if (!token) return;

      try {
        // First, check the backend for any active scan (most reliable source)
        console.log('🔄 Checking for active scan in database...');
        const response = await fetch(`${API_BASE}/api/scan/active-scan`, {
          headers: { 'x-auth-token': token }
        });

        if (!response.ok) {
          console.log('⚠️ Could not check for active scan');
          localStorage.removeItem('activeScan');
          return;
        }

        const data = await response.json();

        // No active scan found in database
        if (!data.hasActiveScan) {
          console.log('ℹ️ No active scan found in database');
          localStorage.removeItem('activeScan');
          return;
        }

        // Active scan found! Restore the state
        console.log('🔄 Found scan in database:', data.analysisId);
        console.log('   Status:', data.status);
        console.log('   Target:', data.target);

        // CASE 1: Scan is COMPLETED - show results directly, no polling needed
        if (data.status === 'completed') {
          console.log('✅ Scan already completed - showing results');

          // Set the full report from database (includes WebCheck results)
          setReport({
            ...data,
            isPartial: false
          });

          // Clear localStorage since scan is done
          localStorage.removeItem('activeScan');

          // No loading state needed - we have all results
          setLoading(false);
          return;
        }

        // CASE 2: Scan is IN PROGRESS - need to resume polling
        console.log('🔄 Scan still in progress - resuming...');

        // Update localStorage to match database (for consistency)
        localStorage.setItem('activeScan', JSON.stringify({
          scanId: data.analysisId,
          url: data.target,
          timestamp: new Date(data.createdAt).getTime()
        }));

        // Set UI state
        setActiveScanId(data.analysisId);
        setScanUrl(data.target);
        setLoading(true);
        setLoadingStage('Resuming scan...');
        stopPollingRef.current = false;

        // Calculate progress based on what's completed
        let progress = 10;
        if (data.hasPsiResult && data.hasObservatoryResult) progress = 30;
        if (data.zapPending) progress = 60;
        if (data.hasZapResult) progress = 85;
        if (data.hasRefinedReport) progress = 95;
        setLoadingProgress(progress);

        // Set partial report data from the server response immediately
        // This shows any progress that was made before refresh
        // WebCheck results now come from backend via polling - no frontend calls needed
        console.log('🔄 Restoring partial scan data from database');
        setReport({
          ...data,
          isPartial: true
        });

        // Resume with WebSocket-first (polling fallback activates after WS_FALLBACK_MS silence)
        activeScanIdRef.current = data.analysisId;
        startWebSocketListener(data.analysisId, token);

      } catch (err) {
        console.error('Error checking for active scan:', err);
        localStorage.removeItem('activeScan');
      }
    };

    checkForActiveScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historicalScan]);

  // Report prose is rendered exactly as provided by the backend. Frontend UI
  // localization uses only static local dictionaries and makes no translation calls.

  // ⚡ ZAP scan is now integrated in the backend combined scan
  // No need for independent frontend ZAP call

  // 🛑 Stop scan handler
  const handleStopScan = async () => {
    // IMMEDIATELY set stop flag to prevent any new updates/fetches
    stopPollingRef.current = true;
    console.log('🛑 Stop button clicked - stopping scan updates');

    // Unregister WebSocket scan listener and cancel watchdog
    if (activeScanIdRef.current) {
      removeScanListener(activeScanIdRef.current);
      wsListeningRef.current = false;
    }
    if (wsWatchdogRef.current) {
      clearTimeout(wsWatchdogRef.current);
      wsWatchdogRef.current = null;
    }

    // Abort any in-flight fetch requests immediately (one-off fetches, etc.)
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      console.log('🛑 Aborted in-flight requests');
    }

    // Get scanId from state or localStorage as fallback
    let scanIdToStop = activeScanId;

    if (!scanIdToStop) {
      // Try to get from localStorage
      const persistedScan = localStorage.getItem('activeScan');
      if (persistedScan) {
        try {
          const parsed = JSON.parse(persistedScan);
          scanIdToStop = parsed.scanId;
        } catch (e) {
          console.error('Failed to parse activeScan from localStorage');
        }
      }
    }

    if (!scanIdToStop) {
      console.log('⏳ No scan ID yet - scan still initializing, stopping UI only');
      // Stop polling and clear UI even if we don't have a scan ID yet
      stopPollingRef.current = true;
      setLoadingStage(t('stoppingScan'));
      setTimeout(() => {
        setLoading(false);
        setActiveScanId(null);
        setScanUrl('');
        setLoadingProgress(0);
        setLoadingStage('');
        localStorage.removeItem('activeScan');
      }, 1000);
      return;
    }

    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    console.log('🛑 Stopping scan:', scanIdToStop);
    setLoadingStage(t('stoppingScanAndRestartingContainers'));

    try {
      const response = await fetch(`${API_BASE}/api/scan/stop-scan/${scanIdToStop}`, {
        method: 'POST',
        headers: {
          'x-auth-token': token
        }
      });

      const data = await response.json();
      console.log('🛑 Stop response:', data);

      if (data.success) {
        setLoadingStage(t('scanStoppedContainersRestartingForFreshEnvironment'));
      } else {
        console.error('Stop failed:', data);
        setLoadingStage(t('stopRequestSent'));
      }

      // Short delay to show the message before clearing
      setTimeout(() => {
        setLoading(false);
        setActiveScanId(null);
        setScanUrl('');
        setLoadingProgress(0);
        setLoadingStage('');
        localStorage.removeItem('activeScan');
      }, 2000);

    } catch (err) {
      console.error('Stop error:', err);
      setError(t('failedToStopScanWithReason', { reason: err.message }));
      setLoading(false);
    }
  };

  // ──────────────────────────────────────────────────────────────────────────
  // applyUpdateData — merges a scan:update payload (from WS or poll) into state
  // ──────────────────────────────────────────────────────────────────────────
  const applyUpdateData = useCallback((data) => {
    const status = data.status;

    if (status === 'completed') {
      // WS sends `aiReport`; component reads `report.refinedReport` — normalize the key
      const normalized = { ...data };
      if (normalized.aiReport && !normalized.refinedReport) {
        normalized.refinedReport = normalized.aiReport;
      }
      setReport(prev => ({ ...prev, ...normalized, isPartial: false }));
      setHasReport(true);
      setLoading(false);
      setLoadingProgress(100);
      setLoadingStage('');
      localStorage.removeItem('activeScan');
      setActiveScanId(null);
      activeScanIdRef.current = null;
      wsListeningRef.current = false;
      if (wsWatchdogRef.current) { clearTimeout(wsWatchdogRef.current); wsWatchdogRef.current = null; }

      // WS events carry raw fields only; fetch processed score-card summaries
      // (psiScores, observatoryData, zapData, webCheckData, urlscanData, analysisId)
      const token = localStorage.getItem('token');
      const currentScanId = data.scanId || data.analysisId || activeScanIdRef.current;
      if (token && currentScanId) {
        fetch(`${API_BASE}/api/scan/combined-analysis/${currentScanId}`, { headers: { 'x-auth-token': token } })
          .then(r => r.ok ? r.json() : null)
          .then(d => { if (d) setReport(prev => ({ ...prev, ...d, isPartial: false })); })
          .catch(() => {});
      }
      return;
    }

    if (status === 'failed') {
      setLoading(false);
      setLoadingProgress(0);
      setLoadingStage('');
      wsListeningRef.current = false;
      if (wsWatchdogRef.current) { clearTimeout(wsWatchdogRef.current); wsWatchdogRef.current = null; }
      setError(t('analysisFailed', { reason: data.error || t('unknownError') }));
      localStorage.removeItem('activeScan');
      setActiveScanId(null);
      activeScanIdRef.current = null;
      return;
    }

    if (status === 'stopped') {
      setLoading(false);
      setLoadingStage(t('scanWasStopped'));
      wsListeningRef.current = false;
      if (wsWatchdogRef.current) { clearTimeout(wsWatchdogRef.current); wsWatchdogRef.current = null; }
      localStorage.removeItem('activeScan');
      setActiveScanId(null);
      activeScanIdRef.current = null;
      return;
    }

    // Partial update — merge in whatever data arrived
    setReport(prev => ({ ...(prev || {}), ...data, isPartial: true }));
    if (data.progress != null) setLoadingProgress(data.progress);
    if (data.message)           setLoadingStage(data.message);
  }, [setHasReport, t]);

  // ──────────────────────────────────────────────────────────────────────────
  // startWebSocketListener — primary real-time path
  // ──────────────────────────────────────────────────────────────────────────
  const startWebSocketListener = useCallback((analysisId, token) => {
    if (wsListeningRef.current) return;
    wsListeningRef.current = true;

    console.log('⚡ WebSocket listener registered for scan:', analysisId);

    addScanListener(analysisId, (data) => {
      if (stopPollingRef.current) return;
      // First WS event cancels the polling watchdog — WebSocket is alive
      if (wsWatchdogRef.current) {
        clearTimeout(wsWatchdogRef.current);
        wsWatchdogRef.current = null;
      }
      console.log('⚡ scan:update via WebSocket:', data.status, data.progress);
      applyUpdateData(data);
    });

    // Watchdog: if no WS event arrives within 15s, fall back to HTTP polling
    wsWatchdogRef.current = setTimeout(() => {
      wsWatchdogRef.current = null;
      if (!stopPollingRef.current && wsListeningRef.current) {
        console.warn('⚠️ No WS event in 15s — activating HTTP polling fallback');
        pollRef.current?.(analysisId, token);
      }
    }, 15000);
  }, [addScanListener, applyUpdateData]); // eslint-disable-line react-hooks/exhaustive-deps

  // ──────────────────────────────────────────────────────────────────────────
  // pollAnalysis — HTTP fallback (unchanged shape, used when WS is silent)
  // ──────────────────────────────────────────────────────────────────────────
  // 🔄 Polling fallback — triggered by watchdog in startWebSocketListener when WS is silent
  const pollAnalysis = async (analysisId, token) => {
    // Prevent duplicate polling instances (React StrictMode / double useEffect)
    if (isPollingRef.current) {
      console.log('⚠️ Polling already in progress, skipping duplicate call');
      return;
    }
    isPollingRef.current = true;
    // Polling is now the primary path; WS listener guard is no longer needed
    wsListeningRef.current = false;

    let attempts = 0;
    // Increased from 60 to 450 attempts (15 minutes at 2-second intervals)
    // ZAP scans can take 5-10+ minutes, so we need longer polling
    const maxAttempts = 450;

    const poll = async () => {
      // Check if polling was stopped (user clicked Stop Scan)
      if (stopPollingRef.current) {
        console.log('🛑 Polling stopped by user');
        isPollingRef.current = false;
        return;
      }

      attempts++;
      const progressIncrement = 60 / maxAttempts;
      const currentProgress = Math.min(30 + (attempts * progressIncrement), 90);
      setLoadingProgress(Math.floor(currentProgress));

      try {
        // Create new AbortController for this request
        abortControllerRef.current = new AbortController();

        const analysisRes = await fetch(`${API_BASE}/api/scan/combined-analysis/${analysisId}`, {
          headers: { 'x-auth-token': token },
          signal: abortControllerRef.current.signal
        });
        const analysisData = await analysisRes.json();
        const status = analysisData.status;

        // Check again if polling was stopped during the fetch
        if (stopPollingRef.current) {
          console.log('🛑 Polling stopped by user (after fetch)');
          return;
        }

        // Progressive Loading: Update report with partial data
        if (analysisData.target) {
          setReport(prevReport => ({
            ...prevReport,
            ...analysisData,
            isPartial: status !== 'completed'
          }));
        }

        if (status === 'completed') {
          setLoadingProgress(100);
          setLoadingStage(t('analysisComplete'));
          localStorage.removeItem('activeScan');
          setActiveScanId(null);
          setScanUrl('');
          isPollingRef.current = false; // Reset polling flag
          setTimeout(() => {
            setLoading(false);
            setLoadingProgress(0);
            setLoadingStage('');
          }, 500);
        } else if (status === 'failed') {
          localStorage.removeItem('activeScan');
          setActiveScanId(null);
          isPollingRef.current = false; // Reset polling flag
          throw new Error('Analysis failed: ' + (analysisData.error || 'Unknown error'));
        } else if (status === 'stopped') {
          localStorage.removeItem('activeScan');
          setActiveScanId(null);
          setLoading(false);
          setLoadingStage(t('scanWasStopped'));
          isPollingRef.current = false; // Reset polling flag
        } else if (attempts >= maxAttempts) {
          setLoading(false);
          setLoadingProgress(0);
          setLoadingStage('');
          isPollingRef.current = false; // Reset polling flag
          console.log('Max attempts reached, showing partial results');
        } else {
          // Show progress indicators based on what we have
          let statusMessage = t('analyzing');
          const hasPsi = analysisData.hasPsiResult;
          const hasObs = analysisData.hasObservatoryResult;
          const hasZap = analysisData.hasZapResult;
          const zapPending = analysisData.zapPending;
          const hasAi = analysisData.hasRefinedReport;

          if (!hasPsi || !hasObs) statusMessage = `📊 ${t('fetchingPerformanceAndSecurityMetadata')}`;
          else if (zapPending && analysisData.zapData) {
            const zapPhase = analysisData.zapData.phase || 'scanning';
            const zapProgress = analysisData.zapData.progress || 0;
            statusMessage = `⚡ ${t('vulnerabilityAnalysisInProgress', { phase: zapPhase, progress: zapProgress })}`;
          }
          else if (!hasZap && !zapPending) statusMessage = `⚡ ${t('startingComprehensiveVulnerabilityScan')}`;
          else if (!hasAi) statusMessage = `🤖 ${t('generatingAiPoweredSecurityInsights')}`;
          else statusMessage = `✅ ${t('finalizingResults')}`;

          setLoadingStage(statusMessage);
          setTimeout(poll, 2000);
        }
      } catch (pollError) {
        // If request was aborted (user clicked stop), exit gracefully
        if (pollError.name === 'AbortError') {
          console.log('🛑 Request aborted - scan was stopped by user');
          isPollingRef.current = false; // Reset polling flag
          return;
        }
        // If polling was stopped by user, don't throw - just exit gracefully
        if (stopPollingRef.current) {
          console.log('🛑 Polling error ignored - scan was stopped by user');
          isPollingRef.current = false; // Reset polling flag
          return;
        }
        console.error('Polling error:', pollError);
        isPollingRef.current = false; // Reset polling flag
        throw pollError;
      }
    };

    await poll();
  };
  // Keep pollRef pointed at the latest closure so the WS watchdog can invoke it without
  // needing pollAnalysis as a stable useCallback dep.
  pollRef.current = pollAnalysis;

  // 🔍 WebCheck scans now run entirely in backend - no frontend API calls needed
  // Results come via the combined-analysis polling endpoint along with ZAP and other scans

  // Results come via the combined-analysis polling endpoint along with ZAP and other scans
  
  const submitSchedule = async (url, config) => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(true);
    setLoadingStage(t('savingSchedule'));
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/api/schedules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        },
        body: JSON.stringify({
          scanType: config.scanType,
          targetUrl: url,
          scheduleType: config.scheduleType || (config.recurring ? 'recurring' : 'one-time'),
          scheduledAt: config.scheduledAt,
          recurring: config.recurring,
          timezone: config.timezone || 'Asia/Kolkata'
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || t('failedSaveSchedule'));

      sessionStorage.removeItem('pendingScheduleConfig');
      setPendingSchedule(null);
      alert(t('scheduleCreatedSuccessfully'));
      navigate('/schedules');
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const url = e.target.elements.url.value;
    
    if (pendingSchedule) {
      return submitSchedule(url, pendingSchedule);
    }

    const token = localStorage.getItem('token');

    if (!token) {
      navigate('/login');
      return;
    }

    // --- PROACTIVE PLAN GATING (org-based) ---
    // Check if user has an active organization subscription
    // Falls back to user.planType for backward compatibility
    const hasActivePlan = (organization && organization.subscriptionStatus === 'active') ||
                          (user && user.planType);

    if (!hasActivePlan) {
      console.warn('⚠️ No active plan detected, redirecting to profile');
      // Store pending scan intent so we can resume after payment
      localStorage.setItem('pendingAction', JSON.stringify({
        type: 'scan',
        url: url,
        timestamp: Date.now()
      }));
      navigate('/profile?redirect=scan');
      return;
    }

    setLoading(true);
    setLoadingProgress(0);
    setLoadingStage(t('initializingScan'));
    setError(null);
    setReport(null);
    setScanUrl(url);
    stopPollingRef.current = false; // Reset stop flag for new scan
    isPollingRef.current = false; // Reset polling flag for new scan

    // ⚡ ZAP and WebCheck are now both integrated in the backend combined scan
    // Backend triggers both scans independently and saves results to MongoDB
    // Frontend just polls and displays whatever data is available

    try {
      console.log('🔍 Submitting URL for scan:', url);
      setLoadingProgress(10);
      setLoadingStage(t('analyzingTargetEnvironment'));

      const res = await fetch(`${API_BASE}/api/scan/combined-url-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ error: 'Unknown error' }));
        if (res.status === 401) {
          console.error('❌ Scan 401 Unauthorized — token invalid or missing. Please log in again.');
          navigate('/login');
          return;
        }
        if (res.status === 429) {
          const retryAfter = errorData.retryAfter || '1 minute';
          throw new Error(`Rate limit exceeded. Please wait ${retryAfter}.`);
        }
        // Plan quota exceeded — guide user to upgrade
        if (res.status === 403 && (errorData.code === 'PLAN_LIMIT_EXCEEDED' || errorData.error === 'PLAN_LIMIT_EXCEEDED' || errorData.code === 'NO_ORGANIZATION')) {
          console.error('❌ Scan 403 Plan limit exceeded:', errorData);
          throw new Error(`${errorData.message || 'Plan limit reached.'} Visit your Profile page to upgrade.`);
        }
        console.error('❌ Scan request failed:', res.status, errorData);
        throw new Error(errorData.error || errorData.details || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setLoadingProgress(20);
      setLoadingStage(t('scanRequestAccepted'));

      const analysisId = data.analysisId || data.data?.id;
      if (!analysisId) throw new Error("No analysisId in response");

      // 🔄 Persist scan to localStorage for resume on page refresh
      setActiveScanId(analysisId);
      localStorage.setItem('activeScan', JSON.stringify({
        scanId: analysisId,
        url,
        timestamp: Date.now()
      }));

      setLoadingProgress(30);
      setLoadingStage(t('performingComprehensiveSiteAnalysis'));

      // Check if stop was clicked during the initial API call
      if (stopPollingRef.current) {
        console.log('🛑 Scan was stopped during initialization');
        setLoading(false);
        localStorage.removeItem('activeScan');
        return;
      }

      // ⚡ WebSocket-first: register listener immediately so we don't miss early events.
      // Always reset wsListeningRef so a second scan on the same page gets a fresh listener,
      // and remove any stale listener left from the previous scan.
      if (activeScanIdRef.current) {
        removeScanListener(activeScanIdRef.current);
      }
      if (wsWatchdogRef.current) {
        clearTimeout(wsWatchdogRef.current);
        wsWatchdogRef.current = null;
      }
      wsListeningRef.current = false;
      activeScanIdRef.current = analysisId;
      startWebSocketListener(analysisId, token);

    } catch (err) {
      console.error('Analysis error:', err);
      let errorMessage = t('analysisFailed', { reason: '' });
      if (err.message.includes('429')) errorMessage = err.message;
      else errorMessage += err.message;

      setError(errorMessage);
      setLoading(false);
      setLoadingProgress(0);
      localStorage.removeItem('activeScan');
      setActiveScanId(null);
    }
  };

  // Note: renderPartialReport removed - replaced by progressive loading in main report layout

  const renderReport = () => {
    // Show error if present
    if (error) return <p className="error-msg">{error}</p>;

    // Don't render anything if no report and not loading
    if (!report && !loading) return null;

    // Extract data - will be null/empty during loading
    const psiScores = report?.psiScores || {};
    const observatoryData = report?.observatoryData || null;
    const refinedReport = report?.refinedReport;

    const getScoreClass = (score) => score >= 90 ? 'score-good' : score >= 50 ? 'score-medium' : 'score-poor';
    const getObservatoryGradeColor = (grade) => {
      if (!grade) return '#888';
      const map = { 'A': '#00d084', 'B': '#7fba00', 'C': '#ffb900', 'D': '#ff8c00', 'F': '#e81123' };
      return map[grade[0]] || '#888';
    };

    // ⚡ ZAP Helpers - Now using backend zapData with status support
    let zapRiskLabel = "Passed";
    let zapRiskColor = "#00d084";
    let zapPendingMessage = null;

    const backendZapData = report?.zapData;
    if (backendZapData) {
      if (backendZapData.status === 'pending' || backendZapData.status === 'running') {
        // ZAP scan in progress
        zapRiskLabel = "Scanning...";
        zapRiskColor = "#ffb900";
        const progress = backendZapData.progress || 0;
        const phase = backendZapData.phase || 'starting';
        zapPendingMessage = `${phase}: ${progress}%`;
      } else if (backendZapData.status === 'completed' && backendZapData.riskCounts) {
        // ZAP scan complete
        if (backendZapData.riskCounts.High > 0) { zapRiskLabel = "Vulnerable (High)"; zapRiskColor = "#e81123"; }
        else if (backendZapData.riskCounts.Medium > 0) { zapRiskLabel = "Vulnerable (Medium)"; zapRiskColor = "#ff8c00"; }
        else if (backendZapData.riskCounts.Low > 0) { zapRiskLabel = "Vulnerable (Low)"; zapRiskColor = "#ffb900"; }
      } else if (backendZapData.status === 'failed') {
        zapRiskLabel = "Failed";
        zapRiskColor = "#e81123";
        zapPendingMessage = backendZapData.message || 'Scan failed';
      }
    }

    // 🔍 WebCheck data - now comes from backend via polling
    // Structure: { status: 'running'|'uploading'|'completed'|'completed_with_errors'|'completed_partial'|'failed', results: {...}, progress: 0-100 }
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

    return (
      <div className="report-container">
        {/* 🔄 Progress Bar - Show during loading */}
        {loading && (
          <div className="scan-progress-bar">
            <div className="progress-header">
              <span className="progress-title">🔍 Scanning {report?.target || 'URL'}...</span>
              <span className="progress-percentage">{loadingProgress}%</span>
            </div>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${loadingProgress}%` }} />
            </div>
            <div className="progress-stage">{loadingStage}</div>
          </div>
        )}

        <h3 className="report-title">📊 {t('combinedScanReport')}{report?.target ? t('combinedScanReportTarget', { target: report.target }) : ''}</h3>
        {report?.status && <p>Status: <b>{report.status}</b></p>}

        {/* AI Summary - Shows loading placeholder or content */}
        <div className="ai-report-section markdown-content" style={{
          background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)',
          padding: '1.5rem',
          marginBottom: '2rem',
          borderRadius: '8px',
          border: '2px solid var(--accent)',
          lineHeight: '1.6',
          fontSize: '0.95rem'
        }}>
          <h4 style={{ marginTop: 0, color: 'var(--accent)' }}>{t('aiGeneratedAnalysisSummary')}</h4>
          {refinedReport ? (
            isTranslatingReport ? (
              <div style={{ textAlign: 'center', padding: '1rem' }}>
                <p style={{ color: 'var(--accent)' }}>🌐 Translating report to Japanese...</p>
              </div>
            ) : (
              <ReactMarkdown>
                {(() => {
                  const urlParams = new URLSearchParams(window.location.search);
                  const forceEn = urlParams.get('lang') === 'en';
                  return (currentLang === 'ja' && translatedReport && !forceEn) ? translatedReport : refinedReport;
                })()}
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
                ⏳ Generating AI analysis... (waiting for all scan data)
              </p>
            </div>
          )}
        </div>

        {/* Combined Scores Grid */}
        <div className="score-cards-grid">
          {/* ⚡ OWASP ZAP Score Card - Now uses backend data with async support */}
          {/* ⚡ OWASP ZAP Score Card - Now uses backend data with async support */}
          <div className="score-card">
            <h4 className="score-card__title">⚡ OWASP ZAP</h4>
            {backendZapData ? (
              <>
                <span className="score-card__value" style={{ color: zapRiskColor }}>{zapRiskLabel}</span>
                {zapPendingMessage ? (
                  <p className="score-card__label" style={{ color: '#ffb900' }}>{zapPendingMessage}</p>
                ) : backendZapData.status === 'completed' ? (
                  <p className="score-card__label">{t('alertsCount', { count: backendZapData.alerts ? backendZapData.alerts.length : 0 })}</p>
                ) : backendZapData.status === 'completed_partial' ? (
                  <p className="score-card__label" style={{ color: '#ffb900' }}>{t('alertsCountPartial', { count: backendZapData.alerts ? backendZapData.alerts.length : 0 })}</p>
                ) : null}
              </>
            ) : report?.zapResult?.error || (report?.status === 'completed' && !report?.hasZapResult) ? (
              <div style={{ color: '#ffb900', marginTop: '10px' }}>{t('unavailable')}</div>
            ) : (
              <div className="score-card__loading loading-pulse">
                <LoadingPlaceholder height="1.5rem" width="60%" style={{ marginBottom: '0.5rem' }} />
                <LoadingPlaceholder height="0.85rem" width="40%" />
              </div>
            )}
          </div>

          {/* Performance (PSI) */}
          {/* Performance (PSI) */}
          <div className="score-card">
            <h4 className="score-card__title">⚡ {t('performance')}</h4>
            {psiScores?.performance != null ? (
              <>
                <span className={`score-card__value ${getScoreClass(psiScores.performance)}`}>{psiScores.performance}</span>
                <p className="score-card__label">{t('outOf100')}</p>
              </>
            ) : (
              <div className="score-card__loading loading-pulse">
                <LoadingPlaceholder height="1.5rem" width="50%" style={{ marginBottom: '0.5rem' }} />
                <LoadingPlaceholder height="0.85rem" width="40%" />
              </div>
            )}
          </div>



          {/* Security Config (Observatory) */}
          {/* Security Config (Observatory) */}
          <div className="score-card">
            <h4 className="score-card__title">🔒 {t('securityConfig')}</h4>
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

          {/* 🔍 URLScan.io Security Verdict */}
          {/* 🔍 URLScan.io Security Verdict */}
          <div className="score-card">
            <h4 className="score-card__title">🌐 URLScan.io</h4>
            {report?.hasUrlscanResult && report?.urlscanData ? (
              <>
                <span className="score-card__value" style={{
                  color: report.urlscanData.verdicts?.overall?.malicious ? '#e81123' : '#00d084'
                }}>
                  {report.urlscanData.verdicts?.overall?.malicious ? 'Malicious' : 'Clean'}
                </span>
                <p className="score-card__label">
                  {report.urlscanData.verdicts?.overall?.score || 0} {t('threatScore')}
                </p>
              </>
            ) : report?.urlscanResult?.error || (report?.status === 'completed' && !report?.hasUrlscanResult) ? (
              <div style={{ color: '#ffb900', marginTop: '10px' }}>{t('unavailable')}</div>
            ) : (
              <div className="score-card__loading loading-pulse">
                <LoadingPlaceholder height="1.5rem" width="50%" style={{ marginBottom: '0.5rem' }} />
                <LoadingPlaceholder height="0.85rem" width="40%" />
              </div>
            )}
          </div>

          {/* 🔍 WebCheck: SSL Certificate */}
          {/* 🔍 WebCheck: SSL Certificate */}
          <div className="score-card">
            <h4 className="score-card__title">🔐 {t('sslCertificate')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.ssl && !webCheckReport.ssl.error ? (
              <>
                <span className="score-card__value score-card__value--safe">Valid</span>
                <p className="score-card__label">{webCheckReport.ssl.issuer?.O || t('unknownIssuer')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{webCheckError ? t('scanFailed') : t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Security Headers */}
          {/* 🔍 WebCheck: Security Headers */}
          <div className="score-card">
            <h4 className="score-card__title">🛡️ {t('securityHeaders')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['http-security'] && !webCheckReport['http-security'].error ? (
              <>
                {(() => {
                  const sec = webCheckReport['http-security'];
                  const passed = [sec.strictTransportPolicy, sec.xFrameOptions, sec.xContentTypeOptions, sec.xXSSProtection, sec.contentSecurityPolicy].filter(Boolean).length;
                  const color = passed >= 4 ? '#00d084' : passed >= 2 ? '#ffb900' : '#e81123';
                  return <span className="score-card__value" style={{ color }}>{passed}/5</span>;
                })()}
                <p className="score-card__label">{t('headersPresent')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Tech Stack */}
          {/* 🔍 WebCheck: Tech Stack */}
          <div className="score-card">
            <h4 className="score-card__title">🛠️ {t('techStack')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : (() => {
              // Handle various response formats from tech-stack scan
              const techData = webCheckReport?.['tech-stack'];
              const techArray = techData?.technologies ||
                (Array.isArray(techData) ? techData : null) ||
                (techData && !techData.error && typeof techData === 'object' ? Object.keys(techData) : null);

              if (techArray && techArray.length > 0) {
                return (
                  <>
                    <span className="score-card__value score-card__value--safe">{techArray.length}</span>
                    <p className="score-card__label">{t('technologiesDetected')}</p>
                  </>
                );
              } else if (techData && !techData.error) {
                return <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('noTechnologiesDetected')}</div>;
              } else {
                return <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{techData?.error ? t('scanFailed') : t('pending')}</div>;
              }
            })()}
          </div>

          {/* 🔍 WebCheck: Firewall/WAF */}
          {/* 🔍 WebCheck: Firewall/WAF */}
          <div className="score-card">
            <h4 className="score-card__title">🔥 {t('firewall')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.firewall && !webCheckReport.firewall.error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport.firewall.hasWaf ? 'safe' : 'medium'}`}>
                  {webCheckReport.firewall.hasWaf ? webCheckReport.firewall.waf : 'None Detected'}
                </span>
                <p className="score-card__label">{t('wafStatus')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: TLS Grade */}
          {/* 🔍 WebCheck: TLS Grade */}
          <div className="score-card">
            <h4 className="score-card__title">🔒 {t('tlsGrade')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.tls && !webCheckReport.tls.error ? (
              <>
                <span className="score-card__value" style={{ color: getObservatoryGradeColor(webCheckReport.tls.tlsInfo?.grade) }}>
                  {webCheckReport.tls.tlsInfo?.grade || 'N/A'}
                </span>
                <p className="score-card__label">{t('scoreOf100', { score: webCheckReport.tls.tlsInfo?.score || 0 })}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Quality (PageSpeed) */}
          {/* 🔍 WebCheck: Quality (PageSpeed) */}
          <div className="score-card">
            <h4 className="score-card__title">📊 {t('quality')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.quality && !webCheckReport.quality.error ? (
              (() => {
                const perfScore = Math.round((webCheckReport.quality.lighthouseResult?.categories?.performance?.score || 0) * 100);
                return (
                  <>
                    <span className={`score-card__value score-card__value--${perfScore >= 90 ? 'safe' : perfScore >= 50 ? 'medium' : 'high'}`}>
                      {perfScore}
                    </span>
                    <p className="score-card__label">{t('optimizationScore')}</p>
                  </>
                );
              })()
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Mail Config */}
          {/* 🔍 WebCheck: Mail Config */}
          <div className="score-card">
            <h4 className="score-card__title">📧 {t('mailConfig')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['mail-config'] && !webCheckReport['mail-config'].error && !webCheckReport['mail-config'].skipped ? (
              <>
                <span className="score-card__value score-card__value--safe">
                  {webCheckReport['mail-config'].mxRecords?.length || 0}
                </span>
                <p className="score-card__label">{t('mxRecordsFound')}</p>
              </>
            ) : webCheckReport?.['mail-config']?.skipped ? (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('noMailServer')}</div>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: WHOIS */}
          {/* 🔍 WebCheck: WHOIS */}
          <div className="score-card">
            <h4 className="score-card__title">📋 WHOIS</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.whois && !webCheckReport.whois.error ? (
              <>
                <span className="score-card__value score-card__value--safe" style={{ fontSize: '0.9rem' }}>
                  {webCheckReport.whois.registrar?.substring(0, 20) || 'Found'}
                </span>
                <p className="score-card__label">{t('domainRegistered')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: HSTS */}
          {/* 🔍 WebCheck: HSTS */}
          <div className="score-card">
            <h4 className="score-card__title">🔐 HSTS</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.hsts && !webCheckReport.hsts.error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport.hsts.hstsEnabled ? 'safe' : 'high'}`}>
                  {webCheckReport.hsts.hstsEnabled ? 'Enabled' : 'Disabled'}
                </span>
                <p className="score-card__label">{webCheckReport.hsts.hstsPreloaded ? t('preloaded') : t('notPreloaded')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Block Lists */}
          {/* 🔍 WebCheck: Block Lists */}
          <div className="score-card">
            <h4 className="score-card__title">🚫 {t('securityBlacklist')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['block-lists'] && !webCheckReport['block-lists'].error ? (
              (() => {
                const blocklists = webCheckReport['block-lists'].blocklists || [];
                const blockedCount = blocklists.filter(b => b.isBlocked).length;
                return (
                  <>
                    <span className={`score-card__value score-card__value--${blockedCount === 0 ? 'safe' : 'high'}`}>
                      {blockedCount === 0 ? 'Clean' : `${blockedCount} Found`}
                    </span>
                    <p className="score-card__label">{t('listsChecked', { count: blocklists.length })}</p>
                  </>
                );
              })()
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Carbon Footprint */}
          {/* 🔍 WebCheck: Carbon Footprint */}
          <div className="score-card">
            <h4 className="score-card__title">🌱 {t('carbon')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.carbon && !webCheckReport.carbon.error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport.carbon.isGreen ? 'safe' : 'medium'}`}>
                  {webCheckReport.carbon.isGreen ? 'Green' : 'Standard'}
                </span>
                <p className="score-card__label">{webCheckReport.carbon.co2?.grid?.grams ? `${webCheckReport.carbon.co2.grid.grams.toFixed(2)}g CO2` : t('hosting')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Archives */}
          {/* 🔍 WebCheck: Archives */}
          <div className="score-card">
            <h4 className="score-card__title">📚 {t('archives')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.archives?.skipped ? (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('notArchived')}</div>
            ) : webCheckReport?.archives?.totalScans ? (
              <>
                <span className="score-card__value score-card__value--safe">
                  {webCheckReport.archives.totalScans}
                </span>
                <p className="score-card__label">{t('historicalSnapshots')}</p>
              </>
            ) : webCheckReport?.archives?.error ? (
              <div className="score-card__label" style={{ color: '#ffb900', marginTop: '10px' }}>{t('timeout')}</div>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Sitemap */}
          {/* 🔍 WebCheck: Sitemap */}
          <div className="score-card">
            <h4 className="score-card__title">🗺️ {t('sitemap')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.sitemap?.skipped || webCheckReport?.sitemap?.error ? (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('notFound')}</div>
            ) : webCheckReport?.sitemap?.urlset ? (
              <>
                <span className="score-card__value score-card__value--safe">
                  {webCheckReport.sitemap.urlset?.url?.length || 'Found'}
                </span>
                <p className="score-card__label">{t('urlsInSitemap')}</p>
              </>
            ) : webCheckReport?.sitemap ? (
              <div className="score-card__value score-card__value--safe" style={{ fontSize: '1.2rem' }}>Found</div>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Social Tags */}
          {/* 🔍 WebCheck: Social Tags */}
          <div className="score-card">
            <h4 className="score-card__title">📱 {t('socialTags')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['social-tags'] && !webCheckReport['social-tags'].error ? (
              (() => {
                const tags = webCheckReport['social-tags'];
                const hasOg = tags.ogTitle || tags.openGraph?.title;
                const hasTwitter = tags.twitterCard || tags.twitter?.card;
                return (
                  <>
                    <span className={`score-card__value score-card__value--${(hasOg || hasTwitter) ? 'safe' : 'medium'}`}>
                      {(hasOg && hasTwitter) ? 'Complete' : (hasOg || hasTwitter) ? 'Partial' : 'Missing'}
                    </span>
                    <p className="score-card__label">{hasOg ? 'OG' : ''}{hasOg && hasTwitter ? ' + ' : ''}{hasTwitter ? 'Twitter' : ''}</p>
                  </>
                );
              })()
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Linked Pages */}
          <div className="score-card">
            <h4 className="score-card__title">🔗 {t('links')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['linked-pages'] && !webCheckReport['linked-pages'].error ? (
              <>
                <span className="score-card__value score-card__value--safe">
                  {webCheckReport['linked-pages'].internal?.length || webCheckReport['linked-pages'].links?.length || 0}
                </span>
                <p className="score-card__label">{t('linksFound')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Redirects */}
          <div className="score-card">
            <h4 className="score-card__title">↪️ {t('redirects')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.redirects && !webCheckReport.redirects.error ? (
              <>
                <span className={`score-card__value score-card__value--${(webCheckReport.redirects.redirects?.length || 0) <= 2 ? 'safe' : 'medium'}`}>
                  {webCheckReport.redirects.redirects?.length || 0}
                </span>
                <p className="score-card__label">{t('redirectHops')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: DNS Server */}
          <div className="score-card">
            <h4 className="score-card__title">🌐 {t('dnsServer')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['dns-server'] && !webCheckReport['dns-server'].error ? (
              <>
                <span className="score-card__value score-card__value--safe" style={{ fontSize: '1.2rem' }}>
                  {webCheckReport['dns-server'].dns?.length || 1}
                </span>
                <p className="score-card__label">{t('serversFound')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: DNSSEC */}
          <div className="score-card">
            <h4 className="score-card__title">🔑 DNSSEC</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.dnssec && !webCheckReport.dnssec.error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport.dnssec.isValid || webCheckReport.dnssec.enabled ? 'safe' : 'medium'}`} style={{ fontSize: '1.2rem' }}>
                  {webCheckReport.dnssec.isValid || webCheckReport.dnssec.enabled ? 'Valid' : 'Not Set'}
                </span>
                <p className="score-card__label">{t('dnssecStatus')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Security.txt */}
          <div className="score-card">
            <h4 className="score-card__title">📄 Security.txt</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['security-txt'] && !webCheckReport['security-txt'].error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport['security-txt'].isPresent || webCheckReport['security-txt'].found ? 'safe' : 'medium'}`} style={{ fontSize: '1.2rem' }}>
                  {webCheckReport['security-txt'].isPresent || webCheckReport['security-txt'].found ? 'Found' : 'Missing'}
                </span>
                <p className="score-card__label">{t('securityPolicy')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Robots.txt */}
          <div className="score-card">
            <h4 className="score-card__title">🤖 {t('robotsTxt')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['robots-txt'] && !webCheckReport['robots-txt'].error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport['robots-txt'].exists || webCheckReport['robots-txt'].isPresent ? 'safe' : 'medium'}`} style={{ fontSize: '1.2rem' }}>
                  {webCheckReport['robots-txt'].exists || webCheckReport['robots-txt'].isPresent ? 'Found' : 'Missing'}
                </span>
                <p className="score-card__label">{t('crawlerRules')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Status */}
          <div className="score-card">
            <h4 className="score-card__title">🟢 {t('status')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.status && !webCheckReport.status.error ? (
              <>
                <span className={`score-card__value score-card__value--${webCheckReport.status.isUp || webCheckReport.status.statusCode === 200 ? 'safe' : 'high'}`}>
                  {webCheckReport.status.statusCode || (webCheckReport.status.isUp ? '200' : 'Down')}
                </span>
                <p className="score-card__label">{webCheckReport.status.responseTime ? `${webCheckReport.status.responseTime}ms` : t('httpStatus')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>

          {/* 🔍 WebCheck: Legacy Rank */}
          <div className="score-card">
            <h4 className="score-card__title">📈 {t('rank')}</h4>
            {webCheckLoading ? (
              <div className="score-card__loading" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{webCheckUploading ? t('uploadProgress', { progress: webCheckUploadProgress }) : t('scanning')}</div>
            ) : webCheckReport?.['legacy-rank'] && !webCheckReport['legacy-rank'].error ? (
              <>
                <span className="score-card__value score-card__value--safe" style={{ fontSize: '1rem' }}>
                  #{webCheckReport['legacy-rank'].rank || webCheckReport['legacy-rank'].globalRank || 'N/A'}
                </span>
                <p className="score-card__label">{t('globalRank')}</p>
              </>
            ) : (
              <div className="score-card__label" style={{ color: '#888', marginTop: '10px' }}>{t('pending')}</div>
            )}
          </div>
        </div>

        {/* 📸 Screenshot Preview - Full Width (WebCheck or URLScan.io fallback) */}
        {(() => {
          // Try WebCheck screenshot first, then URLScan.io as fallback
          const webCheckScreenshot = webCheckReport?.screenshot?.image && !webCheckReport?.screenshot?.error
            ? `data:image/png;base64,${webCheckReport.screenshot.image}`
            : null;
          const urlscanScreenshot = report?.urlscanData?.screenshot || null;
          const screenshotSrc = webCheckScreenshot || urlscanScreenshot;
          const screenshotSource = webCheckScreenshot ? 'WebCheck' : (urlscanScreenshot ? 'URLScan.io' : null);

          if (!screenshotSrc) return null;

          return (
            <div className="screenshot-preview">
              <h4>📸 {t('websiteScreenshot')} <span>({screenshotSource})</span></h4>
              <img
                src={screenshotSrc}
                alt={t('websiteScreenshot')}
              />
            </div>
          );
        })()}

        {/* ⚡ OWASP ZAP Enhanced Results - Only show when completed */}
        {backendZapData && backendZapData.status === 'completed' && backendZapData.alerts && (
          <ZapReportEnhanced
            zapData={backendZapData}
            scanId={report?.scanId || report?.analysisId}
            currentLang={currentLang}
          />
        )}

        {/* ZAP Pending/Running Status */}
        {backendZapData && (backendZapData.status === 'pending' || backendZapData.status === 'running') && (
          <div className="zap-progress-card">
            <h3>⚡ OWASP ZAP Security Scan in Progress</h3>
            <p className="zap-status">
              {backendZapData.phase || 'Scanning'}: {backendZapData.progress || 0}%
            </p>
            <p className="zap-details">
              {backendZapData.message || 'Running comprehensive security tests...'}
            </p>
            {backendZapData.urlsFound > 0 && (
              <p className="zap-stats">
                Found {backendZapData.urlsFound} URLs • {backendZapData.alertsFound || 0} alerts so far
              </p>
            )}
            <p className="zap-details" style={{ marginTop: '1rem', fontSize: '0.8rem' }}>
              This page will automatically update when the scan completes.
            </p>
          </div>
        )}

        {/* 🔍 WebCheck Detailed Results */}
        <WebCheckDetails webCheckReport={webCheckReport} theme={theme} />

        {/* 🌐 URLScan.io Detailed Results */}
        {report?.hasUrlscanResult && report?.urlscanData && (
          <details style={{ marginBottom: '2rem' }}>
            <summary style={{ cursor: 'pointer', fontWeight: 'bold', padding: '1rem', background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', borderRadius: '8px', border: '1px solid #00d084' }}>
              🌐 {t('viewUrlscanAnalysis')}
            </summary>
            <div style={{ marginTop: '1rem', display: 'grid', gap: '1rem' }}>

              {/* Security Verdict */}
              <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px' }}>
                <h5 style={{ margin: '0 0 0.5rem 0', color: 'var(--accent)' }}>🛡️ {t('urlscanSecurityVerdict')}</h5>
                <p><b>{t('urlscanOverall')}:</b> <span style={{ color: report.urlscanData.verdicts?.overall?.malicious ? '#e81123' : '#00d084', fontWeight: 'bold' }}>
                  {report.urlscanData.verdicts?.overall?.malicious ? t('urlscanMalicious') : t('urlscanClean')}
                </span></p>
                <p><b>{t('urlscanThreatScore')}:</b> {report.urlscanData.verdicts?.overall?.score || 0}</p>
                {report.urlscanData.verdicts?.urlscan?.score > 0 && (
                  <p><b>{t('urlscanUrlscanScore')}:</b> {report.urlscanData.verdicts.urlscan.score}</p>
                )}
                {report.urlscanData.verdicts?.engines?.malicious > 0 && (
                  <p><b>{t('urlscanEngineDetections')}:</b> <span style={{ color: '#e81123' }}>{t('urlscanMaliciousCount', { count: report.urlscanData.verdicts.engines.malicious })}</span></p>
                )}
                {report.urlscanData.verdicts?.community?.score > 0 && (
                  <p><b>{t('urlscanCommunityScore')}:</b> {report.urlscanData.verdicts.community.score}</p>
                )}
              </div>

              {/* Page Information */}
              {report.urlscanData.page && (
                <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px' }}>
                  <h5 style={{ margin: '0 0 0.5rem 0', color: 'var(--accent)' }}>📄 {t('urlscanPageInformation')}</h5>
                  <p><b>{t('urlscanDomain')}:</b> {report.urlscanData.page.domain || 'N/A'}</p>
                  <p><b>{t('urlscanIpAddress')}:</b> {report.urlscanData.page.ip || 'N/A'}</p>
                  <p><b>{t('urlscanCountry')}:</b> {report.urlscanData.page.country || 'N/A'}</p>
                  <p><b>{t('urlscanServer')}:</b> {report.urlscanData.page.server || 'N/A'}</p>
                  {report.urlscanData.page.tlsIssuer && (
                    <p><b>{t('urlscanTlsIssuer')}:</b> {report.urlscanData.page.tlsIssuer}</p>
                  )}
                  {report.urlscanData.page.tlsValidDays && (
                    <p><b>{t('urlscanTlsValidDays')}:</b> {report.urlscanData.page.tlsValidDays}</p>
                  )}
                </div>
              )}

              {/* Network Statistics */}
              {report.urlscanData.stats && (
                <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '1rem', borderRadius: '8px' }}>
                  <h5 style={{ margin: '0 0 0.5rem 0', color: 'var(--accent)' }}>📊 {t('urlscanNetworkStatistics')}</h5>
                  <p><b>{t('urlscanHttpRequests')}:</b> {report.urlscanData.stats.requests || 0}</p>
                  <p><b>{t('urlscanUniqueIps')}:</b> {report.urlscanData.stats.uniqIPs || 0}</p>
                  <p><b>{t('urlscanUniqueCountries')}:</b> {report.urlscanData.stats.uniqCountries || 0}</p>
                  <p><b>{t('urlscanDataTransferred')}:</b> {report.urlscanData.stats.dataLength ? `${(report.urlscanData.stats.dataLength / 1024).toFixed(1)} KB` : 'N/A'}</p>
                </div>
              )}

              {/* Scan summary note */}
              <div style={{ background: theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)', padding: '0.75rem 1rem', borderRadius: '8px', fontSize: '0.82rem', color: '#888', borderLeft: '3px solid var(--accent)' }}>
                ✅ {t('urlscanAllDataShown')}
              </div>
            </div>
          </details>
        )}

        {/* Observatory Summary */}
        {observatoryData ? (
          <div className="report-summary" style={{ marginTop: '2rem' }}>
            <h4>🔒 {t('mozillaObservatorySecurityConfiguration')}</h4>
            <p><b>{t('obsSecurityGrade')}:</b> <span style={{ color: getObservatoryGradeColor(observatoryData.grade), fontWeight: 'bold', fontSize: '1.2rem' }}>{observatoryData.grade}</span></p>
            <p><b>{t('obsScore')}:</b> {observatoryData.score}/100</p>
            <p><b>{t('obsTestsPassed')}:</b> <span style={{ color: '#00d084', fontWeight: 'bold' }}>{observatoryData.tests_passed}/{observatoryData.tests_quantity}</span></p>
            <p><b>{t('obsTestsFailed')}:</b> <span style={{ color: observatoryData.tests_failed > 0 ? '#e81123' : '#00d084', fontWeight: 'bold' }}>{observatoryData.tests_failed}/{observatoryData.tests_quantity}</span></p>

            {/* Grade interpretation */}
            {(() => {
              const g = (observatoryData.grade || '').charAt(0);
              const gradeMap = {
                'A': { label: t('obsGradeA'), color: '#00d084', icon: '✅' },
                'B': { label: t('obsGradeB'), color: '#00d084', icon: '🟢' },
                'C': { label: t('obsGradeC'), color: '#ffb900', icon: '⚠️' },
                'D': { label: t('obsGradeD'), color: '#ff8c00', icon: '🔴' },
                'F': { label: t('obsGradeF'), color: '#e81123', icon: '🔴' },
              };
              const info = gradeMap[g];
              if (!info) return null;
              return (
                <div style={{ background: theme === 'light' ? 'rgba(255,255,255,0.6)' : 'rgba(0,0,0,0.4)', border: `1px solid ${info.color}`, borderRadius: '6px', padding: '0.75rem 1rem', marginTop: '0.5rem' }}>
                  <p style={{ margin: 0, fontWeight: 'bold', color: info.color }}>{info.icon} {info.label}</p>
                </div>
              );
            })()}

            {/* Remediation guidance for poor grades */}
            {observatoryData.tests_failed > 0 && (
              <div style={{ background: theme === 'light' ? 'rgba(255,255,255,0.6)' : 'rgba(0,0,0,0.4)', border: '1px solid #ffb900', borderRadius: '6px', padding: '0.75rem 1rem', marginTop: '0.75rem' }}>
                <p style={{ margin: '0 0 0.4rem 0', fontWeight: 'bold' }}>💡 {t('obsRecommendedFixes')}</p>
                <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.875rem', lineHeight: '1.7' }}>
                  <li><b>Content-Security-Policy (CSP)</b> — {t('obsCspDesc')}</li>
                  <li><b>Strict-Transport-Security (HSTS)</b> — {t('obsHstsDesc')}</li>
                  <li><b>X-Content-Type-Options: nosniff</b> — {t('obsXctoDesc')}</li>
                  <li><b>X-Frame-Options / CSP frame-ancestors</b> — {t('obsXfoDesc')}</li>
                  <li><b>Referrer-Policy</b> — {t('obsRpDesc')}</li>
                  <li><b>Permissions-Policy</b> — {t('obsPpDesc')}</li>
                </ul>
              </div>
            )}
          </div>
        ) : (
          <div className="report-summary" style={{ marginTop: '2rem', opacity: 0.7 }}>
            <h4>🔒 {t('mozillaObservatorySecurityConfiguration')}</h4>
            <p style={{ color: '#888' }}><i>{t('obsNoData')}</i></p>
          </div>
        )}

        {/* Download Reports Section */}
        {report?.analysisId && report?.status === 'completed' && (
          <div className="download-section">
            <h4>{t('downloadScanReports')}</h4>
            <p>
              {t('downloadCompleteSecurityResults')}
            </p>
            <div className="download-buttons">
              {/* PDF Download Dropdown */}
              <div className="pdf-dropdown-container">
                <button
                  className="download-btn download-btn--pdf"
                  disabled={pdfDownloading}
                  onClick={() => !pdfDownloading && setPdfDropdownOpen(!pdfDropdownOpen)}
                >
                  {pdfDownloading ? t('generating') : t('downloadPdfReport')}
                </button>

                {pdfDropdownOpen && !pdfDownloading && (
                  <div className="pdf-dropdown-menu">
                    <button
                      onClick={async () => {
                        setPdfDropdownOpen(false);
                        if (pdfDownloading) return; // Prevent duplicate clicks
                        try {
                          setPdfDownloading(true);
                          setPdfProgress(0);
                          setPdfProgressMessage(t('initializingEnglishPdf'));

                          const token = localStorage.getItem('token');
                          const startRes = await fetch(`${API_BASE}/api/scan/pdf-job`, {
                            method: 'POST',
                            headers: { 'x-auth-token': token, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ analysisId: report.analysisId || report.scanId || activeScanId, lang: 'en' })
                          });
                          if (!startRes.ok) {
                            const e = await startRes.json().catch(() => ({}));
                            throw new Error(e.error || 'Failed to start PDF generation');
                          }
                          const { jobId } = await startRes.json();

                          const progressSteps = [
                            { progress: 15, message: t('formattingScanData') },
                            { progress: 35, message: t('waitingRateLimit') },
                            { progress: 55, message: t('formattingAiAnalysis') },
                            { progress: 75, message: t('renderingPdfDocument') },
                            { progress: 90, message: t('finalizing') },
                          ];
                          let pollCount = 0;
                          let consecutive404 = 0; // Track transient 404s
                          const MAX_404_RETRIES = 3;

                          while (true) {
                            await new Promise(r => setTimeout(r, 5000));
                            pollCount++;
                            if (pollCount > 120) throw new Error('PDF generation timed out');

                            const stepIdx = Math.min(pollCount - 1, progressSteps.length - 1);
                            setPdfProgress(progressSteps[stepIdx].progress);
                            setPdfProgressMessage(progressSteps[stepIdx].message);

                            let pollRes;
                            try {
                              pollRes = await fetch(`${API_BASE}/api/scan/pdf-job/${jobId}`, {
                                headers: { 'x-auth-token': token }
                              });
                            } catch (networkErr) {
                              console.warn('PDF poll network error, retrying…', networkErr.message);
                              continue; // Retry on network failures
                            }

                            if (pollRes.status === 202) { consecutive404 = 0; continue; }

                            if (pollRes.status === 200) {
                              consecutive404 = 0;
                              setPdfProgress(100);
                              setPdfProgressMessage(t('downloadComplete'));
                              const blob = await pollRes.blob();
                              const url = window.URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = `security_report_EN_${report.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;
                              document.body.appendChild(a);
                              a.click();
                              window.URL.revokeObjectURL(url);
                              document.body.removeChild(a);
                              console.log('PDF EN report downloaded');
                              break;
                            }

                            // Handle 404 — may be transient Redis miss, retry before giving up
                            if (pollRes.status === 404) {
                              consecutive404++;
                              console.warn(`PDF poll returned 404 (attempt ${consecutive404}/${MAX_404_RETRIES})`);
                              if (consecutive404 < MAX_404_RETRIES) continue;
                              throw new Error('PDF job not found after multiple retries — it may have expired');
                            }

                            consecutive404 = 0;
                            const errorData = await pollRes.json().catch(() => ({}));
                            if (pollRes.status === 429 && errorData.errorCode === 'GEMINI_KEY_EXHAUSTED') {
                              alert(t('geminiKeyExhausted'));
                              throw new Error('Gemini key is exhausted');
                            }
                            if (errorData.errorCode === 'EN_CONTENT_NOT_ENGLISH' || errorData.errorCode === 'EN_TEMPLATE_NOT_ENGLISH') {
                              alert(t('englishPdfOnly'));
                              throw new Error(errorData.error || 'English-only validation failed');
                            }
                            throw new Error(errorData.error || 'PDF generation failed');
                          }

                          setTimeout(() => {
                            setPdfDownloading(false);
                            setPdfProgress(0);
                            setPdfProgressMessage('');
                          }, 2000);
                        } catch (err) {
                          console.error('PDF download failed:', err);
                          setPdfProgressMessage(`Error: ${err.message}`);
                          setTimeout(() => {
                            setPdfDownloading(false);
                            setPdfProgress(0);
                            setPdfProgressMessage('');
                          }, 3000);
                        }
                      }}
                    >
                      {t('englishVersion')}
                    </button>
                    <button
                      onClick={async () => {
                        setPdfDropdownOpen(false);
                        if (pdfDownloading) return; // Prevent duplicate clicks
                        try {
                          setPdfDownloading(true);
                          setPdfProgress(0);
                          setPdfProgressMessage(t('initializingJapanesePdf'));

                          const token = localStorage.getItem('token');
                          const startRes = await fetch(`${API_BASE}/api/scan/pdf-job`, {
                            method: 'POST',
                            headers: { 'x-auth-token': token, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ analysisId: report.analysisId || report.scanId || activeScanId, lang: 'ja' })
                          });
                          if (!startRes.ok) {
                            const e = await startRes.json().catch(() => ({}));
                            throw new Error(e.error || 'Failed to start PDF generation');
                          }
                          const { jobId } = await startRes.json();

                          const progressSteps = [
                            { progress: 10, message: t('formattingScanData') },
                            { progress: 25, message: t('waitingRateLimit') },
                            { progress: 40, message: t('formattingAiAnalysis') },
                            { progress: 55, message: t('waitingRateLimit') },
                            { progress: 70, message: t('translatingToJapanese') },
                            { progress: 85, message: t('renderingPdfDocument') },
                            { progress: 92, message: t('finalizing') },
                          ];
                          let pollCount = 0;
                          let consecutive404 = 0;
                          const MAX_404_RETRIES = 3;

                          while (true) {
                            await new Promise(r => setTimeout(r, 5000));
                            pollCount++;
                            if (pollCount > 120) throw new Error('PDF generation timed out');

                            const stepIdx = Math.min(pollCount - 1, progressSteps.length - 1);
                            setPdfProgress(progressSteps[stepIdx].progress);
                            setPdfProgressMessage(progressSteps[stepIdx].message);

                            let pollRes;
                            try {
                              pollRes = await fetch(`${API_BASE}/api/scan/pdf-job/${jobId}`, {
                                headers: { 'x-auth-token': token }
                              });
                            } catch (networkErr) {
                              console.warn('PDF poll network error, retrying…', networkErr.message);
                              continue;
                            }

                            if (pollRes.status === 202) { consecutive404 = 0; continue; }

                            if (pollRes.status === 200) {
                              consecutive404 = 0;
                              setPdfProgress(100);
                              setPdfProgressMessage(t('downloadComplete'));
                              const blob = await pollRes.blob();
                              const url = window.URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = `security_report_JA_${report.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.pdf`;
                              document.body.appendChild(a);
                              a.click();
                              window.URL.revokeObjectURL(url);
                              document.body.removeChild(a);
                              console.log('PDF JA report downloaded');
                              break;
                            }

                            if (pollRes.status === 404) {
                              consecutive404++;
                              console.warn(`PDF poll returned 404 (attempt ${consecutive404}/${MAX_404_RETRIES})`);
                              if (consecutive404 < MAX_404_RETRIES) continue;
                              throw new Error('PDF job not found after multiple retries — it may have expired');
                            }

                            consecutive404 = 0;
                            const errorData = await pollRes.json().catch(() => ({}));
                            if (pollRes.status === 429 && errorData.errorCode === 'GEMINI_KEY_EXHAUSTED') {
                              alert(t('geminiKeyExhausted'));
                              throw new Error('Gemini key is exhausted');
                            }
                            if (errorData.errorCode === 'EN_CONTENT_NOT_ENGLISH' || errorData.errorCode === 'EN_TEMPLATE_NOT_ENGLISH') {
                              alert(t('englishPdfOnly'));
                              throw new Error(errorData.error || 'English-only validation failed');
                            }
                            throw new Error(errorData.error || 'PDF generation failed');
                          }

                          setTimeout(() => {
                            setPdfDownloading(false);
                            setPdfProgress(0);
                            setPdfProgressMessage('');
                          }, 2000);
                        } catch (err) {
                          console.error('PDF download failed:', err);
                          setPdfProgressMessage(`Error: ${err.message}`);
                          setTimeout(() => {
                            setPdfDownloading(false);
                            setPdfProgress(0);
                            setPdfProgressMessage('');
                          }, 3000);
                        }
                      }}
                    >
                      {t('japaneseVersion')}
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
                    const response = await fetch(`${API_BASE}/api/scan/download-complete-json/${report.analysisId || report.scanId || activeScanId}`, {
                      headers: { 'x-auth-token': token }
                    });

                    if (!response.ok) {
                      throw new Error('Download failed');
                    }

                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `scan_report_${report.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    console.log('✅ Complete JSON report downloaded');
                  } catch (err) {
                    console.error('❌ Download failed:', err);
                    alert(t('failedDownloadReportTryAgain'));
                  }
                }}
              >
                {t('downloadJsonData')}
              </button>
            </div>

            {/* PDF Download Progress Bar */}
            {pdfDownloading && (
              <div className="pdf-progress-container">
                <div className="pdf-progress-bar">
                  <div
                    className="pdf-progress-fill"
                    style={{ width: `${pdfProgress}%` }}
                  />
                </div>
                <p className="pdf-progress-message">{pdfProgressMessage}</p>
                <p className="pdf-progress-note">
                  {t('pdfProgressNote')}
                </p>
              </div>
            )}

            <p className="download-note">
              {t('downloadNote')}
            </p>
          </div>
        )}
      </div>
    );
  };

  return (
    <section className="hero-container">
      <div className="hero-content">
        {isHistorical ? (
          <>
            {/* Historical scan header with animated back button */}
            <div className="historical-header">
              <button
                className="back-to-profile-btn"
                onClick={() => navigate('/profile')}
              >
                <span className="btn-icon">←</span>
                <span>{t('backToProfile')}</span>
              </button>
              <h2 className="historical-title">
                {t('historicalScan')}: <span className="highlight">{report?.target}</span>
              </h2>
            </div>
            <p className="historical-meta">
              {t('scannedOn')}: {report?.createdAt ? new Date(report.createdAt).toLocaleString(currentLang === 'ja' ? 'ja-JP' : 'en-US') : t('notAvailable')}
            </p>
          </>
        ) : (
          <>
            <h1 className="hero-title">{t('heroTitle')}</h1>
            
            {pendingSchedule && (
              <div className="scheduling-mode-banner" style={{ background: 'rgba(0, 176, 198, 0.1)', border: '1px solid var(--accent)', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', textAlign: 'center', color: 'var(--accent)' }}>
                <strong>{t('schedulingModeActive')}</strong><br/>
                {t('settingUpPublicScan', { date: pendingSchedule.date, time: pendingSchedule.time })}
              </div>
            )}
            
            <form className="analyze-form" onSubmit={handleSubmit}>
              <label htmlFor="url-input">{t('enterUrlToStart')}</label>
              <div className="input-wrapper">
                <input id="url-input" name="url" type="text" placeholder={t('urlExample')} value={scanUrl} onChange={(e) => setScanUrl(e.target.value)} required disabled={loading} />
                {!loading ? (
                  <div className="action-buttons" style={{ flexDirection: 'row' }}>
                    <button type="submit" className="analyze-button">
                      <span className="button-text">
                        {pendingSchedule ? t('saveScheduledScan') : t('analyzeUrl')}
                      </span>
                    </button>
                  </div>
                ) : (
                  <button type="button" onClick={handleStopScan} className="stop-button">
                    <span className="button-text">{t('stopScan')}</span>
                  </button>
                )}
              </div>
            </form>
            {loading && (
              <p style={{ marginTop: '0.75rem', fontSize: '0.82rem', color: 'rgba(255,255,255,0.5)', textAlign: 'center', letterSpacing: '0.01em' }}>
                ⚠ {t('scanNotice')}
              </p>
            )}
          </>
        )}
        {renderReport()}
      </div>
    </section>
  );
};

export default Hero;

