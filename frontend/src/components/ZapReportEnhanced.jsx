// Enhanced ZAP Report Display Component
// Shows vulnerabilities grouped by type with expandable URL lists
// File: frontend/src/components/ZapReportEnhanced.jsx

import React, { useState, useEffect } from 'react';
import '../styles/ZapReportEnhanced.scss';

import { API_BASE } from '../config/api';
import { useTranslation } from '../contexts/TranslationContext';

const ZapReportEnhanced = ({ zapData, scanId, apiPrefix = '/api/zap', currentLang = 'ja' }) => {
    const { t } = useTranslation();
    const [expandedAlerts, setExpandedAlerts] = useState(new Set());
    const [downloadingDetailed, setDownloadingDetailed] = useState(false);
    const [pdfDropdownOpen, setPdfDropdownOpen] = useState(false);
    const [downloadingPdf, setDownloadingPdf] = useState(false);
    const [pdfLang, setPdfLang] = useState(null); // Track which language is downloading
    const [translatedAlerts, setTranslatedAlerts] = useState(null);
    const [isTranslating, setIsTranslating] = useState(false);
    const translateFetchedRef = React.useRef(false); // tracks if fetch was initiated for current scan+lang

    // Raw request/response evidence (occurrences with request/response), fetched
    // lazily from the detailed-report endpoint on first alert expansion.
    const [detailedMap, setDetailedMap] = useState(null); // { [alertName]: occurrences[] }
    const [rawExpandedAll, setRawExpandedAll] = useState(new Set()); // alert names showing all pairs
    const detailedFetchedRef = React.useRef(false);
    const RAW_PREVIEW_COUNT = 3;

    // Close PDF dropdown when clicking outside
    useEffect(() => {
        const handleClickOutside = (e) => {
            if (pdfDropdownOpen && !e.target.closest('.zap-pdf-dropdown-container')) {
                setPdfDropdownOpen(false);
            }
        };
        document.addEventListener('click', handleClickOutside);
        return () => document.removeEventListener('click', handleClickOutside);
    }, [pdfDropdownOpen]);

    // Translate dynamic ZAP alert content (names, descriptions, solutions) via Gemini.
    // Uses a ref guard + AbortController to prevent double-fetch in React StrictMode.
    useEffect(() => {
        if (currentLang !== 'ja') {
            setTranslatedAlerts(null);
            translateFetchedRef.current = false;
            return;
        }
        if (!zapData?.alerts?.length) return;
        if (translateFetchedRef.current) return; // already fetching or fetched for this scan

        translateFetchedRef.current = true;
        const controller = new AbortController();
        const alerts = zapData.alerts;
        // Flat text array: [name0, desc0, sol0, name1, desc1, sol1, ...]
        const texts = alerts.flatMap(a => [a.alert, a.description, a.solution]);

        setIsTranslating(true);
        fetch(`${API_BASE}/api/translate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': localStorage.getItem('token')
            },
            body: JSON.stringify({ texts, targetLang: 'ja' }),
            signal: controller.signal
        })
            .then(r => r.json())
            .then(data => {
                if (!data.translated) return;
                const translated = data.translated;
                const result = alerts.map((a, i) => ({
                    ...a,
                    _enAlert: a.alert, // preserve English name for detailed-alert lookup
                    alert: translated[i * 3] || a.alert,
                    description: translated[i * 3 + 1] || a.description,
                    solution: translated[i * 3 + 2] || a.solution,
                }));
                setTranslatedAlerts(result);
            })
            .catch(err => { if (err.name !== 'AbortError') console.error('ZAP translation error:', err); })
            .finally(() => setIsTranslating(false));

        return () => { controller.abort(); translateFetchedRef.current = false; };
    }, [currentLang, zapData?.alerts]);

    if (!zapData || !zapData.alerts) {
        return null;
    }

    // Lazily fetch the GridFS detailed alerts (occurrences incl. raw
    // request/response) once, the first time any alert is expanded. If the
    // historical loader already supplied zapData.detailedAlerts, use that instead.
    const ensureDetailedLoaded = async () => {
        if (detailedFetchedRef.current) return;
        if (zapData?.detailedAlerts?.length) return; // already available on props
        if (!scanId) return;
        detailedFetchedRef.current = true;
        try {
            const res = await fetch(`${API_BASE}${apiPrefix}/detailed-report/${scanId}`, {
                headers: { 'x-auth-token': localStorage.getItem('token') }
            });
            if (!res.ok) throw new Error('Failed to load detailed report');
            const data = await res.json();
            const map = {};
            (Array.isArray(data) ? data : []).forEach(a => {
                if (a && a.alert) map[a.alert] = Array.isArray(a.occurrences) ? a.occurrences : [];
            });
            setDetailedMap(map);
        } catch (err) {
            console.warn('Failed to load ZAP request/response evidence:', err.message);
            detailedFetchedRef.current = false; // allow a later retry
        }
    };

    // Occurrences (with raw request/response) for a given alert name.
    // Returns null when detailed data has not loaded yet.
    const getRawOccurrences = (alertName) => {
        let occ = null;
        if (zapData?.detailedAlerts?.length) {
            const d = zapData.detailedAlerts.find(a => (a.alert || a.name) === alertName);
            occ = d?.occurrences || [];
        } else if (detailedMap) {
            occ = detailedMap[alertName] || [];
        }
        if (occ === null) return null;
        return occ.filter(o => o && (o.request || o.response));
    };

    const toggleRawAll = (alertName) => {
        const next = new Set(rawExpandedAll);
        next.has(alertName) ? next.delete(alertName) : next.add(alertName);
        setRawExpandedAll(next);
    };

    const toggleAlert = (alertName) => {
        const newExpanded = new Set(expandedAlerts);
        if (newExpanded.has(alertName)) {
            newExpanded.delete(alertName);
        } else {
            newExpanded.add(alertName);
            ensureDetailedLoaded(); // fire-and-forget on first expand
        }
        setExpandedAlerts(newExpanded);
    };

    const downloadDetailedReport = async () => {
        setDownloadingDetailed(true);
        try {
            const response = await fetch(`${API_BASE}${apiPrefix}/detailed-report/${scanId}`, {
                headers: {
                    'x-auth-token': localStorage.getItem('token')
                }
            });

            if (!response.ok) throw new Error('Download failed');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `zap_detailed_report_${scanId}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error('Download error:', error);
            alert(t('failedDownloadDetailedReport'));
        } finally {
            setDownloadingDetailed(false);
        }
    };

    const downloadPdfReport = async (lang) => {
        setDownloadingPdf(true);
        setPdfLang(lang);
        setPdfDropdownOpen(false);
        try {
            const response = await fetch(`${API_BASE}${apiPrefix}/detailed-report-pdf/${scanId}?lang=${lang}`, {
                headers: {
                    'x-auth-token': localStorage.getItem('token')
                }
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                if (response.status === 429 && errorData.errorCode === 'GEMINI_KEY_EXHAUSTED') {
                    alert(t('geminiKeyExhausted'));
                    throw new Error(t('geminiKeyExhausted'));
                }
                if (response.status === 400 && (errorData.errorCode === 'EN_CONTENT_NOT_ENGLISH' || errorData.errorCode === 'EN_TEMPLATE_NOT_ENGLISH')) {
                    alert(t('englishPdfOnly'));
                    throw new Error(errorData.error || 'English-only validation failed');
                }
                throw new Error(errorData.error || t('pdfDownloadFailed'));
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `zap_vulnerability_report_${scanId}_${lang}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error('PDF download error:', error);
            alert(t('failedDownloadPdfReport', { message: t(error.messageKey || 'errUnexpected') }));
        } finally {
            setDownloadingPdf(false);
            setPdfLang(null);
        }
    };

    const getRiskColor = (risk) => {
        switch (risk) {
            case 'High': return '#e81123';
            case 'Medium': return '#ff8c00';
            case 'Low': return '#ffb900';
            default: return '#00d084';
        }
    };

    const getRiskIcon = (risk) => {
        switch (risk) {
            case 'High': return '🔴';
            case 'Medium': return '🟠';
            case 'Low': return '🟡';
            default: return '🔵';
        }
    };

    const riskLabels = {
        'High': t('high'),
        'Medium': t('medium'),
        'Low': t('low'),
        'Informational': t('informational'),
    };

    const displayAlerts = (currentLang === 'ja' && translatedAlerts) ? translatedAlerts : zapData.alerts;

    return (
        <div className="zap-report-enhanced">
            <div className="report-header">
                <h3>{t('vulnerabilityAnalysisResults')}</h3>
                <div className="report-stats">
                    <span className="stat">
                        <strong>{zapData.totalAlerts}</strong> {t('alertTypes')}
                    </span>
                    <span className="stat">
                        <strong>{zapData.totalOccurrences}</strong> {t('totalOccurrences')}
                    </span>
                    <button
                        onClick={downloadDetailedReport}
                        disabled={downloadingDetailed}
                        className="download-btn"
                    >
                        {downloadingDetailed ? t('downloading') : `📥 ${t('jsonReport')}`}
                    </button>

                    {/* PDF Download Dropdown */}
                    <div className="zap-pdf-dropdown-container">
                        <button
                            onClick={(e) => {
                                e.stopPropagation();
                                setPdfDropdownOpen(!pdfDropdownOpen);
                            }}
                            disabled={downloadingPdf}
                            className="download-btn pdf-btn"
                        >
                            {downloadingPdf ? t('generatingLang', { lang: pdfLang?.toUpperCase() }) : `📄 ${t('pdfReport')} ▼`}
                        </button>
                        {pdfDropdownOpen && (
                            <div className="zap-pdf-dropdown">
                                <button
                                    onClick={() => downloadPdfReport('en')}
                                    className="dropdown-item"
                                >
                                    🇺🇸 {t('englishPdf')}
                                </button>
                                <button
                                    onClick={() => downloadPdfReport('ja')}
                                    className="dropdown-item"
                                >
                                    🇯🇵 日本語 PDF
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Risk Summary */}
            <div className="risk-summary">
                {Object.entries(zapData.riskCounts || {}).map(([risk, count]) => (
                    count > 0 && (
                        <div key={risk} className={`risk-badge risk-${risk.toLowerCase()}`}>
                            {getRiskIcon(risk)} {riskLabels[risk] || risk}: {count}
                        </div>
                    )
                ))}
            </div>

            {/* Translation status */}
            {isTranslating && (
                <p style={{ color: 'var(--accent)', padding: '0.5rem 0' }}>🌐 {t('translatingVulnerabilityData')}</p>
            )}

            {/* Alert List */}
            <div className="alerts-list">
                {displayAlerts.map((alert, idx) => {
                    const isExpanded = expandedAlerts.has(alert.alert);

                    return (
                        <div key={idx} className="alert-card">
                            <div
                                className="alert-header"
                                onClick={() => toggleAlert(alert.alert)}
                                style={{ borderLeftColor: getRiskColor(alert.risk) }}
                            >
                                <div className="alert-title">
                                    <span className="alert-icon">{getRiskIcon(alert.risk)}</span>
                                    <span className="alert-name">{alert.alert}</span>
                                    <span className="occurrence-count">
                                        {alert.totalOccurrences} {alert.totalOccurrences !== 1 ? t('occurrences') : t('occurrence')}
                                    </span>
                                </div>
                                <div className="alert-meta">
                                    <span className={`risk-label risk-${alert.risk.toLowerCase()}`}>
                                        {riskLabels[alert.risk] || alert.risk}
                                    </span>
                                    <span className="expand-icon">
                                        {isExpanded ? '▼' : '▶'}
                                    </span>
                                </div>
                            </div>

                            {isExpanded && (
                                <div className="alert-details">
                                    <div className="detail-section">
                                        <h4>{t('description')}</h4>
                                        <p>{alert.description}</p>
                                    </div>

                                    <div className="detail-section">
                                        <h4>{t('solution')}</h4>
                                        <p>{alert.solution}</p>
                                    </div>

                                    <div className="detail-section">
                                        <h4>{t('affectedUrls', { count: alert.sampleUrls.length, more: alert.hasMoreUrls ? t('moreInFullReport') : '' })}</h4>
                                        <ul className="url-list">
                                            {alert.sampleUrls.map((url, urlIdx) => (
                                                <li key={urlIdx} className="url-item">
                                                    <span className="url-icon">🔗</span>
                                                    <a
                                                        href={url}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="url-link"
                                                    >
                                                        {url}
                                                    </a>
                                                </li>
                                            ))}
                                        </ul>
                                        {alert.hasMoreUrls && (
                                            <p className="more-urls-notice">
                                                ⚠️ {t('vulnerabilityAffectsUrls', { count: alert.totalOccurrences })}
                                            </p>
                                        )}
                                    </div>

                                    {(() => {
                                        const enName = alert._enAlert || alert.alert; // detailed data is keyed by English name
                                        const rawOccs = getRawOccurrences(enName);
                                        const showAll = rawExpandedAll.has(enName);
                                        return (
                                            <div className="detail-section raw-evidence">
                                                <h4>🧾 {t('requestResponseEvidence')}</h4>
                                                {rawOccs === null && (
                                                    <p className="raw-loading">{t('loadingEvidence')}</p>
                                                )}
                                                {rawOccs && rawOccs.length === 0 && (
                                                    <p className="raw-empty">{t('noEvidenceCaptured')}</p>
                                                )}
                                                {rawOccs && rawOccs.length > 0 && (
                                                    <>
                                                        {(showAll ? rawOccs : rawOccs.slice(0, RAW_PREVIEW_COUNT)).map((occ, occIdx) => (
                                                            <div key={occIdx} className="raw-occurrence">
                                                                <div className="raw-occ-meta">
                                                                    {occ.method && <span className="raw-method">{occ.method}</span>}
                                                                    <span className="raw-url">{occ.url}</span>
                                                                    {occ.param && <span className="raw-param">({occ.param})</span>}
                                                                </div>
                                                                {occ.request && (
                                                                    <div className="raw-pair">
                                                                        <div className="raw-label raw-label-req">{t('evidenceRequest')}</div>
                                                                        <pre className="raw-block">{`${occ.request.header || ''}${occ.request.body || ''}`}</pre>
                                                                    </div>
                                                                )}
                                                                {occ.response && (
                                                                    <div className="raw-pair">
                                                                        <div className="raw-label raw-label-resp">{t('evidenceResponse')}</div>
                                                                        <pre className="raw-block">{`${occ.response.header || ''}${occ.response.body || ''}`}</pre>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ))}
                                                        {rawOccs.length > RAW_PREVIEW_COUNT && (
                                                            <button
                                                                type="button"
                                                                className="raw-toggle-btn"
                                                                onClick={() => toggleRawAll(enName)}
                                                            >
                                                                {showAll ? t('showLessEvidence') : t('showAllEvidence', { count: rawOccs.length })}
                                                            </button>
                                                        )}
                                                        <p className="raw-json-note">{t('evidenceFullInJson')}</p>
                                                    </>
                                                )}
                                            </div>
                                        );
                                    })()}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>

            {displayAlerts.length === 0 && (
                <div className="no-alerts">
                    ✅ {t('noVulnerabilities')}
                </div>
            )}
        </div>
    );
};

export default ZapReportEnhanced;
