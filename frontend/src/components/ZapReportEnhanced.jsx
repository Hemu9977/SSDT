// Enhanced ZAP Report Display Component
// Shows vulnerabilities grouped by type with expandable URL lists
// File: frontend/src/components/ZapReportEnhanced.jsx

import React, { useState, useEffect } from 'react';
import '../styles/ZapReportEnhanced.scss';

const API_BASE = 'http://localhost:3001';

const ZapReportEnhanced = ({ zapData, scanId, apiPrefix = '/api/zap' }) => {
    const [expandedAlerts, setExpandedAlerts] = useState(new Set());
    const [downloadingDetailed, setDownloadingDetailed] = useState(false);
    const [pdfDropdownOpen, setPdfDropdownOpen] = useState(false);
    const [downloadingPdf, setDownloadingPdf] = useState(false);
    const [pdfLang, setPdfLang] = useState(null); // Track which language is downloading

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

    if (!zapData || !zapData.alerts) {
        return null;
    }

    const toggleAlert = (alertName) => {
        const newExpanded = new Set(expandedAlerts);
        if (newExpanded.has(alertName)) {
            newExpanded.delete(alertName);
        } else {
            newExpanded.add(alertName);
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
            alert('Failed to download detailed report');
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
                    alert('Gemini key is exhausted');
                    throw new Error('Gemini key is exhausted');
                }
                if (response.status === 400 && (errorData.errorCode === 'EN_CONTENT_NOT_ENGLISH' || errorData.errorCode === 'EN_TEMPLATE_NOT_ENGLISH')) {
                    alert('English PDF must contain English only');
                    throw new Error(errorData.error || 'English-only validation failed');
                }
                throw new Error(errorData.error || 'PDF download failed');
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
            alert(`Failed to download PDF report: ${error.message}`);
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

    return (
        <div className="zap-report-enhanced">
            <div className="report-header">
                <h3>⚡ Vulnerability Analysis Results</h3>
                <div className="report-stats">
                    <span className="stat">
                        <strong>{zapData.totalAlerts}</strong> Alert Types
                    </span>
                    <span className="stat">
                        <strong>{zapData.totalOccurrences}</strong> Total Occurrences
                    </span>
                    <button
                        onClick={downloadDetailedReport}
                        disabled={downloadingDetailed}
                        className="download-btn"
                    >
                        {downloadingDetailed ? 'Downloading...' : '📥 JSON Report'}
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
                            {downloadingPdf ? `Generating ${pdfLang?.toUpperCase()}...` : '📄 PDF Report ▼'}
                        </button>
                        {pdfDropdownOpen && (
                            <div className="zap-pdf-dropdown">
                                <button
                                    onClick={() => downloadPdfReport('en')}
                                    className="dropdown-item"
                                >
                                    🇺🇸 English PDF
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
                            {getRiskIcon(risk)} {risk}: {count}
                        </div>
                    )
                ))}
            </div>

            {/* Alert List */}
            <div className="alerts-list">
                {zapData.alerts.map((alert, idx) => {
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
                                        {alert.totalOccurrences} occurrence{alert.totalOccurrences !== 1 ? 's' : ''}
                                    </span>
                                </div>
                                <div className="alert-meta">
                                    <span className={`risk-label risk-${alert.risk.toLowerCase()}`}>
                                        {alert.risk}
                                    </span>
                                    <span className="expand-icon">
                                        {isExpanded ? '▼' : '▶'}
                                    </span>
                                </div>
                            </div>

                            {isExpanded && (
                                <div className="alert-details">
                                    <div className="detail-section">
                                        <h4>Description</h4>
                                        <p>{alert.description}</p>
                                    </div>

                                    <div className="detail-section">
                                        <h4>Solution</h4>
                                        <p>{alert.solution}</p>
                                    </div>

                                    <div className="detail-section">
                                        <h4>Affected URLs ({alert.sampleUrls.length} shown{alert.hasMoreUrls ? ', more in full report' : ''})</h4>
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
                                                ⚠️ This vulnerability affects {alert.totalOccurrences} URLs total.
                                                Download the full report to see all affected URLs.
                                            </p>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>

            {zapData.alerts.length === 0 && (
                <div className="no-alerts">
                    ✅ No security vulnerabilities detected. Great job!
                </div>
            )}
        </div>
    );
};

export default ZapReportEnhanced;
