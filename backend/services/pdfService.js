'use strict';

/**
 * pdfService.js
 * Generates single-language (English or Japanese) security scan PDF reports.
 * Depends on: reportLocalization.js (all prose localization and the language
 * gate), zapDetailedAlerts.js (GridFS), ScanResult model, i18n/reportStrings.js.
 *
 * A report whose prose cannot be fully localized is never rendered: both
 * generators reject with code REPORT_LOCALIZATION_INCOMPLETE instead.
 *
 * Usage:
 *   const { generateSingleLanguagePdf, generateZapPdf } = require('./pdfService');
 *   const pdfBuffer = await generateSingleLanguagePdf(scanResult, 'en');
 *   const pdfBuffer = await generateZapPdf(scanResult, 'ja');
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getSanitizedAlerts } = require('../utils/vulnFilter');
const { isHstsEnabled } = require('./inHouse/siteChecks');
const { redactHeaderBlock } = require('../utils/credentialRedaction');

const ScanResult = require('../models/ScanResult');
const { formatAiAnalysisForPdf } = require('./geminiService');
const { loadReportAlerts, detailedAlertsBucket } = require('./zapDetailedAlerts');
const { getReportTemplateStaticContent } = require('./reportTemplateDocx');
const { localizeReport, engineVersion } = require('./reportLocalization');
const { t, riskLabel, confidenceLabel, statusLabel } = require('../i18n/reportStrings');
const { lighthouseScores, formatScore, formatMetric, NOT_AVAILABLE } = require('../utils/scoreFormat');

// ─── Config ────────────────────────────────────────────────────────────────────
const pdfOpts = { maxRetries: 1, timeoutMs: 35000, maxBackoffMs: 3000 };

// Localization: every report's prose goes through services/reportLocalization.js.
// It either returns fully localized prose or throws REPORT_LOCALIZATION_INCOMPLETE
// before anything is rendered, so a mixed-language PDF is never produced.

// Identifies what a generated PDF was built with. A PDF job records it, and a
// finished job is reused only while it matches (services/pdfJobStore.js), so a
// report built by older code is never served as a new one after a deploy.
// Bump RENDERER_REVISION whenever the rendered output changes.
// r4: HTTP Basic reports lose the extra scope section; HSTS read via isHstsEnabled.
const RENDERER_REVISION = 4;
let reportVersionMemo = null;
function reportVersion() {
  if (!reportVersionMemo) {
    reportVersionMemo = `r${RENDERER_REVISION}-${crypto.createHash('sha256').update(engineVersion()).digest('hex').slice(0, 12)}`;
  }
  return reportVersionMemo;
}

// Request/Response evidence: keep the headers (that's the proof for header/config
// findings) but only a short "taste" of the body — a full HTTP response body is an
// entire HTML page and would balloon the PDF to hundreds of pages. The complete,
// untruncated request/response for every occurrence always lives in the JSON export.
const EVIDENCE_BODY_MAX_CHARS = 600;   // short body snippet
const EVIDENCE_HEADER_MAX_CHARS = 4000; // generous safety net; real headers fit easily

/**
 * Build a bounded evidence blob: full header (capped as a safety net) + a short body
 * snippet, with a localized "full body in JSON export" note when anything is trimmed.
 * Pure — exported for tests.
 */
function buildEvidenceText(header, body, lang = 'en') {
  // Credential headers (Authorization, Cookie, Set-Cookie values) are never drawn,
  // whatever the caller passed in. Findings normally arrive already redacted
  // (getSanitizedAlerts); this is the last line for anything that did not.
  let hdr = redactHeaderBlock(String(header || ''));
  let bdy = String(body || '');
  let trimmed = false;
  const binary = isBinaryBody(bdy);

  if (hdr.length > EVIDENCE_HEADER_MAX_CHARS) { hdr = hdr.slice(0, EVIDENCE_HEADER_MAX_CHARS); trimmed = true; }
  if (binary) bdy = '';
  else if (bdy.length > EVIDENCE_BODY_MAX_CHARS) { bdy = bdy.slice(0, EVIDENCE_BODY_MAX_CHARS); trimmed = true; }

  let out = hdr;
  const append = s => { out += (out && !out.endsWith('\n') ? '\n' : '') + s; };
  if (bdy) append(bdy);
  if (binary) append(t(lang, 'binaryBody'));
  if (trimmed) append(t(lang, 'bodyTruncated'));
  return out;
}

/**
 * True when a body is mostly undecodable bytes — an image, font or compressed
 * response decoded as UTF-8. It carries no readable evidence and would otherwise
 * render as a wall of U+FFFD / control characters.
 */
function isBinaryBody(body) {
  const sample = String(body || '').slice(0, 2048);
  if (!sample) return false;
  if (sample.includes('\u0000')) return true;
  const junk = sample.match(/[\uFFFD\u0001-\u0008\u000B\u000C\u000E-\u001F]/g);
  return !!junk && junk.length / sample.length > 0.1;
}

const FONTS = {
  regular: path.join(__dirname, '../fonts/NotoSansJP-Regular.ttf'),
  bold:    path.join(__dirname, '../fonts/NotoSansJP-Bold.ttf')
};

const COLORS = {
  primary:    '#21525F',
  accent:     '#F08A1F',
  success:    '#22c55e',
  warning:    '#f59e0b',
  danger:     '#ef4444',
  info:       '#3b82f6',
  text:       '#1f2937',
  textLight:  '#6b7280',
  border:     '#BFBFBF',
  background: '#ffffff'
};

const ASSETS_DIR = path.join(__dirname, '../assets');
const TEMPLATE_IMAGES = {
  coverBg:   path.join(ASSETS_DIR, 'image1.jpeg'),
  frameBg:   path.join(ASSETS_DIR, 'image3.jpeg'),
  logo:      path.join(ASSETS_DIR, 'image2.jpeg'),
  logoLarge: path.join(ASSETS_DIR, 'image3.jpeg'),
};

const TEMPLATE_PAGE   = { width: 595.28, height: 841.89 };
const TEMPLATE_MARGIN = { top: 60, bottom: 60, left: 55, right: 55 };

// ─── Small utilities ────────────────────────────────────────────────────────────

function buildAiAnalysisFromRefinedReport(refinedReport) {
  try {
    const lines = refinedReport.split('\n');
    const sections = [];
    let currentSection = { heading: '', content: [] };
    let currentParagraph = [];
    let currentList = [];

    const pushParagraph = () => {
      if (currentParagraph.length) {
        currentSection.content.push({ type: 'paragraph', text: currentParagraph.join(' ') });
        currentParagraph = [];
      }
    };
    const pushList = () => {
      if (currentList.length) {
        currentSection.content.push({ type: 'bullets', items: currentList });
        currentList = [];
      }
    };

    for (const line of lines) {
      // Inline-code backticks (`Strict-Transport-Security`) were drawn literally;
      // keep what is inside them.
      const trimmed = line.trim().replace(/`([^`\n]+)`/g, '$1');
      if (!trimmed) {
        pushParagraph();
        pushList();
        continue;
      }

      if (trimmed.startsWith('#')) {
        pushParagraph();
        pushList();
        if (currentSection.heading || currentSection.content.length) {
          sections.push(currentSection);
        }
        currentSection = { heading: trimmed.replace(/^#+\s*/, ''), content: [] };
      } else if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
        pushParagraph();
        currentList.push(trimmed.substring(2).trim());
      } else {
        pushList();
        currentParagraph.push(trimmed);
      }
    }
    pushParagraph();
    pushList();
    if (currentSection.heading || currentSection.content.length) {
      sections.push(currentSection);
    }
    
    if (!sections.length && lines.length) {
       sections.push({ heading: 'Analysis', content: [{ type: 'paragraph', text: refinedReport }] });
    }

    return {
      title: 'AI-Generated Security Analysis',
      sections: sections
    };
  } catch (e) {
    return null;
  }
}


function containsJapanese(text) {
  return /[\u3040-\u30ff\u3400-\u9fff]/.test(String(text || ''));
}

function decodeHtmlEntities(input) {
  const s = String(input || '');
  if (!s.includes('&')) return s;
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
      const cp = parseInt(hex, 16);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : _;
    })
    .replace(/&#(\d+);/g, (_, dec) => {
      const cp = parseInt(dec, 10);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : _;
    });
}

function decodeLiteralBackslashEscapes(input) {
  let s = String(input || '');
  if (!s.includes('\\')) return s;
  s = s
    .replace(/\\r\\n/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\r/g, '\r');
  s = s.replace(/\\u\{([0-9a-fA-F]+)\}/g, (m, hex) => {
    const cp = parseInt(hex, 16);
    return Number.isFinite(cp) ? String.fromCodePoint(cp) : m;
  });
  s = s.replace(/\\u([0-9a-fA-F]{4})/g, (m, hex) => {
    const cp = parseInt(hex, 16);
    return Number.isFinite(cp) ? String.fromCharCode(cp) : m;
  });
  return s;
}

function sanitizeTextForPdf(input, lang) {
  let s = String(input ?? '');
  if (!s) return s;

  // Decode common encodings that sometimes leak from LLM output.
  s = decodeHtmlEntities(s);

  // For Japanese PDFs, also decode literal backslash escapes and normalize.
  if (lang === 'ja') {
    s = decodeLiteralBackslashEscapes(s);
    try { s = s.normalize('NFKC'); } catch {}
  }

  // Drop control chars (except tab/newline) and invisible bidi/ZW chars.
  s = s
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '');

  // Normalize newlines/whitespace.
  s = s.replace(/\r\n/g, '\n');
  s = s.replace(/[ \t]+\n/g, '\n');
  s = s.replace(/\n{4,}/g, '\n\n\n');
  return s.trim();
}


function getRiskColor(risk) {
  if (!risk) return COLORS.textLight;
  const r = String(risk).toLowerCase();
  if (r.includes('high')   || r.includes('高')) return COLORS.danger;
  if (r.includes('medium') || r.includes('中')) return COLORS.warning;
  if (r.includes('low')    || r.includes('低')) return COLORS.info;
  return COLORS.success;
}

function getTypeColor(type) {
  return { danger: COLORS.danger, warning: COLORS.warning,
           success: COLORS.success, info: COLORS.info }[type] || COLORS.text;
}

function stripBoldMarkers(text) { return String(text || '').replace(/\*\*/g, ''); }

function isBoldBalanced(text) {
  const m = String(text || '').match(/\*\*/g);
  return !m || m.length % 2 === 0;
}

// ─── Disclaimer / history helpers ───────────────────────────────────────────────

function formatHistoryDate(date, lang) {
  const d = date instanceof Date ? date : (date ? new Date(date) : null);
  if (!d || isNaN(d.getTime())) return '';
  const [y, mo, dd, h, mi] = [
    d.getFullYear(), String(d.getMonth() + 1).padStart(2, '0'),
    String(d.getDate()).padStart(2, '0'), String(d.getHours()).padStart(2, '0'),
    String(d.getMinutes()).padStart(2, '0')
  ];
  // Spec: JA => YYYY/MM/DD, EN => DD/MM/YYYY
  return lang === 'ja' ? `${y}/${mo}/${dd}` : `${dd}/${mo}/${y}`;
}

/**
 * Format a date for the PDF cover page.
 * EN => "June 30, 2026"  (human-readable month name)
 * JA => "2026年6月30日"   (standard Japanese date)
 */
function formatCoverDate(date, lang) {
  const d = date instanceof Date ? date : (date ? new Date(date) : null);
  if (!d || isNaN(d.getTime())) return '';
  if (lang === 'ja') {
    return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
  }
  const months = ['January','February','March','April','May','June',
                  'July','August','September','October','November','December'];
  return `${months[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
}

function projectLangValue(val, lang) {
  if (val && typeof val === 'object' && !Array.isArray(val)) {
    if (Object.prototype.hasOwnProperty.call(val, lang)) return val[lang];
    if (Object.prototype.hasOwnProperty.call(val, 'en') || Object.prototype.hasOwnProperty.call(val, 'ja')) {
      return val[lang] ?? val.en ?? val.ja;
    }
  }
  return val;
}

function executorDisplay(user, lang) {
  const name  = user?.name  ? String(user.name)  : '';
  const email = user?.email ? String(user.email) : '';
  // English PDFs must remain English-only: never emit Japanese characters.
  if (lang !== 'ja') {
    if (email) return email;
    if (name && !containsJapanese(name)) return name;
    return 'Unknown';
  }
  if (name) return name;
  if (email) return email;
  if (name)  return name;
  return lang === 'ja' ? '（不明）' : 'Unknown';
}

function getStatusLabel(status, lang) {
  return statusLabel(status, lang);
}

async function fetchScanHistoryRows(scanResult, limit = 8) {
  const fallback = [{
    dateEn: formatHistoryDate(scanResult?.createdAt, 'en') || '',
    dateJa: formatHistoryDate(scanResult?.createdAt, 'ja') || '',
    executedByEn: executorDisplay(scanResult?.userId, 'en'),
    executedByJa: executorDisplay(scanResult?.userId, 'ja'),
    status: scanResult?.status || 'unknown'
  }];

  if (!scanResult?.userId) return fallback;

  try {
    // Scoped to THIS target. Without the filter the table listed the operator's
    // recent scans across every target, so a report delivered to one client
    // disclosed when other clients' sites were scanned — and the table did not
    // mean what its heading claimed.
    const records = await ScanResult.find({ userId: scanResult.userId, target: scanResult.target })
      .sort({ createdAt: -1 }).limit(limit)
      .select('analysisId target createdAt userId status')
      .populate('userId', 'name email').lean();

    const rows = (records || []).map(r => ({
      dateEn: formatHistoryDate(r.createdAt, 'en'),
      dateJa: formatHistoryDate(r.createdAt, 'ja'),
      executedByEn: executorDisplay(r.userId, 'en'),
      executedByJa: executorDisplay(r.userId, 'ja'),
      status: r.status || 'unknown'
    }));

    return rows.length ? rows : fallback;
  } catch {
    return fallback;
  }
}

/**
 * The Scan History table, built from the database rows. Pure.
 *
 * It used to be whatever Gemini returned: the rows (with the operator's name and
 * email) went to Gemini unsanitized, and Gemini could copy the Japanese name or a
 * Japanese status label into an English row. Nothing in this table needs a model.
 */
function buildScanHistoryTable(scanHistoryRows) {
  const rows = Array.isArray(scanHistoryRows) ? scanHistoryRows : [];
  return {
    title: { en: t('en', 'scanHistory'), ja: t('ja', 'scanHistory') },
    headers: {
      en: ['historyDate', 'historyExecutedBy', 'historyStatus'].map(k => t('en', k)),
      ja: ['historyDate', 'historyExecutedBy', 'historyStatus'].map(k => t('ja', k))
    },
    rows: {
      en: rows.map(r => [r.dateEn || '', r.executedByEn || '', getStatusLabel(r.status, 'en')]),
      ja: rows.map(r => [r.dateJa || '', r.executedByJa || '', getStatusLabel(r.status, 'ja')])
    }
  };
}

/**
 * Fill scanData's header (target, scan ID, date) and threat-reputation items
 * (domain, server IP, country) from the scan itself.
 *
 * If a value is genuinely unavailable, logs an explicit warning and sets "N/A".
 */
function injectRealScanMetadata(scanData, scanResult) {
  if (!scanData || !scanData.header) {
    scanData = scanData || {};
    scanData.header = scanData.header || {};
  }

  // ── Scan URL ──
  const realTarget = scanResult?.target;
  if (realTarget && realTarget !== 'REDACTED') {
    scanData.header.target = realTarget;
  } else if (!realTarget) {
    console.warn('[PDF] Missing scan URL');
    scanData.header.target = 'N/A';
  } else if (realTarget === 'REDACTED') {
    // scanResult itself should never have REDACTED — defensive guard
    console.warn('[PDF] Missing scan URL');
    scanData.header.target = 'N/A';
  }

  // ── Scan ID / Analysis ID ──
  const realId = scanResult?.analysisId;
  if (realId && realId !== 'REDACTED') {
    scanData.header.scanId = realId;
  } else if (!realId) {
    console.warn('[PDF] Missing scan ID');
    scanData.header.scanId = 'N/A';
  } else if (realId === 'REDACTED') {
    console.warn('[PDF] Missing scan ID');
    scanData.header.scanId = 'N/A';
  }

  // ── Date — store raw Date so renderCoverPage() can format per-language ──
  scanData.header.dateRaw = scanResult?.createdAt || new Date();

  // ── Threat Reputation Metadata ──
  const realUrlscan = scanResult?.urlscanResult || scanResult?.urlscanData;
  let fallbackDomain = 'N/A';
  if (scanResult?.target && scanResult.target !== 'REDACTED') {
    try {
      fallbackDomain = new URL(scanResult.target).hostname;
    } catch {
      fallbackDomain = scanResult.target.replace(/^https?:\/\//, '').split('/')[0];
    }
  }
  const domain = realUrlscan?.page?.domain || fallbackDomain;
  const serverIp = realUrlscan?.page?.ip || 'N/A';
  const country = realUrlscan?.page?.country || 'N/A';

  console.log('[PDF] Threat reputation metadata', { domain, serverIp, country });
  if (domain === 'N/A' && serverIp === 'N/A') {
    console.warn('[PDF] Missing threat reputation metadata');
  }

  if (Array.isArray(scanData.sections)) {
    for (const section of scanData.sections) {
      const items = section.items || section.content;
      if (!Array.isArray(items)) continue;
      
      for (const item of items) {
        if (!item || !item.label) continue;
        
        const labelObj = item.label;
        const labelEn = (typeof labelObj === 'string' ? labelObj : (labelObj.en || '')).toString().toLowerCase().trim();
        const labelJa = (typeof labelObj === 'string' ? labelObj : (labelObj.ja || '')).toString().toLowerCase().trim();
        
        const isDomain = labelEn.includes('domain') || labelJa.includes('ドメイン');
        const isIp = labelEn.includes('ip') || labelJa.includes('ip');
        const isCountry = labelEn.includes('country') || labelJa.includes('国');
        
        if (isDomain) {
           item.value = domain;
        } else if (isIp) {
           item.value = serverIp;
        } else if (isCountry) {
           item.value = country;
        } else if (typeof item.value === 'string' && item.value.includes('REDACTED')) {
           item.value = item.value.replace(/REDACTED/g, 'N/A');
        }
      }
    }
  }

  return scanData;
}

// ─── Scan data ──────────────────────────────────────────────────────────────────

/**
 * The report's scan-results data, derived from the scan. Pure.
 *
 * This used to be Gemini's job (formatScanDataForPdf) with this as the fallback.
 * After 19 August 2026 that call never once finished inside the PDF's 35s window
 * in production, so every report already used this — after waiting the 35s.
 */
function buildScanDataForPdf(scanResult) {
  const safe = (v, fb = 0) => { const n = Number(v); return isFinite(n) ? n : fb; };
  // null when PageSpeed never returned the category — rendered "N/A", not "0/100".
  const psi = lighthouseScores(scanResult?.pagespeedResult);

  const obs   = scanResult?.observatoryResult  || {};
  const zap   = scanResult?.zapResult          || {};
  const urlsc = scanResult?.urlscanResult      || {};
  const wc    = scanResult?.webCheckResult?.fullResults || {};

  // WebCheck failing is not fatal to a scan, but its findings must not be
  // presented as measurements. "Not checked" and "checked, absent" are different
  // claims: a missing WAF probe must read "N/A", never "No".
  const wcOk = ['completed', 'completed_partial', 'completed_with_errors']
    .includes(scanResult?.webCheckResult?.status);
  // `checked` must reflect whether THIS SPECIFIC sub-scan returned data, not just
  // whether the overall WebCheck run was non-fatal — a run can be wcOk (partial
  // success) while the firewall/hsts probe itself individually errored or never
  // got a turn (both are HEAVY_SCANS, serialized behind WEBCHECK_HEAVY_SCAN_CONCURRENCY=1).
  const wcYesNo = (checked, present, yesJa, noJa) => checked
    ? { en: present ? 'Yes' : 'No', ja: present ? yesJa : noJa }
    : { en: NOT_AVAILABLE, ja: NOT_AVAILABLE };

  const hiCnt = safe(zap?.riskCounts?.High, 0);
  const mdCnt = safe(zap?.riskCounts?.Medium, 0);
  const isMal = !!urlsc?.verdicts?.overall?.malicious;
  const riskEn = (hiCnt > 0 || isMal) ? 'High' : mdCnt > 0 ? 'Medium' : 'Low';
  const riskJa = riskEn === 'High' ? '高' : riskEn === 'Medium' ? '中' : '低';

  const alerts = Array.isArray(zap?.alerts) ? zap.alerts : [];

  return {
    header: {
      title:  { en: 'Security Scan Report', ja: 'セキュリティスキャンレポート' },
      target: scanResult?.target || '',
      scanId: scanResult?.analysisId || '',
      date:   new Date().toLocaleDateString(),
      status: { en: statusLabel(scanResult?.status, 'en'), ja: statusLabel(scanResult?.status, 'ja') }
    },
    summary: {
      title:      { en: 'Executive Summary', ja: 'エグゼクティブサマリー' },
      riskLevel:  { en: riskEn, ja: riskJa },
      riskLabel:  { en: 'Overall Risk Level', ja: '全体的なリスクレベル' }
    },
    sections: [
      {
        id: 'pagespeed',
        title: { en: 'Performance & Accessibility Analysis', ja: 'パフォーマンス・アクセシビリティ分析' },
        items: [
          { label: { en: 'Performance',    ja: 'パフォーマンス'     }, value: formatScore(psi.performance),   type: 'score' },
          { label: { en: 'Accessibility',  ja: 'アクセシビリティ'    }, value: formatScore(psi.accessibility), type: 'score' },
          { label: { en: 'Best Practices', ja: 'ベストプラクティス'  }, value: formatScore(psi.bestPractices), type: 'score' },
          { label: { en: 'SEO',            ja: 'SEO'               }, value: formatScore(psi.seo),           type: 'score' }
        ]
      },
      {
        id: 'observatory',
        title: { en: 'Security Configuration Assessment', ja: 'セキュリティ設定評価' },
        items: [
          { label: { en: 'Security Grade',  ja: 'セキュリティ評価'  }, value: obs.grade || 'N/A',              type: 'grade'   },
          { label: { en: 'Score',           ja: 'スコア'            }, value: formatMetric(obs.score),          type: 'score'   },
          { label: { en: 'Tests Passed',    ja: '合格テスト数'      }, value: safe(obs.tests_passed, 0),        type: 'success' },
          { label: { en: 'Tests Failed',    ja: '不合格テスト数'    }, value: safe(obs.tests_failed, 0),        type: 'danger'  }
        ]
      },
      {
        id: 'zap',
        title: { en: 'Vulnerability Scan Results', ja: '脆弱性スキャン結果' },
        items: [
          { label: { en: 'Total Alerts',   ja: '総アラート数' }, value: safe(zap.totalAlerts, alerts.length),         type: 'stat'    },
          { label: { en: 'High Risk',      ja: '高リスク'     }, value: safe(zap?.riskCounts?.High, 0),               type: 'danger'  },
          { label: { en: 'Medium Risk',    ja: '中リスク'     }, value: safe(zap?.riskCounts?.Medium, 0),             type: 'warning' },
          { label: { en: 'Low Risk',       ja: '低リスク'     }, value: safe(zap?.riskCounts?.Low, 0),               type: 'info'    },
          { label: { en: 'Informational',  ja: '情報'         }, value: safe(zap?.riskCounts?.Informational, 0),      type: 'stat'    }
        ],
        alerts: alerts.slice(0, 7).map(a => ({ risk: a.risk, alert: a.alert })),
        detailedAlerts: alerts.map(a => ({
          name: a.alert, pluginId: a.pluginId, risk: a.risk, confidence: a.confidence,
          description: a.description || '',
          solution:    a.solution    || '',
          reference:   a.reference   || '',
          cweid: a.cweid, wascid: a.wascid,
          totalOccurrences: a.totalOccurrences || a.occurrences?.length || 0,
          sampleUrls: a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || []
        }))
      },
      {
        id: 'urlscan',
        title: { en: 'Threat & Reputation Analysis', ja: '脅威・レピュテーション分析' },
        items: [
          { label: { en: 'Verdict',      ja: '判定'        }, value: { en: isMal ? 'MALICIOUS' : 'Clean', ja: isMal ? '悪性' : 'クリーン' }, type: isMal ? 'danger' : 'success' },
          { label: { en: 'Threat Score', ja: '脅威スコア'  }, value: formatMetric(urlsc?.verdicts?.overall?.score), type: 'score' },
          { label: { en: 'Domain',       ja: 'ドメイン'    }, value: urlsc?.page?.domain  || 'N/A', type: 'stat' },
          { label: { en: 'Server IP',    ja: 'サーバーIP'  }, value: urlsc?.page?.ip      || 'N/A', type: 'stat' },
          { label: { en: 'Country',      ja: '国'          }, value: urlsc?.page?.country || 'N/A', type: 'stat' },
          { label: { en: 'Server',       ja: 'サーバー'    }, value: urlsc?.page?.server  || 'N/A', type: 'stat' }
        ]
      },
      {
        id: 'webcheck',
        title: { en: 'Web Security Configuration', ja: 'Webセキュリティ設定' },
        items: [
          { label: { en: 'TLS Grade',    ja: 'TLS評価'      }, value: (wcOk && (wc?.tls?.tlsInfo?.grade || wc?.ssl?.grade)) || NOT_AVAILABLE, type: 'grade' },
          { label: { en: 'WAF Detected', ja: 'WAF検出'      }, value: wcYesNo(wcOk && !!wc?.firewall && !wc.firewall.error, wc?.firewall?.hasWaf, 'はい', 'いいえ'), type: (!wcOk || !wc?.firewall || wc.firewall.error) ? 'stat' : (wc?.firewall?.hasWaf ? 'success' : 'warning') },
          { label: { en: 'HSTS Enabled', ja: 'HSTS有効'     }, value: wcYesNo(wcOk && !!wc?.hsts && !wc.hsts.error, isHstsEnabled(wc?.hsts), '有効', '無効'),     type: (!wcOk || !wc?.hsts || wc.hsts.error) ? 'stat' : (isHstsEnabled(wc?.hsts) ? 'success' : 'warning') },
          { label: { en: 'Technologies', ja: 'テクノロジー' }, value: (wcOk && Array.isArray(wc?.['tech-stack']?.technologies)) ? wc['tech-stack'].technologies.slice(0, 5).map(t => t.name || t).join(', ') : NOT_AVAILABLE, type: 'stat' }
        ]
      }
    ]
  };
}

/**
 * Build the static strings/overrides applied on top of the template content.
 * Now accepts scanData so the final page can show scan-specific metadata.
 */
function buildTemplateStaticOverrides(base, { lang, scanData }) {
  // Spec requirement: template static strings come verbatim from the DOCX and
  // must not be overridden in code; EN/JA share the same extracted content.
  return { ...(base || {}), lang };
}

// ─── GridFS helper ──────────────────────────────────────────────────────────────

/**
 * The plan-filtered findings from the scan's detailed-alerts file, carrying only
 * the occurrences a report draws (see zapDetailedAlerts.loadReportAlerts — the
 * file can be hundreds of MB). null when there is no file or it cannot be read.
 */
async function loadReportFindings(scanResult, accessLevel) {
  const file = scanResult.zapResult?.reportFiles?.find(f => f.filename?.includes('detailed_alerts'));
  if (!file?.fileId) return null;
  try {
    const alerts = await loadReportAlerts(file.fileId, detailedAlertsBucket(file));
    return getSanitizedAlerts(alerts, accessLevel).map(a => ({
      name: a.alert, pluginId: a.pluginId, risk: a.risk, confidence: a.confidence,
      description: a.description || '',
      solution:    a.solution    || '',
      reference:   a.reference   || '',
      cweid: a.cweid, wascid: a.wascid,
      totalOccurrences: a.totalOccurrences || a.occurrenceCount || 0,
      sampleUrls: a.sampleUrls || a.occurrences.slice(0, 10).map(o => o.uri || o),
      // The first occurrences with raw request/response, for the proof-of-exploit
      // section, and how many there are in all.
      occurrences: a.occurrences,
      rawOccurrenceCount: a.rawOccurrenceCount
    }));
  } catch (e) {
    console.warn(`⚠️ Detailed alerts read failed: ${e.message}`);
    return null;
  }
}

async function fetchFullAlertsFromGridFS(scanResult, zapSection, accessLevel) {
  if (!zapSection) return;
  const findings = await loadReportFindings(scanResult, accessLevel);
  if (findings) {
    zapSection.detailedAlerts = findings;
    console.log(`✅ Loaded ${findings.length} plan-filtered alerts from GridFS`);
  } else {
    // Summary alerts from the scan document — the plan's severity filter applies here too.
    zapSection.detailedAlerts = getSanitizedAlerts(zapSection.detailedAlerts, accessLevel);
  }
}

// ─── PDFKit text helpers ────────────────────────────────────────────────────────

function renderTextWithBold(doc, text, options = {}) {
  const parts = [];
  let last = 0;
  const re = /\*\*([^*]+)\*\*/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push({ text: text.slice(last, m.index), bold: false });
    parts.push({ text: m[1], bold: true });
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push({ text: text.slice(last), bold: false });
  if (!parts.length) { doc.text(text, options); return; }
  parts.forEach((p, i) => {
    doc.font(p.bold ? 'NotoSans-Bold' : 'NotoSans')
       .text(p.text, { ...options, continued: i < parts.length - 1 });
  });
}

// ─── Template context ───────────────────────────────────────────────────────────

function getTemplateImage(ts, name, fallback) {
  const buf = ts?.images?.[name]?.buffer;
  if (buf && Buffer.isBuffer(buf)) return buf;
  if (fallback && fs.existsSync(fallback)) return fallback;
  return null;
}

function getPageBackground(ts, pageIndex) {
  const list = ts?.pageBackgrounds;
  if (!Array.isArray(list) || list.length === 0) return null;
  const exact = list.find(p => p.index === pageIndex);
  if (exact?.buffer) return exact.buffer;
  const last = list[list.length - 1];
  return last?.buffer || null;
}

function drawFullPageImage(doc, image) {
  if (!image) return;
  if (Buffer.isBuffer(image) || (typeof image === 'string' && fs.existsSync(image)))
    doc.image(image, 0, 0, { width: doc.page.width, height: doc.page.height });
}

function createCtx(doc, templateStatic) {
  const ctx = {
    doc, templateStatic,
    margin:       TEMPLATE_MARGIN,
    contentX:     TEMPLATE_MARGIN.left,
    contentWidth: doc.page.width - TEMPLATE_MARGIN.left - TEMPLATE_MARGIN.right,
    topY:         TEMPLATE_MARGIN.top,
    bottomY:      doc.page.height - TEMPLATE_MARGIN.bottom,
    bgIndex:      2,
    initFramedPage() {
      const bg = getPageBackground(templateStatic, this.bgIndex);
      if (bg) drawFullPageImage(doc, bg);
      else {
        const frame = getTemplateImage(templateStatic, 'image4.jpeg', TEMPLATE_IMAGES.frameBg);
        drawFullPageImage(doc, frame);
      }
      doc.x = this.contentX; doc.y = this.topY;
    },
    addFramedPage() { doc.addPage(); this.bgIndex += 1; this.initFramedPage(); }
  };
  return ctx;
}

function ensureSpace(ctx, h) {
  if (ctx.doc.y + h > ctx.bottomY) ctx.addFramedPage();
}

function findFittingSubstring(doc, text, opts, maxH) {
  const raw = String(text || '');
  if (!raw) return '';
  const fits = s => doc.heightOfString(stripBoldMarkers(s), opts) <= maxH;
  if (fits(raw)) return raw;
  let lo = 0, hi = raw.length;
  while (lo + 1 < hi) { const mid = (lo + hi) >> 1; fits(raw.slice(0, mid)) ? lo = mid : hi = mid; }
  let cut = Math.max(1, lo);
  while (cut > 1 && !/\s/.test(raw[cut - 1])) cut--;
  if (cut <= 1) cut = Math.max(1, lo);
  // Japanese has no spaces to break at: backing up to the last space stranded a
  // bullet marker ("•") at the foot of a page with its text on the next one.
  // Between CJK characters any position is a valid line break, so use the fit.
  if (cut < lo * 0.5 && /[　-ヿ㐀-鿿＀-￯]/.test(raw.slice(cut, lo))) {
    cut = Math.max(1, lo);
    if (/[\uD800-\uDBFF]/.test(raw[cut - 1] || '')) cut--; // never split a surrogate pair
  }
  while (cut > 1 && !isBoldBalanced(raw.slice(0, cut))) {
    let b = cut - 1; while (b > 1 && !/\s/.test(raw[b - 1])) b--; if (b <= 1) break; cut = b;
  }
  return raw.slice(0, cut);
}

function writeFlowText(ctx, text, { width, align = 'left', lineGap = 3, fontSize = 10, color = COLORS.text } = {}) {
  const doc = ctx.doc;
  width = width || ctx.contentWidth;
  const lang = ctx?.templateStatic?.lang || 'en';
  let rem = sanitizeTextForPdf(text, lang);
  if (!rem) return;
  doc.font('NotoSans').fontSize(fontSize).fillColor(color);
  while (rem.length) {
    const avail = ctx.bottomY - doc.y;
    if (avail < fontSize + 6) { ctx.addFramedPage(); continue; }
    const chunk = findFittingSubstring(doc, rem, { width, lineGap }, avail);
    renderTextWithBold(doc, chunk, { width, align, lineGap });
    rem = rem.slice(chunk.length).replace(/^[ \t]+/, '');
    if (rem.length) ctx.addFramedPage();
  }
}

// ─── Request/Response evidence text ─────────────────────────────────────────────
// Evidence is verbatim HTTP traffic, not prose, so it bypasses sanitizeTextForPdf
// (HTML-entity decoding, and for JA backslash-escape decoding + NFKC, all rewrite
// what the server actually sent) and renderTextWithBold (which eats `**` in
// scripts and globs). Both languages get identical treatment.

const EVIDENCE_TAB_WIDTH = 4;
// Invisible format characters (soft hyphen, zero-width, bidi controls, BOM) are
// shown as escapes: in evidence their presence can be the finding.
const EVIDENCE_INVISIBLE_RE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;

// Scripts Noto Sans JP has no glyphs for but real pages carry — e.g. the multilingual
// notice on IANA's example domains. The regular weight also serves bold evidence text.
const EVIDENCE_FALLBACK_FONTS = [
  { name: 'NotoSansArabic',     file: 'NotoSansArabic-Regular.ttf',     rtl: true },
  { name: 'NotoSansHebrew',     file: 'NotoSansHebrew-Regular.ttf',     rtl: true },
  { name: 'NotoSansThai',       file: 'NotoSansThai-Regular.ttf' },
  { name: 'NotoSansDevanagari', file: 'NotoSansDevanagari-Regular.ttf' }
].map(f => ({ ...f, path: path.join(__dirname, '../fonts', f.file) }));
const RTL_FONTS = new Set(EVIDENCE_FALLBACK_FONTS.filter(f => f.rtl).map(f => f.name));

function registerPdfFonts(doc) {
  doc.registerFont('NotoSans',      FONTS.regular);
  doc.registerFont('NotoSans-Bold', FONTS.bold);
  EVIDENCE_FALLBACK_FONTS.forEach(f => doc.registerFont(f.name, f.path));
}

// Parsed font files, for glyph coverage and metrics. Regular and Bold Noto Sans JP
// cover the same code points with the same ascent, so the regular file serves both.
const fontkitFonts = new Map();
function fontkitFor(pdfFontName) {
  const file = EVIDENCE_FALLBACK_FONTS.find(f => f.name === pdfFontName)?.path || FONTS.regular;
  if (!fontkitFonts.has(file)) fontkitFonts.set(file, require('@pdf-lib/fontkit').create(fs.readFileSync(file)));
  return fontkitFonts.get(file);
}

/** The PDF font that can draw `cp`: `primary`, else a fallback, else null. */
function evidenceFontFor(cp, primary = 'NotoSans') {
  if (fontkitFor(primary).hasGlyphForCodePoint(cp)) return primary;
  return EVIDENCE_FALLBACK_FONTS.find(f => fontkitFor(f.name).hasGlyphForCodePoint(cp))?.name || null;
}

function escapeCodePoint(cp) {
  const hex = cp.toString(16).toUpperCase();
  return cp > 0xFFFF ? `\\u{${hex}}` : `\\u${hex.padStart(4, '0')}`;
}

/**
 * Make raw HTTP text drawable without changing what it says: CRLF/CR become line
 * breaks, tabs expand to spaces, and a character no bundled font can draw (which
 * PDFKit renders as a square) or a control/invisible character is written as a
 * \uXXXX escape. Nothing is decoded or normalized; only trailing whitespace and
 * runs of more than two blank lines are dropped, as for prose.
 * Pure — exported for tests.
 */
function sanitizeEvidenceForPdf(text) {
  return String(text ?? '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map(line => {
      let out = '';
      for (const ch of line) {
        const cp = ch.codePointAt(0);
        if (ch === '\t') out += ' '.repeat(EVIDENCE_TAB_WIDTH - (out.length % EVIDENCE_TAB_WIDTH));
        else if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F) || EVIDENCE_INVISIBLE_RE.test(ch) || !evidenceFontFor(cp)) out += escapeCodePoint(cp);
        else out += ch;
      }
      return out.trimEnd();
    })
    .join('\n')
    .replace(/\n{4,}/g, '\n\n\n') // same blank-line cap as sanitizeTextForPdf
    .trimEnd();
}

/**
 * Split one line into runs of a single font. A space between two characters of
 * the same fallback font stays in that run, so an Arabic phrase is one run.
 */
function splitFontRuns(line, primary) {
  const chars = Array.from(line, ch => ({ ch, font: ch === ' ' ? null : evidenceFontFor(ch.codePointAt(0), primary) || primary }));
  const prev = [];
  chars.forEach((c, i) => { prev[i] = c.font || (i ? prev[i - 1] : null); });
  let next = null;
  for (let i = chars.length - 1; i >= 0; i--) {
    if (chars[i].font) { next = chars[i].font; continue; }
    chars[i].font = i && prev[i - 1] && prev[i - 1] === next ? next : primary;
  }
  const runs = [];
  for (const { ch, font } of chars) {
    const last = runs[runs.length - 1];
    if (last && last.font === font) last.text += ch;
    else runs.push({ text: ch, font });
  }
  return runs;
}

/**
 * Wrap font runs into rows no wider than `width`: break at spaces, and split a
 * token longer than a whole row (cookies, tokens) at the last character that fits.
 */
function layoutEvidenceRows(doc, runs, width, fontSize) {
  const measure = (s, font) => doc.font(font).fontSize(fontSize).widthOfString(s);
  const rows = [[]];
  let used = 0;
  const push = (text, font) => { rows[rows.length - 1].push({ text, font }); used += measure(text, font); };
  const newRow = () => { rows.push([]); used = 0; };

  for (const { text, font } of runs) {
    for (const word of text.match(/\S+\s*|\s+/g) || []) {
      let rest = word;
      while (rest) {
        if (used + measure(rest, font) <= width) { push(rest, font); break; }
        const trimmed = rest.trimEnd();
        if (!trimmed) { if (used > 0) newRow(); break; }                // spaces at a wrap point
        if (used + measure(trimmed, font) <= width) { push(trimmed, font); used = width; break; }
        if (used > 0 && measure(trimmed, font) <= width) { newRow(); continue; }
        const chars = Array.from(rest);
        let lo = 0, hi = chars.length;
        while (lo + 1 < hi) { const mid = (lo + hi) >> 1; used + measure(chars.slice(0, mid).join(''), font) <= width ? lo = mid : hi = mid; }
        if (lo === 0 && used > 0) { newRow(); continue; }
        const head = chars.slice(0, Math.max(1, lo)).join('');
        push(head, font); newRow();
        rest = rest.slice(head.length);
      }
    }
  }
  while (rows.length > 1 && !rows[rows.length - 1].length) rows.pop();
  return rows;
}

/**
 * Write already-sanitized evidence inside the content frame, row by row, moving to
 * a new framed page whenever the next row would cross the bottom margin. Runs in
 * different fonts share one baseline. fontkit shapes an RTL word on its own, but
 * PDFKit misplaces spaces in a multi-word RTL run, so those words are placed here.
 */
function writeEvidenceText(ctx, text, { font = 'NotoSans', fontSize = 7, lineGap = 1, color = COLORS.text } = {}) {
  const doc = ctx.doc;
  const ascent = f => { const fk = fontkitFor(f); return fk.ascent / fk.unitsPerEm * fontSize; };
  const lineHeight = f => doc.font(f).fontSize(fontSize).currentLineHeight(true);
  doc.fillColor(color);

  // Every row keeps the primary font's height and baseline, so rows stay evenly
  // spaced; a fallback's ink sits inside that. Fallback fonts declare much taller
  // line boxes (Arabic reserves 2.1em for stacked marks), so only the page-break
  // test accounts for how far below the baseline they can reach.
  const rowH = lineHeight(font) + lineGap;
  const fitH = f => ascent(font) - ascent(f) + lineHeight(f);

  for (const line of String(text || '').split('\n')) {
    for (const row of layoutEvidenceRows(doc, splitFontRuns(line, font), ctx.contentWidth, fontSize)) {
      const fonts = [font, ...row.map(item => item.font)];
      if (doc.y + Math.max(rowH, ...fonts.map(fitH)) > ctx.bottomY) { ctx.addFramedPage(); doc.fillColor(color); }
      const top = doc.y;
      const baseline = top + ascent(font);
      let x = ctx.contentX;
      const merged = [];
      row.forEach(item => {
        const last = merged[merged.length - 1];
        if (last && last.font === item.font) last.text += item.text; else merged.push({ ...item });
      });
      for (const item of merged) {
        doc.font(item.font).fontSize(fontSize);
        const y = baseline - ascent(item.font);
        const tokens = RTL_FONTS.has(item.font) ? item.text.match(/\S+|\s+/g).reverse() : [item.text];
        for (const tok of tokens) {
          if (tok.trim()) doc.text(tok, x, y, { lineBreak: false });
          x += doc.widthOfString(tok);
        }
      }
      doc.x = ctx.contentX;
      doc.y = top + rowH;
    }
  }
  doc.font(font).fontSize(fontSize);
}

// ─── Cover page ─────────────────────────────────────────────────────────────────

function renderCoverPage(doc, scanData, lang, ts) {
  const W  = doc.page.width, H = doc.page.height;
  const ML = TEMPLATE_MARGIN.left, MR = TEMPLATE_MARGIN.right;
  const cw = W - ML - MR;

  // 1. Full-bleed cover background (page-1.png preferred)
  drawFullPageImage(doc, getPageBackground(ts, 1) || getTemplateImage(ts, 'image1.png', TEMPLATE_IMAGES.coverBg));

  // 2. Large AEVUS logo centred near the top
  const logoLg = ts?.logoOverride?.buffer || getTemplateImage(ts, 'image3.png', TEMPLATE_IMAGES.logoLarge);
  if (logoLg) {
    const lw = 300;
    doc.image(logoLg, (W - lw) / 2, 90, { width: lw });
  }

  // 3. Report title
  const title = typeof scanData.header?.title === 'object'
    ? scanData.header.title[lang]
    : (scanData.header?.title || 'Security Scan Report');

  const titleS = sanitizeTextForPdf(title, lang);
  const targetS = sanitizeTextForPdf(scanData.header?.target || '', lang);
  // Use dateRaw (injected by injectRealScanMetadata) for per-language formatting;
  // fall back to header.date string if dateRaw is absent.
  const dateRawValue = scanData.header?.dateRaw || scanData.header?.date || '';
  const parsedDate = dateRawValue instanceof Date ? dateRawValue : (dateRawValue ? new Date(dateRawValue) : null);
  const dateS = parsedDate && !isNaN(parsedDate.getTime())
    ? formatCoverDate(parsedDate, lang)
    : sanitizeTextForPdf(String(dateRawValue), lang);
  const scanIdS = sanitizeTextForPdf(scanData.header?.scanId || '', lang);

  doc.font('NotoSans-Bold').fontSize(28).fillColor(COLORS.primary)
      .text(titleS, ML, 255, { width: cw, align: 'center' });

  // 4. Scan URL
  doc.font('NotoSans').fontSize(12).fillColor(COLORS.text)
      .text(`${t(lang, 'scanUrl')}: ${targetS}`, ML, 318, { width: cw, align: 'center' });

  // 5. Date & Scan ID
  doc.fontSize(10).fillColor(COLORS.textLight)
      .text(`${t(lang, 'generated')}: ${dateS}`, ML, 348, { width: cw, align: 'center' })
      .text(`${t(lang, 'scanId')}: ${scanIdS}`, ML, 363, { width: cw, align: 'center' });

  // 6. Bottom rule
  doc.moveTo(ML, H - 80).lineTo(W - MR, H - 80).lineWidth(0.5).stroke(COLORS.border);
}

// ─── Section helpers ────────────────────────────────────────────────────────────

function addTemplateSectionHeader(ctx, title) {
  ensureSpace(ctx, 44);
  const lang = ctx?.templateStatic?.lang || 'en';
  ctx.doc.font('NotoSans-Bold').fontSize(14).fillColor(COLORS.primary)
    .text(sanitizeTextForPdf(title, lang));
  ctx.doc.moveDown(0.3);
}

function renderExecutiveSummarySection(ctx, scanData, lang) {
  const summ = scanData.summary || {};
  const title     = typeof summ.title     === 'object' ? summ.title[lang]     : (summ.title || 'Executive Summary');
  const riskLabel = typeof summ.riskLabel === 'object' ? summ.riskLabel[lang] : (summ.riskLabel || 'Overall Risk Level');
  const riskLevel = typeof summ.riskLevel === 'object' ? summ.riskLevel[lang] : (summ.riskLevel || 'N/A');
  addTemplateSectionHeader(ctx, title);
    const riskLabelS = sanitizeTextForPdf(riskLabel, lang);
    const riskLevelS = sanitizeTextForPdf(riskLevel, lang);
    ctx.doc.font('NotoSans').fontSize(11).fillColor(COLORS.text)
      .text(`${riskLabelS}: `, { continued: true })
      .font('NotoSans-Bold').fillColor(getRiskColor(riskLevelS)).text(riskLevelS);
  ctx.doc.moveDown(0.6);
}

function renderTemplateContentBlock(ctx, block) {
  const doc = ctx.doc;
  if (!block) return;
  switch (block.type) {
    case 'paragraph':
      writeFlowText(ctx, block.text || '', { lineGap: 3, fontSize: 10, color: COLORS.text });
      doc.moveDown(0.3); break;
    case 'bullets':
      (block.items || []).forEach(item => {
        ensureSpace(ctx, 18);
        writeFlowText(ctx, `•  ${item}`, { lineGap: 2, fontSize: 10, color: COLORS.text });
      });
      doc.moveDown(0.2); break;
    case 'bold_text':
      ensureSpace(ctx, 16);
      doc.font('NotoSans-Bold').fontSize(10).fillColor(COLORS.text)
         .text(`${block.label} `, { continued: true })
         .font('NotoSans').fillColor(getTypeColor(String(block.text || '').toLowerCase() === 'high' ? 'danger' : 'stat'))
         .text(block.text || '');
      doc.moveDown(0.2); break;
    default:
      if (block.text) { writeFlowText(ctx, block.text, { lineGap: 3, fontSize: 10, color: COLORS.text }); doc.moveDown(0.3); }
  }
}

function renderAiAnalysisSection(ctx, aiAnalysis, lang) {
  const sectionTitle = t(lang, 'aiSectionTitle');
  if (!aiAnalysis) {
    addTemplateSectionHeader(ctx, sectionTitle);
    writeFlowText(ctx, t(lang, 'aiUnavailable'), { lineGap: 3, fontSize: 10, color: COLORS.textLight });
    ctx.doc.moveDown(0.5);
    return;
  }
  addTemplateSectionHeader(ctx, sanitizeTextForPdf(aiAnalysis.title || sectionTitle, lang));
  (aiAnalysis.sections || []).forEach(section => {
    ensureSpace(ctx, 70);
    if (section.heading) {
      ctx.doc.font('NotoSans-Bold').fontSize(12).fillColor(COLORS.primary)
        .text(sanitizeTextForPdf(section.heading, lang));
      ctx.doc.moveDown(0.2);
    }
    (section.content || []).forEach(block => renderTemplateContentBlock(ctx, block));
    ctx.doc.moveDown(0.3);
  });
}

function renderScanResultsSection(ctx, scanData, lang) {
  const doc = ctx.doc;
  addTemplateSectionHeader(ctx, t(lang, 'scanResults'));
  doc.font('NotoSans').fontSize(10).fillColor(COLORS.textLight)
     .text(t(lang, 'scanResultsDetails'));
  doc.moveDown(0.4);

  (scanData.sections || []).forEach(section => {
    ensureSpace(ctx, 60);
    const title = typeof section.title === 'object' ? section.title[lang] : section.title;
    doc.font('NotoSans-Bold').fontSize(11).fillColor(COLORS.primary).text(title || '');
    doc.moveDown(0.2);
    (section.items || []).forEach(item => {
      ensureSpace(ctx, 16);
      const lbl = typeof item.label === 'object' ? item.label[lang] : item.label;
      let val = item.value;
      if (typeof val === 'object' && val) val = val[lang] || val.en || '';
      const lblS = sanitizeTextForPdf(lbl, lang);
      const valS = sanitizeTextForPdf(String(val), lang);
      doc.font('NotoSans').fontSize(10).fillColor(COLORS.textLight)
         .text(`${lblS}: `, { continued: true }).fillColor(COLORS.text).text(valS);
    });
    doc.moveDown(0.4);
  });
}

function renderVulnerabilityDetailsSection(ctx, vulnerabilities, lang) {
  const doc = ctx.doc;
  addTemplateSectionHeader(ctx, t(lang, 'vulnDetailsTitle'));

  if (!vulnerabilities?.length) {
    doc.font('NotoSans').fontSize(11).fillColor(COLORS.success)
       .text(t(lang, 'noVulnerabilities'));
    doc.moveDown(0.5); return;
  }

  vulnerabilities.forEach((v, idx) => {
    ensureSpace(ctx, 80);
     const vName = sanitizeTextForPdf(v.name || v.alert || '', lang);
     doc.font('NotoSans-Bold').fontSize(11).fillColor(COLORS.text)
       .text(`${idx + 1}. ${vName}`, { width: ctx.contentWidth });
    doc.font('NotoSans').fontSize(9).fillColor(COLORS.textLight)
       .text(`${t(lang, 'risk')}: `, { continued: true })
       .fillColor(getRiskColor(v.risk)).font('NotoSans-Bold')
       .text(riskLabel(v.risk, lang), { continued: true })
       .fillColor(COLORS.textLight).font('NotoSans')
       .text(`  |  ${t(lang, 'confidence')}: `, { continued: true })
       .fillColor(COLORS.text).text(confidenceLabel(v.confidence, lang));
    doc.moveDown(0.2);

    if (v.description) {
      ensureSpace(ctx, 30);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.primary)
         .text(t(lang, 'description'));
      writeFlowText(ctx, v.description, { lineGap: 2, fontSize: 9, color: COLORS.text });
      doc.moveDown(0.2);
    }
    if (v.solution) {
      ensureSpace(ctx, 30);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.success)
         .text(t(lang, 'solution'));
      writeFlowText(ctx, v.solution, { lineGap: 2, fontSize: 9, color: COLORS.text });
      doc.moveDown(0.2);
    }
    if (v.sampleUrls && v.sampleUrls.length > 0) {
      ensureSpace(ctx, 30);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.warning)
         .text(t(lang, 'affectedUrls'));
      v.sampleUrls.forEach((urlObj) => {
          const urlStr = typeof urlObj === 'string' ? urlObj : urlObj.uri || urlObj.url || String(urlObj);
          if (urlStr) {
             writeFlowText(ctx, `• ${urlStr}`, { lineGap: 2, fontSize: 8, color: COLORS.text });
          }
      });
      doc.moveDown(0.2);
    }

    // Raw request/response proof-of-exploit — up to 3 occurrences per finding.
    // The complete set (all occurrences, full bodies) is in the JSON export.
    const occWithRaw = Array.isArray(v.occurrences)
      ? v.occurrences.filter(o => o && (o.request || o.response))
      : [];
    // Report findings carry only the first few occurrences; rawOccurrenceCount is
    // how many have raw evidence in all.
    const rawTotal = Math.max(v.rawOccurrenceCount || 0, occWithRaw.length);
    if (occWithRaw.length > 0) {
      const width = ctx.contentWidth;
      const lineH = (font, size, gap = 0) => { doc.font(font).fontSize(size); return doc.currentLineHeight(true) + gap; };
      // Keep each heading/label on the same page as the first lines it introduces.
      const labelH    = lineH('NotoSans-Bold', 8);
      const evidenceH = 2 * lineH('NotoSans', 7, 1);
      const shown = occWithRaw.slice(0, 3).map((occ, oIdx) => {
        const metaBits = [
          occ.method ? String(occ.method) : null,
          occ.url ? String(occ.url) : null,
          occ.param ? `${t(lang, 'param')}: ${occ.param}` : null
        ].filter(Boolean).join('  ');
        const meta = sanitizeEvidenceForPdf(`#${oIdx + 1}  ${metaBits}`);
        doc.font('NotoSans-Bold').fontSize(8);
        return { occ, meta, metaH: doc.heightOfString(meta, { width }) };
      });

      ensureSpace(ctx, lineH('NotoSans-Bold', 9) + shown[0].metaH + labelH + evidenceH);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.primary)
         .text(t(lang, 'evidence'), { width });
      doc.moveDown(0.1);

      shown.forEach(({ occ, meta, metaH }) => {
        ensureSpace(ctx, metaH + labelH + evidenceH);
        writeEvidenceText(ctx, meta, { font: 'NotoSans-Bold', fontSize: 8, lineGap: 0, color: COLORS.text });

        [[occ.request, t(lang, 'request')],
         [occ.response, t(lang, 'response')]].forEach(([part, label]) => {
          if (!part) return;
          ensureSpace(ctx, labelH + evidenceH);
          doc.font('NotoSans-Bold').fontSize(8).fillColor(COLORS.textLight).text(label, { width });
          writeEvidenceText(ctx, sanitizeEvidenceForPdf(buildEvidenceText(part.header, part.body, lang)),
            { fontSize: 7, lineGap: 1, color: COLORS.text });
        });
        doc.moveDown(0.15);
      });

      if (rawTotal > shown.length) {
        ensureSpace(ctx, 12);
        doc.font('NotoSans').fontSize(7).fillColor(COLORS.textLight)
           .text(t(lang, 'moreEvidence', { n: rawTotal - shown.length }), { width });
      }
      doc.moveDown(0.2);
    }

    if (v.reference) {
      ensureSpace(ctx, 16);
      writeFlowText(ctx, `${t(lang, 'references')}: ${v.reference}`,
        { lineGap: 0, fontSize: 8, color: COLORS.textLight });
    }
    doc.moveDown(0.4);
    ensureSpace(ctx, 12);
    doc.moveTo(TEMPLATE_MARGIN.left, doc.y)
       .lineTo(doc.page.width - TEMPLATE_MARGIN.right, doc.y)
       .lineWidth(0.5).stroke(COLORS.border);
    doc.moveDown(0.4);
  });
}

function renderDisclaimerPage(ctx) {
  const t = ctx.templateStatic;
  addTemplateSectionHeader(ctx, t.disclaimerTitle);
  // Render each paragraph separated by double newline
  const paragraphs = String(sanitizeTextForPdf(t.disclaimerBody || '', t.lang) || '').split('\n\n');
  paragraphs.forEach(para => {
    writeFlowText(ctx, para, { lineGap: 4, fontSize: 10, color: COLORS.text });
    ctx.doc.moveDown(0.5);
  });
}

function renderDiagnosisHistoryPage(ctx, { allowPageBreaks = true } = {}) {
  const doc = ctx.doc, t = ctx.templateStatic;
  addTemplateSectionHeader(ctx, t.diagnosisTitle);

  const W  = doc.page.width - TEMPLATE_MARGIN.left - TEMPLATE_MARGIN.right;
  const headers = t.diagnosisHeaders || [];
  const cn  = Math.max(1, headers.length);

  // Column widths: 3-col → date 25%, user 40%, status 35%
  let cw;
  if (cn === 3) cw = [W * 0.25, W * 0.40, W * 0.35];
  else if (cn === 4) cw = [W * 0.2, W * 0.2, W * 0.25, W * 0.35];
  else cw = Array.from({ length: cn }, () => W / cn);

  drawTablePaged(ctx, TEMPLATE_MARGIN.left, doc.y, cw, [headers, ...(t.diagnosisRows || [])], { allowPageBreaks });
}

/**
 * Final page: AEVUS logo + scan metadata — matches the PDF template exactly.
 */
function renderFinalPage(ctx) {
  const doc = ctx.doc, t = ctx.templateStatic;
  const W  = doc.page.width, ML = TEMPLATE_MARGIN.left, MR = TEMPLATE_MARGIN.right;
  const cw = W - ML - MR;
  const cx = W / 2;
  const lang = t?.lang || 'en';

  // 1. Logo (folder override preferred)
  const logo = t?.logoOverride?.buffer || getTemplateImage(t, 'image2.png', TEMPLATE_IMAGES.logo);
  if (logo) {
    const lw = 240;
    doc.image(logo, cx - lw / 2, 100, { width: lw });
  }

  // 2. DOCX marketing copy (verbatim)
  const lines = Array.isArray(t?.finalPageLines) ? t.finalPageLines : [];
  const body = sanitizeTextForPdf(lines.filter(Boolean).join('\n'), lang);
  if (body) {
    doc.font('NotoSans').fontSize(12).fillColor(COLORS.text)
       .text(body, ML, 300, { width: cw, align: 'center', lineGap: 6 });
  }

  // 3. URL (verbatim)
  if (t?.finalPageUrl) {
    const url = sanitizeTextForPdf(t.finalPageUrl, lang);
    doc.font('NotoSans-Bold').fontSize(12).fillColor(COLORS.accent)
       .text(url, ML, 540, { width: cw, align: 'center' });
  }
}

function drawTablePaged(ctx, startX, startY, colWidths, rows, { allowPageBreaks = true } = {}) {
  const doc = ctx.doc;
  const lang = ctx?.templateStatic?.lang || 'en';
  let y = startY;
  const pad = 6;
  rows.forEach((row, ri) => {
    const rowSan = (row || []).map(cell => sanitizeTextForPdf(String(cell || ''), lang));
    const heights = rowSan.map((cell, i) => {
      doc.font('NotoSans').fontSize(ri === 0 ? 10 : 9);
      return doc.heightOfString(String(cell || ''), { width: colWidths[i] - pad * 2 });
    });
    const rowH = Math.max(...heights) + pad * 2;
    if (y + rowH > ctx.bottomY) {
      if (!allowPageBreaks) return;
      ctx.addFramedPage(); y = doc.y;
      if (ri > 0 && rows.length > 1) {
        let x2 = startX;
        const hdr = (rows[0] || []).map(cell => sanitizeTextForPdf(String(cell || ''), lang));
        hdr.forEach((cell, i) => {
          doc.rect(x2, y, colWidths[i], rowH).stroke(COLORS.border);
          doc.font('NotoSans').fontSize(10).fillColor(COLORS.text)
             .text(String(cell || ''), x2 + pad, y + pad, { width: colWidths[i] - pad * 2 });
          x2 += colWidths[i];
        });
        y += rowH; doc.y = y;
      }
    }
    let x = startX;
    rowSan.forEach((cell, i) => {
      // Header row gets a light fill
      if (ri === 0) {
        doc.rect(x, y, colWidths[i], rowH).fillAndStroke('#f3f4f6', COLORS.border);
        doc.fillColor(COLORS.text);
      } else {
        doc.rect(x, y, colWidths[i], rowH).stroke(COLORS.border);
      }
      doc.font('NotoSans').fontSize(ri === 0 ? 10 : 9).fillColor(COLORS.text)
         .text(String(cell || ''), x + pad, y + pad, { width: colWidths[i] - pad * 2 });
      x += colWidths[i];
    });
    y += rowH; doc.y = y;
  });
}

// ─── Template report orchestrator ───────────────────────────────────────────────

// HTTP Basic scans: say exactly which checks ran signed in. Neutral wording — the
// report never names the scan engines.
// HTTP Basic scans used to carry an extra scope section here (EN/JA), saying
// the header grade and site configuration checks ran without credentials. They now
// run signed in (authFastScanService), so every scan type has the same sections.

function renderTemplateReport(doc, scanData, aiAnalysis, vulnerabilities, lang, ts) {
  renderCoverPage(doc, scanData, lang, ts);
  doc.addPage();

  const ctx = createCtx(doc, ts);
  ctx.initFramedPage();

  // Page 2: Disclaimer + Scan History
  renderDisclaimerPage(ctx);
  ctx.doc.moveDown(0.6);
  renderDiagnosisHistoryPage(ctx, { allowPageBreaks: false });

  // Page 3+: All scan results (Gemini-driven), as before
  ctx.addFramedPage();
  renderExecutiveSummarySection(ctx, scanData, lang);
  renderAiAnalysisSection(ctx, aiAnalysis, lang);
  renderScanResultsSection(ctx, scanData, lang);
  renderVulnerabilityDetailsSection(ctx, vulnerabilities, lang);

  // Last page
  ctx.addFramedPage();
  renderFinalPage(ctx);
}

function renderTemplateZapReport(doc, vulnerabilities, lang, ts) {
  const ctx = createCtx(doc, ts);
  ctx.initFramedPage();
  renderVulnerabilityDetailsSection(ctx, vulnerabilities, lang);
  ctx.addFramedPage();
  renderFinalPage(ctx);
}

function makePdfDoc(meta) {
  const doc = new PDFDocument({
    size: 'A4', bufferPages: true,
    margins: { top: 0, bottom: 0, left: 0, right: 0 },
    info: { ...meta, CreationDate: new Date() }
  });
  registerPdfFonts(doc);
  return doc;
}

function collectBuffer(doc) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end',  () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

// ─── Public API ─────────────────────────────────────────────────────────────────

async function generateSingleLanguagePdf(scanResult, lang = 'en', accessLevel = 'critical-high') {
  const analysisId = scanResult?.analysisId || 'unknown';
  console.log(`[PDF][${analysisId}] Starting ${lang.toUpperCase()} PDF generation (accessLevel=${accessLevel})…`);

  // ── Validate scan data before proceeding ──────────────────────────────────
  if (!scanResult) {
    const err = new Error('scanResult is null or undefined — cannot generate PDF');
    err.code = 'MISSING_SCAN_DATA';
    throw err;
  }
  if (!scanResult.target) {
    const err = new Error('scanResult.target is missing — cannot generate PDF');
    err.code = 'MISSING_SCAN_DATA';
    throw err;
  }
  const hasAnyData = scanResult.pagespeedResult || scanResult.observatoryResult ||
                     scanResult.urlscanResult   || scanResult.zapResult ||
                     scanResult.webCheckResult;
  if (!hasAnyData) {
    console.error(`[PDF][${analysisId}] No scan data available. pagespeed=${!!scanResult.pagespeedResult} observatory=${!!scanResult.observatoryResult} urlscan=${!!scanResult.urlscanResult} zap=${!!scanResult.zapResult} webcheck=${!!scanResult.webCheckResult}`);
    const err = new Error('No scan results available for PDF generation. At least one scanner result is required.');
    err.code = 'MISSING_SCAN_DATA';
    throw err;
  }
  console.log(`[PDF][${analysisId}] Scan data present: pagespeed=${!!scanResult.pagespeedResult} observatory=${!!scanResult.observatoryResult} urlscan=${!!scanResult.urlscanResult} zap=${!!scanResult.zapResult} webcheck=${!!scanResult.webCheckResult}`);

  // Elapsed time, not console.time: overlapping jobs shared one console.time label,
  // so a second PDF logged a warning and the first one's total came out wrong.
  const startedAt = Date.now();
  const elapsed = () => `${((Date.now() - startedAt) / 1000).toFixed(1)}s`;

  console.log(`[PDF][${analysisId}] Fetching scan history rows…`);
  const scanHistoryRows = await fetchScanHistoryRows(scanResult);

  const scanData = injectRealScanMetadata(buildScanDataForPdf(scanResult), scanResult);
  scanData.scanHistory = buildScanHistoryTable(scanHistoryRows);

  const zapSection = scanData.sections?.find(s => s.id === 'zap');
  await fetchFullAlertsFromGridFS(scanResult, zapSection, accessLevel);

  let aiAnalysis = null;
  if (scanResult.refinedReport) {
    try {
      let parsed = buildAiAnalysisFromRefinedReport(scanResult.refinedReport);
      if (!parsed || !parsed.title || !parsed.sections?.length) {
         console.warn(`[PDF][${analysisId}] Local parser failed, falling back to Gemini`);
         parsed = await formatAiAnalysisForPdf(scanResult.refinedReport, pdfOpts);
      }
      aiAnalysis = parsed;
      console.log(`[PDF][${analysisId}] Using local parser-generated report`);
    } catch (e) {
      console.warn(`[PDF][${analysisId}] AI section unavailable, generating PDF from scan findings:`, e.message);
      // aiAnalysis stays null — PDF renders without AI narrative section
    }
  }

  const findings = zapSection?.detailedAlerts || [];

  const scanHistory = scanData?.scanHistory || null;
  const diagnosis = {
    title:   projectLangValue(scanHistory?.title, lang) || t(lang, 'scanHistory'),
    headers: scanHistory?.headers?.[lang] || ['historyDate', 'historyExecutedBy', 'historyStatus'].map(k => t(lang, k)),
    rows:    scanHistory?.rows?.[lang] || []
  };

  // Template text is loaded before localization so the language gate covers it.
  const tsBase = await getReportTemplateStaticContent({ lang });
  const ts = buildTemplateStaticOverrides(tsBase, { lang, scanData });
  ts.diagnosisTitle   = diagnosis.title;
  ts.diagnosisHeaders = diagnosis.headers;
  ts.diagnosisRows    = diagnosis.rows;

  // Every prose field in the report language, or REPORT_LOCALIZATION_INCOMPLETE
  // (nothing is rendered). Evidence, URLs, references and scan values are data:
  // never translated, never sent.
  console.log(`[PDF][${analysisId}] Localizing report (${elapsed()})`);
  const localized = await localizeReport(
    { findings, aiAnalysis, scanData, template: ts },
    lang,
    { logLabel: analysisId }
  );
  console.log(`[PDF][${analysisId}] Localization complete (${elapsed()})`);

  const doc = makePdfDoc({
    Title:   `Security Scan Report (${lang.toUpperCase()}) - ${scanResult.target}`,
    Author:  'SSDT',
    Subject: 'Security Analysis'
  });

  console.log(`[PDF][${analysisId}] Rendering PDF (${elapsed()})`);
  const buf = collectBuffer(doc);
  renderTemplateReport(doc, scanData, localized.aiAnalysis, localized.findings, lang, ts);
  doc.end();
  const out = await buf;
  console.log(`[PDF][${analysisId}] PDF completed in ${elapsed()}`);
  return out;
}

/**
 * Generate a ZAP-only vulnerability PDF.
 */
async function generateZapPdf(scanResult, lang = 'en', accessLevel = 'critical-high') {
  console.log(`📄 Starting ZAP ${lang.toUpperCase()} PDF generation…`);

  let vulnerabilities = (await loadReportFindings(scanResult, accessLevel)) || [];

  if (!vulnerabilities.length && scanResult.zapResult?.summaryAlerts) {
    const filtered = getSanitizedAlerts(scanResult.zapResult.summaryAlerts, accessLevel);
    vulnerabilities = filtered.map(a => ({
      name: a.alert, pluginId: a.pluginId, risk: a.risk, confidence: a.confidence,
      description: a.description || '',
      solution:    a.solution    || '',
      reference: a.reference || '', cweid: a.cweid, wascid: a.wascid,
      totalOccurrences: a.totalOccurrences || 0,
      sampleUrls: a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || [],
      urls: [] // occurrence URLs stripped
    }));
  }

  const ts = await getReportTemplateStaticContent({ lang });
  const tsFinal = buildTemplateStaticOverrides(ts, { lang });

  const localized = await localizeReport(
    { findings: vulnerabilities, aiAnalysis: null, template: { finalPageLines: tsFinal.finalPageLines } },
    lang,
    { logLabel: `ZAP-PDF ${scanResult.analysisId || ''}`.trim() }
  );

  const doc = makePdfDoc({
    // Document properties are client-visible in any PDF reader — keep them free of
    // third-party engine names.
    Title:   `Vulnerability Report (${lang.toUpperCase()}) - ${scanResult.target}`,
    Author:  'SSD',
    Subject: 'Detailed Vulnerability Analysis'
  });
  const buf = collectBuffer(doc);
  renderTemplateZapReport(doc, localized.findings, lang, tsFinal);
  doc.end();
  return buf;
}

module.exports = { generateSingleLanguagePdf, generateZapPdf, reportVersion, buildAiAnalysisFromRefinedReport, buildScanHistoryTable, renderVulnerabilityDetailsSection, renderAiAnalysisSection, buildEvidenceText, sanitizeEvidenceForPdf, registerPdfFonts, _buildScanDataForPdf: buildScanDataForPdf };
