'use strict';

/**
 * pdfService.js
 * Generates bilingual (English + Japanese) security scan PDF reports.
 * Depends on: geminiService.js, gridfsService.js, ScanResult model.
 *
 * Usage:
 *   const { generateSingleLanguagePdf, generateZapPdf } = require('./pdfService');
 *   const pdfBuffer = await generateSingleLanguagePdf(scanResult, 'en');
 *   const pdfBuffer = await generateZapPdf(scanResult, 'ja');
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { getSanitizedAlerts } = require('../utils/vulnFilter');

let puppeteer;
try { puppeteer = require('puppeteer'); } catch { puppeteer = null; }

const ScanResult = require('../models/ScanResult');
const { formatScanDataForPdf, formatScanHistoryForPdf, formatAiAnalysisForPdf, translateAiAnalysisSectionsToJapanese, translateVulnerabilitiesToJapanese } = require('./geminiService');
const gridfsService = require('./gridfsService');
const { getReportTemplateStaticContent } = require('./reportTemplateDocx');
const { sanitizeScanForLLM } = require('./geminiSanitizer');

// ─── Config ────────────────────────────────────────────────────────────────────
// Spec requirement: PDFKit-only (no Puppeteer/HTML renderer)
const PDF_RENDERER = 'pdfkit';
const pdfOpts = { maxRetries: 1, timeoutMs: 35000, maxBackoffMs: 3000 };
// Japanese translation is the single most failure-prone step and its failure
// silently degrades the whole JA report (thin AI summary + untranslated findings).
// It gets a far more generous budget than the fast-fail `pdfOpts`: real retries
// for transient 503s and a per-attempt timeout large enough for a Flash call.
// The overall PDF job budget is 300s (virustotalRoutes PDF_JOB_TIMEOUT_MS), so
// this stays well within it even in the worst case.
const translateOpts = { maxRetries: 3, timeoutMs: 60000, maxBackoffMs: 15000 };
// Outer ceiling for the whole (chunked, multi-call) JA translation stage. A final
// safety net only — `_generate` already enforces per-attempt timeouts and retries.
const TRANSLATION_CEILING_MS = 200000;
// Vulnerabilities are translated in small chunks so one transient failure only
// costs that chunk (kept English), not the entire findings list.
const VULN_TRANSLATION_CHUNK_SIZE = 5;

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

function timeout(ms, message) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms));
}

function severityRank(risk) {
  const r = String(risk || '').toLowerCase();
  if (r.includes('critical') || r.includes('high') || r.includes('高')) return 4;
  if (r.includes('medium') || r.includes('中')) return 3;
  if (r.includes('low') || r.includes('低')) return 2;
  return 1;
}

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
      const trimmed = line.trim();
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


function escapeHtml(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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

function getRiskLabel(risk, lang) {
  if (lang !== 'ja') return risk || 'Unknown';
  const r = String(risk || '').toLowerCase();
  if (r.includes('high'))          return '高';
  if (r.includes('medium'))        return '中';
  if (r.includes('low'))           return '低';
  if (r.includes('informational')) return '情報';
  return '不明';
}

function stripBoldMarkers(text) { return String(text || '').replace(/\*\*/g, ''); }

function isBoldBalanced(text) {
  const m = String(text || '').match(/\*\*/g);
  return !m || m.length % 2 === 0;
}

// ─── Disclaimer / history helpers ───────────────────────────────────────────────

function getDisclaimerContent(lang) {
  if (lang === 'ja') return {
    title: '免責事項',
    body: [
      '本レポートは自動スキャン結果に基づいて作成されており、検出内容が不完全である場合や、環境・設定差により実際の状態と異なる場合があります。',
      '本レポートの内容について、完全性・正確性・最新性を保証するものではありません。重要な意思決定(運用判断、法的判断、投資判断等)を行う際には、本レポートのみに依拠せず、追加の検証や専門家による確認を実施してください。',
      '本レポートの利用に起因して発生したいかなる損害(直接・間接を問わず)についても、提供者は責任を負いません。'
    ].join('\n\n')
  };
  return {
    title: 'Disclaimer',
    body: [
      'This report is generated based on automated scan results. Detected findings may be incomplete or may differ from the actual state due to environmental or configuration differences.',
      'We do not guarantee the completeness, accuracy, or timeliness of the content of this report. When making important decisions (operational, legal, investment, etc.), please do not rely solely on this report and conduct additional verification or consultation with experts.',
      'The provider shall not be liable for any damages (direct or indirect) arising from the use of this report.'
    ].join('\n\n')
  };
}

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

function looksLikeUrl(text) {
  const s = String(text || '').trim();
  if (!s) return false;
  if (/^https?:\/\//i.test(s)) return true;
  if (/^www\./i.test(s)) return true;
  // e.g. example.com/path
  if (/^[\w.-]+\.[a-z]{2,}(\/|$)/i.test(s)) return true;
  return false;
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

function collectStringsForEnglishValidation(value, lang, keyHint = '') {
  const out = [];
  const walk = (v, k) => {
    if (v == null) return;
    // Raw HTTP evidence (verbatim request/response from the target) may legitimately
    // contain any language — skip these subtrees entirely for English validation.
    if (k && ['occurrences', 'request', 'response'].includes(k)) return;
    const projected = projectLangValue(v, lang);
    if (typeof projected === 'string') {
      // Allow URLs/targets/references to contain non-ASCII.
      if (k && ['target', 'url', 'urls', 'reference'].includes(k)) return;
      if (looksLikeUrl(projected)) return;
      out.push(projected);
      return;
    }
    if (typeof projected === 'number' || typeof projected === 'boolean') return;
    if (Array.isArray(projected)) {
      projected.forEach(item => walk(item, k));
      return;
    }
    if (typeof projected === 'object') {
      for (const kk of Object.keys(projected)) {
        walk(projected[kk], kk);
      }
    }
  };
  walk(value, keyHint);
  return out;
}

function assertEnglishOnlyPdfContent({ scanData, aiAnalysis, vulnerabilities, diagnosisTable }) {
  const pieces = [];
  pieces.push(...collectStringsForEnglishValidation(scanData, 'en'));
  pieces.push(...collectStringsForEnglishValidation(aiAnalysis, 'en'));
  pieces.push(...collectStringsForEnglishValidation(vulnerabilities, 'en'));
  pieces.push(...collectStringsForEnglishValidation(diagnosisTable, 'en'));

  for (const s of pieces) {
    if (containsJapanese(s)) {
      const err = new Error('English PDF contains non-English (Japanese) characters');
      err.code = 'EN_CONTENT_NOT_ENGLISH';
      err.sample = s.slice(0, 120);
      throw err;
    }
  }
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
  if (lang !== 'ja') return status || 'unknown';
  const s = status || '';
  if (s === 'completed')                            return '診断終了';
  if (s === 'combining' || s === 'pending' || s === 'queued') return 'スキャン中';
  if (s === 'failed')                               return '失敗';
  if (s === 'stopped' || s === 'cancelled')         return '停止';
  return s || '不明';
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
    const records = await ScanResult.find({ userId: scanResult.userId })
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

async function ensureGeminiScanHistory(scanData, scanHistoryRows) {
  const hasRows = !!(scanData?.scanHistory?.rows?.en?.length || scanData?.scanHistory?.rows?.ja?.length);
  if (hasRows) return scanData.scanHistory;
  // If Gemini returned rows but the sanitizer replaced executor fields with
  // "REDACTED", re-inject the real executedBy/date/status values from the
  // DB-provided `scanHistoryRows` so the PDF shows actual data.
  try {
    const formatted = scanData.scanHistory;
    if (formatted && formatted.rows && Array.isArray(scanHistoryRows)) {
      const enRows = Array.isArray(formatted.rows.en) ? formatted.rows.en : [];
      const jaRows = Array.isArray(formatted.rows.ja) ? formatted.rows.ja : [];
      for (let i = 0; i < scanHistoryRows.length; i++) {
        const src = scanHistoryRows[i] || {};
        if (enRows[i] && Array.isArray(enRows[i])) {
          for (let c = 0; c < enRows[i].length; c++) {
            const cell = enRows[i][c];
            if (typeof cell === 'string' && cell.includes('REDACTED')) {
              if (c === 0) enRows[i][c] = src.dateEn || cell.replace(/REDACTED/g, 'N/A');
              else if (c === 1) enRows[i][c] = src.executedByEn || cell.replace(/REDACTED/g, 'N/A');
              else if (c === 2) enRows[i][c] = src.status || cell.replace(/REDACTED/g, '');
            }
          }
        }
        if (jaRows[i] && Array.isArray(jaRows[i])) {
          for (let c = 0; c < jaRows[i].length; c++) {
            const cell = jaRows[i][c];
            if (typeof cell === 'string' && cell.includes('REDACTED')) {
              if (c === 0) jaRows[i][c] = src.dateJa || cell.replace(/REDACTED/g, 'N/A');
              else if (c === 1) jaRows[i][c] = src.executedByJa || cell.replace(/REDACTED/g, 'N/A');
              else if (c === 2) jaRows[i][c] = getStatusLabel(src.status, 'ja') || cell.replace(/REDACTED/g, '');
            }
          }
        }
      }
      // write back patched rows
      formatted.rows.en = enRows;
      formatted.rows.ja = jaRows;
      scanData.scanHistory = formatted;
    }
  } catch (e) {
    console.warn('[PDF] Failed to patch REDACTED in Gemini scanHistory:', e && e.message);
  }
  return scanData.scanHistory;
  try {
    const formatted = await formatScanHistoryForPdf(scanHistoryRows);
    if (scanData && typeof scanData === 'object') {
      scanData.scanHistory = formatted;
    }
    return formatted;
  } catch (e) {
    // Gemini unavailable — build a static fallback scan history table so the
    // PDF is still generated rather than returning a 500 to the user.
    console.warn('[PDF] ensureGeminiScanHistory: Gemini failed, using static fallback:', e.message);
    const fallbackHistory = {
      title: { en: 'Scan History', ja: '診断履歴' },
      headers: { en: ['Date', 'Executed by', 'Status'], ja: ['日付', '実行ユーザー', 'ステータス'] },
      rows: {
        en: (scanHistoryRows || []).map(r => [r.dateEn || '', r.executedByEn || '', r.status || '']),
        ja: (scanHistoryRows || []).map(r => [r.dateJa || '', r.executedByJa || '', r.status || ''])
      }
    };
    if (scanData && typeof scanData === 'object') {
      scanData.scanHistory = fallbackHistory;
    }
    return fallbackHistory;
  }
}

/**
 * Re-inject real scan metadata into scanData after Gemini formatting.
 *
 * The Gemini sanitizer replaces target/analysisId with "REDACTED" to protect
 * user privacy during LLM calls. This function restores the real values from
 * the original scanResult for PDF rendering.
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

async function getDiagnosisHistoryTable(scanResult, lang, limit = 8) {
  // ── 3-column design matching the report template ──
  const headers = lang === 'ja'
    ? ['日付', '実行ユーザー', 'ステータス']
    : ['Date', 'Executed by', 'Status'];
  const title = lang === 'ja' ? '診断履歴' : 'Scan History';

  const fallback = [[
    formatHistoryDate(scanResult?.createdAt, lang) || '',
    executorDisplay(scanResult?.userId, lang),
    getStatusLabel(scanResult?.status, lang)
  ]];

  if (!scanResult?.userId) return { title, headers, rows: fallback };

  try {
    const records = await ScanResult.find({ userId: scanResult.userId })
      .sort({ createdAt: -1 }).limit(limit)
      .select('analysisId target createdAt userId status')
      .populate('userId', 'name email').lean();

    const rows = (records || []).map(r => [
      formatHistoryDate(r.createdAt, lang),
      executorDisplay(r.userId, lang),
      getStatusLabel(r.status, lang)
    ]);

    return { title, headers, rows: rows.length ? rows : fallback };
  } catch { return { title, headers, rows: fallback }; }
}

// ─── Fallbacks when Gemini is unavailable ───────────────────────────────────────

function buildFallbackScanDataForPdf(scanResult) {
  const safe = (v, fb = 0) => { const n = Number(v); return isFinite(n) ? n : fb; };
  const cats  = scanResult?.pagespeedResult?.lighthouseResult?.categories || {};
  const perf  = safe(Math.round((cats.performance?.score   || 0) * 100));
  const a11y  = safe(Math.round((cats.accessibility?.score || 0) * 100));
  const bp    = safe(Math.round((cats['best-practices']?.score || 0) * 100));
  const seo   = safe(Math.round((cats.seo?.score            || 0) * 100));

  const obs   = scanResult?.observatoryResult  || {};
  const zap   = scanResult?.zapResult          || {};
  const urlsc = scanResult?.urlscanResult      || {};
  const wc    = scanResult?.webCheckResult?.fullResults || {};

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
      status: { en: scanResult?.status || 'unknown', ja: scanResult?.status === 'completed' ? '完了' : (scanResult?.status || '不明') }
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
          { label: { en: 'Performance',    ja: 'パフォーマンス'     }, value: `${perf}/100`,  type: 'score' },
          { label: { en: 'Accessibility',  ja: 'アクセシビリティ'    }, value: `${a11y}/100`,  type: 'score' },
          { label: { en: 'Best Practices', ja: 'ベストプラクティス'  }, value: `${bp}/100`,    type: 'score' },
          { label: { en: 'SEO',            ja: 'SEO'               }, value: `${seo}/100`,   type: 'score' }
        ]
      },
      {
        id: 'observatory',
        title: { en: 'Security Configuration Assessment', ja: 'セキュリティ設定評価' },
        items: [
          { label: { en: 'Security Grade',  ja: 'セキュリティ評価'  }, value: obs.grade || 'N/A',              type: 'grade'   },
          { label: { en: 'Score',           ja: 'スコア'            }, value: `${safe(obs.score, 0)}/100`,      type: 'score'   },
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
          name: a.alert, risk: a.risk, confidence: a.confidence,
          description: a.description || 'No description available',
          solution:    a.solution    || 'No solution provided',
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
          { label: { en: 'Threat Score', ja: '脅威スコア'  }, value: `${safe(urlsc?.verdicts?.overall?.score, 0)}/100`, type: 'score' },
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
          { label: { en: 'TLS Grade',    ja: 'TLS評価'      }, value: wc?.tls?.tlsInfo?.grade || wc?.ssl?.grade || 'N/A', type: 'grade' },
          { label: { en: 'WAF Detected', ja: 'WAF検出'      }, value: { en: wc?.firewall?.hasWaf ? 'Yes' : 'No', ja: wc?.firewall?.hasWaf ? 'はい' : 'いいえ' }, type: wc?.firewall?.hasWaf ? 'success' : 'warning' },
          { label: { en: 'HSTS Enabled', ja: 'HSTS有効'     }, value: { en: wc?.hsts?.enabled ? 'Yes' : 'No',    ja: wc?.hsts?.enabled ? '有効' : '無効'     }, type: wc?.hsts?.enabled ? 'success' : 'warning' },
          { label: { en: 'Technologies', ja: 'テクノロジー' }, value: Array.isArray(wc?.['tech-stack']?.technologies) ? wc['tech-stack'].technologies.slice(0, 5).map(t => t.name || t).join(', ') : 'N/A', type: 'stat' }
        ]
      }
    ]
  };
}

function buildJapaneseAiAnalysisFromScanData(scanData, vulnerabilitiesEn = []) {
  const risk   = scanData?.summary?.riskLevel?.ja || '不明';
  const target = scanData?.header?.target || '';
  const rc = { high: 0, medium: 0, low: 0, info: 0 };
  for (const v of vulnerabilitiesEn) {
    const r = String(v?.risk || '').toLowerCase();
    if (r.includes('high'))   rc.high++;
    else if (r.includes('medium')) rc.medium++;
    else if (r.includes('low'))    rc.low++;
    else rc.info++;
  }
  const findings = [];
  if (rc.high   > 0) findings.push(`高リスクの脆弱性が${rc.high}件検出されています。`);
  if (rc.medium > 0) findings.push(`中リスクの脆弱性が${rc.medium}件検出されています。`);
  if (!findings.length) findings.push('重大な脆弱性は検出されませんでした。');

  return {
    title: 'AIによるセキュリティ分析',
    sections: [
      { heading: '総評', content: [
          { type: 'paragraph', text: `対象: ${target}` },
          { type: 'paragraph', text: `総合リスク評価: ${risk}` },
          { type: 'bullets', items: findings }
      ]},
      { heading: '推奨対応', content: [{ type: 'bullets', items: [
          '高リスク項目は最優先で修正し、再スキャンで効果を確認してください。',
          '入力検証、認証・セッション管理、セキュリティヘッダーの設定状況を重点的に見直してください。',
          '運用上の露出（公開範囲、管理画面、API）を踏まえて、WAF/レート制限/監視も併用してください。'
      ]}]}
    ]
  };
}

/**
 * Translate the AI analysis and vulnerabilities to Japanese — resiliently and
 * granularly, so a failure in one area never blanks the whole Japanese report.
 *
 *  - The AI analysis is translated on its own. Only if that specific call fails
 *    (or returns no Japanese) does the AI narrative fall back to the short
 *    static buildJapaneseAiAnalysisFromScanData stub.
 *  - Vulnerabilities are translated in small chunks. A chunk that fails keeps its
 *    English text while the other chunks stay Japanese (partial success).
 *  - `occurrences` (raw request/response) and `sampleUrls`/`urls` are always kept
 *    from the English source and re-attached — they are never sent to Gemini and
 *    never lost, so the Request/Response Evidence section still renders.
 *
 * `deps` lets tests inject stub translators (no network); production uses the real
 * Gemini calls with the generous `translateOpts` budget.
 *
 * @returns {Promise<{ aiToUse: object|null, vulnsToUse: Array }>}
 */
async function translateReportToJapanese({ aiAnalysis = null, vulnsEn = [], scanData = null } = {}, deps = {}) {
  const {
    translateAi        = (ai)    => translateAiAnalysisSectionsToJapanese(ai, translateOpts),
    translateVulnChunk = (chunk) => translateVulnerabilitiesToJapanese(chunk, translateOpts),
    chunkSize          = VULN_TRANSLATION_CHUNK_SIZE,
    logLabel           = 'PDF'
  } = deps;

  // ── AI analysis (independent) ───────────────────────────────────────────────
  let aiToUse = aiAnalysis;
  if (aiAnalysis) {
    try {
      const ja = await translateAi(aiAnalysis);
      // Accept the translated analysis only if at least one SECTION actually became
      // Japanese (the title alone is always Japanese, so it can't be the signal).
      // If every section failed to translate, fall back to the static summary.
      if (ja && ja.sections?.length && containsJapanese(JSON.stringify(ja.sections))) {
        aiToUse = ja;
      } else {
        console.warn(`[${logLabel}] AI translation produced no Japanese sections — using static summary`);
        aiToUse = buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn);
      }
    } catch (e) {
      console.warn(`[${logLabel}] AI analysis translation failed (${e.message}) — using static summary`);
      aiToUse = buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn);
    }
  }

  // ── Vulnerabilities (independent, chunked) ──────────────────────────────────
  // Start as the English list; replace each chunk in place only on success.
  const vulnsToUse = vulnsEn.slice();
  for (let start = 0; start < vulnsEn.length; start += chunkSize) {
    const chunkEn = vulnsEn.slice(start, start + chunkSize);
    // Strip bulky/technical fields before translation; re-attached from source below.
    const chunkForTranslate = chunkEn.map(({ occurrences, sampleUrls, urls, ...rest }) => rest);
    try {
      const jaChunk = await translateVulnChunk(chunkForTranslate);
      if (Array.isArray(jaChunk)) {
        jaChunk.forEach((jv, i) => {
          const src = chunkEn[i];
          if (!src || !jv) return;
          vulnsToUse[start + i] = {
            ...src, // keep name/risk/confidence/reference/cwe/wasc + occurrences/sampleUrls/urls
            description: jv.description ?? src.description,
            solution:    jv.solution ?? src.solution
          };
        });
      }
    } catch (e) {
      console.warn(`[${logLabel}] Vulnerability chunk ${start + 1}-${start + chunkEn.length} translation failed (${e.message}) — keeping English for this chunk`);
      // chunk stays English (already present in vulnsToUse)
    }
  }

  return { aiToUse, vulnsToUse };
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

async function fetchFullAlertsFromGridFS(scanResult, zapSection, accessLevel) {
  if (!zapSection || !scanResult.zapResult?.reportFiles?.length) return;
  const file = scanResult.zapResult.reportFiles.find(f => f.filename?.includes('detailed_alerts'));
  if (!file?.fileId) return;
  try {
    const bucket = file.filename?.includes('zap_auth') ? 'zap_auth_reports' : 'zap_reports';
    const buf    = await gridfsService.downloadFile(file.fileId, bucket);
    const full   = JSON.parse(buf.toString('utf-8'));
    // Apply plan filter before building the alerts array for the PDF
    const filtered = getSanitizedAlerts(full, accessLevel);
    zapSection.detailedAlerts = filtered.map(a => ({
      name: a.alert, risk: a.risk, confidence: a.confidence,
      description: a.description || 'No description available',
      solution:    a.solution    || 'No solution provided',
      reference:   a.reference   || '',
      cweid: a.cweid, wascid: a.wascid,
      totalOccurrences: a.totalOccurrences || a.occurrences?.length || 0,
      sampleUrls: a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || [],
      // Preserve full occurrences (incl. raw request/response) for the
      // proof-of-exploit section rendered below.
      occurrences: Array.isArray(a.occurrences) ? a.occurrences : []
    }));
    console.log(`✅ Loaded ${zapSection.detailedAlerts.length} plan-filtered alerts from GridFS`);
  } catch (e) {
    console.warn(`⚠️ GridFS fetch failed: ${e.message}`);
  }
}

// ─── HTML renderer (Puppeteer) ──────────────────────────────────────────────────

async function renderHtmlToPdfBuffer(html) {
  if (!puppeteer) throw new Error('Puppeteer not available');
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    return await page.pdf({ format: 'A4', printBackground: true,
      margin: { top: '14mm', bottom: '14mm', left: '14mm', right: '14mm' } });
  } finally { await browser.close(); }
}

function sharedCss() {
  const fontUrl = pathToFileURL(FONTS.regular).toString();
  return `
    @font-face { font-family: NotoSansJP; src: url('${fontUrl}'); }
    * { box-sizing: border-box; }
    body { font-family: NotoSansJP, Arial, sans-serif; color: ${COLORS.text}; }
    h1 { color: ${COLORS.primary}; font-size: 22px; margin: 0 0 6px; }
    h2 { color: ${COLORS.primary}; font-size: 16px; margin: 18px 0 8px; }
    h3 { color: ${COLORS.primary}; font-size: 12px; margin: 12px 0 6px; }
    h4 { color: ${COLORS.accent};  font-size: 10px; margin: 10px 0 4px; }
    p, li, td, th { font-size: 10px; line-height: 1.45; }
    p  { margin: 0 0 6px; overflow-wrap: anywhere; word-break: break-word; }
    ul { margin: 0 0 6px 18px; padding: 0; }
    .page-break { page-break-before: always; }
    .meta { display: flex; flex-wrap: wrap; gap: 14px; color: ${COLORS.textLight}; font-size: 9px; margin-bottom: 6px; }
    .kv  { margin: 2px 0; }
    .k   { color: ${COLORS.textLight}; }
    .ok  { color: ${COLORS.success}; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid ${COLORS.border}; padding: 6px; vertical-align: top; overflow-wrap: anywhere; }
    th { background: #f3f4f6; text-align: left; }
    .vuln { border-top: 1px solid ${COLORS.border}; padding-top: 8px; margin-top: 8px; }
  `;
}

function buildSingleLanguageReportHtml({ scanData, aiAnalysis, vulnerabilities, lang, disclaimer, diagnosis }) {
  const L = lang;
  const hdr  = scanData?.header || {};
  const summ = scanData?.summary || {};
  const title     = typeof hdr.title      === 'object' ? hdr.title[L]      : (hdr.title || 'Security Scan Report');
  const riskLabel = typeof summ.riskLabel === 'object' ? summ.riskLabel[L] : (summ.riskLabel || 'Overall Risk');
  const riskLevel = typeof summ.riskLevel === 'object' ? summ.riskLevel[L] : (summ.riskLevel || 'N/A');
  const aiTitle   = escapeHtml(aiAnalysis?.title || (L === 'ja' ? 'AIによるセキュリティ分析' : 'AI-Generated Security Analysis'));

  const renderBlocks = blocks => (Array.isArray(blocks) ? blocks : []).map(b => {
    if (!b) return '';
    if (b.type === 'paragraph')  return `<p>${escapeHtml(b.text || '')}</p>`;
    if (b.type === 'bullets')    return `<ul>${(b.items || []).map(it => `<li>${escapeHtml(it)}</li>`).join('')}</ul>`;
    if (b.type === 'bold_text')  return `<p><strong>${escapeHtml(b.label || '')}</strong> ${escapeHtml(b.text || '')}</p>`;
    return b.text ? `<p>${escapeHtml(b.text)}</p>` : '';
  }).join('');

  const aiSections = (aiAnalysis?.sections || []).map(s => {
    const hd = s?.heading ? `<h3>${escapeHtml(s.heading)}</h3>` : '';
    return `${hd}${renderBlocks(s?.content)}`;
  }).join('');

  const scanSections = (scanData?.sections || []).map(s => {
    const st = typeof s.title === 'object' ? s.title[L] : s.title || '';
    const items = (s.items || []).map(it => {
      const lbl = typeof it.label === 'object' ? it.label[L] : it.label || '';
      let val = it.value;
      if (typeof val === 'object' && val) val = val[L] || val.en || '';
      return `<div class="kv"><span class="k">${escapeHtml(lbl)}:</span> <span>${escapeHtml(String(val ?? ''))}</span></div>`;
    }).join('');
    return `<section><h3>${escapeHtml(st)}</h3>${items}</section>`;
  }).join('');

  const vulnHtml = (() => {
    const list = Array.isArray(vulnerabilities) ? vulnerabilities : [];
    if (!list.length) return `<p class="ok">${L === 'ja' ? '脆弱性は検出されませんでした。' : 'No vulnerabilities detected.'}</p>`;
    return list.map((v, i) => `
      <div class="vuln">
        <h3>${i + 1}. ${escapeHtml(v?.name || v?.alert || '')}</h3>
        <div class="meta">
          <span>${escapeHtml(L === 'ja' ? 'リスク' : 'Risk')}: ${escapeHtml(String(v?.risk || ''))}</span>
          <span>${escapeHtml(L === 'ja' ? '信頼度' : 'Confidence')}: ${escapeHtml(String(v?.confidence || ''))}</span>
        </div>
        ${v?.description ? `<h4>${escapeHtml(L === 'ja' ? '説明' : 'Description')}</h4><p>${escapeHtml(v.description)}</p>` : ''}
        ${v?.solution    ? `<h4>${escapeHtml(L === 'ja' ? '推奨される修正方法' : 'Recommended Solution')}</h4><p>${escapeHtml(v.solution)}</p>` : ''}
        ${v?.reference   ? `<h4>${escapeHtml(L === 'ja' ? '参考情報' : 'References')}</h4><p>${escapeHtml(v.reference)}</p>` : ''}
      </div>`).join('');
  })();

  const histHtml = `<table>
    <thead><tr>${(diagnosis?.headers || []).map(h => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead>
    <tbody>${(diagnosis?.rows || []).map(r => `<tr>${(r || []).map(c => `<td>${escapeHtml(String(c ?? ''))}</td>`).join('')}</tr>`).join('')}</tbody>
  </table>`;

  return `<!doctype html><html lang="${L === 'ja' ? 'ja' : 'en'}"><head><meta charset="utf-8"/>
  <style>${sharedCss()}</style></head><body>
  <h1>${escapeHtml(title)}</h1>
  <div class="meta">
    <span>${escapeHtml(L === 'ja' ? 'スキャンURL' : 'Scan URL')}: ${escapeHtml(hdr.target || '')}</span>
    <span>${escapeHtml(L === 'ja' ? '生成日' : 'Generated')}: ${escapeHtml((() => { const dr = hdr.dateRaw || hdr.date || ''; const dd = dr instanceof Date ? dr : (dr ? new Date(dr) : null); return dd && !isNaN(dd.getTime()) ? formatCoverDate(dd, L) : String(dr); })())}</span>
    <span>${escapeHtml(L === 'ja' ? 'スキャンID' : 'Scan ID')}: ${escapeHtml(hdr.scanId || '')}</span>
  </div>
  <h2>${escapeHtml(L === 'ja' ? 'エグゼクティブサマリー' : 'Executive Summary')}</h2>
  <p><strong>${escapeHtml(riskLabel)}:</strong> ${escapeHtml(String(riskLevel))}</p>
  <h2>${aiTitle}</h2>${aiSections}
  <h2>${escapeHtml(L === 'ja' ? 'スキャン結果' : 'Scan Results')}</h2>${scanSections}
  <h2>${escapeHtml(L === 'ja' ? '脆弱性の詳細と修正方法' : 'Vulnerability Details & Remediation')}</h2>${vulnHtml}
  <div class="page-break"></div>
  <h2>${escapeHtml(disclaimer?.title || (L === 'ja' ? '免責事項' : 'Disclaimer'))}</h2>
  ${String(disclaimer?.body || '').split('\n').map(l => `<p>${escapeHtml(l)}</p>`).join('')}
  <div class="page-break"></div>
  <h2>${escapeHtml(diagnosis?.title || (L === 'ja' ? '診断履歴' : 'Scan History'))}</h2>${histHtml}
  </body></html>`;
}

function buildBilingualReportHtml({ enHtml, jaHtml }) {
  const extract = html => { const m = String(html || '').match(/<body[^>]*>([\s\S]*?)<\/body>/i); return m ? m[1] : html; };
  const fontUrl = pathToFileURL(FONTS.regular).toString();
  return `<!doctype html><html><head><meta charset="utf-8"/>
  <style>@font-face{font-family:NotoSansJP;src:url('${fontUrl}')} ${sharedCss()}</style></head>
  <body>${extract(enHtml)}<div class="page-break"></div>${extract(jaHtml)}</body></html>`;
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
      .text(`${lang === 'ja' ? 'スキャンURL' : 'Scan URL'}: ${targetS}`, ML, 318, { width: cw, align: 'center' });

  // 5. Date & Scan ID
  doc.fontSize(10).fillColor(COLORS.textLight)
      .text(`${lang === 'ja' ? '生成日' : 'Generated'}: ${dateS}`, ML, 348, { width: cw, align: 'center' })
      .text(`${lang === 'ja' ? 'スキャンID' : 'Scan ID'}: ${scanIdS}`, ML, 363, { width: cw, align: 'center' });

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
  const sectionTitle = lang === 'ja' ? 'AIによるセキュリティ分析' : 'AI-Generated Security Analysis';
  if (!aiAnalysis) {
    addTemplateSectionHeader(ctx, sectionTitle);
    const notice = lang === 'ja'
      ? 'AIによる分析はモデルのクォータ制限により生成できませんでした。すべてのスキャン結果と検出内容は以下に記載されています。'
      : 'AI analysis could not be generated due to model quota limitations. All scan findings and security results are included below.';
    writeFlowText(ctx, notice, { lineGap: 3, fontSize: 10, color: COLORS.textLight });
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
  addTemplateSectionHeader(ctx, lang === 'ja' ? 'スキャン結果' : 'Scan Results');
  doc.font('NotoSans').fontSize(10).fillColor(COLORS.textLight)
     .text(lang === 'ja' ? 'スキャン結果の詳細' : 'Scan Results Details');
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
  addTemplateSectionHeader(ctx, lang === 'ja' ? '脆弱性の詳細と修正方法' : 'Vulnerability Details & Remediation');

  if (!vulnerabilities?.length) {
    doc.font('NotoSans').fontSize(11).fillColor(COLORS.success)
       .text(lang === 'ja' ? '脆弱性は検出されませんでした' : 'No vulnerabilities detected');
    doc.moveDown(0.5); return;
  }

  vulnerabilities.forEach((v, idx) => {
    ensureSpace(ctx, 80);
     const vName = sanitizeTextForPdf(v.name || v.alert || '', lang);
     doc.font('NotoSans-Bold').fontSize(11).fillColor(COLORS.text)
       .text(`${idx + 1}. ${vName}`);
    doc.font('NotoSans').fontSize(9).fillColor(COLORS.textLight)
       .text(`${lang === 'ja' ? 'リスク' : 'Risk'}: `, { continued: true })
       .fillColor(getRiskColor(v.risk)).font('NotoSans-Bold')
       .text(lang === 'ja' ? getRiskLabel(v.risk, 'ja') : (v.risk || 'Unknown'), { continued: true })
       .fillColor(COLORS.textLight).font('NotoSans')
       .text(`  |  ${lang === 'ja' ? '信頼度' : 'Confidence'}: `, { continued: true })
       .fillColor(COLORS.text).text(v.confidence || 'Unknown');
    doc.moveDown(0.2);

    if (v.description) {
      ensureSpace(ctx, 30);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.primary)
         .text(lang === 'ja' ? '説明:' : 'Description:');
      writeFlowText(ctx, v.description, { lineGap: 2, fontSize: 9, color: COLORS.text });
      doc.moveDown(0.2);
    }
    if (v.solution) {
      ensureSpace(ctx, 30);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.success)
         .text(lang === 'ja' ? '推奨される修正方法:' : 'Recommended Solution:');
      writeFlowText(ctx, v.solution, { lineGap: 2, fontSize: 9, color: COLORS.text });
      doc.moveDown(0.2);
    }
    if (v.sampleUrls && v.sampleUrls.length > 0) {
      ensureSpace(ctx, 30);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.warning)
         .text(lang === 'ja' ? '影響を受けるURL (一部):' : 'Affected URLs (Sample):');
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
    if (occWithRaw.length > 0) {
      ensureSpace(ctx, 40);
      doc.font('NotoSans-Bold').fontSize(9).fillColor(COLORS.primary)
         .text(lang === 'ja' ? 'リクエスト / レスポンスの証跡:' : 'Request / Response Evidence:');
      doc.moveDown(0.1);

      occWithRaw.slice(0, 3).forEach((occ, oIdx) => {
        ensureSpace(ctx, 30);
        const metaBits = [
          occ.method ? String(occ.method) : null,
          occ.url ? String(occ.url) : null,
          occ.param ? `${lang === 'ja' ? 'パラメータ' : 'param'}: ${occ.param}` : null
        ].filter(Boolean).join('  ');
        doc.font('NotoSans-Bold').fontSize(8).fillColor(COLORS.text)
           .text(`#${oIdx + 1}  ${sanitizeTextForPdf(metaBits, lang)}`);

        if (occ.request) {
          ensureSpace(ctx, 16);
          doc.font('NotoSans-Bold').fontSize(8).fillColor(COLORS.textLight)
             .text(lang === 'ja' ? 'リクエスト:' : 'Request:');
          writeFlowText(ctx, `${occ.request.header || ''}${occ.request.body || ''}`,
            { lineGap: 1, fontSize: 7, color: COLORS.text });
        }
        if (occ.response) {
          ensureSpace(ctx, 16);
          doc.font('NotoSans-Bold').fontSize(8).fillColor(COLORS.textLight)
             .text(lang === 'ja' ? 'レスポンス:' : 'Response:');
          writeFlowText(ctx, `${occ.response.header || ''}${occ.response.body || ''}`,
            { lineGap: 1, fontSize: 7, color: COLORS.text });
        }
        doc.moveDown(0.15);
      });

      if (occWithRaw.length > 3) {
        ensureSpace(ctx, 12);
        doc.font('NotoSans').fontSize(7).fillColor(COLORS.textLight)
           .text(lang === 'ja'
             ? `他 ${occWithRaw.length - 3} 件のリクエスト/レスポンスはJSONエクスポートに含まれます`
             : `${occWithRaw.length - 3} more request/response pair(s) available in the JSON export`);
      }
      doc.moveDown(0.2);
    }

    if (v.reference) {
      ensureSpace(ctx, 16);
      doc.font('NotoSans').fontSize(8).fillColor(COLORS.textLight)
          .text(`${lang === 'ja' ? '参考情報' : 'References'}: ${sanitizeTextForPdf(v.reference, lang)}`);
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
  doc.registerFont('NotoSans',      FONTS.regular);
  doc.registerFont('NotoSans-Bold', FONTS.bold);
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

  const isJa = lang === 'ja';

  console.time('[PDF] Total');
  console.log('[PDF] Loading scan data');

  // Sanitized copy for Gemini calls only.
  const llmSafeScan = sanitizeScanForLLM(scanResult);

  const pdfSafeScan = JSON.parse(JSON.stringify(llmSafeScan));
  if (pdfSafeScan.zapResult && Array.isArray(pdfSafeScan.zapResult.alerts)) {
    pdfSafeScan.zapResult.alerts = pdfSafeScan.zapResult.alerts
      .sort((a, b) => severityRank(b.risk) - severityRank(a.risk))
      .slice(0, 50);
  }
  if (pdfSafeScan.webCheckResult && pdfSafeScan.webCheckResult.fullResults) {
    for (const key of Object.keys(pdfSafeScan.webCheckResult.fullResults)) {
      const res = pdfSafeScan.webCheckResult.fullResults[key];
      if (res) {
        delete res.html;
        delete res.rawResponse;
        delete res.headersDump;
      }
    }
  }
  if (pdfSafeScan.pagespeedResult?.lighthouseResult?.categories) {
    const cats = pdfSafeScan.pagespeedResult.lighthouseResult.categories;
    pdfSafeScan.pagespeedResult.lighthouseResult.categories = {
      performance: cats.performance,
      accessibility: cats.accessibility,
      'best-practices': cats['best-practices'],
      seo: cats.seo
    };
  }
  if (pdfSafeScan.urlscanResult) {
    pdfSafeScan.urlscanResult = {
      verdicts: pdfSafeScan.urlscanResult.verdicts,
      page: pdfSafeScan.urlscanResult.page,
      stats: pdfSafeScan.urlscanResult.stats
    };
  }
  if (pdfSafeScan.observatoryResult) {
    pdfSafeScan.observatoryResult = {
      grade: pdfSafeScan.observatoryResult.grade,
      score: pdfSafeScan.observatoryResult.score,
      tests_passed: pdfSafeScan.observatoryResult.tests_passed,
      tests_failed: pdfSafeScan.observatoryResult.tests_failed,
      tests_quantity: pdfSafeScan.observatoryResult.tests_quantity
    };
  }

  const chars = JSON.stringify(pdfSafeScan).length;
  console.log('[PDF] Prompt trimmed');
  console.log('[PDF] Prompt size:', chars);
  console.log('[PDF] Estimated tokens:', Math.ceil(chars / 4));
  console.log('[PDF] ZAP alerts:', pdfSafeScan.zapResult?.alerts?.length || 0);

  console.log(`[PDF][${analysisId}] Fetching scan history rows…`);
  const scanHistoryRows = await fetchScanHistoryRows(scanResult);

  console.log('[PDF] Starting Gemini formatting');
  console.time('[PDF] Gemini format');
  let scanData;
  try { 
    scanData = await Promise.race([
      formatScanDataForPdf(pdfSafeScan, { scanHistoryRows, ...pdfOpts }),
      timeout(35000, 'formatScanDataForPdf timed out')
    ]);
  }
  catch (e) {
    console.warn(`[PDF][${analysisId}] Gemini scan data formatting failed, using fallback:`, e.message);
    scanData = buildFallbackScanDataForPdf(scanResult);
  }
  console.timeEnd('[PDF] Gemini format');
  console.log('[PDF] Gemini formatting completed');

  // Re-inject real scan metadata (target URL, scan ID, date) that was
  // replaced with "REDACTED" by the Gemini sanitizer.
  injectRealScanMetadata(scanData, scanResult);

  console.log(`[PDF][${analysisId}] Ensuring scan history…`);
  await ensureGeminiScanHistory(scanData, scanHistoryRows);

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

  const vulnsEn = zapSection?.detailedAlerts || [];
  let aiToUse = aiAnalysis, vulnsToUse = vulnsEn;

  if (isJa && (aiAnalysis || vulnsEn.length)) {
    console.log(`[PDF][${analysisId}] Starting JA translation…`);
    console.time('[PDF] Translate JA');
    try {
      const out = await Promise.race([
        translateReportToJapanese({ aiAnalysis, vulnsEn, scanData }, { logLabel: `PDF][${analysisId}` }),
        timeout(TRANSLATION_CEILING_MS, 'JA translation timed out')
      ]);
      aiToUse    = out.aiToUse;
      vulnsToUse = out.vulnsToUse;
    } catch (e) {
      // Only reached if the whole stage exceeds the ceiling — per-area failures are
      // already handled inside translateReportToJapanese. Degrade gracefully:
      // static AI summary + English findings (occurrences preserved for evidence).
      console.warn(`[PDF][${analysisId}] JA translation stage failed (${e.message}) — static AI summary + English findings`);
      aiToUse    = aiAnalysis ? buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn) : null;
      vulnsToUse = vulnsEn;
    }
    console.timeEnd('[PDF] Translate JA');
    console.log('[PDF] JA translation completed');
  }

  const disclaimer = getDisclaimerContent(lang);
  const scanHistory = scanData?.scanHistory || null;
  const diagnosis = {
    title: projectLangValue(scanHistory?.title, lang) || (lang === 'ja' ? '診断履歴' : 'Scan History'),
    headers: (scanHistory?.headers && scanHistory.headers[lang]) ? scanHistory.headers[lang] : (lang === 'ja' ? ['日付', '実行ユーザー', 'ステータス'] : ['Date', 'Executed by', 'Status']),
    rows: (scanHistory?.rows && scanHistory.rows[lang]) ? scanHistory.rows[lang] : [[
      lang === 'ja' ? (scanHistoryRows[0]?.dateJa || '') : (scanHistoryRows[0]?.dateEn || ''),
      lang === 'ja' ? (scanHistoryRows[0]?.executedByJa || '') : (scanHistoryRows[0]?.executedByEn || ''),
      lang === 'ja' ? getStatusLabel(scanHistoryRows[0]?.status, 'ja') : (scanHistoryRows[0]?.status || 'unknown')
    ]]
  };

  if (!isJa) {
    assertEnglishOnlyPdfContent({
      scanData,
      aiAnalysis: aiToUse,
      vulnerabilities: vulnsToUse,
      diagnosisTable: diagnosis
    });
  }

  if (PDF_RENDERER === 'html') {
    try {
      const html = buildSingleLanguageReportHtml({ scanData, aiAnalysis: aiToUse, vulnerabilities: vulnsToUse, lang, disclaimer, diagnosis });
      return await renderHtmlToPdfBuffer(html);
    } catch (e) { console.warn('⚠️ HTML renderer failed:', e.message); }
  }

  console.log(`[PDF][${analysisId}] Rendering PDFKit document…`);
  const tsBase = await getReportTemplateStaticContent({ lang });
  const ts = buildTemplateStaticOverrides(tsBase, { lang, scanData });
  ts.diagnosisTitle   = diagnosis.title;
  ts.diagnosisHeaders = diagnosis.headers;
  ts.diagnosisRows    = diagnosis.rows;

  const doc = makePdfDoc({
    Title:   `Security Scan Report (${lang.toUpperCase()}) - ${scanResult.target}`,
    Author:  'SSDT',
    Subject: 'Security Analysis'
  });
  
  console.log(`[PDF][${analysisId}] Rendering PDF`);
  console.time('[PDF] Render');
  const buf = collectBuffer(doc);
  renderTemplateReport(doc, scanData, aiToUse, vulnsToUse, lang, ts);
  doc.end();
  console.timeEnd('[PDF] Render');
  console.log(`[PDF][${analysisId}] PDF completed`);
  console.timeEnd('[PDF] Total');
  return buf;
}

/**
 * Generate a ZAP-only vulnerability PDF.
 */
async function generateZapPdf(scanResult, lang = 'en', accessLevel = 'critical-high') {
  console.log(`📄 Starting ZAP ${lang.toUpperCase()} PDF generation…`);
  const isJa = lang === 'ja';

  // llmSafeScan used only if a Gemini translation is triggered below.
  // For English ZAP PDFs no Gemini call is made, so this is a no-op overhead.
  let vulnerabilities = [];

  if (scanResult.zapResult?.reportFiles?.length) {
    const file = scanResult.zapResult.reportFiles.find(f => f.filename?.includes('detailed_alerts'));
    if (file?.fileId) {
      try {
        const bucket = file.filename?.includes('zap_auth') ? 'zap_auth_reports' : 'zap_reports';
        const buf    = await gridfsService.downloadFile(file.fileId, bucket);
        const full   = JSON.parse(buf.toString('utf-8'));
        // Apply plan filter before building the vulnerabilities list
        const filtered = getSanitizedAlerts(full, accessLevel);
        vulnerabilities = filtered.map(a => ({
          name: a.alert, risk: a.risk, confidence: a.confidence,
          description: a.description || 'No description available',
          solution:    a.solution    || 'No solution provided',
          reference:   a.reference   || '',
          cweid: a.cweid, wascid: a.wascid,
          totalOccurrences: a.totalOccurrences || a.occurrences?.length || 0,
          sampleUrls: a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || [],
          // Full occurrences (incl. raw request/response) for the proof-of-exploit section.
          occurrences: Array.isArray(a.occurrences) ? a.occurrences : [],
          urls: [] // occurrence URLs contain target domain — stripped before Gemini translation
        }));
      } catch (e) { console.warn(`⚠️ GridFS fetch failed: ${e.message}`); }
    }
  }

  if (!vulnerabilities.length && scanResult.zapResult?.summaryAlerts) {
    const filtered = getSanitizedAlerts(scanResult.zapResult.summaryAlerts, accessLevel);
    vulnerabilities = filtered.map(a => ({
      name: a.alert, risk: a.risk, confidence: a.confidence,
      description: a.description || 'No description available',
      solution:    a.solution    || 'No solution provided',
      reference: a.reference || '', cweid: a.cweid, wascid: a.wascid,
      totalOccurrences: a.totalOccurrences || 0, 
      sampleUrls: a.sampleUrls || a.occurrences?.slice(0, 10).map(o => o.uri || o) || [],
      urls: [] // occurrence URLs stripped
    }));
  }

  let vulnsToUse = vulnerabilities;
  if (isJa && vulnerabilities.length) {
    try {
      const out = await Promise.race([
        translateReportToJapanese({ aiAnalysis: null, vulnsEn: vulnerabilities, scanData: null }, { logLabel: 'ZAP-PDF' }),
        timeout(TRANSLATION_CEILING_MS, 'JA translation timed out')
      ]);
      vulnsToUse = out.vulnsToUse;
    } catch (e) {
      console.warn('[PDF] JA vuln translation stage failed:', e.message);
      // vulnsToUse stays as English vulnerabilities — ZAP PDF still includes all findings
    }
  }

  const ts  = await getReportTemplateStaticContent({ lang });
  const tsFinal = buildTemplateStaticOverrides(ts, { lang });

  const doc = makePdfDoc({
    Title:   `ZAP Vulnerability Report (${lang.toUpperCase()}) - ${scanResult.target}`,
    Author:  'SSDT - OWASP ZAP',
    Subject: 'Detailed Vulnerability Analysis'
  });
  const buf = collectBuffer(doc);
  renderTemplateZapReport(doc, vulnsToUse, lang, tsFinal);
  doc.end();
  return buf;
}

module.exports = { generateSingleLanguagePdf, generateZapPdf, translateReportToJapanese, buildAiAnalysisFromRefinedReport, renderVulnerabilityDetailsSection };