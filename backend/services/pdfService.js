'use strict';

/**
 * pdfService.js
 * Generates bilingual (English + Japanese) security scan PDF reports.
 * Depends on: geminiService.js, gridfsService.js, ScanResult model.
 *
 * Usage:
 *   const { generatePdfReport, generateSingleLanguagePdf, generateZapPdf } = require('./pdfService');
 *   const pdfBuffer = await generatePdfReport(scanResult);          // bilingual
 *   const pdfBuffer = await generateSingleLanguagePdf(scanResult, 'en');
 *   const pdfBuffer = await generateZapPdf(scanResult, 'ja');
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

let puppeteer;
try { puppeteer = require('puppeteer'); } catch { puppeteer = null; }

const ScanResult = require('../models/ScanResult');
const { formatScanDataForPdf, formatScanHistoryForPdf, formatAiAnalysisForPdf, translateToJapanese } = require('./geminiService');
const gridfsService = require('./gridfsService');
const { getReportTemplateStaticContent } = require('./reportTemplateDocx');

// ─── Config ────────────────────────────────────────────────────────────────────
// Spec requirement: PDFKit-only (no Puppeteer/HTML renderer)
const PDF_RENDERER = 'pdfkit';
const RATE_LIMIT_DELAY = 35_000; // 35 s — keeps Gemini under 2 RPM

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
          totalOccurrences: a.totalOccurrences || 0
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
 * Build the static strings/overrides applied on top of the template content.
 * Now accepts scanData so the final page can show scan-specific metadata.
 */
function buildTemplateStaticOverrides(base, { lang, scanData }) {
  // Spec requirement: template static strings come verbatim from the DOCX and
  // must not be overridden in code; EN/JA share the same extracted content.
  return { ...(base || {}), lang };
}

// ─── GridFS helper ──────────────────────────────────────────────────────────────

async function fetchFullAlertsFromGridFS(scanResult, zapSection) {
  if (!zapSection || !scanResult.zapResult?.reportFiles?.length) return;
  const file = scanResult.zapResult.reportFiles.find(f => f.filename?.includes('detailed_alerts'));
  if (!file?.fileId) return;
  try {
    const bucket = file.filename?.includes('zap_auth') ? 'zap_auth_reports' : 'zap_reports';
    const buf    = await gridfsService.downloadFile(file.fileId, bucket);
    const full   = JSON.parse(buf.toString('utf-8'));
    zapSection.detailedAlerts = full.map(a => ({
      name: a.alert, risk: a.risk, confidence: a.confidence,
      description: a.description || 'No description available',
      solution:    a.solution    || 'No solution provided',
      reference:   a.reference   || '',
      cweid: a.cweid, wascid: a.wascid,
      totalOccurrences: a.totalOccurrences || a.occurrences?.length || 0
    }));
    console.log(`✅ Loaded ${zapSection.detailedAlerts.length} full alerts from GridFS`);
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
    <span>${escapeHtml(L === 'ja' ? '生成日' : 'Generated')}: ${escapeHtml(hdr.date || '')}</span>
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
  const dateRaw = scanData.header?.date || '';
  // Try to parse and reformat dates to spec; if parsing fails, keep sanitized raw.
  const parsed = dateRaw ? new Date(dateRaw) : null;
  const dateS = parsed && !isNaN(parsed.getTime())
    ? formatHistoryDate(parsed, lang)
    : sanitizeTextForPdf(dateRaw, lang);
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

/**
 * Generate a bilingual (EN + JA) PDF.
 */
async function generatePdfReport(scanResult) {
  console.log('📄 Starting bilingual PDF generation…');

  // Scan history input is dynamic and generated by Gemini as part of scanData.
  const scanHistoryRows = await fetchScanHistoryRows(scanResult);

  // Step 1 – scan data
  let scanData;
  try   { scanData = await formatScanDataForPdf(scanResult, { scanHistoryRows }); }
  catch (e) {
    console.warn('[PDF] Gemini scan data formatting failed, using fallback:', e.message);
    scanData = buildFallbackScanDataForPdf(scanResult);
  }

  // Ensure scanHistory is always populated even if scanData fallback path is used.
  await ensureGeminiScanHistory(scanData, scanHistoryRows);

  const zapSection = scanData.sections?.find(s => s.id === 'zap');
  await fetchFullAlertsFromGridFS(scanResult, zapSection);

  await new Promise(r => setTimeout(r, RATE_LIMIT_DELAY));

  // Step 2 – AI analysis (EN)
  let aiAnalysisEn = null;
  if (scanResult.refinedReport) {
    try {
      aiAnalysisEn = await formatAiAnalysisForPdf(scanResult.refinedReport);
      console.log('[PDF] Using Gemini-generated report');
    } catch (e) {
      console.warn('[PDF] AI section unavailable, generating PDF from scan findings:', e.message);
      // aiAnalysisEn stays null — PDF renders without AI narrative section
    }
  }

  await new Promise(r => setTimeout(r, RATE_LIMIT_DELAY));

  // Step 3 – translate to JA (static fallback if Gemini unavailable)
  const vulnsEn = zapSection?.detailedAlerts || [];
  let aiAnalysisJa = null, vulnsJa = [];

  if (aiAnalysisEn || vulnsEn.length) {
    try {
      const ja = await translateToJapanese(aiAnalysisEn || {}, vulnsEn);
      aiAnalysisJa = ja.aiAnalysis;
      vulnsJa      = ja.vulnerabilities;
      if (aiAnalysisJa && !containsJapanese(JSON.stringify(aiAnalysisJa))) {
        console.warn('[PDF] JA translation did not produce Japanese text, using static fallback');
        aiAnalysisJa = buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn);
        vulnsJa = vulnsEn;
      }
    } catch (e) {
      console.warn('[PDF] AI section unavailable, generating PDF from scan findings:', e.message);
      aiAnalysisJa = buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn);
      vulnsJa = vulnsEn;
    }
  }

  const scanHistory = scanData?.scanHistory || null;
  const diagnosisEn = {
    title: scanHistory?.title?.en || 'Scan History',
    headers: (scanHistory?.headers && scanHistory.headers.en) ? scanHistory.headers.en : ['Date', 'Executed by', 'Status'],
    rows: (scanHistory?.rows && scanHistory.rows.en) ? scanHistory.rows.en : [[scanHistoryRows[0]?.dateEn || '', scanHistoryRows[0]?.executedByEn || '', scanHistoryRows[0]?.status || 'unknown']]
  };

  // Strict EN-only validation (all English pages content must be English)
  assertEnglishOnlyPdfContent({
    scanData,
    aiAnalysis: aiAnalysisEn,
    vulnerabilities: vulnsEn,
    diagnosisTable: diagnosisEn
  });

  // PDFKit path
  const tsBaseEn = await getReportTemplateStaticContent({ lang: 'en' });
  const tsBaseJa = await getReportTemplateStaticContent({ lang: 'ja' });
  const tsEn = buildTemplateStaticOverrides(tsBaseEn, { lang: 'en', scanData });
  const tsJa = buildTemplateStaticOverrides(tsBaseJa, { lang: 'ja', scanData });
  tsEn.diagnosisTitle   = diagnosisEn.title;
  tsEn.diagnosisHeaders = diagnosisEn.headers;
  tsEn.diagnosisRows    = diagnosisEn.rows;

  const diagnosisJa = {
    title: scanHistory?.title?.ja || '診断履歴',
    headers: (scanHistory?.headers && scanHistory.headers.ja) ? scanHistory.headers.ja : ['日付', '実行ユーザー', 'ステータス'],
    rows: (scanHistory?.rows && scanHistory.rows.ja) ? scanHistory.rows.ja : [[scanHistoryRows[0]?.dateJa || '', scanHistoryRows[0]?.executedByJa || '', getStatusLabel(scanHistoryRows[0]?.status, 'ja')]]
  };
  tsJa.diagnosisTitle   = diagnosisJa.title;
  tsJa.diagnosisHeaders = diagnosisJa.headers;
  tsJa.diagnosisRows    = diagnosisJa.rows;

  const doc = makePdfDoc({
    Title:   `Security Scan Report - ${scanResult.target}`,
    Author:  'SSDT Security Scanner',
    Subject: 'Comprehensive Security and Performance Analysis'
  });
  const buf = collectBuffer(doc);
  renderTemplateReport(doc, scanData, aiAnalysisEn, vulnsEn, 'en', tsEn);
  doc.addPage();
  renderTemplateReport(doc, scanData, aiAnalysisJa, vulnsJa, 'ja', tsJa);
  doc.end();
  console.log('[PDF] PDF generation completed successfully');
  return buf;
}

/**
 * Generate a single-language PDF (EN or JA).
 */
async function generateSingleLanguagePdf(scanResult, lang = 'en') {
  console.log(`📄 Starting ${lang.toUpperCase()} PDF generation…`);
  const isJa = lang === 'ja';

  const scanHistoryRows = await fetchScanHistoryRows(scanResult);

  let scanData;
  try   { scanData = await formatScanDataForPdf(scanResult, { scanHistoryRows }); }
  catch (e) {
    console.warn('[PDF] Gemini scan data formatting failed, using fallback:', e.message);
    scanData = buildFallbackScanDataForPdf(scanResult);
  }

  await ensureGeminiScanHistory(scanData, scanHistoryRows);

  const zapSection = scanData.sections?.find(s => s.id === 'zap');
  await fetchFullAlertsFromGridFS(scanResult, zapSection);

  await new Promise(r => setTimeout(r, RATE_LIMIT_DELAY));

  let aiAnalysis = null;
  if (scanResult.refinedReport) {
    try {
      aiAnalysis = await formatAiAnalysisForPdf(scanResult.refinedReport);
      console.log('[PDF] Using Gemini-generated report');
    } catch (e) {
      console.warn('[PDF] AI section unavailable, generating PDF from scan findings:', e.message);
      // aiAnalysis stays null — PDF renders without AI narrative section
    }
  }

  const vulnsEn = zapSection?.detailedAlerts || [];
  let aiToUse = aiAnalysis, vulnsToUse = vulnsEn;

  if (isJa && (aiAnalysis || vulnsEn.length)) {
    await new Promise(r => setTimeout(r, RATE_LIMIT_DELAY));
    try {
      const ja = await translateToJapanese(aiAnalysis || {}, vulnsEn);
      aiToUse    = ja.aiAnalysis;
      vulnsToUse = ja.vulnerabilities;
      if (aiToUse && !containsJapanese(JSON.stringify(aiToUse))) {
        console.warn('[PDF] JA translation did not produce Japanese text, using static fallback');
        aiToUse    = buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn);
        vulnsToUse = vulnsEn;
      }
    } catch (e) {
      console.warn('[PDF] AI section unavailable, generating PDF from scan findings:', e.message);
      aiToUse    = buildJapaneseAiAnalysisFromScanData(scanData, vulnsEn);
      vulnsToUse = vulnsEn;
    }
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
  const buf = collectBuffer(doc);
  renderTemplateReport(doc, scanData, aiToUse, vulnsToUse, lang, ts);
  doc.end();
  console.log('[PDF] PDF generation completed successfully');
  return buf;
}

/**
 * Generate a ZAP-only vulnerability PDF.
 */
async function generateZapPdf(scanResult, lang = 'en') {
  console.log(`📄 Starting ZAP ${lang.toUpperCase()} PDF generation…`);
  const isJa = lang === 'ja';
  let vulnerabilities = [];

  if (scanResult.zapResult?.reportFiles?.length) {
    const file = scanResult.zapResult.reportFiles.find(f => f.filename?.includes('detailed_alerts'));
    if (file?.fileId) {
      try {
        const bucket = file.filename?.includes('zap_auth') ? 'zap_auth_reports' : 'zap_reports';
        const buf    = await gridfsService.downloadFile(file.fileId, bucket);
        const full   = JSON.parse(buf.toString('utf-8'));
        vulnerabilities = full.map(a => ({
          name: a.alert, risk: a.risk, confidence: a.confidence,
          description: a.description || 'No description available',
          solution:    a.solution    || 'No solution provided',
          reference:   a.reference   || '',
          cweid: a.cweid, wascid: a.wascid,
          totalOccurrences: a.totalOccurrences || a.occurrences?.length || 0,
          urls: a.occurrences?.map(o => o.url) || []
        }));
      } catch (e) { console.warn(`⚠️ GridFS fetch failed: ${e.message}`); }
    }
  }

  if (!vulnerabilities.length && scanResult.zapResult?.summaryAlerts) {
    vulnerabilities = scanResult.zapResult.summaryAlerts.map(a => ({
      name: a.alert, risk: a.risk, confidence: a.confidence,
      description: a.description || 'No description available',
      solution:    a.solution    || 'No solution provided',
      reference: a.reference || '', cweid: a.cweid, wascid: a.wascid,
      totalOccurrences: a.totalOccurrences || 0, urls: []
    }));
  }

  let vulnsToUse = vulnerabilities;
  if (isJa && vulnerabilities.length) {
    await new Promise(r => setTimeout(r, RATE_LIMIT_DELAY));
    try {
      const ja   = await translateToJapanese({}, vulnerabilities);
      vulnsToUse = ja.vulnerabilities.map((v, i) => ({ ...v, urls: vulnerabilities[i]?.urls || [] }));
    } catch (e) {
      console.warn('[PDF] AI section unavailable, generating PDF from scan findings:', e.message);
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

module.exports = { generatePdfReport, generateSingleLanguagePdf, generateZapPdf };