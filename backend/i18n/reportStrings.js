'use strict';

/**
 * Every static label the PDF reports draw, in both languages. pdfService reads
 * labels only through t(); there are no inline `lang === 'ja' ? … : …` strings.
 * A test checks that every key has both languages and that each value passes the
 * language audit for its language.
 */

const STRINGS = {
  reportTitle:          { en: 'Security Scan Report', ja: 'セキュリティスキャンレポート' },
  zapReportTitle:       { en: 'Vulnerability Report', ja: '脆弱性レポート' },
  scanUrl:              { en: 'Scan URL', ja: 'スキャンURL' },
  generated:            { en: 'Generated', ja: '生成日' },
  scanId:               { en: 'Scan ID', ja: 'スキャンID' },
  executiveSummary:     { en: 'Executive Summary', ja: 'エグゼクティブサマリー' },
  overallRisk:          { en: 'Overall Risk Level', ja: '全体的なリスクレベル' },
  aiSectionTitle:       { en: 'AI-Generated Security Analysis', ja: 'AIによるセキュリティ分析' },
  aiUnavailable: {
    en: 'AI analysis could not be generated due to model quota limitations. All scan findings and security results are included below.',
    ja: 'AIによる分析はモデルのクォータ制限により生成できませんでした。すべてのスキャン結果と検出内容は以下に記載されています。'
  },
  scanResults:          { en: 'Scan Results', ja: 'スキャン結果' },
  scanResultsDetails:   { en: 'Scan Results Details', ja: 'スキャン結果の詳細' },
  vulnDetailsTitle:     { en: 'Vulnerability Details & Remediation', ja: '脆弱性の詳細と修正方法' },
  noVulnerabilities:    { en: 'No vulnerabilities detected', ja: '脆弱性は検出されませんでした' },
  risk:                 { en: 'Risk', ja: 'リスク' },
  confidence:           { en: 'Confidence', ja: '信頼度' },
  description:          { en: 'Description:', ja: '説明:' },
  solution:             { en: 'Recommended Solution:', ja: '推奨される修正方法:' },
  affectedUrls:         { en: 'Affected URLs (Sample):', ja: '影響を受けるURL (一部):' },
  evidence:             { en: 'Request / Response Evidence:', ja: 'リクエスト / レスポンスの証跡:' },
  request:              { en: 'Request:', ja: 'リクエスト:' },
  response:             { en: 'Response:', ja: 'レスポンス:' },
  param:                { en: 'param', ja: 'パラメータ' },
  moreEvidence: {
    en: '{n} more request/response pair(s) available in the JSON export',
    ja: '他 {n} 件のリクエスト/レスポンスはJSONエクスポートに含まれます'
  },
  references:           { en: 'References', ja: '参考情報' },
  bodyTruncated: {
    en: '…(body truncated — full body available in the JSON export)',
    ja: '…(本文は省略されました — 全文はJSONエクスポートを参照してください)'
  },
  binaryBody: {
    en: '…(binary body not shown — full body available in the JSON export)',
    ja: '…(バイナリデータのため本文は表示されません — 全文はJSONエクスポートを参照してください)'
  },
  // A finding whose rule ships no description / remediation text (e.g. User Agent Fuzzer).
  descriptionUnavailable: {
    en: 'The scanner provides no description for this finding.',
    ja: 'この検出項目には、スキャナーによる説明が提供されていません。'
  },
  solutionUnavailable: {
    en: 'No specific remediation is provided for this finding. Review the affected URLs and the request/response evidence to decide whether action is needed.',
    ja: 'この検出項目には、具体的な修正方法が提供されていません。影響を受けるURLとリクエスト/レスポンスの証跡を確認し、対応の要否を判断してください。'
  },
  unknown:              { en: 'Unknown', ja: '不明' },
  scanHistory:          { en: 'Scan History', ja: '診断履歴' },
  historyDate:          { en: 'Date', ja: '日付' },
  historyExecutedBy:    { en: 'Executed by', ja: '実行ユーザー' },
  historyStatus:        { en: 'Status', ja: 'ステータス' },
};

const RISK = {
  high:          { en: 'High', ja: '高' },
  medium:        { en: 'Medium', ja: '中' },
  low:           { en: 'Low', ja: '低' },
  informational: { en: 'Informational', ja: '情報' },
};

// ZAP confidence levels.
const CONFIDENCE = {
  high:            { en: 'High', ja: '高' },
  medium:          { en: 'Medium', ja: '中' },
  low:             { en: 'Low', ja: '低' },
  confirmed:       { en: 'Confirmed', ja: '確認済み' },
  'user confirmed': { en: 'User Confirmed', ja: 'ユーザー確認済み' },
  'false positive': { en: 'False Positive', ja: '誤検知' },
};

const STATUS = {
  completed: { en: 'Completed', ja: '診断終了' },
  scanning:  { en: 'Scanning', ja: 'スキャン中' },
  failed:    { en: 'Failed', ja: '失敗' },
  cancelled: { en: 'Cancelled', ja: '停止' },
};

const pick = (entry, lang) => (lang === 'ja' ? entry.ja : entry.en);

/**
 * A label in the report language. `{name}` placeholders are filled from `vars`.
 * An unknown key is a programming error and throws, so a typo can never put a raw
 * key into a customer's report.
 */
function t(lang, key, vars = {}) {
  const entry = STRINGS[key];
  if (!entry) throw new Error(`reportStrings: unknown key ${key}`);
  return pick(entry, lang).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

function riskLabel(risk, lang) {
  const r = String(risk || '').toLowerCase();
  const key = r.includes('high') ? 'high' : r.includes('medium') ? 'medium'
    : r.includes('low') ? 'low' : r.includes('informational') || r.includes('info') ? 'informational' : null;
  return key ? pick(RISK[key], lang) : t(lang, 'unknown');
}

function confidenceLabel(confidence, lang) {
  const entry = CONFIDENCE[String(confidence || '').toLowerCase().trim()];
  return entry ? pick(entry, lang) : t(lang, 'unknown');
}

function statusLabel(status, lang) {
  const s = status || '';
  const key = s === 'completed' ? 'completed'
    : (s === 'combining' || s === 'pending' || s === 'queued') ? 'scanning'
    : s === 'failed' ? 'failed'
    : (s === 'stopped' || s === 'cancelled') ? 'cancelled' : null;
  return key ? pick(STATUS[key], lang) : t(lang, 'unknown');
}

/** Every catalog value, for the catalog test and the report language gate. */
function allCatalogEntries() {
  const out = [];
  for (const [k, v] of Object.entries(STRINGS)) out.push({ key: k, ...v });
  for (const [group, map] of Object.entries({ RISK, CONFIDENCE, STATUS })) {
    for (const [k, v] of Object.entries(map)) out.push({ key: `${group}.${k}`, ...v });
  }
  return out;
}

module.exports = { t, riskLabel, confidenceLabel, statusLabel, allCatalogEntries, STRINGS };
