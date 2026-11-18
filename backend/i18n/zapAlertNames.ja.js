'use strict';

/**
 * Reviewed Japanese titles for the scanner's common rules, keyed by the rule's
 * English alert name. A finding whose title is listed here never sends its title
 * for machine translation; any other title goes through the localization engine.
 *
 * Keyed by name (normalized: case and whitespace) because several rules share one
 * plugin id with different names (e.g. the CSP and SQL-injection variants). The
 * pluginId map below is used only when the name is not listed and the id has a
 * single name.
 *
 * Every value must pass the JA language audit as a short field
 * (tests/reportLocalization.test.js checks this).
 */

const BY_NAME = {
  // ── Headers and transport ────────────────────────────────────────────────
  'Content Security Policy (CSP) Header Not Set': 'コンテンツセキュリティポリシー（CSP）ヘッダーが設定されていない',
  'CSP: Wildcard Directive': 'CSP: ワイルドカードを使用したディレクティブ',
  'CSP: script-src unsafe-inline': 'CSP: script-src での unsafe-inline の許可',
  'CSP: style-src unsafe-inline': 'CSP: style-src での unsafe-inline の許可',
  'CSP: script-src unsafe-eval': 'CSP: script-src での unsafe-eval の許可',
  'CSP: Failure to Define Directive with No Fallback': 'CSP: フォールバックのないディレクティブが未定義',
  'CSP: Notices': 'CSP: 注意事項',
  'CSP: Meta Policy Invalid Directive': 'CSP: <meta> 要素のポリシーに無効なディレクティブ',
  'CSP: Header & Meta': 'CSP: ヘッダーと <meta> 要素の両方で指定',
  'Missing Anti-clickjacking Header': 'クリックジャッキング対策ヘッダーの欠落',
  'X-Content-Type-Options Header Missing': 'X-Content-Type-Options ヘッダーの欠落',
  'Strict-Transport-Security Header Not Set': 'Strict-Transport-Security ヘッダーが設定されていない',
  'Strict-Transport-Security Disabled': 'Strict-Transport-Security の無効化',
  'Strict-Transport-Security Missing Max-Age': 'Strict-Transport-Security に max-age が指定されていない',
  'Strict-Transport-Security Defined via META (Non-compliant with Spec)': 'Strict-Transport-Security が <meta> 要素で定義されている（仕様に非準拠）',
  'Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)': 'Strict-Transport-Security ヘッダーの重複（仕様に非準拠）',
  'Permissions Policy Header Not Set': 'Permissions-Policy ヘッダーが設定されていない',
  'Content-Type Header Missing': 'Content-Type ヘッダーの欠落',
  'Re-examine Cache-control Directives': 'Cache-Control ディレクティブの再確認',
  'Insufficient Site Isolation Against Spectre Vulnerability': 'Spectre 脆弱性に対するサイト分離の不備',
  'Server Leaks Version Information via "Server" HTTP Response Header Field': 'Server レスポンスヘッダーによるバージョン情報の漏えい',
  'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)': 'X-Powered-By レスポンスヘッダーによる情報の漏えい',
  'X-AspNet-Version Response Header': 'X-AspNet-Version レスポンスヘッダーによる情報の漏えい',
  'X-Debug-Token Information Leak': 'X-Debug-Token による情報漏えい',
  'X-ChromeLogger-Data (XCOLD) Header Information Leak': 'X-ChromeLogger-Data（XCOLD）ヘッダーによる情報漏えい',
  'X-Backend-Server Header Information Leak': 'X-Backend-Server ヘッダーによる情報漏えい',
  'Cross-Domain Misconfiguration': 'クロスドメイン設定の不備',
  'HTTP Only Site': 'HTTP のみで提供されているサイト',
  'HTTPS Content Available via HTTP': 'HTTPS のコンテンツが HTTP でも取得可能',
  'Secure Pages Include Mixed Content': 'HTTPS ページに混在コンテンツが含まれている',
  'Secure Pages Include Mixed Content (Including Scripts)': 'HTTPS ページに混在コンテンツ（スクリプトを含む）が含まれている',
  'HTTP to HTTPS Insecure Transition in Form Post': 'フォーム送信における HTTP から HTTPS への安全でない遷移',
  'HTTPS to HTTP Insecure Transition in Form Post': 'フォーム送信における HTTPS から HTTP への安全でない遷移',
  'Insecure HTTP Method': '安全でない HTTP メソッドの許可',
  'Httpoxy - Proxy Header Misuse': 'Httpoxy - Proxy ヘッダーの悪用',

  // ── Cookies and sessions ─────────────────────────────────────────────────
  'Cookie No HttpOnly Flag': 'HttpOnly 属性が設定されていない Cookie',
  'Cookie Without Secure Flag': 'Secure 属性が設定されていない Cookie',
  'Cookie without SameSite Attribute': 'SameSite 属性が設定されていない Cookie',
  'Cookie with SameSite Attribute None': 'SameSite 属性が None に設定された Cookie',
  'Cookie with Invalid SameSite Attribute': 'SameSite 属性の値が不正な Cookie',
  'Loosely Scoped Cookie': '適用範囲が広すぎる Cookie',
  'Cookie Poisoning': 'Cookie ポイズニング',
  'Session ID in URL Rewrite': 'URL 内のセッション ID',
  'Session Fixation': 'セッション固定',
  'Session Management Response Identified': 'セッション管理を行うレスポンスの検出',
  'Authentication Request Identified': '認証リクエストの検出',
  'Verification Request Identified': '検証リクエストの検出',
  'Authentication Credentials Captured': '認証情報の取得',
  'Absence of Anti-CSRF Tokens': 'CSRF 対策トークンの欠如',
  'Anti-CSRF Tokens Check': 'CSRF 対策トークンの確認',

  // ── Information disclosure ───────────────────────────────────────────────
  'Information Disclosure - Debug Error Messages': '情報漏えい - デバッグ用エラーメッセージ',
  'Information Disclosure - Sensitive Information in URL': '情報漏えい - URL に含まれる機密情報',
  'Information Disclosure - Sensitive Information in HTTP Referrer Header': '情報漏えい - Referer ヘッダーに含まれる機密情報',
  'Information Disclosure - Suspicious Comments': '情報漏えい - 疑わしいコメント',
  'Application Error Disclosure': 'アプリケーションエラー情報の開示',
  'Private IP Disclosure': 'プライベート IP アドレスの開示',
  'PII Disclosure': '個人情報（PII）の開示',
  'Timestamp Disclosure - Unix': 'タイムスタンプの開示 - Unix',
  'Hash Disclosure - MD5 Crypt': 'ハッシュ値の開示 - MD5 Crypt',
  'Username Hash Found': 'ユーザー名のハッシュ値の検出',
  'Base64 Disclosure': 'Base64 エンコードされたデータの開示',
  'In Page Banner Information Leak': 'ページ内のバナーによる情報漏えい',
  'Big Redirect Detected (Potential Sensitive Information Leak)': 'サイズの大きいリダイレクトの検出（機密情報漏えいの可能性）',
  'Source Code Disclosure - /WEB-INF Folder': 'ソースコードの開示 - /WEB-INF フォルダー',
  'Source Code Disclosure - Git': 'ソースコードの開示 - Git',
  'Source Code Disclosure - SVN': 'ソースコードの開示 - SVN',
  'Source Code Disclosure - CVE-2012-1823': 'ソースコードの開示 - CVE-2012-1823',
  'Backup File Disclosure': 'バックアップファイルの開示',
  'Hidden File Found': '隠しファイルの検出',
  '.htaccess Information Leak': '.htaccess による情報漏えい',
  '.env Information Leak': '.env ファイルによる情報漏えい',
  'ELMAH Information Leak': 'ELMAH による情報漏えい',
  'Trace.axd Information Leak': 'Trace.axd による情報漏えい',
  'Spring Actuator Information Leak': 'Spring Actuator による情報漏えい',
  'Directory Browsing': 'ディレクトリリスティング',
  'Cloud Metadata Potentially Exposed': 'クラウドメタデータが露出している可能性',
  'WSDL File Detection': 'WSDL ファイルの検出',

  // ── Caching ──────────────────────────────────────────────────────────────
  'Storable and Cacheable Content': '保存・キャッシュ可能なコンテンツ',
  'Storable but Non-Cacheable Content': '保存可能だがキャッシュ不可のコンテンツ',
  'Non-Storable Content': '保存不可のコンテンツ',
  'Retrieved from Cache': 'キャッシュから取得されたレスポンス',

  // ── Client side ──────────────────────────────────────────────────────────
  'Cross-Domain JavaScript Source File Inclusion': '外部ドメインの JavaScript ファイルの読み込み',
  'Vulnerable JS Library': '脆弱性のある JavaScript ライブラリ',
  'Dangerous JS Functions': '危険な JavaScript 関数の使用',
  'Reverse Tabnabbing': 'リバースタブナビング',
  'Modern Web Application': 'モダン Web アプリケーション',
  'User Controllable HTML Element Attribute (Potential XSS)': 'ユーザーが制御可能な HTML 要素の属性（XSS の可能性）',
  'User Controllable JavaScript Event (XSS)': 'ユーザーが制御可能な JavaScript イベント（XSS）',
  'User Controllable Charset': 'ユーザーが制御可能な文字コード指定',
  'Charset Mismatch': '文字コードの不一致',
  'Charset Mismatch (Header Versus Meta Content-Type Charset)': '文字コードの不一致（ヘッダーと <meta> 要素の Content-Type）',
  'Sub Resource Integrity Attribute Missing': 'サブリソース完全性（SRI）属性の欠落',
  'Script Served From Malicious Domain (polyfill)': '悪意のあるドメインから配信されたスクリプト（polyfill）',

  // ── Injection and active checks ──────────────────────────────────────────
  'Path Traversal': 'パストラバーサル',
  'Remote File Inclusion': 'リモートファイルインクルージョン',
  'Cross Site Scripting (Reflected)': 'クロスサイトスクリプティング（反射型）',
  'Cross Site Scripting (Persistent)': 'クロスサイトスクリプティング（格納型）',
  'Cross Site Scripting (Persistent) - Prime': 'クロスサイトスクリプティング（格納型）- 事前送信',
  'Cross Site Scripting (Persistent) - Spider': 'クロスサイトスクリプティング（格納型）- 巡回',
  'Cross Site Scripting (DOM Based)': 'クロスサイトスクリプティング（DOM ベース）',
  'SQL Injection': 'SQL インジェクション',
  'SQL Injection - MySQL': 'SQL インジェクション - MySQL',
  'SQL Injection - Hypersonic SQL': 'SQL インジェクション - Hypersonic SQL',
  'SQL Injection - Oracle': 'SQL インジェクション - Oracle',
  'SQL Injection - PostgreSQL': 'SQL インジェクション - PostgreSQL',
  'SQL Injection - SQLite': 'SQL インジェクション - SQLite',
  'SQL Injection - MsSQL': 'SQL インジェクション - MsSQL',
  'SQL Injection - Authentication Bypass': 'SQL インジェクション - 認証回避',
  'Remote OS Command Injection': 'リモート OS コマンドインジェクション',
  'Server Side Code Injection': 'サーバーサイドコードインジェクション',
  'Server Side Code Injection - PHP Code Injection': 'サーバーサイドコードインジェクション - PHP コードインジェクション',
  'Server Side Code Injection - ASP Code Injection': 'サーバーサイドコードインジェクション - ASP コードインジェクション',
  'Server Side Include': 'サーバーサイドインクルード',
  'Server Side Template Injection': 'サーバーサイドテンプレートインジェクション',
  'Server Side Template Injection (Blind)': 'サーバーサイドテンプレートインジェクション（ブラインド）',
  'Server Side Request Forgery': 'サーバーサイドリクエストフォージェリ（SSRF）',
  'XPath Injection': 'XPath インジェクション',
  'XSLT Injection': 'XSLT インジェクション',
  'XML External Entity Attack': 'XML 外部実体参照（XXE）攻撃',
  'SOAP XML Injection': 'SOAP XML インジェクション',
  'SOAP Action Spoofing': 'SOAP アクションのなりすまし',
  'Expression Language Injection': '式言語（EL）インジェクション',
  'CRLF Injection': 'CRLF インジェクション',
  'Parameter Tampering': 'パラメーター改ざん',
  'HTTP Parameter Override': 'HTTP パラメーターの上書き',
  'Format String Error': '書式文字列エラー',
  'Buffer Overflow': 'バッファオーバーフロー',
  'Integer Overflow Error': '整数オーバーフローエラー',
  'Generic Padding Oracle': 'パディングオラクル',
  'Open Redirect': 'オープンリダイレクト',
  'External Redirect': '外部サイトへのリダイレクト',
  'GET for POST': 'POST の代わりに GET でも受け付けるリクエスト',
  'User Agent Fuzzer': 'User-Agent を変更した際の応答の差異',
  'Log4Shell': 'Log4Shell（CVE-2021-44228）',
  'Spring4Shell': 'Spring4Shell（CVE-2022-22965）',
  'Remote Code Execution - Shell Shock': 'リモートコード実行 - Shellshock',
  'Remote Code Execution - CVE-2012-1823': 'リモートコード実行 - CVE-2012-1823',
  'Heartbleed OpenSSL Vulnerability': 'OpenSSL の Heartbleed 脆弱性',
  'Exponential Entity Expansion (Billion Laughs Attack)': '指数関数的なエンティティ展開（Billion Laughs 攻撃）',
  'Proxy Disclosure': 'プロキシ情報の開示',
};

// Rules with exactly one alert name. Used only when the name is not in BY_NAME
// (for example a scan stored by a scanner version that renamed the rule).
const BY_PLUGIN_ID = {
  '0': 'Directory Browsing', '6': 'Path Traversal', '7': 'Remote File Inclusion',
  '10010': 'Cookie No HttpOnly Flag', '10011': 'Cookie Without Secure Flag',
  '10015': 'Re-examine Cache-control Directives', '10017': 'Cross-Domain JavaScript Source File Inclusion',
  '10019': 'Content-Type Header Missing', '10020': 'Missing Anti-clickjacking Header',
  '10021': 'X-Content-Type-Options Header Missing', '10023': 'Information Disclosure - Debug Error Messages',
  '10024': 'Information Disclosure - Sensitive Information in URL',
  '10025': 'Information Disclosure - Sensitive Information in HTTP Referrer Header',
  '10027': 'Information Disclosure - Suspicious Comments', '10028': 'Open Redirect',
  '10029': 'Cookie Poisoning', '10030': 'User Controllable Charset',
  '10031': 'User Controllable HTML Element Attribute (Potential XSS)',
  '10036': 'Server Leaks Version Information via "Server" HTTP Response Header Field',
  '10037': 'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)',
  '10038': 'Content Security Policy (CSP) Header Not Set', '10043': 'User Controllable JavaScript Event (XSS)',
  '10044': 'Big Redirect Detected (Potential Sensitive Information Leak)', '10050': 'Retrieved from Cache',
  '10054': 'Cookie without SameSite Attribute', '10058': 'GET for POST', '10061': 'X-AspNet-Version Response Header',
  '10062': 'PII Disclosure', '10063': 'Permissions Policy Header Not Set', '10096': 'Timestamp Disclosure - Unix',
  '10098': 'Cross-Domain Misconfiguration', '10104': 'User Agent Fuzzer', '10105': 'Authentication Credentials Captured',
  '10106': 'HTTP Only Site', '10108': 'Reverse Tabnabbing', '10109': 'Modern Web Application',
  '10110': 'Dangerous JS Functions', '10111': 'Authentication Request Identified',
  '10112': 'Session Management Response Identified', '10113': 'Verification Request Identified',
  '10202': 'Absence of Anti-CSRF Tokens', '2': 'Private IP Disclosure', '3': 'Session ID in URL Rewrite',
  '40003': 'CRLF Injection', '40008': 'Parameter Tampering', '40009': 'Server Side Include',
  '40012': 'Cross Site Scripting (Reflected)', '40014': 'Cross Site Scripting (Persistent)',
  '40026': 'Cross Site Scripting (DOM Based)', '40046': 'Server Side Request Forgery',
  '90020': 'Remote OS Command Injection', '90021': 'XPath Injection', '90022': 'Application Error Disclosure',
  '90023': 'XML External Entity Attack', '90028': 'Insecure HTTP Method', '90033': 'Loosely Scoped Cookie',
  '90034': 'Cloud Metadata Potentially Exposed', '90035': 'Server Side Template Injection',
};

const normalize = (s) => String(s || '').replace(/\s+/g, ' ').trim().toLowerCase();
const NORMALIZED = new Map(Object.entries(BY_NAME).map(([en, ja]) => [normalize(en), ja]));

/** The reviewed Japanese title for a finding, or null when there is none. */
function curatedJapaneseTitle(name, pluginId) {
  const byName = NORMALIZED.get(normalize(name));
  if (byName) return byName;
  const viaId = pluginId != null ? BY_PLUGIN_ID[String(pluginId)] : null;
  return viaId ? NORMALIZED.get(normalize(viaId)) || null : null;
}

module.exports = { curatedJapaneseTitle, BY_NAME, BY_PLUGIN_ID };
