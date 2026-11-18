'use strict';

/**
 * Text that may stay in its original (Latin-script) form inside Japanese report
 * prose: identifiers, names and notation that Japanese security writing keeps
 * as is. Used by languageAudit.js — anything Latin that is NOT covered here (or
 * by the notation rules in languageAudit) counts as untranslated English.
 *
 * Keep this list reviewed and deliberate. Adding an ordinary English word here
 * ("allow", "list", "input"…) would let untranslated prose pass the audit.
 * Changing this file changes ENGINE_VERSION, which invalidates stored translations.
 */

// Multi-word names, matched (case-insensitively, on word boundaries) before the
// text is split into words, so their parts are never read as an English phrase —
// "Ruby on Rails" must not trip the function-word rule on "on".
const PHRASES = [
  'Ruby on Rails', 'Internet Explorer', "Let's Encrypt", 'Spring Boot', 'Spring Framework',
  'Google Chrome', 'Mozilla Firefox', 'Microsoft Edge', 'Microsoft IIS', 'Apache Tomcat',
  'Apache Struts', 'Apache HTTP Server', 'Node.js', 'ASP.NET', 'Java SecurityManager',
  'Visual Studio', 'Amazon Web Services', 'Google Cloud', 'Microsoft Azure', 'Cloud Run',
  'Active Directory', 'OWASP Top 10', 'Web Security Testing Guide', 'Unicode',
  'Same-Origin Policy', 'Content Security Policy', 'Subresource Integrity',
  'Strict Transport Security', 'Log4Shell', 'Spring4Shell', 'Shellshock',
  'Billion Laughs', 'Single Sign-On', 'Windows Server', 'Mac OS',
  // Found by the scanner-text sweep (scripts/zapCatalogSweep.js, 2026-11-17).
  'Secure Sockets Layer', 'Transport Layer Security', 'Safe C String Library',
];

// Single words allowed as is (case-insensitive). Product, technology, protocol and
// format names, plus a few English loan terms that Japanese security writing
// conventionally keeps in Latin script.
const TERMS = [
  // products / platforms / languages
  'Apache', 'nginx', 'IIS', 'Tomcat', 'Jetty', 'Express', 'PHP', 'Java', 'JavaScript', 'TypeScript',
  'Python', 'Ruby', 'Perl', 'Golang', 'Rust', 'Kotlin', 'Swift', 'Scala', 'WordPress', 'Drupal', 'Joomla',
  'jQuery', 'React', 'Angular', 'Vue', 'Bootstrap', 'Laravel', 'Django', 'Flask', 'Rails', 'Spring',
  'Struts', 'Log4j', 'OpenSSL', 'OpenSSH', 'Windows', 'Linux', 'Unix', 'macOS', 'Android', 'iOS',
  'Chrome', 'Chromium', 'Firefox', 'Safari', 'Edge', 'Opera', 'Mozilla', 'Microsoft', 'Google', 'Oracle',
  'MySQL', 'MariaDB', 'PostgreSQL', 'SQLite', 'MsSQL', 'MongoDB', 'Redis', 'Hypersonic', 'Elasticsearch',
  'AppArmor', 'SELinux', 'chroot', 'Docker', 'Kubernetes', 'Cloudflare', 'Akamai', 'ViewState',
  'ELMAH', 'Heartbleed', 'Spectre', 'Httpoxy', 'Shellshock', 'Polyfill', 'polyfill', 'WebSocket', 'WebSockets',
  'Base64', 'XPath', 'XQuery', 'GraphQL', 'OAuth', 'OpenID', 'SAML', 'Kerberos', 'NTLM', 'LDAP',
  'Lighthouse', 'Gecko', 'WebKit', 'Blink', 'Trident', 'Netscape', 'Git', 'Subversion', 'Actuator',
  'Crypt', 'bcrypt', 'scrypt',
  // loan terms kept in Latin script in Japanese security writing
  'Cookie', 'Cookies', 'cookie', 'cookies', 'Web', 'Referer', 'Referrer', 'Origin', 'Host', 'Content-Type',
  'nosniff', 'HttpOnly', 'Secure', 'SameSite', 'Lax', 'Strict', 'None', 'max-age',
  'includeSubDomains', 'preload', 'no-cache', 'no-store', 'must-revalidate', 'private', 'public',
  'immutable', 'unsafe-inline', 'unsafe-eval', 'self', 'none', 'DENY', 'SAMEORIGIN', 'ALLOW-FROM',
  // CSP source keywords (the scanner's CSP rule titles are e.g. "script-src unsafe-hashes")
  'unsafe-hashes', 'strict-dynamic', 'wasm-unsafe-eval', 'unsafe-allow-redirects', 'report-sample',
  'Viewstate', // the scanner's spelling of ASP.NET ViewState in alert titles
  'default-src', 'script-src', 'style-src', 'img-src', 'frame-ancestors', 'object-src', 'base-uri',
  'form-action', 'report-uri', 'report-to', 'charset', 'jail', 'realpath', 'Content-Security-Policy',
  'localhost', 'REDACTED', 'Basic', 'Bearer', 'Digest',
];

// HTTP header names (case-insensitive), in addition to any X-… header.
const HEADER_NAMES = [
  'Accept', 'Accept-Encoding', 'Accept-Language', 'Access-Control-Allow-Credentials',
  'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin',
  'Access-Control-Expose-Headers', 'Access-Control-Max-Age', 'Age', 'Allow', 'Authorization',
  'Cache-Control', 'Clear-Site-Data', 'Connection', 'Content-Disposition', 'Content-Encoding',
  'Content-Language', 'Content-Length', 'Content-Location', 'Content-Security-Policy',
  'Content-Security-Policy-Report-Only', 'Content-Type', 'Cookie', 'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy', 'Date', 'ETag', 'Expect-CT',
  'Expires', 'Feature-Policy', 'Forwarded', 'Host', 'If-Modified-Since', 'If-None-Match',
  'Last-Modified', 'Link', 'Location', 'Origin', 'Permissions-Policy', 'Pragma',
  'Proxy', 'Proxy-Authorization', 'Public-Key-Pins', 'Referer', 'Referrer-Policy', 'Retry-After', 'Server',
  'Set-Cookie', 'Strict-Transport-Security', 'Timing-Allow-Origin', 'Transfer-Encoding', 'Upgrade',
  'User-Agent', 'Vary', 'Via', 'WWW-Authenticate',
];

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];

module.exports = {
  PHRASES,
  TERMS,
  HEADER_NAMES,
  HTTP_METHODS,
};
