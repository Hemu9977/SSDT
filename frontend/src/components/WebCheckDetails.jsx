import React, { useState } from 'react';
import '../styles/WebCheckDetails.scss';

const getObservatoryGradeColor = (grade) => {
  if (!grade) return '#888';
  const map = { 'A': '#00d084', 'B': '#7fba00', 'C': '#ffb900', 'D': '#ff8c00', 'F': '#e81123' };
  return map[grade[0]] || '#888';
};

const getStatusClass = (code) => {
  const num = parseInt(code, 10);
  if (num >= 200 && num < 300) return 'status-2xx';
  if (num >= 300 && num < 400) return 'status-3xx';
  if (num >= 400 && num < 500) return 'status-4xx';
  return 'status-5xx';
};

const SSL_OID_MAP = {
  '2.16.840.1.114412.2.1': 'DigiCert EV',
  '2.16.840.1.114412.1.3.0.2': 'DigiCert OV',
  '1.3.6.1.4.1.44947.1.1.1': "Let's Encrypt",
  '2.23.140.1.2.1': 'Domain Validated (DV)',
  '2.23.140.1.2.2': 'Organization Validated (OV)',
  '2.23.140.1.1': 'Extended Validation (EV)',
  '2.16.840.1.113733.1.7.23.6': 'VeriSign EV',
  '1.3.6.1.4.1.6449.1.2.1.5.1': 'Comodo EV',
};

const SECURITY_HEADER_DESCRIPTIONS = {
  'Content-Security-Policy': 'Controls which resources the browser loads',
  'X-Frame-Options': 'Prevents clickjacking via iframes',
  'X-Content-Type-Options': 'Prevents MIME type sniffing',
  'Strict-Transport-Security': 'Forces HTTPS connections',
  'X-XSS-Protection': 'Legacy XSS filter (deprecated)',
  'Referrer-Policy': 'Controls referrer information sent',
  'Permissions-Policy': 'Controls browser feature access',
  'X-Permitted-Cross-Domain-Policies': 'Controls Flash/PDF cross-domain',
  'Cross-Origin-Opener-Policy': 'Isolates browsing context',
  'Cross-Origin-Resource-Policy': 'Controls cross-origin reads',
  'Cross-Origin-Embedder-Policy': 'Controls cross-origin embedding',
};

const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A';
  try {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric'
    });
  } catch {
    return dateStr;
  }
};

// Sub-component for expandable/collapsible sections
const Expandable = ({ label, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details className="wc-expandable" open={open} onToggle={(e) => setOpen(e.target.open)}>
      <summary>{label}</summary>
      <div className="wc-expand-content">{children}</div>
    </details>
  );
};

const WebCheckDetails = ({ webCheckReport, theme }) => {
  if (!webCheckReport || Object.keys(webCheckReport).length === 0) return null;

  const bg = theme === 'light' ? 'rgba(255, 255, 255, 0.75)' : 'rgba(0, 0, 0, 0.65)';
  const cardStyle = { background: bg, padding: '1rem', borderRadius: '8px', fontFamily: 'inherit', fontSize: '0.9rem', lineHeight: '1.6', overflow: 'hidden', wordBreak: 'break-word' };
  const h5Style = { margin: '0 0 0.5rem 0', color: 'var(--accent)', fontSize: '1rem', fontWeight: 700 };
  const completedCount = Object.keys(webCheckReport).filter(k => !webCheckReport[k]?.error).length;

  return (
    <details style={{ marginBottom: '2rem', overflow: 'hidden' }}>
      <summary style={{ cursor: 'pointer', fontWeight: 'bold', fontSize: '1rem', padding: '1rem', background: bg, borderRadius: '8px', border: '1px solid #00d084' }}>
        View Site Health Analysis ({completedCount} components analyzed)
      </summary>
      <div style={{ marginTop: '1rem', display: 'grid', gap: '1rem', fontSize: '0.9rem', overflow: 'hidden' }}>

        {/* 1. SSL Certificate Details */}
        {webCheckReport.ssl && !webCheckReport.ssl.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>SSL Certificate Details</h5>
            <p><b>Subject:</b> {webCheckReport.ssl.subject?.CN || 'N/A'}</p>
            <p><b>Issuer:</b> {webCheckReport.ssl.issuer?.O || 'N/A'}{webCheckReport.ssl.issuer?.CN ? ` (${webCheckReport.ssl.issuer.CN})` : ''}</p>
            <p><b>Valid From:</b> {formatDate(webCheckReport.ssl.valid_from)}</p>
            <p><b>Valid To:</b> {formatDate(webCheckReport.ssl.valid_to)}</p>
            {webCheckReport.ssl.serialNumber && <p><b>Serial:</b> <span style={{ fontSize: '0.8rem', fontFamily: 'monospace' }}>{webCheckReport.ssl.serialNumber}</span></p>}
            {webCheckReport.ssl.fingerprint256 && <p style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}><b>SHA-256:</b> {webCheckReport.ssl.fingerprint256}</p>}
            {webCheckReport.ssl.subjectaltname && (
              <Expandable label={`Subject Alt Names (${webCheckReport.ssl.subjectaltname.split(',').length})`}>
                {webCheckReport.ssl.subjectaltname.split(',').map((san, i) => (
                  <p key={i} style={{ margin: '0.15rem 0', fontSize: '0.8rem' }}>{san.trim()}</p>
                ))}
              </Expandable>
            )}
            {(() => {
              const policies = webCheckReport.ssl.infoAccess || {};
              const oids = Object.keys(policies);
              const mapped = oids.map(oid => SSL_OID_MAP[oid]).filter(Boolean);
              if (mapped.length > 0) {
                return <p><b>Validation:</b> {mapped.join(', ')}</p>;
              }
              return null;
            })()}
          </div>
        )}

        {/* 2. DNS Records */}
        {webCheckReport.dns && !webCheckReport.dns.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>DNS Records</h5>
            {webCheckReport.dns.A && (
              <p><b>A:</b> {typeof webCheckReport.dns.A === 'object' ? (webCheckReport.dns.A.address || JSON.stringify(webCheckReport.dns.A)) : webCheckReport.dns.A}</p>
            )}
            {webCheckReport.dns.AAAA && (
              <p><b>AAAA:</b> {Array.isArray(webCheckReport.dns.AAAA) ? webCheckReport.dns.AAAA.map(r => r.address || r).join(', ') : (webCheckReport.dns.AAAA.address || JSON.stringify(webCheckReport.dns.AAAA))}</p>
            )}
            {webCheckReport.dns.CNAME && (
              <p><b>CNAME:</b> {Array.isArray(webCheckReport.dns.CNAME) ? webCheckReport.dns.CNAME.join(', ') : webCheckReport.dns.CNAME}</p>
            )}
            {webCheckReport.dns.MX && webCheckReport.dns.MX.length > 0 && (
              <div>
                <b>MX Records:</b> {webCheckReport.dns.MX.length} found
                {webCheckReport.dns.MX.map((mx, idx) => (
                  <p key={idx} style={{ fontSize: '0.85rem', marginLeft: '1rem' }}>
                    {mx.exchange || mx} {mx.priority !== undefined ? `(priority: ${mx.priority})` : ''}
                  </p>
                ))}
              </div>
            )}
            {webCheckReport.dns.NS && webCheckReport.dns.NS.length > 0 && (
              <p><b>NS:</b> {webCheckReport.dns.NS.join(', ')}</p>
            )}
            {webCheckReport.dns.TXT && (
              <p><b>TXT Records:</b> {webCheckReport.dns.TXT.length || 0} found</p>
            )}
          </div>
        )}

        {/* 3. Security Headers */}
        {webCheckReport['http-security'] && !webCheckReport['http-security'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Security Headers</h5>
            {Object.entries(webCheckReport['http-security']).map(([key, val]) => (
              <div key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <span style={{ color: val ? '#00d084' : '#e81123', fontWeight: 'bold', flexShrink: 0 }}>{val ? '✓' : '✗'}</span>
                <div>
                  <span style={{ fontWeight: 600 }}>{key}</span>
                  {SECURITY_HEADER_DESCRIPTIONS[key] && (
                    <span style={{ fontSize: '0.75rem', opacity: 0.6, marginLeft: '0.5rem' }}> — {SECURITY_HEADER_DESCRIPTIONS[key]}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* 4. Tech Stack */}
        {(() => {
          const techData = webCheckReport['tech-stack'];
          const techArray = techData?.technologies || (Array.isArray(techData) ? techData : null);
          if (techArray && techArray.length > 0) {
            return (
              <div style={cardStyle}>
                <h5 style={h5Style}>Technology Stack</h5>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {techArray.map((tech, idx) => (
                    <span key={idx} style={{ background: 'var(--accent)', color: 'white', padding: '0.25rem 0.5rem', borderRadius: '4px', fontSize: '0.8rem' }}>
                      {typeof tech === 'object' ? (tech.name || tech.technology || JSON.stringify(tech)) : tech}
                    </span>
                  ))}
                </div>
              </div>
            );
          }
          return null;
        })()}

        {/* 5. Open Ports */}
        {webCheckReport.ports && !webCheckReport.ports.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Open Ports</h5>
            {webCheckReport.ports.openPorts && (
              <p><b>Open:</b> {webCheckReport.ports.openPorts.length > 0
                ? webCheckReport.ports.openPorts.map(p => (
                    <span key={p} style={{ background: 'rgba(0, 208, 132, 0.15)', color: '#00d084', padding: '0.1rem 0.4rem', borderRadius: '3px', fontSize: '0.8rem', marginRight: '0.35rem', display: 'inline-block', marginBottom: '0.2rem' }}>{p}</span>
                  ))
                : 'No common ports detected as open'}
              </p>
            )}
            {webCheckReport.ports.closedPorts && webCheckReport.ports.closedPorts.length > 0 && (
              <Expandable label={`Closed/Filtered ports (${webCheckReport.ports.closedPorts.length})`}>
                <p style={{ wordBreak: 'break-all' }}>{webCheckReport.ports.closedPorts.join(', ')}</p>
              </Expandable>
            )}
          </div>
        )}

        {/* 6. Cookies */}
        {webCheckReport.cookies && !webCheckReport.cookies.error && !webCheckReport.cookies.skipped && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Cookies</h5>
            <p><b>Header Cookies:</b> {webCheckReport.cookies.headerCookies?.length || 0} &nbsp; <b>Client Cookies:</b> {webCheckReport.cookies.clientCookies?.length || 0}</p>
            {webCheckReport.cookies.headerCookies && webCheckReport.cookies.headerCookies.length > 0 && (
              <Expandable label={`View header cookies (${webCheckReport.cookies.headerCookies.length})`}>
                {webCheckReport.cookies.headerCookies.map((cookie, idx) => (
                  <div key={idx} className="wc-cookie-row">
                    <div className="wc-cookie-name">{cookie.name || `Cookie ${idx + 1}`}</div>
                    {cookie.domain && <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>{cookie.domain}</span>}
                    <div className="wc-cookie-flags">
                      {cookie.httpOnly && <span>HttpOnly</span>}
                      {cookie.secure && <span>Secure</span>}
                      {cookie.sameSite && <span>SameSite={cookie.sameSite}</span>}
                      {!cookie.httpOnly && <span className="flag-missing">No HttpOnly</span>}
                      {!cookie.secure && <span className="flag-missing">No Secure</span>}
                    </div>
                  </div>
                ))}
              </Expandable>
            )}
            {webCheckReport.cookies.clientCookies && webCheckReport.cookies.clientCookies.length > 0 && (
              <Expandable label={`View client cookies (${webCheckReport.cookies.clientCookies.length})`}>
                {webCheckReport.cookies.clientCookies.map((cookie, idx) => (
                  <div key={idx} className="wc-cookie-row">
                    <div className="wc-cookie-name">{cookie.name || `Cookie ${idx + 1}`}</div>
                    {cookie.domain && <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>{cookie.domain}</span>}
                  </div>
                ))}
              </Expandable>
            )}
          </div>
        )}

        {/* 7. WHOIS */}
        {webCheckReport.whois && !webCheckReport.whois.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>WHOIS Information</h5>
            <p><b>Registrar:</b> {webCheckReport.whois.registrarUrl
              ? <a href={webCheckReport.whois.registrarUrl.startsWith('http') ? webCheckReport.whois.registrarUrl : `https://${webCheckReport.whois.registrarUrl}`} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>{webCheckReport.whois.registrar || webCheckReport.whois.registrarUrl}</a>
              : (webCheckReport.whois.registrar || 'N/A')
            }</p>
            <p><b>Created:</b> {formatDate(webCheckReport.whois.createdDate || webCheckReport.whois.created)}</p>
            <p><b>Expires:</b> {formatDate(webCheckReport.whois.expiresDate || webCheckReport.whois.expires)}</p>
            <p><b>Updated:</b> {formatDate(webCheckReport.whois.updatedDate || webCheckReport.whois.updated)}</p>
            {webCheckReport.whois.nameServers && (
              <p><b>Nameservers:</b> {Array.isArray(webCheckReport.whois.nameServers) ? webCheckReport.whois.nameServers.join(', ') : webCheckReport.whois.nameServers}</p>
            )}
            {webCheckReport.whois.domainStatus && (
              <Expandable label="Domain Status">
                {(Array.isArray(webCheckReport.whois.domainStatus) ? webCheckReport.whois.domainStatus : [webCheckReport.whois.domainStatus]).map((status, idx) => (
                  <p key={idx} style={{ margin: '0.15rem 0' }}>{status}</p>
                ))}
              </Expandable>
            )}
          </div>
        )}

        {/* 8. Mail Config */}
        {webCheckReport['mail-config'] && !webCheckReport['mail-config'].error && !webCheckReport['mail-config'].skipped && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Mail Configuration</h5>
            <p><b>MX Records:</b> {webCheckReport['mail-config'].mxRecords?.length || 0}</p>
            {webCheckReport['mail-config'].mxRecords?.map((mx, idx) => (
              <p key={idx} style={{ fontSize: '0.85rem', marginLeft: '1rem' }}>
                {mx.exchange} (priority: {mx.priority})
              </p>
            ))}
            <p><b>Mail Services:</b> {webCheckReport['mail-config'].mailServices?.map(s => s.provider).join(', ') || 'None detected'}</p>
            {webCheckReport['mail-config'].txtRecords && webCheckReport['mail-config'].txtRecords.length > 0 && (
              <Expandable label={`Mail TXT records (${webCheckReport['mail-config'].txtRecords.length})`}>
                {webCheckReport['mail-config'].txtRecords.map((r, idx) => (
                  <p key={idx} style={{ wordBreak: 'break-all', margin: '0.15rem 0' }}>{r}</p>
                ))}
              </Expandable>
            )}
          </div>
        )}

        {/* 9. TLS Security */}
        {webCheckReport.tls && !webCheckReport.tls.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>TLS Security Analysis</h5>
            <p><b>Grade:</b> <span style={{ color: getObservatoryGradeColor(webCheckReport.tls.tlsInfo?.grade), fontWeight: 'bold', fontSize: '1.2rem' }}>{webCheckReport.tls.tlsInfo?.grade || 'N/A'}</span></p>
            <p><b>Score:</b> {webCheckReport.tls.tlsInfo?.score || 0}/100</p>
            <p><b>Host:</b> {webCheckReport.tls.tlsInfo?.host || 'N/A'}</p>
          </div>
        )}

        {/* 10. Social Tags */}
        {webCheckReport['social-tags'] && !webCheckReport['social-tags'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Social Media Tags</h5>
            <p><b>OG Title:</b> {webCheckReport['social-tags'].ogTitle || webCheckReport['social-tags'].openGraph?.title || 'N/A'}</p>
            <p><b>OG Description:</b> {(webCheckReport['social-tags'].ogDescription || webCheckReport['social-tags'].openGraph?.description || 'N/A').substring(0, 150)}</p>
            <p><b>Twitter Card:</b> {webCheckReport['social-tags'].twitterCard || webCheckReport['social-tags'].twitter?.card || 'N/A'}</p>
            {(webCheckReport['social-tags'].ogImage || webCheckReport['social-tags'].openGraph?.image) && (
              <div>
                <b>OG Image:</b>
                <img
                  src={webCheckReport['social-tags'].ogImage || webCheckReport['social-tags'].openGraph?.image}
                  alt="OG preview"
                  className="wc-og-image"
                  onError={(e) => { e.target.style.display = 'none'; }}
                />
              </div>
            )}
            {(webCheckReport['social-tags'].themeColor || webCheckReport['social-tags'].openGraph?.themeColor) && (
              <p>
                <b>Theme Color:</b> {webCheckReport['social-tags'].themeColor || webCheckReport['social-tags'].openGraph?.themeColor}
                <span className="wc-theme-swatch" style={{ backgroundColor: webCheckReport['social-tags'].themeColor || webCheckReport['social-tags'].openGraph?.themeColor }} />
              </p>
            )}
          </div>
        )}

        {/* 11. Redirects */}
        {webCheckReport.redirects && !webCheckReport.redirects.error && webCheckReport.redirects.redirects?.length > 0 && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Redirect Chain</h5>
            <div className="wc-arrow-chain">
              {webCheckReport.redirects.redirects.map((redirect, idx) => (
                <div key={idx} className="wc-arrow-step">
                  <span className="wc-step-number">{idx + 1}</span>
                  <span className="wc-step-status" style={{ color: redirect.statusCode >= 400 ? '#e81123' : '#ffb900' }}>{redirect.statusCode}</span>
                  <span className="wc-step-url">{redirect.url || 'N/A'}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 12. Archives */}
        {webCheckReport.archives && !webCheckReport.archives.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Web Archive History</h5>
            <p><b>Total Snapshots:</b> {webCheckReport.archives.scanCount || webCheckReport.archives.length || 'Available'}</p>
            {webCheckReport.archives.firstScan && <p><b>First Snapshot:</b> {webCheckReport.archives.firstScan}</p>}
            {webCheckReport.archives.lastScan && <p><b>Last Snapshot:</b> {webCheckReport.archives.lastScan}</p>}
          </div>
        )}

        {/* 13. Carbon Footprint */}
        {webCheckReport.carbon && !webCheckReport.carbon.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Carbon Footprint</h5>
            <p><b>Green Hosting:</b> <span style={{ color: webCheckReport.carbon.isGreen ? '#00d084' : '#ffb900' }}>{webCheckReport.carbon.isGreen ? 'Yes' : 'No'}</span></p>
            {webCheckReport.carbon.co2 && (
              <>
                <p><b>CO2 per visit:</b> {webCheckReport.carbon.co2.grid?.grams?.toFixed(2) || 'N/A'}g</p>
                <p><b>Cleaner than:</b> {webCheckReport.carbon.cleanerThan ? `${(webCheckReport.carbon.cleanerThan * 100).toFixed(0)}% of sites` : 'N/A'}</p>
              </>
            )}
          </div>
        )}

        {/* 14. TXT Records */}
        {webCheckReport['txt-records'] && !webCheckReport['txt-records'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>TXT Records</h5>
            <div className="wc-scrollable">
              {(webCheckReport['txt-records'].txtRecords || webCheckReport['txt-records'].records || []).map((record, idx) => {
                const text = Array.isArray(record) ? record.join('') : String(record);
                const isSPF = text.startsWith('v=spf');
                const isDKIM = text.startsWith('v=DKIM');
                const isDMARC = text.startsWith('v=DMARC');
                let label = null;
                if (isSPF) label = 'SPF';
                if (isDKIM) label = 'DKIM';
                if (isDMARC) label = 'DMARC';
                return (
                  <div key={idx} style={{ marginBottom: '0.5rem', paddingBottom: '0.5rem', borderBottom: '1px solid rgba(128,128,128,0.15)' }}>
                    {label && <span style={{ background: 'var(--accent)', color: 'white', padding: '0.1rem 0.35rem', borderRadius: '3px', fontSize: '0.7rem', fontWeight: 700, marginRight: '0.5rem' }}>{label}</span>}
                    <span style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>{text}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* 15. HTTP Headers */}
        {webCheckReport.headers && !webCheckReport.headers.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>HTTP Headers</h5>
            <div className="wc-scrollable">
              {Object.entries(webCheckReport.headers).map(([key, val]) => (
                <p key={key} style={{ fontSize: '0.8rem', margin: '0.2rem 0' }}><b>{key}:</b> {String(val)}</p>
              ))}
            </div>
          </div>
        )}

        {/* 16. Firewall / WAF */}
        {webCheckReport.firewall && !webCheckReport.firewall.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Firewall / WAF Detection</h5>
            <p>
              <b>WAF Detected:</b>{' '}
              <span style={{
                color: (webCheckReport.firewall.detected || webCheckReport.firewall.hasWaf) ? '#00d084' : '#ffb900',
                fontWeight: 'bold'
              }}>
                {(webCheckReport.firewall.detected || webCheckReport.firewall.hasWaf) ? 'Yes' : 'Not Detected'}
              </span>
            </p>
            {(webCheckReport.firewall.name || webCheckReport.firewall.wafName) && (
              <p><b>Name:</b> {webCheckReport.firewall.name || webCheckReport.firewall.wafName}</p>
            )}
            {webCheckReport.firewall.confidence && (
              <p><b>Confidence:</b> {webCheckReport.firewall.confidence}</p>
            )}
          </div>
        )}

        {/* 17. HSTS */}
        {webCheckReport.hsts && !webCheckReport.hsts.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>HSTS (HTTP Strict Transport Security)</h5>
            <p>
              <b>Enabled:</b>{' '}
              <span style={{ color: (webCheckReport.hsts.enabled || webCheckReport.hsts.preloaded) ? '#00d084' : '#e81123', fontWeight: 'bold' }}>
                {(webCheckReport.hsts.enabled || webCheckReport.hsts.preloaded) ? 'Yes' : 'No'}
              </span>
            </p>
            {webCheckReport.hsts.maxAge !== undefined && (
              <p><b>Max-Age:</b> {webCheckReport.hsts.maxAge} seconds ({Math.round(webCheckReport.hsts.maxAge / 86400)} days)</p>
            )}
            {webCheckReport.hsts.includeSubDomains !== undefined && (
              <p><b>Include Subdomains:</b> <span style={{ color: webCheckReport.hsts.includeSubDomains ? '#00d084' : '#888' }}>{webCheckReport.hsts.includeSubDomains ? 'Yes' : 'No'}</span></p>
            )}
            {webCheckReport.hsts.preloaded !== undefined && (
              <p><b>Preloaded:</b> <span style={{ color: webCheckReport.hsts.preloaded ? '#00d084' : '#888' }}>{webCheckReport.hsts.preloaded ? 'Yes' : 'No'}</span></p>
            )}
          </div>
        )}

        {/* 18. Security.txt */}
        {webCheckReport['security-txt'] && !webCheckReport['security-txt'].error && !webCheckReport['security-txt'].skipped && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Security.txt</h5>
            {webCheckReport['security-txt'].present === false ? (
              <p style={{ opacity: 0.7 }}>No security.txt file found</p>
            ) : (
              <>
                {webCheckReport['security-txt'].contact && (
                  <p><b>Contact:</b> {Array.isArray(webCheckReport['security-txt'].contact) ? webCheckReport['security-txt'].contact.join(', ') : webCheckReport['security-txt'].contact}</p>
                )}
                {webCheckReport['security-txt'].expires && (
                  <p><b>Expires:</b> {formatDate(webCheckReport['security-txt'].expires)}</p>
                )}
                {webCheckReport['security-txt'].preferredLanguages && (
                  <p><b>Languages:</b> {webCheckReport['security-txt'].preferredLanguages}</p>
                )}
                {webCheckReport['security-txt'].canonical && (
                  <p><b>Canonical:</b> <a href={webCheckReport['security-txt'].canonical} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>{webCheckReport['security-txt'].canonical}</a></p>
                )}
                {webCheckReport['security-txt'].content && (
                  <Expandable label="View full security.txt">
                    <div className="wc-code-block">{webCheckReport['security-txt'].content}</div>
                  </Expandable>
                )}
              </>
            )}
          </div>
        )}

        {/* 19. Block Lists */}
        {webCheckReport['block-lists'] && !webCheckReport['block-lists'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Block Lists</h5>
            {(() => {
              const data = webCheckReport['block-lists'];
              const lists = data.lists || data.blocklists || data.results || [];
              if (Array.isArray(lists) && lists.length > 0) {
                const blocked = lists.filter(l => l.blocked || l.listed);
                const clean = lists.filter(l => !l.blocked && !l.listed);
                return (
                  <>
                    <p>
                      <b>Status:</b>{' '}
                      <span style={{ color: blocked.length > 0 ? '#e81123' : '#00d084', fontWeight: 'bold' }}>
                        {blocked.length > 0 ? `Listed on ${blocked.length} blocklist(s)` : 'Not listed on any blocklists'}
                      </span>
                    </p>
                    {blocked.length > 0 && blocked.map((bl, idx) => (
                      <p key={idx} style={{ color: '#e81123', fontSize: '0.85rem' }}>✗ {bl.name || bl.list || `Blocklist ${idx + 1}`}</p>
                    ))}
                    {clean.length > 0 && (
                      <Expandable label={`Clean on ${clean.length} lists`}>
                        {clean.map((cl, idx) => (
                          <p key={idx} style={{ color: '#00d084', margin: '0.1rem 0' }}>✓ {cl.name || cl.list || `List ${idx + 1}`}</p>
                        ))}
                      </Expandable>
                    )}
                  </>
                );
              }
              // Fallback: simple object display
              if (data.blocked !== undefined) {
                return <p><b>Blocked:</b> <span style={{ color: data.blocked ? '#e81123' : '#00d084', fontWeight: 'bold' }}>{data.blocked ? 'Yes' : 'No'}</span></p>;
              }
              return <p>Block list data available</p>;
            })()}
          </div>
        )}

        {/* 20. Linked Pages */}
        {webCheckReport['linked-pages'] && !webCheckReport['linked-pages'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Linked Pages</h5>
            {(() => {
              const data = webCheckReport['linked-pages'];
              const internal = data.internal || data.internalLinks || [];
              const external = data.external || data.externalLinks || [];
              return (
                <>
                  <p><b>Internal Links:</b> {internal.length} &nbsp; <b>External Links:</b> {external.length}</p>
                  {internal.length > 0 && (
                    <Expandable label={`View internal links (${internal.length})`}>
                      <div className="wc-link-list">
                        {internal.slice(0, 50).map((link, idx) => (
                          <span key={idx}>{typeof link === 'object' ? (link.url || link.href || JSON.stringify(link)) : link}</span>
                        ))}
                        {internal.length > 50 && <span style={{ opacity: 0.6 }}>...and {internal.length - 50} more</span>}
                      </div>
                    </Expandable>
                  )}
                  {external.length > 0 && (
                    <Expandable label={`View external links (${external.length})`}>
                      <div className="wc-link-list">
                        {external.slice(0, 50).map((link, idx) => (
                          <span key={idx}>{typeof link === 'object' ? (link.url || link.href || JSON.stringify(link)) : link}</span>
                        ))}
                        {external.length > 50 && <span style={{ opacity: 0.6 }}>...and {external.length - 50} more</span>}
                      </div>
                    </Expandable>
                  )}
                </>
              );
            })()}
          </div>
        )}

        {/* 21. Robots.txt */}
        {webCheckReport['robots-txt'] && !webCheckReport['robots-txt'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Robots.txt</h5>
            {webCheckReport['robots-txt'].present === false ? (
              <p style={{ opacity: 0.7 }}>No robots.txt file found</p>
            ) : (
              <>
                {webCheckReport['robots-txt'].content && (
                  <div className="wc-code-block">{webCheckReport['robots-txt'].content}</div>
                )}
                {!webCheckReport['robots-txt'].content && webCheckReport['robots-txt'].rules && (
                  <div className="wc-code-block">
                    {(Array.isArray(webCheckReport['robots-txt'].rules) ? webCheckReport['robots-txt'].rules : [webCheckReport['robots-txt'].rules]).map((rule, idx) => (
                      <div key={idx}>{typeof rule === 'object' ? JSON.stringify(rule, null, 2) : rule}</div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* 22. Sitemap */}
        {webCheckReport.sitemap && !webCheckReport.sitemap.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Sitemap</h5>
            {webCheckReport.sitemap.present === false ? (
              <p style={{ opacity: 0.7 }}>No sitemap found</p>
            ) : (
              <>
                {webCheckReport.sitemap.url && <p><b>URL:</b> <a href={webCheckReport.sitemap.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>{webCheckReport.sitemap.url}</a></p>}
                {(webCheckReport.sitemap.urlCount || webCheckReport.sitemap.urls?.length) && (
                  <p><b>URLs:</b> {webCheckReport.sitemap.urlCount || webCheckReport.sitemap.urls?.length}</p>
                )}
                {webCheckReport.sitemap.sitemaps && webCheckReport.sitemap.sitemaps.length > 0 && (
                  <Expandable label={`View sitemaps (${webCheckReport.sitemap.sitemaps.length})`}>
                    {webCheckReport.sitemap.sitemaps.map((sm, idx) => (
                      <p key={idx} style={{ margin: '0.15rem 0', wordBreak: 'break-all' }}>{typeof sm === 'object' ? (sm.url || sm.loc || JSON.stringify(sm)) : sm}</p>
                    ))}
                  </Expandable>
                )}
                {webCheckReport.sitemap.urls && webCheckReport.sitemap.urls.length > 0 && (
                  <Expandable label={`View URLs (${webCheckReport.sitemap.urls.length})`}>
                    <div className="wc-link-list">
                      {webCheckReport.sitemap.urls.slice(0, 100).map((u, idx) => (
                        <span key={idx}>{typeof u === 'object' ? (u.url || u.loc || JSON.stringify(u)) : u}</span>
                      ))}
                      {webCheckReport.sitemap.urls.length > 100 && <span style={{ opacity: 0.6 }}>...and {webCheckReport.sitemap.urls.length - 100} more</span>}
                    </div>
                  </Expandable>
                )}
              </>
            )}
          </div>
        )}

        {/* 23. DNS Server */}
        {webCheckReport['dns-server'] && !webCheckReport['dns-server'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>DNS Server</h5>
            {(() => {
              const data = webCheckReport['dns-server'];
              const servers = data.servers || data.dns || data.nameservers || [];
              if (Array.isArray(servers) && servers.length > 0) {
                return servers.map((server, idx) => (
                  <div key={idx} style={{ marginBottom: '0.5rem', paddingBottom: '0.5rem', borderBottom: '1px solid rgba(128,128,128,0.15)' }}>
                    <p style={{ margin: '0.1rem 0' }}><b>Server {idx + 1}:</b> {server.ip || server.address || server.name || (typeof server === 'string' ? server : JSON.stringify(server))}</p>
                    {server.provider && <p style={{ margin: '0.1rem 0', fontSize: '0.85rem' }}><b>Provider:</b> {server.provider}</p>}
                    {server.country && <p style={{ margin: '0.1rem 0', fontSize: '0.85rem' }}><b>Country:</b> {server.country}</p>}
                  </div>
                ));
              }
              // Fallback: simple display
              if (data.ip || data.address) {
                return <p><b>Server:</b> {data.ip || data.address}</p>;
              }
              return <p>DNS server information available</p>;
            })()}
          </div>
        )}

        {/* 24. DNSSEC */}
        {webCheckReport.dnssec && !webCheckReport.dnssec.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>DNSSEC</h5>
            <p>
              <b>Status:</b>{' '}
              <span style={{
                color: (webCheckReport.dnssec.enabled || webCheckReport.dnssec.secure || webCheckReport.dnssec.isValid) ? '#00d084' : '#e81123',
                fontWeight: 'bold'
              }}>
                {(webCheckReport.dnssec.enabled || webCheckReport.dnssec.secure || webCheckReport.dnssec.isValid) ? 'Enabled & Valid' : 'Not Enabled'}
              </span>
            </p>
            {webCheckReport.dnssec.algorithm && (
              <p><b>Algorithm:</b> {webCheckReport.dnssec.algorithm}{webCheckReport.dnssec.algorithmName ? ` (${webCheckReport.dnssec.algorithmName})` : ''}</p>
            )}
            {webCheckReport.dnssec.keyTag && <p><b>Key Tag:</b> {webCheckReport.dnssec.keyTag}</p>}
            {webCheckReport.dnssec.digestType && <p><b>Digest Type:</b> {webCheckReport.dnssec.digestType}</p>}
            {webCheckReport.dnssec.ds && (
              <Expandable label="DS Records">
                {(Array.isArray(webCheckReport.dnssec.ds) ? webCheckReport.dnssec.ds : [webCheckReport.dnssec.ds]).map((ds, idx) => (
                  <p key={idx} style={{ margin: '0.15rem 0', fontSize: '0.8rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{typeof ds === 'object' ? JSON.stringify(ds) : ds}</p>
                ))}
              </Expandable>
            )}
            {webCheckReport.dnssec.dnskey && (
              <Expandable label="DNSKEY Records">
                {(Array.isArray(webCheckReport.dnssec.dnskey) ? webCheckReport.dnssec.dnskey : [webCheckReport.dnssec.dnskey]).map((key, idx) => (
                  <p key={idx} style={{ margin: '0.15rem 0', fontSize: '0.8rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{typeof key === 'object' ? JSON.stringify(key) : key}</p>
                ))}
              </Expandable>
            )}
          </div>
        )}

        {/* 25. Ranking */}
        {webCheckReport['legacy-rank'] && !webCheckReport['legacy-rank'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Website Ranking</h5>
            {(() => {
              const data = webCheckReport['legacy-rank'];
              const rankRaw = data.rank || data.globalRank || data.alexaRank;
              const rankNum = rankRaw ? Number(rankRaw) : null;
              const isFound = data.isFound !== false && rankNum && rankNum > 0;

              if (!isFound) {
                return <p style={{ opacity: 0.7 }}>Not found in the global top 1M domains list.</p>;
              }

              // Logarithmic position: rank 1 = 100%, rank 1M = 0%
              const logPercent = Math.max(0, Math.min(100, 100 - (Math.log10(rankNum) / 6) * 100));
              const barColor = logPercent >= 80 ? '#00d084' : logPercent >= 50 ? '#7fba00' : logPercent >= 25 ? '#ffb900' : '#e81123';
              const tier = rankNum <= 100 ? 'Top 100' : rankNum <= 1000 ? 'Top 1K' : rankNum <= 10000 ? 'Top 10K' : rankNum <= 100000 ? 'Top 100K' : 'Top 1M';

              return (
                <div className="wc-rank-big">
                  <div className="wc-rank-number">
                    #{rankNum.toLocaleString()}
                    <span className="wc-rank-label">Traffic Rank</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 180, maxWidth: 350 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', opacity: 0.6, marginBottom: '0.35rem' }}>
                      <span>#1</span>
                      <span style={{ fontWeight: 700, opacity: 1, color: barColor }}>{tier}</span>
                      <span>#1,000,000</span>
                    </div>
                    <div style={{ height: 14, background: theme === 'light' ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)', borderRadius: 7, overflow: 'hidden' }}>
                      <div style={{ width: `${logPercent}%`, height: '100%', background: `linear-gradient(90deg, ${barColor}, ${barColor}cc)`, borderRadius: 7, transition: 'width 0.6s ease' }} />
                    </div>
                    {data.domain && (
                      <p style={{ fontSize: '0.75rem', opacity: 0.5, marginTop: '0.35rem', textAlign: 'center' }}>{data.domain}</p>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* 26. HTTP Status */}
        {webCheckReport.status && !webCheckReport.status.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>HTTP Status</h5>
            <p>
              <span className={`wc-status-badge ${getStatusClass(webCheckReport.status.statusCode || webCheckReport.status.code || webCheckReport.status)}`}>
                {webCheckReport.status.statusCode || webCheckReport.status.code || (typeof webCheckReport.status === 'number' ? webCheckReport.status : 'N/A')}
              </span>
              {webCheckReport.status.statusMessage && (
                <span style={{ marginLeft: '0.75rem', fontSize: '0.9rem' }}>{webCheckReport.status.statusMessage}</span>
              )}
            </p>
            {webCheckReport.status.responseTime && (
              <p><b>Response Time:</b> {webCheckReport.status.responseTime}ms</p>
            )}
          </div>
        )}

        {/* 27. Trace Route */}
        {webCheckReport['trace-route'] && !webCheckReport['trace-route'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Trace Route</h5>
            {(() => {
              const data = webCheckReport['trace-route'];
              const hops = data.hops || data.result || data.traceroute || [];
              if (Array.isArray(hops) && hops.length > 0) {
                // Filter out hops where all fields are just asterisks or empty
                const hasUsefulData = (hop) => {
                  const ip = hop.ip || hop.address || '';
                  const rtt = hop.rtt || hop.time || hop.ms || '';
                  const host = hop.host || '';
                  return (ip && ip !== '*') || (rtt && rtt !== '*') || (host && host !== '*');
                };
                const usefulHops = hops.filter(hasUsefulData);
                const totalHops = hops.length;
                const filteredCount = totalHops - usefulHops.length;

                if (usefulHops.length === 0) {
                  return (
                    <p style={{ opacity: 0.7 }}>
                      All {totalHops} hops were unreachable (likely blocked by a firewall or CDN).
                    </p>
                  );
                }

                const hasHost = usefulHops.some(h => h.host);
                return (
                  <>
                    <table className="wc-hops-table">
                      <thead>
                        <tr>
                          <th>Hop</th>
                          <th>IP</th>
                          <th>RTT</th>
                          {hasHost && <th>Host</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {usefulHops.map((hop, idx) => (
                          <tr key={idx}>
                            <td>{hop.hop || idx + 1}</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{hop.ip || hop.address || '*'}</td>
                            <td>{hop.rtt || hop.time || hop.ms ? `${hop.rtt || hop.time || hop.ms}ms` : '*'}</td>
                            {hasHost && <td style={{ fontSize: '0.8rem' }}>{hop.host || ''}</td>}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {filteredCount > 0 && (
                      <p style={{ opacity: 0.6, fontSize: '0.8rem', marginTop: '0.5rem' }}>
                        {filteredCount} unreachable hop{filteredCount > 1 ? 's' : ''} hidden
                      </p>
                    )}
                  </>
                );
              }
              // Fallback string display
              if (typeof data === 'string' || data.output) {
                return <div className="wc-code-block">{data.output || data}</div>;
              }
              return <p>Trace route data available</p>;
            })()}
          </div>
        )}

        {/* 28. IP Address */}
        {webCheckReport['get-ip'] && !webCheckReport['get-ip'].error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>IP Address</h5>
            <p><b>IP:</b> <span style={{ fontFamily: 'monospace', fontSize: '1rem' }}>{webCheckReport['get-ip'].ip || webCheckReport['get-ip'].address || JSON.stringify(webCheckReport['get-ip'])}</span></p>
            {webCheckReport['get-ip'].family && <p><b>Version:</b> IPv{webCheckReport['get-ip'].family}</p>}
            {webCheckReport['get-ip'].city && <p><b>Location:</b> {[webCheckReport['get-ip'].city, webCheckReport['get-ip'].region, webCheckReport['get-ip'].country].filter(Boolean).join(', ')}</p>}
            {webCheckReport['get-ip'].isp && <p><b>ISP:</b> {webCheckReport['get-ip'].isp}</p>}
            {webCheckReport['get-ip'].org && <p><b>Organization:</b> {webCheckReport['get-ip'].org}</p>}
          </div>
        )}

        {/* 29. Quality Metrics */}
        {webCheckReport.quality && !webCheckReport.quality.error && (
          <div style={cardStyle}>
            <h5 style={h5Style}>Quality Metrics</h5>
            {(() => {
              const data = webCheckReport.quality;
              const displayMetrics = [];

              // Parse PageSpeed Insights API response (lighthouseResult.categories)
              const lhCategories = data.lighthouseResult?.categories;
              if (lhCategories) {
                if (lhCategories.performance) displayMetrics.push({ name: 'Performance', score: lhCategories.performance.score });
                if (lhCategories.accessibility) displayMetrics.push({ name: 'Accessibility', score: lhCategories.accessibility.score });
                if (lhCategories['best-practices']) displayMetrics.push({ name: 'Best Practices', score: lhCategories['best-practices'].score });
                if (lhCategories.seo) displayMetrics.push({ name: 'SEO', score: lhCategories.seo.score });
                if (lhCategories.pwa) displayMetrics.push({ name: 'PWA', score: lhCategories.pwa.score });
              }

              // Fallback: try direct categories/metrics keys
              if (displayMetrics.length === 0) {
                const metrics = data.categories || data.metrics || data;
                if (metrics.performance !== undefined) displayMetrics.push({ name: 'Performance', score: metrics.performance });
                if (metrics.accessibility !== undefined) displayMetrics.push({ name: 'Accessibility', score: metrics.accessibility });
                if (metrics.bestPractices !== undefined || metrics['best-practices'] !== undefined) displayMetrics.push({ name: 'Best Practices', score: metrics.bestPractices || metrics['best-practices'] });
                if (metrics.seo !== undefined) displayMetrics.push({ name: 'SEO', score: metrics.seo });
              }

              // Parse loading experience category (from PSI API top-level)
              const loadingExp = data.loadingExperience;
              const overallCategory = loadingExp?.overall_category;

              if (displayMetrics.length > 0) {
                return (
                  <>
                    {overallCategory && (
                      <p style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                        <b>Overall:</b>{' '}
                        <span style={{
                          color: overallCategory === 'FAST' ? '#00d084' : overallCategory === 'AVERAGE' ? '#ffb900' : '#e81123',
                          fontWeight: 700
                        }}>{overallCategory}</span>
                      </p>
                    )}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '0.75rem' }}>
                      {displayMetrics.map((m, idx) => {
                        const score = typeof m.score === 'number' ? (m.score > 1 ? m.score : Math.round(m.score * 100)) : 0;
                        const color = score >= 90 ? '#00d084' : score >= 50 ? '#ffb900' : '#e81123';
                        return (
                          <div key={idx} style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '1.5rem', fontWeight: 900, color }}>{score}</div>
                            <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>{m.name}</div>
                          </div>
                        );
                      })}
                    </div>
                  </>
                );
              }

              // Minimal fallback: show loading experience if available
              if (overallCategory) {
                return (
                  <p style={{ fontSize: '0.9rem' }}>
                    <b>Loading Experience:</b>{' '}
                    <span style={{
                      color: overallCategory === 'FAST' ? '#00d084' : overallCategory === 'AVERAGE' ? '#ffb900' : '#e81123',
                      fontWeight: 700
                    }}>{overallCategory}</span>
                  </p>
                );
              }

              // Last resort: just show the score/grade if available from summary
              if (data.score !== undefined || data.grade) {
                return (
                  <>
                    {data.score !== undefined && <p style={{ fontSize: '0.9rem' }}><b>Score:</b> {data.score}</p>}
                    {data.grade && <p style={{ fontSize: '0.9rem' }}><b>Grade:</b> {data.grade}</p>}
                  </>
                );
              }

              return <p style={{ fontSize: '0.85rem', opacity: 0.7 }}>Quality data available</p>;
            })()}
          </div>
        )}

      </div>
    </details>
  );
};

export default WebCheckDetails;
