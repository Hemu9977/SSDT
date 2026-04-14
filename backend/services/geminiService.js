const { GoogleGenerativeAI } = require('@google/generative-ai');

// Model name is configurable via GEMINI_MODEL env var
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';

/**
 * Get all available Gemini API keys from environment variables
 * Supports GEMINI_API_KEY, GEMINI_API_KEY_2, GEMINI_API_KEY_3, etc.
 * @returns {Array<string>} - Array of API keys
 */
function getApiKeys() {
  const keys = [];

  // Get primary API key
  if (process.env.GEMINI_API_KEY) {
    keys.push(process.env.GEMINI_API_KEY);
  }

  // Get additional API keys (GEMINI_API_KEY_2, GEMINI_API_KEY_3, etc.)
  let i = 2;
  while (process.env[`GEMINI_API_KEY_${i}`]) {
    keys.push(process.env[`GEMINI_API_KEY_${i}`]);
    i++;
  }

  console.log(`📋 Found ${keys.length} Gemini API key(s) configured`);
  return keys;
}

/**
 * Refine and combine PageSpeed, Observatory, ZAP, urlscan, and WebCheck reports using Gemini AI
 * @param {Object} _unused - Reserved parameter (unused, pass null)
 * @param {Object} psiReport - PageSpeed Insights report
 * @param {Object} observatoryReport - Mozilla Observatory scan result
 * @param {string} url - The scanned URL
 * @param {Object} zapReport - OWASP ZAP vulnerability scan result (optional)
 * @param {Object} urlscanReport - urlscan.io website analysis result (optional)
 * @param {Object} webCheckReport - WebCheck comprehensive scan results (optional)
 * @returns {Promise<string>} - AI-generated refined report in Markdown format
 */
async function refineReport(_unused, psiReport, observatoryReport, url, zapReport = null, urlscanReport = null, webCheckReport = null) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured. Please set GEMINI_API_KEY in environment variables.');
  }

  let lastError = null;
  const MAX_NETWORK_RETRIES = 3;

  for (let networkRetry = 0; networkRetry < MAX_NETWORK_RETRIES; networkRetry++) {
    if (networkRetry > 0) {
      const delay = networkRetry * 5000; // 5s, 10s
      console.log(`🔄 Network retry ${networkRetry}/${MAX_NETWORK_RETRIES - 1} - waiting ${delay / 1000}s before retrying all keys...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }

    // Try each API key until one succeeds
    for (let i = 0; i < apiKeys.length; i++) {
      const apiKey = apiKeys[i];
      const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

      try {
        console.log(`🔑 Attempting Gemini API with ${keyLabel} key (${i + 1}/${apiKeys.length})...`);

        // Initialize Gemini AI with current API key
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

        // Extract PageSpeed scores
        const lighthouseResult = psiReport?.lighthouseResult || {};
        const categories = lighthouseResult.categories || {};
        const performanceScore = categories.performance?.score ? Math.round(categories.performance.score * 100) : 'N/A';
        const accessibilityScore = categories.accessibility?.score ? Math.round(categories.accessibility.score * 100) : 'N/A';
        const bestPracticesScore = categories['best-practices']?.score ? Math.round(categories['best-practices'].score * 100) : 'N/A';
        const seoScore = categories.seo?.score ? Math.round(categories.seo.score * 100) : 'N/A';

        // Extract Observatory data
        const observatoryGrade = observatoryReport?.grade || 'N/A';
        const observatoryScore = observatoryReport?.score || 'N/A';
        const observatoryTestsPassed = observatoryReport?.tests_passed || 0;
        const observatoryTestsFailed = observatoryReport?.tests_failed || 0;
        const observatoryTestsTotal = observatoryReport?.tests_quantity || 0;
        const hasObservatoryData = observatoryReport && !observatoryReport.error;

        // Extract ZAP data
        const hasZapData = zapReport && !zapReport.error && zapReport.alerts;
        const zapRiskCounts = zapReport?.riskCounts || { High: 0, Medium: 0, Low: 0, Informational: 0 };
        const zapAlertCount = zapReport?.alerts?.length || 0;
        const zapHighRisk = zapReport?.alerts?.filter(a => a.risk === 'High') || [];
        const zapMediumRisk = zapReport?.alerts?.filter(a => a.risk === 'Medium') || [];

        // Extract urlscan data
        const hasUrlscanData = urlscanReport && !urlscanReport.error && urlscanReport.verdicts;
        const urlscanVerdicts = urlscanReport?.verdicts || {};
        const urlscanPage = urlscanReport?.page || {};
        const urlscanStats = urlscanReport?.stats || {};
        const urlscanIsMalicious = urlscanVerdicts?.overall?.malicious || false;
        const urlscanScore = urlscanVerdicts?.overall?.score || 0;

        // Extract WebCheck data
        const hasWebCheckData = webCheckReport && Object.keys(webCheckReport).length > 0;
        const webCheckHeaders = webCheckReport?.headers || {};
        const webCheckTls = webCheckReport?.tls || webCheckReport?.ssl || {};
        const webCheckTechStack = webCheckReport?.['tech-stack'] || {};
        const webCheckFirewall = webCheckReport?.firewall || {};
        const webCheckDns = webCheckReport?.dns || {};
        const webCheckHsts = webCheckReport?.hsts || {};
        const webCheckSecurityTxt = webCheckReport?.['security-txt'] || {};
        const webCheckRobotsTxt = webCheckReport?.['robots-txt'] || {};
        const webCheckCookies = webCheckReport?.cookies || {};
        const webCheckCarbon = webCheckReport?.carbon || {};
        const webCheckQuality = webCheckReport?.quality || {};

        // Build the prompt for Gemini
        const prompt = `You are a cybersecurity and web performance expert. Analyze the following reports for the URL: ${url}

Performance Analysis Report:
- Performance Score: ${performanceScore}/100
- Accessibility Score: ${accessibilityScore}/100
- Best Practices Score: ${bestPracticesScore}/100
- SEO Score: ${seoScore}/100

${hasObservatoryData ? `Security Configuration Analysis:
- Security Grade: ${observatoryGrade}
- Security Score: ${observatoryScore}/100
- Tests Passed: ${observatoryTestsPassed}
- Tests Failed: ${observatoryTestsFailed}
- Total Tests: ${observatoryTestsTotal}` : 'Security Configuration Analysis: Not available for this scan'}

${hasZapData ? `Vulnerability Scan Report:
- Total Alerts: ${zapAlertCount}
- High Risk Vulnerabilities: ${zapRiskCounts.High}
- Medium Risk Vulnerabilities: ${zapRiskCounts.Medium}
- Low Risk Vulnerabilities: ${zapRiskCounts.Low}
- Informational: ${zapRiskCounts.Informational}
${zapHighRisk.length > 0 ? `- High Risk Issues: ${zapHighRisk.slice(0, 5).map(a => a.alert).join(', ')}` : ''}
${zapMediumRisk.length > 0 ? `- Medium Risk Issues: ${zapMediumRisk.slice(0, 5).map(a => a.alert).join(', ')}` : ''}` : 'Vulnerability Scan: Not available or still in progress'}

${hasUrlscanData ? `Threat & Reputation Analysis:
- Malicious Verdict: ${urlscanIsMalicious ? 'YES - MALICIOUS' : 'No - Clean'}
- Threat Score: ${urlscanScore}/100
- Domain: ${urlscanPage.domain || 'N/A'}
- Server IP: ${urlscanPage.ip || 'N/A'}
- Country: ${urlscanPage.country || 'N/A'}
- Server: ${urlscanPage.server || 'N/A'}
- TLS Issuer: ${urlscanPage.tlsIssuer || 'N/A'}
- Unique IPs: ${urlscanStats.uniqIPs || 0}
- Total Requests: ${urlscanStats.requests || 0}` : 'Threat & Reputation Analysis: Not available or still in progress'}

${hasWebCheckData ? `Web Security Configuration Report:
- Security Headers: ${JSON.stringify(webCheckHeaders?.headers || webCheckHeaders || 'N/A')}
- TLS/SSL Configuration: ${webCheckTls?.grade || webCheckTls?.valid ? `Grade: ${webCheckTls.grade || 'Valid'}, Protocol: ${webCheckTls.protocol || 'N/A'}, Cipher: ${webCheckTls.cipher || 'N/A'}` : 'N/A'}
- Technology Stack: ${Array.isArray(webCheckTechStack?.technologies) ? webCheckTechStack.technologies.map(t => t.name || t).join(', ') : 'N/A'}
- Firewall/WAF Detection: ${webCheckFirewall?.hasWaf ? `Detected: ${webCheckFirewall.waf || 'Yes'}` : 'No WAF detected'}
- HSTS Status: ${webCheckHsts?.enabled ? `Enabled (max-age: ${webCheckHsts.maxAge || 'N/A'})` : 'Not enabled'}
- DNS Configuration: ${webCheckDns?.a ? `A Records: ${webCheckDns.a.join(', ')}` : 'N/A'}
- Security.txt: ${webCheckSecurityTxt?.present ? 'Present' : 'Not found'}
- Robots.txt: ${webCheckRobotsTxt?.present ? 'Present' : 'Not found'}
- Cookies: ${Array.isArray(webCheckCookies) ? `${webCheckCookies.length} cookies found` : 'N/A'}
- Carbon Footprint: ${webCheckCarbon?.co2 ? `${webCheckCarbon.co2}g CO2 per visit` : 'N/A'}
- Code Quality Score: ${webCheckQuality?.score || 'N/A'}` : 'Web Security Configuration: Not available or still in progress'}

Task:
Generate a comprehensive, professional analysis report that includes:

1. Executive Summary (2-3 sentences): Overall assessment of the URL's security and performance.

2. Security Analysis:
   - Risk level (Low/Medium/High) based on vulnerability scan and threat analysis results
   - Security configuration grade and assessment (if available)
   - Vulnerability findings and their severity (if available)
   - Threat detection and reputation analysis (if available)
   - Security headers, TLS/SSL grade, WAF detection, HSTS status (if available)
   - Key security findings and threats detected (if any)
   - Specific concerns or red flags from all scan sources

3. Infrastructure Analysis (if available):
   - Technology stack and frameworks detected
   - DNS configuration assessment
   - Cookie security analysis
   - Security.txt and robots.txt presence

4. Performance Analysis:
   - Overall performance rating
   - Key performance metrics and their implications
   - Accessibility and SEO considerations
   - Environmental impact (carbon footprint if available)

5. Conclusion: Final verdict on whether the URL is safe to use and performs well.

6. Actionable Recommendations:
   - Security improvements (if needed) - include malware protection, security header configuration, vulnerability remediation, TLS improvements, and HSTS implementation
   - Performance optimizations
   - Best practices to implement

IMPORTANT FORMATTING INSTRUCTIONS:
- Use simple text formatting with headers (use # for headers) and bullet points (use - for lists)
- DO NOT use double asterisks for bolding any terms within headers or list items
- DO NOT wrap the entire response in markdown code blocks (do not use triple backticks)
- Keep the report concise, professional, and actionable
- Focus on practical insights rather than raw data
- Do NOT mention the names of any specific third-party tools or services used to collect the data
- Ensure ALL scores (Performance, Accessibility, Best Practices, SEO, Security Grade, vulnerability counts, and web security configuration findings if available) are mentioned in the analysis`;

        // Generate the refined report
        const result = await model.generateContent(prompt);
        const response = await result.response;
        const refinedReport = response.text();

        console.log(`✅ Successfully generated report using ${keyLabel} key`);
        return refinedReport;

      } catch (error) {
        lastError = error;
        console.error(`❌ ${keyLabel} key failed:`, error.message);

        // Check if it's a rate limit or overload error
        const isRateLimitError = error.message?.includes('overloaded') ||
          error.message?.includes('503') ||
          error.message?.includes('quota') ||
          error.message?.includes('rate limit');

        const isAuthError = error.message?.includes('API key') ||
          error.message?.includes('401') ||
          error.message?.includes('403');

        if (isAuthError) {
          console.warn(`⚠️  ${keyLabel} key has authentication issues, skipping to next key...`);
        } else if (isRateLimitError) {
          console.warn(`⚠️  ${keyLabel} key is rate limited or overloaded, trying next key...`);
        } else {
          console.warn(`⚠️  ${keyLabel} key encountered error, trying next key...`);
        }

        // If this is the last key, throw the error
        if (i === apiKeys.length - 1) {
          console.error('❌ All Gemini API keys failed');
          break;
        }

        // Wait a bit before trying the next key (500ms)
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }

    // All keys failed this round - check if it's a network error worth retrying
    const isNetworkError = lastError?.message?.includes('fetch failed') ||
      lastError?.message?.includes('ECONNREFUSED') ||
      lastError?.message?.includes('ETIMEDOUT') ||
      lastError?.message?.includes('ENOTFOUND') ||
      lastError?.message?.includes('network');
    const isAuthError = lastError?.message?.includes('API key') ||
      lastError?.message?.includes('401') || lastError?.message?.includes('403');

    if (isNetworkError && !isAuthError && networkRetry < MAX_NETWORK_RETRIES - 1) {
      console.warn(`⚠️ All keys failed with network error, will retry...`);
      continue; // retry the outer loop
    }

    break; // non-network error or last retry, stop
  } // end of networkRetry loop

  // All API keys and retries failed, throw the last error
  console.error('💥 All Gemini API keys exhausted');

  if (lastError?.message?.includes('API key') || lastError?.message?.includes('401') || lastError?.message?.includes('403')) {
    throw new Error('Gemini API authentication failed for all configured keys. Please check your API keys.');
  } else if (lastError?.message?.includes('overloaded') || lastError?.message?.includes('503')) {
    throw new Error('All Gemini API keys are currently overloaded or rate limited. Please try again later or add more API keys.');
  } else {
    throw new Error(`Gemini service error: ${lastError?.message || 'Unknown error'}`);
  }
}

/**
 * Format a markdown report into clean plain text for PDF generation
 * @param {string} markdownReport - The markdown-formatted report
 * @returns {Promise<string>} - Clean plain text formatted for PDF
 */
async function formatReportForPdf(markdownReport) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    // Fallback: basic markdown stripping if no API keys
    return stripMarkdownBasic(markdownReport);
  }

  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`📄 Formatting report for PDF using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      const prompt = `Convert the following markdown report into clean, professionally formatted plain text suitable for a PDF document.

RULES:
1. Remove all markdown syntax (# headers, ** bold, - bullets, etc.)
2. Convert headers into UPPERCASE section titles followed by a blank line
3. Convert bullet points into properly indented paragraphs with ">" prefix
4. Keep the content readable and well-structured
5. Do NOT use any emojis or special Unicode characters
6. Use only standard ASCII characters
7. Preserve all important information
8. Add appropriate spacing between sections

MARKDOWN REPORT:
${markdownReport}

OUTPUT (clean plain text only):`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      const formattedText = response.text().trim();

      console.log(`✅ Successfully formatted report for PDF using ${keyLabel} key`);
      return formattedText;

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for PDF formatting:`, error.message);

      if (i === apiKeys.length - 1) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  // Fallback to basic stripping if all keys fail
  console.warn('⚠️ All Gemini keys failed, using basic markdown stripping');
  return stripMarkdownBasic(markdownReport);
}

/**
 * Basic markdown stripping fallback
 * @param {string} text - Markdown text
 * @returns {string} - Plain text
 */
function stripMarkdownBasic(text) {
  return text
    // Remove headers
    .replace(/^#{1,6}\s+/gm, '')
    // Remove bold/italic
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/_([^_]+)_/g, '$1')
    // Convert bullets to indented text
    .replace(/^[-*]\s+/gm, '  > ')
    // Remove code blocks
    .replace(/```[\s\S]*?```/g, '')
    .replace(/`([^`]+)`/g, '$1')
    // Clean up extra whitespace
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Format scan data into structured bilingual JSON for PDF
 * @param {Object} scanResult - The complete scan result
 * @param {Object} [options]
 * @param {Array<Object>} [options.scanHistoryRows] - Scan history rows (pre-formatted dates/user display); each item:
 *   { dateEn, dateJa, executedByEn, executedByJa, status }
 * @returns {Promise<Object>} - Structured bilingual data
 */
async function formatScanDataForPdf(scanResult, options = {}) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured');
  }

  // Extract all scan data
  // Derive overall risk from ZAP findings and urlscan verdict
  const zapHighCount = scanResult.zapResult?.riskCounts?.High || 0;
  const zapMediumCount = scanResult.zapResult?.riskCounts?.Medium || 0;
  const urlscanMalicious = scanResult.urlscanResult?.verdicts?.overall?.malicious || false;
  const overallRisk = (zapHighCount > 0 || urlscanMalicious) ? 'High' : zapMediumCount > 0 ? 'Medium' : 'Low';

  const categories = scanResult.pagespeedResult?.lighthouseResult?.categories || {};
  const performanceScore = Math.round((categories.performance?.score || 0) * 100);
  const accessibilityScore = Math.round((categories.accessibility?.score || 0) * 100);
  const bestPracticesScore = Math.round((categories['best-practices']?.score || 0) * 100);
  const seoScore = Math.round((categories.seo?.score || 0) * 100);

  const obs = scanResult.observatoryResult || {};
  const zap = scanResult.zapResult || {};
  const urlscan = scanResult.urlscanResult || {};
  const webCheck = scanResult.webCheckResult?.fullResults || {};

  const scanHistoryRows = Array.isArray(options.scanHistoryRows) ? options.scanHistoryRows : [];

  const scanDataText = `
Target URL: ${scanResult.target}
Scan ID: ${scanResult.analysisId}
Status: ${scanResult.status}
Overall Risk Level: ${overallRisk}

PAGESPEED INSIGHTS:
- Performance Score: ${performanceScore}/100
- Accessibility Score: ${accessibilityScore}/100
- Best Practices Score: ${bestPracticesScore}/100
- SEO Score: ${seoScore}/100

MOZILLA OBSERVATORY:
- Security Grade: ${obs.grade || 'N/A'}
- Score: ${obs.score || 0}/100
- Tests Passed: ${obs.tests_passed || 0}
- Tests Failed: ${obs.tests_failed || 0}

OWASP ZAP VULNERABILITY SCAN:
- Status: ${zap.status || 'N/A'}
- Total Alerts: ${zap.totalAlerts || 0}
- High Risk: ${zap.riskCounts?.High || 0}
- Medium Risk: ${zap.riskCounts?.Medium || 0}
- Low Risk: ${zap.riskCounts?.Low || 0}
- Informational: ${zap.riskCounts?.Informational || 0}
${zap.alerts ? `- Top Vulnerabilities: ${zap.alerts.slice(0, 5).map(a => `[${a.risk}] ${a.alert}`).join('; ')}` : ''}

URLSCAN.IO ANALYSIS:
- Verdict: ${urlscan.verdicts?.overall?.malicious ? 'MALICIOUS' : 'Clean'}
- Threat Score: ${urlscan.verdicts?.overall?.score || 0}/100
- Domain: ${urlscan.page?.domain || 'N/A'}
- Server IP: ${urlscan.page?.ip || 'N/A'}
- Country: ${urlscan.page?.country || 'N/A'}
- Server: ${urlscan.page?.server || 'N/A'}

WEBCHECK ANALYSIS:
- TLS Grade: ${webCheck.tls?.tlsInfo?.grade || webCheck.ssl?.grade || 'N/A'}
- WAF Detected: ${webCheck.firewall?.hasWaf ? `Yes (${webCheck.firewall.waf})` : 'No'}
- HSTS Enabled: ${webCheck.hsts?.enabled ? 'Yes' : 'No'}
- Technologies: ${webCheck['tech-stack']?.technologies?.slice(0, 5).map(t => t.name || t).join(', ') || 'N/A'}
`;

  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`📊 Formatting scan data for PDF using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      const prompt = `Convert this security scan data into a structured JSON format for a professional bilingual PDF report (English and Japanese).

SCAN DATA:
${scanDataText}

    SCAN HISTORY INPUT (JSON array):
    ${JSON.stringify(scanHistoryRows, null, 2)}

Return a JSON object with this EXACT structure:
{
  "header": {
    "title": { "en": "Security Scan Report", "ja": "Japanese translation" },
    "target": "${scanResult.target}",
    "scanId": "${scanResult.analysisId}",
    "date": "${new Date().toLocaleDateString()}",
    "status": { "en": "${scanResult.status}", "ja": "Japanese translation" }
  },
  "scanHistory": {
    "title": { "en": "Scan History", "ja": "Japanese translation" },
    "headers": {
      "en": ["Date", "Executed by", "Status"],
      "ja": ["日付", "実行ユーザー", "ステータス"]
    },
    "rows": {
      "en": [["DD/MM/YYYY", "user@example.com", "Completed"]],
      "ja": [["YYYY/MM/DD", "user@example.com", "診断終了"]]
    }
  },
  "summary": {
    "title": { "en": "Executive Summary", "ja": "Japanese translation" },
    "riskLevel": { "en": "${overallRisk}", "ja": "Japanese translation" },
    "riskLabel": { "en": "Overall Risk Level", "ja": "Japanese translation" }
  },
  "sections": [
    {
      "id": "pagespeed",
      "title": { "en": "Performance & Accessibility Analysis", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Performance", "ja": "Japanese" }, "value": "${performanceScore}/100", "type": "score" },
        { "label": { "en": "Accessibility", "ja": "Japanese" }, "value": "${accessibilityScore}/100", "type": "score" },
        { "label": { "en": "Best Practices", "ja": "Japanese" }, "value": "${bestPracticesScore}/100", "type": "score" },
        { "label": { "en": "SEO", "ja": "Japanese" }, "value": "${seoScore}/100", "type": "score" }
      ]
    },
    {
      "id": "observatory",
      "title": { "en": "Security Configuration Assessment", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Security Grade", "ja": "Japanese" }, "value": "${obs.grade || 'N/A'}", "type": "grade" },
        { "label": { "en": "Score", "ja": "Japanese" }, "value": "${obs.score || 0}/100", "type": "score" },
        { "label": { "en": "Tests Passed", "ja": "Japanese" }, "value": "${obs.tests_passed || 0}", "type": "success" },
        { "label": { "en": "Tests Failed", "ja": "Japanese" }, "value": "${obs.tests_failed || 0}", "type": "danger" }
      ]
    },
    {
      "id": "zap",
      "title": { "en": "Vulnerability Scan Results", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Total Alerts", "ja": "Japanese" }, "value": "${zap.totalAlerts || 0}", "type": "stat" },
        { "label": { "en": "High Risk", "ja": "Japanese" }, "value": "${zap.riskCounts?.High || 0}", "type": "danger" },
        { "label": { "en": "Medium Risk", "ja": "Japanese" }, "value": "${zap.riskCounts?.Medium || 0}", "type": "warning" },
        { "label": { "en": "Low Risk", "ja": "Japanese" }, "value": "${zap.riskCounts?.Low || 0}", "type": "info" },
        { "label": { "en": "Informational", "ja": "Japanese" }, "value": "${zap.riskCounts?.Informational || 0}", "type": "stat" }
      ],
      "alerts": ${JSON.stringify((zap.alerts || []).slice(0, 7).map(a => ({ risk: a.risk, alert: a.alert })))},
      "detailedAlerts": ${JSON.stringify((zap.alerts || []).map(a => ({
        name: a.alert,
        risk: a.risk,
        confidence: a.confidence,
        description: a.description || 'No description available',
        solution: a.solution || 'No solution provided',
        reference: a.reference || '',
        cweid: a.cweid,
        wascid: a.wascid,
        totalOccurrences: a.totalOccurrences || 0
      })))}
    },
    {
      "id": "urlscan",
      "title": { "en": "Threat & Reputation Analysis", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "Verdict", "ja": "Japanese" }, "value": { "en": "${urlscan.verdicts?.overall?.malicious ? 'MALICIOUS' : 'Clean'}", "ja": "Japanese" }, "type": "${urlscan.verdicts?.overall?.malicious ? 'danger' : 'success'}" },
        { "label": { "en": "Threat Score", "ja": "Japanese" }, "value": "${urlscan.verdicts?.overall?.score || 0}/100", "type": "score" },
        { "label": { "en": "Domain", "ja": "Japanese" }, "value": "${urlscan.page?.domain || 'N/A'}", "type": "stat" },
        { "label": { "en": "Server IP", "ja": "Japanese" }, "value": "${urlscan.page?.ip || 'N/A'}", "type": "stat" },
        { "label": { "en": "Country", "ja": "Japanese" }, "value": "${urlscan.page?.country || 'N/A'}", "type": "stat" },
        { "label": { "en": "Server", "ja": "Japanese" }, "value": "${urlscan.page?.server || 'N/A'}", "type": "stat" }
      ]
    },
    {
      "id": "webcheck",
      "title": { "en": "Web Security Configuration", "ja": "Japanese translation" },
      "items": [
        { "label": { "en": "TLS Grade", "ja": "Japanese" }, "value": "${webCheck.tls?.tlsInfo?.grade || webCheck.ssl?.grade || 'N/A'}", "type": "grade" },
        { "label": { "en": "WAF Detected", "ja": "Japanese" }, "value": { "en": "${webCheck.firewall?.hasWaf ? 'Yes' : 'No'}", "ja": "Japanese" }, "type": "${webCheck.firewall?.hasWaf ? 'success' : 'warning'}" },
        { "label": { "en": "HSTS Enabled", "ja": "Japanese" }, "value": { "en": "${webCheck.hsts?.enabled ? 'Yes' : 'No'}", "ja": "Japanese" }, "type": "${webCheck.hsts?.enabled ? 'success' : 'warning'}" },
        { "label": { "en": "Technologies", "ja": "Japanese" }, "value": "${webCheck['tech-stack']?.technologies?.slice(0, 5).map(t => t.name || t).join(', ') || 'N/A'}", "type": "stat" }
      ]
    }
  ]
}

IMPORTANT RULES:
1. Return ONLY valid JSON, no markdown or extra text
2. Translate ALL "ja" fields to proper Japanese
3. Keep technical terms (like URLs, IPs, scores) unchanged
4. Ensure professional translations suitable for a business report
5. The "scanHistory" section MUST be generated from SCAN HISTORY INPUT:
  - Use the SAME number of rows and SAME row order as input
  - For English rows, use input.dateEn and input.executedByEn EXACTLY (do not change date formats)
  - For Japanese rows, use input.dateJa and input.executedByJa EXACTLY (do not change date formats)
  - Convert the input "status" into a user-friendly label in each language (e.g., completed -> Completed/診断終了, pending/queued/combining -> Scanning/スキャン中, failed -> Failed/失敗, cancelled/stopped -> Cancelled/停止)
  - Do NOT invent rows that are not in the input
`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      let jsonText = response.text().trim();

      // Clean up JSON
      jsonText = jsonText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      const parsed = JSON.parse(jsonText);

      // Manually add detailedAlerts to ZAP section (Gemini might not return it)
      // This ensures we always have the vulnerability details for the PDF
      const zapSection = parsed.sections?.find(s => s.id === 'zap');
      if (zapSection && zap.alerts && zap.alerts.length > 0) {
        zapSection.detailedAlerts = zap.alerts.map(a => ({
          name: a.alert,
          risk: a.risk,
          confidence: a.confidence,
          description: a.description || 'No description available',
          solution: a.solution || 'No solution provided',
          reference: a.reference || '',
          cweid: a.cweid,
          wascid: a.wascid,
          totalOccurrences: a.totalOccurrences || 0
        }));
        console.log(`📊 Added ${zapSection.detailedAlerts.length} detailed alerts to ZAP section`);
      }

      console.log(`✅ Successfully formatted scan data using ${keyLabel} key`);
      return parsed;

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for scan data formatting:`, error.message);

      if (i === apiKeys.length - 1) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  throw new Error(`Scan data formatting failed: ${lastError?.message}`);
}

/**
 * Format scan history into structured bilingual JSON for PDF.
 * Used when scanData formatting fails to include scanHistory.
 * @param {Array<Object>} scanHistoryRows - Each item: { dateEn, dateJa, executedByEn, executedByJa, status }
 * @returns {Promise<Object>} - { title, headers, rows } bilingual
 */
async function formatScanHistoryForPdf(scanHistoryRows) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured');
  }

  const rows = Array.isArray(scanHistoryRows) ? scanHistoryRows : [];

  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`📋 Formatting scan history for PDF using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      const prompt = `Generate the Scan History table content for a professional bilingual PDF report (English and Japanese).

INPUT (JSON array):
${JSON.stringify(rows, null, 2)}

Return ONLY valid JSON with this EXACT structure:
{
  "title": { "en": "Scan History", "ja": "Japanese translation" },
  "headers": {
    "en": ["Date", "Executed by", "Status"],
    "ja": ["日付", "実行ユーザー", "ステータス"]
  },
  "rows": {
    "en": [["DD/MM/YYYY", "user@example.com", "Completed"]],
    "ja": [["YYYY/MM/DD", "user@example.com", "診断終了"]]
  }
}

CRITICAL RULES:
1. Use the SAME number of rows and SAME order as the input array.
2. For English rows, use input.dateEn and input.executedByEn EXACTLY (do not change date formats).
3. For Japanese rows, use input.dateJa and input.executedByJa EXACTLY (do not change date formats).
4. Convert input.status into a user-friendly label in each language:
   - completed -> Completed / 診断終了
   - pending/queued/combining -> Scanning / スキャン中
   - failed -> Failed / 失敗
   - cancelled/stopped -> Cancelled / 停止
5. Do NOT add any text outside of the JSON.`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      let jsonText = response.text().trim();

      jsonText = jsonText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      const parsed = JSON.parse(jsonText);

      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Invalid scanHistory response - not an object');
      }
      if (!parsed.title || !parsed.headers || !parsed.rows) {
        throw new Error('Invalid scanHistory response - missing title/headers/rows');
      }

      console.log(`✅ Successfully formatted scan history using ${keyLabel} key`);
      return parsed;

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for scan history formatting:`, error.message);
      if (i === apiKeys.length - 1) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  throw new Error(`Scan history formatting failed: ${lastError?.message}`);
}

/**
 * Validate and clean content blocks within a section
 * MINIMAL validation - only remove truly invalid content (empty/null)
 * DO NOT filter based on capitalization or text patterns
 * @param {Array} content - Array of content blocks
 * @returns {Array} - Cleaned content blocks
 */
function validateContentBlocks(content) {
  if (!Array.isArray(content)) return [];

  const validContent = [];

  for (const block of content) {
    if (!block || typeof block !== 'object') continue;

    // Validate paragraph blocks
    if (block.type === 'paragraph') {
      // Only skip if truly empty
      if (!block.text || typeof block.text !== 'string' || block.text.trim().length === 0) {
        console.warn('⚠️  Skipping empty paragraph block');
        continue;
      }

      // Keep ALL non-empty paragraphs - Gemini should generate them correctly
      validContent.push(block);
    }
    // Validate bullet blocks
    else if (block.type === 'bullets') {
      if (!Array.isArray(block.items) || block.items.length === 0) {
        console.warn('⚠️  Skipping empty bullets block');
        continue;
      }

      // Only filter out truly empty items
      const validItems = block.items.filter(item => {
        return item && typeof item === 'string' && item.trim().length > 0;
      });

      if (validItems.length > 0) {
        validContent.push({
          ...block,
          items: validItems
        });
      } else {
        console.warn('⚠️  Skipping bullets block with no valid items');
      }
    }
    // Validate bold_text blocks
    else if (block.type === 'bold_text') {
      if (!block.label || !block.text) {
        console.warn('⚠️  Skipping invalid bold_text block');
        continue;
      }
      validContent.push(block);
    }
    // Unknown type - keep it anyway
    else {
      validContent.push(block);
    }
  }

  return validContent;
}

/**
 * Clean duplicate sections and overlapping content from parsed JSON
 * @param {Object} parsed - The parsed JSON from Gemini
 * @returns {Object} - Cleaned JSON structure
 */
function cleanDuplicateSections(parsed) {
  if (!parsed || !parsed.sections || !Array.isArray(parsed.sections)) {
    return parsed;
  }

  const seenHeadings = new Set();
  const uniqueSections = [];

  for (const section of parsed.sections) {
    // Must have heading
    if (!section.heading || typeof section.heading !== 'string' || section.heading.trim().length === 0) {
      console.warn('⚠️  Skipping section with no heading');
      continue;
    }

    // Check for duplicate headings (case-insensitive)
    const headingLower = section.heading.toLowerCase().trim();
    if (seenHeadings.has(headingLower)) {
      console.warn(`⚠️  Duplicate section detected and removed: "${section.heading}"`);
      continue; // Skip duplicate
    }

    // Must have valid type
    if (!section.type || !['paragraph', 'bullets', 'mixed'].includes(section.type)) {
      console.warn(`⚠️  Skipping section with invalid type: "${section.heading}"`);
      continue;
    }

    // Must have content array
    if (!Array.isArray(section.content) || section.content.length === 0) {
      console.warn(`⚠️  Skipping section with no content: "${section.heading}"`);
      continue;
    }

    // Validate and clean content blocks
    const validatedContent = validateContentBlocks(section.content);

    if (validatedContent.length === 0) {
      console.warn(`⚠️  Skipping section with no valid content: "${section.heading}"`);
      continue;
    }

    // Add cleaned section
    seenHeadings.add(headingLower);
    uniqueSections.push({
      ...section,
      content: validatedContent
    });
  }

  console.log(`🧹 Cleaned sections: ${parsed.sections.length} → ${uniqueSections.length}`);

  return {
    ...parsed,
    sections: uniqueSections
  };
}

/**
 * Format AI analysis into structured JSON for PDF
 * @param {string} markdownReport - The markdown AI report
 * @returns {Promise<Object>} - Structured analysis data
 */
async function formatAiAnalysisForPdf(markdownReport) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured');
  }

  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`📝 Formatting AI analysis for PDF using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      const prompt = `Convert this security analysis report into a structured JSON format for a professional PDF document.

REPORT:
${markdownReport}

Return a JSON object with this EXACT structure:
{
  "title": "AI-Generated Security Analysis",
  "sections": [
    {
      "heading": "Section Title (e.g., Executive Summary)",
      "type": "paragraph|bullets|mixed",
      "content": [
        { "type": "paragraph", "text": "Paragraph text here..." },
        { "type": "bullets", "items": ["Bullet point 1", "Bullet point 2"] },
        { "type": "bold_text", "label": "Risk Level:", "text": "HIGH" }
      ]
    }
  ]
}

CRITICAL RULES - MUST FOLLOW STRICTLY:

**JSON FORMAT:**
1. Return ONLY valid JSON - absolutely NO text before or after the JSON
2. No markdown code blocks (no \`\`\`json) - just raw JSON

**NO DUPLICATES OR OVERLAPS:**
3. Each section heading must appear EXACTLY ONCE - NO DUPLICATES WHATSOEVER
4. NEVER repeat the same content in multiple sections
5. NEVER overlap or mix content between sections
6. Complete one entire section before starting the next
7. Do NOT include an "Executive Summary" section - it is rendered separately in the PDF

**COMPLETE CONTENT BLOCKS - CRITICAL:**
7. Every paragraph MUST be a complete thought with full sentences
8. NEVER break paragraphs mid-sentence or mid-word
9. Every bullet point must be a complete statement
10. NO truncated text ending with "..." unless it's an intentional ellipsis
11. ALL paragraphs must be self-contained and readable on their own

**PROPER STRUCTURE:**
12. Use "paragraph" type for flowing text (2-3 complete sentences per paragraph, split longer ones into separate blocks)
13. Use "bullets" type for lists (3-8 complete items per bullet block)
14. Use "bold_text" type ONLY for key-value metrics - MUST have BOTH "label" AND "text" fields:
    - CORRECT: { "type": "bold_text", "label": "Risk Level:", "text": "HIGH" }
    - WRONG: { "type": "bold_text" } or { "type": "bold_text", "label": "Risk:" }
15. Each section must have at least one complete content block
16. NEVER create bold_text blocks without both label and text properties

**FORMATTING:**
17. NO emojis or special unicode characters
18. Professional business language only
19. Clear section boundaries - do not mix sections
20. Logical flow from one section to the next
21. ALL text must be complete - no mid-sentence cutoffs

**VALIDATION:**
22. Double-check for duplicate headings before returning
23. Verify EVERY paragraph ends with proper punctuation (. ! ?)
24. Ensure no text overlaps between sections
25. Confirm ALL content blocks are complete and readable

EXAMPLE OF COMPLETE VS INCOMPLETE:
✅ CORRECT: "The website uses Cloudflare for content delivery, security (WAF), and TLS/SSL management."
❌ WRONG: "The website uses Cloudflare for content delivery, security (WAF), and"`;





      const result = await model.generateContent(prompt);
      const response = await result.response;
      let jsonText = response.text().trim();

      jsonText = jsonText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      const parsed = JSON.parse(jsonText);

      // Clean and validate the structure
      const cleaned = cleanDuplicateSections(parsed);

      console.log(`✅ Successfully formatted AI analysis using ${keyLabel} key`);
      return cleaned;

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for AI analysis formatting:`, error.message);

      if (i === apiKeys.length - 1) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  throw new Error(`AI analysis formatting failed: ${lastError?.message}`);
}

/**
 * Translate formatted AI analysis to Japanese
 * @param {Object} formattedAnalysis - The structured English analysis
 * @returns {Promise<Object>} - Same structure in Japanese
 */
async function translateAiAnalysisToJapanese(formattedAnalysis) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured');
  }

  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`🌐 Translating AI analysis to Japanese using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      const prompt = `Translate this security analysis JSON from English to Japanese. Keep the exact same structure, only translate the text content.

INPUT JSON:
${JSON.stringify(formattedAnalysis, null, 2)}

CRITICAL RULES - MUST FOLLOW STRICTLY:

**JSON FORMAT:**
1. Return ONLY valid JSON - absolutely NO text before or after
2. No markdown code blocks (no \`\`\`json) - just raw JSON
3. Preserve the EXACT same structure as the input

**TRANSLATION RULES:**
4. Translate ALL text content to Japanese (headings, paragraphs, bullets)
5. Keep technical terms unchanged: URLs, IPs, version numbers, HTTP headers
6. The "title" should be: "AIによるセキュリティ分析"
7. Maintain professional business Japanese (です/ます form)
8. Use proper Japanese punctuation (。、 instead of .,)

**NO DUPLICATES OR OVERLAPS:**
9. Do NOT duplicate any sections - each heading appears EXACTLY ONCE
10. Do NOT add new sections not in the input
11. Preserve the exact number of sections from input (no more, no less)
12. NEVER overlap or mix content between sections

**COMPLETE CONTENT BLOCKS - CRITICAL:**
13. Every translated paragraph MUST be COMPLETE with full sentences
14. NEVER break paragraphs mid-sentence or mid-word
15. Every bullet point must be a complete statement
16. NO truncated text ending with "..." unless intentional ellipsis
17. ALL translated paragraphs must be self-contained and readable
18. Preserve complete sentence structure from English source

**VALIDATION:**
19. Double-check for duplicate headings before returning
20. Verify EVERY paragraph ends with proper Japanese punctuation (。！？)
21. Ensure no text overlaps between sections
22. Count sections: output must match input exactly (same number of sections)
23. Confirm ALL translated content is complete and readable

EXAMPLE OF COMPLETE VS INCOMPLETE TRANSLATION:
✅ CORRECT: "このサイトは、コンテンツ配信、セキュリティ（WAF）、およびTLS/SSL管理にCloudflareを利用しています。"
❌ WRONG: "このサイトは、コンテンツ配信、セキュリティ（WAF）、および"

OUTPUT (Japanese JSON only):`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      let jsonText = response.text().trim();

      jsonText = jsonText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      const parsed = JSON.parse(jsonText);

      // Clean and validate the Japanese structure too
      const cleaned = cleanDuplicateSections(parsed);

      console.log(`✅ Successfully translated AI analysis to Japanese using ${keyLabel} key`);
      return cleaned;

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for Japanese translation:`, error.message);

      if (i === apiKeys.length - 1) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  throw new Error(`Japanese translation failed: ${lastError?.message}`);
}

/**
 * Translate both AI analysis AND vulnerability details to Japanese in a SINGLE API call
 * This reduces API costs by combining two translations into one
 * @param {Object} formattedAnalysis - The formatted AI analysis object
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {Promise<Object>} - Object with { aiAnalysis, vulnerabilities }
 */
async function translateToJapanese(formattedAnalysis, vulnerabilities) {
  const apiKeys = getApiKeys();
  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured');
  }

  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`🌐 Translating AI analysis + vulnerabilities to Japanese using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      const prompt = `You are translating a security report from English to Japanese. You need to translate TWO things in a SINGLE response:

1. AI Security Analysis (JSON object)
2. Vulnerability Details (JSON array)

Return a JSON object with this structure:
{
  "aiAnalysis": { ...translated AI analysis... },
  "vulnerabilities": [ ...translated vulnerabilities array... ]
}

INPUT AI ANALYSIS:
${JSON.stringify(formattedAnalysis, null, 2)}

INPUT VULNERABILITIES:
${JSON.stringify(vulnerabilities, null, 2)}

CRITICAL RULES - MUST FOLLOW STRICTLY:

**JSON FORMAT:**
1. Return ONLY valid JSON object with "aiAnalysis" and "vulnerabilities" keys
2. No markdown code blocks (no \`\`\`json) - just raw JSON
3. Preserve the EXACT same structure for both inputs

**TRANSLATION RULES FOR AI ANALYSIS:**
4. Translate ALL text content to Japanese (headings, paragraphs, bullets)
5. The "title" should be: "AIによるセキュリティ分析"
6. Maintain professional business Japanese (です/ます form)
7. Use proper Japanese punctuation (。、 instead of .,)
8. Keep technical terms unchanged: URLs, IPs, version numbers, HTTP headers
9. Do NOT duplicate sections - each heading appears EXACTLY ONCE
10. Every paragraph MUST be COMPLETE with full sentences - NO truncation

**TRANSLATION RULES FOR VULNERABILITIES:**
11. Translate "description" and "solution" fields to professional Japanese
12. Keep "name", "risk", "confidence", "reference", "cweid", "wascid", "totalOccurrences" fields unchanged
13. Maintain technical accuracy - do NOT change technical terms like HTTP headers, URLs, code snippets
14. Preserve complete sentence structure - NO fragmented translations

**VALIDATION:**
15. Verify EVERY paragraph ends with proper Japanese punctuation (。！？)
16. Ensure ALL translated content is complete and readable
17. Double-check JSON structure is valid

EXAMPLE OF COMPLETE VS INCOMPLETE TRANSLATION:
✅ CORRECT: "このサイトは、コンテンツ配信、セキュリティ（WAF）、およびTLS/SSL管理にCloudflareを利用しています。"
❌ WRONG: "このサイトは、コンテンツ配信、セキュリティ（WAF）、および"

OUTPUT (Japanese JSON object only):`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      let jsonText = response.text().trim();

      jsonText = jsonText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      const parsed = JSON.parse(jsonText);

      if (!parsed.aiAnalysis || !parsed.vulnerabilities) {
        throw new Error('Invalid response structure - missing aiAnalysis or vulnerabilities');
      }

      // Clean and validate the Japanese AI analysis
      const cleanedAiAnalysis = cleanDuplicateSections(parsed.aiAnalysis);

      console.log(`✅ Successfully translated AI analysis + ${parsed.vulnerabilities.length} vulnerabilities to Japanese using ${keyLabel} key`);
      return {
        aiAnalysis: cleanedAiAnalysis,
        vulnerabilities: parsed.vulnerabilities
      };

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for Japanese translation:`, error.message);

      if (i === apiKeys.length - 1) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  throw new Error(`Japanese translation failed: ${lastError?.message}`);
}

module.exports = {
  refineReport,
  translateText,
  formatReportForPdf,
  formatScanDataForPdf,
  formatScanHistoryForPdf,
  formatAiAnalysisForPdf,
  translateAiAnalysisToJapanese,  // Keep for backwards compatibility
  translateToJapanese  // NEW: Combined translation function
};

/**
 * Translate an array of texts using Gemini AI
 * Uses JSON format for reliable 1:1 text mapping
 * @param {string[]} texts - Array of texts to translate
 * @param {string} targetLang - Target language ('en' for English, 'ja' for Japanese)
 * @returns {Promise<string[]>} - Array of translated texts
 */
async function translateText(texts, targetLang) {
  const apiKeys = getApiKeys();

  if (apiKeys.length === 0) {
    throw new Error('No Gemini API keys configured. Please set GEMINI_API_KEY in environment variables.');
  }

  if (!texts || texts.length === 0) {
    return [];
  }

  const langName = targetLang === 'ja' ? 'Japanese' : 'English';
  const sourceLang = targetLang === 'ja' ? 'English' : 'Japanese';

  let lastError = null;

  // Try each API key until one succeeds
  for (let i = 0; i < apiKeys.length; i++) {
    const apiKey = apiKeys[i];
    const keyLabel = i === 0 ? 'primary' : `fallback #${i}`;

    try {
      console.log(`🌐 Translating ${texts.length} texts to ${langName} using ${keyLabel} key...`);

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

      // Build input as JSON object with numeric keys
      const inputObj = {};
      texts.forEach((text, idx) => {
        inputObj[idx] = text;
      });

      const prompt = `Translate the following texts from ${sourceLang} to ${langName}.

INPUT (JSON object with numeric keys):
${JSON.stringify(inputObj, null, 2)}

CRITICAL RULES:
1. Return ONLY a valid JSON object
2. Use the SAME numeric keys as the input
3. Each value should be the translation of the corresponding input value
4. Preserve emojis and special characters
5. Do NOT add any text before or after the JSON

OUTPUT (JSON object only):`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      let translatedText = response.text().trim();

      // Clean up response - remove markdown code blocks if present
      translatedText = translatedText
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '')
        .trim();

      // Parse JSON response
      let translatedObj;
      try {
        translatedObj = JSON.parse(translatedText);
      } catch (parseError) {
        console.error('❌ Failed to parse Gemini JSON response:', translatedText.substring(0, 200));
        throw new Error('Invalid JSON response from Gemini');
      }

      // Build result array in correct order
      const translations = [];
      for (let j = 0; j < texts.length; j++) {
        if (translatedObj[j] !== undefined) {
          translations.push(String(translatedObj[j]));
        } else if (translatedObj[String(j)] !== undefined) {
          translations.push(String(translatedObj[String(j)]));
        } else {
          // Fallback to original if translation missing
          console.warn(`⚠️ Missing translation for index ${j}, using original`);
          translations.push(texts[j]);
        }
      }

      console.log(`✅ Successfully translated ${translations.length} texts using ${keyLabel} key`);
      return translations;

    } catch (error) {
      lastError = error;
      console.error(`❌ ${keyLabel} key failed for translation:`, error.message);

      if (i === apiKeys.length - 1) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  console.error('💥 All Gemini API keys exhausted for translation');
  throw new Error(`Translation failed: ${lastError?.message || 'Unknown error'}`);
}

