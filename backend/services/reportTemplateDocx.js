const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');
const { DOMParser } = require('@xmldom/xmldom');

const { translateText } = require('./geminiService');

const TEMPLATE_DIR = path.resolve(__dirname, '../../frontend/public/report-template');
const TEMPLATE_DOCX_PATH_NEW = path.join(TEMPLATE_DIR, 'New Report Template.docx');
const TEMPLATE_DOCX_PATH_LEGACY = path.resolve(__dirname, '../../frontend/public/report-template.docx');
const BACKEND_ASSETS_DIR = path.resolve(__dirname, '../assets');
const TEMPLATE_DOCX_PATH_BACKEND = path.join(BACKEND_ASSETS_DIR, 'Report Template.docx');

const cachedPromiseByLang = new Map();
let cachedJaPromise = null;

function resolveTemplateDocxPath() {
  if (fs.existsSync(TEMPLATE_DOCX_PATH_NEW)) return TEMPLATE_DOCX_PATH_NEW;
  if (fs.existsSync(TEMPLATE_DOCX_PATH_BACKEND)) return TEMPLATE_DOCX_PATH_BACKEND;
  if (fs.existsSync(TEMPLATE_DOCX_PATH_LEGACY)) return TEMPLATE_DOCX_PATH_LEGACY;
  return null;
}

function splitParagraphs(text) {
  return String(text || '')
    .replace(/\r\n/g, '\n')
    .split(/\n\n+/)
    .map(s => s.trim())
    .filter(Boolean);
}

function joinParagraphs(paras) {
  return (paras || []).filter(Boolean).join('\n\n');
}

function safeDefaultEnglishHeaders(count) {
  if (count === 3) return ['Scan Date', 'Scanner', 'Result'];
  if (count === 4) return ['Scan Date', 'Scanner', 'Method', 'Result'];
  return Array.from({ length: Math.max(1, count || 1) }, (_, i) => `Column ${i + 1}`);
}

function isGeminiKeyExhaustedError(err) {
  const msg = String(err?.message || '').toLowerCase();
  return (
    msg.includes('no gemini api keys configured') ||
    msg.includes('resource_exhausted') ||
    msg.includes('quota') ||
    msg.includes('too many requests') ||
    msg.includes('429')
  );
}

function containsJapanese(text) {
  return /[\u3040-\u30ff\u3400-\u9fff]/.test(String(text || ''));
}

// The bundled template's text in English (backend/assets/Report Template.docx).
// The English report used to have Gemini translate it, and any Gemini failure
// aborted the whole English report; a legal disclaimer should also read the same
// in every report. Only text not listed here (a changed template) goes to Gemini.
const TEMPLATE_ENGLISH = new Map([
  ['\u514d\u8cac\u4e8b\u9805', 'Disclaimer'],
  ['\u3053\u306e\u30ec\u30dd\u30fc\u30c8\u3067\u5171\u6709\u3055\u308c\u308b\u60c5\u5831\u306f\u6a5f\u5bc6\u60c5\u5831\u3067\u3042\u308a\u3001\u6cd5\u7684\u306b\u7279\u6a29\u3092\u6301\u3064\u5834\u5408\u304c\u3042\u308a\u307e\u3059\u3002\u3053\u308c\u306f\u53d7\u53d6\u4eba\u306e\u307f\u3092\u5bfe\u8c61\u3068\u3057\u3066\u304a\u308a\u3001\u4ed6\u306e\u8ab0\u3067\u3082\u3053\u306e\u30ec\u30dd\u30fc\u30c8\u306b\u30a2\u30af\u30bb\u30b9\u3059\u308b\u3053\u3068\u306f\u8a31\u53ef\u3055\u308c\u3066\u3044\u307e\u305b\u3093\u3002\u304a\u5ba2\u69d8\u304c\u610f\u56f3\u3055\u308c\u305f\u53d7\u9818\u8005\u3067\u306a\u3044\u5834\u5408\u3001\u958b\u793a\u3001\u30b3\u30d4\u30fc\u3001\u8907\u88fd\u3001\u914d\u5e03\u3001\u307e\u305f\u306f\u305d\u308c\u306b\u4f9d\u62e0\u3057\u3066\u53d6\u3089\u308c\u305f\u3001\u307e\u305f\u306f\u53d6\u3089\u308c\u308b\u3053\u3068\u3092\u7701\u7565\u3057\u305f\u884c\u52d5\u306f\u7981\u6b62\u3055\u308c\u3066\u304a\u308a\u3001\u9055\u6cd5\u3068\u306a\u308b\u53ef\u80fd\u6027\u304c\u3042\u308a\u307e\u3059\u3002\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u30c1\u30fc\u30e0\u306f\u3001\u5f53\u793e\u306e\u5408\u7406\u7684\u306a\u5236\u5fa1\u304c\u53ca\u3070\u306a\u3044\u4e8b\u8c61\u304b\u3089\u751f\u3058\u308b\u3044\u304b\u306a\u308b\u640d\u5931\u306b\u95a2\u3057\u3066\u3082\u3001\u304a\u5ba2\u69d8\u306b\u5bfe\u3057\u3066\u8cac\u4efb\u3092\u8ca0\u3044\u307e\u305b\u3093\u3002\u5f53\u793e\u306f\u3001\u5229\u76ca\u3001\u53ce\u5165\u3001\u53ce\u76ca\u3001\u4f7f\u7528\u3001\u751f\u7523\u3001\u4e88\u60f3\u3055\u308c\u308b\u8caf\u84c4\u3001\u4e8b\u696d\u3001\u5951\u7d04\u3001\u5546\u696d\u6a5f\u4f1a\u3001\u307e\u305f\u306f\u55b6\u696d\u6a29\u306e\u640d\u5931\u307e\u305f\u306f\u640d\u5bb3\u3092\u542b\u3080\u304c\u3053\u308c\u3089\u306b\u9650\u5b9a\u3055\u308c\u306a\u3044\u3001\u307e\u305f\u306f\u8ab0\u304b\u306b\u3088\u308b\u3053\u306e\u30ec\u30dd\u30fc\u30c8\u306e\u4f7f\u7528\u307e\u305f\u306f\u8aa4\u7528\u306b\u8d77\u56e0\u3059\u308b\u30d3\u30b8\u30cd\u30b9\u4e0a\u306e\u640d\u5931\u306b\u95a2\u3057\u3066\u3001\u304a\u5ba2\u69d8\u306b\u5bfe\u3057\u3066\u8cac\u4efb\u3092\u8ca0\u3044\u307e\u305b\u3093\u3002\u3053\u306e\u30ec\u30dd\u30fc\u30c8\u3067\u63d0\u4f9b\u3055\u308c\u3066\u3044\u308b\u3059\u3079\u3066\u306e\u63a8\u5968\u4e8b\u9805\u3068\u89e3\u6c7a\u7b56\u306f\u73fe\u72b6\u306e\u307e\u307e\u3067\u3042\u308a\u3001\u660e\u793a\u307e\u305f\u306f\u9ed9\u793a\u306e\u4fdd\u8a3c\u306f\u7121\u52b9\u3068\u306a\u308a\u307e\u3059\u3002',
   'The information shared in this report is confidential and may be legally privileged. It is intended solely for the recipient, and no one else is authorized to access this report. If you are not the intended recipient, any disclosure, copying, reproduction or distribution of this report, or any action taken or omitted in reliance on it, is prohibited and may be unlawful. The security team shall not be liable to you for any loss arising from events beyond our reasonable control. We shall not be liable to you for any loss or damage, including but not limited to loss of profits, income, revenue, use, production, anticipated savings, business, contracts, commercial opportunities or goodwill, or for any business loss arising from the use or misuse of this report by anyone. All recommendations and solutions provided in this report are provided as is, without any warranty, express or implied.'],
  ['\u8a3a\u65ad\u5c65\u6b74', 'Scan History'],
  ['\u65e5\u4ed8', 'Date'],
  ['\u5b9f\u884c\u30e6\u30fc\u30b6\u30fc', 'Executed by'],
  ['\u30b9\u30c6\u30fc\u30bf\u30b9', 'Status'],
  ['\u4f01\u696d\u5411\u3051\u306e\u5305\u62ec\u7684\u306a\u30b5\u30a4\u30d0\u30fc\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u30bd\u30ea\u30e5\u30fc\u30b7\u30e7\u30f3\u3092\u63d0\u4f9b\u3057\u3066\u3044\u307e\u3059\u3002', 'We provide comprehensive cybersecurity solutions for businesses.'],
  ['\u5f53\u793e\u306e\u5c02\u9580\u77e5\u8b58\u3067\u304a\u5ba2\u69d8\u306e\u30c7\u30fc\u30bf\u3068\u30b7\u30b9\u30c6\u30e0\u3092\u4fdd\u8b77\u3057\u307e\u3059\u3002', 'We protect your data and systems with our expertise.'],
  ['\u4fe1\u983c\u3067\u304d\u308b\u30b5\u30fc\u30d3\u30b9\u3067\u30aa\u30f3\u30e9\u30a4\u30f3\u306e\u8105\u5a01\u304b\u3089\u8eab\u3092\u5b88\u308a\u307e\u3057\u3087\u3046\u3002', 'Protect yourself from online threats with a service you can trust.'],
]);

// Used for template text that has no English above and could not be translated.
const FALLBACK_DISCLAIMER_EN = 'This report is generated based on automated scan results. Detected findings may be incomplete or may differ from the actual state due to environmental or configuration differences. We do not guarantee the completeness, accuracy, or timeliness of the content of this report. The provider shall not be liable for any damages (direct or indirect) arising from the use of this report.';

/**
 * The template's static text in English. Never throws: text without a known
 * English version is translated by Gemini, and if that fails (or comes back with
 * Japanese) the slot falls back to built-in English \u2014 a closing-page line is
 * dropped \u2014 rather than failing the report.
 */
async function translateTemplateStaticToEnglish(jaTemplate, deps = {}) {
  const translate = deps.translate || ((texts) => translateText(texts, 'en'));
  const disclaimerParas = splitParagraphs(jaTemplate.disclaimerBody);
  const finalLines = Array.isArray(jaTemplate.finalPageLines) ? jaTemplate.finalPageLines : [];
  const headers = Array.isArray(jaTemplate.diagnosisHeaders) ? jaTemplate.diagnosisHeaders : [];

  const english = new Map();
  const unknown = [];
  for (const text of [jaTemplate.disclaimerTitle, ...disclaimerParas, jaTemplate.diagnosisTitle, ...headers, ...finalLines]) {
    const key = String(text || '').trim();
    if (!key || english.has(key)) continue;
    if (!containsJapanese(key)) english.set(key, key);
    else if (TEMPLATE_ENGLISH.has(key)) english.set(key, TEMPLATE_ENGLISH.get(key));
    else unknown.push(key);
  }
  if (unknown.length) {
    try {
      const out = await translate(unknown);
      unknown.forEach((key, i) => {
        const t = Array.isArray(out) ? out[i] : null;
        if (typeof t === 'string' && t.trim() && !containsJapanese(t)) english.set(key, t.trim());
      });
    } catch (e) {
      const kind = isGeminiKeyExhaustedError(e) ? 'quota' : 'error';
      console.warn(`[reportTemplateDocx] English template translation failed (${kind}: ${e?.message}) \u2014 using built-in English`);
    }
  }
  const en = (text) => english.get(String(text || '').trim()) || null;

  const translatedParas = disclaimerParas.map(en);
  const translatedHeaders = headers.map(en);
  return {
    ...jaTemplate,
    disclaimerTitle: en(jaTemplate.disclaimerTitle) || 'Disclaimer',
    disclaimerBody: translatedParas.every(Boolean) ? joinParagraphs(translatedParas) : FALLBACK_DISCLAIMER_EN,
    diagnosisTitle: en(jaTemplate.diagnosisTitle) || 'Scan History',
    diagnosisHeaders: translatedHeaders.every(Boolean) ? translatedHeaders : safeDefaultEnglishHeaders(headers.length),
    finalPageLines: finalLines.map(en).filter(Boolean)
  };
}

function getLocalName(node) {
  if (!node) return '';
  return node.localName || String(node.nodeName || '').split(':').pop();
}

function collectTextFromNode(node, out) {
  if (!node) return;

  const name = getLocalName(node);

  if (name === 't') {
    out.push(node.textContent || '');
    return;
  }

  if (name === 'tab') {
    out.push('\t');
    return;
  }

  if (name === 'br' || name === 'cr') {
    out.push('\n');
    return;
  }

  if (node.childNodes && node.childNodes.length) {
    for (let i = 0; i < node.childNodes.length; i++) {
      collectTextFromNode(node.childNodes[i], out);
    }
  }
}

function paragraphText(pNode) {
  const parts = [];
  collectTextFromNode(pNode, parts);
  const text = parts.join('');
  return text.replace(/\r\n/g, '\n');
}

function cellText(tcNode) {
  const paragraphs = [];
  const children = tcNode.childNodes || [];
  for (let i = 0; i < children.length; i++) {
    const child = children[i];
    if (getLocalName(child) === 'p') {
      const t = paragraphText(child);
      if (t !== '') paragraphs.push(t);
    }
  }
  return paragraphs.join('\n');
}

function extractBlocksFromDocXml(docXmlString) {
  const dom = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} }
  }).parseFromString(docXmlString, 'text/xml');

  const body = dom.getElementsByTagName('w:body')[0] || dom.getElementsByTagName('body')[0];
  if (!body) return [];

  const blocks = [];
  const children = body.childNodes || [];

  for (let i = 0; i < children.length; i++) {
    const node = children[i];
    const name = getLocalName(node);

    if (name === 'p') {
      blocks.push({ type: 'p', text: paragraphText(node) });
    } else if (name === 'tbl') {
      const rows = [];
      const tblChildren = node.childNodes || [];
      for (let r = 0; r < tblChildren.length; r++) {
        const tr = tblChildren[r];
        if (getLocalName(tr) !== 'tr') continue;

        const row = [];
        const trChildren = tr.childNodes || [];
        for (let c = 0; c < trChildren.length; c++) {
          const tc = trChildren[c];
          if (getLocalName(tc) !== 'tc') continue;
          row.push(cellText(tc));
        }
        if (row.length) rows.push(row);
      }
      blocks.push({ type: 'tbl', rows });
    }
  }

  return blocks;
}

function findFirstParagraphIndex(blocks, regex) {
  return blocks.findIndex(
    (b) => b.type === 'p' && typeof b.text === 'string' && regex.test(b.text.trim())
  );
}

function extractDisclaimer(blocks) {
  const titleIdx = findFirstParagraphIndex(blocks, /免責事項/);
  if (titleIdx === -1) return null;

  const title = blocks[titleIdx].text.trim();
  const stopRegex = /^(診断履歴|診断\s*履歴|Diagnosis\s*History|最終|Final)/;
  const paras = [];

  for (let i = titleIdx + 1; i < blocks.length; i++) {
    const b = blocks[i];
    if (b.type === 'p') {
      const t = (b.text || '').trim();
      if (t === '') continue;
      if (stopRegex.test(t)) break;
      paras.push(b.text);
      continue;
    }
    if (b.type === 'tbl') break;
  }

  return { disclaimerTitle: title, disclaimerBody: paras.join('\n') };
}

function extractDiagnosisHistory(blocks) {
  const titleIdx = findFirstParagraphIndex(blocks, /診断\s*履歴/);
  if (titleIdx === -1) return null;

  const title = blocks[titleIdx].text.trim();

  let table = null;
  for (let i = titleIdx + 1; i < blocks.length; i++) {
    if (blocks[i].type === 'tbl') {
      table = blocks[i].rows;
      break;
    }
  }

  if (!table || table.length === 0) {
    return { diagnosisTitle: title, diagnosisHeaders: [], diagnosisRows: [] };
  }

  const headers = table[0] || [];
  const rows = table.slice(1);

  return { diagnosisTitle: title, diagnosisHeaders: headers, diagnosisRows: rows };
}

function extractFinalPage(blocks) {
  const urlRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)/i;

  let urlIdx = -1;
  let url = null;

  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i];
    if (b.type !== 'p') continue;
    const m = String(b.text || '').match(urlRegex);
    if (m) {
      urlIdx = i;
      url = m[0];
    }
  }

  if (urlIdx === -1) return null;

  const lines = [];
  for (let i = urlIdx - 1; i >= 0; i--) {
    const b = blocks[i];
    if (b.type !== 'p') continue;
    const t = String(b.text || '').trim();
    if (!t) continue;
    if (/^(免責事項|診断\s*履歴)/.test(t)) break;
    lines.push(b.text);
    if (lines.length >= 3) break;
  }

  return { finalPageLines: lines.reverse(), finalPageUrl: url };
}

async function extractEmbeddedImages(zip) {
  const slots = [
    ['word/media/image1.png', 'word/media/image1.jpeg'],
    ['word/media/image2.png', 'word/media/image2.jpeg'],
    ['word/media/image3.png', 'word/media/image3.jpeg'],
    ['word/media/image4.png', 'word/media/image4.jpeg'],
  ];

  const images = {};
  for (const candidates of slots) {
    for (const name of candidates) {
      const file = zip.file(name);
      if (!file) continue;
      images[path.basename(name)] = { name, buffer: await file.async('nodebuffer') };
      break; // first match wins; don't overwrite with alternate extension
    }
  }
  return images;
}

function loadPageBackgrounds() {
  if (!fs.existsSync(TEMPLATE_DIR)) return [];
  const files = fs.readdirSync(TEMPLATE_DIR);
  return files
    .map((f) => {
      const m = /^page-(\d+)\.png$/i.exec(f);
      if (!m) return null;
      return { index: parseInt(m[1], 10), filePath: path.join(TEMPLATE_DIR, f) };
    })
    .filter(Boolean)
    .sort((a, b) => a.index - b.index)
    .map((item) => ({
      index: item.index,
      buffer: fs.readFileSync(item.filePath),
      filePath: item.filePath
    }));
}

function loadLogoOverride() {
  const logoPath = path.join(TEMPLATE_DIR, 'logo.png');
  if (!fs.existsSync(logoPath)) return null;
  return { filePath: logoPath, buffer: fs.readFileSync(logoPath) };
}

async function loadTemplateFromDocx() {
  const docxPath = resolveTemplateDocxPath();
  if (!docxPath) {
    // Fallback so the app can still generate PDFs in dev environments where
    // the template files haven't been placed yet.
    const pageBackgrounds = loadPageBackgrounds();
    const logoOverride = loadLogoOverride();
    return {
      disclaimerTitle: '免責事項',
      disclaimerBody: '',
      diagnosisTitle: '診断履歴',
      diagnosisHeaders: ['診断日', '診断者', '診断結果'],
      diagnosisRows: [],
      finalPageLines: [],
      finalPageUrl: 'https://aevus.jp/',
      images: {},
      templateDir: TEMPLATE_DIR,
      docxPath: null,
      pageBackgrounds,
      logoOverride
    };
  }

  const docxBuffer = fs.readFileSync(docxPath);
  const zip = await JSZip.loadAsync(docxBuffer);

  const docXmlFile = zip.file('word/document.xml');
  if (!docXmlFile) {
    throw new Error('Invalid DOCX: word/document.xml not found');
  }

  const docXml = await docXmlFile.async('text');
  const blocks = extractBlocksFromDocXml(docXml);

  const disclaimer = extractDisclaimer(blocks);
  const history = extractDiagnosisHistory(blocks);
  const finalPage = extractFinalPage(blocks);
  const images = await extractEmbeddedImages(zip);

  if (!disclaimer?.disclaimerTitle || !disclaimer?.disclaimerBody) {
    console.warn('[reportTemplateDocx] Disclaimer section missing or incomplete — using built-in fallback');
  }
  if (!history?.diagnosisTitle || !history?.diagnosisHeaders?.length) {
    console.warn('[reportTemplateDocx] Diagnosis History section missing or incomplete — using built-in fallback');
  }
  if (!finalPage?.finalPageUrl || !finalPage?.finalPageLines?.length) {
    console.warn('[reportTemplateDocx] Final Page section missing or incomplete — using built-in fallback');
  }

  const pageBackgrounds = loadPageBackgrounds();
  const logoOverride = loadLogoOverride();

  return {
    disclaimerTitle: disclaimer?.disclaimerTitle || '免責事項',
    disclaimerBody:  disclaimer?.disclaimerBody  || '',
    diagnosisTitle:   history?.diagnosisTitle    || '診断履歴',
    diagnosisHeaders: history?.diagnosisHeaders?.length ? history.diagnosisHeaders : ['診断日', '診断者', '診断結果'],
    diagnosisRows:    history?.diagnosisRows     || [],
    finalPageLines: finalPage?.finalPageLines?.length ? finalPage.finalPageLines : [],
    finalPageUrl:   finalPage?.finalPageUrl      || 'https://aevus.jp/',
    images,
    templateDir: TEMPLATE_DIR,
    docxPath,
    pageBackgrounds,
    logoOverride
  };
}

async function getReportTemplateStaticContent({ forceReload = false, lang = 'ja' } = {}) {
  const resolvedLang = String(lang || 'ja').toLowerCase().startsWith('en') ? 'en' : 'ja';
  if (forceReload) {
    cachedPromiseByLang.clear();
    cachedJaPromise = null;
  }
  if (cachedPromiseByLang.has(resolvedLang)) return cachedPromiseByLang.get(resolvedLang);

  const promise = (async () => {
    if (!cachedJaPromise) cachedJaPromise = loadTemplateFromDocx();
    const jaTemplate = await cachedJaPromise;
    if (resolvedLang === 'ja') return jaTemplate;
    return translateTemplateStaticToEnglish(jaTemplate);
  })();

  // Never keep a failure: a cached rejection would fail every later report in
  // this language until the process restarted.
  cachedPromiseByLang.set(resolvedLang, promise);
  promise.catch(() => {
    if (cachedPromiseByLang.get(resolvedLang) === promise) cachedPromiseByLang.delete(resolvedLang);
    cachedJaPromise = null;
  });
  return promise;
}

module.exports = {
  getReportTemplateStaticContent,
  translateTemplateStaticToEnglish,
  TEMPLATE_ENGLISH,
  TEMPLATE_DIR,
  TEMPLATE_DOCX_PATH_NEW,
  TEMPLATE_DOCX_PATH_LEGACY,
  TEMPLATE_DOCX_PATH_BACKEND
};
