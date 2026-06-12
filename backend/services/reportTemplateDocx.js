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

async function translateTemplateStaticToEnglish(jaTemplate) {
  const disclaimerParas = splitParagraphs(jaTemplate.disclaimerBody);
  const finalLines = Array.isArray(jaTemplate.finalPageLines) ? jaTemplate.finalPageLines : [];
  const headers = Array.isArray(jaTemplate.diagnosisHeaders) ? jaTemplate.diagnosisHeaders : [];

  const texts = [
    jaTemplate.disclaimerTitle,
    ...disclaimerParas,
    jaTemplate.diagnosisTitle,
    ...headers,
    ...finalLines
  ];

  let translated;
  try {
    translated = await translateText(texts, 'en');
  } catch (e) {
    const err = new Error('Gemini key is exhausted');
    err.code = isGeminiKeyExhaustedError(e) ? 'GEMINI_KEY_EXHAUSTED' : 'TEMPLATE_TRANSLATION_FAILED';
    err.details = e?.message;
    throw err;
  }
  let idx = 0;
  const disclaimerTitle = translated[idx++];
  const translatedParas = disclaimerParas.map(() => translated[idx++] ?? '');
  const diagnosisTitle = translated[idx++];
  const translatedHeaders = headers.map(() => translated[idx++] ?? '');
  const translatedFinalLines = finalLines.map(() => translated[idx++] ?? '');

  if (!disclaimerTitle || !diagnosisTitle) {
    const err = new Error('Gemini template translation returned empty result');
    err.code = 'GEMINI_KEY_EXHAUSTED';
    throw err;
  }

  const headersOut = translatedHeaders.every(Boolean)
    ? translatedHeaders
    : safeDefaultEnglishHeaders(headers.length);

  const out = {
    ...jaTemplate,
    disclaimerTitle,
    disclaimerBody: joinParagraphs(translatedParas),
    diagnosisTitle,
    diagnosisHeaders: headersOut,
    finalPageLines: translatedFinalLines.filter(Boolean)
  };

  // Hard guard: EN template must not contain Japanese characters.
  const joined = [
    out.disclaimerTitle,
    out.disclaimerBody,
    out.diagnosisTitle,
    ...(out.diagnosisHeaders || []),
    ...(out.finalPageLines || [])
  ].join('\n');
  if (containsJapanese(joined)) {
    const err = new Error('English template translation contains Japanese characters');
    err.code = 'EN_TEMPLATE_NOT_ENGLISH';
    throw err;
  }

  return out;
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

  cachedPromiseByLang.set(resolvedLang, promise);
  return promise;
}

module.exports = {
  getReportTemplateStaticContent,
  TEMPLATE_DIR,
  TEMPLATE_DOCX_PATH_NEW,
  TEMPLATE_DOCX_PATH_LEGACY,
  TEMPLATE_DOCX_PATH_BACKEND
};
