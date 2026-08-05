import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { defaultLanguage, locales, supportedLanguages } from '../locales';

const STORAGE_KEY = 'fortexa-language';

const LanguageContext = createContext(null);

// An explicit language choice ALWAYS wins; the default is only seeded when nothing is
// stored yet (new or cleared browser). A previous version force-reset every browser to
// the default once, which silently destroyed a saved English selection — and, because
// the write that recorded "already migrated" could itself throw, could re-fire on every
// load and pin the UI to Japanese permanently. Reading first removes both failure modes:
// a stored value is always honoured, and a failed seed just means we re-seed next time.
const readInitialLanguage = () => {
  if (typeof window === 'undefined') return defaultLanguage;
  // Runs in the useState initializer (render phase) and touches storage, so it must
  // never throw: localStorage can be unavailable outright under private browsing or a
  // strict cookie policy, and a throw here would break first paint for everyone.
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (supportedLanguages.includes(stored)) return stored;
    window.localStorage.setItem(STORAGE_KEY, defaultLanguage);
  } catch {
    /* storage unavailable — fall through to the in-memory default */
  }
  return defaultLanguage;
};

const interpolate = (value, params = {}) => {
  if (typeof value !== 'string') return value;
  return value.replace(/\{(\w+)\}/g, (_, key) => (
    Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : `{${key}}`
  ));
};

export const LanguageProvider = ({ children }) => {
  const [language, setLanguageState] = useState(readInitialLanguage);
  const [hasReport, setHasReport] = useState(false);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  const setLanguage = useCallback((nextLanguage) => {
    if (!supportedLanguages.includes(nextLanguage)) return;
    setLanguageState(nextLanguage);
    document.documentElement.lang = nextLanguage;
    // Persisting is best-effort: if storage is blocked the switch must still apply for
    // this session rather than throwing out of the click handler mid-way.
    try {
      window.localStorage.setItem(STORAGE_KEY, nextLanguage);
    } catch {
      /* storage unavailable — choice applies for this session only */
    }
  }, []);

  const toggleLanguage = useCallback(() => {
    setLanguage(language === 'en' ? 'ja' : 'en');
  }, [language, setLanguage]);

  const t = useCallback((key, params) => {
    // Fall back through English, not defaultLanguage: `en` is the complete base
    // dictionary (ja.js spreads ...en), so a key missing from the active dictionary
    // resolves to English rather than leaking Japanese into the English UI — which is
    // what would happen if the fallback tracked defaultLanguage now that it is 'ja'.
    const dictionary = locales[language] || locales.en;
    const value = dictionary[key] !== undefined ? dictionary[key] : locales.en[key];
    return interpolate(value !== undefined ? value : key, params);
  }, [language]);

  const value = useMemo(() => ({
    language,
    currentLang: language,
    setLanguage,
    toggleLanguage,
    t,
    hasReport,
    setHasReport,
    isTranslating: false,
    translationProgress: 0,
    translatePage: setLanguage,
    clearTranslationCache: () => {},
    translationCache: null,
  }), [language, setLanguage, toggleLanguage, t, hasReport]);

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = () => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
};
