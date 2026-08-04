import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { defaultLanguage, locales, supportedLanguages } from '../locales';

const STORAGE_KEY = 'fortexa-language';

const LanguageContext = createContext(null);

// One-time migration: existing browsers already hold a `fortexa-language` value from
// when English was the default, so flipping defaultLanguage alone would never reach
// them. Reset those to Japanese exactly once; the toggle is respected from then on.
const JA_DEFAULT_MIGRATION_KEY = 'fortexa-language-default-ja';

const readInitialLanguage = () => {
  if (typeof window === 'undefined') return defaultLanguage;
  // This runs in the useState initializer (render phase) and writes to storage, so it
  // must never throw: localStorage access can fail outright under private browsing or
  // a strict cookie policy, and a throw here would break first paint for everyone.
  try {
    if (!window.localStorage.getItem(JA_DEFAULT_MIGRATION_KEY)) {
      window.localStorage.setItem(JA_DEFAULT_MIGRATION_KEY, '1');
      window.localStorage.setItem(STORAGE_KEY, defaultLanguage);
      return defaultLanguage;
    }
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return supportedLanguages.includes(stored) ? stored : defaultLanguage;
  } catch {
    return defaultLanguage;
  }
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
    window.localStorage.setItem(STORAGE_KEY, nextLanguage);
    document.documentElement.lang = nextLanguage;
  }, []);

  const toggleLanguage = useCallback(() => {
    setLanguage(language === 'en' ? 'ja' : 'en');
  }, [language, setLanguage]);

  const t = useCallback((key, params) => {
    const dictionary = locales[language] || locales[defaultLanguage];
    const fallback = locales[defaultLanguage][key] || key;
    return interpolate(dictionary[key] || fallback, params);
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
