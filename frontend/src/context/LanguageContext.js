import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { defaultLanguage, locales, supportedLanguages } from '../locales';

const STORAGE_KEY = 'fortexa-language';

const LanguageContext = createContext(null);

const readInitialLanguage = () => {
  if (typeof window === 'undefined') return defaultLanguage;
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return supportedLanguages.includes(stored) ? stored : defaultLanguage;
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
