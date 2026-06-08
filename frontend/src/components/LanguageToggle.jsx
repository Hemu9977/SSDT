import React from 'react';
import { useTranslation } from '../contexts/TranslationContext';
import '../styles/LanguageToggle.css';

const LanguageToggle = () => {
  const { currentLang, toggleLanguage, t } = useTranslation();
  const isJapanese = currentLang === 'ja';

  return (
    <button
      className={`language-toggle ${isJapanese ? 'is-japanese' : 'is-english'}`}
      onClick={toggleLanguage}
      type="button"
      aria-label={isJapanese ? t('switchToEnglish') : t('switchToJapanese')}
      title={isJapanese ? t('switchToEnglish') : t('switchToJapanese')}
    >
      <span className="language-toggle__option language-toggle__option--en">
        {t('englishShort')}
      </span>
      <span className="language-toggle__option language-toggle__option--ja">
        {t('japaneseNative')}
      </span>
      <span className="language-toggle__thumb" aria-hidden="true" />
    </button>
  );
};

export default LanguageToggle;
