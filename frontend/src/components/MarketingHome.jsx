import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { useTranslation } from '../contexts/TranslationContext';
import '../styles/MarketingHome.scss';

// Illustrative-only sample values for the results-preview mockup below — not
// live data. Category labels are generic on purpose (see CLAUDE.md UI Language
// Policy: never surface the names of the underlying scanning tools/providers).
const PREVIEW_ROWS = [
  { key: 'performance', grade: 'A', tone: 'safe' },
  { key: 'security', grade: 'B', tone: 'low' },
  { key: 'vuln', grade: 'medium', tone: 'medium' },
  { key: 'infra', grade: 'A', tone: 'safe' },
];

const CAPABILITIES = [
  'Performance',
  'Vuln',
  'Infra',
  'Auth',
  'Ai',
  'Monitor',
];

const HOW_STEPS = ['Step1', 'Step2', 'Step3'];

const fadeUp = (reduceMotion) => ({
  initial: reduceMotion ? {} : { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.5, ease: 'easeOut' },
});

const MarketingHome = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const reduceMotion = useReducedMotion();

  const goToScan = () => navigate('/?type=normal');
  const goToAbout = () => navigate('/about');
  const goToRegister = () => navigate('/register');

  const motionProps = fadeUp(reduceMotion);

  return (
    <div className="marketing-home">
      {/* Hero */}
      <section className="marketing-hero">
        <div className="marketing-hero-copy">
          <span className="marketing-eyebrow">{t('marketingHeroEyebrow')}</span>
          <h1 className="marketing-hero-title">{t('marketingHeroTitle')}</h1>
          <p className="marketing-hero-subtitle">{t('marketingHeroSubtitle')}</p>
          <div className="marketing-hero-actions">
            <button type="button" className="marketing-btn marketing-btn--primary" onClick={goToScan}>
              {t('marketingHeroCtaPrimary')}
            </button>
            <button type="button" className="marketing-btn marketing-btn--secondary" onClick={goToAbout}>
              {t('marketingHeroCtaSecondary')}
            </button>
          </div>
          <p className="marketing-hero-note">{t('marketingHeroNote')}</p>
        </div>

        <div className="marketing-hero-visual" aria-hidden="true">
          <div className="scan-ring">
            <div className="scan-core">
              <span className="scan-core-grade">A</span>
            </div>
          </div>
        </div>
      </section>

      {/* Value strip */}
      <motion.section className="marketing-stats" {...motionProps}>
        <div className="marketing-stat">
          <span className="marketing-stat-value">6</span>
          <span className="marketing-stat-label">{t('marketingStat1Label')}</span>
        </div>
        <div className="marketing-stat">
          <span className="marketing-stat-value">2</span>
          <span className="marketing-stat-label">{t('marketingStat2Label')}</span>
        </div>
        <div className="marketing-stat">
          <span className="marketing-stat-value">EN / 日本語</span>
          <span className="marketing-stat-label">{t('marketingStat3Label')}</span>
        </div>
        <div className="marketing-stat marketing-stat--badge">
          <span className="marketing-stat-label">{t('marketingStat4Label')}</span>
        </div>
      </motion.section>

      {/* Capabilities */}
      <motion.section className="marketing-section" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('marketingCapabilitiesTitle')}</h2>
        <div className="marketing-capability-grid">
          {CAPABILITIES.map((key) => (
            <div className="marketing-capability-card" key={key}>
              <h3 className="marketing-capability-title">{t(`marketingCap${key}Title`)}</h3>
              <p className="marketing-capability-description">{t(`marketingCap${key}Description`)}</p>
            </div>
          ))}
        </div>
      </motion.section>

      {/* How it works */}
      <motion.section className="marketing-section marketing-panel" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('marketingHowTitle')}</h2>
        <div className="marketing-how-steps">
          {HOW_STEPS.map((key, index) => (
            <div className="marketing-how-step" key={key}>
              <div className="marketing-how-step-number">{index + 1}</div>
              <div>
                <h3 className="marketing-how-step-title">{t(`marketingHow${key}Title`)}</h3>
                <p className="marketing-how-step-description">{t(`marketingHow${key}Description`)}</p>
              </div>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Product preview */}
      <motion.section className="marketing-section" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('marketingPreviewTitle')}</h2>
        <p className="marketing-section-text marketing-section-text--center">{t('marketingPreviewSubtitle')}</p>

        <div className="marketing-preview-panel">
          {PREVIEW_ROWS.map((row) => (
            <div className="marketing-preview-row" key={row.key}>
              <span className="marketing-preview-label">{t(`marketingPreviewLabel${row.key.charAt(0).toUpperCase()}${row.key.slice(1)}`)}</span>
              <span className={`marketing-preview-grade marketing-preview-grade--${row.tone}`}>
                {row.tone === 'medium' ? t('marketingPreviewRiskMedium') : row.grade}
              </span>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Final CTA */}
      <motion.section className="marketing-cta-section" {...motionProps}>
        <h2 className="marketing-cta-title">{t('marketingFinalCtaTitle')}</h2>
        <p className="marketing-cta-subtitle">{t('marketingFinalCtaSubtitle')}</p>
        <div className="marketing-hero-actions marketing-cta-actions">
          <button type="button" className="marketing-btn marketing-btn--primary" onClick={goToScan}>
            {t('marketingFinalCtaPrimary')}
          </button>
          <button type="button" className="marketing-btn marketing-btn--secondary" onClick={goToRegister}>
            {t('marketingFinalCtaSecondary')}
          </button>
        </div>
      </motion.section>
    </div>
  );
};

export default MarketingHome;
