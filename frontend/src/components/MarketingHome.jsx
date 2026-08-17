import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { useTranslation } from '../contexts/TranslationContext';
import logo from '../assets/logo.png';
import '../styles/MarketingHome.scss';

// Three value props, not six capability cards — this is a short first-touch
// entry page, not a feature inventory (that's what /about is for).
const VALUE_PROPS = ['Detect', 'Auth', 'Ai'];

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

  const goToAbout = () => navigate('/about');
  const goToRegister = () => navigate('/register');

  const motionProps = fadeUp(reduceMotion);

  return (
    <div className="marketing-home">
      {/* Hero — this is the entire first viewport at "/"; no splash gate in front of it */}
      <section className="marketing-hero">
        <div className="marketing-hero-copy">
          <span className="marketing-eyebrow">{t('marketingHeroEyebrow')}</span>
          <h1 className="marketing-hero-title">{t('marketingHeroTitle')}</h1>
          <p className="marketing-hero-subtitle">{t('marketingHeroSubtitle')}</p>
          <div className="marketing-hero-actions">
            <button type="button" className="marketing-btn marketing-btn--secondary" onClick={goToAbout}>
              {t('marketingHeroCtaSecondary')}
            </button>
          </div>
        </div>

        <div className="marketing-hero-visual" aria-hidden="true">
          <div className="scan-ring">
            <div className="scan-core">
              <img src={logo} alt="" className="scan-core-logo" />
            </div>
          </div>
        </div>
      </section>

      {/* Value proposition — 3 concise reasons, no card walls */}
      <motion.section className="marketing-values" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('marketingValueTitle')}</h2>
        <div className="marketing-value-grid">
          {VALUE_PROPS.map((key) => (
            <div className="marketing-value-item" key={key}>
              <h3 className="marketing-value-title">{t(`marketingValue${key}Title`)}</h3>
              <p className="marketing-value-description">{t(`marketingValue${key}Description`)}</p>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Final CTA */}
      <motion.section className="marketing-cta-section" {...motionProps}>
        <h2 className="marketing-cta-title">{t('marketingFinalCtaTitle')}</h2>
        <div className="marketing-hero-actions marketing-cta-actions">
          <button type="button" className="marketing-btn marketing-btn--secondary" onClick={goToRegister}>
            {t('marketingFinalCtaSecondary')}
          </button>
        </div>
      </motion.section>
    </div>
  );
};

export default MarketingHome;
