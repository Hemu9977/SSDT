import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { useTranslation } from '../contexts/TranslationContext';
import { plansForCycle, PLAN_NAMES } from '../config/planCatalog';
import logo from '../assets/logo.png';
import '../styles/MarketingHome.scss';
// Reused for the sections merged in from the removed /about page (feature
// grid, steps, report-format cards, plan/trial cards, panel treatment) — see
// styles/About.scss. Kept as-is rather than duplicated so this page inherits
// the exact same visual design.
import '../styles/About.scss';

// Plan figures come from the shared catalog, which the Profile plan chooser also
// reads and which a test keeps in step with the backend — see
// config/planCatalog.js. This page shows the monthly price with the annual figure
// as a sub-line, so it pairs the two cycles rather than using one directly.
const PLANS = plansForCycle('monthly').map((plan, i) => ({
  ...plan,
  annualPrice: plansForCycle('annual')[i].price,
}));

const TRIALS = plansForCycle('onetime').map((plan) => ({
  ...plan,
  scans: plan.totalScans,
}));

// "AI-Powered Analysis" is deliberately excluded here — it gets its own
// dedicated, more prominent section below rather than competing as one card
// among several.
const CAPABILITIES = ['Performance', 'Vulnerability', 'Infra', 'Auth', 'Reports', 'Ongoing'];

// Rendered with their first sentence bold — split into Lead/Rest translation
// keys per item so the bold portion never depends on runtime string-splitting.
const BOLD_PRIVACY_ITEM_KEYS = ['Target', 'User', 'Headers'];

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
  const isLoggedIn = Boolean(localStorage.getItem('token'));

  const goToRegister = () => navigate('/register');
  const handlePlanCta = () => navigate(isLoggedIn ? '/profile' : '/register');

  const motionProps = fadeUp(reduceMotion);

  const capabilities = CAPABILITIES.map((key) => ({
    key,
    title: t(`aboutFeature${key}Title`),
    description: t(`aboutFeature${key}Description`),
  }));

  const howItWorksSteps = [1, 2, 3, 4, 5].map((n) => ({
    title: t(`aboutStep${n}Title`),
    description: t(`aboutStep${n}Description`),
  }));

  const boldPrivacyItems = BOLD_PRIVACY_ITEM_KEYS.map((key) => ({
    key,
    lead: t(`marketingAiPrivacyItem${key}Lead`),
    rest: t(`marketingAiPrivacyItem${key}Rest`),
  }));
  const privacyGuardrailItem = t('marketingAiPrivacyItemGuardrail');

  return (
    <div className="marketing-home">
      {/* Hero — this is the entire first viewport at "/"; no splash gate in front of it */}
      <section className="marketing-hero">
        <div className="marketing-hero-copy">
          <span className="marketing-eyebrow">{t('marketingHeroEyebrow')}</span>
          <h1 className="marketing-hero-title">{t('marketingHeroTitle')}</h1>
          <p className="marketing-hero-subtitle">{t('marketingHeroSubtitle')}</p>
        </div>

        <div className="marketing-hero-visual" aria-hidden="true">
          <div className="scan-ring">
            <div className="scan-ring-track" />
            <div className="scan-ring-arc" />
            <div className="scan-ring-node scan-ring-node--1" />
            <div className="scan-ring-node scan-ring-node--2" />
            <div className="scan-ring-node scan-ring-node--3" />
            <div className="scan-ring-node scan-ring-node--4" />
            <div className="scan-core">
              <img src={logo} alt="" className="scan-core-logo" />
            </div>
          </div>
        </div>
      </section>

      {/* Why FORTEXA / core capabilities — reorganized from the former /about page's
          "What We Do" + "Key Features" sections */}
      <motion.section className="marketing-section about-section" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('marketingValueTitle')}</h2>
        <div className="about-feature-grid marketing-capability-grid">
          {capabilities.map((c) => (
            <div className="about-feature-card" key={c.key}>
              <h3 className="about-feature-title">{c.title}</h3>
              <p className="about-feature-description">{c.description}</p>
            </div>
          ))}
        </div>
      </motion.section>

      {/* AI-Powered Security Analysis — a dedicated, visually prominent section
          since this is a core capability, not one feature among many. */}
      <motion.section className="marketing-ai-section" {...motionProps}>
        <div className="marketing-ai-panel">
          <h2 className="marketing-ai-title">{t('marketingAiTitle')}</h2>
          <p className="marketing-ai-lead">{t('marketingAiLead')}</p>
          <p className="marketing-ai-body">{t('marketingAiBody')}</p>

          <div className="marketing-ai-privacy">
            <h3 className="marketing-ai-privacy-title">{t('marketingAiPrivacyTitle')}</h3>
            <p className="marketing-ai-privacy-intro">{t('marketingAiPrivacyIntro')}</p>
            <ul className="marketing-ai-privacy-list">
              {boldPrivacyItems.map(({ key, lead, rest }) => (
                <li key={key}><strong>{lead}</strong>{rest}</li>
              ))}
              <li>{privacyGuardrailItem}</li>
            </ul>
          </div>
        </div>
      </motion.section>

      {/* How It Works — moved from /about */}
      <motion.section className="marketing-section about-section about-panel" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('aboutHowItWorksTitle')}</h2>
        <div className="about-steps">
          {howItWorksSteps.map((step, index) => (
            <div className="about-step" key={step.title}>
              <div className="about-step-number">{index + 1}</div>
              <div>
                <h3 className="about-step-title">{step.title}</h3>
                <p className="about-step-description">{step.description}</p>
              </div>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Reports & Results — moved from /about */}
      <motion.section className="marketing-section about-section" {...motionProps}>
        <h2 className="marketing-section-title">{t('aboutReportsTitle')}</h2>
        <p className="about-section-text">{t('aboutReportsBody')}</p>
        <div className="about-format-grid">
          <div className="about-format-card">
            <h3 className="about-format-title">{t('aboutFormatPdfTitle')}</h3>
            <p className="about-format-description">{t('aboutFormatPdfDescription')}</p>
          </div>
          <div className="about-format-card">
            <h3 className="about-format-title">{t('aboutFormatJsonTitle')}</h3>
            <p className="about-format-description">{t('aboutFormatJsonDescription')}</p>
          </div>
        </div>
      </motion.section>

      {/* Plans & Pricing — moved from /about */}
      <motion.section className="marketing-section about-section" {...motionProps}>
        <h2 className="marketing-section-title marketing-section-title--center">{t('aboutPlansTitle')}</h2>
        <p className="about-section-text about-section-text--center">{t('aboutPlansSubtitle')}</p>

        <div className="about-plan-grid">
          {PLANS.map((plan) => (
            <div className={`about-plan-card${plan.planType === 'basic' ? ' about-plan-card--highlight' : ''}`} key={plan.planType}>
              {plan.planType === 'basic' && (
                <div className="about-plan-badge">{t('mostPopular')}</div>
              )}
              <div className="about-plan-name">{t(PLAN_NAMES[plan.planType])}</div>
              <div className="about-plan-price">
                {plan.price}
                <span className="about-plan-period">{t('periodMonth')}</span>
              </div>
              <div className="about-plan-annual">{t('aboutOrAnnual', { amount: plan.annualPrice })}</div>
              <div className="about-plan-tax-note">{t('priceExcludingTax')}</div>
              <ul className="about-plan-features">
                <li>{t('planAccounts', { count: plan.accounts, plural: plan.accounts === 1 ? '' : 's' })}</li>
                <li>{t('planScansPerMonth', { count: plan.totalScans, plural: plan.totalScans === 1 ? '' : 's' })}</li>
                <li className={plan.severity === 'all' ? 'about-plan-feature--highlight' : ''}>
                  {plan.severity === 'all' ? t('severityAllLevels') : t('severityCriticalHighOnly')}
                </li>
              </ul>
              <button className="about-plan-button" onClick={handlePlanCta} type="button">
                {t('selectPlan')}
              </button>
            </div>
          ))}
        </div>

        <h3 className="about-trials-title">{t('aboutTrialsTitle')}</h3>
        <div className="about-trial-grid">
          {TRIALS.map((trial) => (
            <div className="about-trial-card" key={trial.planType}>
              <div className="about-plan-name">{t(PLAN_NAMES[trial.planType])}</div>
              <div className="about-plan-price">{trial.price}</div>
              <div className="about-plan-tax-note">{t('priceExcludingTax')}</div>
              <ul className="about-plan-features">
                <li>{t('planScansForTarget', { count: trial.scans, plural: trial.scans === 1 ? '' : 's' })}</li>
                <li className={trial.severity === 'all' ? 'about-plan-feature--highlight' : ''}>
                  {trial.severity === 'all' ? t('severityAllLevels') : t('severityCriticalHighOnly')}
                </li>
              </ul>
              <button className="about-plan-button" onClick={handlePlanCta} type="button">
                {t('selectPlan')}
              </button>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Secure Payments — moved from /about */}
      <motion.section className="marketing-section about-section about-panel" {...motionProps}>
        <h2 className="about-section-title">{t('aboutPaymentsTitle')}</h2>
        <p className="about-section-text">{t('aboutPaymentsBody')}</p>
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
