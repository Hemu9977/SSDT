import React from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import { useTranslation } from '../contexts/TranslationContext';
import useDocumentMeta from '../hooks/useDocumentMeta';
import '../styles/About.scss';

// Mirrors the plan data shown on the Profile page's plan chooser — figures must
// stay in sync with PLANS in pages/Profile.jsx.
const PLANS = [
  { planType: 'light', price: '¥30,000', annualPrice: '¥300,000', accounts: 1, totalScans: 3, severity: 'critical-high' },
  { planType: 'basic', price: '¥50,000', annualPrice: '¥500,000', accounts: 3, totalScans: 5, severity: 'all' },
  { planType: 'pro', price: '¥100,000', annualPrice: '¥1,000,000', accounts: 5, totalScans: 10, severity: 'all' },
];

const TRIALS = [
  { planType: 'trial1', price: '¥20,000', scans: 1, severity: 'critical-high' },
  { planType: 'trial2', price: '¥30,000', scans: 2, severity: 'all' },
];

const PLAN_NAMES = { light: 'planLight', basic: 'planBasic', pro: 'planPro', trial1: 'planTrial1', trial2: 'planTrial2' };

const About = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const isLoggedIn = Boolean(localStorage.getItem('token'));

  useDocumentMeta({
    title: 'About Fortexa – Website Security Scanning & Vulnerability Detection',
    description: 'Learn how Fortexa scans websites for vulnerabilities, security header issues, and performance problems, and view our plans and pricing.',
    path: '/about',
  });

  const handlePrimaryCta = () => {
    navigate(isLoggedIn ? '/' : '/register');
  };

  const handlePlanCta = () => {
    navigate(isLoggedIn ? '/profile' : '/register');
  };

  const howItWorksSteps = [
    { title: t('aboutStep1Title'), description: t('aboutStep1Description') },
    { title: t('aboutStep2Title'), description: t('aboutStep2Description') },
    { title: t('aboutStep3Title'), description: t('aboutStep3Description') },
    { title: t('aboutStep4Title'), description: t('aboutStep4Description') },
    { title: t('aboutStep5Title'), description: t('aboutStep5Description') },
  ];

  const features = [
    { title: t('aboutFeaturePerformanceTitle'), description: t('aboutFeaturePerformanceDescription') },
    { title: t('aboutFeatureVulnerabilityTitle'), description: t('aboutFeatureVulnerabilityDescription') },
    { title: t('aboutFeatureInfraTitle'), description: t('aboutFeatureInfraDescription') },
    { title: t('aboutFeatureAuthTitle'), description: t('aboutFeatureAuthDescription') },
    { title: t('aboutFeatureAiTitle'), description: t('aboutFeatureAiDescription') },
    { title: t('aboutFeatureReportsTitle'), description: t('aboutFeatureReportsDescription') },
  ];

  return (
    <div className="about-page">
      <ParticleBackground />
      <Header />
      <main>
        <div className="about-container">

          {/* Hero */}
          <section className="about-hero">
            <h1 className="about-hero-title">
              <span className="highlight">{t('appName')}</span> {t('aboutHeroTitleSuffix')}
            </h1>
          </section>

          {/* What We Do */}
          <section className="about-section about-panel">
            <h2 className="about-section-title">{t('aboutWhatWeDoTitle')}</h2>
            <p className="about-section-text">{t('aboutWhatWeDoBody1')}</p>
            <p className="about-section-text">{t('aboutWhatWeDoBody2')}</p>
          </section>

          {/* Key Features */}
          <section className="about-section">
            <h2 className="about-section-title about-section-title--center">{t('aboutFeaturesTitle')}</h2>
            <div className="about-feature-grid">
              {features.map((feature) => (
                <div className="about-feature-card" key={feature.title}>
                  <h3 className="about-feature-title">{feature.title}</h3>
                  <p className="about-feature-description">{feature.description}</p>
                </div>
              ))}
            </div>
          </section>

          {/* How It Works */}
          <section className="about-section about-panel">
            <h2 className="about-section-title about-section-title--center">{t('aboutHowItWorksTitle')}</h2>
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
          </section>

          {/* Reports & Results */}
          <section className="about-section about-panel">
            <h2 className="about-section-title">{t('aboutReportsTitle')}</h2>
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
          </section>

          {/* Plans & Pricing */}
          <section className="about-section">
            <h2 className="about-section-title about-section-title--center">{t('aboutPlansTitle')}</h2>
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
          </section>

          {/* Secure Payments */}
          <section className="about-section about-panel">
            <h2 className="about-section-title">{t('aboutPaymentsTitle')}</h2>
            <p className="about-section-text">{t('aboutPaymentsBody')}</p>
          </section>

          {/* Final CTA */}
          <section className="about-cta-section">
            <h2 className="about-cta-title">{t('aboutFinalCtaTitle')}</h2>
            <button className="about-cta-button" onClick={handlePrimaryCta} type="button">
              {t('aboutHeroCta')}
            </button>
          </section>

        </div>
      </main>
    </div>
  );
};

export default About;
