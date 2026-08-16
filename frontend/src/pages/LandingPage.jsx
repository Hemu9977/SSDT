import React from 'react';
import { useLocation } from 'react-router-dom';
import Header from '../components/header';
import Hero from '../components/Hero';
import ScanTypeSelector from '../components/ScanTypeSelector';
import AuthenticatedScanPanel from '../components/AuthenticatedScanPanel';
import MarketingHome from '../components/MarketingHome';
import ParticleBackground from '../components/ParticleBackground';
import useDocumentMeta from '../hooks/useDocumentMeta';
import '../styles/LandingPage.scss';

const LandingPage = ({ historicalScan }) => {
  const location = useLocation();
  const isLoggedIn = Boolean(localStorage.getItem('token'));

  const searchParams = new URLSearchParams(location.search);
  const scanType = searchParams.get('type');

  // Signed-out visitors with no scan already in progress get the marketing
  // front door instead of the scan-type chooser. Logged-in users, an active
  // ?type= scan, and historical scan views are untouched — see CLAUDE.md.
  const showMarketingHome = !historicalScan && !scanType && !isLoggedIn;

  useDocumentMeta(showMarketingHome ? {
    title: 'Fortexa – Understand Your Website’s Security Posture',
    description: 'Fortexa gives you a clear, understandable view of your website’s security, performance, and configuration — with AI-written insights and no login required to get started.',
    path: '/',
  } : {
    title: 'Fortexa – Website Security Scanning & Vulnerability Detection',
    description: 'Fortexa scans your website for security vulnerabilities, HTTP header issues, and performance problems, then delivers an AI-written report in plain language.',
    path: '/',
  });

  // Determine which component to show
  let mainContent;
  if (historicalScan) {
    // Historical scan view - always use Hero component (works for both normal and auth scans)
    mainContent = <Hero historicalScan={historicalScan} />;
  } else if (!scanType) {
    // No scan type selected - show the marketing home for signed-out visitors,
    // otherwise the scan-type chooser (unchanged for logged-in users)
    mainContent = showMarketingHome ? <MarketingHome /> : <ScanTypeSelector />;
  } else if (scanType === 'normal') {
    // Normal scan
    mainContent = <Hero />;
  } else if (scanType === 'auth') {
    // Authenticated scan
    mainContent = <AuthenticatedScanPanel />;
  } else {
    // Invalid scan type - default to selector
    mainContent = <ScanTypeSelector />;
  }

  return (
    <div className="landing-page">
      <ParticleBackground />
      <Header />
      <main>
        {mainContent}
      </main>
    </div>
  );
};

export default LandingPage;
