import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import ThemeToggle from './ThemeToggle';
import LanguageToggle from './LanguageToggle';
import { useUser } from '../contexts/UserContext';
import { useTranslation } from '../contexts/TranslationContext';
import '../styles/Header.scss';
import logo from '../assets/logo.png';

const Header = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const token = localStorage.getItem('token');
  const { isPro } = useUser();
  const { t } = useTranslation();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!menuOpen) return;
    const handleOutside = (e) => {
      if (!e.target.closest('.header-container')) setMenuOpen(false);
    };
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, [menuOpen]);

  useEffect(() => {
    document.body.style.overflow = menuOpen ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [menuOpen]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setMenuOpen(false);
    navigate('/');
    window.location.reload();
  };

  return (
    <header className="header-container">
      <Link to="/" className="logo-container">
        <img src={logo} alt={t('fortexaLogoAlt')} className="logo" />
        <h1>{t('appName')}</h1>
      </Link>

      <button
        className={`hamburger${menuOpen ? ' open' : ''}`}
        onClick={() => setMenuOpen((value) => !value)}
        aria-label={t('toggleNavigationMenu')}
        aria-expanded={menuOpen}
        type="button"
      >
        <span />
        <span />
        <span />
      </button>

      <div className={`header-controls${menuOpen ? ' open' : ''}`}>
        <ThemeToggle />
        <LanguageToggle />
        <Link
          to="/about"
          className="about-button"
          onClick={() => setMenuOpen(false)}
        >
          {t('about')}
        </Link>

        {token ? (
          <>
            <Link
              to="/profile"
              className="profile-button"
              onClick={() => setMenuOpen(false)}
            >
              {t('profile')}
              {isPro && <span className="pro-badge-header">{t('pro')}</span>}
            </Link>
            <button onClick={handleLogout} className="logout-button" type="button">
              {t('logout')}
            </button>
          </>
        ) : (
          <Link
            to="/register"
            className="signup-button"
            onClick={() => setMenuOpen(false)}
          >
            {t('signup')}
          </Link>
        )}
      </div>
    </header>
  );
};

export default Header;
