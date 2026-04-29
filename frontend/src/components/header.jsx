import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import ThemeToggle from './ThemeToggle';
import LanguageToggle from './LanguageToggle';
import { useUser } from '../contexts/UserContext';
import '../styles/Header.scss';
import logo from '../assets/logo.png';

const Header = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const token = localStorage.getItem('token');
  const { isPro } = useUser();
  const [menuOpen, setMenuOpen] = useState(false);

  // Close menu on route change
  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  // Close menu on outside click
  useEffect(() => {
    if (!menuOpen) return;
    const handleOutside = (e) => {
      if (!e.target.closest('.header-container')) setMenuOpen(false);
    };
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, [menuOpen]);

  // Prevent body scroll when mobile menu is open
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
        <img src={logo} alt="FORTEXA Logo" className="logo" />
        <h1>FORTEXA</h1>
      </Link>

      <button
        className={`hamburger${menuOpen ? ' open' : ''}`}
        onClick={() => setMenuOpen(v => !v)}
        aria-label="Toggle navigation menu"
        aria-expanded={menuOpen}
      >
        <span />
        <span />
        <span />
      </button>

      <div className={`header-controls${menuOpen ? ' open' : ''}`}>
        <ThemeToggle />
        <LanguageToggle />

        {token ? (
          <>
            <Link
              to="/profile"
              className="profile-button"
              onClick={() => setMenuOpen(false)}
            >
              Profile
              {isPro && <span className="pro-badge-header">PRO ⚡</span>}
            </Link>
            <button onClick={handleLogout} className="logout-button">
              Logout
            </button>
          </>
        ) : (
          <Link
            to="/register"
            className="signup-button"
            onClick={() => setMenuOpen(false)}
          >
            Sign Up
          </Link>
        )}
      </div>
    </header>
  );
};

export default Header;
