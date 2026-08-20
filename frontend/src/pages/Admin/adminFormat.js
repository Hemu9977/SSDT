// frontend/src/pages/Admin/adminFormat.js
// Locale-aware date, time, and number formatting for the Admin Dashboard.
// Mirrors the exact convention already established in Profile.jsx and
// ScheduledScans.jsx — toLocaleDateString/toLocaleString/toLocaleNumberString
// tied to the app's language toggle (currentLang from useTranslation), not the
// browser's ambient locale — so a date renders in Japanese the instant the
// header language switch flips to 日本語, on every page, without a refresh.

const localeFor = (currentLang) => (currentLang === 'ja' ? 'ja-JP' : 'en-US');

export const formatAdminDate = (currentLang, d) => {
  if (!d) return '—';
  return new Date(d).toLocaleDateString(localeFor(currentLang), {
    year: 'numeric', month: 'short', day: 'numeric',
  });
};

export const formatAdminDateTime = (currentLang, d) => {
  if (!d) return '—';
  return new Date(d).toLocaleString(localeFor(currentLang), {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
};

export const formatAdminTime = (currentLang, d) => {
  if (!d) return '—';
  return new Date(d).toLocaleTimeString(localeFor(currentLang));
};

export const formatAdminNumber = (currentLang, n) => {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return Number(n).toLocaleString(localeFor(currentLang));
};

// Japanese Yen has no decimal places by definition — Intl.NumberFormat
// handles that automatically for currency: 'JPY'.
export const formatAdminYen = (currentLang, n) => {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return new Intl.NumberFormat(localeFor(currentLang), { style: 'currency', currency: 'JPY' }).format(n);
};
