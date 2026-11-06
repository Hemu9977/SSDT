import React from 'react';
import { render, screen } from '@testing-library/react';

// The real locale strings, with the same {key} substitution as LanguageContext.
let mockLang = 'en';
jest.mock('../contexts/TranslationContext', () => {
  const { locales } = jest.requireActual('../locales');
  return {
    useTranslation: () => ({
      currentLang: mockLang,
      t: (key, vars) => String(locales[mockLang][key] ?? key)
        .replace(/\{(\w+)\}/g, (m, k) => (vars && vars[k] !== undefined ? String(vars[k]) : m)),
    }),
  };
});

// eslint-disable-next-line import/first
import IpAllowlistNote from '../components/IpAllowlistNote';
// eslint-disable-next-line import/first
import { FORTEXA_EGRESS_IP } from '../config/egress';
// eslint-disable-next-line import/first
import { locales } from '../locales';

const renderNote = (lang) => {
  mockLang = lang;
  return render(<ul><IpAllowlistNote block="scan-note" /></ul>);
};

test('the outbound IP has one configurable source: the verified production NAT gateway IP', () => {
  expect(FORTEXA_EGRESS_IP).toBe('54.178.209.53');
});

test.each(['en', 'ja'])('%s: the IP and both ports are highlighted, and every sentence is shown', (lang) => {
  const { container } = renderNote(lang);
  const highlighted = [...container.querySelectorAll('.scan-note__value')].map((el) => el.textContent);
  expect(highlighted).toEqual([FORTEXA_EGRESS_IP, '80 (HTTP)', '443 (HTTPS)']);

  const text = container.textContent;
  expect(text).toContain(locales[lang].ipAllowlistNoteTitle);
  expect(text).toContain(locales[lang].ipAllowlistNoteConsequence);
  expect(text).not.toContain('{ip}');
  expect(screen.getAllByText(FORTEXA_EGRESS_IP)).toHaveLength(1);
});

test('the note never names a scan engine', () => {
  for (const lang of ['en', 'ja']) {
    const all = ['ipAllowlistNoteTitle', 'ipAllowlistNoteAccess', 'ipAllowlistNotePorts', 'ipAllowlistNoteConsequence']
      .map((k) => locales[lang][k]).join(' ');
    expect(all).not.toMatch(/ZAP|WebCheck|urlscan|Observatory|PageSpeed|Gemini/i);
  }
});
