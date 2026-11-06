import React from 'react';
import { useTranslation } from '../contexts/TranslationContext';
import { FORTEXA_EGRESS_IP } from '../config/egress';

// Written identically in en.js and ja.js, so they are highlighted in both languages.
const PORT_TOKENS = ['80 (HTTP)', '443 (HTTPS)'];

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Wrap each occurrence of `tokens` in `text` in a highlighted span. */
function highlight(text, tokens, className) {
  const pattern = new RegExp(`(${tokens.map(escapeRegExp).join('|')})`, 'g');
  return text.split(pattern).map((part, i) => (
    tokens.includes(part) ? <span key={i} className={className}>{part}</span> : part
  ));
}

/**
 * "IP Restrictions / Firewall Allowlisting" bullet for the "Before You Start"
 * notice on both scan forms. `block` is the notice's BEM block class
 * (`auth-scan-note` or `scan-note`); see styles/_scanNote.scss.
 */
export default function IpAllowlistNote({ block }) {
  const { t } = useTranslation();
  const value = `${block}__value`;
  const para = `${block}__para`;
  return (
    <li>
      <strong>{t('ipAllowlistNoteTitle')}</strong>{' '}
      {highlight(t('ipAllowlistNoteAccess', { ip: FORTEXA_EGRESS_IP }), [FORTEXA_EGRESS_IP], value)}
      <span className={para}>{highlight(t('ipAllowlistNotePorts'), PORT_TOKENS, value)}</span>
      <span className={para}>{t('ipAllowlistNoteConsequence')}</span>
    </li>
  );
}
