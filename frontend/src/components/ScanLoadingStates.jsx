/**
 * Loading / pending / completed / failed presentation for the scan report.
 *
 * Used by both Hero.jsx (normal scan) and AuthenticatedScanPanel.jsx
 * (authenticated scan), so the two report pages cannot drift apart. The state
 * each piece shows comes from utils/scanToolState.js; this file only renders it.
 *
 * Copy is neutral by design: no scanner or engine name ever appears here
 * (see "UI Language Policy" in CLAUDE.md).
 */
import React, { useEffect, useState } from 'react';
import {
  FaBrain,
  FaBug,
  FaExclamationTriangle,
  FaLock,
  FaRegClock,
  FaSatelliteDish,
  FaTachometerAlt,
} from 'react-icons/fa';
import { useTranslation } from '../contexts/TranslationContext';
import { TOOL_STATE } from '../utils/scanToolState';
import '../styles/ScanLoading.scss';

const TOOL_ICONS = {
  vulnerability: FaBug,
  performance: FaTachometerAlt,
  securityConfig: FaLock,
  threatIntel: FaSatelliteDish,
};

// Literal keys so the locale-parity test can see every one of them.
const toolLoadingMessage = (tool, t) => {
  switch (tool) {
    case 'vulnerability': return t('toolLoadingVulnerability');
    case 'performance': return t('toolLoadingPerformance');
    case 'securityConfig': return t('toolLoadingSecurityConfig');
    case 'threatIntel': return t('toolLoadingThreatIntel');
    default: return t('scanning');
  }
};

function ToolStatus({ tool, status }) {
  const { t } = useTranslation();

  if (status.state === TOOL_STATE.PENDING) {
    return (
      <div className="tool-status tool-status--pending" role="status">
        <span className="tool-status__label">
          <FaRegClock aria-hidden="true" /> {t('pending')}
        </span>
        <p className="tool-status__message">{t('toolPendingQueued')}</p>
      </div>
    );
  }

  if (status.state === TOOL_STATE.FAILED) {
    const isFailure = status.reason === 'failed';
    return (
      <div className={`tool-status tool-status--failed tool-status--${isFailure ? 'error' : 'warning'}`} role="status">
        <span className="tool-status__label">
          <FaExclamationTriangle aria-hidden="true" /> {isFailure ? t('scanFailed') : t('unavailable')}
        </span>
      </div>
    );
  }

  // Loading. A determinate bar only when the backend reported real progress.
  const progress = status.progress ?? null;
  return (
    <div className="tool-status tool-status--loading" role="status">
      <p className="tool-status__message">{toolLoadingMessage(tool, t)}</p>
      {progress != null ? (
        <>
          <div
            className="tool-status__track"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
          >
            <span className="tool-status__bar" style={{ width: `${progress}%` }} />
          </div>
          <span className="tool-status__meta">{progress}%</span>
        </>
      ) : (
        <div className="tool-status__track" aria-hidden="true">
          <span className="tool-status__bar tool-status__bar--indeterminate" />
        </div>
      )}
    </div>
  );
}

/**
 * A report score card for one diagnostic tool.
 *
 * `children` is a render function, called only once the tool has completed, so
 * the result markup can dereference its data without guarding against null.
 */
export function ScanToolCard({ tool, title, status, children }) {
  const Icon = TOOL_ICONS[tool] || FaBug;
  const isCompleted = status.state === TOOL_STATE.COMPLETED;

  return (
    <div
      className={`score-card scan-tool-card scan-tool-card--${status.state}`}
      aria-busy={status.state === TOOL_STATE.LOADING ? 'true' : undefined}
      data-tool={tool}
      data-state={status.state}
    >
      <div className="scan-tool-card__head">
        <span className="scan-tool-card__icon" aria-hidden="true"><Icon /></span>
        <h4 className="score-card__title">{title}</h4>
      </div>
      {isCompleted ? (
        <div className="scan-tool-card__result">{children()}</div>
      ) : (
        <ToolStatus tool={tool} status={status} />
      )}
    </div>
  );
}

const MESSAGE_ROTATION_MS = 4000;

/**
 * The AI summary's waiting state. `state` comes from getAiSummaryState();
 * pass `translating` while a finished summary is being translated.
 */
export function AiSummaryLoader({ state, translating = false }) {
  const { t } = useTranslation();
  const stage = translating ? 'translating' : state?.stage;
  const collecting = stage === 'collecting';

  // While inputs are still arriving, alternate between two descriptions of the
  // same work. This is wording only — progress is shown by the real count below.
  const [phrase, setPhrase] = useState(0);
  useEffect(() => {
    if (!collecting) return undefined;
    const id = setInterval(() => setPhrase((p) => (p + 1) % 2), MESSAGE_ROTATION_MS);
    return () => clearInterval(id);
  }, [collecting]);

  if (stage === 'unavailable') {
    return (
      <div className="ai-loader ai-loader--unavailable" role="status">
        <span className="ai-loader__static-icon" aria-hidden="true"><FaExclamationTriangle /></span>
        <p className="ai-loader__message">{t('aiSummaryUnavailable')}</p>
      </div>
    );
  }

  let message;
  let stableMessage;
  let hint = null;
  if (stage === 'translating') {
    message = stableMessage = t('translatingReportToJapanese');
  } else if (stage === 'composing') {
    message = stableMessage = t('aiLoadingPreparing');
    hint = t('aiLoadingAllReceived');
  } else {
    stableMessage = t('aiLoadingAnalyzing');
    message = phrase === 0 ? stableMessage : t('aiLoadingCorrelating');
    hint = t('aiLoadingHint');
  }

  const settled = state?.settled ?? 0;
  const total = state?.total ?? 0;

  return (
    <div className={`ai-loader ai-loader--${stage}`} role="status" aria-live="polite">
      <div className="ai-loader__orb" aria-hidden="true">
        <svg className="ai-loader__ring" viewBox="0 0 48 48" focusable="false">
          <circle className="ai-loader__ring-track" cx="24" cy="24" r="21" />
          <circle className="ai-loader__ring-arc" cx="24" cy="24" r="21" />
        </svg>
        <FaBrain className="ai-loader__icon" />
      </div>
      <div className="ai-loader__text">
        {/* The rotating line is hidden from assistive tech; it hears the stable one. */}
        <span className="scan-loading-sr">{stableMessage}</span>
        <p className="ai-loader__message" key={message} aria-hidden="true">{message}</p>
        {hint && <p className="ai-loader__hint">{hint}</p>}
        {collecting && total > 0 && (
          <div className="ai-loader__inputs">
            <div className="ai-loader__segments" aria-hidden="true">
              {Array.from({ length: total }, (_, i) => (
                <span key={i} className={`ai-loader__segment${i < settled ? ' is-done' : ''}`} />
              ))}
            </div>
            <span className="ai-loader__count">{t('aiLoadingInputs', { completed: settled, total })}</span>
          </div>
        )}
      </div>
      {/* Painted last, over the text: an animated layer *under* text forces the
          text onto its own compositor layer, which Chrome rasterizes blurry. */}
      <div className="ai-loader__sheen" aria-hidden="true" />
    </div>
  );
}

/** Wraps content that just replaced a loading state, so it fades in. */
export function LoadedReveal({ children, className = '' }) {
  return <div className={`scan-loaded-reveal ${className}`.trim()}>{children}</div>;
}
