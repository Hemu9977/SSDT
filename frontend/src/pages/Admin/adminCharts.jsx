// frontend/src/pages/Admin/adminCharts.jsx
// Dependency-free chart primitives — pure SVG/CSS. The site deliberately has
// no chart library (recharts was removed in favor of pure-CSS visualizations,
// see CLAUDE.md); these two components extend that same convention rather
// than introducing a new one.

import React from 'react';

// Shared color assignment for plan badges — used by both the Overview and
// Analytics tabs so a given plan always renders in the same color everywhere.
export const PLAN_COLOR = {
  pro:    { bg: 'rgba(168,85,247,0.15)', color: '#a855f7', border: 'rgba(168,85,247,0.4)' },
  basic:  { bg: 'rgba(59,130,246,0.15)', color: '#3b82f6', border: 'rgba(59,130,246,0.4)' },
  light:  { bg: 'rgba(255,185,0,0.15)',  color: '#ffb900', border: 'rgba(255,185,0,0.4)' },
  trial1: { bg: 'rgba(0,208,132,0.12)',  color: '#00d084', border: 'rgba(0,208,132,0.3)' },
  trial2: { bg: 'rgba(0,208,132,0.12)',  color: '#00d084', border: 'rgba(0,208,132,0.3)' },
  free:   { bg: 'rgba(127,186,0,0.12)',  color: '#7fba00', border: 'rgba(127,186,0,0.3)' },
  null:   { bg: 'rgba(156,163,175,0.12)',color: '#9ca3af', border: 'rgba(156,163,175,0.3)' },
};

// Matches the same status colors used by .scan-status elsewhere (Profile.scss).
export const SUBSCRIPTION_STATUS_COLOR = {
  active:   { bg: 'rgba(0,208,132,0.15)',  color: '#00d084', border: 'rgba(0,208,132,0.3)' },
  canceled: { bg: 'rgba(232,17,35,0.15)',  color: '#e81123', border: 'rgba(232,17,35,0.3)' },
  past_due: { bg: 'rgba(255,185,0,0.15)',  color: '#ffb900', border: 'rgba(255,185,0,0.3)' },
  trialing: { bg: 'rgba(0,176,198,0.15)',  color: '#00b0c6', border: 'rgba(0,176,198,0.3)' },
  null:     { bg: 'rgba(156,163,175,0.12)',color: '#9ca3af', border: 'rgba(156,163,175,0.3)' },
};

// Sparkline-style area+line trend chart for a daily time series.
// `data` is [{ date, [valueKey]: number }, ...] in chronological order.
export const TrendLine = ({ data, valueKey = 'count', height = 64 }) => {
  if (!data || data.length === 0) return null;
  const values = data.map((d) => d[valueKey]);
  const max = Math.max(...values, 1);
  const width = 100;
  const stepX = data.length > 1 ? width / (data.length - 1) : 0;

  const points = data
    .map((d, i) => {
      const x = i * stepX;
      const y = height - (d[valueKey] / max) * height;
      return `${x},${y.toFixed(2)}`;
    })
    .join(' ');

  return (
    <svg
      className="admin-trend-line"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <polygon className="admin-trend-line-area" points={`0,${height} ${points} ${width},${height}`} />
      <polyline className="admin-trend-line-stroke" points={points} />
    </svg>
  );
};

// A horizontal bar-per-category distribution row (color badge + proportional
// bar + count) — generalizes the plan-distribution pattern already used on
// the Overview tab so it can render any label/value breakdown.
export const DistributionBars = ({ rows, total, renderLabel, renderColor, emptyText }) => {
  if (!rows || rows.length === 0) {
    return emptyText ? <p className="admin-empty">{emptyText}</p> : null;
  }
  return (
    <div className="admin-plan-list">
      {rows.map((row) => {
        const color = renderColor(row);
        return (
          <div key={row.key} className="admin-plan-row">
            <span
              className="admin-plan-badge"
              style={{ background: color.bg, color: color.color, border: `1px solid ${color.border}` }}
            >
              {renderLabel(row)}
            </span>
            <div className="admin-plan-bar-wrap">
              <div
                className="admin-plan-bar"
                style={{
                  width: `${total > 0 ? Math.min(100, (row.count / total) * 100) : 0}%`,
                  background: color.color,
                }}
              />
            </div>
            <span className="admin-plan-count">{row.displayValue ?? row.count}</span>
          </div>
        );
      })}
    </div>
  );
};
