/**
 * ScheduledScans Page
 * Dashboard view for managing scheduled scans.
 * Uses the same layout as LandingPage (Header + ParticleBackground).
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Header from '../components/header';
import ParticleBackground from '../components/ParticleBackground';
import ScheduleScanModal from '../components/ScheduleScanModal';
import { useUser } from '../contexts/UserContext';
import '../styles/LandingPage.scss';
import '../styles/ScheduledScans.scss';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:3001';

const STATUS_CONFIG = {
  scheduled: { label: 'Scheduled', color: '#00b8d4', icon: '' },
  running:   { label: 'Running',   color: '#ffb900', icon: '' },
  completed: { label: 'Completed', color: '#00d084', icon: '' },
  failed:    { label: 'Failed',    color: '#ff4d6a', icon: '' },
};

const ScheduledScans = () => {
  const [schedules, setSchedules] = useState([]);
  const [limits, setLimits] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { isPro } = useUser();
  
  const searchParams = new URLSearchParams(location.search);
  const urlScanType = searchParams.get('type') || 'public';
  
  const handleCloseModal = () => {
    setModalOpen(false);
    setEditingSchedule(null);
  };

  const fetchSchedules = useCallback(async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/schedules`, {
        headers: { 'x-auth-token': token }
      });

      if (!res.ok) throw new Error('Failed to fetch schedules');

      const data = await res.json();
      setSchedules(data.schedules || []);
      setLimits(data.limits || {});
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    fetchSchedules();
    const interval = setInterval(fetchSchedules, 30000);
    return () => clearInterval(interval);
  }, [fetchSchedules]);

  const handleDelete = async (id) => {
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API_BASE}/api/schedules/${id}`, {
        method: 'DELETE',
        headers: { 'x-auth-token': token }
      });

      if (!res.ok) throw new Error('Failed to delete schedule');

      setSchedules(prev => prev.filter(s => s.id !== id));
      setDeleteConfirm(null);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleRunNow = async (id) => {
    const token = localStorage.getItem('token');
    try {
      const res = await fetch(`${API_BASE}/api/schedules/${id}/run-now`, {
        method: 'POST',
        headers: { 'x-auth-token': token }
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to trigger scan');

      fetchSchedules();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEdit = (schedule) => {
    setEditingSchedule(schedule);
    setModalOpen(true);
  };

  // Open the modal to configure a new schedule
  const handleNewSchedule = () => {
    setModalOpen(true);
  };

  const handleScheduleCreated = () => {
    fetchSchedules();
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  };

  const formatRecurring = (recurring) => {
    if (!recurring || !recurring.days) return '';
    const days = recurring.days.join(', ');
    return `Day${recurring.days.length > 1 ? 's' : ''} ${days} at ${recurring.time}`;
  };

  const isAuthTheme = isPro && (urlScanType === 'authenticated' || urlScanType === 'auth');

  return (
    <div className={`landing-page ${isAuthTheme || isPro ? 'pro-theme' : ''}`}>
      <ParticleBackground />
      <Header />
      <main>
        <div className={`schedules-page ${isAuthTheme || isPro ? 'pro-theme' : ''}`}>
          {/* Header */}
          <div className="schedules-header">
            <div className="schedules-header__left">
              <div>
                <h1>
                  Scheduled Scans
                </h1>
                <p className="schedules-subtitle">
                  Manage your one-time and recurring security scans
                </p>
              </div>
            </div>
            <button className="new-schedule-btn" onClick={handleNewSchedule} id="new-schedule-btn">
              + New Schedule
            </button>
          </div>

          {/* Plan Usage Stats */}
          <div className="plan-usage-bar">
            <div className="usage-stat">
              <span className="usage-label">Active Schedules</span>
              <span className="usage-value">
                {limits.activeSchedules || 0} / {limits.maxSchedules || 0}
              </span>
            </div>
            <div className="usage-progress">
              <div
                className="usage-progress-fill"
                style={{
                  width: `${Math.min(100, ((limits.activeSchedules || 0) / Math.max(1, limits.maxSchedules || 1)) * 100)}%`
                }}
              />
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="schedules-error">
              {error}
              <button onClick={() => setError('')}>✕</button>
            </div>
          )}

          {/* Loading */}
          {loading ? (
            <div className="schedules-loading">
              <div className="loading-spinner" />
              <p>Loading schedules...</p>
            </div>
          ) : schedules.length === 0 ? (
            /* Empty state */
            <div className="schedules-empty">
              <h3>No Scheduled Scans</h3>
              <p>Create your first scheduled scan to automatically run security tests on your targets.</p>
              <button className="new-schedule-btn" onClick={() => navigate('/')}>
                Go to Dashboard to Schedule
              </button>
            </div>
          ) : (
            /* Schedule List */
            <div className="schedules-list">
              <AnimatePresence>
                {schedules.map((schedule, index) => {
                  const status = STATUS_CONFIG[schedule.status] || STATUS_CONFIG.scheduled;
                  return (
                    <motion.div
                      key={schedule.id}
                      className={`schedule-card ${isAuthTheme ? 'pro-theme' : ''}`}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      transition={{ delay: index * 0.05 }}
                    >
                      <div className="schedule-card__main">
                        <div className="schedule-card__info">
                          <div className="schedule-card__url">
                            {schedule.targetUrl}
                          </div>
                          <div className="schedule-card__meta">
                            <span className={`badge badge--${schedule.scanType}`}>
                              {schedule.scanType === 'public' ? 'Public' : 'Auth'}
                            </span>
                            <span className="badge badge--type">
                              {schedule.scheduleType === 'recurring' ? 'Recurring' : 'One-Time'}
                            </span>
                            <span className="badge" style={{ borderColor: status.color, color: status.color }}>
                              {status.label}
                            </span>
                          </div>
                        </div>

                        <div className="schedule-card__timing">
                          {schedule.scheduleType === 'recurring' ? (
                            <div className="timing-info">
                              <span className="timing-label">Recurrence</span>
                              <span className="timing-value">{formatRecurring(schedule.recurring)}</span>
                            </div>
                          ) : null}
                          <div className="timing-info">
                            <span className="timing-label">Next Run</span>
                            <span className="timing-value">{formatDate(schedule.nextRun)}</span>
                          </div>
                          {schedule.lastRun && (
                            <div className="timing-info">
                              <span className="timing-label">Last Run</span>
                              <span className="timing-value">{formatDate(schedule.lastRun)}</span>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Failure info */}
                      {schedule.lastFailure?.reason && (
                        <div className="schedule-card__failure">
                          Last failure: {schedule.lastFailure.reason}
                        </div>
                      )}

                      {/* Actions */}
                      <div className="schedule-card__actions">
                        <button
                          className="action-btn action-btn--run"
                          onClick={() => handleRunNow(schedule.id)}
                          title="Run Now"
                        >
                          Run Now
                        </button>
                        <button
                          className="action-btn action-btn--edit"
                          onClick={() => handleEdit(schedule)}
                          title="Edit"
                        >
                          Edit
                        </button>
                        <button
                          className="action-btn action-btn--delete"
                          onClick={() => setDeleteConfirm(schedule.id)}
                          title="Delete"
                        >
                          Delete
                        </button>
                      </div>

                      {/* Delete confirmation */}
                      {deleteConfirm === schedule.id && (
                        <div className="delete-confirm">
                          <span>Delete this schedule?</span>
                          <button className="confirm-yes" onClick={() => handleDelete(schedule.id)}>Yes, Delete</button>
                          <button className="confirm-no" onClick={() => setDeleteConfirm(null)}>Cancel</button>
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          )}

          {/* Schedule Modal */}
          <ScheduleScanModal
            isOpen={modalOpen}
            onClose={handleCloseModal}
            onScheduleCreated={handleScheduleCreated}
            editSchedule={editingSchedule}
            defaultScanType={urlScanType}
          />
        </div>
      </main>
    </div>
  );
};

export default ScheduledScans;
