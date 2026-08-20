/**
 * ScheduleScanModal
 * Modal for creating and editing scheduled scans.
 * Supports instant, one-time, and recurring modes.
 */

import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useUser } from '../contexts/UserContext';
import { useTranslation } from '../contexts/TranslationContext';
import '../styles/ScheduleScanModal.scss';
import { API_BASE } from '../config/api';

const CustomCalendar = ({ value, onChange, label, t }) => {
  const [showPicker, setShowPicker] = useState(false);
  const parseLocalDate = (isoDate) => {
    if (!isoDate) return null;
    // Treat YYYY-MM-DD as a local date (avoid UTC parsing shifts)
    const d = new Date(`${isoDate}T00:00`);
    return Number.isNaN(d.getTime()) ? null : d;
  };

  const [viewDate, setViewDate] = useState(() => parseLocalDate(value) || new Date());
  const selectedDate = parseLocalDate(value);
  const containerRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setShowPicker(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const daysInMonth = (year, month) => new Date(year, month + 1, 0).getDate();
  const firstDayOfMonth = (year, month) => new Date(year, month, 1).getDay();

  const handlePrevMonth = (e) => {
    e.stopPropagation();
    setViewDate(new Date(viewDate.getFullYear(), viewDate.getMonth() - 1, 1));
  };

  const handleNextMonth = (e) => {
    e.stopPropagation();
    setViewDate(new Date(viewDate.getFullYear(), viewDate.getMonth() + 1, 1));
  };

  const pad2 = (n) => String(n).padStart(2, '0');

  const handleSelectDate = (day) => {
    const year = viewDate.getFullYear();
    const month = viewDate.getMonth() + 1;
    const isoDate = `${year}-${pad2(month)}-${pad2(day)}`;
    onChange(isoDate);
    setShowPicker(false);
  };

  const renderDays = () => {
    const days = [];
    const totalDays = daysInMonth(viewDate.getFullYear(), viewDate.getMonth());
    const startDay = firstDayOfMonth(viewDate.getFullYear(), viewDate.getMonth());

    // Padding for first week
    for (let i = 0; i < startDay; i++) {
      days.push(<div key={`empty-${i}`} className="calendar-day empty" />);
    }

    for (let d = 1; d <= totalDays; d++) {
      const isSelected = selectedDate && 
                        selectedDate.getDate() === d && 
                        selectedDate.getMonth() === viewDate.getMonth() && 
                        selectedDate.getFullYear() === viewDate.getFullYear();
      const isToday = new Date().toDateString() === new Date(viewDate.getFullYear(), viewDate.getMonth(), d).toDateString();
      
      days.push(
        <button
          key={d}
          type="button"
          className={`calendar-day ${isSelected ? 'selected' : ''} ${isToday ? 'today' : ''}`}
          onClick={() => handleSelectDate(d)}
        >
          {d}
        </button>
      );
    }
    return days;
  };

  const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

  return (
    <div className={`custom-calendar-wrapper ${showPicker ? 'picker-open' : ''}`} ref={containerRef}>
      <label>{label}</label>
      <div className="calendar-input-trigger" onClick={() => setShowPicker(!showPicker)}>
        <span className="current-value">{value || t('selectDate')}</span>
        <span className="calendar-icon">📅</span>
      </div>
      
      <AnimatePresence>
        {showPicker && (
          <motion.div 
            className="calendar-dropdown"
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            <div className="calendar-header">
              <button type="button" onClick={handlePrevMonth}>&lt;</button>
              <div className="month-year">
                {monthNames[viewDate.getMonth()]} {viewDate.getFullYear()}
              </div>
              <button type="button" onClick={handleNextMonth}>&gt;</button>
            </div>
            <div className="calendar-weekdays">
              {['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'].map(d => <div key={d}>{d}</div>)}
            </div>
            <div className="calendar-grid">
              {renderDays()}
            </div>
            <button type="button" className="calendar-today-btn" onClick={() => {
              const now = new Date();
              setViewDate(new Date(now.getFullYear(), now.getMonth(), 1));
              const isoDate = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}`;
              onChange(isoDate);
              setShowPicker(false);
            }}>{t('today')}</button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const ScrollingTimePicker = ({ value, onChange, label, t }) => {
  // Parse initial value (HH:mm)
  const h24 = parseInt((value || '10:00').split(':')[0]);
  const m = parseInt((value || '10:00').split(':')[1]);
  const initialPeriod = h24 >= 12 ? 'PM' : 'AM';
  const initialHour = h24 % 12 || 12;

  const [hour, setHour] = useState(initialHour);
  const [minute, setMinute] = useState(m);
  const [period, setPeriod] = useState(initialPeriod);

  // Update parent when local state changes
  useEffect(() => {
    let finalHour = hour;
    if (period === 'PM' && hour < 12) finalHour += 12;
    if (period === 'AM' && hour === 12) finalHour = 0;
    
    const formattedTime = `${String(finalHour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
    if (formattedTime !== value) {
      onChange(formattedTime);
    }
  }, [hour, minute, period, onChange, value]);

  const hours = Array.from({ length: 12 }, (_, i) => i + 1);
  const minutesArr = Array.from({ length: 60 }, (_, i) => i);

  return (
    <div className="scrolling-time-picker">
      <label>{label}</label>
      <div className="picker-container">
        {/* Hours */}
        <div className="picker-column hour-column">
          <div className="column-label">HH</div>
          <div className="scroll-area">
            {hours.map(h => (
              <button
                key={h}
                type="button"
                className={`picker-item ${hour === h ? 'active' : ''}`}
                onClick={() => setHour(h)}
              >
                {String(h).padStart(2, '0')}
              </button>
            ))}
          </div>
        </div>

        <div className="picker-separator">:</div>

        {/* Minutes */}
        <div className="picker-column minute-column">
          <div className="column-label">MM</div>
          <div className="scroll-area">
            {minutesArr.map(mm => (
              <button
                key={mm}
                type="button"
                className={`picker-item ${minute === mm ? 'active' : ''}`}
                onClick={() => setMinute(mm)}
              >
                {String(mm).padStart(2, '0')}
              </button>
            ))}
          </div>
        </div>

        {/* AM/PM */}
        <div className="picker-column period-column">
          <div className="column-label">AM/PM</div>
          <div className="period-toggle">
            <button
              type="button"
              className={`picker-item ${period === 'AM' ? 'active' : ''}`}
              onClick={() => setPeriod('AM')}
            >
              AM
            </button>
            <button
              type="button"
              className={`picker-item ${period === 'PM' ? 'active' : ''}`}
              onClick={() => setPeriod('PM')}
            >
              PM
            </button>
          </div>
        </div>
      </div>
      <div className="picker-selected-value">
        {t('selectedTime', { time: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')} ${period}` })}
      </div>
    </div>
  );
};

const ScheduleScanModal = ({ isOpen, onClose, onScheduleCreated, editSchedule = null, defaultScanType = 'public' }) => {
  const navigate = useNavigate();
  const [scanType, setScanType] = useState(defaultScanType);
  const [mode, setMode] = useState('one-time'); // 'one-time', 'recurring'
  const [scheduledDate, setScheduledDate] = useState('');
  const [scheduledTime, setScheduledTime] = useState('10:00');
  const [frequency, setFrequency] = useState('monthly');
  const [selectedDays, setSelectedDays] = useState([1]);
  const [recurringTime, setRecurringTime] = useState('10:00');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const { isPro } = useUser();
  const { t } = useTranslation();

  const resetForm = React.useCallback(() => {
    setScanType(defaultScanType);
    setMode('one-time');
    setScheduledDate('');
    setScheduledTime('10:00');
    setFrequency('monthly');
    setSelectedDays([1]);
    setRecurringTime('10:00');
    setError('');
    setSuccess('');
  }, [defaultScanType]);

  // Pre-fill when editing
  useEffect(() => {
    if (editSchedule) {
      setScanType(editSchedule.scanType || 'public');
      setMode(editSchedule.scheduleType || 'one-time');

      if (editSchedule.scheduleType === 'one-time' && editSchedule.scheduledAt) {
        const d = new Date(editSchedule.scheduledAt);
        setScheduledDate(d.toISOString().split('T')[0]);
        setScheduledTime(d.toTimeString().slice(0, 5));
      }

      if (editSchedule.scheduleType === 'recurring' && editSchedule.recurring) {
        setFrequency(editSchedule.recurring.frequency || 'monthly');
        setSelectedDays(editSchedule.recurring.days || [1]);
        setRecurringTime(editSchedule.recurring.time || '10:00');
      }
    } else {
      resetForm();
    }
  }, [editSchedule, isOpen, resetForm]);

  const handleFrequencyChange = (freq) => {
    setFrequency(freq);
    if (freq === 'monthly') setSelectedDays([1]);
    else if (freq === 'twice-monthly') setSelectedDays([1, 15]);
  };

  const toggleDay = (day) => {
    setSelectedDays(prev => {
      if (prev.includes(day)) {
        return prev.filter(d => d !== day);
      }
      return [...prev, day].sort((a, b) => a - b);
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    const token = localStorage.getItem('token');
    if (!token) {
      setError(t('pleaseLoginSchedule'));
      setLoading(false);
      return;
    }

    // Build request body or config
    const configData = {
      scanType,
      scheduleType: mode,
    };

    if (mode === 'one-time') {
      if (!scheduledDate || !scheduledTime) {
        setError(t('pleaseSelectDateTime'));
        setLoading(false);
        return;
      }

      const scheduledLocal = new Date(`${scheduledDate}T${scheduledTime}`);
      if (Number.isNaN(scheduledLocal.getTime())) {
        setError(t('invalidDateTime'));
        setLoading(false);
        return;
      }
      const now = new Date();
      if (scheduledLocal <= now) {
        setError(t('scheduledTimeFuture'));
        setLoading(false);
        return;
      }

      const maxAllowed = new Date(now);
      maxAllowed.setMonth(maxAllowed.getMonth() + 1);
      if (scheduledLocal > maxAllowed) {
        setError(t('scheduledTimeWithinMonth'));
        setLoading(false);
        return;
      }

      configData.scheduledAt = scheduledLocal.toISOString();
      configData.date = scheduledDate;
      configData.time = scheduledTime;
    }

    if (mode === 'recurring') {
      if (selectedDays.length === 0) {
        setError(t('pleaseSelectDay'));
        setLoading(false);
        return;
      }
      configData.recurring = {
        frequency,
        days: selectedDays,
        time: recurringTime
      };
    }

    if (!editSchedule) {
      sessionStorage.setItem('pendingScheduleConfig', JSON.stringify(configData));
      setSuccess(t('configSavedRedirecting'));
      
      setTimeout(() => {
        resetForm();
        onClose();
        if (scanType === 'public') {
          navigate('/?type=normal&mode=schedule');
        } else {
          navigate('/?type=auth&mode=schedule');
        }
      }, 800);
      return;
    }

    // Save schedule (create or edit)
    try {
      const url = `${API_BASE}/api/schedules/${editSchedule.id}`;
      
      const method = 'PUT';

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'x-auth-token': token
        },
        body: JSON.stringify(configData)
      });

      const data = await res.json();

      if (!res.ok) {
        // data.error is English server text — carry a key, not the prose.
        throw Object.assign(new Error('save schedule failed'), { messageKey: 'failedSaveSchedule' });
      }

      setSuccess(editSchedule ? t('scheduleUpdated') : t('scanScheduledSuccess'));
      if (onScheduleCreated) onScheduleCreated(data.schedule);

      setTimeout(() => {
        resetForm();
        onClose();
      }, 1200);

    } catch (err) {
      setError(t(err.messageKey || 'failedSaveSchedule'));
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        className="schedule-modal-overlay"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <motion.div
          className={`schedule-modal ${isPro ? 'pro-theme' : ''}`}
          initial={{ opacity: 0, scale: 0.9, y: 30 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 30 }}
          transition={{ type: 'spring', stiffness: 300, damping: 25 }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="schedule-modal__header">
            <h2>{editSchedule ? t('editSchedule') : t('scheduleAScan')}</h2>
            <button className="schedule-modal__close" onClick={onClose}>&times;</button>
          </div>

          <form onSubmit={handleSubmit} style={{ display: 'contents' }}>
            <div className="schedule-modal__form">
              {/* Display Read-Only URL when editing */}
              {editSchedule && editSchedule.targetUrl && (
                <div className="form-group">
                  <label>{t('targetUrlReadOnly')}</label>
                  <input
                    type="url"
                    value={editSchedule.targetUrl}
                    disabled
                    className="url-input readonly"
                  />
                </div>
              )}

              {/* Mode Selector */}
              <div className="form-group">
                <label>{t('scheduleMode')}</label>
                <div className="mode-selector">
                  <button
                    type="button"
                    className={`mode-btn ${mode === 'one-time' ? 'active' : ''}`}
                    onClick={() => setMode('one-time')}
                  >
                    <span className="mode-label">{t('oneTime')}</span>
                    <span className="mode-desc">{t('pickDateTime')}</span>
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${mode === 'recurring' ? 'active' : ''}`}
                    onClick={() => setMode('recurring')}
                  >
                    <span className="mode-label">{t('recurring')}</span>
                    <span className="mode-desc">{t('autoRepeat')}</span>
                  </button>
                </div>
              </div>

              {/* One-Time: Date/Time Picker */}
              {mode === 'one-time' && (
                <div className="form-row">
                  <div className="form-group half">
                    <CustomCalendar
                      label={t('date')}
                      value={scheduledDate}
                      onChange={setScheduledDate}
                      t={t}
                    />
                  </div>
                  <div className="form-group half">
                    <ScrollingTimePicker
                      label={t('time')}
                      value={scheduledTime}
                      onChange={setScheduledTime}
                      t={t}
                    />
                  </div>
                </div>
              )}

              {/* Recurring: Frequency + Days + Time */}
              {mode === 'recurring' && (
                <div className="recurring-config">
                  <div className="form-group">
                    <label>{t('frequency')}</label>
                    <div className="frequency-selector">
                      {['monthly', 'twice-monthly', 'custom'].map(freq => (
                        <button
                          key={freq}
                          type="button"
                          className={`freq-btn ${frequency === freq ? 'active' : ''}`}
                          onClick={() => handleFrequencyChange(freq)}
                        >
                          {t(freq === 'twice-monthly' ? 'twiceMonthly' : freq)}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="form-group">
                    <label>{t('daysOfMonth')}</label>
                    <div className="day-picker">
                      {Array.from({ length: 31 }, (_, i) => i + 1).map(day => (
                        <button
                          key={day}
                          type="button"
                          className={`day-btn ${selectedDays.includes(day) ? 'active' : ''}`}
                          onClick={() => toggleDay(day)}
                        >
                          {day}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="form-group">
                    <ScrollingTimePicker
                      label={t('executionTime')}
                      value={recurringTime}
                      onChange={setRecurringTime}
                      t={t}
                    />
                  </div>
                </div>
              )}

              {/* Error / Success Messages */}
              {error && <div className="schedule-error" style={{ color: '#ff4d6a', padding: '10px', fontSize: '0.9rem' }}>{error}</div>}
              {success && <div className="schedule-success" style={{ color: '#00d084', padding: '10px', fontSize: '0.9rem' }}>{success}</div>}
            </div>

            <div className="schedule-modal__actions">
              <button type="button" className="btn-cancel" onClick={onClose}>{t('cancel')}</button>
              <button type="submit" className="btn-submit" disabled={loading}>
                {loading ? t('processing') : (editSchedule ? t('updateSchedule') : t('continueToConfig'))}
              </button>
            </div>
          </form>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default ScheduleScanModal;
