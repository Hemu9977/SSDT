/**
 * ScanCompletionPopup
 * Renders real-time scan completion notifications in the top-right corner.
 * Uses Framer Motion for slide-in / fade-in animation.
 * Must be placed inside <BrowserRouter> and <NotificationProvider>.
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useNotifications } from '../contexts/NotificationContext';
import '../styles/ScanCompletionPopup.scss';

const ScanCompletionPopup = () => {
  const { notifications, removeNotification, markAsRead } = useNotifications();
  const navigate = useNavigate();

  const handleViewReport = (notification) => {
    removeNotification(notification.id);
    if (notification.isScheduled) {
      markAsRead(notification.scanId);
    }
    navigate(`/scan/${notification.scanId}${notification.isScheduled ? '?lang=en' : ''}`);
  };

  const handleDismiss = (notification) => {
    removeNotification(notification.id);
    if (notification.isScheduled) {
      markAsRead(notification.scanId);
    }
  };

  return (
    <div className="scan-notification-container" id="scan-notification-container">
      <AnimatePresence>
        {notifications.map((notification) => (
          <motion.div
            key={notification.id}
            className="scan-notification-popup"
            initial={{ opacity: 0, scale: 0.9, x: 100 }}
            animate={{ opacity: 1, scale: 1, x: 0 }}
            exit={{ opacity: 0, scale: 0.9, x: 100 }}
            transition={{ 
              type: 'spring', 
              stiffness: 300, 
              damping: 25,
              duration: 0.4
            }}
          >
            <div className="notification-content">
              <div className="notification-icon">
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" fill="var(--popup-accent, #00d084)" opacity="0.15" />
                  <path
                    d="M9 12l2 2 4-4"
                    stroke="var(--popup-accent, #00d084)"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <circle cx="12" cy="12" r="10" stroke="var(--popup-accent, #00d084)" strokeWidth="1.5" />
                </svg>
              </div>

              <div className="notification-text">
                <h4 className="notification-title">Scan Completed</h4>
                <p className="notification-message">
                  Your {notification.scanType || 'security scan'} for{' '}
                  <span className="notification-url">
                    {notification.targetUrl
                      ? new URL(notification.targetUrl).hostname
                      : 'target URL'}
                  </span>{' '}
                  has completed successfully.
                </p>
              </div>
            </div>

            <div className="notification-actions">
              <button
                className="notification-btn notification-btn-secondary"
                onClick={() => handleDismiss(notification)}
              >
                Dismiss
              </button>
              <button
                className="notification-btn notification-btn-primary"
                onClick={() => handleViewReport(notification)}
              >
                View Report
              </button>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};

export default ScanCompletionPopup;
