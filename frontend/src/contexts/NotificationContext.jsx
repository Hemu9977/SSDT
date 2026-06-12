/**
 * Notification Context
 * Manages Socket.IO connection and scan completion notifications.
 * 
 * Provides:
 * - Real-time Socket.IO connection (when user is logged in)
 * - Notification queue for scan completion popups
 * - addNotification / removeNotification methods
 * - Auto-dismiss after 8 seconds
 */

import { createContext, useContext, useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { io } from 'socket.io-client';
import { useUser } from './UserContext';
import { API_BASE } from '../config/api';

const NotificationContext = createContext();

export const useNotifications = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotifications must be used within a NotificationProvider');
  }
  return context;
};

export const NotificationProvider = ({ children }) => {
  const { user } = useUser();
  const [notifications, setNotifications] = useState([]);
  const socketRef = useRef(null);
  const notificationIdRef = useRef(0);
  const timerRefs = useRef({});
  // Map of scanId → callback for real-time scan:update events
  const scanListenersRef = useRef(new Map());

  // Remove a notification by ID
  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
    if (timerRefs.current[id]) {
      clearTimeout(timerRefs.current[id]);
      delete timerRefs.current[id];
    }
  }, []);

  // Add a persistent notification (no auto-dismiss)
  const addNotification = useCallback((notification) => {
    const id = ++notificationIdRef.current;
    const newNotification = { ...notification, id, createdAt: Date.now() };

    setNotifications(prev => [...prev, newNotification]);

    return id;
  }, []);

  // Clean up remaining timers on unmount
  useEffect(() => {
    return () => {
      Object.values(timerRefs.current).forEach(clearTimeout);
      timerRefs.current = {};
    };
  }, []);

  // Connect to Socket.IO when user is logged in
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token || !user) {
      // No token - disconnect if connected
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      return;
    }

    // --- FETCH UNREAD NOTIFICATIONS ON MOUNT ---
    const fetchUnread = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/notifications/unread`, {
          headers: { 'x-auth-token': token }
        });
        const data = await response.json();
        if (data.unread && Array.isArray(data.unread)) {
          data.unread.forEach(scan => {
            // Add as persistent notifications
            addNotification({
              type: 'scan_completed',
              scanId: scan.analysisId,
              scanType: scan.scanType || (scan.triggerSource === 'scheduled' ? 'Scheduled Scan' : 'Security Scan'),
              targetUrl: scan.target,
              triggerSource: scan.triggerSource,
              isScheduled: scan.triggerSource === 'scheduled',
              isPersistent: true // Mark as persistent from unread fetch
            });
          });
        }
      } catch (err) {
        console.error('❌ Failed to fetch unread notifications:', err);
      }
    };

    fetchUnread();

    // Create Socket.IO connection with auth token
    const socket = io(API_BASE, {
      auth: { token },
      // Force WebSocket-only.
      // Socket.IO long-polling fallback can create high-frequency HTTP traffic under load,
      // which worsens backend overload and competes with scan workers.
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 2000,
      reconnectionDelayMax: 10000,
      timeout: 20000
    });

    socket.on('connect', () => {
      console.log('🔌 Notification socket connected:', socket.id);

      // Re-join scan rooms after reconnect so scan replay works reliably.
      try {
        for (const scanId of scanListenersRef.current.keys()) {
          socket.emit('join:scan', { scanId });
        }
      } catch (_) {
        // best-effort
      }
    });

    socket.on('disconnect', (reason) => {
      console.log('🔌 Notification socket disconnected:', reason);
    });

    socket.on('connect_error', (error) => {
      console.warn('🔌 Notification socket connection error:', error.message);
    });

    // Listen for scan completion events (UI notification popup)
    socket.on('scan_completed', (data) => {
      console.log('📢 Scan completed notification received:', data);
      addNotification({
        type: 'scan_completed',
        scanId: data.scanId,
        scanType: data.scanType,
        targetUrl: data.targetUrl,
        triggerSource: data.triggerSource,
        isScheduled: data.isScheduled
      });
    });

    // Forward scan:update events to registered per-scan listeners
    socket.on('scan:update', (data) => {
      const { scanId } = data;
      if (scanId && scanListenersRef.current.has(scanId)) {
        scanListenersRef.current.get(scanId)(data);
      }
    });

    socketRef.current = socket;

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [user, addNotification]);

  /**
   * Register a listener for real-time scan:update events for a specific scan.
   * Also tells the server to join the scan:<scanId> room for tighter delivery.
   *
   * @param {string}   scanId   - The analysisId of the scan to watch
   * @param {Function} callback - Called with the full scan:update payload
   */
  const addScanListener = useCallback((scanId, callback) => {
    scanListenersRef.current.set(scanId, callback);
    // Ask the server to add us to the scan-specific Socket.IO room
    if (socketRef.current?.connected) {
      socketRef.current.emit('join:scan', { scanId });
    }
  }, []);

  /**
   * Unregister the scan:update listener for a scan (call on component unmount).
   */
  const removeScanListener = useCallback((scanId) => {
    scanListenersRef.current.delete(scanId);
  }, []);

  // Mark notification as read on backend
  const markAsRead = useCallback(async (analysisId) => {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      await fetch(`${API_BASE}/api/notifications/mark-read/${analysisId}`, {
        method: 'POST',
        headers: { 'x-auth-token': token }
      });
    } catch (err) {
      console.error('❌ Failed to mark notification as read:', err);
    }
  }, []);

  // Re-connect when token changes (login/logout)
  useEffect(() => {
    const handleStorageChange = (e) => {
      if (e.key === 'token') {
        // Token changed — force reconnect by triggering re-render
        if (socketRef.current) {
          socketRef.current.disconnect();
          socketRef.current = null;
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const value = useMemo(() => ({
    notifications,
    addNotification,
    removeNotification,
    markAsRead,
    addScanListener,
    removeScanListener
  }), [notifications, addNotification, removeNotification, markAsRead, addScanListener, removeScanListener]);

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
};
