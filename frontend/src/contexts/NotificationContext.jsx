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

import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { io } from 'socket.io-client';
import { useUser } from './UserContext';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:3001';

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
    if (!token) {
      // No token - disconnect if connected
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      return;
    }

    // Create Socket.IO connection with auth token
    const socket = io(API_BASE, {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 2000
    });

    socket.on('connect', () => {
      console.log('🔌 Notification socket connected:', socket.id);
    });

    socket.on('disconnect', (reason) => {
      console.log('🔌 Notification socket disconnected:', reason);
    });

    socket.on('connect_error', (error) => {
      console.warn('🔌 Notification socket connection error:', error.message);
    });

    // Listen for scan completion events
    socket.on('scan_completed', (data) => {
      console.log('📢 Scan completed notification received:', data);
      addNotification({
        type: 'scan_completed',
        scanId: data.scanId,
        scanType: data.scanType,
        targetUrl: data.targetUrl,
        completedAt: data.completedAt
      });
    });

    socketRef.current = socket;

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [addNotification, user]);

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

  const value = {
    notifications,
    addNotification,
    removeNotification
  };

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
};
