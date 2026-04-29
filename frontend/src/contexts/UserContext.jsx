import { createContext, useContext, useState, useEffect, useCallback } from 'react';

import { API_BASE } from '../config/api';

const UserContext = createContext();

export const useUser = () => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};

export const UserProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isPro, setIsPro] = useState(false);

  const fetchUserProfile = useCallback(async () => {
    const token = localStorage.getItem('token');

    if (!token) {
      setLoading(false);
      setIsPro(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/profile`, {
        headers: {
          'x-auth-token': token
        }
      });

      if (!res.ok) {
        throw new Error('Failed to fetch profile');
      }

      const data = await res.json();
      console.log('✅ UserContext: Profile fetched', data.user);
      console.log('🟣 UserContext: isPro =', data.user.isPro);
      setUser(data.user);
      setIsPro(data.user.isPro || false);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch user profile:', err);
      setLoading(false);
      setIsPro(false);
    }
  }, []);

  useEffect(() => {
    console.log('🔵 UserContext: Fetching user profile...');
    fetchUserProfile();
  }, [fetchUserProfile]);

  // Refresh user data when token changes
  useEffect(() => {
    const handleStorageChange = () => {
      fetchUserProfile();
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [fetchUserProfile]);

  const refreshUser = useCallback(() => {
    fetchUserProfile();
  }, [fetchUserProfile]);

  const value = {
    user,
    isPro,
    loading,
    refreshUser
  };

  return (
    <UserContext.Provider value={value}>
      {children}
    </UserContext.Provider>
  );
};
