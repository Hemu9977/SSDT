import { createContext, useContext, useState, useEffect, useCallback } from 'react';

// Define API Base URL - proxy doesn't work reliably in development
const API_BASE = 'http://localhost:3001';

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
  const [organization, setOrganization] = useState(null);
  const [limits, setLimits] = useState(null);
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
        console.error('❌ UserContext: Failed to fetch profile, status:', res.status);
        if (res.status === 401) {
          console.error('❌ UserContext: 401 Unauthorized — token may be invalid or expired');
        }
        throw new Error('Failed to fetch profile');
      }

      const data = await res.json();
      console.log('✅ UserContext: Profile fetched', data.user?.name);

      const userData = data.user;
      const orgData = userData?.organization || null;

      // isPro: true for ANY active paid plan (light, basic, pro, or one-time with scans remaining).
      // Primary: org subscription status (most reliable after webhook fires).
      // Fallback: backend-computed user.isPro field (covers edge case before org is created).
      let proStatus = false;
      if (orgData) {
        proStatus = orgData.subscriptionStatus === 'active';
      } else {
        // Backend user.isPro is now plan-agnostic (fixed) — safe to use as fallback
        proStatus = userData?.isPro || false;
      }

      console.log('🟣 UserContext: isPro =', proStatus, '| org subscriptionStatus =', orgData?.subscriptionStatus);

      setUser(userData);
      setOrganization(orgData);
      setLimits(data.limits || null);
      setIsPro(proStatus);
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
    return fetchUserProfile();
  }, [fetchUserProfile]);

  const value = {
    user,
    organization,  // org-level plan/quota data
    limits,         // account limits from profile
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
