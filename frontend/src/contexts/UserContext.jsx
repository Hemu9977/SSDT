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
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('user_data');
    return saved ? JSON.parse(saved) : null;
  });
  const [organization, setOrganization] = useState(null);
  const [limits, setLimits] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isPro, setIsPro] = useState(() => {
    return localStorage.getItem('is_pro_user') === 'true';
  });

  const fetchUserProfile = useCallback(async () => {
    const token = localStorage.getItem('token');

    if (!token) {
      setLoading(false);
      setIsPro(false);
      setUser(null);
      localStorage.removeItem('is_pro_user');
      localStorage.removeItem('user_data');
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
          localStorage.removeItem('token');
          localStorage.removeItem('is_pro_user');
          localStorage.removeItem('user_data');
        }
        throw new Error('Failed to fetch profile');
      }

      const data = await res.json();
      console.log('✅ UserContext: Profile fetched', data.user?.name);

      const userData = data.user;
      const orgData = userData?.organization || null;

      // isPro: Strictly true ONLY for the 'pro' plan tier for theming purposes.
      // Light/Basic users will now correctly see the Orange theme.
      const currentPlanType = orgData ? orgData.planType : userData?.planType;
      const isActive = orgData ? orgData.subscriptionStatus === 'active' : userData?.isPro;
      const proStatus = isActive && currentPlanType === 'pro';

      console.log('🟣 UserContext: isPro (theme) =', proStatus, '| planType =', currentPlanType);


      setUser(userData);
      setOrganization(orgData);
      setLimits(data.limits || null);
      setIsPro(proStatus);
      setLoading(false);

      // Persist to localStorage for hydration on next refresh
      localStorage.setItem('is_pro_user', proStatus.toString());
      localStorage.setItem('user_data', JSON.stringify(userData));
    } catch (err) {
      console.error('Failed to fetch user profile:', err);
      setLoading(false);
      // Don't clear localStorage on network error to keep theme stable
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
