// File path: frontend/src/App.js

import { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

import SplashScreen from './components/SplashScreen';
import LandingPage from './pages/LandingPage';
// Updated import paths
import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import OTPVerification from './pages/auth/OTPVerification';
import ForgotPasswordPage from './pages/auth/ForgotPasswordPage';
import ResetPasswordPage from './pages/auth/ResetPasswordPage';
import Profile from './pages/Profile';
import Dashboard from './pages/Dashboard';
import ScanViewer from './pages/ScanViewer';
import ScheduledScans from './pages/ScheduledScans';
import JoinOrganization from './pages/JoinOrganization';
// Translation imports
import { TranslationProvider } from './contexts/TranslationContext';
import { UserProvider, useUser } from './contexts/UserContext';
// Notification imports
import { NotificationProvider } from './contexts/NotificationContext';
function AppContent() {
  const [showSplash, setShowSplash] = useState(true);
  const { loading } = useUser();

  const handleSplashComplete = () => {
    setShowSplash(false);
  };

  // Show splash screen on first load
  if (showSplash) {
    return <SplashScreen onEnter={handleSplashComplete} />;
  }

  return (
    <div>
      <TranslationProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/verify-otp" element={<OTPVerification />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/scan/:analysisId" element={<ScanViewer />} />
            <Route path="/schedules" element={<ScheduledScans />} />
            <Route path="/join" element={<JoinOrganization />} />
          </Routes>
        </BrowserRouter>
      </TranslationProvider>
    </div>
  );
}

function App() {
  return (
    <UserProvider>
      <NotificationProvider>
        <AppContent />
      </NotificationProvider>
    </UserProvider>
  );
}

export default App;