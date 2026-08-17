// File path: frontend/src/App.js

import { BrowserRouter, Routes, Route } from 'react-router-dom';

import LandingPage from './pages/LandingPage';
import About from './pages/About';
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
import { UserProvider } from './contexts/UserContext';
// Notification imports
import { NotificationProvider } from './contexts/NotificationContext';

// No splash gate here anymore: LandingPage (MarketingHome, for signed-out
// visitors) must be the first thing that renders at "/" — see
// components/MarketingHome.jsx for the unified entry experience that used to
// live behind a "Click to Enter" splash screen.
function AppContent() {
  return (
    <TranslationProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/about" element={<About />} />
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