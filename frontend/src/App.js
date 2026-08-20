// File path: frontend/src/App.js

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import LandingPage from './pages/LandingPage';
// Updated import paths
import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import OTPVerification from './pages/auth/OTPVerification';
import ForgotPasswordPage from './pages/auth/ForgotPasswordPage';
import ResetPasswordPage from './pages/auth/ResetPasswordPage';
import Profile from './pages/Profile';
import ScanViewer from './pages/ScanViewer';

import ScheduledScans from './pages/ScheduledScans';
import JoinOrganization from './pages/JoinOrganization';
import AdminPanel from './pages/Admin/AdminPanel';
import RequireAdmin from './components/RequireAdmin';

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
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/verify-otp" element={<OTPVerification />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/scan/:analysisId" element={<ScanViewer />} />
          <Route path="/schedules" element={<ScheduledScans />} />
          <Route path="/join" element={<JoinOrganization />} />
          <Route
            path="/admin"
            element={<RequireAdmin><AdminPanel /></RequireAdmin>}
          />

          {/* The standalone /about page was folded into MarketingHome, but the
              URL was public and is in the sitemap history — keep it resolving
              instead of rendering nothing. */}
          <Route path="/about" element={<Navigate to="/" replace />} />

          {/* Catch-all. Without it an unmatched path rendered a blank page,
              which is what /dashboard, /reports, /history and /settings all did
              once their routes were removed. */}
          <Route path="*" element={<Navigate to="/" replace />} />
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
