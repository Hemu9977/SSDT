import React, { useState, useEffect } from 'react';
import Sidebar from "../components/sidebar";
import Header from "../components/header";
import ScanForm from "../components/scanform";
import ReportCard from "../components/reportcard";

const API_BASE = 'http://localhost:3001';

const Dashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);

  // 🔥 ADD THIS
  const [scanResult, setScanResult] = useState(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const res = await fetch(`${API_BASE}/api/profile`, {
          headers: { 'x-auth-token': token }
        });
        if (res.ok) {
          const data = await res.json();
          setDashboardData(data);
        }
      } catch (err) {
        console.error('Failed to fetch dashboard data', err);
      } finally {
        setLoading(false);
      }
    };
    fetchDashboardData();
  }, []);

  // 🔥 ADD THIS ENTIRE BLOCK
  useEffect(() => {
    const handleScanCompleted = (event) => {
      console.log('✅ Scan result received:', event.detail);
      setScanResult(event.detail);
    };

    window.addEventListener('scanCompleted', handleScanCompleted);

    return () => {
      window.removeEventListener('scanCompleted', handleScanCompleted);
    };
  }, []);

  return (
    <div style={{ display: "flex", height: "100vh", backgroundColor: "#111827" }}>
      <Sidebar />
      <div style={{ flex: 1, padding: "20px", color: "white" }}>
        <Header />
        <ScanForm />

        {/* 🔥 SHOW SCAN RESULT */}
        {scanResult && (
          <div style={{ marginTop: '20px', background: '#1f2937', padding: '15px', borderRadius: '10px' }}>
            <h3>Scan Result</h3>
            <pre style={{ whiteSpace: 'pre-wrap' }}>
              {JSON.stringify(scanResult, null, 2)}
            </pre>
          </div>
        )}
        
        {loading ? (
          <div style={{ marginTop: '20px', color: '#a0aec0' }}>Loading dashboard data...</div>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", marginTop: "20px" }}>
            <ReportCard 
              title="Current Plan" 
              value={dashboardData?.user?.organization?.planType || dashboardData?.user?.planType || 'Free'} 
            />
            <ReportCard 
              title="Scans Used" 
              value={`${dashboardData?.user?.organization?.scansUsed || 0} / ${dashboardData?.user?.organization?.scanLimit || '∞'}`} 
            />
            <ReportCard 
              title="Seats Used" 
              value={`${dashboardData?.user?.organization?.seatsUsed || 1} / ${dashboardData?.user?.organization?.seatsAllowed || 1}`} 
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;