import Sidebar from "../components/sidebar";
import Header from "../components/header";
import ScanForm from "../components/scanform";
import ReportCard from "../components/reportcard";
import { useTranslation } from "../contexts/TranslationContext";

const Dashboard = () => {
  const { t } = useTranslation();

  return (
    <div style={{ display: "flex", height: "100vh", backgroundColor: "#111827" }}>
      <Sidebar />
      <div style={{ flex: 1, padding: "20px", color: "white" }}>
        <Header />
        <ScanForm />
        <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", marginTop: "20px" }}>
          <ReportCard title={t('ipAddress')} value="192.168.1.1" />
          <ReportCard title={t('sslStatus')} value={t('valid')} />
          <ReportCard title={t('dnsRecords')} value={t('fetched')} />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
