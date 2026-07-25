import { Routes, Route, Link, useNavigate, Navigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Terminal, Globe, Database, LogOut, LogIn, MessageSquare } from 'lucide-react';
import Upload from './pages/Upload';
import FraudCard from './pages/FraudCard';
import TechnicalView from './pages/TechnicalView';
import ThreatIntelView from './pages/ThreatIntelView';
import Login, { getToken, getUser, clearToken } from './pages/Login';
import History from './pages/History';
import InvestigationChat from './pages/InvestigationChat';
import { useState } from 'react';

// ─── Type Definitions ─────────────────────────────────────────────────────────

export type IOCReputation = {
  indicator: string;
  type: string;
  reputation: string;
  source: string;
  vt_malicious?: number;
  vt_total?: number;
  abuse_score?: number;
  country?: string;
  otx_pulses?: number;
};

export type ThreatCorrelation = {
  available: boolean;
  sha256_detections: number;
  sha256_total: number;
  vt_detection_ratio: number;
  vt_malicious_vendors: string[];
  ioc_reputation: IOCReputation[];
  known_family: string | null;
  campaign: string | null;
  threat_score: number;
  sources_queried: string[];
  correlation_confidence: number;
  suspicious_domains: string[];
  malicious_ips: string[];
};

export type FRSBreakdown = {
  stei: number;
  dynamic: number;
  correlation: number;
  banking_impact: number;
  formula_used: string;
  dynamic_available: boolean;
  // 5-axis STEI breakdown
  stei_axes?: {
    ct: number;  // Credential Theft (0.60)
    bt: number;  // Banking Targeting (0.20)
    pr: number;  // Permission Risk (0.10)
    ob: number;  // Obfuscation (0.05)
    ir: number;  // Infrastructure Risk (0.05)
  };
};

export type ThreatScenarioRow = {
  indicator: string;
  threat_scenario: string;
  overlay_risk: string;
  credential_theft_risk: string;
  c2_risk: string;
  persistence_risk: string;
  evidence: string;
  confidence: number;
};

export type IntelligenceReport = {
  plain_english_narrative: string;
  fraud_objective?: string;
  affected_banking_apps: string[];
  mitre_techniques_used: string[];
  banking_impact_assessment?: string;
  cert_in_recommendations: string[];
  recommended_actions: string[];
  customer_advisory_draft: string;
  confidence: string;
  analysis_note?: string;
};

export type ManifestFinding = {
  severity: string;
  title: string;
  description: string;
  component: string;
};

export type CodeFinding = {
  severity: string;
  title: string;
  description: string;
  files: string[];
};

export type DynamicAnalysis = {
  available: boolean;
  activities_triggered: string[];
  network_logs: string[];
  api_calls: string[];
  files_accessed: string[];
  screenshots: string[];
  logcat: string;
  multi_stage_summary: Record<string, any>;
  coverage_metrics: Record<string, any>;
  attack_timeline: any[];
  clicked_nodes: string[];
  anti_analysis_events: any[];
  yara_matches: any[];
};

export type FraudCardData = {
  // Identity
  sha256: string;
  package_name: string;
  app_name?: string;
  analysis_mode: string;

  // Async job
  job_id?: string;

  // Core risk
  family_classification: string;
  base_score: number;
  ai_confidence_multiplier: number;
  final_risk_score: number;
  risk_band: string;
  confidence: number;
  recommended_action: string;

  // FRS breakdown (5-axis STEI)
  frs_breakdown?: FRSBreakdown;

  // Threat scenario table
  threat_scenario_table?: ThreatScenarioRow[];

  // Raw flags
  all_permissions: string[];
  hardcoded_urls_ips: string[];
  targets_indian_banks: boolean;
  has_accessibility_abuse: boolean;
  has_sms_read_write: boolean;
  has_system_alert_window: boolean;
  // Obfuscation
  obfuscation_score?: number;
  has_reflection?: boolean;

  // Threat intelligence
  threat_correlation?: ThreatCorrelation;
  dynamic_available: boolean;
  dynamic_analysis?: DynamicAnalysis;

  // MobSF enrichment
  manifest_findings: ManifestFinding[];
  code_findings: CodeFinding[];
  dangerous_permissions: Array<{
    permission: string;
    short: string;
    status: string;
    info: string;
    description: string;
  }>;
  activities: string[];
  services: string[];
  receivers: string[];
  certificate: Record<string, unknown>;
  domains: Record<string, unknown>;
  hardcoded_secrets: string[];
  appsec_score?: string | number;
  mobsf_scan_hash?: string;

  // Intelligence report
  intelligence_report?: IntelligenceReport;

  // Legacy compat
  executive_view: {
    risk_badge: string;
    plain_english_narrative: string;
    recommended_actions: string[];
    customer_advisory_draft: string;
  };
  technical_view: {
    permissions_fired: string[];
    strings_fired: string[];
    apis_fired: string[];
    matched_rule: string;
    decoded_manifest_excerpts: string[];
  };
};

// ─── Auth Guard ───────────────────────────────────────────────────────────────

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = getToken();
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

// ─── App ──────────────────────────────────────────────────────────────────────

function App() {
  const [analysisResult, setAnalysisResult] = useState<FraudCardData | null>(null);
  const navigate = useNavigate();
  const user = getUser();
  const isAuthed = !!getToken();

  const hasIntel = analysisResult?.threat_correlation?.available;

  const handleLogout = () => {
    clearToken();
    setAnalysisResult(null);
    navigate('/login');
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-100">
      <nav className="bg-blue-900 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-400" />
              <div>
                <span className="font-bold text-xl tracking-wider">SUDARSHAN</span>
                <span className="ml-2 text-xs text-blue-400 font-mono hidden sm:inline">v2.1 ENTERPRISE</span>
              </div>
            </div>
            <div className="flex items-center space-x-1">
              {isAuthed && analysisResult && (
                <>
                  <Link
                    to="/fraud-card"
                    className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors"
                  >
                    <LayoutDashboard className="h-4 w-4 mr-1.5" />
                    <span className="hidden sm:inline">Fraud Analyst</span>
                  </Link>
                  <Link
                    to="/technical"
                    className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors"
                  >
                    <Terminal className="h-4 w-4 mr-1.5" />
                    <span className="hidden sm:inline">SOC / Technical</span>
                  </Link>
                  <Link
                    to="/chat"
                    className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors relative"
                  >
                    <MessageSquare className="h-4 w-4 mr-1.5" />
                    <span className="hidden sm:inline">AI Assistant</span>
                    <span className="ml-1.5 w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  </Link>
                  <Link
                    to="/threat-intel"
                    className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors relative"
                  >
                    <Globe className="h-4 w-4 mr-1.5" />
                    <span className="hidden sm:inline">Threat Intel</span>
                    {hasIntel && (
                      <span className="ml-1.5 w-2 h-2 rounded-full bg-red-400 animate-pulse" />
                    )}
                  </Link>
                </>
              )}
              {isAuthed && (
                <Link
                  to="/history"
                  className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors"
                >
                  <Database className="h-4 w-4 mr-1.5" />
                  <span className="hidden sm:inline">History</span>
                </Link>
              )}
              {isAuthed ? (
                <button
                  onClick={handleLogout}
                  className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors text-blue-300"
                  title={`Logged in as ${user?.username} (${user?.role})`}
                >
                  <LogOut className="h-4 w-4 mr-1.5" />
                  <span className="hidden sm:inline">{user?.username}</span>
                </button>
              ) : (
                <Link
                  to="/login"
                  className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors"
                >
                  <LogIn className="h-4 w-4 mr-1.5" />
                  Sign In
                </Link>
              )}
            </div>
          </div>
        </div>
      </nav>

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        <Routes>
          {/* Public */}
          <Route path="/login" element={<Login />} />

          {/* Protected */}
          <Route path="/" element={
            <RequireAuth><Upload onAnalysisComplete={setAnalysisResult} /></RequireAuth>
          } />
          <Route path="/fraud-card" element={
            <RequireAuth><FraudCard data={analysisResult} /></RequireAuth>
          } />
          <Route path="/technical" element={
            <RequireAuth><TechnicalView data={analysisResult} /></RequireAuth>
          } />
          <Route path="/threat-intel" element={
            <RequireAuth><ThreatIntelView data={analysisResult} /></RequireAuth>
          } />
          <Route path="/chat" element={
            <RequireAuth><InvestigationChat data={analysisResult} /></RequireAuth>
          } />
          <Route path="/history" element={
            <RequireAuth><History /></RequireAuth>
          } />
        </Routes>
      </main>
    </div>
  );
}

export default App;
