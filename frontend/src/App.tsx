import { Routes, Route, Link, useNavigate, Navigate, useParams } from 'react-router-dom';
import { Shield, LayoutDashboard, Terminal, Globe, Database, LogOut, LogIn, MessageSquare } from 'lucide-react';
import Login, { getToken, getUser, clearToken } from './pages/Login';
import { lazy, Suspense, useEffect, useCallback } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import { AnalysisProvider, useAnalysis } from './context/AnalysisContext';
import { LoadingSpinner, ErrorState } from './components/ui/Skeleton';

// Lazy views
const Upload = lazy(() => import('./pages/Upload'));
const FraudCard = lazy(() => import('./pages/FraudCard'));
const TechnicalView = lazy(() => import('./pages/TechnicalView'));
const ThreatIntelView = lazy(() => import('./pages/ThreatIntelView'));
const History = lazy(() => import('./pages/History'));
const InvestigationChat = lazy(() => import('./pages/InvestigationChat'));

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
  stei_axes?: {
    ct: number;
    bt: number;
    pr: number;
    ob: number;
    ir: number;
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
  // MobSF compliance mappings
  rule_id?: string;
  masvs?: string;
  cwe?: string;
  owasp?: string;
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

export type WorkflowStage = {
  label: string;
  technique_id: string;
  description: string;
  start_ms: number;
  end_ms: number;
  evidence_ids: string[];
  hook_names: string[];
  confidence: number;
};

export type FraudWorkflow = {
  stages: WorkflowStage[];
  fraud_sequence_detected: boolean;
  sequence_label: string;
  chain_confidence: number;
  total_events_analyzed: number;
  stage_count: number;
};

export type FraudCardData = {
  sha256: string;
  package_name: string;
  app_name?: string;
  analysis_mode: string;
  job_id?: string;
  family_classification: string;
  base_score: number;
  ai_confidence_multiplier: number;
  final_risk_score: number;
  risk_band: string;
  confidence: number;
  recommended_action: string;
  frs_breakdown?: FRSBreakdown;
  threat_scenario_table?: ThreatScenarioRow[];
  all_permissions: string[];
  hardcoded_urls_ips: string[];
  targets_indian_banks: boolean;
  has_accessibility_abuse: boolean;
  has_sms_read_write: boolean;
  has_system_alert_window: boolean;
  obfuscation_score?: number;
  has_reflection?: boolean;
  threat_correlation?: ThreatCorrelation;
  dynamic_available: boolean;
  dynamic_analysis?: DynamicAnalysis;
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
  // MobSF enrichment fields (optional — populated only in MobSF mode)
  providers?: string[];
  exported_activities?: string[];
  exported_services?: string[];
  exported_receivers?: string[];
  binary_analysis?: Array<{
    name: string;
    nx?: string;
    stack_canary?: string;
    relro?: string;
    rpath?: string;
    runpath?: string;
    fortify?: string;
    stripped?: string;
    symbols?: string[];
  }>;
  network_security?: Record<string, unknown>;
  trackers?: Array<{
    name: string;
    categories: string[];
    website: string;
  }>;
  emails?: string[];
  intelligence_report?: IntelligenceReport;
  fraud_workflow?: FraudWorkflow;
  dynamic_result?: any;
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

// ─── Auth Guard & Wrappers ──────────────────────────────────────────────────

function RouteFallback() {
  return <LoadingSpinner label="Loading view…" />;
}

function RequireAuth({ children, label }: { children: React.ReactNode; label?: string }) {
  const token = getToken();
  if (!token) return <Navigate to="/login" replace />;
  return (
    <ErrorBoundary label={label}>
      <Suspense fallback={<RouteFallback />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

function CaseDetailRoute() {
  const { sha256 } = useParams<{ sha256: string }>();
  const { analysisResult, loadCaseByHash, loading, error } = useAnalysis();

  useEffect(() => {
    if (sha256 && analysisResult?.sha256 !== sha256) {
      loadCaseByHash(sha256);
    }
  }, [sha256, analysisResult, loadCaseByHash]);

  if (loading) return <LoadingSpinner label={`Restoring case ${sha256?.slice(0, 12)}…`} />;
  if (error) return <ErrorState title="Case Restore Failed" message={error} />;
  if (!analysisResult) return <Navigate to="/history" replace />;

  return <FraudCard data={analysisResult} />;
}

function ActiveCaseRoute({ component: Component }: { component: React.ComponentType<{ data: FraudCardData | null }> }) {
  const { analysisResult } = useAnalysis();
  return <Component data={analysisResult} />;
}

// ─── App Structure ──────────────────────────────────────────────────────────

function AppContent() {
  const navigate = useNavigate();
  const user = getUser();
  const isAuthed = !!getToken();
  const { setAnalysisResult, clearAnalysis } = useAnalysis();

  const handleLogout = useCallback(() => {
    clearToken();
    clearAnalysis();
    navigate('/login');
  }, [navigate, clearAnalysis]);

  return (
    <div className="min-h-screen flex flex-col bg-slate-100">
      <nav className="bg-blue-900 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-400" />
              <div>
                <span className="font-bold text-xl tracking-wider">SUDARSHAN</span>
                <span className="ml-2 text-xs text-blue-400 font-mono hidden sm:inline">ENTERPRISE SOC</span>
              </div>
            </div>

            <div className="flex items-center space-x-1">
              {isAuthed && (
                <>
                  <Link
                    to="/"
                    className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors"
                  >
                    Upload
                  </Link>
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
                  </Link>
                  <Link
                    to="/history"
                    className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors"
                  >
                    <Database className="h-4 w-4 mr-1.5" />
                    <span className="hidden sm:inline">History</span>
                  </Link>
                </>
              )}

              {isAuthed ? (
                <button
                  onClick={handleLogout}
                  className="flex items-center px-3 py-2 rounded-md text-sm font-medium hover:bg-blue-800 transition-colors text-blue-300 ml-2"
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
            <RequireAuth label="Upload"><Upload onAnalysisComplete={setAnalysisResult} /></RequireAuth>
          } />
          <Route path="/fraud-card" element={
            <RequireAuth label="Fraud Card"><ActiveCaseRoute component={FraudCard} /></RequireAuth>
          } />
          <Route path="/technical" element={
            <RequireAuth label="Technical View"><ActiveCaseRoute component={TechnicalView} /></RequireAuth>
          } />
          <Route path="/threat-intel" element={
            <RequireAuth label="Threat Intelligence"><ActiveCaseRoute component={ThreatIntelView} /></RequireAuth>
          } />
          <Route path="/chat" element={
            <RequireAuth label="Investigation Chat"><ActiveCaseRoute component={InvestigationChat} /></RequireAuth>
          } />
          <Route path="/history" element={
            <RequireAuth label="Case History"><History /></RequireAuth>
          } />
          <Route path="/history/:sha256" element={
            <RequireAuth label="Case Detail"><CaseDetailRoute /></RequireAuth>
          } />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AnalysisProvider>
      <AppContent />
    </AnalysisProvider>
  );
}
