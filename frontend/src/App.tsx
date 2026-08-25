import { Routes, Route, Navigate, useParams, useLocation, Location } from 'react-router-dom';
import Login from './pages/Login';
import AppShell from './components/layout/AppShell';
import { lazy, Suspense, useEffect } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import InvestigationShell from './components/investigation/InvestigationShell';
import { AnalysisProvider, useAnalysis } from './context/AnalysisContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LoadingSpinner, ErrorState } from './components/ui/Skeleton';

function lazyWithRetry<T extends React.ComponentType<any>>(
  componentImport: () => Promise<{ default: T }>
) {
  return lazy(async () => {
    const pageHasBeenRefreshed = JSON.parse(
      window.sessionStorage.getItem('page_has_been_refreshed') || 'false'
    );
    try {
      const component = await componentImport();
      window.sessionStorage.setItem('page_has_been_refreshed', 'false');
      return component;
    } catch (error) {
      if (!pageHasBeenRefreshed) {
        window.sessionStorage.setItem('page_has_been_refreshed', 'true');
        window.location.reload();
        return new Promise(() => {});
      }
      throw error;
    }
  });
}

// Lazy views
const Upload = lazyWithRetry(() => import('./pages/Upload'));
const FraudCard = lazyWithRetry(() => import('./pages/FraudCard'));
const TechnicalView = lazyWithRetry(() => import('./pages/TechnicalView'));
const ThreatIntelView = lazyWithRetry(() => import('./pages/ThreatIntelView'));
const History = lazyWithRetry(() => import('./pages/History'));
const InvestigationChat = lazyWithRetry(() => import('./pages/InvestigationChat'));
const BatchScan = lazyWithRetry(() => import('./pages/BatchScan'));
const BatchDetail = lazyWithRetry(() => import('./pages/BatchDetail'));

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
  threat_score_sources?: string[];
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
  axes_used?: Record<string, number>;
  axes_excluded?: string[];
  concealed_payload?: boolean;
  verdict_floored_for_visibility?: boolean;
  verdict_floored_for_evasion?: boolean;
  dynamic_ran?: boolean;
  dynamic_conclusive?: boolean;
  /**
   * Why the dynamic axis could not be scored. "We observed nothing bad" and
   * "we never got to look" must not render identically.
   */
  dynamic_exclusion_reason?: string | null;
};

export type RiskExplanation = {
  evidence_lines?: string[];
  component_evidence?: Record<string, string[]>;
  stei_evidence_by_axis?: Record<string, string[]>;
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
  resilience_actions?: {
    type: string;
    title: string;
    result_summary: string;
  }[];
  bfci?: number;
  bfci_components?: Record<string, number>;
  bfci_evidence?: string[];
  artifact_dir?: string;
  evidence_record_count?: number;
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
  version_name?: string;
  apk_size?: string;
  created_at?: string;
  analysis_mode: string;
  job_id?: string;
  family_classification: string;
  base_score: number;
  ai_confidence_multiplier: number;
  final_risk_score: number;
  risk_band: string;
  confidence: number;
  recommended_action: string;
  /**
   * `risk_band` in the ordinary case, `INCOMPLETE_EXERCISE` when the sandbox
   * ran but never exercised the sample. Optional so cases stored before the
   * Execution Assertion Matrix existed still typecheck.
   */
  verdict?: string;
  execution_assertions?: ExecutionAssertions;
  frs_breakdown?: FRSBreakdown;
  risk_explanation?: RiskExplanation;
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
  // MobSF enrichment fields (optional - populated only in MobSF mode)
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
  apktool_enrichment?: Record<string, unknown>;
  jadx_enrichment?: Record<string, unknown>;
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
  vide?: VideResult;
};

/** One fraud precondition and whether the sandbox run reached it. */
export type ExecutionAssertion = {
  key: string;
  label: string;
  fired: boolean;
  evidence: string;
  remediation: string;
};

export type ExecutionAssertions = {
  verdict: string;
  incomplete_exercise: boolean;
  dynamic_ran: boolean;
  threat_events_observed: number;
  coverage_ratio: number;
  fired_count: number;
  total_count: number;
  assertions: ExecutionAssertion[];
  unfired_keys: string[];
};

export type VideCompareScores = {
  string_jaccard?: number;
  tree_similarity?: number;
  color_match?: number;
};

export type VideCompareResult = {
  rule_id: string;
  detected: boolean;
  capability?: string;
  institution_id?: string;
  institution_display?: string;
  confidence?: number;
  scores?: VideCompareScores;
  matched_strings?: string[];
  evidence_lines?: string[];
  forensics?: VideForensicBreakdown;
};

export type VideSignerResult = {
  detected: boolean;
  rule_id?: string;
  package_name?: string;
  signer_sha256?: string;
  evidence_lines?: string[];
};

/** One node of the normalised suspect view hierarchy (VIDE AST). */
export type VideAstNode = {
  role: string;
  tag?: string;
  text?: string;
  children?: VideAstNode[];
};

export type VideColorMatch = {
  baseline: string;
  suspect: string;
  score: number;
  distance: number;
  /** Alias for `distance` under the name the CIE formula is known by. */
  delta_e?: number;
  /** Plain-language reading of the ΔE, e.g. "high visual match". */
  verdict?: string;
};

/** One suspect-vs-baseline swatch pair, ready to render. */
export type VideForensicSwatch = {
  baseline_hex: string;
  suspect_hex: string;
  delta_e: number;
  score: number;
  verdict: string;
  exact: boolean;
};

export type VideConfidenceTier = 'high' | 'moderate' | 'low' | 'none';

/**
 * Why VIDE called this a clone, broken out on the three axes it scores.
 *
 * Built engine-side (see `engines/vide/forensics.py`) so the card and the PDF
 * render the same facts rather than each re-deriving them from evidence prose.
 */
export type VideForensicBreakdown = {
  threshold?: number;
  confidence?: number;
  tier?: VideConfidenceTier;
  tier_label?: string;
  over_threshold?: boolean;
  detected?: boolean;
  institution_id?: string;
  institution_display?: string;
  color_scheme?: {
    score?: number;
    matched_count?: number;
    target_count?: number;
    exact_matches?: number;
    matches?: VideForensicSwatch[];
  };
  ui_text?: {
    score?: number;
    matched_count?: number;
    target_count?: number;
    matched_strings?: string[];
    reworded?: { baseline: string; suspect: string; ratio: number }[];
  };
  view_hierarchy?: {
    score?: number;
    matched_signatures?: string[];
    suspect_signatures?: string[];
  };
};

export type VideCorpusRanked = {
  institution_id: string;
  display_name: string;
  bank?: string;
  confidence: number;
  scores?: {
    string_containment?: number;
    structural?: number;
    color?: number;
  };
  matched_strings?: string[];
  matched_signatures?: string[];
  color_matches?: VideColorMatch[];
};

export type VideCorpusCompare = {
  rule_id?: string;
  detected?: boolean;
  institution_id?: string;
  institution_display?: string;
  bank?: string;
  confidence?: number;
  banking_shape_score?: number;
  attribution?: {
    margin?: number;
    ambiguous?: boolean;
    candidates?: string[];
  };
  suspect_signatures?: string[];
  scores?: {
    string_containment?: number;
    structural?: number;
    color?: number;
  };
  matched_strings?: string[];
  color_matches?: VideColorMatch[];
  ranked?: VideCorpusRanked[];
  evidence_lines?: string[];
  forensics?: VideForensicBreakdown;
};

/** Advisory LLM assessment. Never the verdict - see semantic_matcher.py. */
export type VideSemanticMatch = {
  status?: string;
  advisory?: boolean;
  institution_id?: string;
  model?: string;
  semantic_match?: boolean;
  semantic_confidence?: number;
  matched_design_elements?: string[];
  divergences?: string[];
  impersonation_rationale?: string;
  injection_suspected?: boolean;
  error?: string;
};

/** Raw HTML overlay intercepted from a WebView hook. Evidence, never rendered. */
export type VideOverlayPayload = {
  sha256?: string;
  source?: string;
  hook?: string;
  length?: number;
  html?: string;
  truncated?: boolean;
};

export type VideResult = {
  available?: boolean;
  status?: string;
  error?: string;
  vide_compare?: VideCompareResult;
  corpus_compare?: VideCorpusCompare;
  semantic_match?: VideSemanticMatch;
  suspect_ast?: VideAstNode | null;
  overlay_payloads?: VideOverlayPayload[];
  signer_impersonation?: VideSignerResult;
  suspect_profile_summary?: {
    string_count?: number;
    view_node_count?: number;
    ast_node_count?: number;
    ast_depth?: number;
    sources?: string;
  };
  critical_visual_cluster?: boolean;
  visual_impersonation_detected?: boolean;
  visual_impersonation_institution?: string;
  visual_impersonation_confidence?: number;
  visual_impersonation_tier?: VideConfidenceTier;
  visual_impersonation_tier_label?: string;
  detection_threshold?: number;
  forensic_breakdown?: VideForensicBreakdown;
  ui_hierarchy_integrated?: boolean;
};

// ─── Auth Guard & Wrappers ──────────────────────────────────────────────────

function RouteFallback() {
  return <LoadingSpinner label="Loading view…" />;
}

function AuthLoadingScreen() {
  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-white">
      <LoadingSpinner label="Initializing authentication..." />
    </div>
  );
}

function RequireAuth({ children, label }: { children: React.ReactNode; label?: string }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === 'INITIALIZING') {
    return <AuthLoadingScreen />;
  }

  if (status === 'UNAUTHENTICATED') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return (
    <ErrorBoundary label={label}>
      <Suspense fallback={<RouteFallback />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

function PublicOnlyRoute({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === 'INITIALIZING') {
    return <AuthLoadingScreen />;
  }

  if (status === 'AUTHENTICATED') {
    const rawFrom = (location.state as { from?: Location })?.from?.pathname || '/';
    const from = rawFrom === '/login' ? '/' : rawFrom;
    return <Navigate to={from} replace />;
  }

  return <>{children}</>;
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
  const { setAnalysisResult } = useAnalysis();

  return (
    <AppShell>
      <Routes>
        <Route
          path="/login"
          element={
            <PublicOnlyRoute>
              <Login />
            </PublicOnlyRoute>
          }
        />
        <Route
          path="/"
          element={
            <RequireAuth label="Upload">
              <div className="w-full flex-1 flex flex-col justify-center min-h-0">
                <Upload onAnalysisComplete={setAnalysisResult} />
              </div>
            </RequireAuth>
          }
        />
        <Route
          path="/fraud-card"
          element={
            <RequireAuth label="Fraud Card">
              <InvestigationShell>
                <ActiveCaseRoute component={FraudCard} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/technical"
          element={
            <RequireAuth label="Technical View">
              <InvestigationShell>
                <ActiveCaseRoute component={TechnicalView} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/threat-intel"
          element={
            <RequireAuth label="Threat Intelligence">
              <InvestigationShell>
                <ActiveCaseRoute component={ThreatIntelView} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/chat"
          element={
            <RequireAuth label="Investigation Chat">
              <InvestigationShell className="analyst-page-tight">
                <ActiveCaseRoute component={InvestigationChat} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/history"
          element={
            <RequireAuth label="Case History">
              <div className="analyst-page">
                <History />
              </div>
            </RequireAuth>
          }
        />
        <Route
          path="/history/:sha256"
          element={
            <RequireAuth label="Case Detail">
              <InvestigationShell>
                <CaseDetailRoute />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/batch"
          element={
            <RequireAuth label="Batch Scan">
              <div className="analyst-page">
                <BatchScan />
              </div>
            </RequireAuth>
          }
        />
        <Route
          path="/batch/:batch_id"
          element={
            <RequireAuth label="Batch Detail">
              <div className="analyst-page">
                <BatchDetail />
              </div>
            </RequireAuth>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AnalysisProvider>
        <AppContent />
      </AnalysisProvider>
    </AuthProvider>
  );
}
