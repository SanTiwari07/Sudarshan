from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


# ─── Static Analysis Models ───────────────────────────────────────────────────

class StaticAnalysisFlags(BaseModel):
    has_accessibility_abuse: bool = False
    has_sms_read_write: bool = False
    has_system_alert_window: bool = False
    dangerous_apis_found: List[str] = Field(default_factory=list)
    hardcoded_urls_ips: List[str] = Field(default_factory=list)
    targets_indian_banks: bool = False
    indian_bank_packages_found: List[str] = Field(default_factory=list)
    # Obfuscation / reflection signals — used by 5-axis STEI
    obfuscation_score: float = 0.0   # 0.0–1.0 Shannon entropy ratio
    has_reflection: bool = False      # Class.forName / getDeclaredMethod / invoke

    # Packer / dropper concealment.
    #
    # A dropper ships its real payload as an encrypted asset or a nested APK/DEX
    # and unpacks it at runtime, so the manifest declares almost nothing. On the
    # labelled corpus Anubis declared 4 permissions and Hook just 1, which made
    # both score lower than a file manager. Concealment is itself the signal.
    has_concealed_payload: bool = False
    concealment_evidence: List[str] = Field(default_factory=list)

    # True when static analysis had so little to work with that a low score
    # says more about visibility than about safety.
    limited_static_visibility: bool = False


class AndroguardOutput(BaseModel):
    package_name: str
    permissions: List[str]
    flags: StaticAnalysisFlags
    suspicious_strings: List[str] = Field(default_factory=list)


# ─── Fraud Card Views ─────────────────────────────────────────────────────────

class FraudCardExecutiveView(BaseModel):
    risk_badge: str
    plain_english_narrative: str
    recommended_actions: List[str]
    customer_advisory_draft: str


class FraudCardTechnicalView(BaseModel):
    permissions_fired: List[str]
    strings_fired: List[str]
    apis_fired: List[str]
    matched_rule: str
    decoded_manifest_excerpts: List[str]


# ─── FRS Breakdown ────────────────────────────────────────────────────────────

class FRSBreakdown(BaseModel):
    stei: float = 0.0
    dynamic: float = 0.0
    correlation: float = 0.0
    banking_impact: float = 0.0
    formula_used: str = "static_only_frs"
    dynamic_available: bool = False
    # STEI axis breakdown (PDF 5-axis formula)
    stei_axes: Dict[str, float] = Field(default_factory=dict)

    # Scoring provenance. FastAPI's response_model silently drops any key not
    # declared here, so omitting these made the API report `null` for fields the
    # engine had actually computed — the analyst could not see WHY a verdict was
    # reached, or that an axis had been excluded for lack of evidence.
    axes_used: Dict[str, float] = Field(default_factory=dict)
    axes_excluded: List[str] = Field(default_factory=list)

    # Why a verdict may be floored despite a low arithmetic score.
    concealed_payload: bool = False
    verdict_floored_for_visibility: bool = False

    # Distinguishes "the sandbox ran and saw nothing" from "the sandbox ran and
    # observed real behaviour" — only the latter is scored.
    dynamic_ran: bool = False
    dynamic_conclusive: bool = False


# ─── Threat Scenario Table ────────────────────────────────────────────────────

class ThreatScenarioRow(BaseModel):
    """Granular mapping of a detected flag to a named threat scenario."""
    indicator: str            # e.g. "Accessibility Service"
    threat_scenario: str      # e.g. "OTP Harvesting via UI Scraping"
    overlay_risk: str         # High / Medium / Low / N/A
    credential_theft_risk: str
    c2_risk: str
    persistence_risk: str
    evidence: str             # the raw flag that fired this row
    confidence: int           # 0–100


# ─── Threat Correlation ───────────────────────────────────────────────────────

class IOCReputation(BaseModel):
    indicator: str
    type: str  # URL | Domain | IP | Hash
    reputation: str  # malicious | suspicious | clean | unknown
    source: str
    vt_malicious: Optional[int] = None
    vt_total: Optional[int] = None
    abuse_score: Optional[int] = None
    country: Optional[str] = None
    otx_pulses: Optional[int] = None


class ThreatCorrelationResult(BaseModel):
    available: bool = False
    sha256_detections: int = 0
    sha256_total: int = 0
    vt_detection_ratio: float = 0.0
    vt_malicious_vendors: List[str] = Field(default_factory=list)
    ioc_reputation: List[IOCReputation] = Field(default_factory=list)
    known_family: Optional[str] = None
    campaign: Optional[str] = None
    threat_score: float = 0.0
    sources_queried: List[str] = Field(default_factory=list)
    correlation_confidence: float = 0.0
    suspicious_domains: List[str] = Field(default_factory=list)
    malicious_ips: List[str] = Field(default_factory=list)


# ─── Dynamic Analysis ────────────────────────────────────────────────────────

class DynamicAnalysisResult(BaseModel):
    available: bool = False
    activities_triggered: List[str] = Field(default_factory=list)
    network_logs: List[Any] = Field(default_factory=list)
    api_calls: List[Any] = Field(default_factory=list)
    files_accessed: List[str] = Field(default_factory=list)
    screenshots: List[str] = Field(default_factory=list)
    logcat: str = ""
    multi_stage_summary: Dict[str, Any] = Field(default_factory=dict)
    coverage_metrics: Dict[str, int] = Field(default_factory=dict)
    attack_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    clicked_nodes: List[str] = Field(default_factory=list)
    anti_analysis_events: List[Dict[str, Any]] = Field(default_factory=list)
    yara_matches: List[str] = Field(default_factory=list)


# ─── Fraud Workflow Reconstruction ───────────────────────────────────────────────────────────────────

class WorkflowStage(BaseModel):
    """A single causal stage in the reconstructed fraud workflow chain."""
    label: str
    technique_id: str            # MITRE ATT&CK for Mobile technique ID
    description: str
    start_ms: int = 0            # Frida timestamp (ms since epoch)
    end_ms: int = 0
    evidence_ids: List[str] = Field(default_factory=list)
    hook_names: List[str] = Field(default_factory=list)
    confidence: float = 0.0      # 0.0–1.0


class FraudWorkflow(BaseModel):
    """Reconstructed fraud workflow from WorkflowReconstructor causal chain engine."""
    stages: List[WorkflowStage] = Field(default_factory=list)
    fraud_sequence_detected: bool = False
    sequence_label: str = "NONE"   # e.g. FULL_ACCOUNT_TAKEOVER, OTP_THEFT_CHAIN
    chain_confidence: float = 0.0
    total_events_analyzed: int = 0
    stage_count: int = 0


# ─── Extended AI Response ─────────────────────────────────────────────────────

class IntelligenceReport(BaseModel):
    plain_english_narrative: str
    fraud_objective: Optional[str] = None
    affected_banking_apps: List[str] = Field(default_factory=list)
    mitre_techniques_used: List[str] = Field(default_factory=list)
    banking_impact_assessment: Optional[str] = None
    cert_in_recommendations: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    customer_advisory_draft: str
    confidence: str = "Medium"
    analysis_note: Optional[str] = None


# ─── MobSF Manifest Finding ──────────────────────────────────────────────────

class ManifestFinding(BaseModel):
    severity: str
    title: str
    description: str
    component: str = ""


class CodeFinding(BaseModel):
    severity: str
    title: str
    description: str
    files: List[str] = Field(default_factory=list)


# ─── Full Analysis Response ───────────────────────────────────────────────────

class AnalysisResponse(BaseModel):
    # Identity
    sha256: str
    package_name: str
    app_name: Optional[str] = None
    analysis_mode: str = "androguard"  # "mobsf" | "androguard"

    # Async job tracking
    job_id: Optional[str] = None

    # Core Risk
    family_classification: str
    base_score: float
    ai_confidence_multiplier: float
    final_risk_score: float
    risk_band: str
    confidence: float = 70.0
    recommended_action: str = ""

    # FRS breakdown (now includes 5-axis STEI)
    frs_breakdown: Optional[FRSBreakdown] = None

    # Granular threat-scenario correlation table
    threat_scenario_table: List[ThreatScenarioRow] = Field(default_factory=list)

    # Raw flags (for frontend derivation)
    all_permissions: List[str] = Field(default_factory=list)
    hardcoded_urls_ips: List[str] = Field(default_factory=list)
    targets_indian_banks: bool = False
    has_accessibility_abuse: bool = False
    has_sms_read_write: bool = False
    has_system_alert_window: bool = False
    # Obfuscation signals
    obfuscation_score: float = 0.0
    has_reflection: bool = False

    # Threat Intelligence
    threat_correlation: Optional[ThreatCorrelationResult] = None

    # Dynamic Analysis
    dynamic_analysis: Optional[DynamicAnalysisResult] = None
    dynamic_available: bool = False

    # MobSF enrichment (optional — None if Androguard mode)
    manifest_findings: List[ManifestFinding] = Field(default_factory=list)
    code_findings: List[CodeFinding] = Field(default_factory=list)
    dangerous_permissions: List[Dict[str, Any]] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    certificate: Dict[str, Any] = Field(default_factory=dict)
    domains: Dict[str, Any] = Field(default_factory=dict)
    hardcoded_secrets: List[str] = Field(default_factory=list)
    appsec_score: Optional[Any] = None
    mobsf_scan_hash: Optional[str] = None

    # Intelligence Report (from RAG + Ollama)
    intelligence_report: Optional[IntelligenceReport] = None

    # Fraud Workflow Reconstruction (from WorkflowReconstructor)
    fraud_workflow: Optional[FraudWorkflow] = None

    # Legacy view compatibility (kept for existing frontend)
    executive_view: FraudCardExecutiveView
    technical_view: FraudCardTechnicalView
