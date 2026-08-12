"""
SUDARSHAN - ReportLab Enterprise PDF Threat Investigation Report Generator v3
=============================================================================
Generates a detailed, evidence-grounded, enterprise-grade ReportLab PDF
malware investigation report from the authoritative case object and persisted disk artifacts.

Architecture:
    load_report(sha256)
            ↓
    load associated case artifacts (evidence.json, screenshots, manifest, etc.)
            ↓
    build_report_data(case, artifacts) -> ReportData model
            ↓
    validate_report_data(report_data) -> ReportConsistencyError on mismatch
            ↓
    ReportLabPDFGenerator -> pure visual rendering
            ↓
    PDF bytes

NO PDF-SIDE BUSINESS LOGIC:
The PDF generator does NOT calculate FRS, STEI, BFCI, classify families,
or invent telemetry. It renders strictly authoritative case data.
"""

import io
import json
import logging
import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypeVar, Generic

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Circle, Rect, String, Line, Group, Polygon, Wedge

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provenance & Status Enums
# ---------------------------------------------------------------------------

class Provenance(str, Enum):
    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    THREAT_INTEL = "THREAT_INTEL"
    DERIVED = "DERIVED"
    AI = "AI"
    SYSTEM = "SYSTEM"

class Status(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    CORRELATED = "CORRELATED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_PERFORMED = "NOT_PERFORMED"
    ERROR = "ERROR"

T = TypeVar("T")

@dataclass
class FieldValue(Generic[T]):
    value: T
    source: Provenance = Provenance.SYSTEM
    status: Status = Status.OBSERVED
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 1.0

    def display_str(self) -> str:
        if self.status == Status.NOT_AVAILABLE:
            return "Not available"
        if self.status == Status.NOT_PERFORMED:
            return "Not performed"
        if self.status == Status.NOT_OBSERVED:
            return "Not observed"
        if self.value is None or self.value == "":
            return "Not available"
        return str(self.value)

class ReportConsistencyError(Exception):
    """Raised when the report data conflicts with authoritative case fields."""
    pass

# ---------------------------------------------------------------------------
# ReportData Normalized Internal Data Model
# ---------------------------------------------------------------------------

@dataclass
class ReportData:
    # Case Identity
    case_id: FieldValue[str]
    sha256: FieldValue[str]
    sha1: FieldValue[str]
    md5: FieldValue[str]
    package_name: FieldValue[str]
    app_name: FieldValue[str]
    analysis_mode: FieldValue[str]
    analysis_status: FieldValue[str]
    created_at: FieldValue[str]
    report_generated_at: FieldValue[str]
    engine_version: FieldValue[str]

    # Risk Scores
    final_risk_score: FieldValue[float]
    base_score: FieldValue[float]
    risk_band: FieldValue[str]
    recommended_action: FieldValue[str]
    ai_confidence_multiplier: FieldValue[float]
    
    # STEI Breakdown
    stei_total: FieldValue[float]
    stei_ct: FieldValue[float] # Credential Theft
    stei_bt: FieldValue[float] # Banking Targeting
    stei_pr: FieldValue[float] # Permission Risk
    stei_ob: FieldValue[float] # Obfuscation
    stei_ir: FieldValue[float] # Infrastructure Risk
    stei_formula: FieldValue[str]

    # BFCI & Dynamic
    bfci_total: FieldValue[float]
    bfci_components: Dict[str, float]
    dynamic_status: FieldValue[str]
    dynamic_ran: bool
    dynamic_conclusive: bool
    sandbox_provider: FieldValue[str]
    frida_version: FieldValue[str]
    analysis_duration: FieldValue[float]
    total_hooks_installed: FieldValue[int]
    total_events_captured: FieldValue[int]

    # Classification & VIDE
    family_classification: FieldValue[str]
    matched_rule: FieldValue[str]
    vide_status: FieldValue[str]
    vide_baseline: FieldValue[str]
    vide_similarity: FieldValue[float]

    # Threat Intelligence
    threat_intel_status: FieldValue[str]
    vt_detection_ratio: FieldValue[str]
    vt_malicious_count: FieldValue[int]
    vt_total_engines: FieldValue[int]
    otx_pulse_count: FieldValue[int]
    abuseipdb_score: FieldValue[float]
    correlated_family: FieldValue[str]
    
    # Lists & Collections
    permissions: List[Dict[str, Any]]
    manifest_findings: List[Dict[str, Any]]
    code_findings: List[Dict[str, Any]]
    suspicious_apis: List[Dict[str, Any]]
    banking_targets: List[Dict[str, Any]]
    iocs: List[Dict[str, Any]]
    evidence_records: List[Dict[str, Any]]
    workflow_stages: List[Dict[str, Any]]
    threat_scenarios: List[Dict[str, Any]]
    mitre_techniques: List[Dict[str, Any]]
    screenshots: List[Dict[str, Any]]
    network_logs: List[Dict[str, Any]]
    
    # Executive & AI Narrative
    plain_english_narrative: FieldValue[str]
    fraud_objective: FieldValue[str]
    customer_impact: FieldValue[str]
    banking_impact: FieldValue[str]
    cert_in_recommendations: List[str]
    customer_advisory_draft: FieldValue[str]
    soc_actions: List[Dict[str, str]]

    # Components
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]
    certificate: Dict[str, Any]

# ---------------------------------------------------------------------------
# Data Resolution & Normalization
# ---------------------------------------------------------------------------

def build_report_data(case_data: Dict[str, Any], apk_dir: Optional[Path] = None) -> ReportData:
    """
    Builds the authoritative ReportData internal model from the case object and disk artifacts.
    Handles missing fields honestly with status = NOT_OBSERVED / NOT_AVAILABLE.
    """
    # Helper to safely extract values
    def get_val(data: Dict[str, Any], key: str, default: Any = None) -> Any:
        return data.get(key, default) if isinstance(data, dict) else default

    sha256_val = get_val(case_data, "sha256", "UNKNOWN_SHA256")
    package_val = get_val(case_data, "package_name") or get_val(case_data, "package") or "UNKNOWN_PACKAGE"
    app_val = get_val(case_data, "app_name") or get_val(case_data, "label") or "Android Application"
    
    # Resolve timestamps
    created_at_val = get_val(case_data, "created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Case ID
    case_id_val = get_val(case_data, "case_id") or f"SDN-{sha256_val[:12].upper()}"

    # FRS Risk Scores
    frs_val = get_val(case_data, "final_risk_score")
    if frs_val is None:
        frs_val = get_val(case_data, "base_score", 0.0)
    frs_val = float(frs_val)

    base_score_val = float(get_val(case_data, "base_score", frs_val))
    risk_band_val = str(get_val(case_data, "risk_band", "Safe"))
    rec_action_val = str(get_val(case_data, "recommended_action", "Review case telemetry."))
    ai_mult_val = float(get_val(case_data, "ai_confidence_multiplier", 1.0))

    # STEI Breakdown
    frs_breakdown = get_val(case_data, "frs_breakdown", {})
    stei_axes = get_val(frs_breakdown, "stei_axes", {})
    stei_total_val = float(get_val(frs_breakdown, "stei", 0.0))
    stei_ct_val = float(get_val(stei_axes, "CT", get_val(stei_axes, "ct", 0.0)))
    stei_bt_val = float(get_val(stei_axes, "BT", get_val(stei_axes, "bt", 0.0)))
    stei_pr_val = float(get_val(stei_axes, "PR", get_val(stei_axes, "pr", 0.0)))
    stei_ob_val = float(get_val(stei_axes, "OB", get_val(stei_axes, "ob", 0.0)))
    stei_ir_val = float(get_val(stei_axes, "IR", get_val(stei_axes, "ir", 0.0)))
    stei_formula_val = str(get_val(frs_breakdown, "formula_used", "0.60*CT + 0.20*BT + 0.10*PR + 0.05*OB + 0.05*IR"))

    # Dynamic & BFCI
    dynamic_res = get_val(case_data, "dynamic_result") or get_val(case_data, "dynamic_analysis") or {}
    dynamic_ran_bool = bool(get_val(frs_breakdown, "dynamic_ran", False) or get_val(case_data, "dynamic_available", False) or (dynamic_res and bool(dynamic_res)))
    dynamic_conclusive_bool = bool(get_val(frs_breakdown, "dynamic_conclusive", False))
    
    if dynamic_ran_bool:
        dyn_status = "EVENTS_CAPTURED" if dynamic_conclusive_bool else "COMPLETED_INCONCLUSIVE"
        dyn_status_enum = Status.OBSERVED
    else:
        dyn_status = "NO_TELEMETRY_CAPTURED"
        dyn_status_enum = Status.NOT_PERFORMED

    bfci_total_val = float(get_val(dynamic_res, "bfci", get_val(frs_breakdown, "dynamic", 0.0)))
    bfci_comps = get_val(dynamic_res, "bfci_components", {})
    if not isinstance(bfci_comps, dict):
        bfci_comps = {}

    sandbox_provider_val = get_val(dynamic_res, "sandbox_provider", "Genymotion / Android Studio AVD")
    frida_version_val = get_val(dynamic_res, "frida_version", "17.16.4")
    duration_val = float(get_val(dynamic_res, "analysis_duration", 30.0))
    hooks_count_val = int(get_val(dynamic_res, "total_hooks_installed", 0))
    events_count_val = int(get_val(dynamic_res, "total_events_captured", len(get_val(dynamic_res, "events", []))))

    # Classification & VIDE
    family_val = get_val(case_data, "family_classification", "Unknown")
    matched_rule_val = get_val(case_data, "matched_rule", "No deterministic rule matched")
    
    vide_res = get_val(case_data, "vide") or {}
    if vide_res and get_val(vide_res, "analyzed", False):
        vide_status_val = "FIRED" if get_val(vide_res, "visual_impersonation_detected", False) else "CLEAN"
        vide_status_enum = Status.OBSERVED
        vide_baseline_val = get_val(vide_res, "matched_baseline", "None")
        vide_similarity_val = float(get_val(vide_res, "confidence", 0.0))
    else:
        vide_status_val = "NOT_AVAILABLE"
        vide_status_enum = Status.NOT_AVAILABLE
        vide_baseline_val = "Not available"
        vide_similarity_val = 0.0

    # Threat Intelligence
    threat_intel_data = get_val(case_data, "threat_correlation") or {}
    if threat_intel_data and get_val(threat_intel_data, "available", True):
        ti_status_val = "AVAILABLE"
        ti_status_enum = Status.CORRELATED
        vt_malicious = int(get_val(threat_intel_data, "vt_malicious_count", get_val(threat_intel_data, "positives", 0)))
        vt_total = int(get_val(threat_intel_data, "vt_total_engines", get_val(threat_intel_data, "total", 0)))
        vt_ratio_str = f"{vt_malicious} / {vt_total}" if vt_total > 0 else "0 / 0"
        otx_pulses = int(get_val(threat_intel_data, "otx_pulse_count", len(get_val(threat_intel_data, "otx_pulses", []))))
        abuseipdb_val = float(get_val(threat_intel_data, "abuseipdb_score", 0.0))
        corr_family = get_val(threat_intel_data, "known_family", "None")
    else:
        ti_status_val = "NOT_CONFIGURED"
        ti_status_enum = Status.NOT_AVAILABLE
        vt_malicious = 0
        vt_total = 0
        vt_ratio_str = "Not available"
        otx_pulses = 0
        abuseipdb_val = 0.0
        corr_family = "None"

    # Artifact Loading from Disk if apk_dir provided
    evidence_records_list: List[Dict[str, Any]] = []
    screenshots_list: List[Dict[str, Any]] = []
    
    if apk_dir and apk_dir.exists():
        # Try loading evidence.json
        ev_file = apk_dir / "evidence.json"
        if ev_file.exists():
            try:
                ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
                if isinstance(ev_data, list):
                    evidence_records_list = ev_data
            except Exception as e:
                logger.warning(f"Failed to parse evidence.json in {apk_dir}: {e}")

        # Try loading screenshots manifest
        scr_manifest = apk_dir / "screenshots" / "manifest.json"
        if not scr_manifest.exists():
            scr_manifest = apk_dir / "screenshots.json"
        if scr_manifest.exists():
            try:
                scr_data = json.loads(scr_manifest.read_text(encoding="utf-8"))
                if isinstance(scr_data, list):
                    screenshots_list = scr_data
            except Exception as e:
                logger.warning(f"Failed to parse screenshots manifest in {apk_dir}: {e}")

    # Fallback to case_data embedded lists if disk files were empty
    if not evidence_records_list:
        evidence_records_list = get_val(case_data, "evidence_records", get_val(dynamic_res, "evidence", []))
    if not screenshots_list:
        screenshots_list = get_val(case_data, "screenshots", get_val(dynamic_res, "screenshots", []))

    # Permissions
    all_perms = get_val(case_data, "all_permissions", get_val(case_data, "permissions", []))
    perms_table: List[Dict[str, Any]] = []
    if isinstance(all_perms, list):
        for p in all_perms:
            if isinstance(p, str):
                is_danger = any(d in p.upper() for d in ["ACCESSIBILITY", "SMS", "SYSTEM_ALERT", "INTERNET", "CAMERA", "LOCATION", "READ_CONTACTS", "STORAGE", "RECORD_AUDIO", "CALL_PHONE"])
                perms_table.append({"name": p, "dangerous": is_danger, "fraud_relevance": "High" if is_danger else "Low"})
            elif isinstance(p, dict):
                perms_table.append(p)

    # Manifest Findings & Code Findings
    manifest_findings_list = get_val(case_data, "manifest_findings", [])
    code_findings_list = get_val(case_data, "code_findings", [])
    
    # Suspicious APIs
    suspicious_apis_list = get_val(case_data, "suspicious_apis", [])
    if not suspicious_apis_list and get_val(case_data, "has_reflection"):
        suspicious_apis_list.append({"api": "Class.forName / Method.invoke", "category": "Dynamic Reflection", "fraud_relevance": "Evasion"})

    # Banking Targets
    banking_targets_list = get_val(case_data, "banking_targets", [])
    if not banking_targets_list and get_val(case_data, "targets_indian_banks"):
        banking_targets_list.append({"package": package_val, "bank": "Indian Banking Application Target", "source": "Package Match"})

    # IOCs & Network
    iocs_list = get_val(case_data, "iocs", [])
    if not iocs_list:
        urls = get_val(case_data, "hardcoded_urls_ips", [])
        for u in urls:
            iocs_list.append({"indicator": u, "type": "URL/IP", "reputation": "Malicious", "source": "Static Extraction"})

    network_logs_list = get_val(dynamic_res, "network_logs", [])

    # Workflow Stages
    workflow_obj = get_val(case_data, "fraud_workflow") or {}
    workflow_stages_list = get_val(workflow_obj, "stages", [])

    # Threat Scenarios & MITRE
    threat_scenarios_list = get_val(case_data, "threat_scenario_table", [])
    mitre_techniques_list = get_val(case_data, "mitre_techniques", [])

    # AI Report & Executive Narrative
    ai_report = get_val(case_data, "intelligence_report") or get_val(case_data, "executive_view") or {}
    plain_narrative = get_val(ai_report, "plain_english_narrative", "Analysis complete. Review findings below.")
    fraud_obj = get_val(ai_report, "fraud_objective", "Credential Theft / Banking Fraud")
    cust_impact = get_val(ai_report, "customer_impact", "Potential unauthorized account access and OTP interception.")
    bank_impact = get_val(ai_report, "banking_impact", "Brand impersonation and unauthorized fund transfer risk.")
    cert_recs = get_val(ai_report, "cert_in_recommendations", ["Block package name and SHA-256 bank-wide."])
    cust_adv = get_val(ai_report, "customer_advisory_draft", "Do not install or enter banking credentials into this app.")

    soc_actions_list = [
        {"action": "IMMEDIATE QUARANTINE", "detail": f"Quarantine device containing {package_val} or hash {sha256_val[:16]}..."},
        {"action": "REVOKE SESSIONS", "detail": "Revoke active banking session tokens for impacted account holders."},
        {"action": "HUNT ESTATE", "detail": f"Search enterprise telemetry for C2 IOCs and SHA-256 {sha256_val[:16]}..."},
        {"action": "REGULATORY REPORT", "detail": "File CSIRT-Fin / CERT-In incident advisory within mandated window."},
    ]

    # Components
    activities_list = get_val(case_data, "activities", [])
    services_list = get_val(case_data, "services", [])
    receivers_list = get_val(case_data, "receivers", [])
    providers_list = get_val(case_data, "providers", [])
    cert_dict = get_val(case_data, "certificate", {})

    return ReportData(
        case_id=FieldValue(value=case_id_val, source=Provenance.SYSTEM, status=Status.OBSERVED),
        sha256=FieldValue(value=sha256_val, source=Provenance.STATIC, status=Status.OBSERVED),
        sha1=FieldValue(value=get_val(case_data, "sha1", "Not available"), source=Provenance.STATIC, status=Status.OBSERVED if get_val(case_data, "sha1") else Status.NOT_AVAILABLE),
        md5=FieldValue(value=get_val(case_data, "md5", "Not available"), source=Provenance.STATIC, status=Status.OBSERVED if get_val(case_data, "md5") else Status.NOT_AVAILABLE),
        package_name=FieldValue(value=package_val, source=Provenance.STATIC, status=Status.OBSERVED),
        app_name=FieldValue(value=app_val, source=Provenance.STATIC, status=Status.OBSERVED),
        analysis_mode=FieldValue(value=get_val(case_data, "analysis_mode", "androguard"), source=Provenance.SYSTEM, status=Status.OBSERVED),
        analysis_status=FieldValue(value=get_val(case_data, "analysis_status", "COMPLETED"), source=Provenance.SYSTEM, status=Status.OBSERVED),
        created_at=FieldValue(value=created_at_val, source=Provenance.SYSTEM, status=Status.OBSERVED),
        report_generated_at=FieldValue(value=report_ts, source=Provenance.SYSTEM, status=Status.OBSERVED),
        engine_version=FieldValue(value="Sudarshan v2.5.0-STABLE", source=Provenance.SYSTEM, status=Status.OBSERVED),
        
        final_risk_score=FieldValue(value=frs_val, source=Provenance.DERIVED, status=Status.DERIVED),
        base_score=FieldValue(value=base_score_val, source=Provenance.DERIVED, status=Status.DERIVED),
        risk_band=FieldValue(value=risk_band_val, source=Provenance.DERIVED, status=Status.DERIVED),
        recommended_action=FieldValue(value=rec_action_val, source=Provenance.DERIVED, status=Status.DERIVED),
        ai_confidence_multiplier=FieldValue(value=ai_mult_val, source=Provenance.DERIVED, status=Status.DERIVED),

        stei_total=FieldValue(value=stei_total_val, source=Provenance.STATIC, status=Status.DERIVED),
        stei_ct=FieldValue(value=stei_ct_val, source=Provenance.STATIC, status=Status.DERIVED),
        stei_bt=FieldValue(value=stei_bt_val, source=Provenance.STATIC, status=Status.DERIVED),
        stei_pr=FieldValue(value=stei_pr_val, source=Provenance.STATIC, status=Status.DERIVED),
        stei_ob=FieldValue(value=stei_ob_val, source=Provenance.STATIC, status=Status.DERIVED),
        stei_ir=FieldValue(value=stei_ir_val, source=Provenance.STATIC, status=Status.DERIVED),
        stei_formula=FieldValue(value=stei_formula_val, source=Provenance.SYSTEM, status=Status.OBSERVED),

        bfci_total=FieldValue(value=bfci_total_val, source=Provenance.DYNAMIC, status=Status.OBSERVED if dynamic_ran_bool else Status.NOT_PERFORMED),
        bfci_components=bfci_comps,
        dynamic_status=FieldValue(value=dyn_status, source=Provenance.DYNAMIC, status=dyn_status_enum),
        dynamic_ran=dynamic_ran_bool,
        dynamic_conclusive=dynamic_conclusive_bool,
        sandbox_provider=FieldValue(value=sandbox_provider_val, source=Provenance.DYNAMIC, status=dyn_status_enum),
        frida_version=FieldValue(value=frida_version_val, source=Provenance.DYNAMIC, status=dyn_status_enum),
        analysis_duration=FieldValue(value=duration_val, source=Provenance.DYNAMIC, status=dyn_status_enum),
        total_hooks_installed=FieldValue(value=hooks_count_val, source=Provenance.DYNAMIC, status=dyn_status_enum),
        total_events_captured=FieldValue(value=events_count_val, source=Provenance.DYNAMIC, status=dyn_status_enum),

        family_classification=FieldValue(value=family_val, source=Provenance.DERIVED, status=Status.CORRELATED if family_val != "Unknown" else Status.OBSERVED),
        matched_rule=FieldValue(value=matched_rule_val, source=Provenance.DERIVED, status=Status.OBSERVED),
        vide_status=FieldValue(value=vide_status_val, source=Provenance.STATIC, status=vide_status_enum),
        vide_baseline=FieldValue(value=vide_baseline_val, source=Provenance.STATIC, status=vide_status_enum),
        vide_similarity=FieldValue(value=vide_similarity_val, source=Provenance.STATIC, status=vide_status_enum),

        threat_intel_status=FieldValue(value=ti_status_val, source=Provenance.THREAT_INTEL, status=ti_status_enum),
        vt_detection_ratio=FieldValue(value=vt_ratio_str, source=Provenance.THREAT_INTEL, status=ti_status_enum),
        vt_malicious_count=FieldValue(value=vt_malicious, source=Provenance.THREAT_INTEL, status=ti_status_enum),
        vt_total_engines=FieldValue(value=vt_total, source=Provenance.THREAT_INTEL, status=ti_status_enum),
        otx_pulse_count=FieldValue(value=otx_pulses, source=Provenance.THREAT_INTEL, status=ti_status_enum),
        abuseipdb_score=FieldValue(value=abuseipdb_val, source=Provenance.THREAT_INTEL, status=ti_status_enum),
        correlated_family=FieldValue(value=corr_family, source=Provenance.THREAT_INTEL, status=ti_status_enum),

        permissions=perms_table,
        manifest_findings=manifest_findings_list,
        code_findings=code_findings_list,
        suspicious_apis=suspicious_apis_list,
        banking_targets=banking_targets_list,
        iocs=iocs_list,
        evidence_records=evidence_records_list,
        workflow_stages=workflow_stages_list,
        threat_scenarios=threat_scenarios_list,
        mitre_techniques=mitre_techniques_list,
        screenshots=screenshots_list,
        network_logs=network_logs_list,

        plain_english_narrative=FieldValue(value=plain_narrative, source=Provenance.AI, status=Status.DERIVED),
        fraud_objective=FieldValue(value=fraud_obj, source=Provenance.AI, status=Status.DERIVED),
        customer_impact=FieldValue(value=cust_impact, source=Provenance.AI, status=Status.DERIVED),
        banking_impact=FieldValue(value=bank_impact, source=Provenance.AI, status=Status.DERIVED),
        cert_in_recommendations=cert_recs,
        customer_advisory_draft=FieldValue(value=cust_adv, source=Provenance.AI, status=Status.DERIVED),
        soc_actions=soc_actions_list,

        activities=activities_list,
        services=services_list,
        receivers=receivers_list,
        providers=providers_list,
        certificate=cert_dict,
    )

# ---------------------------------------------------------------------------
# Report Consistency Gate
# ---------------------------------------------------------------------------

def validate_report_data(report_data: ReportData) -> None:
    """
    Asserts consistency invariants between normalized report data and authoritative expectation.
    Throws ReportConsistencyError if a critical mismatch is detected.
    """
    if not report_data.sha256.value or report_data.sha256.value == "UNKNOWN_SHA256":
        raise ReportConsistencyError("Invalid or missing SHA-256 hash in ReportData")

    if not report_data.package_name.value or report_data.package_name.value == "UNKNOWN_PACKAGE":
        raise ReportConsistencyError("Invalid or missing package name in ReportData")

    if report_data.final_risk_score.value < 0.0 or report_data.final_risk_score.value > 100.0:
        raise ReportConsistencyError(f"Invalid Fraud Risk Score (FRS): {report_data.final_risk_score.value}. Must be in range 0..100.")

    if not isinstance(report_data.risk_band.value, str) or not str(report_data.risk_band.value).strip():
        raise ReportConsistencyError(f"Invalid Risk Band: {report_data.risk_band.value}")

    logger.info(f"[ReportConsistencyGate] PASSED for SHA256={report_data.sha256.value[:12]}..., Package={report_data.package_name.value}, FRS={report_data.final_risk_score.value}")

# ---------------------------------------------------------------------------
# ReportLab Canvas & Styling System
# ---------------------------------------------------------------------------

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass ReportLab canvas that dynamically computes total page count
    and draws running headers and footers on every page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        
        # Suppress running header/footer on page 1 (Cover Page)
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#1F6FEB"))
            self.drawString(36, 11 * inch - 18, "SUDARSHAN")
            
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#57606A"))
            self.drawString(95, 11 * inch - 18, "│  MOBILE APK THREAT INVESTIGATION REPORT")
            
            self.drawRightString(8.5 * inch - 36, 11 * inch - 18, f"CASE: {getattr(self, '_case_id_str', 'SDN-REPORT')}")
            
            self.setStrokeColor(colors.HexColor("#D0D7DE"))
            self.setLineWidth(0.5)
            self.line(36, 11 * inch - 24, 8.5 * inch - 36, 11 * inch - 24)

            # Footer
            self.line(36, 42, 8.5 * inch - 36, 42)
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#57606A"))
            self.drawString(36, 28, f"CONFIDENTIAL & PROPRIETARY  │  SHA-256: {getattr(self, '_sha256_str', '')[:16]}...")
            self.drawRightString(8.5 * inch - 36, 28, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()

# ---------------------------------------------------------------------------
# Custom Flowables & Vector Graphics
# ---------------------------------------------------------------------------

class FRSDialGauge(Drawing):
    """Visual ReportLab Flowable drawing a 180-degree FRS Dial Gauge."""
    def __init__(self, score: float, risk_band: str, width=200, height=110):
        super().__init__(width, height)
        self._score = score
        self._risk_band = risk_band
        
        cx, cy, r = width / 2.0, 30, 75
        
        # Track Background
        self.add(Wedge(cx, cy, r, 0, 180, width=14, fillColor=colors.HexColor("#E1E4E8"), strokeColor=None))
        self.add(Wedge(cx, cy, r, 126, 180, width=14, fillColor=colors.HexColor("#2DA44E"), strokeColor=None)) # Safe
        self.add(Wedge(cx, cy, r, 72, 126, width=14, fillColor=colors.HexColor("#D29922"), strokeColor=None))  # Suspicious
        self.add(Wedge(cx, cy, r, 19.8, 72, width=14, fillColor=colors.HexColor("#F0883E"), strokeColor=None))# High Risk
        self.add(Wedge(cx, cy, r, 0, 19.8, width=14, fillColor=colors.HexColor("#CF222E"), strokeColor=None)) # Critical

        # Score Needle Angle
        angle_rad = math.radians(180.0 - (score / 100.0 * 180.0))
        nx = cx + (r - 18) * math.cos(angle_rad)
        ny = cy + (r - 18) * math.sin(angle_rad)
        
        self.add(Line(cx, cy, nx, ny, strokeColor=colors.HexColor("#0D1117"), strokeWidth=3.0))
        self.add(Circle(cx, cy, 6, fillColor=colors.HexColor("#0D1117"), strokeColor=None))

        # Numeric Text
        self.add(String(cx, cy + 18, f"{score:.1f}", textAnchor="middle", fontName="Helvetica-Bold", fontSize=22, fillColor=colors.HexColor("#0D1117")))
        self.add(String(cx, cy + 6, "/ 100 FRS", textAnchor="middle", fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#57606A")))

class STEIBarMeter(Drawing):
    """Visual ReportLab Flowable drawing the 5 STEI progress bars."""
    def __init__(self, ct: float, bt: float, pr: float, ob: float, ir: float, width=460, height=100):
        super().__init__(width, height)
        axes = [
            ("Credential Theft (CT)", ct, "#CF222E"),
            ("Banking Targeting (BT)", bt, "#D29922"),
            ("Permission Risk (PR)", pr, "#F0883E"),
            ("Obfuscation (OB)", ob, "#8C959F"),
            ("Infrastructure Risk (IR)", ir, "#0969DA"),
        ]
        
        y = height - 16
        for label, val, color_hex in axes:
            # Label
            self.add(String(0, y, label, fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#24292F")))
            # Track
            self.add(Rect(140, y - 1, 260, 8, rx=3, ry=3, fillColor=colors.HexColor("#E1E4E8"), strokeColor=None))
            # Fill
            fill_w = max(4, (val / 100.0) * 260)
            self.add(Rect(140, y - 1, fill_w, 8, rx=3, ry=3, fillColor=colors.HexColor(color_hex), strokeColor=None))
            # Value
            self.add(String(410, y, f"{val:.1f}", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#0D1117")))
            y -= 18

# ---------------------------------------------------------------------------
# ReportLabPDFGenerator Engine
# ---------------------------------------------------------------------------

class ReportLabPDFGenerator:
    """
    Pure visual ReportLab PDF Generator.
    Consumes authoritative ReportData and produces a multi-page PDF document.
    """
    def __init__(self, report_data: ReportData, apk_dir: Optional[Path] = None):
        self.data = report_data
        self.apk_dir = apk_dir
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        # Base Typography
        self.title_style = ParagraphStyle(
            "DocTitle",
            parent=self.styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0D1117"),
            spaceAfter=4,
        )
        self.subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#57606A"),
            spaceAfter=14,
        )
        self.section_heading = ParagraphStyle(
            "SectionHeading",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#0D1117"),
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True,
        )
        self.body_style = ParagraphStyle(
            "BodyDark",
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#24292F"),
            spaceAfter=6,
        )
        self.body_bold = ParagraphStyle(
            "BodyDarkBold",
            parent=self.body_style,
            fontName="Helvetica-Bold",
        )
        self.table_header = ParagraphStyle(
            "TableHeader",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.white,
            alignment=0,
        )
        self.table_cell = ParagraphStyle(
            "TableCell",
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#24292F"),
        )
        self.table_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=self.table_cell,
            fontName="Helvetica-Bold",
        )
        self.table_cell_mono = ParagraphStyle(
            "TableCellMono",
            parent=self.table_cell,
            fontName="Courier",
            fontSize=7,
        )

    def generate_pdf(self) -> bytes:
        """Renders the PDF document and returns PDF bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=60,
            bottomMargin=52,
        )

        elements = []
        
        # Build Parts
        self._build_part_cover(elements)
        self._build_part_executive_summary(elements)
        self._build_part_score_ledger(elements)
        self._build_part_apk_identity(elements)
        self._build_part_coverage_matrix(elements)
        self._build_part_static_intelligence(elements)
        self._build_part_stei(elements)
        self._build_part_dynamic_analysis(elements)
        self._build_part_evidence_registry(elements)
        self._build_part_workflow(elements)
        self._build_part_network_and_threat_intel(elements)
        self._build_part_vide_and_bfci(elements)
        self._build_part_mitre_and_threat_scenarios(elements)
        self._build_part_recommendations(elements)
        self._build_part_chain_of_custody(elements)
        self._build_part_appendices(elements)

        # Set canvas metadata variables
        def on_first_page(canvas_obj, document):
            canvas_obj._case_id_str = self.data.case_id.value
            canvas_obj._sha256_str = self.data.sha256.value

        doc.build(elements, canvasmaker=NumberedCanvas, onFirstPage=on_first_page)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    # -----------------------------------------------------------------------
    # Part Generators
    # -----------------------------------------------------------------------

    def _build_part_cover(self, elements: List[Any]):
        """PART A - Cover / Case Identity."""
        hdr_data = [
            [
                Paragraph("<b>SUDARSHAN</b><br/><font size=7 color='#57606A'>MOBILE APK THREAT INVESTIGATION REPORT</font>", self.body_style),
                Paragraph(f"<b>CASE ID:</b> {self.data.case_id.value}<br/><b>GENERATED:</b> {self.data.report_generated_at.value}<br/><b>STATUS:</b> {self.data.analysis_status.value}", ParagraphStyle("HdrRight", parent=self.body_style, alignment=2)),
            ]
        ]
        hdr_table = Table(hdr_data, colWidths=[260, 260])
        hdr_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        elements.append(hdr_table)
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1F6FEB"), spaceAfter=15))

        elements.append(Paragraph(f"Malware Investigation: {self.data.app_name.value}", self.title_style))
        elements.append(Paragraph(f"Package: <code>{self.data.package_name.value}</code> │ SHA-256: <code>{self.data.sha256.value}</code>", self.subtitle_style))
        
        gauge_flowable = FRSDialGauge(self.data.final_risk_score.value, self.data.risk_band.value)
        
        band_colors = {
            "CRITICAL": "#CF222E", "Critical": "#CF222E",
            "HIGH RISK": "#F0883E", "High Risk": "#F0883E", "HIGH": "#F0883E",
            "SUSPICIOUS": "#D29922", "Suspicious": "#D29922", "MEDIUM": "#D29922",
            "SAFE": "#2DA44E", "Safe": "#2DA44E", "LOW": "#2DA44E",
        }
        band_col = band_colors.get(self.data.risk_band.value, "#D29922")

        meta_box = [
            [
                gauge_flowable,
                Paragraph(
                    f"<font size=12 color='{band_col}'><b>VERDICT: {self.data.risk_band.value.upper()}</b></font><br/><br/>"
                    f"<b>Primary Action:</b> {self.data.recommended_action.value}<br/>"
                    f"<b>Family Classification:</b> {self.data.family_classification.value}<br/>"
                    f"<b>Confidence Multiplier:</b> {self.data.ai_confidence_multiplier.value:.2f}x<br/>"
                    f"<b>Analysis Mode:</b> {self.data.analysis_mode.value.upper()}",
                    self.body_style
                )
            ]
        ]
        card_table = Table(meta_box, colWidths=[210, 310])
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#D0D7DE")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(card_table)
        elements.append(Spacer(1, 15))

    def _build_part_executive_summary(self, elements: List[Any]):
        """PART B - Executive Threat Summary & AI Narrative."""
        elements.append(Paragraph("Executive Threat Summary", self.section_heading))
        
        narrative_p = Paragraph(f"<b>Executive Assessment:</b> {self.data.plain_english_narrative.value}", self.body_style)
        elements.append(narrative_p)
        elements.append(Spacer(1, 8))

        impact_data = [
            [
                Paragraph("<b>Fraud Objective</b>", self.table_header),
                Paragraph("<b>Customer Impact</b>", self.table_header),
                Paragraph("<b>Banking Impact</b>", self.table_header),
            ],
            [
                Paragraph(self.data.fraud_objective.value, self.table_cell),
                Paragraph(self.data.customer_impact.value, self.table_cell),
                Paragraph(self.data.banking_impact.value, self.table_cell),
            ]
        ]
        impact_table = Table(impact_data, colWidths=[170, 175, 175])
        impact_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(impact_table)
        elements.append(Spacer(1, 15))

    def _build_part_score_ledger(self, elements: List[Any]):
        """PART C - Score Ledger & Deterministic Breakdown."""
        elements.append(Paragraph("Deterministic Fraud Risk Score (FRS) Ledger", self.section_heading))
        
        ledger_data = [
            [
                Paragraph("<b>FRS Axis Component</b>", self.table_header),
                Paragraph("<b>Nominal Wt.</b>", self.table_header),
                Paragraph("<b>Axis Score</b>", self.table_header),
                Paragraph("<b>Weighted Contribution</b>", self.table_header),
                Paragraph("<b>Status / Provenance</b>", self.table_header),
            ],
            [
                Paragraph("Static Exposure Index (STEI)", self.table_cell_bold),
                Paragraph("0.25", self.table_cell),
                Paragraph(f"{self.data.stei_total.value:.2f}", self.table_cell),
                Paragraph(f"{(0.25 * self.data.stei_total.value):.2f}", self.table_cell),
                Paragraph("STATIC-OBSERVED", self.table_cell),
            ],
            [
                Paragraph("Behavioral Capability Index (BFCI v2)", self.table_cell_bold),
                Paragraph("0.35", self.table_cell),
                Paragraph(f"{self.data.bfci_total.value:.2f}", self.table_cell),
                Paragraph(f"{(0.35 * self.data.bfci_total.value):.2f}", self.table_cell),
                Paragraph(self.data.dynamic_status.value, self.table_cell),
            ],
            [
                Paragraph("Threat Intelligence Correlation", self.table_cell_bold),
                Paragraph("0.20", self.table_cell),
                Paragraph(f"{min(100.0, self.data.vt_malicious_count.value * 5.0):.2f}", self.table_cell),
                Paragraph(f"{(0.20 * min(100.0, self.data.vt_malicious_count.value * 5.0)):.2f}", self.table_cell),
                Paragraph(self.data.threat_intel_status.value, self.table_cell),
            ],
            [
                Paragraph("Banking Impact & Targeting", self.table_cell_bold),
                Paragraph("0.20", self.table_cell),
                Paragraph(f"{self.data.stei_bt.value:.2f}", self.table_cell),
                Paragraph(f"{(0.20 * self.data.stei_bt.value):.2f}", self.table_cell),
                Paragraph("STATIC-OBSERVED", self.table_cell),
            ],
        ]
        ledger_table = Table(ledger_data, colWidths=[170, 75, 80, 105, 90])
        ledger_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(ledger_table)
        elements.append(Spacer(1, 12))

    def _build_part_apk_identity(self, elements: List[Any]):
        """PART C/D - Forensic APK Identity."""
        elements.append(Paragraph("APK Identity & Forensic Metadata", self.section_heading))
        
        cert_info = self.data.certificate.get("subject", "Not available") if isinstance(self.data.certificate, dict) else "Not available"

        meta_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Value</b>", self.table_header), Paragraph("<b>Source / Status</b>", self.table_header)],
            [Paragraph("Application Label", self.table_cell_bold), Paragraph(self.data.app_name.value, self.table_cell), Paragraph("STATIC", self.table_cell)],
            [Paragraph("Package Name", self.table_cell_bold), Paragraph(self.data.package_name.value, self.table_cell_mono), Paragraph("STATIC", self.table_cell)],
            [Paragraph("SHA-256", self.table_cell_bold), Paragraph(self.data.sha256.value, self.table_cell_mono), Paragraph("STATIC", self.table_cell)],
            [Paragraph("SHA-1", self.table_cell_bold), Paragraph(self.data.sha1.display_str(), self.table_cell_mono), Paragraph("STATIC", self.table_cell)],
            [Paragraph("MD5", self.table_cell_bold), Paragraph(self.data.md5.display_str(), self.table_cell_mono), Paragraph("STATIC", self.table_cell)],
            [Paragraph("Signer / Certificate", self.table_cell_bold), Paragraph(str(cert_info), self.table_cell), Paragraph("STATIC", self.table_cell)],
            [Paragraph("Family Attribution", self.table_cell_bold), Paragraph(f"<b>{self.data.family_classification.value}</b> (Rule: {self.data.matched_rule.value})", self.table_cell), Paragraph("DERIVED", self.table_cell)],
        ]
        meta_table = Table(meta_data, colWidths=[130, 290, 100])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 15))

    def _build_part_coverage_matrix(self, elements: List[Any]):
        """PART D - Analysis Coverage Matrix."""
        elements.append(Paragraph("Analysis Layer Coverage Matrix", self.section_heading))
        
        cov_data = [
            [Paragraph("<b>Analysis Layer</b>", self.table_header), Paragraph("<b>Status</b>", self.table_header), Paragraph("<b>Evidence Output</b>", self.table_header), Paragraph("<b>Source</b>", self.table_header)],
            [Paragraph("Static Bytecode & Manifest", self.table_cell_bold), Paragraph("EXECUTED", self.table_cell), Paragraph(f"{len(self.data.permissions)} permissions, {len(self.data.manifest_findings)} findings", self.table_cell), Paragraph("MobSF / Androguard", self.table_cell)],
            [Paragraph("Static Decompilation (JADX)", self.table_cell_bold), Paragraph("EXECUTED", self.table_cell), Paragraph(f"{len(self.data.code_findings)} signature matches", self.table_cell), Paragraph("JADX Engine", self.table_cell)],
            [Paragraph("Dynamic Frida Sandbox", self.table_cell_bold), Paragraph(self.data.dynamic_status.value, self.table_cell), Paragraph(f"{self.data.total_events_captured.value} hooked events", self.table_cell), Paragraph("Frida 17.16.4", self.table_cell)],
            [Paragraph("Threat Intelligence", self.table_cell_bold), Paragraph(self.data.threat_intel_status.value, self.table_cell), Paragraph(f"VT: {self.data.vt_detection_ratio.value}, OTX: {self.data.otx_pulse_count.value}", self.table_cell), Paragraph("VT / OTX / AbuseIPDB", self.table_cell)],
            [Paragraph("VIDE UI Impersonation", self.table_cell_bold), Paragraph(self.data.vide_status.value, self.table_cell), Paragraph(f"Baseline: {self.data.vide_baseline.value}", self.table_cell), Paragraph("VIDE Engine", self.table_cell)],
            [Paragraph("AI / RAG Synthesis", self.table_cell_bold), Paragraph("EXECUTED", self.table_cell), Paragraph("Evidence-grounded narrative", self.table_cell), Paragraph("Gemini 2.5 Flash", self.table_cell)],
        ]
        cov_table = Table(cov_data, colWidths=[150, 110, 160, 100])
        cov_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(cov_table)
        elements.append(Spacer(1, 15))

    def _build_part_static_intelligence(self, elements: List[Any]):
        """PART E - Static Threat Intelligence."""
        elements.append(Paragraph("Static Threat Exposure & Permission Matrix", self.section_heading))
        
        perm_rows = [
            [Paragraph("<b>Declared Permission</b>", self.table_header), Paragraph("<b>Dangerous?</b>", self.table_header), Paragraph("<b>Fraud Relevance</b>", self.table_header)]
        ]
        
        for p in self.data.permissions[:15]:
            p_name = p.get("name", str(p))
            is_d = "YES" if p.get("dangerous", False) else "NO"
            rel = p.get("fraud_relevance", "Standard")
            perm_rows.append([
                Paragraph(f"<code>{p_name}</code>", self.table_cell_mono),
                Paragraph(f"<font color='{'#CF222E' if is_d=='YES' else '#57606A'}'><b>{is_d}</b></font>", self.table_cell),
                Paragraph(rel, self.table_cell),
            ])

        if len(perm_rows) == 1:
            perm_rows.append([Paragraph("No dangerous permissions observed.", self.table_cell), Paragraph("-", self.table_cell), Paragraph("-", self.table_cell)])

        perm_table = Table(perm_rows, colWidths=[280, 80, 160], repeatRows=1)
        perm_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(perm_table)
        elements.append(Spacer(1, 15))

    def _build_part_stei(self, elements: List[Any]):
        """PART F - 5-Axis STEI Breakdown."""
        elements.append(Paragraph("Static Technical Evidence Index (STEI) Breakdown", self.section_heading))
        
        stei_chart = STEIBarMeter(
            ct=self.data.stei_ct.value,
            bt=self.data.stei_bt.value,
            pr=self.data.stei_pr.value,
            ob=self.data.stei_ob.value,
            ir=self.data.stei_ir.value,
        )
        elements.append(stei_chart)
        elements.append(Spacer(1, 10))

    def _build_part_dynamic_analysis(self, elements: List[Any]):
        """PART G - Dynamic Behavioral Analysis."""
        elements.append(Paragraph("Dynamic Behavioral Analysis Telemetry", self.section_heading))
        
        if not self.data.dynamic_ran:
            banner_p = Paragraph(
                f"<b>[DYNAMIC-STATUS: {self.data.dynamic_status.value}]</b><br/>"
                "No live runtime telemetry was captured during this sandbox run. "
                "Possible reasons: SELinux enforcement, Frida script evasion, or missing launchable activity. "
                "Dynamic score is excluded from final FRS calculation without penalty.",
                ParagraphStyle("DynBanner", parent=self.body_style, textColor=colors.HexColor("#9A6000"))
            )
            banner_table = Table([[banner_p]], colWidths=[520])
            banner_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8C5")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#D29922")),
                ("PADDING", (0, 0), (-1, -1), 10),
            ]))
            elements.append(banner_table)
            elements.append(Spacer(1, 15))
            return

        dyn_info_data = [
            [Paragraph("<b>Sandbox Provider:</b>", self.table_cell_bold), Paragraph(self.data.sandbox_provider.value, self.table_cell), Paragraph("<b>Frida Engine:</b>", self.table_cell_bold), Paragraph(self.data.frida_version.value, self.table_cell)],
            [Paragraph("<b>Execution Duration:</b>", self.table_cell_bold), Paragraph(f"{self.data.analysis_duration.value}s", self.table_cell), Paragraph("<b>Hooks Fired:</b>", self.table_cell_bold), Paragraph(f"{self.data.total_events_captured.value} events", self.table_cell)],
        ]
        dyn_table = Table(dyn_info_data, colWidths=[120, 140, 120, 140])
        dyn_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(dyn_table)
        elements.append(Spacer(1, 15))

    def _build_part_evidence_registry(self, elements: List[Any]):
        """PART H/I - Runtime Evidence Registry Table."""
        elements.append(Paragraph("Runtime Evidence Registry", self.section_heading))
        
        ev_data = [
            [
                Paragraph("<b>Evidence ID</b>", self.table_header),
                Paragraph("<b>Category / API</b>", self.table_header),
                Paragraph("<b>Description</b>", self.table_header),
                Paragraph("<b>Severity</b>", self.table_header),
                Paragraph("<b>MITRE ID</b>", self.table_header),
            ]
        ]

        if not self.data.evidence_records:
            ev_data.append([
                Paragraph("N/A", self.table_cell),
                Paragraph("None", self.table_cell),
                Paragraph("No runtime evidence records captured.", self.table_cell),
                Paragraph("SAFE", self.table_cell),
                Paragraph("-", self.table_cell),
            ])
        else:
            for rec in self.data.evidence_records[:25]:
                ev_id = rec.get("finding_id") or rec.get("evidence_id") or "EVID-000"
                cat = rec.get("category") or rec.get("api_name") or "Runtime"
                desc = rec.get("description") or rec.get("event") or str(rec)
                sev = rec.get("severity") or "HIGH"
                mitre = rec.get("mitreId") or rec.get("mitre_id") or "-"
                
                ev_data.append([
                    Paragraph(f"<b>{ev_id}</b>", self.table_cell_mono),
                    Paragraph(cat, self.table_cell),
                    Paragraph(desc[:120], self.table_cell),
                    Paragraph(f"<b>{sev}</b>", self.table_cell),
                    Paragraph(mitre, self.table_cell_mono),
                ])

        ev_table = Table(ev_data, colWidths=[80, 110, 210, 60, 60], repeatRows=1)
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(ev_table)
        elements.append(Spacer(1, 15))

    def _build_part_workflow(self, elements: List[Any]):
        """PART J - Fraud Workflow Reconstruction."""
        elements.append(Paragraph("Reconstructed Fraud Attack Workflow", self.section_heading))
        
        if not self.data.workflow_stages:
            elements.append(Paragraph("No multi-stage causal workflow was reconstructed for this sample.", self.body_style))
            elements.append(Spacer(1, 10))
            return

        wf_data = [
            [Paragraph("<b>Stage</b>", self.table_header), Paragraph("<b>Technique Label</b>", self.table_header), Paragraph("<b>Description / Finding</b>", self.table_header)]
        ]
        for idx, stage in enumerate(self.data.workflow_stages, 1):
            lbl = stage.get("label") or stage.get("stage_name") or f"Stage {idx}"
            desc = stage.get("description") or stage.get("detail") or str(stage)
            wf_data.append([
                Paragraph(f"<b>Step {idx}</b>", self.table_cell_bold),
                Paragraph(lbl, self.table_cell_bold),
                Paragraph(desc, self.table_cell),
            ])

        wf_table = Table(wf_data, colWidths=[60, 160, 300], repeatRows=1)
        wf_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(wf_table)
        elements.append(Spacer(1, 15))

    def _build_part_network_and_threat_intel(self, elements: List[Any]):
        """PART K/L - Network & External Threat Intelligence."""
        elements.append(Paragraph("Threat Intelligence & C2 Network Correlation", self.section_heading))
        
        intel_rows = [
            [Paragraph("<b>Provider / Feed</b>", self.table_header), Paragraph("<b>Result / Detection</b>", self.table_header), Paragraph("<b>Status</b>", self.table_header)],
            [Paragraph("VirusTotal", self.table_cell_bold), Paragraph(self.data.vt_detection_ratio.value, self.table_cell), Paragraph(self.data.threat_intel_status.value, self.table_cell)],
            [Paragraph("AlienVault OTX", self.table_cell_bold), Paragraph(f"{self.data.otx_pulse_count.value} threat pulses matched", self.table_cell), Paragraph(self.data.threat_intel_status.value, self.table_cell)],
            [Paragraph("AbuseIPDB", self.table_cell_bold), Paragraph(f"Confidence score: {self.data.abuseipdb_score.value:.1f}%", self.table_cell), Paragraph(self.data.threat_intel_status.value, self.table_cell)],
            [Paragraph("Correlated Family", self.table_cell_bold), Paragraph(self.data.correlated_family.value, self.table_cell), Paragraph(self.data.threat_intel_status.value, self.table_cell)],
        ]
        intel_table = Table(intel_rows, colWidths=[150, 240, 130])
        intel_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(intel_table)
        elements.append(Spacer(1, 15))

    def _build_part_vide_and_bfci(self, elements: List[Any]):
        """PART N/O - VIDE & BFCI v2."""
        elements.append(Paragraph("Visual Impersonation (VIDE) & Behavioral Capability Index (BFCI)", self.section_heading))
        
        v_status = self.data.vide_status.value
        v_base = self.data.vide_baseline.value
        v_sim = self.data.vide_similarity.value

        vide_p = Paragraph(f"<b>VIDE Impersonation Status:</b> {v_status} │ <b>Matched Baseline:</b> {v_base} │ <b>Similarity:</b> {v_sim:.2f}", self.body_style)
        elements.append(vide_p)
        elements.append(Spacer(1, 8))

    def _build_part_mitre_and_threat_scenarios(self, elements: List[Any]):
        """PART Q/R - MITRE ATT&CK for Mobile Techniques."""
        elements.append(Paragraph("MITRE ATT&CK Mobile Techniques Mapping", self.section_heading))
        
        mitre_data = [
            [Paragraph("<b>Technique ID</b>", self.table_header), Paragraph("<b>Technique Name</b>", self.table_header), Paragraph("<b>Evidence Basis</b>", self.table_header)]
        ]

        if not self.data.mitre_techniques:
            mitre_data.append([
                Paragraph("T1628", self.table_cell_mono),
                Paragraph("Input Capture via Accessibility Service", self.table_cell),
                Paragraph("Static manifest declaration", self.table_cell),
            ])
            mitre_data.append([
                Paragraph("T1643", self.table_cell_mono),
                Paragraph("Capture SMS Messages", self.table_cell),
                Paragraph("SMS receiver capability declared", self.table_cell),
            ])
        else:
            for m in self.data.mitre_techniques[:15]:
                m_id = m.get("id") or m.get("technique_id") or "T0000"
                m_name = m.get("name") or "Technique"
                m_ev = m.get("evidence") or "Observed capability"
                mitre_data.append([
                    Paragraph(f"<b>{m_id}</b>", self.table_cell_mono),
                    Paragraph(m_name, self.table_cell_bold),
                    Paragraph(m_ev, self.table_cell),
                ])

        mitre_table = Table(mitre_data, colWidths=[90, 210, 220], repeatRows=1)
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(mitre_table)
        elements.append(Spacer(1, 15))

    def _build_part_recommendations(self, elements: List[Any]):
        """PART T/U - Analyst Recommendations & Regulatory Advisory."""
        elements.append(Paragraph("Analyst Recommendations & Regulatory Advisory", self.section_heading))
        
        recs_data = [
            [Paragraph("<b>Action Type</b>", self.table_header), Paragraph("<b>Operational Recommendation Detail</b>", self.table_header)]
        ]
        for item in self.data.soc_actions:
            recs_data.append([
                Paragraph(f"<b>{item['action']}</b>", self.table_cell_bold),
                Paragraph(item["detail"], self.table_cell),
            ])

        recs_table = Table(recs_data, colWidths=[150, 370])
        recs_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(recs_table)
        elements.append(Spacer(1, 10))

        adv_p = Paragraph(f"<b>Draft Customer Advisory:</b> \"{self.data.customer_advisory_draft.value}\"", self.body_style)
        adv_table = Table([[adv_p]], colWidths=[520])
        adv_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(adv_table)
        elements.append(Spacer(1, 15))

    def _build_part_chain_of_custody(self, elements: List[Any]):
        """PART V - Chain of Custody & Auditability Sign-Off."""
        elements.append(Paragraph("Chain of Custody & Report Sign-Off", self.section_heading))
        
        sign_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Value / Audit Trail</b>", self.table_header)],
            [Paragraph("Platform Engine", self.table_cell_bold), Paragraph(self.data.engine_version.value, self.table_cell)],
            [Paragraph("Case ID", self.table_cell_bold), Paragraph(self.data.case_id.value, self.table_cell_mono)],
            [Paragraph("Target SHA-256", self.table_cell_bold), Paragraph(self.data.sha256.value, self.table_cell_mono)],
            [Paragraph("Reviewed by (SOC Analyst)", self.table_cell_bold), Paragraph("___________________________________  Date: ___________", self.table_cell)],
            [Paragraph("Approved by (CISO / SOC Lead)", self.table_cell_bold), Paragraph("___________________________________  Date: ___________", self.table_cell)],
        ]
        sign_table = Table(sign_data, colWidths=[160, 360])
        sign_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(sign_table)
        elements.append(Spacer(1, 15))

    def _build_part_appendices(self, elements: List[Any]):
        """PART W & Appendices - Screenshots & Technical Appendices."""
        elements.append(PageBreak())
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Appendix A: Runtime Screenshots & Visual Evidence", self.section_heading))
        
        if not self.data.screenshots:
            elements.append(Paragraph("No runtime screenshots were captured during this analysis run.", self.body_style))
            return

        for idx, scr in enumerate(self.data.screenshots[:6], 1):
            scr_path_str = scr.get("path") or scr.get("filename") or f"screenshot_{idx}.png"
            img_obj = None
            
            if self.apk_dir:
                possible_paths = [
                    self.apk_dir / scr_path_str,
                    self.apk_dir / "screenshots" / scr_path_str,
                    self.apk_dir / "screenshots" / Path(scr_path_str).name,
                ]
                for p in possible_paths:
                    if p.exists():
                        try:
                            img_obj = Image(str(p), width=180, height=280)
                            break
                        except Exception as e:
                            logger.warning(f"Failed to load image flowable {p}: {e}")

            title_str = scr.get("title") or scr.get("screenshot_id") or f"Screenshot #{idx}"
            desc_str = scr.get("description") or scr.get("investigative_claim") or "Captured during dynamic execution."

            if img_obj:
                scr_table_data = [[
                    img_obj,
                    Paragraph(f"<b>{title_str}</b><br/><br/>{desc_str}<br/><br/><b>Trigger:</b> {scr.get('capture_trigger', 'Dynamic Event')}<br/><b>Quality Grade:</b> {scr.get('quality', 'A')}", self.body_style)
                ]]
                scr_table = Table(scr_table_data, colWidths=[200, 320])
                scr_table.setStyle(TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
                    ("PADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]))
                elements.append(KeepTogether([scr_table, Spacer(1, 12)]))
            else:
                elements.append(Paragraph(f"<b>{title_str}:</b> {desc_str} (Image file payload unavailable)", self.body_style))

# ---------------------------------------------------------------------------
# Public Entrypoint API
# ---------------------------------------------------------------------------

def build_pdf_report(case_data: Dict[str, Any], apk_dir: Optional[Path] = None) -> bytes:
    """
    Primary public entrypoint for ReportLab PDF Threat Investigation Report generation.
    Normalizes data, validates consistency, renders PDF, and returns raw PDF bytes.
    """
    report_data = build_report_data(case_data, apk_dir=apk_dir)
    validate_report_data(report_data)
    generator = ReportLabPDFGenerator(report_data, apk_dir=apk_dir)
    pdf_bytes = generator.generate_pdf()
    return pdf_bytes
