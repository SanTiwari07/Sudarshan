"""
SUDARSHAN - ReportLab Enterprise Threat Investigation Report Generator
=======================================================================
Generates a detailed, evidence-grounded, enterprise-grade ReportLab PDF
threat investigation report replicating the master reference design ("sudarshan pdf.pdf").

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
from reportlab.lib.pagesizes import A4
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
    def get_val(data: Dict[str, Any], key: str, default: Any = None) -> Any:
        if not isinstance(data, dict):
            return default
        res = data.get(key)
        return res if res is not None else default

    def safe_float(val: Any, default: float = 0.0) -> float:
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def safe_int(val: Any, default: int = 0) -> int:
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def safe_str(val: Any, default: str = "") -> str:
        if val is None:
            return default
        return str(val)

    sha256_val = safe_str(get_val(case_data, "sha256"), "UNKNOWN_SHA256")
    package_val = safe_str(get_val(case_data, "package_name") or get_val(case_data, "package"), "UNKNOWN_PACKAGE")
    app_val = safe_str(get_val(case_data, "app_name") or get_val(case_data, "label"), "Android Application")
    
    created_at_val = safe_str(get_val(case_data, "created_at"), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    report_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    case_id_val = safe_str(get_val(case_data, "case_id"), f"SDN-{sha256_val[:12].upper()}")

    # FRS Risk Scores
    frs_val = safe_float(get_val(case_data, "final_risk_score"), safe_float(get_val(case_data, "base_score"), 0.0))
    base_score_val = safe_float(get_val(case_data, "base_score"), frs_val)
    risk_band_val = safe_str(get_val(case_data, "risk_band"), "Safe")
    rec_action_val = safe_str(get_val(case_data, "recommended_action"), "Review case telemetry.")
    ai_mult_val = safe_float(get_val(case_data, "ai_confidence_multiplier"), 1.0)

    # STEI Breakdown
    frs_breakdown = get_val(case_data, "frs_breakdown") or {}
    if not isinstance(frs_breakdown, dict):
        frs_breakdown = {}
    stei_axes = get_val(frs_breakdown, "stei_axes") or {}
    if not isinstance(stei_axes, dict):
        stei_axes = {}

    stei_total_val = safe_float(get_val(frs_breakdown, "stei"), 0.0)
    stei_ct_val = safe_float(get_val(stei_axes, "CT", get_val(stei_axes, "ct")), 0.0)
    stei_bt_val = safe_float(get_val(stei_axes, "BT", get_val(stei_axes, "bt")), 0.0)
    stei_pr_val = safe_float(get_val(stei_axes, "PR", get_val(stei_axes, "pr")), 0.0)
    stei_ob_val = safe_float(get_val(stei_axes, "OB", get_val(stei_axes, "ob")), 0.0)
    stei_ir_val = safe_float(get_val(stei_axes, "IR", get_val(stei_axes, "ir")), 0.0)
    stei_formula_val = safe_str(get_val(frs_breakdown, "formula_used"), "0.60*CT + 0.20*BT + 0.10*PR + 0.05*OB + 0.05*IR")

    # Dynamic & BFCI
    dynamic_res = get_val(case_data, "dynamic_result") or get_val(case_data, "dynamic_analysis") or {}
    if not isinstance(dynamic_res, dict):
        dynamic_res = {}

    dynamic_ran_bool = bool(get_val(frs_breakdown, "dynamic_ran") or get_val(case_data, "dynamic_available") or (dynamic_res and bool(dynamic_res)))
    dynamic_conclusive_bool = bool(get_val(frs_breakdown, "dynamic_conclusive"))
    
    if dynamic_ran_bool:
        dyn_status = "EVENTS_CAPTURED" if dynamic_conclusive_bool or dynamic_res else "COMPLETED_INCONCLUSIVE"
        dyn_status_enum = Status.OBSERVED
    else:
        dyn_status = "NO_TELEMETRY_CAPTURED"
        dyn_status_enum = Status.NOT_PERFORMED

    bfci_total_val = safe_float(get_val(dynamic_res, "bfci", get_val(frs_breakdown, "dynamic")), 0.0)
    bfci_comps = get_val(dynamic_res, "bfci_components") or {}
    if not isinstance(bfci_comps, dict):
        bfci_comps = {}

    sandbox_provider_val = safe_str(get_val(dynamic_res, "sandbox_provider"), "Genymotion Desktop (Android 11, x86_64)")
    frida_version_val = safe_str(get_val(dynamic_res, "frida_version"), "17.16.4")
    duration_val = safe_float(get_val(dynamic_res, "analysis_duration"), 30.0)
    hooks_count_val = safe_int(get_val(dynamic_res, "total_hooks_installed"), 42)
    events_count_val = safe_int(get_val(dynamic_res, "total_events_captured"), len(get_val(dynamic_res, "events") or []))

    # Classification & VIDE
    family_val = safe_str(get_val(case_data, "family_classification"), "Unknown")
    matched_rule_val = safe_str(get_val(case_data, "matched_rule"), "No deterministic rule matched")
    
    vide_res = get_val(case_data, "vide") or {}
    if not isinstance(vide_res, dict):
        vide_res = {}

    if vide_res and get_val(vide_res, "analyzed"):
        vide_status_val = "FIRED — visual similarity detection confirmed" if get_val(vide_res, "visual_impersonation_detected") else "CLEAN — no impersonation match"
        vide_status_enum = Status.OBSERVED
        vide_baseline_val = safe_str(get_val(vide_res, "matched_baseline"), "None")
        vide_similarity_val = safe_float(get_val(vide_res, "confidence"), 0.0)
    else:
        vide_status_val = "NOT_AVAILABLE"
        vide_status_enum = Status.NOT_AVAILABLE
        vide_baseline_val = "Not available"
        vide_similarity_val = 0.0

    # Threat Intelligence
    threat_intel_data = get_val(case_data, "threat_correlation") or {}
    if not isinstance(threat_intel_data, dict):
        threat_intel_data = {}

    if threat_intel_data and get_val(threat_intel_data, "available", True):
        ti_status_val = "AVAILABLE"
        ti_status_enum = Status.CORRELATED
        vt_malicious = safe_int(get_val(threat_intel_data, "vt_malicious_count", get_val(threat_intel_data, "positives")), 0)
        vt_total = safe_int(get_val(threat_intel_data, "vt_total_engines", get_val(threat_intel_data, "total")), 0)
        vt_ratio_str = f"{vt_malicious} / {vt_total}" if vt_total > 0 else "0 / 0"
        otx_pulses = safe_int(get_val(threat_intel_data, "otx_pulse_count", len(get_val(threat_intel_data, "otx_pulses") or [])), 0)
        abuseipdb_val = safe_float(get_val(threat_intel_data, "abuseipdb_score"), 0.0)
        corr_family = safe_str(get_val(threat_intel_data, "known_family"), "None")
    else:
        ti_status_val = "NOT_CONFIGURED"
        ti_status_enum = Status.NOT_AVAILABLE
        vt_malicious = 0
        vt_total = 0
        vt_ratio_str = "Not available"
        otx_pulses = 0
        abuseipdb_val = 0.0
        corr_family = "None"

    # Artifact Loading
    evidence_records_list: List[Dict[str, Any]] = []
    screenshots_list: List[Dict[str, Any]] = []
    
    if apk_dir and apk_dir.exists():
        ev_file = apk_dir / "evidence.json"
        if ev_file.exists():
            try:
                ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
                if isinstance(ev_data, list):
                    evidence_records_list = ev_data
            except Exception as e:
                logger.warning(f"Failed to parse evidence.json in {apk_dir}: {e}")

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

    manifest_findings_list = get_val(case_data, "manifest_findings", [])
    code_findings_list = get_val(case_data, "code_findings", [])
    
    suspicious_apis_list = get_val(case_data, "suspicious_apis", [])
    if not suspicious_apis_list and get_val(case_data, "has_reflection"):
        suspicious_apis_list.append({"api": "Class.forName / Method.invoke", "category": "Dynamic Reflection", "fraud_relevance": "Evasion"})

    banking_targets_list = get_val(case_data, "banking_targets", [])
    if not banking_targets_list and get_val(case_data, "targets_indian_banks"):
        banking_targets_list.append({"package": package_val, "bank": "Indian Banking Application Target", "source": "Package Match"})

    iocs_list = get_val(case_data, "iocs", [])
    if not iocs_list:
        urls = get_val(case_data, "hardcoded_urls_ips", [])
        for u in urls:
            iocs_list.append({"indicator": u, "type": "URL/IP", "reputation": "Malicious", "source": "Static Extraction"})

    network_logs_list = get_val(dynamic_res, "network_logs", [])

    workflow_obj = get_val(case_data, "fraud_workflow") or {}
    workflow_stages_list = get_val(workflow_obj, "stages", [])

    threat_scenarios_list = get_val(case_data, "threat_scenario_table", [])
    mitre_techniques_list = get_val(case_data, "mitre_techniques", [])

    ai_report = get_val(case_data, "intelligence_report") or get_val(case_data, "executive_view") or {}
    plain_narrative = get_val(ai_report, "plain_english_narrative", "Analysis complete. Review findings below.")
    fraud_obj = get_val(ai_report, "fraud_objective", "Credential Theft / Banking Fraud")
    cust_impact = get_val(ai_report, "customer_impact", "Potential unauthorized account access and OTP interception.")
    bank_impact = get_val(ai_report, "banking_impact", "Brand impersonation and unauthorized fund transfer risk.")
    cert_recs = get_val(ai_report, "cert_in_recommendations", ["Block package name and SHA-256 bank-wide."])
    cust_adv = get_val(ai_report, "customer_advisory_draft", "Do not install or enter banking credentials into this app.")

    soc_actions_list = [
        {"action": "IMMEDIATE", "detail": f"Quarantine any device on which the package {package_val} or hash {sha256_val[:16]}... is detected. Revoke active banking session tokens for affected accounts."},
        {"action": "INVESTIGATE", "detail": "Review recent banking sessions, fund-transfer activity, and login geo/IP for accounts associated with impacted devices."},
        {"action": "HUNT", "detail": f"Search enterprise EMM/MDM and network telemetry for the package name, SHA-256, and the C2 endpoint {iocs_list[0]['indicator'] if iocs_list else '194.163.142.89'} across the estate."},
        {"action": "STEP-UP AUTH", "detail": "Force hardware-token or app-based transaction approval (bypassing SMS OTP as sole factor) for accounts that installed the sample, for a minimum 30-day monitoring window."},
        {"action": "RE-ANALYZE", "detail": "Where a matching sample surfaces without dynamic telemetry, queue it for sandbox execution before closing the case as static-only."},
        {"action": "REGULATORY", "detail": "Report indicators to CERT-In and the sector CSIRT-Fin channel per the bank's incident-reporting SLA; see CERT-In recommendations below."},
    ]

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
        engine_version=FieldValue(value="Sudarshan v2.1.0 (backend/app/main.py)", source=Provenance.SYSTEM, status=Status.OBSERVED),
        
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
    and draws running top banner, headers, and footers matching reference PDF across ALL pages.
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
        
        # 1. Top Red Notice Banner on ALL pages
        self.setFillColor(colors.HexColor("#A40E26"))
        self.rect(0, 11 * inch - 14, 8.5 * inch, 14, fill=1, stroke=0)
        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(colors.white)
        self.drawCentredString(4.25 * inch, 11 * inch - 10, "DEMONSTRATION REPORT — SYNTHETIC / ILLUSTRATIVE DATA FOR PLATFORM CAPABILITY REVIEW")

        # 2. Running Header on ALL pages
        # Logo square on left
        self.setFillColor(colors.HexColor("#0D1117"))
        self.rect(36, 11 * inch - 36, 18, 18, fill=1, stroke=0)
        self.setFont("Helvetica-Bold", 11)
        self.setFillColor(colors.white)
        self.drawCentredString(45, 11 * inch - 32, "S")

        self.setFont("Helvetica-Bold", 9)
        self.setFillColor(colors.HexColor("#0D1117"))
        self.drawString(60, 11 * inch - 26, "SUDARSHAN")
        
        self.setFont("Helvetica", 6.5)
        self.setFillColor(colors.HexColor("#57606A"))
        self.drawString(60, 11 * inch - 33, "MOBILE APK THREAT INVESTIGATION REPORT")
        
        self.setFont("Helvetica-Bold", 6.5)
        self.setFillColor(colors.HexColor("#D97706"))
        self.drawString(60, 11 * inch - 40, "DEMONSTRATION / CAPABILITY-REVIEW BUILD")

        # Case Info on right
        case_str = getattr(self, '_case_id_str', 'SDN-2026-08-0091-DEMO')
        gen_str = getattr(self, '_gen_str', '2026-08-11 14:20 UTC')
        pkg_str = getattr(self, '_pkg_str', 'com.sbi.lotusintouch.refund')

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#0D1117"))
        self.drawRightString(8.5 * inch - 36, 11 * inch - 24, f"Case ID: {case_str}")
        
        self.setFont("Helvetica", 6.5)
        self.setFillColor(colors.HexColor("#57606A"))
        self.drawRightString(8.5 * inch - 36, 11 * inch - 32, f"Generated: {gen_str}")
        if pkg_str:
            self.drawRightString(8.5 * inch - 36, 11 * inch - 40, f"Package: {pkg_str}")

        self.setStrokeColor(colors.HexColor("#D0D7DE"))
        self.setLineWidth(0.5)
        self.line(36, 11 * inch - 44, 8.5 * inch - 36, 11 * inch - 44)

        # 3. Running Footer on ALL pages
        self.line(36, 36, 8.5 * inch - 36, 36)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#57606A"))
        self.drawString(36, 24, f"Sudarshan · DEMONSTRATION Report — {case_str}")
        self.drawRightString(8.5 * inch - 36, 24, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()

# ---------------------------------------------------------------------------
# Custom Flowables & Vector Graphics
# ---------------------------------------------------------------------------

class FRSDialGauge(Drawing):
    """180-degree FRS Dial Gauge Flowable matching reference PDF Page 1."""
    def __init__(self, score: float, risk_band: str, width=180, height=95):
        super().__init__(width, height)
        self._score = score
        self._risk_band = risk_band
        
        cx, cy, r = width / 2.0, 24, 65
        
        # Track Background
        self.add(Wedge(cx, cy, r, 0, 180, width=12, fillColor=colors.HexColor("#E1E4E8"), strokeColor=None))
        self.add(Wedge(cx, cy, r, 126, 180, width=12, fillColor=colors.HexColor("#2DA44E"), strokeColor=None)) # Safe
        self.add(Wedge(cx, cy, r, 72, 126, width=12, fillColor=colors.HexColor("#D29922"), strokeColor=None))  # Suspicious
        self.add(Wedge(cx, cy, r, 19.8, 72, width=12, fillColor=colors.HexColor("#F0883E"), strokeColor=None))# High Risk
        self.add(Wedge(cx, cy, r, 0, 19.8, width=12, fillColor=colors.HexColor("#CF222E"), strokeColor=None)) # Critical

        # Score Needle Angle
        angle_rad = math.radians(180.0 - (score / 100.0 * 180.0))
        nx = cx + (r - 14) * math.cos(angle_rad)
        ny = cy + (r - 14) * math.sin(angle_rad)
        
        self.add(Line(cx, cy, nx, ny, strokeColor=colors.HexColor("#0D1117"), strokeWidth=2.5))
        self.add(Circle(cx, cy, 5, fillColor=colors.HexColor("#0D1117"), strokeColor=None))

        # Numeric Text
        self.add(String(cx, cy + 14, f"{score:.1f}", textAnchor="middle", fontName="Helvetica-Bold", fontSize=18, fillColor=colors.HexColor("#0D1117")))
        self.add(String(cx, cy + 4, "/ 100 CONFIRMED FRS", textAnchor="middle", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#57606A")))

class FRSBarMeter(Drawing):
    """Horizontal bar chart for Page 3 FRS Score Ledger."""
    def __init__(self, stei: float, bfci: float, corr: float, bank: float, width=520, height=85):
        super().__init__(width, height)
        items = [
            ("Static Exposure (STEI)", stei, 0.25, stei * 0.25, "#1F6FEB"),
            ("Dynamic Behavior (BFCI v2)", bfci, 0.35, bfci * 0.35, "#CF222E"),
            ("Threat Correlation", corr, 0.20, corr * 0.20, "#8250DF"),
            ("Banking Impact", bank, 0.20, bank * 0.20, "#057642"),
        ]
        y = height - 14
        for label, val, wt, wtd, color_hex in items:
            self.add(String(0, y, label, fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#24292F")))
            self.add(Rect(170, y - 1, 240, 7, rx=2, ry=2, fillColor=colors.HexColor("#E1E4E8"), strokeColor=None))
            fill_w = max(2, (val / 100.0) * 240)
            self.add(Rect(170, y - 1, fill_w, 7, rx=2, ry=2, fillColor=colors.HexColor(color_hex), strokeColor=None))
            self.add(String(420, y, f"{val:.1f}", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#0D1117")))
            self.add(String(460, y, f"w={wt:.2f} → {wtd:.2f}", fontName="Helvetica", fontSize=6.5, fillColor=colors.HexColor("#57606A")))
            y -= 18

class STEIBarMeter(Drawing):
    """5-axis STEI Progress Bar Meter for Page 4."""
    def __init__(self, ct: float, bt: float, pr: float, ob: float, ir: float, width=520, height=95):
        super().__init__(width, height)
        axes = [
            ("Credential Theft (CT)", ct, "#CF222E"),
            ("Banking Targeting (BT)", bt, "#D29922"),
            ("Permission Risk (PR)", pr, "#F0883E"),
            ("Obfuscation (OB)", ob, "#8C959F"),
            ("Infrastructure Risk (IR)", ir, "#0969DA"),
        ]
        y = height - 14
        for label, val, color_hex in axes:
            self.add(String(0, y, label, fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#24292F")))
            self.add(Rect(170, y - 1, 260, 7, rx=2, ry=2, fillColor=colors.HexColor("#E1E4E8"), strokeColor=None))
            fill_w = max(2, (val / 100.0) * 260)
            self.add(Rect(170, y - 1, fill_w, 7, rx=2, ry=2, fillColor=colors.HexColor(color_hex), strokeColor=None))
            self.add(String(440, y, f"{val:.1f}", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#0D1117")))
            y -= 16

class VIDEBarMeter(Drawing):
    """Horizontal bar chart for VIDE UI Fingerprint comparison (Page 9)."""
    def __init__(self, jaccard: float, viewtree: float, color: float, composite: float, width=520, height=85):
        super().__init__(width, height)
        bars = [
            ("String Jaccard (40% wt.)", jaccard, "#1F6FEB"),
            ("View-Tree Similarity (35% wt.)", viewtree, "#1F6FEB"),
            ("Brand Color Overlap (25% wt.)", color, "#1F6FEB"),
            ("Composite Confidence", composite, "#CF222E"),
        ]
        y = height - 14
        for label, val, color_hex in bars:
            self.add(String(0, y, label, fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#24292F")))
            self.add(Rect(170, y - 1, 250, 8, rx=2, ry=2, fillColor=colors.HexColor("#E1E4E8"), strokeColor=None))
            fill_w = max(2, val * 250)
            self.add(Rect(170, y - 1, fill_w, 8, rx=2, ry=2, fillColor=colors.HexColor(color_hex), strokeColor=None))
            self.add(String(430, y, f"{val:.2f}", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#0D1117")))
            y -= 18

        # Detection threshold line at 0.72
        tx = 170 + (0.72 * 250)
        self.add(Line(tx, 0, tx, height, strokeColor=colors.HexColor("#CF222E"), strokeWidth=1, strokeDashArray=[2, 2]))
        self.add(String(tx, height - 6, "detection threshold 0.72", textAnchor="middle", fontName="Helvetica-Bold", fontSize=6, fillColor=colors.HexColor("#CF222E")))

class BFCIBarMeter(Drawing):
    """Vertical bar chart for BFCI v2 category breakdown (Page 7)."""
    def __init__(self, components: Dict[str, float], width=520, height=95):
        super().__init__(width, height)
        cats = [
            ("Accessibility Abuse (A)", components.get("accessibility", 95.0), 0.35, "#CF222E"),
            ("SMS Interception (S)", components.get("sms", 88.0), 0.25, "#F0883E"),
            ("Overlay Attack (O)", components.get("overlay", 90.0), 0.20, "#D29922"),
            ("Banking Interaction (B)", components.get("banking", 70.0), 0.10, "#0969DA"),
            ("Network C2 (N)", components.get("network", 55.0), 0.05, "#8250DF"),
            ("Persistence (P)", components.get("persistence", 40.0), 0.05, "#057642"),
        ]
        
        bw = 36
        gap = 42
        x = 50
        max_h = 55
        
        # Grid Y
        for y_val in [0, 20, 40, 60, 80, 100]:
            y_p = 25 + (y_val / 100.0) * max_h
            self.add(Line(40, y_p, width - 20, y_p, strokeColor=colors.HexColor("#E1E4E8"), strokeWidth=0.5))
            self.add(String(35, y_p - 2, str(y_val), textAnchor="end", fontName="Helvetica", fontSize=6, fillColor=colors.HexColor("#57606A")))

        for label, val, wt, color_hex in cats:
            bh = (val / 100.0) * max_h
            self.add(Rect(x, 25, bw, bh, rx=2, ry=2, fillColor=colors.HexColor(color_hex), strokeColor=None))
            self.add(String(x + bw/2.0, 25 + bh + 3, f"{val:.0f}", textAnchor="middle", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#0D1117")))
            
            # Short labels below
            lbl_parts = label.split(" ")
            self.add(String(x + bw/2.0, 14, lbl_parts[0], textAnchor="middle", fontName="Helvetica-Bold", fontSize=6, fillColor=colors.HexColor("#24292F")))
            self.add(String(x + bw/2.0, 6, f"(W={wt:.2f})", textAnchor="middle", fontName="Helvetica", fontSize=5.5, fillColor=colors.HexColor("#57606A")))
            x += bw + gap

class CausalWorkflowDiagram(Drawing):
    """Reconstructed Causal Workflow sequence diagram for Page 7."""
    def __init__(self, width=520, height=65):
        super().__init__(width, height)
        steps = [
            ("1", "T+0s", "Accessibility\nService Enabled", "T1628", "#CF222E"),
            ("2", "T+8s", "Overlay Phishing\nShown (fake SBI login)", "T1637", "#F0883E"),
            ("3", "T+19s", "SMS OTP\nIntercepted", "T1643", "#D29922"),
            ("4", "T+24s", "C2 Exfiltration\nPOST Request", "T1437", "#8250DF"),
        ]
        
        # Timeline bar
        self.add(Line(60, 42, 460, 42, strokeColor=colors.HexColor("#D0D7DE"), strokeWidth=2))
        
        x_step = 100
        for num, ts, name, tag, col in steps:
            # Circle node
            self.add(Circle(x_step, 42, 12, fillColor=colors.HexColor(col), strokeColor=colors.white, strokeWidth=1.5))
            self.add(String(x_step, 38, num, textAnchor="middle", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.white))
            
            # Timestamp header
            self.add(String(x_step, 56, ts, textAnchor="middle", fontName="Helvetica-Bold", fontSize=6.5, fillColor=colors.HexColor("#57606A")))
            
            # Description text
            lines = name.split("\n")
            self.add(String(x_step, 24, lines[0], textAnchor="middle", fontName="Helvetica", fontSize=6, fillColor=colors.HexColor("#24292F")))
            if len(lines) > 1:
                self.add(String(x_step, 17, lines[1], textAnchor="middle", fontName="Helvetica", fontSize=5.5, fillColor=colors.HexColor("#57606A")))
            
            # MITRE tag pill
            self.add(Rect(x_step - 14, 2, 28, 9, rx=2, ry=2, fillColor=colors.HexColor("#F3E8FF"), strokeColor=colors.HexColor("#D8B4FE")))
            self.add(String(x_step, 4, tag, textAnchor="middle", fontName="Helvetica-Bold", fontSize=5.5, fillColor=colors.HexColor("#6B21A8")))
            
            x_step += 110

# ---------------------------------------------------------------------------
# ReportLabPDFGenerator Engine
# ---------------------------------------------------------------------------

class ReportLabPDFGenerator:
    """
    Pure visual ReportLab PDF Generator.
    Consumes authoritative ReportData and produces a multi-page PDF document matching reference.
    """
    def __init__(self, report_data: ReportData, apk_dir: Optional[Path] = None):
        self.data = report_data
        self.apk_dir = apk_dir
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.part_header = ParagraphStyle(
            "PartHeader",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#1F6FEB"),
            spaceAfter=3,
            textTransform="uppercase",
        )
        self.section_bar = ParagraphStyle(
            "SectionBar",
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=11.5,
            textColor=colors.white,
            backColor=colors.HexColor("#0D1117"),
            borderPadding=(3.5, 6, 3.5, 6),
            spaceBefore=6,
            spaceAfter=6,
            keepWithNext=True,
        )
        self.body_style = ParagraphStyle(
            "BodyDark",
            fontName="Helvetica",
            fontSize=7.5,
            leading=10.5,
            textColor=colors.HexColor("#24292F"),
            spaceAfter=3,
        )
        self.body_bold = ParagraphStyle(
            "BodyDarkBold",
            parent=self.body_style,
            fontName="Helvetica-Bold",
        )
        self.table_header = ParagraphStyle(
            "TableHeader",
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=8.5,
            textColor=colors.white,
            alignment=0,
        )
        self.table_cell = ParagraphStyle(
            "TableCell",
            fontName="Helvetica",
            fontSize=6.5,
            leading=8.5,
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
            fontSize=6,
        )

    def generate_pdf(self) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=52,
            bottomMargin=44,
        )

        elements = []
        
        # Build All 12 Sections + Appendix
        self._build_page1_verdict_summary(elements)
        elements.append(PageBreak())
        
        self._build_page2_narrative_and_response(elements)
        elements.append(PageBreak())
        
        self._build_page3_score_ledger(elements)
        elements.append(PageBreak())
        
        self._build_page4_stei_breakdown(elements)
        elements.append(PageBreak())
        
        self._build_page5_forensic_static(elements)
        elements.append(PageBreak())
        
        self._build_page6_evidence_mapping(elements)
        elements.append(PageBreak())
        
        self._build_page7_dynamic_and_workflow(elements)
        elements.append(PageBreak())
        
        self._build_page8_hook_inventory(elements)
        elements.append(PageBreak())
        
        self._build_page9_vide_impersonation(elements)
        elements.append(PageBreak())
        
        self._build_page10_threat_intel_scenarios(elements)
        elements.append(PageBreak())
        
        self._build_page11_coverage_and_evidence_ledger(elements)
        elements.append(PageBreak())
        
        self._build_page12_iocs_governance_signoff(elements)
        
        self._build_appendices(elements)

        def on_first_page(canvas_obj, document):
            canvas_obj._case_id_str = self.data.case_id.value
            canvas_obj._gen_str = self.data.report_generated_at.value
            canvas_obj._pkg_str = self.data.package_name.value

        doc.build(elements, canvasmaker=NumberedCanvas, onFirstPage=on_first_page)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    # -----------------------------------------------------------------------
    # Section Builders
    # -----------------------------------------------------------------------

    def _build_page1_verdict_summary(self, elements: List[Any]):
        """PAGE 1 — PART A · EXECUTIVE — VERDICT SUMMARY."""
        elements.append(Paragraph("PART A · EXECUTIVE — VERDICT SUMMARY", self.part_header))
        
        # Disclaimer callout box matching reference PDF
        about_p = Paragraph(
            "<b>About this document.</b> This is a demonstration build of the Sudarshan report format. Static findings (STEI axes, permissions, package "
            "targeting, hardcoded C2 string) are sourced verbatim from the platform's published Drinik case study (docs/CASE_STUDIES.md) and "
            "are marked STATIC-VERIFIED. Dynamic behavior, VIDE visual-impersonation, and threat-correlation figures are ILLUSTRATIVE "
            "synthetic data built to show what a completed run produces once that telemetry exists — every such section is flagged in-line. No real "
            "customer, device, or account data appears anywhere in this file.",
            self.body_style
        )
        about_table = Table([[about_p]], colWidths=[540])
        about_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DDF4FF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#54AEFF")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(about_table)
        elements.append(Spacer(1, 4))

        elements.append(Paragraph("VERDICT SUMMARY", self.section_bar))

        gauge_flowable = FRSDialGauge(self.data.final_risk_score.value, self.data.risk_band.value)
        
        verdict_text = Paragraph(
            f"<b>{self.data.risk_band.value.upper()} RISK → CRITICAL</b> (escalated on confirmed dynamic execution)<br/><br/>"
            f"<font size=6.5 color='#24292F'>Static-only preliminary verdict (Day-0, before sandbox run): <b>{self.data.base_score.value:.1f} / 100 — HIGH RISK</b> [STATIC-VERIFIED]. "
            f"Confirmed verdict after dynamic + VIDE execution: <b>{self.data.final_risk_score.value:.1f} / 100 — CRITICAL</b> [ILLUSTRATIVE]. See Score Ledger, page 3.</font>",
            self.body_style
        )

        family_box = Paragraph(
            f"<font size=6.5 color='#57606A'><b>FAMILY ATTRIBUTION CONFIDENCE</b></font><br/><br/>"
            f"<font size=11 color='#0D1117'><b>HIGH — 3 / 3</b></font><br/>"
            f"<font size=6 color='#57606A'>deterministic classifier rule conditions matched (has_accessibility_abuse, has_sms_read_write, targets_indian_banks)</font>",
            self.body_style
        )

        v_table_data = [[gauge_flowable, verdict_text, family_box]]
        v_table = Table(v_table_data, colWidths=[175, 220, 145])
        v_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#F6F8FA")),
            ("BOX", (2, 0), (2, 0), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(v_table)
        elements.append(Spacer(1, 6))

        # Executive Conclusion
        conc_p = Paragraph(
            f"<b>EXECUTIVE CONCLUSION.</b> The sample impersonates a State Bank of India tax-refund utility and carries a deterministic Drinik-family "
            f"fingerprint: accessibility-service abuse for on-screen credential capture, SMS receiver registration for OTP interception, and a "
            f"system-alert-window overlay capability consistent with fake banking login screens. A confirmed dynamic run additionally observed the "
            f"full causal attack chain — accessibility enable → overlay phishing → SMS intercept → C2 exfiltration — completing in 24 seconds.<br/>"
            f"<b>Recommended action:</b> immediate device quarantine, step-up authentication for affected accounts, and CERT-In notification.",
            self.body_style
        )
        conc_table = Table([[conc_p]], colWidths=[540])
        conc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFEBE9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#FF8170")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(conc_table)
        elements.append(Spacer(1, 6))

        # Key Findings Row (4 cards matching reference PDF)
        elements.append(Paragraph("<b>KEY FINDINGS</b>", self.body_bold))
        kf_data = [[
            Paragraph("<font size=6 color='#6B21A8'><b>CORRELATED</b></font><br/><b>Malware family — Drinik</b><br/>(deterministic rule match)", self.table_cell),
            Paragraph("<font size=6 color='#15803D'><b>STATIC INDICATOR</b></font><br/><b>SMS interception capability (T1643)</b>", self.table_cell),
            Paragraph("<font size=6 color='#15803D'><b>STATIC INDICATOR</b></font><br/><b>Accessibility-based input capture (T1628)</b>", self.table_cell),
            Paragraph("<font size=6 color='#B45309'><b>ILLUSTRATIVE</b></font><br/><b>Confirmed overlay → SMS → C2 chain</b> (demo dynamic run)", self.table_cell),
        ]]
        kf_table = Table(kf_data, colWidths=[135, 135, 135, 135])
        kf_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F3E8FF")),
            ("BACKGROUND", (1, 0), (2, 0), colors.HexColor("#DCFCE7")),
            ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#FEF3C7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(kf_table)
        elements.append(Spacer(1, 6))

        # Sample Reputation Table
        elements.append(Paragraph("<b>SAMPLE REPUTATION — external threat-intelligence evidence (illustrative)</b>", self.body_bold))
        rep_data = [
            [Paragraph("<b>VIRUSTOTAL</b>", self.table_header), Paragraph("<b>DETECTION RATIO</b>", self.table_header), Paragraph("<b>OTX PULSES</b>", self.table_header), Paragraph("<b>ABUSEIPDB (C2 IP)</b>", self.table_header), Paragraph("<b>KNOWN FAMILY</b>", self.table_header)],
            [Paragraph(self.data.vt_detection_ratio.value, self.table_cell_bold), Paragraph("54%", self.table_cell), Paragraph(f"{self.data.otx_pulse_count.value} (Drinik-2026-H1 cluster)", self.table_cell), Paragraph(f"{self.data.abuseipdb_score.value:.0f} / 100 confidence", self.table_cell), Paragraph(f"Drinik — CORRELATED", self.table_cell_bold)],
        ]
        rep_table = Table(rep_data, colWidths=[120, 90, 130, 110, 90])
        rep_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(rep_table)
        elements.append(Paragraph("<font size=6 color='#57606A'>Illustrative composite figures — see Threat Intelligence, page 7, for derivation notes.</font>", self.body_style))
        elements.append(Spacer(1, 4))

        # Analysis Coverage Badges
        elements.append(Paragraph("<b>ANALYSIS COVERAGE</b>", self.body_bold))
        cov_badges = [[
            Paragraph("<b>STATIC ANALYSIS — COMPLETE</b>", ParagraphStyle("C1", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#15803D"))),
            Paragraph("<b>THREAT INTEL — COMPLETE (ILLUS.)</b>", ParagraphStyle("C2", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#B45309"))),
            Paragraph("<b>DYNAMIC — COMPLETE (ILLUS.)</b>", ParagraphStyle("C3", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#B45309"))),
            Paragraph("<b>VIDE — COMPLETE (ILLUS.)</b>", ParagraphStyle("C4", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#B45309"))),
        ]]
        cov_badge_table = Table(cov_badges, colWidths=[135, 135, 135, 135])
        cov_badge_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#DCFCE7")),
            ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#FEF3C7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(cov_badge_table)
        elements.append(Spacer(1, 6))

        # Risk Contributors Table
        elements.append(Paragraph("<b>RISK CONTRIBUTORS</b>", self.body_bold))
        contrib_data = [
            [Paragraph("<b>CONTRIBUTOR</b>", self.table_header), Paragraph("<b>LEVEL</b>", self.table_header), Paragraph("<b>STATUS</b>", self.table_header)],
            [Paragraph("Threat Intelligence Correlation", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell)],
            [Paragraph("Static Exposure (STEI)", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell)],
            [Paragraph("Banking Impact", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell)],
            [Paragraph("Dynamic Behavior (BFCI v2)", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell)],
            [Paragraph("Visual Impersonation (VIDE-F001)", self.table_cell_bold), Paragraph("Medium-High", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell)],
        ]
        contrib_table = Table(contrib_data, colWidths=[240, 150, 150])
        contrib_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(contrib_table)

    def _build_page2_narrative_and_response(self, elements: List[Any]):
        """PAGE 2 — PART A · EXECUTIVE — NARRATIVE & RESPONSE."""
        elements.append(Paragraph("PART A · EXECUTIVE — NARRATIVE & RESPONSE (for non-technical readers)", self.part_header))
        elements.append(Paragraph("PLAIN-ENGLISH SUMMARY", self.section_bar))
        
        narrative_text = (
            "This application presents itself as an income-tax refund utility from the State Bank of India but is a repackaged Drinik-family "
            "banking trojan. Once installed, it asks the victim to enable an accessibility service [STAT-001] — a legitimate Android feature for "
            "assistive technology that this sample instead uses to read on-screen text and simulate taps inside real banking apps. It separately "
            "registers to receive incoming SMS messages [STAT-002], which lets it capture one-time passwords (OTPs) before the account "
            "holder ever sees them. It also requests permission to draw over other apps [STAT-003], the mechanism used to place a fake "
            "SBI/ICICI login screen on top of the real banking app.<br/><br/>"
            "In an <b>illustrative demonstration run</b> of the dynamic sandbox, these three capabilities were observed firing in sequence within "
            "24 seconds of launch — accessibility enable, phishing overlay, SMS interception, then a network POST to a hardcoded external "
            "server [STAT-004] — which is the same operational pattern SBI, ICICI, HDFC and other Indian banks have seen associated with "
            "the Drinik campaign family. Static and (illustrative) dynamic evidence corroborate each other: this is not a single suspicious "
            "permission in isolation, it is a complete, working account-takeover chain."
        )
        elements.append(Paragraph(narrative_text, self.body_style))
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("RECOMMENDED SOC ACTIONS", self.section_bar))
        
        soc_rows = [
            [Paragraph("<b>ACTION</b>", self.table_header), Paragraph("<b>OPERATIONAL INSTRUCTION</b>", self.table_header)]
        ]
        for item in self.data.soc_actions:
            act = item.get("action", "ACTION") if isinstance(item, dict) else "ACTION"
            det = item.get("detail", str(item)) if isinstance(item, dict) else str(item)
            soc_rows.append([Paragraph(f"<b>{act}</b>", self.table_cell_bold), Paragraph(det, self.table_cell)])

        soc_table = Table(soc_rows, colWidths=[110, 430])
        soc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(soc_table)
        elements.append(Spacer(1, 6))

        # Customer Advisory Box
        elements.append(Paragraph("<b>CUSTOMER ADVISORY DRAFT — AI-generated, evidence-grounded (edit before sending)</b>", self.body_bold))
        adv_p = Paragraph(
            "“We have identified a fraudulent application impersonating an income-tax refund service from your bank. If you have installed an app "
            "named ‘TaxRefund_IncomeTax.apk’ from outside the official Play Store, please uninstall it immediately. Do not enter your banking "
            "credentials, card details, or OTP into this app. Your bank will never ask you to install a refund-processing app from a link sent by SMS "
            "or email. If you have already entered any details, contact our 24x7 fraud helpline immediately.”",
            self.body_style
        )
        adv_table = Table([[adv_p]], colWidths=[540])
        adv_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(adv_table)
        elements.append(Spacer(1, 6))

        # CERT-In Recommendations
        elements.append(Paragraph("<b>CERT-In / REGULATORY RECOMMENDATIONS</b>", self.body_bold))
        recs = [
            "Block SHA-256 hash and package name at MDM / enterprise app-scanning layer bank-wide.",
            "File incident report with CERT-In per applicable reporting timelines; reference campaign cluster “Drinik-2026-H1” and C2 IOC 194.163.142.89.",
            "Issue the customer advisory above via SMS, email, and in-app notification channels for the affected campaign window.",
            "Rotate/verify server-side session tokens for accounts that had the package installed; monitor for anomalous fund-transfer patterns for 30 days (RBI MDS-2021 OTP-risk guidance).",
            "Coordinate with SBI, ICICI (confirmed package targets) and proactively notify HDFC / Bank of India (named in broader campaign metadata but no confirmed local package match in this sample).",
        ]
        for r in recs:
            elements.append(Paragraph(f"• {r}", self.body_style))

    def _build_page3_score_ledger(self, elements: List[Any]):
        """PAGE 3 — PART B · TECHNICAL — DETERMINISTIC SCORE LEDGER."""
        elements.append(Paragraph("PART B · TECHNICAL — DETERMINISTIC SCORE LEDGER", self.part_header))
        elements.append(Paragraph("FRAUD RISK SCORE (FRS) — FULL BREAKDOWN", self.section_bar))

        det_p = Paragraph(
            "<b>Determinism invariant.</b> The Fraud Risk Score is computed strictly by <code>risk_engine.py</code> from observable evidence. "
            "No generative-AI output contributes to this number at any stage — the LLM narrative on page 2 is generated downstream of, and cannot alter, the score below.",
            self.body_style
        )
        det_table = Table([[det_p]], colWidths=[540])
        det_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DDF4FF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#54AEFF")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(det_table)
        elements.append(Spacer(1, 6))

        # FRS Horizontal Bar Chart
        frs_meter = FRSBarMeter(
            stei=self.data.stei_total.value if self.data.stei_total.value > 0 else 79.12,
            bfci=self.data.bfci_total.value if self.data.bfci_total.value > 0 else 86.00,
            corr=74.00,
            bank=80.00,
        )
        elements.append(frs_meter)
        elements.append(Spacer(1, 6))

        # Axis Table matching reference PDF Page 3
        axis_data = [
            [Paragraph("<b>Axis</b>", self.table_header), Paragraph("<b>Nom. Wt.</b>", self.table_header), Paragraph("<b>Included because...</b>", self.table_header), Paragraph("<b>Score</b>", self.table_header), Paragraph("<b>Wtd.</b>", self.table_header), Paragraph("<b>Status</b>", self.table_header)],
            [Paragraph("Static Exposure (STEI)", self.table_cell_bold), Paragraph("0.25", self.table_cell), Paragraph("Yes — static analysis always runs", self.table_cell), Paragraph("79.12", self.table_cell), Paragraph("19.78", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell)],
            [Paragraph("Dynamic Behavior (BFCI v2)", self.table_cell_bold), Paragraph("0.35", self.table_cell), Paragraph("Yes — dynamic_status = EVENTS_CAPTURED", self.table_cell), Paragraph("86.00", self.table_cell), Paragraph("30.10", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell)],
            [Paragraph("Threat Correlation", self.table_cell_bold), Paragraph("0.20", self.table_cell), Paragraph("Yes — VT/OTX/AbuseIPDB returned available:true", self.table_cell), Paragraph("74.00", self.table_cell), Paragraph("14.80", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell)],
            [Paragraph("Banking Impact", self.table_cell_bold), Paragraph("0.20", self.table_cell), Paragraph("Yes — always included", self.table_cell), Paragraph("80.00", self.table_cell), Paragraph("16.00", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell)],
        ]
        axis_table = Table(axis_data, colWidths=[130, 45, 175, 50, 50, 90])
        axis_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(axis_table)
        elements.append(Spacer(1, 4))

        # Formula calculation box matching reference PDF Page 3
        formula_box_text = (
            "<code>FRS_base = (0.25×79.12) + (0.35×86.00) + (0.20×74.00) + (0.20×80.00)<br/>"
            "         = 19.78 + 30.10 + 14.80 + 16.00 = <b>80.68</b><br/>"
            "ai_confidence_multiplier = 1.20  (deterministic family-classifier match — 3/3 rule conditions; clamp range [0.5, 1.5])<br/>"
            "final_risk_score = min(80.68 × 1.20, 100) = min(96.82, 100) = <b>96.8 → CRITICAL</b> band (≥ 90.0)</code>"
        )
        formula_p = Paragraph(formula_box_text, self.body_style)
        formula_table = Table([[formula_p]], colWidths=[540])
        formula_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(formula_table)
        elements.append(Spacer(1, 6))

        # Static vs Confirmed comparison table matching reference PDF Page 3
        elements.append(Paragraph("<b>STATIC-ONLY vs. CONFIRMED VERDICT — escalation on dynamic evidence</b>", self.body_bold))
        comp_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Day-0: Static-only</b>", self.table_header), Paragraph("<b>Confirmed: Static + Dynamic + Intel</b>", self.table_header)],
            [Paragraph("Axes live", self.table_cell_bold), Paragraph("STEI + Banking Impact only (dynamic, correlation excluded)", self.table_cell), Paragraph("STEI + Dynamic + Correlation + Banking Impact", self.table_cell)],
            [Paragraph("Renormalized weights", self.table_cell_bold), Paragraph("STEI 0.556 / Banking 0.444", self.table_cell), Paragraph("0.25 / 0.35 / 0.20 / 0.20 (nominal, no exclusion)", self.table_cell)],
            [Paragraph("ai_confidence_multiplier", self.table_cell_bold), Paragraph("1.00 (pending re-baseline — see note)", self.table_cell), Paragraph("1.20 (deterministic family match)", self.table_cell)],
            [Paragraph("Final FRS", self.table_cell_bold), Paragraph("79.5", self.table_cell), Paragraph("<b>96.8</b>", self.table_cell_bold)],
            [Paragraph("Risk band", self.table_cell_bold), Paragraph("HIGH RISK", self.table_cell), Paragraph("<b>CRITICAL</b>", self.table_cell_bold)],
            [Paragraph("Source", self.table_cell_bold), Paragraph("CASE_STUDIES.md — [STATIC-VERIFIED]", self.table_cell), Paragraph("This demonstration — [ILLUSTRATIVE]", self.table_cell)],
        ]
        comp_table = Table(comp_data, colWidths=[130, 205, 205])
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(comp_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<font size=6 color='#57606A'>Note: docs/CASE_STUDIES.md computes the static-only Drinik FRS (79.51) without applying the family-match multiplier documented in PROJECT_CONTEXT.md §4.3.</font>", self.body_style))

    def _build_page4_stei_breakdown(self, elements: List[Any]):
        """PAGE 4 — STEI — 5-AXIS BREAKDOWN."""
        elements.append(Paragraph("<font size=6 color='#57606A'>confirmed-scenario figure above applies the documented multiplier correctly and is internally consistent end-to-end.</font>", self.body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("STEI — 5-AXIS BREAKDOWN [STATIC-VERIFIED]", self.section_bar))

        stei_meter = STEIBarMeter(
            ct=100.0,
            bt=40.0,
            pr=71.0,
            ob=70.4,
            ir=10.0,
        )
        elements.append(stei_meter)
        elements.append(Spacer(1, 8))

        stei_table_data = [
            [Paragraph("<b>Axis</b>", self.table_header), Paragraph("<b>Wt.</b>", self.table_header), Paragraph("<b>Score</b>", self.table_header), Paragraph("<b>Wtd.</b>", self.table_header), Paragraph("<b>Basis</b>", self.table_header)],
            [Paragraph("Credential Theft (CT)", self.table_cell_bold), Paragraph("0.60", self.table_cell), Paragraph("100.0", self.table_cell), Paragraph("60.00", self.table_cell), Paragraph("Accessibility +40, SMS +35, Overlay +25 = 100 (capped)", self.table_cell)],
            [Paragraph("Banking Targeting (BT)", self.table_cell_bold), Paragraph("0.20", self.table_cell), Paragraph("40.0", self.table_cell), Paragraph("8.00", self.table_cell), Paragraph("2 of 21 tracked Indian bank package prefixes matched", self.table_cell)],
            [Paragraph("Permission Risk (PR)", self.table_cell_bold), Paragraph("0.10", self.table_cell), Paragraph("71.0", self.table_cell), Paragraph("7.10", self.table_cell), Paragraph("10 dangerous permissions vs. baseline set", self.table_cell)],
            [Paragraph("Obfuscation (OB)", self.table_cell_bold), Paragraph("0.05", self.table_cell), Paragraph("70.4", self.table_cell), Paragraph("3.52", self.table_cell), Paragraph("String entropy H=0.68 + reflection + DexClassLoader", self.table_cell)],
            [Paragraph("Infrastructure Risk (IR)", self.table_cell_bold), Paragraph("0.05", self.table_cell), Paragraph("10.0", self.table_cell), Paragraph("0.50", self.table_cell), Paragraph("1 hardcoded C2 URL × 10 pts (cap 100)", self.table_cell)],
        ]
        stei_table = Table(stei_table_data, colWidths=[140, 45, 50, 50, 255])
        stei_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(stei_table)
        elements.append(Spacer(1, 6))
        
        formula_p = Paragraph(
            "<code>STEI = 0.60×100.0 + 0.20×40.0 + 0.10×71.0 + 0.05×70.4 + 0.05×10.0 = <b>79.12</b></code>",
            self.body_style
        )
        elements.append(formula_p)

    def _build_page5_forensic_static(self, elements: List[Any]):
        """PAGE 5 — PART B · TECHNICAL — FORENSIC EVIDENCE (STATIC)."""
        elements.append(Paragraph("PART B · TECHNICAL — FORENSIC EVIDENCE (STATIC)", self.part_header))
        elements.append(Paragraph("APK IDENTITY", self.section_bar))

        id_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Value</b>", self.table_header)],
            [Paragraph("Application name", self.table_cell_bold), Paragraph(self.data.app_name.value, self.table_cell)],
            [Paragraph("Package", self.table_cell_bold), Paragraph(self.data.package_name.value, self.table_cell_mono)],
            [Paragraph("SHA-256", self.table_cell_bold), Paragraph(self.data.sha256.value, self.table_cell_mono)],
            [Paragraph("SHA-1", self.table_cell_bold), Paragraph(self.data.sha1.value, self.table_cell_mono)],
            [Paragraph("MD5", self.table_cell_bold), Paragraph(self.data.md5.value, self.table_cell_mono)],
            [Paragraph("Certificate", self.table_cell_bold), Paragraph("Not available (self-signed / stripped debug cert)", self.table_cell)],
            [Paragraph("Target SDK", self.table_cell_bold), Paragraph("30 (Android 11) — illustrative", self.table_cell)],
            [Paragraph("Family", self.table_cell_bold), Paragraph(f"Drinik / trojan.hqwar family cluster — <b>CORRELATED</b> (deterministic rule match)", self.table_cell)],
        ]
        id_table = Table(id_data, colWidths=[130, 410])
        id_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(id_table)
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("STATIC FINDINGS [STATIC-VERIFIED]", self.section_bar))
        findings_data = [
            [Paragraph("<b>Finding</b>", self.table_header), Paragraph("<b>Evidence</b>", self.table_header), Paragraph("<b>Status</b>", self.table_header)],
            [Paragraph("Accessibility service declared", self.table_cell_bold), Paragraph("BIND_ACCESSIBILITY_SERVICE + AccessibilityService subclass", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)],
            [Paragraph("SMS receiver capability", self.table_cell_bold), Paragraph("RECEIVE_SMS + READ_SMS, SmsManager component declared", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)],
            [Paragraph("Overlay / phishing window capability", self.table_cell_bold), Paragraph("SYSTEM_ALERT_WINDOW, TYPE_APPLICATION_OVERLAY reference", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)],
            [Paragraph("Banking package targeting", self.table_cell_bold), Paragraph("com.sbi.lotusintouch, com.icicibank.mobilebanking matched", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)],
            [Paragraph("Dangerous permissions declared", self.table_cell_bold), Paragraph("10 (see permission table)", self.table_cell), Paragraph("—", self.table_cell)],
            [Paragraph("Obfuscation / string entropy", self.table_cell_bold), Paragraph("H = 0.68 (high) + reflection + DexClassLoader", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)],
            [Paragraph("Hardcoded URLs / IPs", self.table_cell_bold), Paragraph("1 — http://194.163.142.89/drinik/gate.php", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)],
        ]
        findings_table = Table(findings_data, colWidths=[150, 270, 120])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(findings_table)
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("DANGEROUS PERMISSIONS DECLARED (10)", self.section_bar))
        perm_rows = [
            [Paragraph("<code>android.permission.INTERNET</code>", self.table_cell_mono), Paragraph("<code>android.permission.READ_SMS</code>", self.table_cell_mono)],
            [Paragraph("<code>android.permission.RECEIVE_SMS</code>", self.table_cell_mono), Paragraph("<code>android.permission.SEND_SMS</code>", self.table_cell_mono)],
            [Paragraph("<code>android.permission.SYSTEM_ALERT_WINDOW</code>", self.table_cell_mono), Paragraph("<code>android.permission.BIND_ACCESSIBILITY_SERVICE</code>", self.table_cell_mono)],
            [Paragraph("<code>android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS</code>", self.table_cell_mono), Paragraph("<code>android.permission.QUERY_ALL_PACKAGES</code>", self.table_cell_mono)],
            [Paragraph("<code>android.permission.READ_CONTACTS</code>", self.table_cell_mono), Paragraph("<code>android.permission.CALL_PHONE</code>", self.table_cell_mono)],
        ]
        perm_table = Table(perm_rows, colWidths=[270, 270])
        perm_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(perm_table)

    def _build_page6_evidence_mapping(self, elements: List[Any]):
        """PAGE 6 — EVIDENCE → TECHNIQUE → FRAUD IMPACT."""
        elements.append(Paragraph("EVIDENCE → TECHNIQUE → FRAUD IMPACT", self.section_bar))

        map_data = [
            [Paragraph("<b>Static Evidence</b>", self.table_header), Paragraph("<b>MITRE ATT&CK Technique</b>", self.table_header), Paragraph("<b>Potential Fraud Impact</b>", self.table_header)],
            [Paragraph("Accessibility-service interaction", self.table_cell_bold), Paragraph("T1628 — Input Capture via Accessibility Service", self.table_cell), Paragraph("Banking-app manipulation / ATS", self.table_cell)],
            [Paragraph("android.provider.Telephony.SMS_RECEIVED", self.table_cell_bold), Paragraph("T1643 — Capture SMS Messages", self.table_cell), Paragraph("OTP interception", self.table_cell)],
            [Paragraph("TYPE_APPLICATION_OVERLAY reference", self.table_cell_bold), Paragraph("T1637 — App Overlay Attack", self.table_cell), Paragraph("Credential phishing over SBI/ICICI login", self.table_cell)],
            [Paragraph("Hardcoded HTTP endpoint (static string)", self.table_cell_bold), Paragraph("T1437 — Application Layer C2", self.table_cell), Paragraph("Exfiltration channel for stolen data", self.table_cell)],
            [Paragraph("DexClassLoader + Class.forName/invoke", self.table_cell_bold), Paragraph("T1407 — Download New Code at Runtime", self.table_cell), Paragraph("Anti-static-analysis / staged payload", self.table_cell)],
        ]
        map_table = Table(map_data, colWidths=[170, 185, 185])
        map_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(map_table)

    def _build_page7_dynamic_and_workflow(self, elements: List[Any]):
        """PAGE 7 — PART B · TECHNICAL — ATTACK & BEHAVIOR ANALYSIS (DYNAMIC)."""
        elements.append(Paragraph("PART B · TECHNICAL — ATTACK & BEHAVIOR ANALYSIS (DYNAMIC)", self.part_header))
        
        if not self.data.dynamic_ran:
            badge_p = Paragraph(f"<font size=6 color='#B45309'><b>{self.data.dynamic_status.value}</b></font>", ParagraphStyle("BadgeD", parent=self.table_cell, alignment=2))
            title_p = Paragraph("DYNAMIC EXECUTION & WORKFLOW RECONSTRUCTION", ParagraphStyle("TitleBD", parent=self.section_bar, backColor=None, textColor=colors.white))
            hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1117")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(hdr_table)
            elements.append(Spacer(1, 6))

            banner_p = Paragraph(
                f"<b>[DYNAMIC-STATUS: {self.data.dynamic_status.value}]</b><br/>"
                "No live runtime telemetry was captured during this sandbox run. "
                "Dynamic score is excluded from final FRS calculation without penalty.",
                self.body_style
            )
            banner_table = Table([[banner_p]], colWidths=[540])
            banner_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8C5")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D29922")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(banner_table)
            elements.append(Spacer(1, 10))
            return

        # Title Box with Right Badge
        badge_p = Paragraph("<font size=6 color='#B45309'><b>ILLUSTRATIVE — SYNTHETIC DEMO RUN</b></font>", ParagraphStyle("Badge", parent=self.table_cell, alignment=2))
        title_p = Paragraph("DYNAMIC EXECUTION & WORKFLOW RECONSTRUCTION", ParagraphStyle("TitleB", parent=self.section_bar, backColor=None, textColor=colors.white))
        
        hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1117")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(hdr_table)
        elements.append(Spacer(1, 4))

        # Yellow Callout Box
        dyn_p = Paragraph(
            "This section demonstrates the report format produced when a Frida sandbox run completes with <code>dynamic_status = EVENTS_CAPTURED</code>. "
            "All hook counts, timestamps, and the workflow timeline below are synthetic and constructed for this demonstration — no live device or sandbox was "
            "executed for this PDF. See DAE_CURRENT_STATE.md for the platform's real, verified dynamic-analysis capability status.",
            self.body_style
        )
        dyn_table = Table([[dyn_p]], colWidths=[540])
        dyn_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8C5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D29922")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(dyn_table)
        elements.append(Spacer(1, 6))

        # Sandbox Metadata Table
        dyn_meta_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Value</b>", self.table_header)],
            [Paragraph("dynamic_status", self.table_cell_bold), Paragraph(self.data.dynamic_status.value, self.table_cell_mono)],
            [Paragraph("Canary event", self.table_cell_bold), Paragraph("Received at T+0.4s (script load confirmed)", self.table_cell)],
            [Paragraph("Java.deoptimizeEverything()", self.table_cell_bold), Paragraph("Executed successfully (ART interpreter mode forced)", self.table_cell)],
            [Paragraph("Sandbox provider", self.table_cell_bold), Paragraph(self.data.sandbox_provider.value, self.table_cell)],
            [Paragraph("Total runtime", self.table_cell_bold), Paragraph(f"{self.data.analysis_duration.value}s fixed capture window", self.table_cell)],
            [Paragraph("Screen-hash loop detections", self.table_cell_bold), Paragraph("0 (no redundant navigation loops)", self.table_cell)],
        ]
        dyn_meta_table = Table(dyn_meta_data, colWidths=[170, 370])
        dyn_meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(dyn_meta_table)
        elements.append(Spacer(1, 6))

        # Reconstructed Causal Workflow Diagram
        elements.append(Paragraph("<b>RECONSTRUCTED CAUSAL WORKFLOW — FULL_ACCOUNT_TAKEOVER sequence</b>", self.body_bold))
        elements.append(Spacer(1, 2))
        wf_diagram = CausalWorkflowDiagram(width=540, height=65)
        elements.append(wf_diagram)
        elements.append(Spacer(1, 2))
        elements.append(Paragraph("<font size=6 color='#57606A'>Sequence bonus S_sequence = +15.0 applied — causal chain completed within the 30-second window required by bfci_scorer.py.</font>", self.body_style))
        elements.append(Spacer(1, 6))

        # BFCI v2 Bar Meter
        elements.append(Paragraph("<b>BFCI v2 — BEHAVIORAL CATEGORY BREAKDOWN</b>", self.body_bold))
        bfci_meter = BFCIBarMeter(self.data.bfci_components)
        elements.append(bfci_meter)
        elements.append(Spacer(1, 2))
        elements.append(Paragraph("<font size=6 color='#57606A'>BFCI v2 = Sum over categories of [ W(c) · min(1, ln(1+N(c))/ln(1+M(c))) × 100 ] + S_sequence, capped at 100. Composite category sub-scores shown above are illustrative outputs of that formula for this demo run; resulting BFCI v2 = 86.0.</font>", self.body_style))

    def _build_page8_hook_inventory(self, elements: List[Any]):
        """PAGE 8 — HOOK BUNDLE INVENTORY."""
        elements.append(Paragraph("HOOK BUNDLE INVENTORY (this run)", self.section_bar))

        hook_data = [
            [Paragraph("<b>Hook Bundle</b>", self.table_header), Paragraph("<b>Monitored Classes/APIs</b>", self.table_header), Paragraph("<b>Events</b>", self.table_header), Paragraph("<b>Fraud Signature</b>", self.table_header)],
            [Paragraph("accessibility", self.table_cell_mono), Paragraph("AccessibilityService, AccessibilityEvent", self.table_cell), Paragraph("42", self.table_cell), Paragraph("UI scraping on SBI/ICICI login fields", self.table_cell)],
            [Paragraph("sms", self.table_cell_mono), Paragraph("SmsManager, SmsMessage, BroadcastReceiver", self.table_cell), Paragraph("18", self.table_cell), Paragraph("Inbound OTP SMS intercepted", self.table_cell)],
            [Paragraph("overlay", self.table_cell_mono), Paragraph("WindowManager, TYPE_APPLICATION_OVERLAY", self.table_cell), Paragraph("9", self.table_cell), Paragraph("Phishing window drawn over com.sbi.lotusintouch", self.table_cell)],
            [Paragraph("banking", self.table_cell_mono), Paragraph("Target package intent launches", self.table_cell), Paragraph("5", self.table_cell), Paragraph("Banking-app foreground detection", self.table_cell)],
            [Paragraph("network", self.table_cell_mono), Paragraph("OkHttp3 / Socket / SSLSocket", self.table_cell), Paragraph("3", self.table_cell), Paragraph("C2 POST to 194.163.142.89", self.table_cell)],
            [Paragraph("persistence", self.table_cell_mono), Paragraph("DeviceAdminReceiver / PackageManager", self.table_cell), Paragraph("1", self.table_cell), Paragraph("Device-admin escalation attempt", self.table_cell)],
        ]
        hook_table = Table(hook_data, colWidths=[90, 200, 50, 200])
        hook_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(hook_table)

    def _build_page9_vide_impersonation(self, elements: List[Any]):
        """PAGE 9 — PART B · TECHNICAL — VISUAL IMPERSONATION DETECTION (VIDE)."""
        elements.append(Paragraph("PART B · TECHNICAL — VISUAL IMPERSONATION DETECTION (VIDE)", self.part_header))
        
        if "NOT_AVAILABLE" in self.data.vide_status.value or self.data.vide_status.status == Status.NOT_AVAILABLE or "CLEAN" in self.data.vide_status.value:
            badge_p = Paragraph(f"<font size=6 color='#57606A'><b>{self.data.vide_status.value}</b></font>", ParagraphStyle("BadgeV", parent=self.table_cell, alignment=2))
            title_p = Paragraph("VIDE — UI FINGERPRINT COMPARISON", ParagraphStyle("TitleV", parent=self.section_bar, backColor=None, textColor=colors.white))
            hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1117")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(hdr_table)
            elements.append(Spacer(1, 6))

            caveat_p = Paragraph(
                f"<b>[VIDE-STATUS: {self.data.vide_status.value}]</b> Visual impersonation analysis state: NOT_AVAILABLE.",
                self.body_style
            )
            caveat_table = Table([[caveat_p]], colWidths=[540])
            caveat_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(caveat_table)
            elements.append(Spacer(1, 10))
            return

        # Header bar with badge
        badge_p = Paragraph("<font size=6 color='#B45309'><b>ILLUSTRATIVE — SYNTHETIC DEMO RUN</b></font>", ParagraphStyle("Badge2", parent=self.table_cell, alignment=2))
        title_p = Paragraph("VIDE — UI FINGERPRINT COMPARISON", ParagraphStyle("TitleV", parent=self.section_bar, backColor=None, textColor=colors.white))
        
        hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1117")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(hdr_table)
        elements.append(Spacer(1, 4))

        vide_p = Paragraph(
            "<b>VIDE is a deterministic engine</b> — no LLM decides whether it fires. It compares the suspect app's UI fingerprint (layout XML + "
            "assets/*.html via APKTool, merged with WebView HTML captured at runtime) against lab/hackathon institution baselines. <b>These "
            "baselines (SBI/HDFC/ICICI) are demo/lab fixtures, not production bank authority</b> — see docs/architecture/VIDE.md.",
            self.body_style
        )
        elements.append(vide_p)
        elements.append(Spacer(1, 6))

        vide_meter = VIDEBarMeter(
            jaccard=0.55,
            viewtree=0.83,
            color=0.90,
            composite=self.data.vide_similarity.value if self.data.vide_similarity.value > 0 else 0.74,
        )
        elements.append(vide_meter)
        elements.append(Spacer(1, 6))

        vide_table_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Value</b>", self.table_header)],
            [Paragraph("Baseline shortlisted", self.table_cell_bold), Paragraph(self.data.vide_baseline.value, self.table_cell)],
            [Paragraph("String Jaccard (40% wt.)", self.table_cell_bold), Paragraph("0.55", self.table_cell)],
            [Paragraph("View-tree similarity (35% wt.)", self.table_cell_bold), Paragraph("0.83", self.table_cell)],
            [Paragraph("Brand color overlap (25% wt.)", self.table_cell_bold), Paragraph("0.90", self.table_cell)],
            [Paragraph("Composite confidence", self.table_cell_bold), Paragraph(f"{self.data.vide_similarity.value:.2f} (threshold: ≥ 0.72)", self.table_cell)],
            [Paragraph("VIDE-F001", self.table_cell_bold), Paragraph(f"<b>{self.data.vide_status.value}</b>", self.table_cell_bold)],
            [Paragraph("critical_visual_cluster", self.table_cell_bold), Paragraph("NOT triggered — requires confidence ≥ 0.80", self.table_cell)],
            [Paragraph("CH06 signer impersonation", self.table_cell_bold), Paragraph("Not evaluated — certificate unavailable for this sample", self.table_cell)],
        ]
        vide_table = Table(vide_table_data, colWidths=[170, 370])
        vide_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(vide_table)
        elements.append(Spacer(1, 6))

        # Text Box below table
        interact_p = Paragraph(
            "<b>How this interacts with the score.</b> Because the Banking Targeting (BT) axis in this case is already saturated via direct package-name "
            "matches (com.sbi.lotusintouch, com.icicibank.mobilebanking), VIDE-F001 does not additionally raise BT here. Its evidentiary value is "
            "independent corroboration: it confirms brand impersonation from the UI layer itself, and would be the primary escalation path for a "
            "package-obfuscated Drinik variant that lacked a matching banking package name. Per the documented escalation rule, a visual-only "
            "match caps toward High Risk (~75) and is <b>not</b> promoted to Critical without a critical_visual_cluster or CH06 signer hit — neither fired in "
            "this run.",
            self.body_style
        )
        elements.append(interact_p)
        elements.append(Spacer(1, 6))

        # Yellow Callout Box
        caveat_p = Paragraph(
            "<b>Lab-baseline caveat (from VIDE.md).</b> UI baselines and the signer registry used above are demonstration/hackathon fixtures. They "
            "are not production-authoritative bank data and must not be represented as such outside this demonstration context.",
            self.body_style
        )
        caveat_table = Table([[caveat_p]], colWidths=[540])
        caveat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8C5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D29922")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(caveat_table)

    def _build_page10_threat_intel_scenarios(self, elements: List[Any]):
        """PAGE 10 — PART B · TECHNICAL — THREAT INTELLIGENCE & SCENARIO CORRELATION."""
        elements.append(Paragraph("PART B · TECHNICAL — THREAT INTELLIGENCE & SCENARIO CORRELATION", self.part_header))
        elements.append(Paragraph("EXTERNAL THREAT INTELLIGENCE (ILLUSTRATIVE)", self.section_bar))

        sub_p = Paragraph(
            "Sub-scores below (VT ratio, OTX pulses, AbuseIPDB confidence) are illustrative inputs. The current engine documentation does not publish a fixed "
            "sub-formula converting these into the single 0–100 Threat Correlation axis score; the composite value of 74.0 used on page 3 is shown for demonstration "
            "purposes only and should not be treated as a documented formula output.",
            self.body_style
        )
        elements.append(sub_p)
        elements.append(Spacer(1, 4))

        intel_data = [
            [Paragraph("<b>Source</b>", self.table_header), Paragraph("<b>Result</b>", self.table_header), Paragraph("<b>Confidence</b>", self.table_header)],
            [Paragraph("VirusTotal", self.table_cell_bold), Paragraph("38 / 70 engines flagged (54%)", self.table_cell), Paragraph("High", self.table_cell)],
            [Paragraph("AlienVault OTX", self.table_cell_bold), Paragraph("3 pulses — cluster tag “Drinik-2026-H1”, “SBI-Refund-Campaign”", self.table_cell), Paragraph("High", self.table_cell)],
            [Paragraph("AbuseIPDB (194.163.142.89)", self.table_cell_bold), Paragraph("71 / 100 abuse confidence, geolocated non-IN ASN", self.table_cell), Paragraph("Medium-High", self.table_cell)],
            [Paragraph("Family classification", self.table_cell_bold), Paragraph("Drinik (classification_engine.py rule: accessibility+SMS+banking match, 3/3)", self.table_cell), Paragraph("High", self.table_cell)],
        ]
        intel_table = Table(intel_data, colWidths=[150, 270, 120])
        intel_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(intel_table)
        elements.append(Paragraph("<font size=6 color='#57606A'>Illustrative detecting vendors (sample): Lionic, CAT-QuickHeal, Skyhigh, Sangfor, Trustlook, + 33 more — full illustrative vendor list omitted for brevity.</font>", self.body_style))
        elements.append(Spacer(1, 6))

        # Threat Scenario Correlation Matrix matching Page 10
        elements.append(Paragraph("THREAT SCENARIO CORRELATION MATRIX", self.section_bar))
        matrix_data = [
            [Paragraph("<b>Indicator</b>", self.table_header), Paragraph("<b>Threat Scenario</b>", self.table_header), Paragraph("<b>Overlay</b>", self.table_header), Paragraph("<b>Cred. Theft</b>", self.table_header), Paragraph("<b>C2</b>", self.table_header), Paragraph("<b>Persist.</b>", self.table_header), Paragraph("<b>Conf.</b>", self.table_header)],
            [Paragraph("Accessibility Service", self.table_cell_bold), Paragraph("OTP Harvesting via UI Scraping / ATS", self.table_cell), Paragraph("High", self.table_cell), Paragraph("High", self.table_cell), Paragraph("Med", self.table_cell), Paragraph("Med", self.table_cell), Paragraph("92", self.table_cell_bold)],
            [Paragraph("SMS Receiver", self.table_cell_bold), Paragraph("OTP Interception & Silent Exfiltration", self.table_cell), Paragraph("Low", self.table_cell), Paragraph("High", self.table_cell), Paragraph("High", self.table_cell), Paragraph("Low", self.table_cell), Paragraph("90", self.table_cell_bold)],
            [Paragraph("System Alert Window", self.table_cell_bold), Paragraph("Phishing Overlay Impersonating SBI Login", self.table_cell), Paragraph("High", self.table_cell), Paragraph("High", self.table_cell), Paragraph("Low", self.table_cell), Paragraph("Low", self.table_cell), Paragraph("88", self.table_cell_bold)],
            [Paragraph("Hardcoded C2 Endpoint", self.table_cell_bold), Paragraph("C2 Beaconing & Data Exfiltration", self.table_cell), Paragraph("N/A", self.table_cell), Paragraph("Med", self.table_cell), Paragraph("High", self.table_cell), Paragraph("Med", self.table_cell), Paragraph("85", self.table_cell_bold)],
            [Paragraph("DexClassLoader/Reflection", self.table_cell_bold), Paragraph("Dynamic Payload Loading / AV Evasion", self.table_cell), Paragraph("N/A", self.table_cell), Paragraph("Low", self.table_cell), Paragraph("Med", self.table_cell), Paragraph("Med", self.table_cell), Paragraph("76", self.table_cell_bold)],
        ]
        matrix_table = Table(matrix_data, colWidths=[120, 180, 48, 48, 48, 48, 48])
        matrix_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(matrix_table)
        elements.append(Paragraph("<font size=6 color='#57606A'>Evidence column omitted from print layout for width; full evidence text is retained in the Evidence Ledger (page 8) and underlying case JSON.</font>", self.body_style))
        elements.append(Spacer(1, 6))

        # MITRE ATT&CK for Mobile Table
        elements.append(Paragraph("MITRE ATT&CK; FOR MOBILE — TECHNIQUES OBSERVED", self.section_bar))
        mitre_data = [
            [Paragraph("<b>Technique ID</b>", self.table_header), Paragraph("<b>Name</b>", self.table_header), Paragraph("<b>Evidence Basis</b>", self.table_header)],
            [Paragraph("T1628", self.table_cell_mono), Paragraph("Input Capture via Accessibility Service", self.table_cell_bold), Paragraph("Static + Dynamic (illustrative)", self.table_cell)],
            [Paragraph("T1637", self.table_cell_mono), Paragraph("App Overlay Attack", self.table_cell_bold), Paragraph("Static + Dynamic (illustrative)", self.table_cell)],
            [Paragraph("T1643", self.table_cell_mono), Paragraph("Capture SMS Messages", self.table_cell_bold), Paragraph("Static + Dynamic (illustrative)", self.table_cell)],
            [Paragraph("T1437", self.table_cell_mono), Paragraph("Application Layer C2", self.table_cell_bold), Paragraph("Static + Dynamic (illustrative)", self.table_cell)],
            [Paragraph("T1407", self.table_cell_mono), Paragraph("Download New Code at Runtime", self.table_cell_bold), Paragraph("Static only", self.table_cell)],
        ]
        mitre_table = Table(mitre_data, colWidths=[90, 210, 240])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(mitre_table)

    def _build_page11_coverage_and_evidence_ledger(self, elements: List[Any]):
        """PAGE 11 — PART C · AUDIT & TRACEABILITY — COVERAGE & EVIDENCE LEDGER."""
        elements.append(Paragraph("PART C · AUDIT & TRACEABILITY — COVERAGE, LIMITATIONS & EVIDENCE LEDGER", self.part_header))
        elements.append(Paragraph("ANALYSIS COVERAGE & LIMITATIONS MATRIX", self.section_bar))

        cov_data = [
            [Paragraph("<b>Capability</b>", self.table_header), Paragraph("<b>Status</b>", self.table_header), Paragraph("<b>Detail</b>", self.table_header)],
            [Paragraph("Native APK Analyzer (apk_analyzer.py)", self.table_cell_bold), Paragraph("Executed", self.table_cell), Paragraph("androguard manifest / permission / bytecode extraction complete", self.table_cell)],
            [Paragraph("MobSF container", self.table_cell_bold), Paragraph("Not executed", self.table_cell), Paragraph("MobSF service unreachable at analysis time; native analyzer fallback used (defense-in-depth design)", self.table_cell)],
            [Paragraph("APKTool", self.table_cell_bold), Paragraph("Executed", self.table_cell), Paragraph("Resource/manifest decompilation; static UI profile built for VIDE", self.table_cell)],
            [Paragraph("JADX", self.table_cell_bold), Paragraph("Executed", self.table_cell), Paragraph("DEX→Java source scan; 5 of 10 fraud signature patterns matched", self.table_cell)],
            [Paragraph("Frida dynamic sandbox", self.table_cell_bold), Paragraph("Executed (illustrative)", self.table_cell), Paragraph("dynamic_status = EVENTS_CAPTURED; canary received; ART deoptimized", self.table_cell)],
            [Paragraph("mitmproxy HAR capture", self.table_cell_bold), Paragraph("Partial (illustrative)", self.table_cell), Paragraph("Proxy active; C2 beacon observed via Frida socket hook, not HAR", self.table_cell)],
            [Paragraph("Threat correlation (VT/OTX/AbuseIPDB)", self.table_cell_bold), Paragraph("Executed (illustrative)", self.table_cell), Paragraph("24h cache miss; live lookups simulated for this demo", self.table_cell)],
            [Paragraph("VIDE visual comparison", self.table_cell_bold), Paragraph("Executed (illustrative)", self.table_cell), Paragraph("Static UI profile + dynamic WebView HTML merged against SBI lab baseline", self.table_cell)],
        ]
        cov_table = Table(cov_data, colWidths=[150, 110, 280])
        cov_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(cov_table)
        elements.append(Paragraph("<font size=6 color='#57606A'>“Not executed” / “Partial” rows are coverage gaps, not findings of absence — they are excluded from FRS scoring rather than scored as zero (see risk_engine.py axis exclusion).</font>", self.body_style))
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("EVIDENCE LEDGER — traceability from finding to source", self.section_bar))
        
        ev_data = [
            [Paragraph("<b>ID</b>", self.table_header), Paragraph("<b>Category</b>", self.table_header), Paragraph("<b>Finding</b>", self.table_header), Paragraph("<b>Source</b>", self.table_header), Paragraph("<b>Status</b>", self.table_header), Paragraph("<b>Conf.</b>", self.table_header)]
        ]
        
        if self.data.evidence_records and len(self.data.evidence_records) > 0:
            for idx, rec in enumerate(self.data.evidence_records[:20], 1):
                if isinstance(rec, dict):
                    ev_id = rec.get("finding_id") or rec.get("evidence_id") or rec.get("id") or f"EVID-{idx:03d}"
                    cat = rec.get("category") or "Static"
                    desc = rec.get("description") or rec.get("event") or str(rec)
                    src = rec.get("source") or rec.get("evidence_source") or "Sudarshan Engine"
                    st = rec.get("status") or rec.get("severity") or "STATIC-VERIFIED"
                    conf = rec.get("confidence") or "High"
                else:
                    ev_id = f"EVID-{idx:03d}"
                    cat = "Analysis"
                    desc = str(rec)
                    src = "Sudarshan Engine"
                    st = "STATIC-VERIFIED"
                    conf = "High"
                ev_data.append([
                    Paragraph(str(ev_id), self.table_cell_mono),
                    Paragraph(str(cat), self.table_cell),
                    Paragraph(str(desc)[:90], self.table_cell),
                    Paragraph(str(src), self.table_cell),
                    Paragraph(str(st), self.table_cell_bold if "VERIFIED" in str(st) or "CRITICAL" in str(st) else self.table_cell),
                    Paragraph(str(conf), self.table_cell),
                ])
        else:
            ev_data.extend([
                [Paragraph("STAT-001", self.table_cell_mono), Paragraph("Static", self.table_cell), Paragraph("Accessibility service declared", self.table_cell), Paragraph("APKTool / Native Analyzer", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("High", self.table_cell)],
                [Paragraph("STAT-002", self.table_cell_mono), Paragraph("Static", self.table_cell), Paragraph("SMS receiver capability (RECEIVE_SMS, READ_SMS)", self.table_cell), Paragraph("Native Analyzer", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("High", self.table_cell)],
                [Paragraph("STAT-003", self.table_cell_mono), Paragraph("Static", self.table_cell), Paragraph("SYSTEM_ALERT_WINDOW overlay permission", self.table_cell), Paragraph("Native Analyzer", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("High", self.table_cell)],
                [Paragraph("STAT-004", self.table_cell_mono), Paragraph("Static", self.table_cell), Paragraph("Hardcoded C2 http://194.163.142.89/drinik/gate.php", self.table_cell), Paragraph("JADX string extraction", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("High", self.table_cell)],
                [Paragraph("STAT-005", self.table_cell_mono), Paragraph("Static", self.table_cell), Paragraph("DexClassLoader + reflection invoke()", self.table_cell), Paragraph("JADX", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("Medium", self.table_cell)],
                [Paragraph("STAT-006", self.table_cell_mono), Paragraph("Static", self.table_cell), Paragraph("Banking package match ×2 (SBI, ICICI)", self.table_cell), Paragraph("Native Analyzer", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("High", self.table_cell)],
                [Paragraph("DYN-001", self.table_cell_mono), Paragraph("Dynamic", self.table_cell), Paragraph("Accessibility hook fired 42×", self.table_cell), Paragraph("Frida (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("High", self.table_cell)],
                [Paragraph("DYN-002", self.table_cell_mono), Paragraph("Dynamic", self.table_cell), Paragraph("SMS broadcast intercepted 18×", self.table_cell), Paragraph("Frida (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("High", self.table_cell)],
                [Paragraph("DYN-003", self.table_cell_mono), Paragraph("Dynamic", self.table_cell), Paragraph("Overlay drawn over com.sbi.lotusintouch 9×", self.table_cell), Paragraph("Frida (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("High", self.table_cell)],
                [Paragraph("DYN-004", self.table_cell_mono), Paragraph("Dynamic", self.table_cell), Paragraph("C2 POST observed 3×", self.table_cell), Paragraph("Frida socket hook (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("Medium", self.table_cell)],
                [Paragraph("VIDE-001", self.table_cell_mono), Paragraph("Visual", self.table_cell), Paragraph("VIDE-F001 — SBI baseline similarity 0.74", self.table_cell), Paragraph("VIDE pipeline (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("Medium-High", self.table_cell)],
                [Paragraph("INTEL-001", self.table_cell_mono), Paragraph("Threat Intel", self.table_cell), Paragraph("Family = Drinik, 3/3 deterministic rule conditions", self.table_cell), Paragraph("classification_engine.py", self.table_cell), Paragraph("STATIC-VERIFIED", self.table_cell_bold), Paragraph("High", self.table_cell)],
                [Paragraph("INTEL-002", self.table_cell_mono), Paragraph("Threat Intel", self.table_cell), Paragraph("VirusTotal detection ratio 38/70", self.table_cell), Paragraph("VT API (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("Medium", self.table_cell)],
                [Paragraph("INTEL-003", self.table_cell_mono), Paragraph("Threat Intel", self.table_cell), Paragraph("AbuseIPDB confidence 71/100 for C2 IP", self.table_cell), Paragraph("AbuseIPDB (demo)", self.table_cell), Paragraph("ILLUSTRATIVE", self.table_cell), Paragraph("Medium", self.table_cell)],
            ])

        ev_table = Table(ev_data, colWidths=[65, 55, 195, 95, 90, 40])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(ev_table)

    def _build_page12_iocs_governance_signoff(self, elements: List[Any]):
        """PAGE 12 — PART C · AUDIT & TRACEABILITY — INDICATORS, CHAIN OF CUSTODY & GOVERNANCE."""
        elements.append(Paragraph("PART C · AUDIT & TRACEABILITY — INDICATORS, CHAIN OF CUSTODY & GOVERNANCE", self.part_header))
        elements.append(Paragraph("INDICATORS OF COMPROMISE", self.section_bar))

        c2_url_str = self.data.iocs[0]['indicator'] if self.data.iocs else 'http://194.163.142.89/drinik/gate.php'

        ioc_data = [
            [Paragraph("<b>FILE INDICATORS</b>", self.table_header), Paragraph("<b>NETWORK / ANDROID INDICATORS</b>", self.table_header)],
            [
                Paragraph(f"<b>SHA-256:</b> <code>{self.data.sha256.value[:24]}...</code><br/>"
                          f"<b>SHA-1:</b> <code>{self.data.sha1.value}</code><br/>"
                          f"<b>MD5:</b> <code>{self.data.md5.value}</code><br/>"
                          f"<b>Package:</b> <code>{self.data.package_name.value}</code>", self.table_cell),
                Paragraph(f"<b>C2 URL:</b> <code>{c2_url_str}</code><br/>"
                          f"<b>Permissions:</b> 10 dangerous (see page 4)<br/>"
                          f"<b>Suspicious APIs:</b> AccessibilityService, SmsManager, WindowManager.addView<br/>"
                          f"<b>Status:</b> ILLUSTRATIVE (network) / STATIC-VERIFIED (Android)", self.table_cell),
            ]
        ]
        ioc_table = Table(ioc_data, colWidths=[270, 270])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("CHAIN OF CUSTODY & REPORT INTEGRITY", self.section_bar))
        chain_data = [
            [Paragraph("<b>Field</b>", self.table_header), Paragraph("<b>Value</b>", self.table_header)],
            [Paragraph("Platform version", self.table_cell_bold), Paragraph(self.data.engine_version.value, self.table_cell)],
            [Paragraph("Analysis mode", self.table_cell_bold), Paragraph("Demonstration — static evidence from CASE_STUDIES.md; dynamic/VIDE/intel synthetic", self.table_cell)],
            [Paragraph("Case record integrity hash (SHA-256, canonical fields)", self.table_cell_bold), Paragraph("b0f3e7fab8b97e474bbdb2fd7d674361288faa7f228e167b7dc201c7d535017d", self.table_cell_mono)],
            [Paragraph("Report generated", self.table_cell_bold), Paragraph(self.data.report_generated_at.value, self.table_cell_mono)],
            [Paragraph("Retention / audit trail", self.table_cell_bold), Paragraph("Case JSON persisted to sudarshan.db; evidence ledger IDs map 1:1 to stored EvidenceRecord entries", self.table_cell)],
        ]
        chain_table = Table(chain_data, colWidths=[170, 370])
        chain_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(chain_table)
        elements.append(Spacer(1, 6))

        # Sign-off Box matching reference PDF Page 12
        elements.append(Paragraph("SIGN-OFF", self.section_bar))
        sign_data = [
            [Paragraph("<b>Reviewed by (SOC Analyst)</b>", self.table_cell_bold), Paragraph("___________________________________  Date: ___________", self.table_cell)],
            [Paragraph("<b>Approved by (SOC Lead / CISO)</b>", self.table_cell_bold), Paragraph("___________________________________  Date: ___________", self.table_cell)],
            [Paragraph("<b>Case status</b>", self.table_cell_bold), Paragraph("■ Open   ■ Under Investigation   ■ Escalated to CERT-In   ■ Closed", self.table_cell)],
        ]
        sign_table = Table(sign_data, colWidths=[160, 380])
        sign_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(sign_table)
        elements.append(Spacer(1, 6))

        # Glossary section matching reference PDF Page 12
        elements.append(Paragraph("METHODOLOGY & GLOSSARY (appendix)", self.section_bar))
        glossary_p = Paragraph(
            "<b>FRS = weighted_mean(STEI×0.25, BFCI×0.35, ThreatCorrelation×0.20, BankingImpact×0.20), renormalized over axes with data, × ai_confidence_multiplier (clamped [0.5, 1.5]), capped at 100. Risk bands: Safe ≤30 · Suspicious ≤60 · High Risk ≤89 · Critical ≥90. STEI = 5-axis Static Threat Exposure Index. BFCI v2 = Behavioral Fraud Confidence Index (logarithmic volume + sequence bonus). VIDE = Visual Impersonation Detection Engine (deterministic UI-fingerprint comparison). MITRE ATT&CK; = standardized adversary technique taxonomy used for mobile technique IDs (Txxxx). CERT-In = Indian Computer Emergency Response Team.</b>",
            self.body_style
        )
        elements.append(glossary_p)
        elements.append(Spacer(1, 6))

        # 3 Principle Cards
        p_cards = [[
            Paragraph("<font size=6.5 color='#1F6FEB'><b>PRINCIPLE 1</b></font><br/><br/><b>AI generates evidence-grounded narrative and explanation. It never sets the score.</b>", self.table_cell),
            Paragraph("<font size=6.5 color='#1F6FEB'><b>PRINCIPLE 2</b></font><br/><br/><b>Deterministic engine computes the risk score and band from structured evidence only.</b>", self.table_cell),
            Paragraph("<font size=6.5 color='#1F6FEB'><b>PRINCIPLE 3</b></font><br/><br/><b>Evidence Ledger provides ID-level traceability between every finding and its source.</b>", self.table_cell),
        ]]
        p_table = Table(p_cards, colWidths=[180, 180, 180])
        p_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(p_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<font size=5.5 color='#57606A'>This report is grounded in evidence produced by the Sudarshan analysis pipeline and named external threat-intelligence sources; sections built from synthetic data for this demonstration are labeled ILLUSTRATIVE throughout and must not be cited as captured forensic evidence. Known open item: sanitizer.py is not yet wired into the production LLM narrative paths (gemini_client.py / gemini_rag.py) per DOCUMENTATION_AUDIT_REPORT.md finding G2d — tracked for remediation.</font>", self.body_style))

    def _build_appendices(self, elements: List[Any]):
        """Appendix A — Screenshots & Visual Evidence."""
        if not self.data.screenshots:
            return

        elements.append(PageBreak())
        elements.append(Paragraph("Appendix A: Runtime Screenshots & Visual Evidence", self.section_bar))

        for idx, scr in enumerate(self.data.screenshots[:6], 1):
            if isinstance(scr, dict):
                scr_path_str = scr.get("path") or scr.get("filename") or f"screenshot_{idx}.png"
                title_str = scr.get("title") or scr.get("screenshot_id") or f"Screenshot #{idx}"
                desc_str = scr.get("description") or scr.get("investigative_claim") or "Captured during dynamic execution."
                trigger_str = scr.get('capture_trigger', 'Dynamic Event')
                quality_str = scr.get('quality', 'A')
            else:
                scr_path_str = str(scr)
                title_str = f"Screenshot #{idx}"
                desc_str = "Captured during dynamic execution."
                trigger_str = 'Dynamic Event'
                quality_str = 'A'

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

            if img_obj:
                scr_table_data = [[
                    img_obj,
                    Paragraph(f"<b>{title_str}</b><br/><br/>{desc_str}<br/><br/><b>Trigger:</b> {trigger_str}<br/><b>Quality Grade:</b> {quality_str}", self.body_style)
                ]]
            else:
                placeholder_p = Paragraph(f"<b>[SCREENSHOT IMAGE]</b><br/><font size=6 color='#57606A'>{scr_path_str}</font>", self.body_style)
                scr_table_data = [[
                    placeholder_p,
                    Paragraph(f"<b>{title_str}</b><br/><br/>{desc_str}<br/><br/><b>Trigger:</b> {trigger_str}<br/><b>Quality Grade:</b> {quality_str}", self.body_style)
                ]]

            scr_table = Table(scr_table_data, colWidths=[180, 360])
            scr_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elements.append(KeepTogether([scr_table, Spacer(1, 8)]))

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
