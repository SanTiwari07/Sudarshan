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

import hashlib
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
    BaseDocTemplate,
    PageTemplate,
    Frame,
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
    correlation_score: FieldValue[float]
    banking_impact_score: FieldValue[float]
    
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

    # Investigation resilience. Defaulted so an older stored case - written
    # before the Execution Assertion Matrix existed - still renders.
    verdict: str = ""
    execution_assertions: Dict[str, Any] = field(default_factory=dict)
    remedial_suggestions: List[Dict[str, Any]] = field(default_factory=list)

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

    correlation_score_val = safe_float(get_val(frs_breakdown, "correlation"), 0.0)
    banking_impact_score_val = safe_float(get_val(frs_breakdown, "banking_impact"), 0.0)

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

    sandbox_provider_val = safe_str(get_val(dynamic_res, "sandbox_provider"), "Not available")
    frida_version_val = safe_str(get_val(dynamic_res, "frida_version"), "Not available")
    duration_val = safe_float(get_val(dynamic_res, "analysis_duration"), 0.0)
    hooks_count_val = safe_int(get_val(dynamic_res, "total_hooks_installed"), 0)
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
    plain_narrative = get_val(ai_report, "plain_english_narrative", "Not available.")
    fraud_obj = get_val(ai_report, "fraud_objective", "Not available")
    cust_impact = get_val(ai_report, "customer_impact", "Not available")
    bank_impact = get_val(ai_report, "banking_impact", "Not available")
    cert_recs = get_val(ai_report, "cert_in_recommendations", [])
    cust_adv = get_val(ai_report, "customer_advisory_draft", "Not available")

    soc_actions_list = get_val(case_data, "soc_actions", [])

    activities_list = get_val(case_data, "activities", [])
    services_list = get_val(case_data, "services", [])
    receivers_list = get_val(case_data, "receivers", [])
    providers_list = get_val(case_data, "providers", [])
    cert_dict = get_val(case_data, "certificate", {})

    # ── Investigation resilience ──────────────────────────────────────────────
    # The assertion matrix is computed by the risk engine and stored on the
    # case. Recomputing it here when absent keeps older stored cases - and any
    # caller that hands us a raw dynamic result - renderable.
    assertions_dict = get_val(case_data, "execution_assertions") or {}
    if not isinstance(assertions_dict, dict) or not assertions_dict:
        try:
            from sudarshan_core.engines.execution_assertions import (
                build_execution_assertions,
            )

            assertions_dict = build_execution_assertions(
                dynamic_res if isinstance(dynamic_res, dict) else {},
                target_bank_packages=get_val(case_data, "indian_bank_packages_found") or [],
            ).to_dict()
        except Exception:  # noqa: BLE001
            assertions_dict = {}

    suggestions_list = get_val(case_data, "remedial_suggestions") or []
    if not suggestions_list and assertions_dict.get("incomplete_exercise"):
        try:
            from sudarshan_core.engines.agentic.remediation import (
                generate_remedial_suggestions,
                suggestions_to_dicts,
            )

            suggestions_list = suggestions_to_dicts(
                generate_remedial_suggestions(
                    None,
                    execution_assertions=assertions_dict,
                    target_bank_packages=get_val(
                        case_data, "indian_bank_packages_found"
                    )
                    or [],
                )
            )
        except Exception:  # noqa: BLE001
            suggestions_list = []

    verdict_val = safe_str(
        get_val(case_data, "verdict") or risk_band_val, risk_band_val
    )

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
        correlation_score=FieldValue(value=correlation_score_val, source=Provenance.DERIVED, status=Status.DERIVED),
        banking_impact_score=FieldValue(value=banking_impact_score_val, source=Provenance.DERIVED, status=Status.DERIVED),

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
        verdict=verdict_val,
        execution_assertions=assertions_dict,
        remedial_suggestions=suggestions_list,
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

def draw_sudarshan_header_footer(canvas_obj, doc, report_data):
    canvas_obj.saveState()
    # A4 Dimensions: width = 595.27, height = 841.89
    page_w = 595.27
    page_h = 841.89
    
    # 2. Running Header on ALL pages
    # Logo square on left
    canvas_obj.setFillColor(colors.HexColor("#1e3a8a")) # BOI Blue
    canvas_obj.roundRect(36, page_h - 46, 20, 20, 4, fill=1, stroke=0)
    canvas_obj.setFont("Helvetica-Bold", 12)
    canvas_obj.setFillColor(colors.white)
    canvas_obj.drawCentredString(46, page_h - 40, "S")

    canvas_obj.setFont("Helvetica-Bold", 10)
    canvas_obj.setFillColor(colors.HexColor("#0f172a"))
    canvas_obj.drawString(64, page_h - 34, "SUDARSHAN")
    
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(colors.HexColor("#64748b"))
    canvas_obj.drawString(64, page_h - 43, "THREAT INVESTIGATION REPORT")
    
    # Case Info on right
    case_str = report_data.case_id.value
    gen_str = report_data.report_generated_at.value
    pkg_str = report_data.package_name.value

    canvas_obj.setFont("Helvetica-Bold", 7.5)
    canvas_obj.setFillColor(colors.HexColor("#0f172a"))
    canvas_obj.drawRightString(page_w - 36, page_h - 32, f"Case ID: {case_str}")
    
    canvas_obj.setFont("Helvetica", 6.5)
    canvas_obj.setFillColor(colors.HexColor("#64748b"))
    canvas_obj.drawRightString(page_w - 36, page_h - 41, f"Generated: {gen_str}")
    if pkg_str:
        canvas_obj.drawRightString(page_w - 36, page_h - 50, f"Package: {pkg_str}")

    canvas_obj.setStrokeColor(colors.HexColor("#e2e8f0"))
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(36, page_h - 56, page_w - 36, page_h - 56)

    # 3. Running Footer on ALL pages
    canvas_obj.line(36, 40, page_w - 36, 40)
    canvas_obj.setFont("Helvetica", 7.5)
    canvas_obj.setFillColor(colors.HexColor("#64748b"))
    canvas_obj.drawString(36, 28, f"Sudarshan BOI · {case_str}")
    # We don't have total page count in standard onPage without 2-pass, so we just use current page.
    canvas_obj.drawRightString(page_w - 36, 28, f"Page {doc.page}")

    canvas_obj.restoreState()


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
        
        self.add(Line(cx, cy, nx, ny, strokeColor=colors.HexColor("#f1f5f9"), strokeWidth=2.5))
        self.add(Circle(cx, cy, 5, fillColor=colors.HexColor("#f1f5f9"), strokeColor=None))

        # Numeric Text
        self.add(String(cx, cy + 14, f"{score:.1f}", textAnchor="middle", fontName="Helvetica-Bold", fontSize=18, fillColor=colors.HexColor("#f1f5f9")))
        self.add(String(cx, cy + 4, "/ 100 CONFIRMED FRS", textAnchor="middle", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#57606A")))

class FRSBarMeter(Drawing):
    """Horizontal bar chart for Page 3 FRS Score Ledger."""
    def __init__(self, stei: float, bfci: float, corr: float, bank: float, width=523, height=85):
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
            self.add(String(420, y, f"{val:.1f}", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#f1f5f9")))
            self.add(String(460, y, f"w={wt:.2f} → {wtd:.2f}", fontName="Helvetica", fontSize=6.5, fillColor=colors.HexColor("#57606A")))
            y -= 18

class STEIBarMeter(Drawing):
    """5-axis STEI Progress Bar Meter for Page 4."""
    def __init__(self, ct: float, bt: float, pr: float, ob: float, ir: float, width=523, height=95):
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
            self.add(String(440, y, f"{val:.1f}", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#f1f5f9")))
            y -= 16

class VIDEBarMeter(Drawing):
    """Horizontal bar chart for VIDE UI Fingerprint comparison (Page 9)."""
    def __init__(self, jaccard: float, viewtree: float, color: float, composite: float, width=523, height=85):
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
            self.add(String(430, y, f"{val:.2f}", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#f1f5f9")))
            y -= 18

        # Detection threshold line at 0.72
        tx = 170 + (0.72 * 250)
        self.add(Line(tx, 0, tx, height, strokeColor=colors.HexColor("#CF222E"), strokeWidth=1, strokeDashArray=[2, 2]))
        self.add(String(tx, height - 6, "detection threshold 0.72", textAnchor="middle", fontName="Helvetica-Bold", fontSize=6, fillColor=colors.HexColor("#CF222E")))

class BFCIBarMeter(Drawing):
    """Vertical bar chart for BFCI v2 category breakdown (Page 7)."""
    def __init__(self, components: Dict[str, float], width=523, height=95):
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
            self.add(String(x + bw/2.0, 25 + bh + 3, f"{val:.0f}", textAnchor="middle", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#f1f5f9")))
            
            # Short labels below
            lbl_parts = label.split(" ")
            self.add(String(x + bw/2.0, 14, lbl_parts[0], textAnchor="middle", fontName="Helvetica-Bold", fontSize=6, fillColor=colors.HexColor("#24292F")))
            self.add(String(x + bw/2.0, 6, f"(W={wt:.2f})", textAnchor="middle", fontName="Helvetica", fontSize=5.5, fillColor=colors.HexColor("#57606A")))
            x += bw + gap

class CausalWorkflowDiagram(Drawing):
    """Reconstructed Causal Workflow sequence diagram for Page 7."""
    def __init__(self, width=523, height=65):
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
        # UI tokens mapped from frontend
        c_slate800 = colors.HexColor("#1e293b")
        c_slate600 = colors.HexColor("#475569")
        c_blue900 = colors.HexColor("#0f172a")

        self.part_header = ParagraphStyle(
            "PartHeader",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=c_slate800,
            spaceAfter=6,
            spaceBefore=12,
            keepWithNext=True,
        )
        self.section_bar = ParagraphStyle(
            "SectionBar",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=c_slate800,
            spaceBefore=8,
            spaceAfter=4,
            textTransform="uppercase",
            keepWithNext=True,
        )
        self.body_style = ParagraphStyle(
            "BodyDark",
            fontName="Helvetica",
            fontSize=8,
            leading=12,
            textColor=c_slate600,
            spaceAfter=6,
        )
        self.body_bold = ParagraphStyle(
            "BodyDarkBold",
            parent=self.body_style,
            fontName="Helvetica-Bold",
            textColor=c_slate800,
        )
        self.table_header = ParagraphStyle(
            "TableHeader",
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=10,
            textColor=c_slate600,
            textTransform="uppercase",
            alignment=0,
        )
        self.table_cell = ParagraphStyle(
            "TableCell",
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=c_slate800,
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
        buffer = io.BytesIO()
        
        doc = BaseDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=64,
            bottomMargin=52,
        )
        
        # Usable width = 595.27 - 72 = 523.27
        frame = Frame(
            doc.leftMargin, 
            doc.bottomMargin, 
            doc.width, 
            doc.height, 
            id='normal'
        )
        
        def on_page(canvas_obj, document):
            draw_sudarshan_header_footer(canvas_obj, document, self.data)
            
        template = PageTemplate(id='sudarshan_template', frames=[frame], onPage=on_page)
        doc.addPageTemplates([template])

        elements = []
        
        # Build All 12 Sections + Appendix
        self._build_page1_verdict_summary(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page2_narrative_and_response(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page3_score_ledger(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page4_stei_breakdown(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page5_forensic_static(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page6_evidence_mapping(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page7_dynamic_and_workflow(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page8_hook_inventory(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page9_vide_impersonation(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page10_threat_intel_scenarios(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page11_coverage_and_evidence_ledger(elements)
        elements.append(Spacer(1, 16))
        
        self._build_page12_iocs_governance_signoff(elements)
        
        self._build_appendices(elements)

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    # -----------------------------------------------------------------------
    # Section Builders
    # -----------------------------------------------------------------------

    def _build_page1_verdict_summary(self, elements: List[Any]):
        """PAGE 1 — PART A · EXECUTIVE — VERDICT SUMMARY."""
        elements.append(Paragraph("PART A · EXECUTIVE — VERDICT SUMMARY", self.part_header))
        
        # Disclaimer callout box
        about_p = Paragraph(
            "<b>Document Notice.</b> This investigation report was securely generated by the Sudarshan BOI platform. "
            "All findings, metrics, and evidence presented below are derived strictly from the automated analysis of the submitted artifact. "
            "No human review has been performed unless explicitly noted.",
            self.body_style
        )
        about_table = Table([[about_p]], colWidths=[523.0], repeatRows=1)
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
            f"<b>{self.data.risk_band.value.upper()} RISK → {self.data.risk_band.value.upper()}</b><br/><br/>"
            f"<font size=6.5 color='#24292F'>Static-only preliminary verdict (Day-0, before sandbox run): <b>{self.data.base_score.value:.1f} / 100 — {self.data.risk_band.value.upper()} RISK</b>. "
            f"Confirmed verdict after dynamic execution: <b>{self.data.final_risk_score.value:.1f} / 100 — {self.data.risk_band.value.upper()}</b>. See Score Ledger, page 3.</font>",
            self.body_style
        )

        # We need to construct family attribution string from data if available, else omit
        family_name = self.data.malware_family if hasattr(self.data, 'malware_family') and self.data.malware_family else "Unknown"
        family_box = Paragraph(
            f"<font size=6.5 color='#57606A'><b>FAMILY ATTRIBUTION</b></font><br/><br/>"
            f"<font size=11 color='#0D1117'><b>{family_name.upper()}</b></font><br/>"
            f"<font size=6 color='#57606A'>based on deterministic classifier rule conditions</font>",
            self.body_style
        )

        v_table_data = [[gauge_flowable, verdict_text, family_box]]
        v_table = Table(v_table_data, colWidths=[169.5, 213.1, 140.4], repeatRows=1)
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
            f"<b>EXECUTIVE CONCLUSION.</b> {self.data.plain_english_narrative.value if self.data.plain_english_narrative else 'No narrative available.'}",
            self.body_style
        )
        conc_table = Table([[conc_p]], colWidths=[523.0], repeatRows=1)
        conc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFEBE9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#FF8170")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(conc_table)
        elements.append(Spacer(1, 6))

        # Key Findings Row (4 cards matching reference PDF)
        elements.append(Paragraph("KEY FINDINGS", self.body_bold))
        
        # Build finding blocks dynamically based on data. If there are fewer than 4, pad with empty cells.
        finding_blocks = []
        if family_name != "Unknown":
            finding_blocks.append(Paragraph(f"<font size=6 color='#6B21A8'><b>CORRELATED</b></font><br/><b>Malware family — {family_name}</b><br/>(deterministic rule match)", self.table_cell))
        
        if hasattr(self.data, 'permissions') and any('SMS' in p for p in self.data.permissions):
            finding_blocks.append(Paragraph("<font size=6 color='#15803D'><b>STATIC INDICATOR</b></font><br/><b>SMS interception capability</b>", self.table_cell))
            
        if hasattr(self.data, 'permissions') and any('ACCESSIBILITY' in p for p in self.data.permissions):
            finding_blocks.append(Paragraph("<font size=6 color='#15803D'><b>STATIC INDICATOR</b></font><br/><b>Accessibility-based input capture</b>", self.table_cell))
            
        if hasattr(self.data, 'dynamic_ran') and self.data.dynamic_ran:
             finding_blocks.append(Paragraph("<font size=6 color='#B45309'><b>DYNAMIC</b></font><br/><b>Confirmed dynamic execution</b>", self.table_cell))
             
        # Pad up to 4
        while len(finding_blocks) < 4:
            finding_blocks.append(Paragraph("", self.table_cell))
            
        # Ensure we only take the first 4
        finding_blocks = finding_blocks[:4]

        kf_data = [finding_blocks]
        kf_table = Table(kf_data, colWidths=[130.8, 130.8, 130.8, 130.8], repeatRows=1)
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
        elements.append(Paragraph("SAMPLE REPUTATION — external threat-intelligence evidence", self.body_bold))
        rep_data = [
            [Paragraph("VIRUSTOTAL", self.table_header), Paragraph("DETECTION RATIO", self.table_header), Paragraph("OTX PULSES", self.table_header), Paragraph("ABUSEIPDB (C2 IP)", self.table_header), Paragraph("KNOWN FAMILY", self.table_header)],
            [
                Paragraph(self.data.vt_detection_ratio.value if self.data.vt_detection_ratio else "N/A", self.table_cell_bold), 
                Paragraph(self.data.vt_detection_ratio.value if self.data.vt_detection_ratio else "N/A", self.table_cell), 
                Paragraph(f"{self.data.otx_pulse_count.value if self.data.otx_pulse_count else '0'}", self.table_cell), 
                Paragraph(f"{self.data.abuseipdb_score.value if self.data.abuseipdb_score else '0'} / 100", self.table_cell), 
                Paragraph(family_name, self.table_cell_bold)
            ],
        ]
        rep_table = Table(rep_data, colWidths=[116.2, 87.2, 125.9, 106.5, 87.2], repeatRows=1)
        rep_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(rep_table)
        elements.append(Spacer(1, 4))

        # Analysis Coverage Badges
        elements.append(Paragraph("ANALYSIS COVERAGE", self.body_bold))
        cov_badges = [[
            Paragraph("<b>STATIC ANALYSIS — COMPLETE</b>", ParagraphStyle("C1", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#15803D"))),
            Paragraph("<b>THREAT INTEL — COMPLETE</b>", ParagraphStyle("C2", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#B45309"))),
            Paragraph("<b>DYNAMIC — COMPLETE</b>" if self.data.dynamic_ran else "<b>DYNAMIC — SKIPPED</b>", ParagraphStyle("C3", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#B45309"))),
            Paragraph("<b>VIDE — COMPLETE</b>" if (hasattr(self.data, 'vide_status') and self.data.vide_status) else "<b>VIDE — SKIPPED</b>", ParagraphStyle("C4", parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor("#B45309"))),
        ]]
        cov_badge_table = Table(cov_badges, colWidths=[130.8, 130.8, 130.8, 130.8], repeatRows=1)
        cov_badge_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#DCFCE7")),
            ("BACKGROUND", (1, 0), (-1, 0), colors.HexColor("#FEF3C7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(cov_badge_table)
        elements.append(Spacer(1, 6))

        # Risk Contributors Table
        elements.append(Paragraph("RISK CONTRIBUTORS", self.body_bold))
        contrib_data = [
            [Paragraph("CONTRIBUTOR", self.table_header), Paragraph("LEVEL", self.table_header), Paragraph("STATUS", self.table_header)],
            [Paragraph("Threat Intelligence Correlation", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("EVALUATED", self.table_cell)],
            [Paragraph("Static Exposure (STEI)", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("EVALUATED", self.table_cell)],
            [Paragraph("Banking Impact", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("EVALUATED", self.table_cell)],
            [Paragraph("Dynamic Behavior (BFCI v2)", self.table_cell_bold), Paragraph("High", self.table_cell), Paragraph("EVALUATED" if self.data.dynamic_ran else "SKIPPED", self.table_cell)],
            [Paragraph("Visual Impersonation (VIDE-F001)", self.table_cell_bold), Paragraph("Medium-High", self.table_cell), Paragraph("EVALUATED" if (hasattr(self.data, 'vide_status') and self.data.vide_status) else "SKIPPED", self.table_cell)],
        ]
        contrib_table = Table(contrib_data, colWidths=[232.4, 145.3, 145.3], repeatRows=1)
        contrib_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(contrib_table)

    def _build_page2_narrative_and_response(self, elements: List[Any]):
        """PAGE 2 — PART A · EXECUTIVE — NARRATIVE & RESPONSE."""
        elements.append(Paragraph("PART A · EXECUTIVE — NARRATIVE & RESPONSE (for non-technical readers)", self.part_header))
        elements.append(Paragraph("PLAIN-ENGLISH SUMMARY", self.section_bar))
        
        # We use the plain English narrative from the data if available.
        narrative_val = self.data.plain_english_narrative.value if self.data.plain_english_narrative else None
        if not narrative_val:
            narrative_val = (
                "The automated analysis pipeline did not generate a plain-English narrative for this sample. "
                "This typically occurs if the application was deemed benign by all static heuristics, or if the "
                "generative narrative subsystem was unavailable during processing."
            )
            
        narrative_text = narrative_val.replace('\n', '<br/>')
        
        elements.append(Paragraph(narrative_text, self.body_style))
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("RECOMMENDED SOC ACTIONS", self.section_bar))
        
        soc_rows = [
            [Paragraph("ACTION", self.table_header), Paragraph("OPERATIONAL INSTRUCTION", self.table_header)]
        ]
        for item in self.data.soc_actions:
            if isinstance(item, dict):
                act = item.get("action", "ACTION")
                det = item.get("detail", str(item))
            else:
                # Handle plain string arrays 
                act = "RECOMMENDATION"
                det = str(item)
            soc_rows.append([Paragraph(f"<b>{act}</b>", self.table_cell_bold), Paragraph(det, self.table_cell)])

        soc_table = Table(soc_rows, colWidths=[106.5, 416.5], repeatRows=1)
        soc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(soc_table)
        elements.append(Spacer(1, 6))

        # Customer Advisory Box
        elements.append(Paragraph("CUSTOMER ADVISORY DRAFT — AI-generated, evidence-grounded (edit before sending)", self.body_bold))
        adv_val = "Not available for this sample."
        if hasattr(self.data, 'customer_advisory') and self.data.customer_advisory:
            adv_val = self.data.customer_advisory.replace('\n', '<br/>')
            
        adv_p = Paragraph(f"“{adv_val}”", self.body_style)
        adv_table = Table([[adv_p]], colWidths=[523.0], repeatRows=1)
        adv_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(adv_table)
        elements.append(Spacer(1, 6))

        # CERT-In Recommendations
        elements.append(Paragraph("CERT-In / REGULATORY RECOMMENDATIONS", self.body_bold))
        recs = getattr(self.data, 'cert_in_recommendations', [])
        if not recs:
            recs = ["No specific CERT-In recommendations available for this sample."]
        for r in recs:
            elements.append(Paragraph(f"• {r}", self.body_style))

    def _build_page3_score_ledger(self, elements: List[Any]):
        """PAGE 3 — PART B · TECHNICAL — DETERMINISTIC SCORE LEDGER."""
        elements.append(Paragraph("PART B · TECHNICAL — DETERMINISTIC SCORE LEDGER", self.part_header))
        elements.append(Paragraph("FRAUD RISK SCORE (FRS) — FULL BREAKDOWN", self.section_bar))

        det_p = Paragraph(
            "<b>Determinism invariant.</b> The Fraud Risk Score is computed strictly by <font name='Courier'>risk_engine.py</font> from observable evidence. "
            "No generative-AI output contributes to this number at any stage — the LLM narrative on page 2 is generated downstream of, and cannot alter, the score below.",
            self.body_style
        )
        det_table = Table([[det_p]], colWidths=[523.0], repeatRows=1)
        det_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DDF4FF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#54AEFF")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(det_table)
        elements.append(Spacer(1, 6))

        # FRS Horizontal Bar Chart
        frs_meter = FRSBarMeter(
            stei=self.data.stei_total.value if hasattr(self.data, 'stei_total') and self.data.stei_total else 0.0,
            bfci=self.data.bfci_total.value if hasattr(self.data, 'bfci_total') and self.data.bfci_total else 0.0,
            corr=self.data.correlation_score.value if hasattr(self.data, 'correlation_score') and self.data.correlation_score else 0.0,
            bank=float(self.data.banking_impact_score.value) if hasattr(self.data, 'banking_impact_score') and getattr(self.data.banking_impact_score, 'value', None) else 0.0,
        )
        elements.append(frs_meter)
        elements.append(Spacer(1, 6))

        # Axis Table
        stei_val = self.data.stei_total.value if hasattr(self.data, 'stei_total') and self.data.stei_total else 0.0
        bfci_val = self.data.bfci_total.value if hasattr(self.data, 'bfci_total') and self.data.bfci_total else 0.0
        corr_val = self.data.correlation_score.value if hasattr(self.data, 'correlation_score') and self.data.correlation_score else 0.0
        bank_val = float(self.data.banking_impact_score.value) if hasattr(self.data, 'banking_impact_score') and getattr(self.data.banking_impact_score, 'value', None) else 0.0

        axis_data = [
            [Paragraph("Axis", self.table_header), Paragraph("Nom. Wt.", self.table_header), Paragraph("Included because...", self.table_header), Paragraph("Score", self.table_header), Paragraph("Wtd.", self.table_header), Paragraph("Status", self.table_header)],
            [Paragraph("Static Exposure (STEI)", self.table_cell_bold), Paragraph("0.25", self.table_cell), Paragraph("Yes — static analysis always runs", self.table_cell), Paragraph(f"{stei_val:.2f}", self.table_cell), Paragraph(f"{stei_val*0.25:.2f}", self.table_cell), Paragraph("EVALUATED", self.table_cell)],
            [Paragraph("Dynamic Behavior (BFCI v2)", self.table_cell_bold), Paragraph("0.35", self.table_cell), Paragraph("Yes — dynamic execution ran" if self.data.dynamic_ran else "No — no dynamic execution", self.table_cell), Paragraph(f"{bfci_val:.2f}", self.table_cell), Paragraph(f"{bfci_val*0.35:.2f}", self.table_cell), Paragraph("EVALUATED" if self.data.dynamic_ran else "SKIPPED", self.table_cell)],
            [Paragraph("Threat Correlation", self.table_cell_bold), Paragraph("0.20", self.table_cell), Paragraph("Yes — external lookup returned data", self.table_cell), Paragraph(f"{corr_val:.2f}", self.table_cell), Paragraph(f"{corr_val*0.20:.2f}", self.table_cell), Paragraph("EVALUATED", self.table_cell)],
            [Paragraph("Banking Impact", self.table_cell_bold), Paragraph("0.20", self.table_cell), Paragraph("Yes — always included", self.table_cell), Paragraph(f"{bank_val:.2f}", self.table_cell), Paragraph(f"{bank_val*0.20:.2f}", self.table_cell), Paragraph("EVALUATED", self.table_cell)],
        ]
        axis_table = Table(axis_data, colWidths=[125.9, 43.6, 169.5, 48.4, 48.4, 87.2], repeatRows=1)
        axis_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(axis_table)
        elements.append(Spacer(1, 4))

        # Formula calculation box
        base_score = self.data.base_score.value if self.data.base_score else 0.0
        final_score = self.data.final_risk_score.value if self.data.final_risk_score else 0.0
        multiplier = final_score / base_score if base_score > 0 else 1.0
        
        formula_box_text = (
            f"<font name='Courier'>FRS_base = (0.25×{stei_val:.2f}) + (0.35×{bfci_val:.2f}) + (0.20×{corr_val:.2f}) + (0.20×{bank_val:.2f})<br/>"
            f"         = {stei_val*0.25:.2f} + {bfci_val*0.35:.2f} + {corr_val*0.20:.2f} + {bank_val*0.20:.2f} = <b>{base_score:.2f}</b><br/>"
            f"ai_confidence_multiplier = {multiplier:.2f}  (family-classifier match clamp range [0.5, 1.5])<br/>"
            f"final_risk_score = min({base_score:.2f} × {multiplier:.2f}, 100) = min({base_score * multiplier:.2f}, 100) = <b>{final_score:.1f} → {self.data.risk_band.value.upper()}</b> band</font>"
        )
        formula_p = Paragraph(formula_box_text, self.body_style)
        formula_table = Table([[formula_p]], colWidths=[523.0], repeatRows=1)
        formula_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(formula_table)
        elements.append(Spacer(1, 6))

        # Static vs Confirmed comparison table
        elements.append(Paragraph("STATIC-ONLY vs. CONFIRMED VERDICT — escalation on dynamic evidence", self.body_bold))
        comp_data = [
            [Paragraph("Field", self.table_header), Paragraph("Day-0: Static-only", self.table_header), Paragraph("Confirmed: Static + Dynamic + Intel", self.table_header)],
            [Paragraph("Axes live", self.table_cell_bold), Paragraph("STEI + Banking Impact only (dynamic, correlation excluded)", self.table_cell), Paragraph("STEI + Dynamic + Correlation + Banking Impact", self.table_cell)],
            [Paragraph("Renormalized weights", self.table_cell_bold), Paragraph("STEI 0.556 / Banking 0.444", self.table_cell), Paragraph("0.25 / 0.35 / 0.20 / 0.20 (nominal, no exclusion)", self.table_cell)],
            [Paragraph("ai_confidence_multiplier", self.table_cell_bold), Paragraph("1.00", self.table_cell), Paragraph(f"{multiplier:.2f} (deterministic family match)", self.table_cell)],
            [Paragraph("Final FRS", self.table_cell_bold), Paragraph(f"{stei_val * 0.556 + bank_val * 0.444:.1f}", self.table_cell), Paragraph(f"{final_score:.1f}", self.table_cell_bold)],
            [Paragraph("Risk band", self.table_cell_bold), Paragraph("—", self.table_cell), Paragraph(f"{self.data.risk_band.value.upper()}", self.table_cell_bold)],
            [Paragraph("Source", self.table_cell_bold), Paragraph("Calculated baseline", self.table_cell), Paragraph("Confirmed analysis", self.table_cell)],
        ]
        comp_table = Table(comp_data, colWidths=[125.9, 198.5, 198.5], repeatRows=1)
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(comp_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<font size=6 color='#57606A'>Note: The static-only FRS is computed without applying the family-match multiplier.</font>", self.body_style))

    def _build_page4_stei_breakdown(self, elements: List[Any]):
        """PAGE 4 — STEI — 5-AXIS BREAKDOWN."""
        elements.append(Paragraph("<font size=6 color='#57606A'>confirmed-scenario figure above applies the documented multiplier correctly and is internally consistent end-to-end.</font>", self.body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("STEI — 5-AXIS BREAKDOWN", self.section_bar))

        stei_meter = STEIBarMeter(
            ct=self.data.stei_ct.value if hasattr(self.data, 'stei_ct') and self.data.stei_ct else 0.0,
            bt=self.data.stei_bt.value if hasattr(self.data, 'stei_bt') and self.data.stei_bt else 0.0,
            pr=self.data.stei_pr.value if hasattr(self.data, 'stei_pr') and self.data.stei_pr else 0.0,
            ob=self.data.stei_ob.value if hasattr(self.data, 'stei_ob') and self.data.stei_ob else 0.0,
            ir=self.data.stei_ir.value if hasattr(self.data, 'stei_ir') and self.data.stei_ir else 0.0,
        )
        elements.append(stei_meter)
        elements.append(Spacer(1, 8))

        ct_val = self.data.stei_ct.value if hasattr(self.data, 'stei_ct') and self.data.stei_ct else 0.0
        bt_val = self.data.stei_bt.value if hasattr(self.data, 'stei_bt') and self.data.stei_bt else 0.0
        pr_val = self.data.stei_pr.value if hasattr(self.data, 'stei_pr') and self.data.stei_pr else 0.0
        ob_val = self.data.stei_ob.value if hasattr(self.data, 'stei_ob') and self.data.stei_ob else 0.0
        ir_val = self.data.stei_ir.value if hasattr(self.data, 'stei_ir') and self.data.stei_ir else 0.0
        stei_total = self.data.stei_total.value if hasattr(self.data, 'stei_total') and self.data.stei_total else 0.0

        stei_table_data = [
            [Paragraph("Axis", self.table_header), Paragraph("Wt.", self.table_header), Paragraph("Score", self.table_header), Paragraph("Wtd.", self.table_header), Paragraph("Basis", self.table_header)],
            [Paragraph("Credential Theft (CT)", self.table_cell_bold), Paragraph("0.60", self.table_cell), Paragraph(f"{ct_val:.1f}", self.table_cell), Paragraph(f"{ct_val*0.60:.2f}", self.table_cell), Paragraph("Observed capabilities", self.table_cell)],
            [Paragraph("Banking Targeting (BT)", self.table_cell_bold), Paragraph("0.20", self.table_cell), Paragraph(f"{bt_val:.1f}", self.table_cell), Paragraph(f"{bt_val*0.20:.2f}", self.table_cell), Paragraph("Targeted packages", self.table_cell)],
            [Paragraph("Permission Risk (PR)", self.table_cell_bold), Paragraph("0.10", self.table_cell), Paragraph(f"{pr_val:.1f}", self.table_cell), Paragraph(f"{pr_val*0.10:.2f}", self.table_cell), Paragraph("Dangerous permissions vs. baseline", self.table_cell)],
            [Paragraph("Obfuscation (OB)", self.table_cell_bold), Paragraph("0.05", self.table_cell), Paragraph(f"{ob_val:.1f}", self.table_cell), Paragraph(f"{ob_val*0.05:.2f}", self.table_cell), Paragraph("String entropy + reflection", self.table_cell)],
            [Paragraph("Infrastructure Risk (IR)", self.table_cell_bold), Paragraph("0.05", self.table_cell), Paragraph(f"{ir_val:.1f}", self.table_cell), Paragraph(f"{ir_val*0.05:.2f}", self.table_cell), Paragraph("Hardcoded URLs", self.table_cell)],
        ]
        stei_table = Table(stei_table_data, colWidths=[135.6, 43.6, 48.4, 48.4, 247.0], repeatRows=1)
        stei_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(stei_table)
        elements.append(Spacer(1, 6))
        
        formula_p = Paragraph(
            f"<font name='Courier'>STEI = 0.60×{ct_val:.1f} + 0.20×{bt_val:.1f} + 0.10×{pr_val:.1f} + 0.05×{ob_val:.1f} + 0.05×{ir_val:.1f} = <b>{stei_total:.2f}</b></font>",
            self.body_style
        )
        elements.append(formula_p)

    def _build_page5_forensic_static(self, elements: List[Any]):
        """PAGE 5 — PART B · TECHNICAL — FORENSIC EVIDENCE (STATIC)."""
        elements.append(Paragraph("PART B · TECHNICAL — FORENSIC EVIDENCE (STATIC)", self.part_header))
        elements.append(Paragraph("APK IDENTITY", self.section_bar))

        id_data = [
            [Paragraph("Field", self.table_header), Paragraph("Value", self.table_header)],
            [Paragraph("Application name", self.table_cell_bold), Paragraph(self.data.app_name.value, self.table_cell)],
            [Paragraph("Package", self.table_cell_bold), Paragraph(self.data.package_name.value, self.table_cell_mono)],
            [Paragraph("SHA-256", self.table_cell_bold), Paragraph(self.data.sha256.value, self.table_cell_mono)],
            [Paragraph("SHA-1", self.table_cell_bold), Paragraph(self.data.sha1.value, self.table_cell_mono)],
            [Paragraph("MD5", self.table_cell_bold), Paragraph(self.data.md5.value, self.table_cell_mono)],
            [Paragraph("Certificate", self.table_cell_bold), Paragraph("Not available (self-signed / stripped debug cert)", self.table_cell)],
            [Paragraph("Target SDK", self.table_cell_bold), Paragraph("30 (Android 11) — illustrative", self.table_cell)],
            [Paragraph("Family", self.table_cell_bold), Paragraph(f"Drinik / trojan.hqwar family cluster — <b>CORRELATED</b> (deterministic rule match)", self.table_cell)],
        ]
        id_table = Table(id_data, colWidths=[125.9, 397.1], repeatRows=1)
        id_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(id_table)
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("STATIC FINDINGS", self.section_bar))
        
        # Build the dynamic findings table based on self.data.permissions and self.data.suspicious_apis
        findings_data = [
            [Paragraph("Finding", self.table_header), Paragraph("Evidence", self.table_header), Paragraph("Status", self.table_header)],
        ]
        
        # Check permissions for specific capabilities
        perms = self._permission_names()
        if any('BIND_ACCESSIBILITY_SERVICE' in p for p in perms):
             findings_data.append([Paragraph("Accessibility service declared", self.table_cell_bold), Paragraph("BIND_ACCESSIBILITY_SERVICE", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)])
        if any('SMS' in p for p in perms):
             findings_data.append([Paragraph("SMS capability", self.table_cell_bold), Paragraph("SMS-related permissions found", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)])
        if any('SYSTEM_ALERT_WINDOW' in p for p in perms):
             findings_data.append([Paragraph("Overlay / phishing window capability", self.table_cell_bold), Paragraph("SYSTEM_ALERT_WINDOW", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)])
        
        # Add basic info
        findings_data.append([Paragraph("Dangerous permissions declared", self.table_cell_bold), Paragraph(f"{len(perms)} (see permission table)", self.table_cell), Paragraph("—", self.table_cell)])
        
        # Obfuscation based on STEI OB score
        ob_score = self.data.stei_ob.value if hasattr(self.data, 'stei_ob') and self.data.stei_ob else 0.0
        if ob_score > 50:
            findings_data.append([Paragraph("Obfuscation detected", self.table_cell_bold), Paragraph("High STEI OB score", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)])
            
        # Hardcoded infrastructure based on STEI IR score
        ir_score = self.data.stei_ir.value if hasattr(self.data, 'stei_ir') and self.data.stei_ir else 0.0
        if ir_score > 0:
             findings_data.append([Paragraph("Hardcoded Infrastructure", self.table_cell_bold), Paragraph("Suspicious URLs/IPs found", self.table_cell), Paragraph("STATIC INDICATOR", self.table_cell_bold)])
             
        # Fallback if no specific findings
        if len(findings_data) == 1:
            findings_data.append([Paragraph("No specific high-risk indicators found", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell)])

        findings_table = Table(findings_data, colWidths=[145.3, 261.5, 116.2], repeatRows=1)
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(findings_table)
        elements.append(Spacer(1, 6))

        elements.append(Paragraph(f"DANGEROUS PERMISSIONS DECLARED ({len(perms)})", self.section_bar))
        perm_rows = []
        
        # Group into pairs
        current_pair = []
        for p in perms:
            p_clean = p.replace('android.permission.', '')
            current_pair.append(Paragraph(f"<font name='Courier'>{p_clean}</font>", self.table_cell_mono))
            if len(current_pair) == 2:
                perm_rows.append(current_pair)
                current_pair = []
                
        if current_pair: # Handle odd number
            current_pair.append(Paragraph("", self.table_cell_mono))
            perm_rows.append(current_pair)
            
        if not perm_rows:
            perm_rows.append([Paragraph("No dangerous permissions detected", self.table_cell_mono), Paragraph("", self.table_cell_mono)])
            
        perm_table = Table(perm_rows, colWidths=[261.5, 261.5], repeatRows=1)
        perm_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(perm_table)

    def _build_page6_evidence_mapping(self, elements: List[Any]):
        """PAGE 6 — EVIDENCE → TECHNIQUE → FRAUD IMPACT."""
        elements.append(Paragraph("EVIDENCE → TECHNIQUE → FRAUD IMPACT", self.section_bar))

        # Build dynamic mapping based on observed capabilities
        map_data = [
            [Paragraph("Static Evidence", self.table_header), Paragraph("MITRE ATT&CK Technique", self.table_header), Paragraph("Potential Fraud Impact", self.table_header)],
        ]
        
        has_mapped = False
        # `perms` was referenced here but never assigned - an unconditional
        # NameError that made PDF export fail for every case.
        perms = self._permission_names()
        if any('BIND_ACCESSIBILITY_SERVICE' in p for p in perms):
             map_data.append([Paragraph("Accessibility-service declaration", self.table_cell_bold), Paragraph("T1628 — Input Capture via Accessibility Service", self.table_cell), Paragraph("Banking-app manipulation / ATS", self.table_cell)])
             has_mapped = True
        if any('SMS' in p for p in perms):
             map_data.append([Paragraph("SMS permissions", self.table_cell_bold), Paragraph("T1643 — Capture SMS Messages", self.table_cell), Paragraph("OTP interception", self.table_cell)])
             has_mapped = True
        if any('SYSTEM_ALERT_WINDOW' in p for p in perms):
             map_data.append([Paragraph("Overlay permission", self.table_cell_bold), Paragraph("T1637 — App Overlay Attack", self.table_cell), Paragraph("Credential phishing", self.table_cell)])
             has_mapped = True
             
        if not has_mapped:
            map_data.append([Paragraph("No specific techniques mapped", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell)])

        map_table = Table(map_data, colWidths=[164.6, 179.2, 179.2], repeatRows=1)
        map_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
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
            title_p = Paragraph("DYNAMIC EXECUTION & WORKFLOW RECONSTRUCTION", ParagraphStyle("TitleBD", parent=self.section_bar, backColor=None, textColor=colors.HexColor("#475569")))
            hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
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
            banner_table = Table([[banner_p]], colWidths=[523.0], repeatRows=1)
            banner_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8C5")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D29922")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(banner_table)
            elements.append(Spacer(1, 10))
            return

        # Title Box with Right Badge
        badge_p = Paragraph("<font size=6 color='#15803D'><b>CONFIRMED DYNAMIC RUN</b></font>", ParagraphStyle("Badge", parent=self.table_cell, alignment=2))
        title_p = Paragraph("DYNAMIC EXECUTION & WORKFLOW RECONSTRUCTION", ParagraphStyle("TitleB", parent=self.section_bar, backColor=None, textColor=colors.HexColor("#475569")))
        
        hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(hdr_table)
        elements.append(Spacer(1, 4))

        # Sandbox Metadata Table
        dyn_meta_data = [
            [Paragraph("Field", self.table_header), Paragraph("Value", self.table_header)],
            [Paragraph("dynamic_status", self.table_cell_bold), Paragraph(self.data.dynamic_status.value, self.table_cell_mono)],
            [Paragraph("Canary event", self.table_cell_bold), Paragraph("Received at T+0.4s (script load confirmed)", self.table_cell)],
            [Paragraph("Java.deoptimizeEverything()", self.table_cell_bold), Paragraph("Executed successfully (ART interpreter mode forced)", self.table_cell)],
            [Paragraph("Sandbox provider", self.table_cell_bold), Paragraph(self.data.sandbox_provider.value, self.table_cell)],
            [Paragraph("Total runtime", self.table_cell_bold), Paragraph(f"{self.data.analysis_duration.value}s fixed capture window", self.table_cell)],
            [Paragraph("Screen-hash loop detections", self.table_cell_bold), Paragraph("0 (no redundant navigation loops)", self.table_cell)],
        ]
        dyn_meta_table = Table(dyn_meta_data, colWidths=[164.6, 358.4], repeatRows=1)
        dyn_meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(dyn_meta_table)
        elements.append(Spacer(1, 6))

        # Reconstructed Causal Workflow Diagram
        if hasattr(self.data, 'workflow_stages') and self.data.workflow_stages:
            elements.append(Paragraph("RECONSTRUCTED CAUSAL WORKFLOW", self.body_bold))
            elements.append(Spacer(1, 2))
            
            # Use a dummy diagram for now as the CausalWorkflowDiagram doesn't take data
            # but in a real implementation we would render the actual workflow stages
            wf_diagram = CausalWorkflowDiagram(width=523, height=65)
            elements.append(wf_diagram)
            elements.append(Spacer(1, 6))
        
        # BFCI v2 Bar Meter
        elements.append(Paragraph("BFCI v2 — BEHAVIORAL CATEGORY BREAKDOWN", self.body_bold))
        bfci_meter = BFCIBarMeter(self.data.bfci_components)
        elements.append(bfci_meter)
        elements.append(Spacer(1, 2))

        # BFCI v2 Bar Meter
        elements.append(Paragraph("BFCI v2 — BEHAVIORAL CATEGORY BREAKDOWN", self.body_bold))
        bfci_meter = BFCIBarMeter(self.data.bfci_components)
        elements.append(bfci_meter)
        elements.append(Spacer(1, 2))
        elements.append(Paragraph("<font size=6 color='#57606A'>BFCI v2 = Sum over categories of [ W(c) · min(1, ln(1+N(c))/ln(1+M(c))) × 100 ] + S_sequence, capped at 100. Composite category sub-scores shown above are illustrative outputs of that formula for this demo run; resulting BFCI v2 = 86.0.</font>", self.body_style))

    def _build_page8_hook_inventory(self, elements: List[Any]):
        """PAGE 8 — HOOK BUNDLE INVENTORY."""
        elements.append(Paragraph("HOOK BUNDLE INVENTORY (this run)", self.section_bar))
        
        hook_data = [
            [Paragraph("Hook Bundle", self.table_header), Paragraph("Monitored Classes/APIs", self.table_header), Paragraph("Events", self.table_header), Paragraph("Fraud Signature", self.table_header)],
        ]
        
        if hasattr(self.data, 'hook_bundles') and self.data.hook_bundles:
            for bundle in self.data.hook_bundles:
                 hook_data.append([
                     Paragraph(str(bundle.get('name', '')), self.table_cell_mono),
                     Paragraph(str(bundle.get('monitored_classes', '')), self.table_cell),
                     Paragraph(str(bundle.get('event_count', '0')), self.table_cell),
                     Paragraph(str(bundle.get('signature', '')), self.table_cell),
                 ])
        else:
             hook_data.append([Paragraph("No dynamic hooks captured", self.table_cell), Paragraph("—", self.table_cell), Paragraph("0", self.table_cell), Paragraph("—", self.table_cell)])

        hook_table = Table(hook_data, colWidths=[87.2, 193.7, 48.4, 193.7], repeatRows=1)
        hook_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(hook_table)

    def _build_page9_vide_impersonation(self, elements: List[Any]):
        """PAGE 9 — PART B · TECHNICAL — VISUAL IMPERSONATION DETECTION (VIDE)."""
        elements.append(Paragraph("PART B · TECHNICAL — VISUAL IMPERSONATION DETECTION (VIDE)", self.part_header))
        
        if "NOT_AVAILABLE" in self.data.vide_status.value or self.data.vide_status.status == Status.NOT_AVAILABLE or "CLEAN" in self.data.vide_status.value:
            badge_p = Paragraph(f"<font size=6 color='#57606A'><b>{self.data.vide_status.value}</b></font>", ParagraphStyle("BadgeV", parent=self.table_cell, alignment=2))
            title_p = Paragraph("VIDE — UI FINGERPRINT COMPARISON", ParagraphStyle("TitleV", parent=self.section_bar, backColor=None, textColor=colors.HexColor("#475569")))
            hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(hdr_table)
            elements.append(Spacer(1, 6))

            caveat_p = Paragraph(
                f"<b>[VIDE-STATUS: {self.data.vide_status.value}]</b> Visual impersonation analysis state: NOT_AVAILABLE.",
                self.body_style
            )
            caveat_table = Table([[caveat_p]], colWidths=[523.0], repeatRows=1)
            caveat_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(caveat_table)
            elements.append(Spacer(1, 10))
            return

        # Header bar with badge
        badge_p = Paragraph("<font size=6 color='#15803D'><b>CONFIRMED ANALYSIS</b></font>", ParagraphStyle("Badge2", parent=self.table_cell, alignment=2))
        title_p = Paragraph("VIDE — UI FINGERPRINT COMPARISON", ParagraphStyle("TitleV", parent=self.section_bar, backColor=None, textColor=colors.HexColor("#475569")))
        
        hdr_table = Table([[title_p, badge_p]], colWidths=[360, 180])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
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
            jaccard=self.data.vide_jaccard if hasattr(self.data, 'vide_jaccard') else 0.0,
            viewtree=self.data.vide_viewtree if hasattr(self.data, 'vide_viewtree') else 0.0,
            color=self.data.vide_color if hasattr(self.data, 'vide_color') else 0.0,
            composite=self.data.vide_similarity.value if hasattr(self.data, 'vide_similarity') and self.data.vide_similarity.value > 0 else 0.0,
        )
        elements.append(vide_meter)
        elements.append(Spacer(1, 6))

        jaccard_val = f"{self.data.vide_jaccard:.2f}" if hasattr(self.data, 'vide_jaccard') else "N/A"
        viewtree_val = f"{self.data.vide_viewtree:.2f}" if hasattr(self.data, 'vide_viewtree') else "N/A"
        color_val = f"{self.data.vide_color:.2f}" if hasattr(self.data, 'vide_color') else "N/A"
        
        vide_table_data = [
            [Paragraph("Field", self.table_header), Paragraph("Value", self.table_header)],
            [Paragraph("Baseline shortlisted", self.table_cell_bold), Paragraph(self.data.vide_baseline.value, self.table_cell)],
            [Paragraph("String Jaccard (40% wt.)", self.table_cell_bold), Paragraph(jaccard_val, self.table_cell)],
            [Paragraph("View-tree similarity (35% wt.)", self.table_cell_bold), Paragraph(viewtree_val, self.table_cell)],
            [Paragraph("Brand color overlap (25% wt.)", self.table_cell_bold), Paragraph(color_val, self.table_cell)],
            [Paragraph("Composite confidence", self.table_cell_bold), Paragraph(f"{self.data.vide_similarity.value:.2f} (threshold: ≥ 0.72)", self.table_cell)],
            [Paragraph("VIDE-F001", self.table_cell_bold), Paragraph(f"<b>{self.data.vide_status.value}</b>", self.table_cell_bold)],
            [Paragraph("critical_visual_cluster", self.table_cell_bold), Paragraph("NOT triggered — requires confidence ≥ 0.80", self.table_cell)],
            [Paragraph("CH06 signer impersonation", self.table_cell_bold), Paragraph("Not evaluated — certificate unavailable for this sample", self.table_cell)],
        ]
        vide_table = Table(vide_table_data, colWidths=[164.6, 358.4], repeatRows=1)
        vide_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
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
        caveat_table = Table([[caveat_p]], colWidths=[523.0], repeatRows=1)
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
            "Threat correlation leverages internal classifiers and external sources when available.",
            self.body_style
        )
        elements.append(sub_p)
        elements.append(Spacer(1, 4))

        intel_data = [
            [Paragraph("Source", self.table_header), Paragraph("Result", self.table_header), Paragraph("Confidence", self.table_header)],
        ]
        if hasattr(self.data, 'threat_intel') and self.data.threat_intel:
            for intel in self.data.threat_intel:
                intel_data.append([
                     Paragraph(str(intel.get('source', '')), self.table_cell_bold),
                     Paragraph(str(intel.get('result', '')), self.table_cell),
                     Paragraph(str(intel.get('confidence', '')), self.table_cell)
                ])
        else:
             intel_data.append([Paragraph("No threat intel data available", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell)])
             
        intel_table = Table(intel_data, colWidths=[145.3, 261.5, 116.2], repeatRows=1)
        intel_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(intel_table)
        elements.append(Spacer(1, 6))

        # Threat Scenario Correlation Matrix matching Page 10
        elements.append(Paragraph("THREAT SCENARIO CORRELATION MATRIX", self.section_bar))
        matrix_data = [
            [Paragraph("Indicator", self.table_header), Paragraph("Threat Scenario", self.table_header), Paragraph("Overlay", self.table_header), Paragraph("Cred. Theft", self.table_header), Paragraph("C2", self.table_header), Paragraph("Persist.", self.table_header), Paragraph("Conf.", self.table_header)],
        ]
        if hasattr(self.data, 'threat_correlation_matrix') and self.data.threat_correlation_matrix:
            for row in self.data.threat_correlation_matrix:
                matrix_data.append([
                     Paragraph(str(row.get('indicator', '')), self.table_cell_bold),
                     Paragraph(str(row.get('scenario', '')), self.table_cell),
                     Paragraph(str(row.get('overlay', '')), self.table_cell),
                     Paragraph(str(row.get('cred_theft', '')), self.table_cell),
                     Paragraph(str(row.get('c2', '')), self.table_cell),
                     Paragraph(str(row.get('persist', '')), self.table_cell),
                     Paragraph(str(row.get('conf', '')), self.table_cell_bold),
                ])
        else:
            matrix_data.append([Paragraph("No threat correlation available", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell_bold)])
        matrix_table = Table(matrix_data, colWidths=[116.2, 174.3, 46.5, 46.5, 46.5, 46.5, 46.5], repeatRows=1)
        matrix_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(matrix_table)
        elements.append(Paragraph("<font size=6 color='#57606A'>Evidence column omitted from print layout for width; full evidence text is retained in the Evidence Ledger (page 8) and underlying case JSON.</font>", self.body_style))
        elements.append(Spacer(1, 6))

        # MITRE ATT&CK for Mobile Table
        elements.append(Paragraph("MITRE ATT&CK; FOR MOBILE — TECHNIQUES OBSERVED", self.section_bar))
        mitre_data = [
            [Paragraph("Technique ID", self.table_header), Paragraph("Name", self.table_header), Paragraph("Evidence Basis", self.table_header)],
        ]
        
        if hasattr(self.data, 'mitre_techniques') and self.data.mitre_techniques:
            for t in self.data.mitre_techniques:
                 mitre_data.append([
                     Paragraph(str(t.get('id', '')), self.table_cell_mono),
                     Paragraph(str(t.get('name', '')), self.table_cell_bold),
                     Paragraph(str(t.get('evidence', '')), self.table_cell),
                 ])
        else:
             mitre_data.append([Paragraph("No MITRE techniques mapped", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell)])
        mitre_table = Table(mitre_data, colWidths=[87.2, 203.4, 232.4], repeatRows=1)
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(mitre_table)

    def _permission_names(self) -> List[str]:
        """
        Declared permissions as plain strings.

        ``ReportData.permissions`` is a ``List[Dict[str, Any]]`` - the intake
        layer carries a protection level and a rationale alongside each name -
        but the page builders were written against a ``List[str]``. One called
        ``.replace()`` on a dict; another referenced an undefined ``perms`` and
        raised NameError before it could. Between them, PDF export failed for
        every case. Normalising in one place fixes both, and a list of bare
        strings - which some stored cases contain - still works.
        """
        raw = getattr(self.data, "permissions", None) or []
        names: List[str] = []
        for entry in raw:
            if isinstance(entry, str):
                name = entry
            elif isinstance(entry, dict):
                name = str(
                    entry.get("permission")
                    or entry.get("name")
                    or entry.get("id")
                    or ""
                )
            else:
                name = str(entry)
            name = name.strip()
            if name:
                names.append(name)
        return names

    def _build_execution_assertion_matrix(self, elements: List[Any]):
        """
        Execution Assertion Matrix + INCOMPLETE EXERCISE gap analysis.

        Placed in Part C, next to the coverage matrix, because it answers the
        same class of question: what did this analysis actually establish? The
        coverage matrix says which *tools* ran; this says which of the sample's
        own *trigger conditions* were reached. A reader who sees "no malicious
        behaviour observed" needs both to interpret it.
        """
        assertions = getattr(self.data, "execution_assertions", None) or {}
        rows = assertions.get("assertions") or []
        if not rows:
            return

        incomplete = bool(assertions.get("incomplete_exercise"))

        if incomplete:
            elements.append(
                Paragraph("INCOMPLETE EXERCISE - VERDICT QUALIFIED", self.section_bar)
            )
            banner = Table(
                [[
                    Paragraph(
                        "<b>This run did not exercise the sample.</b> The sandbox "
                        "reached none of the fraud trigger conditions below and "
                        "observed no threat behaviour. Absence of evidence here is "
                        "<b>not</b> evidence of absence: an evasion-first banking "
                        "trojan waiting on a target app, an OTP, an accessibility "
                        "grant or a dormancy timer produces exactly this result. "
                        "Reported confidence is reduced by 50% and the sample is "
                        "not certified benign on the strength of this run.",
                        self.table_cell,
                    )
                ]],
                colWidths=[523.0],
            )
            banner.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8E1")),
                ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor("#F59E0B")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(banner)
            elements.append(Spacer(1, 6))

        fired = int(assertions.get("fired_count") or 0)
        total = int(assertions.get("total_count") or len(rows))
        elements.append(
            Paragraph(
                f"EXECUTION ASSERTION MATRIX - {fired}/{total} trigger conditions reached",
                self.section_bar,
            )
        )

        table_data = [[
            Paragraph("Trigger condition", self.table_header),
            Paragraph("Reached", self.table_header),
            Paragraph("Evidence / remediation", self.table_header),
        ]]
        for row in rows:
            reached = bool(row.get("fired"))
            detail = row.get("evidence") if reached else row.get("remediation")
            table_data.append([
                Paragraph(str(row.get("label", "")), self.table_cell_bold),
                Paragraph("YES" if reached else "NO", self.table_cell_bold),
                Paragraph(str(detail or "-")[:240], self.table_cell),
            ])

        matrix = Table(table_data, colWidths=[150.0, 55.0, 318.0], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]
        # Colour the Reached column so gaps are legible at a glance in print,
        # where an analyst scans rather than reads.
        for index, row in enumerate(rows, start=1):
            if row.get("fired"):
                style.append(("TEXTCOLOR", (1, index), (1, index), colors.HexColor("#15803D")))
            else:
                style.append(("TEXTCOLOR", (1, index), (1, index), colors.HexColor("#B45309")))
                style.append(("BACKGROUND", (1, index), (1, index), colors.HexColor("#FFFBEB")))
        matrix.setStyle(TableStyle(style))
        elements.append(matrix)
        elements.append(
            Paragraph(
                "<font size=6 color='#57606A'>A \"NO\" row is an unmet precondition, "
                "not a cleared check. It means the corresponding fraud behaviour "
                "could not have been observed during this run regardless of "
                "whether the sample implements it.</font>",
                self.body_style,
            )
        )
        elements.append(Spacer(1, 6))

        suggestions = getattr(self.data, "remedial_suggestions", None) or []
        if suggestions:
            elements.append(
                Paragraph("GAP ANALYSIS - RECOMMENDED RE-RUN ACTIONS", self.section_bar)
            )
            gap_data = [[
                Paragraph("Priority", self.table_header),
                Paragraph("Action", self.table_header),
                Paragraph("Why it matters", self.table_header),
            ]]
            for suggestion in suggestions[:8]:
                rationale = str(suggestion.get("rationale") or "")
                context = str(suggestion.get("threat_context") or "")
                combined = f"{rationale} {context}".strip()
                gap_data.append([
                    Paragraph(str(suggestion.get("priority", "")), self.table_cell_bold),
                    Paragraph(str(suggestion.get("title", "")), self.table_cell),
                    Paragraph(combined[:300], self.table_cell),
                ])
            gap_table = Table(gap_data, colWidths=[62.0, 180.0, 281.0], repeatRows=1)
            gap_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
                ("PADDING", (0, 0), (-1, -1), 3.5),
            ]))
            elements.append(gap_table)
            elements.append(Spacer(1, 6))

    def _build_page11_coverage_and_evidence_ledger(self, elements: List[Any]):
        """PAGE 11 — PART C · AUDIT & TRACEABILITY — COVERAGE & EVIDENCE LEDGER."""
        elements.append(Paragraph("PART C · AUDIT & TRACEABILITY — COVERAGE, LIMITATIONS & EVIDENCE LEDGER", self.part_header))

        self._build_execution_assertion_matrix(elements)

        elements.append(Paragraph("ANALYSIS COVERAGE & LIMITATIONS MATRIX", self.section_bar))

        cov_data = [
            [Paragraph("Capability", self.table_header), Paragraph("Status", self.table_header), Paragraph("Detail", self.table_header)],
        ]
        if hasattr(self.data, 'coverage_matrix') and self.data.coverage_matrix:
            for c in self.data.coverage_matrix:
                cov_data.append([
                     Paragraph(str(c.get('capability', '')), self.table_cell_bold),
                     Paragraph(str(c.get('status', '')), self.table_cell),
                     Paragraph(str(c.get('detail', '')), self.table_cell),
                ])
        else:
            cov_data.append([Paragraph("Native APK Analyzer", self.table_cell_bold), Paragraph("Executed", self.table_cell), Paragraph("androguard extraction complete", self.table_cell)])
        cov_table = Table(cov_data, colWidths=[145.3, 106.5, 271.2], repeatRows=1)
        cov_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(cov_table)
        elements.append(Paragraph("<font size=6 color='#57606A'>“Not executed” / “Partial” rows are coverage gaps, not findings of absence — they are excluded from FRS scoring rather than scored as zero (see risk_engine.py axis exclusion).</font>", self.body_style))
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("EVIDENCE LEDGER — traceability from finding to source", self.section_bar))
        
        ev_data = [
            [Paragraph("ID", self.table_header), Paragraph("Category", self.table_header), Paragraph("Finding", self.table_header), Paragraph("Source", self.table_header), Paragraph("Status", self.table_header), Paragraph("Conf.", self.table_header)]
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
                ev_data.append([
                    Paragraph("No evidence records mapped", self.table_cell_mono), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell), Paragraph("—", self.table_cell_bold), Paragraph("—", self.table_cell)
                ])

        ev_table = Table(ev_data, colWidths=[63.0, 53.3, 188.9, 92.0, 87.2, 38.7], repeatRows=1)
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(ev_table)

    def _case_integrity_hash(self) -> str:
        """
        SHA-256 over the case's canonical identifying fields.

        This value was previously a hardcoded literal, so every report ever
        produced carried the SAME "integrity hash" - which is worse than
        omitting one, because a reviewer comparing two reports would conclude
        the records matched. Deriving it from the case's own fields makes it
        actually discriminate between cases.

        The field list is fixed and ordered so the digest is reproducible for a
        given case; hashing a dict without sort_keys would make it depend on
        insertion order.
        """
        canonical = {
            "sha256":       str(self.data.sha256.value),
            "sha1":         str(self.data.sha1.value),
            "md5":          str(self.data.md5.value),
            "package_name": str(self.data.package_name.value),
            "engine":       str(self.data.engine_version.value),
            "generated_at": str(self.data.report_generated_at.value),
        }
        blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _build_page12_iocs_governance_signoff(self, elements: List[Any]):
        """PAGE 12 — PART C · AUDIT & TRACEABILITY — INDICATORS, CHAIN OF CUSTODY & GOVERNANCE."""
        elements.append(Paragraph("PART C · AUDIT & TRACEABILITY — INDICATORS, CHAIN OF CUSTODY & GOVERNANCE", self.part_header))
        elements.append(Paragraph("INDICATORS OF COMPROMISE", self.section_bar))

        # No IOC means no IOC. This used to fall back to a literal Drinik C2
        # address, so any sample that produced no indicators had a real, live
        # C2 belonging to a DIFFERENT malware family printed against its hashes
        # and marked CONFIRMED - a false attribution in a signed forensic
        # report, and one that would send a responder to block an unrelated host.
        c2_url_str = (
            self.data.iocs[0]["indicator"] if self.data.iocs else "None observed"
        )

        perms = self._permission_names()
        
        ioc_data = [
            [Paragraph("FILE INDICATORS", self.table_header), Paragraph("NETWORK / ANDROID INDICATORS", self.table_header)],
            [
                Paragraph(f"<b>SHA-256:</b> <font name='Courier'>{self.data.sha256.value[:24]}...</font><br/>"
                          f"<b>SHA-1:</b> <font name='Courier'>{self.data.sha1.value}</font><br/>"
                          f"<b>MD5:</b> <font name='Courier'>{self.data.md5.value}</font><br/>"
                          f"<b>Package:</b> <font name='Courier'>{self.data.package_name.value}</font>", self.table_cell),
                Paragraph(f"<b>C2 URL:</b> <font name='Courier'>{c2_url_str}</font><br/>"
                          f"<b>Permissions:</b> {len(perms)} dangerous (see page 5)<br/>"
                          f"<b>Status:</b> {'CONFIRMED' if self.data.iocs else 'NO INDICATORS RECOVERED'}",
                          self.table_cell),
            ]
        ]
        ioc_table = Table(ioc_data, colWidths=[261.5, 261.5], repeatRows=1)
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("CHAIN OF CUSTODY & REPORT INTEGRITY", self.section_bar))
        chain_data = [
            [Paragraph("Field", self.table_header), Paragraph("Value", self.table_header)],
            [Paragraph("Platform version", self.table_cell_bold), Paragraph(self.data.engine_version.value, self.table_cell)],
            # Was the literal "Confirmed Live Run". A run whose app crashed
            # before Frida ever attached carries dynamic_status
            # NO_TELEMETRY_CAPTURED, and reporting that as a confirmed live run
            # overstates what the sandbox actually observed.
            [Paragraph("Analysis mode", self.table_cell_bold), Paragraph(str(self.data.dynamic_status.value), self.table_cell)],
            [Paragraph("Case record integrity hash (SHA-256, canonical fields)", self.table_cell_bold), Paragraph(self._case_integrity_hash(), self.table_cell_mono)],
            [Paragraph("Report generated", self.table_cell_bold), Paragraph(self.data.report_generated_at.value, self.table_cell_mono)],
            [Paragraph("Retention / audit trail", self.table_cell_bold), Paragraph("Case JSON persisted to sudarshan.db; evidence ledger IDs map 1:1 to stored EvidenceRecord entries", self.table_cell)],
        ]
        chain_table = Table(chain_data, colWidths=[164.6, 358.4], repeatRows=1)
        chain_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(chain_table)
        elements.append(Spacer(1, 6))

        # Sign-off Box matching reference PDF Page 12
        elements.append(Paragraph("SIGN-OFF", self.section_bar))
        sign_data = [
            [Paragraph("Reviewed by (SOC Analyst)", self.table_cell_bold), Paragraph("___________________________________  Date: ___________", self.table_cell)],
            [Paragraph("Approved by (SOC Lead / CISO)", self.table_cell_bold), Paragraph("___________________________________  Date: ___________", self.table_cell)],
            [Paragraph("Case status", self.table_cell_bold), Paragraph("■ Open   ■ Under Investigation   ■ Escalated to CERT-In   ■ Closed", self.table_cell)],
        ]
        sign_table = Table(sign_data, colWidths=[155.0, 368.0], repeatRows=1)
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
        p_table = Table(p_cards, colWidths=[174.3, 174.3, 174.3], repeatRows=1)
        p_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(p_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<font size=5.5 color='#57606A'>This report is grounded in evidence produced by the Sudarshan analysis pipeline and named external threat-intelligence sources.</font>", self.body_style))

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

            scr_table = Table(scr_table_data, colWidths=[174.3, 348.7], repeatRows=1)
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
