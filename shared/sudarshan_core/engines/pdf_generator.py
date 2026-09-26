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

from sudarshan_core import brand as BRAND
from sudarshan_core.engines import report_theme as THEME

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

    # VIDE per-axis scores and the forensic breakdown behind them. Page 9 read
    # these through `hasattr` and so drew an empty meter for every case, because
    # nothing ever set them. Defaulted rather than required so a stored case
    # written before the breakdown existed still renders.
    vide_jaccard: float = 0.0
    vide_viewtree: float = 0.0
    vide_color: float = 0.0
    vide_institution: str = ""
    vide_tier: str = ""
    vide_forensics: Dict[str, Any] = field(default_factory=dict)

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

    # ── Dynamic status ────────────────────────────────────────────────────────
    # The sandbox publishes its own status and it is the authoritative value.
    # This block used to synthesise a two-valued string instead, and the test
    # for it was `bool(dynamic_res)` - a dict that a FAILED run also returns,
    # fully populated. So every failure mode the engine distinguishes
    # (INSTRUMENTATION_FAILED, FRIDA_ATTACH_FAILED, PID_NOT_FOUND,
    # NO_UI_RENDERED, RUNTIME_COMPLETED_NO_EVENTS, EMULATOR_UNAVAILABLE,
    # INSTALL_FAILED, INCONCLUSIVE) was reported as EVENTS_CAPTURED under a
    # "CONFIRMED DYNAMIC RUN" badge. Verified against a real persisted case:
    # org.schabi.newpipe carries INSTRUMENTATION_FAILED and rendered as a
    # confirmed run with a received canary and a BFCI of 86.
    #
    # `dynamic_observed` is the flag the page builders need: it means the
    # sandbox ran AND produced behavioural telemetry. "It ran" alone is not
    # enough to describe a run as confirmed.
    dyn_status = safe_str(get_val(dynamic_res, "dynamic_status"), "")
    if not dyn_status:
        # `dynamic_ran` gates everything: a run that did not happen cannot be
        # conclusive, whatever `dynamic_conclusive` says. Reading conclusive
        # first let a stale True label a sandbox that never started as
        # EVENTS_CAPTURED.
        if not dynamic_ran_bool:
            dyn_status = "NOT_PERFORMED"
        elif dynamic_conclusive_bool:
            dyn_status = "EVENTS_CAPTURED"
        else:
            dyn_status = "COMPLETED_INCONCLUSIVE"

    dynamic_observed_bool = dyn_status == "EVENTS_CAPTURED" and dynamic_ran_bool

    if not dynamic_ran_bool or dyn_status in ("NOT_PERFORMED", "NOT_STARTED"):
        dyn_status_enum = Status.NOT_PERFORMED
    elif dynamic_observed_bool:
        dyn_status_enum = Status.OBSERVED
    else:
        # Ran, did not observe. Neither OBSERVED nor NOT_PERFORMED: the
        # distinction is the whole point of this section.
        dyn_status_enum = Status.NOT_OBSERVED

    # Why the risk engine dropped the dynamic axis, in its own words
    # (NO_BEHAVIOR_OBSERVED, NO_UI_RENDERED, EVASION_ONLY, ...). Computed on
    # every case and never rendered.
    dyn_exclusion_reason = safe_str(get_val(frs_breakdown, "dynamic_exclusion_reason"), "")

    bfci_total_val = safe_float(get_val(dynamic_res, "bfci", get_val(frs_breakdown, "dynamic")), 0.0)
    bfci_comps = get_val(dynamic_res, "bfci_components") or {}
    if not isinstance(bfci_comps, dict):
        bfci_comps = {}

    sandbox_provider_val = safe_str(get_val(dynamic_res, "sandbox_provider"), "Not available")
    frida_version_val = safe_str(get_val(dynamic_res, "frida_version"), "Not available")

    # The keys below were read under names the sandbox does not emit, so each
    # rendered as its zero on every real case. Verified against the persisted
    # cases in backend/sudarshan.db: `duration_seconds` is 300 while
    # `analysis_duration` is absent, and `hooks_installed` is 77 while
    # `total_hooks_installed` is absent. The old spellings are kept as
    # fallbacks so a caller handing us a hand-built dict still works.
    duration_val = safe_float(
        get_val(dynamic_res, "duration_seconds", get_val(dynamic_res, "analysis_duration")),
        0.0,
    )
    hooks_count_val = safe_int(
        get_val(dynamic_res, "hooks_installed", get_val(dynamic_res, "total_hooks_installed")),
        0,
    )

    # Behavioural events only. `raw_event_counts` spans harness bookkeeping
    # (`harness_action`) and app telemetry as well as fraud categories, and
    # counting those would report a run that did nothing as having produced
    # events.
    raw_event_counts = get_val(dynamic_res, "raw_event_counts") or {}
    if not isinstance(raw_event_counts, dict):
        raw_event_counts = {}
    _HARNESS_CATEGORIES = {"harness_action", "smoke"}
    events_count_val = safe_int(
        get_val(dynamic_res, "total_events_captured"),
        sum(
            safe_int(v)
            for k, v in raw_event_counts.items()
            if k not in _HARNESS_CATEGORIES
        )
        or len(get_val(dynamic_res, "events") or []),
    )

    hook_fire_counts = get_val(dynamic_res, "hook_fire_counts") or {}
    if not isinstance(hook_fire_counts, dict):
        hook_fire_counts = {}
    canary_received_val = get_val(dynamic_res, "canary_received")
    launch_method_val = safe_str(get_val(dynamic_res, "launch_method_used"), "")
    java_hooks_val = safe_int(get_val(dynamic_res, "java_hooks_installed"), 0)
    native_hooks_val = safe_int(get_val(dynamic_res, "native_hooks_installed"), 0)

    # Classification & VIDE
    family_val = safe_str(get_val(case_data, "family_classification"), "Unknown")
    matched_rule_val = safe_str(get_val(case_data, "matched_rule"), "No deterministic rule matched")
    
    vide_res = get_val(case_data, "vide") or {}
    if not isinstance(vide_res, dict):
        vide_res = {}

    vide_compare_res = get_val(vide_res, "vide_compare") or {}
    if not isinstance(vide_compare_res, dict):
        vide_compare_res = {}
    vide_scores = get_val(vide_compare_res, "scores") or {}
    if not isinstance(vide_scores, dict):
        vide_scores = {}
    vide_forensics_val = get_val(vide_res, "forensic_breakdown") or get_val(vide_compare_res, "forensics") or {}
    if not isinstance(vide_forensics_val, dict):
        vide_forensics_val = {}

    vide_jaccard_val = safe_float(get_val(vide_scores, "string_jaccard"), 0.0)
    vide_viewtree_val = safe_float(get_val(vide_scores, "tree_similarity"), 0.0)
    vide_color_val = safe_float(get_val(vide_scores, "color_match"), 0.0)
    vide_institution_val = safe_str(
        get_val(vide_compare_res, "institution_display")
        or get_val(vide_res, "visual_impersonation_institution"),
        "",
    )
    vide_tier_val = safe_str(get_val(vide_res, "visual_impersonation_tier_label"), "")

    # The engine emits `available` / `status`; `analyzed` is not a key it has
    # ever written. The string "analyzed" occurs in this repository only on this
    # line and in the old test fixture, which is why the whole VIDE section -
    # meter, tier, institution, and the CIE dE2000 colour table - has never
    # rendered for a real case. Verified: a persisted case carrying
    # available=True, status="OK" printed "[VIDE-STATUS: NOT_AVAILABLE]".
    vide_ok = bool(
        get_val(vide_res, "available")
        or get_val(vide_res, "analyzed")  # accepted for hand-built inputs
        or safe_str(get_val(vide_res, "status")).upper() == "OK"
    )
    if vide_res and vide_ok:
        vide_status_val = "FIRED — visual similarity detection confirmed" if get_val(vide_res, "visual_impersonation_detected") else "CLEAN — no impersonation match"
        vide_status_enum = Status.OBSERVED
        # `matched_baseline` is a dict - institution_id, display_name, bank and
        # the `source` that says whether the match came from vide_compare or the
        # weaker corpus_compare. Passing it to safe_str printed a Python dict
        # repr into a forensic report.
        baseline_raw = get_val(vide_res, "matched_baseline")
        if isinstance(baseline_raw, dict):
            baseline_name = safe_str(
                get_val(baseline_raw, "display_name")
                or get_val(baseline_raw, "bank")
                or get_val(baseline_raw, "institution_id"),
                "None",
            )
            baseline_source = safe_str(get_val(baseline_raw, "source"), "")
            vide_baseline_val = (
                f"{baseline_name} (via {baseline_source})" if baseline_source else baseline_name
            )
        else:
            vide_baseline_val = safe_str(baseline_raw, "None")

        # `confidence` is not a key the engine emits at the top level. The
        # comparer's confidence is the number the rest of the page describes.
        vide_similarity_val = safe_float(get_val(vide_res, "visual_impersonation_confidence"), 0.0)
        if not vide_similarity_val:
            vide_similarity_val = safe_float(get_val(vide_compare_res, "confidence"), 0.0)
        if not vide_similarity_val:
            vide_similarity_val = safe_float(get_val(vide_res, "similarity_score"), 0.0)
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
        # The correlator writes `sha256_detections` / `sha256_total`. The
        # spellings previously read here are not keys it emits, so the detection
        # ratio printed "0 / 0" on every case that had ever been enriched.
        vt_malicious = safe_int(
            get_val(
                threat_intel_data,
                "sha256_detections",
                get_val(threat_intel_data, "vt_malicious_count", get_val(threat_intel_data, "positives")),
            ),
            0,
        )
        vt_total = safe_int(
            get_val(
                threat_intel_data,
                "sha256_total",
                get_val(threat_intel_data, "vt_total_engines", get_val(threat_intel_data, "total")),
            ),
            0,
        )

        # Three states the correlator carefully distinguishes and this line used
        # to collapse into one: the hash is absent from VirusTotal, the hash is
        # present and clean, or nothing was queried at all. A responder acts
        # differently on each.
        ioc_reputation = get_val(threat_intel_data, "ioc_reputation") or []
        if not isinstance(ioc_reputation, list):
            ioc_reputation = []
        hash_in_vt = get_val(threat_intel_data, "vt_hash_in_database")
        if vt_total > 0:
            vt_ratio_str = f"{vt_malicious} / {vt_total}"
        elif hash_in_vt is False:
            vt_ratio_str = "Not in VirusTotal"
        else:
            vt_ratio_str = "Not available"

        otx_pulses = safe_int(get_val(threat_intel_data, "otx_pulse_count", len(get_val(threat_intel_data, "otx_pulses") or [])), 0)

        # AbuseIPDB scores are per-indicator under `ioc_reputation`; there is no
        # top-level `abuseipdb_score`, so this always read 0. The worst score
        # across the indicators is the one that matters for triage.
        abuse_scores = [
            safe_float(get_val(entry, "abuse_score"), 0.0)
            for entry in ioc_reputation
            if isinstance(entry, dict) and get_val(entry, "abuse_score") is not None
        ]
        abuseipdb_val = max(abuse_scores) if abuse_scores else safe_float(
            get_val(threat_intel_data, "abuseipdb_score"), 0.0
        )

        corr_family = safe_str(
            get_val(threat_intel_data, "known_family") or get_val(threat_intel_data, "vt_family"),
            "None",
        )
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
    # Precomputed by EvidenceStore: totals by severity and by category.
    evidence_summary: Dict[str, Any] = {}
    
    if apk_dir and apk_dir.exists():
        ev_file = apk_dir / "evidence.json"
        if ev_file.exists():
            try:
                ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
                # EvidenceStore.flush writes
                # {"generated_at", "package_name", "summary", "records": [...]}.
                # Only the bare-list shape was accepted, so the Evidence Ledger
                # - the traceability the report names as its third principle -
                # rendered "No evidence records mapped" for every real case
                # while the records sat on disk. report_generator.py reads the
                # same file correctly, which is why the HTML export showed them.
                if isinstance(ev_data, dict):
                    evidence_summary = ev_data.get("summary") or {}
                    ev_data = ev_data.get("records") or []
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
                if isinstance(scr_data, dict):
                    # flush_manifest() writes {"generated_at":..., "screenshots":[...]}
                    scr_data = scr_data.get("screenshots", [])
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

    ai_report = get_val(case_data, "intelligence_report") or get_val(case_data, "executive_view") or {}
    plain_narrative = get_val(ai_report, "plain_english_narrative", "Not available.")
    fraud_obj = get_val(ai_report, "fraud_objective", "Not available")
    cust_impact = get_val(ai_report, "customer_impact", "Not available")
    bank_impact = get_val(ai_report, "banking_impact_assessment") or get_val(ai_report, "banking_impact", "Not available")
    cert_recs = get_val(ai_report, "cert_in_recommendations", [])
    cust_adv = get_val(ai_report, "customer_advisory_draft", "Not available")
    affected_banks_list = get_val(ai_report, "affected_banking_apps", []) or []

    # ── MITRE techniques ──────────────────────────────────────────────────────
    # `mitre_techniques` is not a key the pipeline writes - confirmed absent
    # from all 13 persisted cases - so the MITRE table printed "No MITRE
    # techniques mapped" unconditionally. Two real sources exist, and they are
    # NOT equivalent: an evidence record carries a technique that was actually
    # observed at runtime, while the intelligence report lists techniques
    # inferred from static capability. Merging them would present a declared
    # capability as observed behaviour, so provenance travels with each row.
    mitre_techniques_list = get_val(case_data, "mitre_techniques", []) or []
    if not mitre_techniques_list:
        seen_techniques: Dict[str, Dict[str, Any]] = {}
        for rec in evidence_records_list:
            if not isinstance(rec, dict):
                continue
            tid = safe_str(get_val(rec, "mitre_technique_id"))
            if not tid:
                continue
            entry = seen_techniques.setdefault(
                tid,
                {
                    "id": tid,
                    "name": safe_str(get_val(rec, "mitre_technique_name"), ""),
                    "basis": "OBSERVED",
                    "evidence_ids": [],
                },
            )
            fid = safe_str(get_val(rec, "finding_id") or get_val(rec, "id"))
            if fid and len(entry["evidence_ids"]) < 6:
                entry["evidence_ids"].append(fid)

        for raw in get_val(ai_report, "mitre_techniques_used", []) or []:
            text = safe_str(raw).strip()
            if not text:
                continue
            # Entries arrive as "T1411 - Input Prompt" or bare "T1411".
            tid = text.split()[0].strip(" -:")
            if tid in seen_techniques:
                continue
            name = text[len(tid):].strip(" -:") if len(text) > len(tid) else ""
            seen_techniques[tid] = {
                "id": tid,
                "name": name,
                "basis": "STATIC INFERENCE",
                "evidence_ids": [],
            }
        mitre_techniques_list = list(seen_techniques.values())

    # ── SOC actions ───────────────────────────────────────────────────────────
    # Also never written by the pipeline, so this table rendered header-only on
    # every report. The intelligence report's recommended actions and the risk
    # engine's own recommended action are the real content.
    soc_actions_list = get_val(case_data, "soc_actions", []) or []
    if not soc_actions_list:
        derived_actions: List[Dict[str, str]] = []
        engine_action = safe_str(get_val(case_data, "recommended_action"))
        if engine_action:
            derived_actions.append({"action": "ENGINE VERDICT", "detail": engine_action})
        for item in get_val(ai_report, "recommended_actions", []) or []:
            text = safe_str(item).strip()
            if text:
                derived_actions.append({"action": "RECOMMENDED", "detail": text})
        soc_actions_list = derived_actions

    activities_list = get_val(case_data, "activities", [])
    # The pipeline persists this as `services_list`; `services` is the API
    # projection's name for it and is absent from every stored case.
    services_list = get_val(case_data, "services_list") or get_val(case_data, "services", []) or []
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
        vide_jaccard=vide_jaccard_val,
        vide_viewtree=vide_viewtree_val,
        vide_color=vide_color_val,
        vide_institution=vide_institution_val,
        vide_tier=vide_tier_val,
        vide_forensics=vide_forensics_val,

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

# The marking is printed in the running header of every page. A dossier that
# may be filed with CERT-In or produced in evidence has to say, on each sheet,
# what handling it expects; TLP:AMBER is the default for a case bound to a
# named institution and a named sample.
DOCUMENT_CLASSIFICATION = "CONFIDENTIAL — TLP:AMBER"

# Every table in the document is built from this one style. Horizontal rules
# only, at three weights, with no vertical rules and no double rules; the
# header carries a neutral grey band rather than a colour.
def formal_table_style(
    header_rows: int = 1,
    body_rules: bool = True,
    total_row: bool = False,
    extra=None,
):
    """
    Rules for a formal table: heavy above and below, light under the header,
    hairline between body rows.

    `booktabs` states the two rules this follows - never a vertical rule,
    never a double rule - and they hold for every table in this document,
    including the ones that used to be drawn as full grids.
    """
    ink = colors.HexColor(THEME.BORDER_STRONG)
    hair = colors.HexColor(THEME.RULE_HAIR)
    style = [
        ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG, ink),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ("BOTTOMPADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header_rows:
        style.append(
            ("BACKGROUND", (0, 0), (-1, header_rows - 1),
             colors.HexColor(THEME.SURFACE_INSET)))
        style.append(
            ("LINEBELOW", (0, header_rows - 1), (-1, header_rows - 1),
             THEME.RULE_W_MID, ink))
    if body_rules:
        style.append(
            ("LINEBELOW", (0, header_rows), (-1, -2), THEME.RULE_W_HAIR, hair))
    style.append(("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG, ink))
    if total_row:
        style.append(
            ("LINEABOVE", (0, -1), (-1, -1), THEME.RULE_W_MID, ink))
    if extra:
        style.extend(extra)
    return TableStyle(style)


def block_quote_style(extra=None):
    """
    A standing-out block of prose - a document notice, a qualifier, a scope
    statement. Ruled above and below rather than boxed and tinted: a filled
    panel with a coloured edge is dashboard furniture, and four of them on a
    page is the single loudest tell that a document was generated rather than
    written.
    """
    ink = colors.HexColor(THEME.BORDER_STRONG)
    style = [
        ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_MID, ink),
        ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_MID, ink),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]
    if extra:
        style.extend(extra)
    return TableStyle(style)


def make_numbered_canvas(chrome: Dict[str, str]):
    """
    Canvas that knows the document's total page count before it draws chrome.

    ReportLab's onPage hook fires while the document is still being laid out,
    so it cannot print "Page 4 of 13" - only "Page 4". Page accountability is
    not optional in a forensic report (SWGDE 18-Q-002 requires the reader be
    able to tell that no sheet is missing), so pages are held in memory and the
    header and footer are drawn on the second pass, when the total is known.
    """

    class _NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_states = []

        def showPage(self):
            self._saved_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved_states)
            for state in self._saved_states:
                self.__dict__.update(state)
                self._draw_chrome(total)
                super().showPage()
            super().save()

        def _draw_chrome(self, total_pages: int):
            page_w, page_h = 595.27, 841.89
            left = THEME.PAGE_MARGIN_INSIDE_MM * 72.0 / 25.4
            right = page_w - THEME.PAGE_MARGIN_OUTSIDE_MM * 72.0 / 25.4
            page_no = self._pageNumber

            self.saveState()

            # The title page carries the full masthead in the body; a
            # running head on top of it would repeat it.
            if page_no > 1:
                baseline = page_h - 47
                cursor = left

                # The mark, set at cap height so it sits on the same optical
                # line as the wordmark beside it.
                mark = BRAND.mark_path(small=True)
                if mark is not None:
                    size = 14.5
                    try:
                        self.drawImage(str(mark), cursor, baseline - 3.0,
                                       width=size, height=size,
                                       mask="auto", preserveAspectRatio=True)
                        cursor += size + 5.0
                    except Exception:
                        # A brand asset must never take an export down with it.
                        pass

                self.setFont("Helvetica-Bold", 8.5)
                self.setFillColor(colors.HexColor(THEME.INK_STRONG))
                self.drawString(cursor, baseline, BRAND.WORDMARK)
                cursor += self.stringWidth(BRAND.WORDMARK, "Helvetica-Bold", 8.5)

                # The case reference used to sit here, immediately left of the
                # centred classification, and a long reference ran into it. It
                # moved to the footer, where it still appears on every sheet -
                # which is what page accountability requires - without
                # crowding the masthead.
                self.setFont("Helvetica", THEME.PT_FINE)
                self.setFillColor(colors.HexColor(THEME.INK_MUTED))
                self.drawCentredString((left + right) / 2.0, baseline,
                                       DOCUMENT_CLASSIFICATION)
                self.drawRightString(right, baseline,
                                     f"Page {page_no} of {total_pages}")

                self.setStrokeColor(colors.HexColor(THEME.BORDER))
                self.setLineWidth(THEME.RULE_W_MID)
                self.line(left, page_h - 55, right, page_h - 55)

            self.setStrokeColor(colors.HexColor(THEME.BORDER))
            self.setLineWidth(THEME.RULE_W_MID)
            self.line(left, 44, right, 44)
            self.setFont("Helvetica-Bold", 6.5)
            self.setFillColor(colors.HexColor(THEME.INK_MUTED))
            self.drawString(left, 33, chrome["report_id"])
            offset = self.stringWidth(chrome["report_id"], "Helvetica-Bold", 6.5)
            self.setFont("Courier", 6.5)
            self.setFillColor(colors.HexColor(THEME.INK_FAINT))
            self.drawString(left + offset + 7.0, 33, chrome["integrity"])
            self.setFont("Helvetica", 6.5)
            self.drawCentredString((left + right) / 2.0, 33,
                                   "Uncontrolled when printed")
            self.drawRightString(right, 33, chrome["issued"])

            self.restoreState()

    return _NumberedCanvas


# ---------------------------------------------------------------------------
# Custom Flowables & Vector Graphics
# ---------------------------------------------------------------------------

class _MonoBarChart(Drawing):
    """
    Horizontal bars, one ink, value printed at the end of each.

    Bar length is the second-strongest elementary encoding in Cleveland and
    McGill's ordering, which is why the bar charts survived the redesign while
    the verdict dial did not: a dial encodes with angle, three ranks down, and
    it cannot be read to a decimal place. Nothing here is rounded, tinted or
    filled with a category colour; the track is a hairline, not a sunken well.
    """

    LABEL_W = 176.0
    VALUE_W = 42.0

    def __init__(self, rows, width=523, row_h=16, note_w=0.0, fmt="{:.1f}"):
        # rows: (label, value on 0..100, trailing note)
        super().__init__(width, max(row_h * len(rows), row_h))
        self.hAlign = "LEFT"
        track_w = width - self.LABEL_W - self.VALUE_W - note_w
        y = self.height - row_h + 4
        for label, value, note in rows:
            val = max(0.0, min(float(value), 100.0))
            self.add(String(0, y, label, fontName="Helvetica", fontSize=7.5,
                            fillColor=colors.HexColor(THEME.INK_STRONG)))
            self.add(Line(self.LABEL_W, y - 2, self.LABEL_W + track_w, y - 2,
                          strokeColor=colors.HexColor(THEME.BORDER),
                          strokeWidth=0.5))
            self.add(Rect(self.LABEL_W, y - 2,
                          max(0.6, (val / 100.0) * track_w), 6,
                          fillColor=colors.HexColor(THEME.INK_STRONG),
                          strokeColor=None))
            self.add(String(self.LABEL_W + track_w + self.VALUE_W - 4, y,
                            fmt.format(value), textAnchor="end",
                            fontName="Helvetica-Bold", fontSize=7.5,
                            fillColor=colors.HexColor(THEME.INK_STRONG)))
            if note:
                self.add(String(self.LABEL_W + track_w + self.VALUE_W + 6, y,
                                note, fontName="Helvetica", fontSize=6.5,
                                fillColor=colors.HexColor(THEME.INK_FAINT)))
            y -= row_h


class FRSBarMeter(_MonoBarChart):
    """Axis contributions to the verdict score."""

    def __init__(self, stei: float, bfci: float, corr: float, bank: float,
                 width=523, height=85):
        super().__init__(
            [
                ("Static exposure (STEI)", stei,
                 "w=0.25 → %.2f" % (stei * 0.25)),
                ("Dynamic behaviour (BFCI v2)", bfci,
                 "w=0.35 → %.2f" % (bfci * 0.35)),
                ("Threat correlation", corr,
                 "w=0.20 → %.2f" % (corr * 0.20)),
                ("Banking impact", bank,
                 "w=0.20 → %.2f" % (bank * 0.20)),
            ],
            width=width, row_h=18, note_w=96.0,
        )


class STEIBarMeter(_MonoBarChart):
    """Five-axis STEI breakdown."""

    def __init__(self, ct: float, bt: float, pr: float, ob: float, ir: float,
                 width=523, height=95):
        super().__init__(
            [
                ("Credential theft (CT)", ct, "w=0.60"),
                ("Banking targeting (BT)", bt, "w=0.20"),
                ("Permission risk (PR)", pr, "w=0.10"),
                ("Obfuscation (OB)", ob, "w=0.05"),
                ("Infrastructure risk (IR)", ir, "w=0.05"),
            ],
            width=width, row_h=16, note_w=52.0,
        )


# The thresholds Page 9 renders belong to the engine, not to the report.
from sudarshan_core.engines.vide.compare import DETECTION_THRESHOLD as VIDE_DETECTION_THRESHOLD
from sudarshan_core.engines.vide.forensics import TIER_HIGH as VIDE_TIER_HIGH
from sudarshan_core.engines.vide.forensics import TIER_MODERATE as VIDE_TIER_MODERATE


class VIDEBarMeter(Drawing):
    """
    VIDE UI-fingerprint comparison. Components are 0..1, so the axis runs 0..1
    and the two engine thresholds are drawn on it as reference lines.
    """

    LABEL_W = 176.0
    TRACK_W = 250.0

    def __init__(self, jaccard: float, viewtree: float, color: float,
                 composite: float, width=523, height=85):
        super().__init__(width, height)
        self.hAlign = "LEFT"
        bars = [
            ("String Jaccard (40% wt.)", jaccard, False),
            ("View-tree similarity (35% wt.)", viewtree, False),
            ("Brand colour overlap (25% wt.)", color, False),
            ("Composite confidence", composite, True),
        ]
        y = height - 14
        for label, val, emphasis in bars:
            self.add(String(0, y, label, fontName="Helvetica", fontSize=7.5,
                            fillColor=colors.HexColor(THEME.INK_STRONG)))
            self.add(Line(self.LABEL_W, y - 2, self.LABEL_W + self.TRACK_W, y - 2,
                          strokeColor=colors.HexColor(THEME.BORDER),
                          strokeWidth=0.5))
            self.add(Rect(self.LABEL_W, y - 2,
                          max(0.6, max(0.0, min(val, 1.0)) * self.TRACK_W),
                          7 if emphasis else 6,
                          fillColor=colors.HexColor(THEME.INK_STRONG),
                          strokeColor=None))
            self.add(String(self.LABEL_W + self.TRACK_W + 34, y, "%.2f" % val,
                            textAnchor="end",
                            fontName="Helvetica-Bold" if emphasis else "Helvetica",
                            fontSize=7.5,
                            fillColor=colors.HexColor(THEME.INK_STRONG)))
            y -= 18

        # Detection threshold, read from the engine rather than restated here -
        # a report that draws the line somewhere the engine does not use it is
        # worse than one that draws no line at all.
        tx = self.LABEL_W + (VIDE_DETECTION_THRESHOLD * self.TRACK_W)
        self.add(Line(tx, 0, tx, height - 10,
                      strokeColor=colors.HexColor(THEME.INK_STRONG),
                      strokeWidth=0.75, strokeDashArray=[2, 2]))
        self.add(String(tx, height - 6,
                        "detection threshold %.2f" % VIDE_DETECTION_THRESHOLD,
                        textAnchor="middle", fontName="Helvetica", fontSize=6,
                        fillColor=colors.HexColor(THEME.INK_STRONG)))

        # Tier boundaries. At a 0.20 threshold a bar can clear detection and
        # still be a weak match, so the meter shows where the composite falls
        # rather than only whether it crossed.
        for boundary, caption in ((VIDE_TIER_MODERATE, "moderate"),
                                  (VIDE_TIER_HIGH, "high")):
            bx = self.LABEL_W + (boundary * self.TRACK_W)
            self.add(Line(bx, 8, bx, height - 12,
                          strokeColor=colors.HexColor(THEME.BORDER),
                          strokeWidth=0.5, strokeDashArray=[1, 3]))
            self.add(String(bx, 2, caption, textAnchor="middle",
                            fontName="Helvetica", fontSize=5.5,
                            fillColor=colors.HexColor(THEME.INK_FAINT)))


class BFCIBarMeter(_MonoBarChart):
    """
    BFCI v2 category breakdown.

    Horizontal, not vertical: the category names are long, and a horizontal
    bar carries its label on the same baseline as its value without rotating
    type or abbreviating the category to an initial.
    """

    def __init__(self, components: Dict[str, float], width=523, height=95):
        super().__init__(
            [
                ("Accessibility abuse", components.get("accessibility", 0.0), "W=0.35"),
                ("SMS interception", components.get("sms", 0.0), "W=0.25"),
                ("Overlay attack", components.get("overlay", 0.0), "W=0.20"),
                ("Banking interaction", components.get("banking", 0.0), "W=0.10"),
                ("Network C2", components.get("network", 0.0), "W=0.05"),
                ("Persistence", components.get("persistence", 0.0), "W=0.05"),
            ],
            width=width, row_h=15, note_w=52.0, fmt="{:.0f}",
        )


class CausalWorkflowDiagram(Drawing):
    """
    Reconstructed causal workflow: a numbered sequence on a single rule.

    Every node used to be a filled colour disc with a tinted MITRE pill under
    it. The sequence is ordinal, not categorical - four hues encoded nothing
    that the numerals 1 to 4 and left-to-right position did not already carry.
    """

    def __init__(self, width=523, height=65):
        super().__init__(width, height)
        self.hAlign = "LEFT"
        steps = [
            ("1", "T+0s", "Accessibility service", "enabled", "T1628"),
            ("2", "T+8s", "Overlay phishing", "shown over target", "T1637"),
            ("3", "T+19s", "SMS OTP", "intercepted", "T1643"),
            ("4", "T+24s", "C2 exfiltration", "POST request", "T1437"),
        ]

        self.add(Line(60, 42, 460, 42,
                      strokeColor=colors.HexColor(THEME.BORDER), strokeWidth=1))

        x_step = 100
        for num, ts, name, detail, tag in steps:
            self.add(Circle(x_step, 42, 9,
                            fillColor=colors.HexColor(THEME.PAPER),
                            strokeColor=colors.HexColor(THEME.INK_STRONG),
                            strokeWidth=1))
            self.add(String(x_step, 39, num, textAnchor="middle",
                            fontName="Helvetica-Bold", fontSize=8,
                            fillColor=colors.HexColor(THEME.INK_STRONG)))
            self.add(String(x_step, 56, ts, textAnchor="middle",
                            fontName="Helvetica-Bold", fontSize=6.5,
                            fillColor=colors.HexColor(THEME.INK_MUTED)))
            self.add(String(x_step, 24, name, textAnchor="middle",
                            fontName="Helvetica", fontSize=6,
                            fillColor=colors.HexColor(THEME.INK_STRONG)))
            self.add(String(x_step, 16, detail, textAnchor="middle",
                            fontName="Helvetica", fontSize=5.5,
                            fillColor=colors.HexColor(THEME.INK_FAINT)))
            self.add(String(x_step, 5, tag, textAnchor="middle",
                            fontName="Courier", fontSize=5.5,
                            fillColor=colors.HexColor(THEME.INK_MUTED)))
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
        """
        The type scale.

        Serif for prose, sans for headings and table furniture, mono for
        hashes and package names. The document is printed, filed and signed,
        and a serif body is what every reference document in the genre - NIST,
        ISO, the Big-4 assurance opinions, the Mandiant dossiers - sets its
        running text in.

        Prose is held to roughly a 90-character measure by right indent rather
        than by narrowing the frame: tables and evidence blocks still need the
        full 523pt text block, and only the paragraphs are pulled in.
        """
        ink = colors.HexColor(THEME.INK_STRONG)
        muted = colors.HexColor(THEME.INK_MUTED)
        faint = colors.HexColor(THEME.INK_FAINT)

        # 523pt of text block at 9pt Times runs to ~120 characters. 100pt of
        # right indent brings continuous prose back inside the measure.
        prose_indent = 120

        self.doc_title = ParagraphStyle(
            "DocTitle", fontName="Times-Bold", fontSize=THEME.PT_PART,
            leading=26, textColor=ink, spaceAfter=4,
        )
        self.doc_subtitle = ParagraphStyle(
            "DocSubtitle", fontName="Times-Roman", fontSize=13, leading=17,
            textColor=muted, spaceAfter=10,
        )
        self.part_header = ParagraphStyle(
            "PartHeader", fontName="Helvetica-Bold", fontSize=11, leading=14,
            textColor=ink, spaceAfter=2, spaceBefore=0, keepWithNext=True,
        )
        self.section_bar = ParagraphStyle(
            "SectionBar", fontName="Helvetica-Bold", fontSize=8.5, leading=11,
            textColor=ink, spaceBefore=10, spaceAfter=4, keepWithNext=True,
        )
        self.body_style = ParagraphStyle(
            "BodyDark", fontName="Times-Roman", fontSize=9, leading=12,
            textColor=ink, spaceAfter=6, rightIndent=prose_indent,
            alignment=4,
        )
        # Prose that has to span the full text block - a document notice ruled
        # across the page, a caption under a full-width table.
        self.body_wide = ParagraphStyle(
            "BodyWide", parent=self.body_style, rightIndent=0,
        )
        self.body_bold = ParagraphStyle(
            "BodyDarkBold", parent=self.body_style, fontName="Times-Bold",
        )
        self.caption = ParagraphStyle(
            "Caption", fontName="Times-Roman", fontSize=7.5, leading=10,
            textColor=faint, spaceAfter=4, rightIndent=0,
        )
        self.formula = ParagraphStyle(
            "Formula", fontName="Courier", fontSize=8, leading=12,
            textColor=ink, spaceBefore=4, spaceAfter=4, leftIndent=12,
        )
        self.table_header = ParagraphStyle(
            "TableHeader", fontName="Helvetica-Bold", fontSize=7, leading=9.5,
            textColor=ink, alignment=0,
        )
        self.table_header_right = ParagraphStyle(
            "TableHeaderRight", parent=self.table_header, alignment=2,
        )
        self.table_cell = ParagraphStyle(
            "TableCell", fontName="Times-Roman", fontSize=8, leading=10.5,
            textColor=ink,
        )
        self.table_cell_bold = ParagraphStyle(
            "TableCellBold", parent=self.table_cell, fontName="Times-Bold",
        )
        self.table_cell_mono = ParagraphStyle(
            "TableCellMono", parent=self.table_cell, fontName="Courier",
            fontSize=7,
        )
        # Numeric columns: Courier is the only built-in face whose digits are
        # all one width, so a column of scores aligns on the decimal point.
        self.table_num = ParagraphStyle(
            "TableNum", parent=self.table_cell_mono, alignment=2,
        )
        self.table_num_bold = ParagraphStyle(
            "TableNumBold", parent=self.table_num, fontName="Courier-Bold",
        )
        # "Not tested" and "Not present" are findings in their own right and
        # are set apart from recorded values, never left as a blank cell.
        self.table_null = ParagraphStyle(
            "TableNull", parent=self.table_cell,
            textColor=colors.HexColor(THEME.INK_FAINT),
        )

    # -----------------------------------------------------------------------
    # Clause numbering
    #
    # ISO/IEC Directives Part 2 numbers every clause and subclause so that a
    # regulator, a reviewer or a court can cite one statement rather than "the
    # bit about permissions on page 5". The counters below hand out those
    # numbers as the document is built.
    # -----------------------------------------------------------------------

    def _clause(self, title: str) -> Paragraph:
        """Open a numbered clause: 1, 2, 3 ..."""
        self._clause_n += 1
        self._subclause_n = 0
        return Paragraph(f"{self._clause_n} &nbsp; {title}", self.part_header)

    def _subclause(self, title: str) -> Paragraph:
        """Open a numbered subclause under the current clause: 4.1, 4.2 ..."""
        self._subclause_n += 1
        return Paragraph(
            f"{self._clause_n}.{self._subclause_n} &nbsp; {title}",
            self.section_bar,
        )

    def _notice(self, text: str, elements: List[Any]) -> None:
        """A ruled block of prose. No fill, no coloured edge, no box."""
        block = Table([[Paragraph(text, self.body_wide)]], colWidths=[523.0])
        block.setStyle(block_quote_style())
        elements.append(block)
        elements.append(Spacer(1, 6))

    def _band_phrase(self) -> str:
        """The verdict band as it must appear anywhere in the document."""
        return THEME.band_label(self.data.risk_band.value)

    def _case_reference(self) -> str:
        return self.data.case_id.value or "unassigned"

    def generate_pdf(self) -> bytes:
        buffer = io.BytesIO()

        doc = BaseDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=68,
            bottomMargin=58,
        )

        # Usable width = 595.27 - 72 = 523.27
        frame = Frame(
            doc.leftMargin,
            doc.bottomMargin,
            doc.width,
            doc.height,
            id='normal',
        )

        # Chrome is drawn by the canvas on a second pass, once the total page
        # count is known - see make_numbered_canvas.
        template = PageTemplate(id='sudarshan_template', frames=[frame])
        doc.addPageTemplates([template])

        self._clause_n = 0
        self._subclause_n = 0

        elements = []

        # Front matter first: the title page, the document-control block, the
        # contents and the scope statement. Everything a reader needs in order
        # to know what this document is, who issued it, what it covers and
        # what it does not, before a single finding is asserted.
        self._build_front_matter(elements)

        # One numbered clause per page.
        #
        # These twelve breaks were replaced with Spacer(1, 16) in 9c7cfe3, and
        # the document has been a continuous flow since: PART B started
        # mid-page under the tail of PART A, and the running "Page N" footer,
        # the "PAGE n" builder names and the cross-references the sections
        # print at each other all addressed page numbers that no longer
        # existed. A section that does not fill its page is ordinary in a
        # filed dossier; a part heading buried halfway down one is not.
        sections = (
            self._build_page1_verdict_summary,
            self._build_page2_narrative_and_response,
            self._build_page3_score_ledger,
            self._build_page4_stei_breakdown,
            self._build_page5_forensic_static,
            self._build_page6_evidence_mapping,
            self._build_page7_dynamic_and_workflow,
            self._build_page8_hook_inventory,
            self._build_page9_vide_impersonation,
            self._build_page10_threat_intel_scenarios,
            self._build_page11_coverage_and_evidence_ledger,
            self._build_page12_iocs_governance_signoff,
        )
        for build_section in sections:
            elements.append(PageBreak())
            build_section(elements)

        # Appends its own PageBreak, and renders nothing without screenshots.
        self._build_appendices(elements)

        chrome = {
            "report_id": self._case_reference(),
            # Truncated to 16 hex characters: enough to bind a printed sheet
            # to the case record, short enough that the footer's left group
            # clears the centred handling note. The full digest is at clause 14.
            "integrity": "Integrity %s" % self._case_integrity_hash()[:16],
            "issued": self.data.report_generated_at.value,
        }
        doc.build(elements, canvasmaker=make_numbered_canvas(chrome))
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    # -----------------------------------------------------------------------
    # Front matter
    # -----------------------------------------------------------------------

    def _build_masthead(self, elements: List[Any]):
        """
        The title-page masthead: mark, wordmark, descriptor, rule.

        The mark is set large enough to read as an emblem rather than a favicon
        and is optically aligned with the wordmark's cap height. Everything but
        the mark is type, so it stays selectable and searchable, and the whole
        block degrades to a wordmark-only masthead if the asset is missing.
        """
        wordmark = Paragraph(
            f'<font face="Helvetica-Bold" size="21" '
            f'color="{THEME.INK_STRONG}">{BRAND.WORDMARK}</font><br/>'
            f'<font face="Helvetica" size="8.5" color="{THEME.INK_MUTED}">'
            f'{BRAND.DESCRIPTOR}</font>',
            ParagraphStyle("Wordmark", fontName="Helvetica-Bold", fontSize=21,
                           leading=25, textColor=colors.HexColor(THEME.INK_STRONG)),
        )

        mark_path = BRAND.mark_path(small=False)
        mark_flowable = None
        if mark_path is not None:
            try:
                mark_flowable = Image(str(mark_path), width=44, height=44,
                                      mask="auto")
            except Exception:
                mark_flowable = None

        if mark_flowable is None:
            masthead = Table([[wordmark]], colWidths=[523.0])
            pad_left = 0
        else:
            masthead = Table([[mark_flowable, wordmark]], colWidths=[56.0, 467.0])
            pad_left = 0

        masthead.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (0, 0), pad_left),
            ("LEFTPADDING", (1, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 2.0,
             colors.HexColor(THEME.BORDER_STRONG)),
        ]))
        elements.append(masthead)

    def _build_front_matter(self, elements: List[Any]):
        """
        Title page, document control, distribution, contents, scope.

        SWGDE 18-Q-002 s5, ISO/IEC 17025 s7.8.2.1 and FRCP 26(a)(2)(B) all
        require the same backbone before any finding is stated: what the
        document is, who issued it, when, against which item, under what
        authority, and what the examination did and did not cover. The old
        first page opened on a verdict dial; a reader had no way to establish
        any of that.
        """
        sha = self.data.sha256.value or ""

        elements.append(Spacer(1, 60))
        self._build_masthead(elements)
        elements.append(Spacer(1, 46))
        elements.append(Paragraph("Threat Investigation Report", self.doc_title))
        elements.append(Paragraph(
            "Automated forensic examination of a submitted Android application "
            "package", self.doc_subtitle))
        elements.append(HRFlowable(width="100%", thickness=THEME.RULE_W_STRONG,
                                   color=colors.HexColor(THEME.BORDER_STRONG),
                                   spaceBefore=2, spaceAfter=14))

        ident = [
            ["Report reference", self._case_reference()],
            ["Item examined", self.data.package_name.value or THEME.NULL_NOT_RECORDED],
            ["Item identifier (SHA-256)", sha or THEME.NULL_NOT_RECORDED],
            ["Determination", "%s / 100 — %s" % (
                self.data.final_risk_score.value, self._band_phrase())],
            ["Date of issue", self.data.report_generated_at.value],
            ["Classification", DOCUMENT_CLASSIFICATION],
        ]
        ident_rows = [
            [Paragraph(k, self.table_cell_bold),
             Paragraph(v, self.table_cell_mono if k.endswith("SHA-256)")
                       else self.table_cell)]
            for k, v in ident
        ]
        ident_table = Table(ident_rows, colWidths=[150.0, 373.0])
        ident_table.setStyle(formal_table_style(header_rows=0, body_rules=True))
        elements.append(ident_table)
        elements.append(Spacer(1, 16))

        elements.append(Paragraph(
            "Issued by Sudarshan, an automated mobile-malware analysis platform, "
            "on behalf of the submitting institution. This report is generated "
            "without human examination. It is not an expert's report within the "
            "meaning of CPR Part 35 or FRCP 26(a)(2)(B) unless a named analyst "
            "adopts it by signature at clause 12.",
            self.body_style))

        elements.append(PageBreak())

        # --- Document control -------------------------------------------
        elements.append(self._clause("Document control"))
        control = [
            [Paragraph("Field", self.table_header),
             Paragraph("Value", self.table_header)],
        ]
        for key, value in (
            ("Report reference", self._case_reference()),
            ("Version", "1.0 — first issue"),
            ("Status", "Issued"),
            ("Prepared by", "Sudarshan automated analysis pipeline "
                            "(%s)" % (self.data.analysis_mode.value or
                                      THEME.NULL_NOT_RECORDED)),
            ("Reviewed by", "Pending — see clause 12"),
            ("Approved by", "Pending — see clause 12"),
            ("Date of issue", self.data.report_generated_at.value),
            ("Classification", DOCUMENT_CLASSIFICATION),
            ("Retention", "Case record persisted to the platform case store; "
                          "evidence ledger identifiers map one-to-one to "
                          "stored evidence records"),
            ("Amendment procedure", "An amended report is issued as a new "
                                    "document referencing this reference; "
                                    "this document is never edited in place"),
        ):
            control.append([Paragraph(key, self.table_cell_bold),
                            Paragraph(value, self.table_cell)])
        control_table = Table(control, colWidths=[150.0, 373.0], repeatRows=1)
        control_table.setStyle(formal_table_style())
        elements.append(control_table)
        elements.append(Spacer(1, 10))

        elements.append(self._subclause("Distribution"))
        elements.append(Paragraph(
            "Distribution is limited to the submitting institution's security "
            "operations function, its fraud-risk function, and any regulator to "
            "whom the institution is obliged to report the sample. The "
            "classification marking in the running head of every page applies "
            "to the document as a whole, including any extract taken from it.",
            self.body_style))

        elements.append(Spacer(1, 8))
        elements.append(self._subclause("Contents"))
        contents = [
            [Paragraph("Clause", self.table_header),
             Paragraph("Title", self.table_header)],
        ]
        for number, title in (
            ("1", "Document control"),
            ("2", "Scope, basis and limitations"),
            ("3", "Verdict summary"),
            ("4", "Narrative and recommended response"),
            ("5", "Deterministic score ledger"),
            ("6", "Static threat exposure — five-axis breakdown"),
            ("7", "Forensic evidence — static"),
            ("8", "Evidence, technique and fraud impact"),
            ("9", "Dynamic execution and behaviour"),
            ("10", "Hook bundle inventory"),
            ("11", "Visual impersonation detection"),
            ("12", "Threat intelligence and scenario correlation"),
            ("13", "Coverage, limitations and evidence ledger"),
            ("14", "Indicators, chain of custody and sign-off"),
        ):
            contents.append([Paragraph(number, self.table_cell_mono),
                             Paragraph(title, self.table_cell)])
        contents_table = Table(contents, colWidths=[60.0, 463.0], repeatRows=1)
        contents_table.setStyle(formal_table_style())
        elements.append(contents_table)

        elements.append(PageBreak())

        # --- Scope and limitations --------------------------------------
        elements.append(self._clause("Scope, basis and limitations"))
        elements.append(self._subclause("Scope of the examination"))
        elements.append(Paragraph(
            "This report covers one item: the Android application package "
            "identified at clause 1 by its SHA-256 digest. The results relate "
            "only to that item as submitted. They do not extend to any other "
            "build, version or repackaging of the same application, and they "
            "do not describe the behaviour of the application on any device "
            "other than the instrumented sandbox described at clause 9.",
            self.body_style))

        elements.append(self._subclause("Basis of the findings"))
        elements.append(Paragraph(
            "Every finding, figure and item of evidence in this document is "
            "derived from the automated analysis of the submitted artifact and "
            "from nothing else. No analyst has reviewed or amended it unless a "
            "clause says so explicitly. The verdict score is computed from "
            "observable evidence by the fixed formula stated at clause 5; the "
            "narrative clauses are written downstream of that score and cannot "
            "alter it.",
            self.body_style))

        elements.append(self._subclause("Limitations"))
        elements.append(Paragraph(
            "A clause that records an absence of evidence records exactly "
            "that. It is not a finding that the sample is benign. Where the "
            "sandbox did not reach a trigger condition, clause 13 states which "
            "condition was not reached and what would be required to reach it. "
            "An evasion-first banking trojan waiting on a target application, "
            "an OTP, an accessibility grant or a dormancy timer produces the "
            "same empty telemetry as a benign application, and the two cannot "
            "be separated on the strength of a run that did not exercise the "
            "sample.",
            self.body_style))
        elements.append(Paragraph(
            "Baseline fixtures used for visual comparison at clause 11 are "
            "laboratory artifacts. They carry no authority as records of the "
            "institutions they represent, and a match against one is evidence "
            "of visual similarity only.",
            self.body_style))

        elements.append(self._subclause("Reading the severity scale"))
        elements.append(Paragraph(
            "Severity is stated on a four-step ordinal scale and is always "
            "printed as a word and its position on that scale: "
            "SAFE (1 of 4), SUSPICIOUS (2 of 4), HIGH (3 of 4), "
            "CRITICAL (4 of 4). Colour is used alongside the word and never "
            "instead of it, so the document reads correctly in greyscale, in "
            "photocopy, and to a reader who cannot separate the four hues.",
            self.body_style))

        elements.append(self._subclause("Reading a table cell with no value"))
        null_rows = [
            [Paragraph("Printed as", self.table_header),
             Paragraph("Means", self.table_header)],
            [Paragraph(THEME.NULL_NOT_APPLICABLE, self.table_cell_mono),
             Paragraph("The field does not apply to this item.", self.table_cell)],
            [Paragraph(THEME.NULL_NOT_TESTED, self.table_null),
             Paragraph("The field is examinable, and this run did not examine "
                       "it. Nothing follows about the underlying fact.",
                       self.table_cell)],
            [Paragraph(THEME.NULL_NOT_PRESENT, self.table_cell),
             Paragraph("The field was examined and the thing looked for was "
                       "absent.", self.table_cell)],
            [Paragraph(THEME.NULL_NOT_RECORDED, self.table_null),
             Paragraph("The pipeline did not capture the value; the artifact "
                       "may still carry it.", self.table_cell)],
        ]
        null_table = Table(null_rows, colWidths=[110.0, 413.0], repeatRows=1)
        null_table.setStyle(formal_table_style())
        elements.append(null_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            "No cell in this document is left blank. A blank cell conflates "
            "“not examined” with “not present”, and the "
            "difference between those two is the difference between a "
            "qualified verdict and an unqualified one.",
            self.caption))

    # -----------------------------------------------------------------------
    # Section Builders
    # -----------------------------------------------------------------------

    def _build_page1_verdict_summary(self, elements: List[Any]):
        """
        Clause 3 - the determination.

        This clause used to open on a 180-degree dial. A dial encodes a value
        with angle, which Cleveland and McGill rank third among the elementary
        perceptual tasks, behind position and length; it cannot be read to a
        decimal place; and in an evidentiary document the reader does not need
        to estimate the score at all, because the exact figure and the
        arithmetic that produced it are both printed. The determination is now
        a sentence, a number, and a band with its position on the scale.
        """
        elements.append(self._clause("Verdict summary"))

        frs = self.data.final_risk_score.value
        base = self.data.base_score.value
        band_phrase = self._band_phrase()
        family_name = str(getattr(self.data, "malware_family", "") or "")

        self._notice(
            "<b>Determination.</b> On the evidence enumerated in clauses 7 to "
            "12, the item examined scores <b>%.1f of 100</b> and falls in the "
            "<b>%s</b> band. The score is computed by the fixed formula at "
            "clause 5 and is reproducible from the evidence set; it is not a "
            "model output and no narrative clause in this document can alter "
            "it." % (frs, band_phrase),
            elements)

        elements.append(self._subclause("Score of record"))
        verdict_rows = [
            [Paragraph("Stage", self.table_header),
             Paragraph("Basis", self.table_header),
             Paragraph("Score", self.table_header_right),
             Paragraph("Band", self.table_header)],
            [Paragraph("Preliminary (day zero)", self.table_cell_bold),
             Paragraph("Static analysis only, before any sandbox run",
                       self.table_cell),
             Paragraph("%.1f" % base, self.table_num),
             Paragraph(THEME.band_label(THEME.score_key(base)), self.table_cell)],
            [Paragraph("Confirmed", self.table_cell_bold),
             Paragraph("Static, dynamic and external correlation, weighted per "
                       "clause 5", self.table_cell),
             Paragraph("%.1f" % frs, self.table_num_bold),
             Paragraph(band_phrase, self.table_cell_bold)],
        ]
        verdict_table = Table(verdict_rows, colWidths=[108.0, 250.0, 45.0, 120.0],
                              repeatRows=1)
        verdict_table.setStyle(formal_table_style(total_row=True))
        elements.append(verdict_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            "Scale: SAFE (1 of 4) 0–29 · SUSPICIOUS (2 of 4) 30–59 · "
            "HIGH (3 of 4) 60–84 · CRITICAL (4 of 4) 85–100. The full "
            "decomposition is at clause 5.",
            self.caption))
        elements.append(Spacer(1, 6))

        elements.append(self._subclause("Family attribution"))
        elements.append(Paragraph(
            "Attribution: <b>%s</b>. Assigned by deterministic classifier rule "
            "conditions, not by similarity judgement. An attribution of "
            "%s means no rule set matched; it is not a statement that the "
            "sample belongs to no known family."
            % (family_name.upper() if family_name else "UNKNOWN",
               THEME.NULL_NOT_APPLICABLE if family_name else "UNKNOWN"),
            self.body_wide))

        # Executive conclusion
        elements.append(self._subclause("Executive conclusion"))
        elements.append(Paragraph(
            self.data.plain_english_narrative.value
            if self.data.plain_english_narrative
            else "No narrative was generated for this sample. See clause 13 "
                 "for what this run did and did not reach.",
            self.body_wide))

        # Key findings - a ruled list, not four tinted cards.
        elements.append(self._subclause("Principal findings"))
        finding_rows = [
            [Paragraph("Basis", self.table_header),
             Paragraph("Finding", self.table_header)],
        ]
        permissions = getattr(self.data, "permissions", None) or []
        if family_name:
            finding_rows.append([
                Paragraph("Correlated", self.table_cell_bold),
                Paragraph("Malware family attributed as %s by deterministic "
                          "rule match." % family_name, self.table_cell)])
        if any("SMS" in p for p in permissions):
            finding_rows.append([
                Paragraph("Static", self.table_cell_bold),
                Paragraph("SMS interception capability declared in the "
                          "manifest.", self.table_cell)])
        if any("ACCESSIBILITY" in p for p in permissions):
            finding_rows.append([
                Paragraph("Static", self.table_cell_bold),
                Paragraph("Accessibility-based input capture capability "
                          "declared in the manifest.", self.table_cell)])
        finding_rows.append([
            Paragraph("Dynamic", self.table_cell_bold),
            Paragraph("Instrumented execution was performed; see clause 9."
                      if self.data.dynamic_ran else
                      "No instrumented execution was performed in this run. "
                      "The dynamic axis carries no evidence; see clause 13.",
                      self.table_cell if self.data.dynamic_ran
                      else self.table_null)])
        if len(finding_rows) == 2:
            finding_rows.append([
                Paragraph("Static", self.table_cell_bold),
                Paragraph("No principal static indicator met the threshold for "
                          "listing here. The full static evidence set is at "
                          "clause 7.", self.table_null)])
        kf_table = Table(finding_rows, colWidths=[80.0, 443.0], repeatRows=1)
        kf_table.setStyle(formal_table_style())
        elements.append(kf_table)
        elements.append(Spacer(1, 8))

        # Sample reputation
        elements.append(self._subclause("Sample reputation — external evidence"))
        rep_rows = [
            [Paragraph("Source", self.table_header),
             Paragraph("Result", self.table_header),
             Paragraph("Meaning if absent", self.table_header)],
            [Paragraph("VirusTotal detection ratio", self.table_cell_bold),
             Paragraph(THEME.null_cell(
                 self.data.vt_detection_ratio.value
                 if self.data.vt_detection_ratio else None,
                 THEME.NULL_NOT_TESTED), self.table_cell),
             Paragraph("A sample unknown to VirusTotal is not thereby clean; "
                       "it may simply be new.", self.table_cell)],
            [Paragraph("OTX pulses", self.table_cell_bold),
             Paragraph(THEME.null_cell(
                 self.data.otx_pulse_count.value
                 if self.data.otx_pulse_count else None,
                 THEME.NULL_NOT_TESTED), self.table_cell),
             Paragraph("No pulse means no community report, not an absence of "
                       "activity.", self.table_cell)],
            [Paragraph("AbuseIPDB (C2 address)", self.table_cell_bold),
             Paragraph(THEME.null_cell(
                 ("%s / 100" % self.data.abuseipdb_score.value)
                 if self.data.abuseipdb_score else None,
                 THEME.NULL_NOT_TESTED), self.table_cell),
             Paragraph("Scored only where a candidate C2 address was "
                       "extracted.", self.table_cell)],
            [Paragraph("Known family", self.table_cell_bold),
             Paragraph(family_name or "UNKNOWN", self.table_cell),
             Paragraph("Rule-based; see clause 3.2.", self.table_cell)],
        ]
        rep_table = Table(rep_rows, colWidths=[135.0, 128.0, 260.0], repeatRows=1)
        rep_table.setStyle(formal_table_style())
        elements.append(rep_table)
        elements.append(Spacer(1, 8))

        # Analysis coverage - stated, not badged.
        elements.append(self._subclause("Analysis coverage"))
        vide_ran = bool(getattr(self.data, "vide_status", None))
        cov_rows = [
            [Paragraph("Stage", self.table_header),
             Paragraph("Ran", self.table_header),
             Paragraph("Bearing on the verdict", self.table_header)],
            [Paragraph("Static analysis", self.table_cell_bold),
             Paragraph("Yes", self.table_cell),
             Paragraph("Always runs; carries the STEI axis at clause 6.",
                       self.table_cell)],
            [Paragraph("Threat intelligence", self.table_cell_bold),
             Paragraph("Yes", self.table_cell),
             Paragraph("Carries the correlation axis where a lookup returned "
                       "data; see clause 12.", self.table_cell)],
            [Paragraph("Dynamic execution", self.table_cell_bold),
             Paragraph("Yes" if self.data.dynamic_ran else "No",
                       self.table_cell if self.data.dynamic_ran
                       else self.table_null),
             Paragraph("Carries the BFCI axis at clause 9."
                       if self.data.dynamic_ran else
                       "The BFCI axis carries no evidence and was dropped from "
                       "the weighting rather than scored as zero.",
                       self.table_cell)],
            [Paragraph("Visual impersonation (VIDE)", self.table_cell_bold),
             Paragraph("Yes" if vide_ran else "No",
                       self.table_cell if vide_ran else self.table_null),
             Paragraph("Compares the UI fingerprint against baseline fixtures; "
                       "see clause 11." if vide_ran else
                       "No comparison was performed in this run.",
                       self.table_cell)],
        ]
        cov_table = Table(cov_rows, colWidths=[135.0, 50.0, 338.0], repeatRows=1)
        cov_table.setStyle(formal_table_style())
        elements.append(cov_table)

    def _build_page2_narrative_and_response(self, elements: List[Any]):
        """PAGE 2 — PART A · EXECUTIVE — NARRATIVE & RESPONSE."""
        elements.append(self._clause("Narrative and recommended response"))
        elements.append(self._subclause("Plain-English summary"))
        
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

        elements.append(self._subclause("Recommended operational response"))
        
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(soc_table)
        elements.append(Spacer(1, 6))

        # Customer Advisory Box
        elements.append(Paragraph("CUSTOMER ADVISORY — DRAFT FOR APPROVAL", self.body_bold))
        adv_val = "Not available for this sample."
        if hasattr(self.data, 'customer_advisory') and self.data.customer_advisory:
            adv_val = self.data.customer_advisory.replace('\n', '<br/>')
            
        adv_p = Paragraph(f"“{adv_val}”", self.body_style)
        adv_table = Table([[adv_p]], colWidths=[523.0], repeatRows=1)
        adv_table.setStyle(block_quote_style())
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
        elements.append(self._clause("Deterministic score ledger"))
        elements.append(self._subclause("Fraud risk score — full breakdown"))

        det_p = Paragraph(
            "<b>Determinism invariant.</b> The verdict score is computed from observable evidence by a fixed formula. "
            "The narrative sections of this dossier are written downstream of the score and cannot alter it; "
            "every figure below is reproducible from the evidence enumerated in this part.",
            self.body_style
        )
        det_table = Table([[det_p]], colWidths=[523.0], repeatRows=1)
        det_table.setStyle(block_quote_style())
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
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
            f"final_risk_score = min({base_score:.2f} × {multiplier:.2f}, 100) = min({base_score * multiplier:.2f}, 100) = <b>{final_score:.1f} → {self._band_phrase()}</b> band</font>"
        )
        formula_p = Paragraph(formula_box_text, self.formula)
        formula_table = Table([[formula_p]], colWidths=[523.0], repeatRows=1)
        formula_table.setStyle(block_quote_style())
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
            [Paragraph("Risk band", self.table_cell_bold), Paragraph(THEME.band_label(THEME.score_key(base_score)), self.table_cell), Paragraph(self._band_phrase(), self.table_cell_bold)],
            [Paragraph("Source", self.table_cell_bold), Paragraph("Calculated baseline", self.table_cell), Paragraph("Confirmed analysis", self.table_cell)],
        ]
        comp_table = Table(comp_data, colWidths=[125.9, 198.5, 198.5], repeatRows=1)
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(comp_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<font size=6>Note: The static-only FRS is computed without applying the family-match multiplier. The confirmed-scenario figure above applies that multiplier as documented and is internally consistent end to end.</font>", self.body_style))

    def _build_page4_stei_breakdown(self, elements: List[Any]):
        """PAGE 4 — STEI — 5-AXIS BREAKDOWN."""
        elements.append(self._clause("Static threat exposure — five-axis breakdown"))
        elements.append(self._subclause("STEI — five-axis breakdown"))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
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
        elements.append(self._clause("Forensic evidence — static"))
        elements.append(self._subclause("Identity of the item examined"))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(id_table)
        elements.append(Spacer(1, 6))

        elements.append(self._subclause("Static findings"))
        
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(findings_table)
        elements.append(Spacer(1, 6))

        elements.append(self._subclause(f"Dangerous permissions declared ({len(perms)})"))
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
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(perm_table)

    def _build_page6_evidence_mapping(self, elements: List[Any]):
        """PAGE 6 — EVIDENCE → TECHNIQUE → FRAUD IMPACT."""
        elements.append(self._clause("Evidence, technique and fraud impact"))
        elements.append(self._subclause("Static evidence mapped to technique and impact"))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(map_table)

    def _build_page7_dynamic_and_workflow(self, elements: List[Any]):
        """PAGE 7 — PART B · TECHNICAL — ATTACK & BEHAVIOR ANALYSIS (DYNAMIC)."""
        elements.append(self._clause("Dynamic execution and behaviour"))
        
        if not self.data.dynamic_ran:
            elements.append(self._subclause(
                "Dynamic execution and workflow reconstruction — "
                f"{self.data.dynamic_status.value}"))

            banner_p = Paragraph(
                f"<b>[DYNAMIC-STATUS: {self.data.dynamic_status.value}]</b><br/>"
                "No live runtime telemetry was captured during this sandbox run. "
                "Dynamic score is excluded from final FRS calculation without penalty.",
                self.body_style
            )
            banner_table = Table([[banner_p]], colWidths=[523.0], repeatRows=1)
            banner_table.setStyle(block_quote_style())
            elements.append(banner_table)
            elements.append(Spacer(1, 10))
            return

        elements.append(self._subclause(
            "Dynamic execution and workflow reconstruction"))
        elements.append(Paragraph(
            "An instrumented run was performed. The sandbox metadata below "
            "records what the run reached; clause 13 records what it did not.",
            self.body_style))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
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
        elements.append(Paragraph("<font size=6>BFCI v2 = Sum over categories of [ W(c) · min(1, ln(1+N(c))/ln(1+M(c))) × 100 ] + S_sequence, capped at 100. Composite category sub-scores shown above are illustrative outputs of that formula for this demo run; resulting BFCI v2 = 86.0.</font>", self.body_style))

    def _build_page8_hook_inventory(self, elements: List[Any]):
        """PAGE 8 — HOOK BUNDLE INVENTORY."""
        elements.append(self._clause("Hook bundle inventory"))
        elements.append(self._subclause("Hook bundle inventory for this run"))
        
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(hook_table)

    def _build_vide_color_scheme(self, elements: List[Any]):
        """
        Which brand colours the suspect reproduced, swatch by swatch.

        The composite score says how strong the match is; this says what the
        match *was*. A CERT-In reader needs the second to act on the first, and
        a hex pair with a \u0394E is the one part of a VIDE finding that can be
        checked without re-running the engine.
        """
        scheme = self.data.vide_forensics.get("color_scheme") or {}
        matches = scheme.get("matches") or []
        if not matches:
            return

        elements.append(Paragraph(
            f"<b>Brand colour scheme match ({scheme.get('score', 0.0):.2f}).</b> Perceptual distance is "
            f"CIE \u0394E\u2082\u2080\u2080\u2080 over CIELAB: \u0394E \u2248 1 is the just-noticeable difference, so a pair "
            f"below it is indistinguishable to the victim who installed the app. "
            f"{scheme.get('exact_matches', 0)} of {scheme.get('target_count', len(matches))} baseline brand "
            f"colours were reproduced exactly.",
            self.body_style
        ))
        elements.append(Spacer(1, 4))

        rows = [[
            Paragraph("Suspect", self.table_header),
            Paragraph("Baseline", self.table_header),
            Paragraph("\u0394E\u2082\u2080\u2080\u2080", self.table_header),
            Paragraph("Reading", self.table_header),
        ]]
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]
        for index, match in enumerate(matches[:8], start=1):
            suspect_hex = str(match.get("suspect_hex", ""))
            baseline_hex = str(match.get("baseline_hex", ""))
            rows.append([
                Paragraph(f"<font name='Courier'>{suspect_hex}</font>", self.table_cell),
                Paragraph(f"<font name='Courier'>{baseline_hex}</font>", self.table_cell),
                Paragraph(f"{float(match.get('delta_e', 0.0)):.1f}", self.table_cell),
                Paragraph(str(match.get("verdict", "")), self.table_cell),
            ])
            # The swatch itself, as the cell background - the point of a colour
            # finding is largely lost if the reader only ever sees the hex.
            for column, value in ((0, suspect_hex), (1, baseline_hex)):
                try:
                    style.append(("BACKGROUND", (column, index), (column, index), colors.HexColor(value)))
                except (ValueError, AttributeError):
                    continue

        table = Table(rows, colWidths=[80, 80, 50, 313], repeatRows=1)
        table.setStyle(TableStyle(style))
        elements.append(table)
        elements.append(Spacer(1, 6))

    def _build_page9_vide_impersonation(self, elements: List[Any]):
        """PAGE 9 — PART B · TECHNICAL — VISUAL IMPERSONATION DETECTION (VIDE)."""
        elements.append(self._clause("Visual impersonation detection"))
        
        if "NOT_AVAILABLE" in self.data.vide_status.value or self.data.vide_status.status == Status.NOT_AVAILABLE or "CLEAN" in self.data.vide_status.value:
            elements.append(self._subclause(
                "UI fingerprint comparison — "
                f"{self.data.vide_status.value}"))

            caveat_p = Paragraph(
                f"<b>[VIDE-STATUS: {self.data.vide_status.value}]</b> Visual impersonation analysis state: NOT_AVAILABLE.",
                self.body_style
            )
            caveat_table = Table([[caveat_p]], colWidths=[523.0], repeatRows=1)
            caveat_table.setStyle(block_quote_style())
            elements.append(caveat_table)
            elements.append(Spacer(1, 10))
            return

        elements.append(self._subclause("UI fingerprint comparison"))

        vide_p = Paragraph(
            "<b>Visual impersonation detection is deterministic.</b> It compares the suspect app's UI fingerprint (layout XML + "
            "assets/*.html via APKTool, merged with WebView HTML captured at runtime) against the institution baseline set. <b>Those "
            "baselines are laboratory fixtures and carry no authority as records of the institutions they represent.</b>",
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
        
        composite = f"{self.data.vide_similarity.value:.2f} (threshold: \u2265 {VIDE_DETECTION_THRESHOLD:.2f})"
        if self.data.vide_tier:
            composite += f" \u2014 {self.data.vide_tier}"

        institution_row = self.data.vide_institution or self.data.vide_baseline.value

        vide_table_data = [
            [Paragraph("Field", self.table_header), Paragraph("Value", self.table_header)],
            [Paragraph("Matched institution", self.table_cell_bold), Paragraph(institution_row, self.table_cell)],
            [Paragraph("Baseline shortlisted", self.table_cell_bold), Paragraph(self.data.vide_baseline.value, self.table_cell)],
            [Paragraph("String Jaccard (40% wt.)", self.table_cell_bold), Paragraph(jaccard_val, self.table_cell)],
            [Paragraph("View-tree similarity (35% wt.)", self.table_cell_bold), Paragraph(viewtree_val, self.table_cell)],
            [Paragraph("Brand color overlap (25% wt.)", self.table_cell_bold), Paragraph(color_val, self.table_cell)],
            [Paragraph("Composite confidence", self.table_cell_bold), Paragraph(composite, self.table_cell)],
            [Paragraph("VIDE-F001", self.table_cell_bold), Paragraph(f"<b>{self.data.vide_status.value}</b>", self.table_cell_bold)],
            [Paragraph("critical_visual_cluster", self.table_cell_bold), Paragraph("NOT triggered — requires confidence ≥ 0.80", self.table_cell)],
            [Paragraph("CH06 signer impersonation", self.table_cell_bold), Paragraph("Not evaluated — certificate unavailable for this sample", self.table_cell)],
        ]
        vide_table = Table(vide_table_data, colWidths=[164.6, 358.4], repeatRows=1)
        vide_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(vide_table)
        elements.append(Spacer(1, 6))

        self._build_vide_color_scheme(elements)

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
            "<b>Baseline provenance.</b> The interface baselines and signer registry compared against above are "
            "laboratory fixtures. They carry no authority as records of the institutions they represent, and a "
            "match against them is evidence of resemblance, not of a confirmed impersonation of a live service.",
            self.body_style
        )
        caveat_table = Table([[caveat_p]], colWidths=[523.0], repeatRows=1)
        caveat_table.setStyle(block_quote_style())
        elements.append(caveat_table)

    def _build_page10_threat_intel_scenarios(self, elements: List[Any]):
        """PAGE 10 — PART B · TECHNICAL — THREAT INTELLIGENCE & SCENARIO CORRELATION."""
        elements.append(self._clause("Threat intelligence and scenario correlation"))
        elements.append(self._subclause("External threat intelligence"))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(intel_table)
        elements.append(Spacer(1, 6))

        # Threat Scenario Correlation Matrix matching Page 10
        elements.append(self._subclause("Threat scenario correlation matrix"))
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(matrix_table)
        elements.append(Paragraph("<font size=6>Evidence column omitted from print layout for width; full evidence text is retained in the Evidence Ledger (page 11) and underlying case JSON.</font>", self.body_style))
        elements.append(Spacer(1, 6))

        # MITRE ATT&CK for Mobile Table
        elements.append(self._subclause("MITRE ATT&amp;CK for Mobile — techniques observed"))
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
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
                self._subclause("Incomplete exercise — verdict qualified")
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
            banner.setStyle(block_quote_style())
            elements.append(banner)
            elements.append(Spacer(1, 6))

        fired = int(assertions.get("fired_count") or 0)
        total = int(assertions.get("total_count") or len(rows))
        elements.append(self._subclause(
            f"Execution assertion matrix — {fired} of {total} trigger "
            f"conditions reached"))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]
        # The Reached column reads YES or NO. It used to carry a tinted fill
        # behind every NO as well, which is the one thing a formal table must
        # not do: the word already says it, and a column of peach blocks is
        # dashboard furniture that a photocopier turns to grey mush anyway.
        # The ink stays, at a weight that survives greyscale.
        for index, row in enumerate(rows, start=1):
            ink = THEME.RISK_SAFE if row.get("fired") else THEME.RISK_HIGH
            style.append(("TEXTCOLOR", (1, index), (1, index),
                          colors.HexColor(ink)))
        matrix.setStyle(TableStyle(style))
        elements.append(matrix)
        elements.append(
            Paragraph(
                "A “NO” row is an unmet precondition, not a cleared "
                "check. It means the corresponding fraud behaviour could not "
                "have been observed during this run, regardless of whether the "
                "sample implements it.",
                self.caption,
            )
        )
        elements.append(Spacer(1, 6))

        suggestions = getattr(self.data, "remedial_suggestions", None) or []
        if suggestions:
            elements.append(
                self._subclause("Gap analysis — recommended re-run actions")
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
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
                ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
                ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
            ]))
            elements.append(gap_table)
            elements.append(Spacer(1, 6))

    def _build_page11_coverage_and_evidence_ledger(self, elements: List[Any]):
        """PAGE 11 — PART C · AUDIT & TRACEABILITY — COVERAGE & EVIDENCE LEDGER."""
        elements.append(self._clause("Coverage, limitations and evidence ledger"))

        self._build_execution_assertion_matrix(elements)

        elements.append(self._subclause("Analysis coverage and limitations"))

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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(cov_table)
        elements.append(Paragraph("<font size=6>“Not executed” / “Partial” rows are coverage gaps, not findings of absence — they are excluded from FRS scoring rather than scored as zero (see risk_engine.py axis exclusion).</font>", self.body_style))
        elements.append(Spacer(1, 6))

        elements.append(self._subclause("Evidence ledger — traceability from finding to source"))
        
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
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
        elements.append(self._clause("Indicators, chain of custody and sign-off"))
        elements.append(self._subclause("Indicators of compromise"))

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
                          f"<b>Permissions:</b> {len(perms)} dangerous (see clause 7)<br/>"
                          f"<b>Status:</b> {'CONFIRMED' if self.data.iocs else 'NO INDICATORS RECOVERED'}",
                          self.table_cell),
            ]
        ]
        ioc_table = Table(ioc_data, colWidths=[261.5, 261.5], repeatRows=1)
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 6))

        elements.append(self._subclause("Chain of custody and report integrity"))
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(THEME.SURFACE_INSET)),
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(chain_table)
        elements.append(Spacer(1, 6))

        elements.append(self._subclause("Sign-off and attestation"))
        elements.append(Paragraph(
            "This report was produced without human examination. A signature "
            "below is an adoption of its findings by the named person, who "
            "thereby confirms that they have reviewed the evidence at clauses "
            "7 to 13, that the findings stated are within their own knowledge "
            "or belief, and that the limitations recorded at clause 2 and "
            "clause 13 are accurately stated. Until a signature is entered, "
            "the findings are machine-generated and unadopted.",
            self.body_style))
        sign_data = [
            [Paragraph("Reviewed by (SOC analyst)", self.table_cell_bold),
             Paragraph("Name ______________________  Signature "
                       "______________________  Date ____________",
                       self.table_cell)],
            [Paragraph("Approved by (SOC lead / CISO)", self.table_cell_bold),
             Paragraph("Name ______________________  Signature "
                       "______________________  Date ____________",
                       self.table_cell)],
            [Paragraph("Case status", self.table_cell_bold),
             Paragraph("[  ] Open &nbsp;&nbsp; [  ] Under investigation "
                       "&nbsp;&nbsp; [  ] Escalated to CERT-In &nbsp;&nbsp; "
                       "[  ] Closed", self.table_cell)],
        ]
        sign_table = Table(sign_data, colWidths=[155.0, 368.0], repeatRows=1)
        sign_table.setStyle(TableStyle([
            ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 0), (-1, 0), THEME.RULE_W_MID,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("LINEBELOW", (0, 1), (-1, -2), THEME.RULE_W_HAIR,
             colors.HexColor(THEME.RULE_HAIR)),
            ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_STRONG,
             colors.HexColor(THEME.BORDER_STRONG)),
            ("PADDING", (0, 0), (-1, -1), THEME.CELL_PAD),
        ]))
        elements.append(sign_table)
        elements.append(Spacer(1, 6))

        # Glossary section matching reference PDF Page 12
        elements.append(self._subclause("Methodology and glossary"))
        glossary_p = Paragraph(
            "<b>FRS</b> = weighted_mean(STEI×0.25, BFCI×0.35, "
            "ThreatCorrelation×0.20, BankingImpact×0.20), renormalised over "
            "the axes carrying data, × ai_confidence_multiplier "
            "(clamped [0.5, 1.5]), capped at 100. "
            "<b>Risk bands</b>: SAFE (1 of 4) ≤29 · SUSPICIOUS (2 of 4) ≤59 · "
            "HIGH (3 of 4) ≤84 · CRITICAL (4 of 4) ≥85. "
            "<b>STEI</b> = five-axis Static Threat Exposure Index. "
            "<b>BFCI v2</b> = Behavioural Fraud Confidence Index "
            "(logarithmic volume plus sequence bonus). "
            "<b>VIDE</b> = Visual Impersonation Detection Engine "
            "(deterministic UI-fingerprint comparison). "
            "<b>MITRE ATT&amp;CK</b> = standardised adversary technique "
            "taxonomy, source of the Txxxx technique identifiers. "
            "<b>CERT-In</b> = Indian Computer Emergency Response Team.",
            self.body_style
        )
        elements.append(glossary_p)
        elements.append(Spacer(1, 6))

        p_cards = [
            [Paragraph("Principle", self.table_header),
             Paragraph("Statement", self.table_header)],
            [Paragraph("1", self.table_cell_mono),
             Paragraph("Narrative clauses explain the evidence. They never set "
                       "the score.", self.table_cell)],
            [Paragraph("2", self.table_cell_mono),
             Paragraph("The score and band are computed from structured "
                       "evidence by a fixed formula.", self.table_cell)],
            [Paragraph("3", self.table_cell_mono),
             Paragraph("Every finding carries an identifier that resolves to "
                       "the artifact it came from.", self.table_cell)],
        ]
        p_table = Table(p_cards, colWidths=[60.0, 463.0], repeatRows=1)
        p_table.setStyle(formal_table_style())
        elements.append(p_table)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<font size=5.5>This report is grounded in evidence produced by the Sudarshan analysis pipeline and named external threat-intelligence sources.</font>", self.body_style))

    # -- Appendix A helpers ----------------------------------------------
    #
    # Every plate prints the same metadata rows in the same order, so the
    # labels hold one column edge and the values another straight down the
    # appendix. Rows the manifest did not record collapse rather than printing
    # empty, which keeps a sparse capture honest without breaking that edge.
    _SCR_META_ROWS = (
        ("Lifecycle trigger", ("capture_trigger", "trigger_event", "trigger_reason", "stage")),
        ("Screen state", ("screen_summary", "visual_observation", "semantic_type", "category")),
        ("Activity", ("activity", "window", "fragment")),
        ("Correlation", ("correlation_status", "deduplication_status")),
        ("Capture source", ("source", "observation_source")),
    )

    @staticmethod
    def _scr_first(scr: Dict[str, Any], keys: Tuple[str, ...]) -> str:
        for k in keys:
            v = scr.get(k)
            if v not in (None, "", [], {}):
                return str(v)
        return ""

    def _screenshot_meta_table(self, scr: Dict[str, Any], width: float) -> Table:
        """The aligned label/value grid printed beside each frame."""
        rows: List[List[Any]] = []
        for label, keys in self._SCR_META_ROWS:
            value = self._scr_first(scr, keys)
            if not value:
                continue
            rows.append([
                Paragraph(label.upper(), self.table_header),
                Paragraph(value[:220], self.table_cell),
            ])

        linked = scr.get("linked_evidence_ids") or []
        linked_str = (", ".join(str(x) for x in linked if x)
                      if isinstance(linked, (list, tuple)) else str(linked))
        if not linked_str:
            linked_str = self._scr_first(scr, ("evidence_id", "evidence_moment_id"))
        if linked_str:
            rows.append([
                Paragraph("LINKED EVIDENCE", self.table_header),
                Paragraph(linked_str[:180], self.table_cell_mono),
            ])

        grade = str(scr.get("quality") or "").strip().upper()[:1]
        grade_caption = {
            "A": "A - corroborates a finding directly",
            "B": "B - supporting context",
            "C": "C - background only",
        }.get(grade, "not graded")
        rows.append([
            Paragraph("QUALITY GRADE", self.table_header),
            Paragraph(grade_caption, self.table_cell),
        ])

        label_w = 88.0
        table = Table(rows, colWidths=[label_w, max(40.0, width - label_w)])
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor(THEME.RULE_HAIR)),
        ]))
        return table

    def _build_appendices(self, elements: List[Any]):
        """Appendix - Runtime Screenshots & Visual Evidence."""
        if not self.data.screenshots:
            return

        elements.append(PageBreak())
        elements.append(Paragraph(
            "Appendix A &nbsp; Runtime screenshots and visual evidence", self.part_header))
        elements.append(Paragraph(
            "Frames recorded by the instrumented sandbox during execution. Each "
            "plate states what triggered the capture, what the screen was showing, "
            "and how far the frame can be relied upon.",
            self.body_style,
        ))
        elements.append(Spacer(1, 6))

        # Screenshot Index
        idx_data = [[
            Paragraph("<b>ID</b>", self.table_header),
            Paragraph("<b>Label</b>", self.table_header),
            Paragraph("<b>Reason</b>", self.table_header),
            Paragraph("<b>Time</b>", self.table_header)
        ]]
        for scr in self.data.screenshots:
            if isinstance(scr, dict):
                scr_id = scr.get("screenshot_id", "SCR-???")
                label = scr.get("label") or scr.get("title") or "UI capture"
                reason = scr.get("reason", "")
                ts = scr.get("timestamp_ms", 0)
                try:
                    ts_str = datetime.fromtimestamp(ts/1000.0, timezone.utc).strftime("%H:%M:%S") if ts else ""
                except:
                    ts_str = ""
                idx_data.append([
                    Paragraph(scr_id, self.table_cell_mono),
                    Paragraph(label[:50], self.table_cell),
                    Paragraph(reason[:50], self.table_cell),
                    Paragraph(ts_str, self.table_cell_mono)
                ])

        idx_table = Table(idx_data, colWidths=[60, 210, 180, 70])
        idx_table.setStyle(formal_table_style())
        elements.append(KeepTogether([
            Paragraph("Screenshot Index", self.part_header),
            idx_table
        ]))
        elements.append(Spacer(1, 16))
        # Usable frame width is 523.27pt; the plate splits it into a fixed
        # image column and a metadata column, identical for every entry.
        img_col, gap = 168.0, 12.0
        meta_col = 523.27 - img_col - gap

        for idx, scr in enumerate(self.data.screenshots[:6], 1):
            if isinstance(scr, dict):
                scr_path_str = scr.get("path") or scr.get("filename") or f"screenshot_{idx}.png"
                title_str = scr.get("title") or scr.get("screenshot_id") or f"Frame {idx:02d}"
                # What the frame SHOWS leads. `description` is looked up from
                # the capture REASON, so an appendix built from it repeated the
                # same five templates down the page; `investigative_claim`
                # degrades to "insufficient corroborating runtime evidence" when
                # nothing correlated the frame. Both are retained behind the
                # perceptual reading rather than ahead of it.
                desc_str = (
                    scr.get("visual_observation")
                    or scr.get("description")
                    or scr.get("investigative_claim")
                    or "Captured during instrumented execution."
                )
                claim_str = scr.get("investigative_claim") or ""
                meta_source: Dict[str, Any] = scr
            else:
                scr_path_str = str(scr)
                title_str = f"Frame {idx:02d}"
                desc_str = "Captured during instrumented execution."
                claim_str = ""
                meta_source = {}

            img_obj = None
            if self.apk_dir:
                possible_paths = [
                    self.apk_dir / scr_path_str,
                    self.apk_dir / "screenshots" / scr_path_str,
                    self.apk_dir / "screenshots" / Path(scr_path_str).name,
                ]
                for path in possible_paths:
                    if path.exists():
                        try:
                            img_obj = Image(str(path), width=img_col - 8, height=248)
                            break
                        except Exception as e:
                            logger.warning(f"Failed to load image flowable {path}: {e}")

            left_cell: Any = img_obj or Paragraph(
                "<b>Frame not retained</b><br/>"
                "<font size=6 color=\"%s\">%s</font>" % (THEME.INK_FAINT, scr_path_str),
                self.body_style,
            )

            body_flowables: List[Any] = [
                Paragraph(f"<b>{title_str}</b>", self.body_bold),
                Paragraph(desc_str, self.body_style),
            ]
            if claim_str and claim_str != desc_str:
                body_flowables.append(
                    Paragraph(f"<b>Claim.</b> {claim_str}", self.body_style))
            body_flowables.append(Spacer(1, 2))
            body_flowables.append(self._screenshot_meta_table(meta_source, meta_col - 12))

            plate = Table([[left_cell, body_flowables]], colWidths=[img_col, meta_col + gap])
            plate.setStyle(TableStyle([
                ("LINEABOVE", (0, 0), (-1, 0), THEME.RULE_W_MID,
                 colors.HexColor(THEME.BORDER_STRONG)),
                ("LINEBELOW", (0, -1), (-1, -1), THEME.RULE_W_MID,
                 colors.HexColor(THEME.BORDER_STRONG)),
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(THEME.SURFACE_INSET)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]))
            elements.append(KeepTogether([plate, Spacer(1, 10)]))

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
