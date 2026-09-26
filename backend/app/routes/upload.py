# backend/app/routes/upload.py
"""
Sudarshan Upload & Analysis Pipeline
======================================
Full pipeline:
  APK → MobSF (or Androguard fallback) → Frida (if ready) → Threat Correlation → Risk Engine → RAG → Gemini 2.5 Flash → Response

Endpoints:
  POST /api/v1/analyze - sync analysis (returns full result immediately)
  POST /api/v1/analyze/async - async analysis (returns job_id; poll /status/{job_id})
  GET  /api/v1/status/{job_id} - poll async job
  GET  /api/v1/sandbox/status - Frida sandbox status
"""

import hashlib
import logging
import os
import tempfile
from pathlib import Path
import asyncio
import httpx
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request

from app.ai.gemini_client import analyze_with_llm
from sudarshan_core.analyzers.apk_analyzer import analyze_apk
from app.auth.auth import get_current_user, require_analyst
from app.db.database import save_case
from app.services.run_recorder import record_run
from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.engines.frida_sandbox import artifact_dir_for, get_sandbox_status, run_frida_analysis
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.models.schemas import (
    AnalysisResponse,
    CodeFinding,
    DynamicAnalysisResult,
    FraudCardExecutiveView,
    FraudCardTechnicalView,
    FRSBreakdown,
    FraudWorkflow,
    IntelligenceReport,
    IOCReputation,
    ManifestFinding,
    RiskExplanation,
    StaticAnalysisFlags,
    ThreatCorrelationResult,
    ThreatScenarioRow,
    WorkflowStage,
)
from app.rag.knowledge_base import build_rag_context  # noqa: F401
from app.ai.gemini_rag import build_investigation_index
from app.routes.report import cache_report
from sudarshan_core.services.mobsf_client import MobSFAnalysisError, MobSFClient, MobSFNotAvailable
from sudarshan_core.services.threat_correlator import correlate, extract_dynamic_urls
from app.workers.analysis_queue import create_job, enqueue, get_job, persist_job, update_job_pipeline
from app.rate_limit import limiter
from sudarshan_core.models.manifest import build_manifest, InvestigationManifest
from sudarshan_core.security.sandbox_containment import gateway_dynamic_allowed

logger = logging.getLogger(__name__)
router = APIRouter()

_mobsf = MobSFClient()


def _pipeline_progress_callback(job_id: Optional[str]):
    if not job_id:
        return None

    def _on_update(snapshot: Dict[str, Any]) -> None:
        update_job_pipeline(job_id, snapshot)

    return _on_update


def _make_pipeline_timer(job_id: Optional[str], case_id: str):
    from sudarshan_core.engines.pipeline_timing import PipelineTimer

    return PipelineTimer(
        job_id=job_id or case_id[:12],
        case_id=case_id,
        on_update=_pipeline_progress_callback(job_id),
    )


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _flags_to_dict(flags: Any) -> Dict[str, Any]:
    """
    Convert StaticAnalysisFlags to a plain dict for the risk engine.

    Dumps the model rather than enumerating fields by hand. The previous
    hand-written list silently dropped any flag added later: when
    has_concealed_payload was introduced, the analyser set it correctly but this
    function discarded it, so the Obfuscation axis never saw it and packed
    malware (Anubis) still scored "Safe" through the backend while the engine
    scored it "Suspicious". A field list that must be kept in sync by hand will
    fall out of sync.
    """
    if hasattr(flags, "model_dump"):        # pydantic v2
        return flags.model_dump()
    if hasattr(flags, "dict"):              # pydantic v1
        return flags.dict()
    if isinstance(flags, dict):
        return dict(flags)
    return {k: v for k, v in vars(flags).items() if not k.startswith("_")}


def _build_correlation_model(raw: Dict) -> ThreatCorrelationResult:
    """Convert raw correlator dict → Pydantic model."""
    ioc_list = []
    for ioc in raw.get("ioc_reputation", []):
        try:
            ioc_list.append(IOCReputation(**ioc))
        except Exception as exc:
            logger.debug("[Correlation] Skipped malformed IOC row: %s", exc)
    return ThreatCorrelationResult(
        available=raw.get("available", False),
        sha256_detections=raw.get("sha256_detections", 0),
        sha256_total=raw.get("sha256_total", 0),
        vt_detection_ratio=raw.get("vt_detection_ratio", 0.0),
        vt_malicious_vendors=raw.get("vt_malicious_vendors", []),
        ioc_reputation=ioc_list,
        known_family=raw.get("known_family"),
        campaign=raw.get("campaign"),
        threat_score=raw.get("threat_score", 0.0),
        sources_queried=raw.get("sources_queried", []),
        correlation_confidence=raw.get("correlation_confidence", 0.0),
        suspicious_domains=raw.get("suspicious_domains", []),
        malicious_ips=raw.get("malicious_ips", []),
        threat_score_sources=raw.get("threat_score_sources", []) or [],
    )


def _build_dynamic_analysis_model(dynamic_result: Optional[Dict]) -> Optional[DynamicAnalysisResult]:
    if not dynamic_result:
        return None
    bfci_ev = dynamic_result.get("bfci_evidence", [])
    if not isinstance(bfci_ev, list):
        bfci_ev = []
    return DynamicAnalysisResult(
        available=dynamic_result.get("available", False),
        activities_triggered=dynamic_result.get("activities_triggered", []),
        network_logs=dynamic_result.get("network_logs", []),
        api_calls=dynamic_result.get("api_calls", []),
        files_accessed=dynamic_result.get("files_accessed", []),
        screenshots=dynamic_result.get("screenshots", []),
        logcat=dynamic_result.get("logcat", ""),
        multi_stage_summary=dynamic_result.get("multi_stage_summary", {}),
        coverage_metrics=dynamic_result.get("coverage_metrics", {}),
        attack_timeline=dynamic_result.get("attack_timeline", []),
        clicked_nodes=list(dynamic_result.get("clicked_nodes", [])),
        anti_analysis_events=dynamic_result.get("anti_analysis_events", []),
        resilience_actions=dynamic_result.get("resilience_actions", []),
        anti_evasion=dynamic_result.get("anti_evasion"),
        yara_matches=dynamic_result.get("yara_matches", []),
        bfci=float(dynamic_result.get("bfci", 0.0) or 0.0),
        bfci_components=dynamic_result.get("bfci_components", {}) or {},
        bfci_evidence=bfci_ev,
        artifact_dir=dynamic_result.get("artifact_dir"),
        evidence_record_count=int(dynamic_result.get("evidence_record_count", 0) or 0),
        crash_info=dynamic_result.get("crash_info"),
        dynamic_status=str(dynamic_result.get("dynamic_status", "NOT_STARTED")),
        screenshot_status=dynamic_result.get("screenshot_status"),
        dynamic_coverage=dynamic_result.get("dynamic_coverage", {}),
        crashes=dynamic_result.get("crashes", []),
    )


def _build_risk_explanation(raw: Optional[Dict]) -> Optional[RiskExplanation]:
    if not raw or not isinstance(raw, dict):
        return None
    try:
        return RiskExplanation(**raw)
    except Exception as exc:
        logger.debug("[RiskExplanation] Skipped malformed payload: %s", exc)
        return None


def _build_fraud_workflow(raw: Optional[Dict]) -> Optional[FraudWorkflow]:
    """Convert raw fraud workflow dict -> FraudWorkflow Pydantic model."""
    if not raw or not isinstance(raw, dict):
        return None
    try:
        stages = []
        for s in raw.get("stages", []):
            if isinstance(s, dict):
                stages.append(WorkflowStage(
                    label=s.get("label", ""),
                    technique_id=s.get("technique_id", "T1000"),
                    description=s.get("description", ""),
                    start_ms=s.get("start_ms", 0),
                    end_ms=s.get("end_ms", 0),
                    evidence_ids=s.get("evidence_ids", []),
                    hook_names=s.get("hook_names", []),
                    confidence=s.get("confidence", 0.0),
                ))
        return FraudWorkflow(
            stages=stages,
            fraud_sequence_detected=raw.get("fraud_sequence_detected", False),
            sequence_label=raw.get("sequence_label", "NONE"),
            chain_confidence=raw.get("chain_confidence", 0.0),
            total_events_analyzed=raw.get("total_events_analyzed", 0),
            stage_count=raw.get("stage_count", len(stages)),
        )
    except Exception as e:
        logger.warning(f"[Workflow] Failed to build FraudWorkflow model: {e}")
        return None


ANALYSIS_ENGINE_URL: str = os.getenv("ANALYSIS_ENGINE_URL", "http://analysis-engine:8001")

# Shared with analysis-engine via the `uploads` docker volume.
_UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


# Must EXCEED the engine's own ANALYSIS_TIMEOUT_SECONDS (600 s in
# docker-compose.yml), plus headroom for request/response transfer.
#
# When this was 310 s and the engine budget was 600 s, any analysis that
# legitimately ran longer than 310 s made httpx give up, _call_analysis_engine
# return None, and the gateway silently re-run the WHOLE pipeline locally - in
# the unhardened container, while the engine was still running the first one.
# Two concurrent analyses of one sample, both contending for the single
# emulator, and only the second reported. With MobSF configured (300 s) plus
# APKTool (120 s) plus JADX (180 s), exceeding 310 s was the expected path, not
# a corner case.
_ENGINE_TIMEOUT_SECONDS: float = float(
    os.getenv("ANALYSIS_ENGINE_TIMEOUT_SECONDS",
              str(int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "600")) + 60))
)


async def _call_analysis_engine(temp_path: str, sha256_hash: str) -> Optional[Dict[str, Any]]:
    """Call containerized analysis-engine microservice via REST over Docker network."""
    url = f"{ANALYSIS_ENGINE_URL}/api/v1/analyze"
    try:
        async with httpx.AsyncClient(timeout=_ENGINE_TIMEOUT_SECONDS) as client:
            from sudarshan_core.security.internal_auth import internal_auth_headers
            # Assuming artifact key pattern apks/{sha256}.apk since we know it
            object_key = f"apks/{sha256_hash}.apk"
            resp = await client.post(
                url,
                json={"object_key": object_key, "sha256": sha256_hash},
                headers=internal_auth_headers(),
            )
            if resp.status_code == 200:
                logger.info(f"[Orchestrator] Analysis engine microservice returned 200 OK for {sha256_hash}")
                return resp.json()
            if resp.status_code == 408:
                detail = resp.text
                try:
                    detail = resp.json().get("detail", detail)
                except Exception:
                    pass
                logger.warning(
                    "[Orchestrator] Analysis engine timed out for %s: %s",
                    sha256_hash,
                    detail,
                )
                raise HTTPException(status_code=408, detail=detail)
            logger.warning(
                f"[Orchestrator] Analysis engine returned status {resp.status_code}: {resp.text}"
            )
    except Exception as e:
        # WARNING, not INFO: the fallback runs the pipeline in the gateway, which
        # has no APKTool/JADX, no memory or CPU cap and no no-new-privileges. A
        # permanent degradation to that path must not look like a healthy run in
        # the logs.
        logger.warning(
            f"[Orchestrator] Analysis engine unavailable ({type(e).__name__}: {e}); "
            f"falling back to the LOCAL pipeline - no APKTool/JADX, no container limits."
        )
    return None


# ─── Engine result → gateway contract ────────────────────────────────────────

# Keys `_build_response` indexes directly. Anything absent here raises KeyError,
# which is exactly how the delegation path used to 500.
_RESPONSE_DEFAULTS: Dict[str, Any] = {
    "package_name": "Unknown",
    "app_name": None,
    "analysis_mode": "androguard",
    "family_classification": "Unknown",
    "base_score": 0.0,
    "ai_confidence_multiplier": 1.0,
    "final_risk_score": 0.0,
    "risk_band": "Safe",
    "confidence": 70.0,
    "recommended_action": "",
    "frs_breakdown": {},
    "threat_scenario_table": [],
    "all_permissions": [],
    "dangerous_perms": [],
    "hardcoded_urls_ips": [],
    "targets_indian_banks": False,
    "has_accessibility_abuse": False,
    "has_sms_read_write": False,
    "has_system_alert_window": False,
    "obfuscation_score": 0.0,
    "has_reflection": False,
    "threat_correlation": {"available": False},
    "dynamic_available": False,
    "dynamic_result": None,
    "fraud_workflow": None,
    "manifest_findings": [],
    "code_findings": [],
    "activities": [],
    "services_list": [],
    "receivers": [],
    "certificate": {},
    "domains": {},
    "hardcoded_secrets": [],
    "appsec_score": None,
    "mobsf_scan_hash": None,
    # MobSF enrichment fields
    "providers": [],
    "exported_activities": [],
    "exported_services": [],
    "exported_receivers": [],
    "binary_analysis": [],
    "network_security": {},
    "trackers": [],
    "emails": [],
    "suspicious_strings": [],
    "dangerous_apis_found_raw": [],
    "matched_rule": "None",
    "intelligence_report": {},
    "investigation_manifest": None,
    "apktool_enrichment": None,
    "jadx_enrichment": None,
}


async def _persist_and_index(
    sha256_hash: str,
    result: Dict[str, Any],
    analyst_id: Optional[int],
) -> None:
    """
    Post-processing shared by BOTH the delegated and local paths.

    Previously only the local path did this, so a delegated analysis was never
    saved, never cached for the STIX/IOC export endpoints, and never indexed for
    the AI assistant.
    """
    await save_case(sha256_hash, result, analyst_id=analyst_id)

    # History row for trending. save_case cannot do this - it is also called
    # when a case is re-opened and re-enriched, which is not a new run.
    await record_run(result, sha256=sha256_hash, stage_name="delegated")

    cache_report(sha256_hash, {
        "sha256": sha256_hash,
        "package_name": result.get("package_name"),
        "family_classification": result.get("family_classification"),
        "final_risk_score": result.get("final_risk_score"),
        "risk_band": result.get("risk_band"),
        "confidence": result.get("confidence"),
        "has_accessibility_abuse": result.get("has_accessibility_abuse", False),
        "has_sms_read_write": result.get("has_sms_read_write", False),
        "has_system_alert_window": result.get("has_system_alert_window", False),
        "hardcoded_urls_ips": result.get("hardcoded_urls_ips", []),
        "targets_indian_banks": result.get("targets_indian_banks", False),
        "threat_correlation": result.get("threat_correlation") or {"available": False},
        "vide": result.get("vide") or {},
        "intelligence_report": result.get("intelligence_report") or {},
    })

    try:
        build_investigation_index(sha256_hash, result)
        logger.info(f"[RAG] Investigation indexed for {sha256_hash}")
    except Exception as e:
        logger.warning(f"[RAG] Investigation indexing failed (non-critical): {e}")


def _coerce_manifest_findings(raw: Any) -> list:
    """
    `_build_response` reads `.title` off each manifest finding, so plain dicts
    from the engine must become ManifestFinding models. Malformed entries are
    dropped rather than allowed to abort the whole analysis.
    """
    out = []
    for item in raw or []:
        if isinstance(item, ManifestFinding):
            out.append(item)
        elif isinstance(item, dict):
            try:
                out.append(ManifestFinding(**item))
            except Exception:
                continue
    return out


def _coerce_dangerous_permissions(raw: Any) -> list:
    """Ensure dangerous_permissions contains structured dicts for both engine and MobSF outputs."""
    out = []
    for item in raw or []:
        if isinstance(item, str):
            short = item.split(".")[-1]
            out.append({"permission": item, "short": short, "status": "dangerous"})
        elif isinstance(item, dict):
            out.append(item)
    return out


async def _enrich_engine_result(
    engine_result: Dict[str, Any],
    sha256_hash: str,
    analyst_id: Optional[int],
    timer=None,
) -> Dict[str, Any]:
    """
    Bring an analysis-engine result up to the gateway's response contract.

    The engine owns static + dynamic analysis. The gateway owns everything that
    needs an LLM, the knowledge base or the database. This composes the two
    instead of letting either pretend to be the other.
    """
    result: Dict[str, Any] = {**_RESPONSE_DEFAULTS, **engine_result}
    result["sha256"] = sha256_hash

    flags_dict = {
        "has_accessibility_abuse": result.get("has_accessibility_abuse", False),
        "has_sms_read_write": result.get("has_sms_read_write", False),
        "has_system_alert_window": result.get("has_system_alert_window", False),
        "dangerous_apis_found": result.get("dangerous_apis_found_raw")
                                or result.get("dangerous_apis_found", []),
        "hardcoded_urls_ips": result.get("hardcoded_urls_ips", []),
        "targets_indian_banks": result.get("targets_indian_banks", False),
        "indian_bank_packages_found": result.get("indian_bank_packages_found", []),
        "obfuscation_score": result.get("obfuscation_score", 0.0),
        "has_reflection": result.get("has_reflection", False),
        "has_concealed_payload": (result.get("frs_breakdown") or {}).get("concealed_payload", False),
    }
    result["dangerous_apis_found_raw"] = flags_dict["dangerous_apis_found"]
    result["manifest_findings"] = _coerce_manifest_findings(result.get("manifest_findings"))
    result["dangerous_perms"] = _coerce_dangerous_permissions(result.get("dangerous_perms"))

    # What the sandbox did TO the device, for the fraud-card banner. Derived
    # from the recorded anti-evasion sequence, not inferred from the sample's
    # own telemetry - see services/resilience_summary.
    if result.get("dynamic_result") and isinstance(result["dynamic_result"], dict):
        from app.services.resilience_summary import build_resilience_actions

        dyn = result["dynamic_result"]
        dyn["resilience_actions"] = build_resilience_actions(dyn, flags_dict)
        result["dynamic_result"] = dyn

    # Family classification - the engine reports one, but only the gateway has
    # the rule set that also yields `matched_rule`.
    family = result.get("family_classification") or "Unknown"
    matched_rule = result.get("matched_rule") or "None"
    try:
        derived_family, derived_rule = classify_family(StaticAnalysisFlags(**{
            k: v for k, v in flags_dict.items()
            if k in StaticAnalysisFlags.model_fields
        }))
        if family == "Unknown" and derived_family != "Unknown":
            family = derived_family
        if matched_rule in ("", "None") and derived_rule:
            matched_rule = derived_rule
    except Exception as e:
        logger.warning(f"[Orchestrator] Family classification on engine result failed: {e}")
    result["family_classification"] = family
    result["matched_rule"] = matched_rule

    # LLM/RAG synthesis - the engine has no LLM, which is why returning its
    # result raw produced KeyError: 'intelligence_report'.
    from sudarshan_core.engines.pipeline_timing import OrchestratorStage

    if timer:
        timer.set_orchestrator_stage(OrchestratorStage.INTELLIGENCE_GENERATION)

    try:
        if timer:
            timer.stage_started("GEMINI", "Gemini 2.5 Flash narrative")
        result["intelligence_report"] = await analyze_with_llm(
            flags=flags_dict,
            family=family,
            matched_rule=matched_rule,
            package_name=result.get("package_name", "Unknown"),
            # _build_evidence_dict reads final_risk_score / risk_band /
            # confidence / evidence off this argument. FRSBreakdown has NONE of
            # them, so passing it told the LLM score=0, band="Unknown" on every
            # delegated run and the narrative contradicted the on-screen verdict.
            risk_result={
                "final_risk_score": result.get("final_risk_score"),
                "risk_band": result.get("risk_band"),
                "confidence": result.get("confidence"),
                "recommended_action": result.get("recommended_action"),
                "frs_breakdown": result.get("frs_breakdown") or {},
                "threat_scenario_table": result.get("threat_scenario_table") or [],
                "evidence": result.get("evidence") or [],
            },
            correlation=result.get("threat_correlation") or {},
            dynamic=result.get("dynamic_result"),
            vide_result=result.get("vide"),
        ) or {}
        if timer:
            timer.stage_completed("GEMINI")
    except Exception as e:
        if timer:
            timer.stage_failed("GEMINI", str(e))
        # Degrade visibly rather than failing the analysis.
        logger.warning(f"[Orchestrator] LLM synthesis failed on engine result: {e}")
        result["intelligence_report"] = {
            "plain_english_narrative": (
                "Static and dynamic analysis completed, but AI narrative synthesis "
                "was unavailable for this run."
            ),
            "analysis_note": f"LLM unavailable: {type(e).__name__}",
            "confidence": "Low",
        }

    if timer:
        timer.set_orchestrator_stage(OrchestratorStage.PERSISTING)
        timer.stage_started("PERSISTENCE", "case store, report cache, RAG index")
    await _persist_and_index(sha256_hash, result, analyst_id)
    if timer:
        timer.stage_completed("PERSISTENCE")
        timer.set_orchestrator_stage(OrchestratorStage.COMPLETED)
        result["pipeline_timing"] = timer.to_dict()
    return result


# ─── Core Analysis Logic (shared by sync + async) ────────────────────────────

async def _run_analysis_pipeline(
    temp_path: str,
    sha256_hash: str,
    analyst_id: Optional[int] = None,
    job_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Full analysis pipeline. Returns a dict that can be serialised as AnalysisResponse.
    Delegates to analysis-engine microservice if available.
    """
    from sudarshan_core.engines.pipeline_timing import OrchestratorStage

    timer = _make_pipeline_timer(job_id, sha256_hash)
    timer.set_orchestrator_stage(OrchestratorStage.VALIDATING)

    timer.stage_started("ENGINE_DELEGATION", "analysis-engine microservice")
    timer.set_orchestrator_stage(OrchestratorStage.ANALYSIS_ENGINE)
    engine_result = await _call_analysis_engine(temp_path, sha256_hash)
    timer.stage_completed("ENGINE_DELEGATION")

    if engine_result:
        pipeline_meta = engine_result.pop("_pipeline", None)
        if pipeline_meta:
            timer.merge_engine_timings(pipeline_meta)
        logger.info(f"[Orchestrator] Enriching analysis-engine result for {sha256_hash}")
        return await _enrich_engine_result(engine_result, sha256_hash, analyst_id, timer=timer)

    if not gateway_dynamic_allowed():
        raise HTTPException(
            status_code=503,
            detail=(
                "Analysis engine unavailable and gateway dynamic analysis is "
                "disabled (SUDARSHAN_ALLOW_GATEWAY_DYNAMIC). Malware must not "
                "run in the unhardened backend container."
            ),
        )

    analysis_mode = "androguard"
    mobsf_report: Optional[Dict] = None
    package_name = "Unknown"
    all_permissions: list = []
    flags_dict: Dict[str, Any] = {}
    dangerous_perms: list = []
    activities: list = []
    services_list: list = []
    receivers: list = []
    certificate: dict = {}
    domains: dict = {}
    hardcoded_secrets: list = []
    manifest_findings: list = []
    code_findings: list = []
    appsec_score = None
    mobsf_scan_hash: Optional[str] = None
    suspicious_strings: list = []
    # MobSF enrichment - initialized to safe defaults (Androguard fallback leaves empty)
    providers: list = []
    exported_activities: list = []
    exported_services: list = []
    exported_receivers: list = []
    binary_analysis_data: list = []
    network_security_data: dict = {}
    trackers_data: list = []
    emails_data: list = []

    timer.set_orchestrator_stage(OrchestratorStage.STATIC_ANALYSIS)
    mobsf_available = await _mobsf.is_available()
    androguard_output = None

    async def _run_native() -> Any:
        timer.stage_started("NATIVE_ANALYSIS", "Androguard static analyzer")
        try:
            out = await asyncio.to_thread(analyze_apk, temp_path)
            timer.stage_completed("NATIVE_ANALYSIS")
            return out
        except Exception as e:
            timer.stage_failed("NATIVE_ANALYSIS", str(e))
            raise

    async def _run_mobsf() -> Optional[Dict]:
        timer.stage_started("MOBSF", "MobSF static engine")
        try:
            report = await _mobsf.analyze(temp_path)
            timer.stage_completed("MOBSF")
            return report
        except (MobSFAnalysisError, MobSFNotAvailable) as e:
            timer.stage_failed("MOBSF", str(e))
            return None
        except Exception as e:
            timer.stage_failed("MOBSF", str(e))
            return None

    if mobsf_available:
        mobsf_report, androguard_output = await asyncio.gather(_run_mobsf(), _run_native())
        if mobsf_report:
            analysis_mode = "mobsf"
            package_name = mobsf_report.get("package_name") or "Unknown"
            all_permissions = _mobsf.get_all_permissions(mobsf_report)
            flags_dict = _mobsf.extract_flags(mobsf_report)
            dangerous_perms = mobsf_report.get("dangerous_permissions", [])
            activities = mobsf_report.get("activities", [])[:20]
            services_list = mobsf_report.get("services", [])[:10]
            receivers = mobsf_report.get("receivers", [])[:10]
            certificate = mobsf_report.get("certificate", {})
            domains = mobsf_report.get("domains", {})
            hardcoded_secrets = mobsf_report.get("hardcoded_secrets", [])
            appsec_score = mobsf_report.get("appsec_score")
            mobsf_scan_hash = mobsf_report.get("scan_hash")
            providers = mobsf_report.get("providers", [])[:20]
            exported_activities = mobsf_report.get("exported_activities", [])
            exported_services = mobsf_report.get("exported_services", [])
            exported_receivers = mobsf_report.get("exported_receivers", [])
            binary_analysis_data = mobsf_report.get("binary_analysis", [])
            network_security_data = mobsf_report.get("network_security", {})
            trackers_data = mobsf_report.get("trackers", [])
            emails_data = mobsf_report.get("emails", [])[:50]
            for mf in mobsf_report.get("manifest_analysis", []):
                try:
                    manifest_findings.append(ManifestFinding(**mf))
                except Exception:
                    pass
            for cf in mobsf_report.get("code_analysis", {}).get("findings", []):
                try:
                    code_findings.append(CodeFinding(**cf))
                except Exception:
                    pass
            logger.info(f"MobSF analysis complete: pkg={package_name}")
        elif androguard_output:
            logger.warning("MobSF failed - using Androguard primary output")
            mobsf_available = False

    if not mobsf_available or not mobsf_report:
        if androguard_output is None:
            androguard_output = await _run_native()
        logger.info("Using Androguard for package metadata")
        package_name = androguard_output.package_name
        all_permissions = androguard_output.permissions or []
        if not flags_dict:
            flags_dict = _flags_to_dict(androguard_output.flags)
        suspicious_strings = androguard_output.suspicious_strings

    # ── STEP 1.5a: APKTool + JADX Enrichment (parallel when available) ──
    apktool_result = None
    jadx_result = None
    try:
        from sudarshan_core.engines.apktool_engine import ApktoolEngine
        from sudarshan_core.engines.jadx_engine import JadxEngine
        _apktool = ApktoolEngine()
        _jadx = JadxEngine()

        async def _apktool_task():
            if not await asyncio.to_thread(_apktool.is_available):
                return None
            timer.stage_started("APKTOOL")
            res = await asyncio.to_thread(_apktool.analyze, temp_path)
            timer.stage_completed("APKTOOL")
            return res

        async def _jadx_task():
            if not await asyncio.to_thread(_jadx.is_available):
                return None
            timer.stage_started("JADX")
            res = await asyncio.to_thread(_jadx.analyze, temp_path)
            timer.stage_completed("JADX")
            return res

        apktool_result, jadx_result = await asyncio.gather(_apktool_task(), _jadx_task())
        if apktool_result and apktool_result.available:
            suspicious_strings = list(dict.fromkeys(
                suspicious_strings + apktool_result.resource_strings
            ))[:100]
            logger.info(
                f"[APKTool] Enrichment: {len(apktool_result.suspicious_resources)} suspicious resources, "
                f"{apktool_result.obfuscated_resource_count} obfuscated names"
            )
        if jadx_result and jadx_result.available:
            for hit in jadx_result.fraud_class_hits:
                label = hit.split(":")[0]
                if label == "ACCESSIBILITY_SERVICE":
                    flags_dict["has_accessibility_abuse"] = True
                elif label == "SMS_RECEIVER":
                    flags_dict["has_sms_read_write"] = True
                elif label in ("OVERLAY_WINDOW", "OVERLAY_DRAW"):
                    flags_dict["has_system_alert_window"] = True
                elif label == "DEVICE_ADMIN":
                    flags_dict["has_device_admin"] = True
                elif label == "DYNAMIC_CLASS_LOAD":
                    flags_dict["has_dynamic_code_loading"] = True
            suspicious_strings = list(dict.fromkeys(
                suspicious_strings + jadx_result.suspicious_strings
            ))[:100]
            logger.info(
                f"[JADX] Enrichment: {len(jadx_result.fraud_class_hits)} fraud class hits, "
                f"{jadx_result.decompiled_class_count} classes decompiled"
            )
    except Exception as e:
        logger.warning(f"[Static Enrichment] APKTool/JADX enrichment failed (non-critical): {e}")

    # ── STEP 1.5b: Build Investigation Manifest (pre-sandbox data contract) ──
    apk_artifact_dir = artifact_dir_for(temp_path)
    manifest: Optional[InvestigationManifest] = None
    try:
        timer.stage_started("MANIFEST")
        manifest = build_manifest(
            sha256=sha256_hash,
            package_name=package_name,
            flags_dict=flags_dict,
            analysis_mode=analysis_mode,
            app_name=mobsf_report.get("app_name") if mobsf_report else None,
            all_permissions=all_permissions,
            dangerous_permissions=dangerous_perms,
            activities=activities,
            services=services_list,
            receivers=receivers,
        )
        manifest.to_file(apk_artifact_dir / "manifest.json")
        timer.stage_completed("MANIFEST")
        logger.info(
            f"[Manifest] Generated: hook_profiles={manifest.hook_profiles}, "
            f"priorities={{A:{manifest.goal_priority_config.accessibility_priority},"
            f"S:{manifest.goal_priority_config.sms_priority},"
            f"O:{manifest.goal_priority_config.overlay_priority}}}"
        )
    except Exception as e:
        timer.stage_failed("MANIFEST", str(e))
        logger.warning(f"[Manifest] Manifest generation failed (non-critical): {e}")

    # ── STEP 1.5c: Frida Dynamic Analysis ────────────────────────────────────
    dynamic_result: Optional[Dict] = None
    frida_status = get_sandbox_status()
    timer.set_orchestrator_stage(OrchestratorStage.DYNAMIC_ANALYSIS)

    if frida_status["ready"]:
        logger.info("Frida sandbox ready - running dynamic behavioral analysis")
        timer.stage_started("AGENTIC_EXPLORER", "Frida sandbox and Agentic Explorer")
        try:
            use_multistage = os.getenv("SUDARSHAN_MULTISTAGE", "false").lower() == "true"
            if use_multistage:
                from sudarshan_core.engines.multi_stage_engine import MultiStageEngine
                engine = MultiStageEngine(apk_path=temp_path, package_name=package_name)
                dynamic_result = await engine.run_all_stages()
            else:
                from sudarshan_core.engines.frida_sandbox import run_frida_analysis
                # Hand the static pass's findings to the dynamic engine. Without
                # this the explorer cannot tell a permission the manifest
                # declared from one it never asked for, so expected-vs-observed
                # permission analysis is impossible.
                dynamic_result = await run_frida_analysis(
                    temp_path,
                    package_name=package_name,
                    static_findings={
                        "permissions": all_permissions,
                        "flags": flags_dict,
                        # The identity the sample claims. Attacker-controlled,
                        # which is exactly why it is useful: permissions are
                        # judged against what the app says it is.
                        "app_label": getattr(androguard_output, "app_label", "") or "",
                    },
                )
            if dynamic_result.get("available"):
                logger.info(f"Frida BFCI={dynamic_result.get('bfci', 0):.1f}")
            else:
                logger.warning(f"Frida did not complete: {dynamic_result.get('error')}")
            timer.stage_completed("AGENTIC_EXPLORER")
        except Exception as e:
            timer.stage_failed("AGENTIC_EXPLORER", str(e))
            logger.warning(f"Frida analysis failed: {e}")
            dynamic_result = None
    else:
        logger.info(f"Frida sandbox not ready ({frida_status['message']})")
        dynamic_result = {
            "available": False,
            "runtime_requested": True,
            "runtime_attempted": False,
            "engine": "frida",
            "dynamic_status": "EMULATOR_UNAVAILABLE",
            "error": frida_status.get("message", "Sandbox not ready"),
        }

    # ── STEP 2: Classification ────────────────────────────────────────────────
    flags_model = StaticAnalysisFlags(**flags_dict)
    family_class, matched_rule = classify_family(flags_model)
    ai_confidence = 1.0 if family_class == "Unknown" else 1.2

    # ── STEP 3: Threat Correlation ────────────────────────────────────────────
    logger.info("Running threat correlation...")
    timer.set_orchestrator_stage(OrchestratorStage.THREAT_CORRELATION)
    timer.stage_started("THREAT_CORRELATION")
    try:
        correlation_raw = await correlate(
            sha256=sha256_hash,
            urls=flags_dict.get("hardcoded_urls_ips", []),
            package_name=package_name,
            dynamic_urls=extract_dynamic_urls(dynamic_result),
        )
        timer.stage_completed("THREAT_CORRELATION")
    except Exception as e:
        timer.stage_failed("THREAT_CORRELATION", str(e))
        logger.warning(f"Threat correlation failed: {e}")
        correlation_raw = {"available": False}

    if correlation_raw.get("known_family") and family_class == "Unknown":
        family_class = correlation_raw["known_family"]
        ai_confidence = 1.15

    if dynamic_result and isinstance(dynamic_result, dict):
        dynamic_result["has_high_risk_capabilities"] = bool(
            flags_dict.get("has_accessibility_abuse")
            or flags_dict.get("has_system_alert_window")
            or flags_dict.get("has_sms_read_write")
        )

    suspect_ui = None
    if apktool_result and apktool_result.available and apktool_result.ui_profile:
        suspect_ui = UIProfile.from_dict(apktool_result.ui_profile)

    timer.stage_started("VIDE_DYNAMIC")
    vide_result = await asyncio.to_thread(
        safe_run_vide_analysis,
        suspect_profile=suspect_ui,
        dynamic_result=dynamic_result,
        package_name=package_name or "",
        certificate=certificate,
        apktool_available=bool(apktool_result and apktool_result.available),
    )
    timer.stage_completed("VIDE_DYNAMIC")

    # Advisory only: explains *why* the UI reads as a clone of the attributed
    # bank, using that bank's design.md schema. The deterministic verdict above
    # is already final and is not revised by this call.
    if isinstance(vide_result, dict) and suspect_ui is not None:
        try:
            from sudarshan_core.engines.vide.baseline_store import get_baselines
            from sudarshan_core.engines.vide.semantic_matcher import enrich_with_semantics

            vide_result = await enrich_with_semantics(
                vide_result, suspect_ui, get_baselines()
            )
        except Exception as exc:
            logger.warning("[Upload] VIDE semantic enrichment skipped: %s", exc)

    if dynamic_result and dynamic_result.get("artifact_dir"):
        try:
            from sudarshan_core.visual_evidence.enrich import enrich_visual_evidence_artifact

            enrich_visual_evidence_artifact(
                Path(dynamic_result["artifact_dir"]),
                analysis_id=sha256_hash,
                package_name=package_name or "",
                vide_result=vide_result if isinstance(vide_result, dict) else {},
                static_flags={
                    "has_accessibility_abuse": flags_dict.get("has_accessibility_abuse", False),
                    "has_system_alert_window": flags_dict.get("has_system_alert_window", False),
                    "has_sms_read_write": flags_dict.get("has_sms_read_write", False),
                    "targets_indian_banks": flags_dict.get("targets_indian_banks", False),
                },
            )
        except Exception as exc:
            logger.warning("[Upload] Visual evidence enrichment failed (non-critical): %s", exc)

    # ── STEP 4: Risk Scoring (5-axis STEI) ───────────────────────────────────
    timer.set_orchestrator_stage(OrchestratorStage.RISK_ASSESSMENT)
    timer.stage_started("RISK", "deterministic FRS")
    risk_result = calculate_risk_score(
        flags=flags_dict,
        ai_confidence=ai_confidence,
        dynamic_result=dynamic_result,
        correlation_result=correlation_raw,
        family=family_class,
        all_permissions=all_permissions,
        vide_result=vide_result,
    )
    timer.stage_completed("RISK")

    # ── STEP 5: RAG + Gemini Flash Intelligence ──────────────────────────────
    logger.info("Running RAG-grounded Gemini Flash AI analysis...")
    timer.set_orchestrator_stage(OrchestratorStage.INTELLIGENCE_GENERATION)
    timer.stage_started("GEMINI")
    llm_response = await analyze_with_llm(
        flags=flags_dict,
        family=family_class,
        matched_rule=matched_rule,
        package_name=package_name,
        risk_result=risk_result,
        correlation=correlation_raw,
        dynamic=dynamic_result,
        vide_result=vide_result,
    )
    timer.stage_completed("GEMINI")

    # ── Assemble result dict ──────────────────────────────────────────────────
    result = {
        "sha256": sha256_hash,
        "package_name": package_name,
        "dangerous_apis_found_raw": flags_dict.get("dangerous_apis_found", []),
        "app_name": mobsf_report.get("app_name") if mobsf_report else (androguard_output.app_label if androguard_output else None),
        "version_name": mobsf_report.get("version_name") if mobsf_report else (androguard_output.version_name if androguard_output else None),
        "apk_size": mobsf_report.get("size") if mobsf_report else (androguard_output.apk_size if androguard_output else None),
        "analysis_mode": analysis_mode,
        "family_classification": family_class,
        "base_score": risk_result["base_score"],
        "ai_confidence_multiplier": risk_result["ai_confidence_multiplier"],
        "final_risk_score": risk_result["final_risk_score"],
        "risk_band": risk_result["risk_band"],
        # The Execution Assertion Matrix. `risk_band` keeps its four-value
        # vocabulary for the badge colours; `verdict` carries INCOMPLETE_EXERCISE
        # when the sandbox ran but never reached any of the sample's own trigger
        # conditions. Without these three keys the frontend cannot distinguish
        # "we observed nothing bad" from "we never got to look", and a floored
        # case reads as a clean one.
        "verdict": risk_result.get("verdict", risk_result["risk_band"]),
        "execution_assertions": risk_result.get("execution_assertions"),
        "incomplete_exercise": bool(risk_result.get("incomplete_exercise", False)),
        "confidence": risk_result.get("confidence", 70.0),
        "recommended_action": risk_result.get("recommended_action", ""),
        "frs_breakdown": risk_result.get("frs_breakdown", {}),
        "risk_explanation": risk_result.get("risk_explanation", {}),
        "threat_scenario_table": risk_result.get("threat_scenario_table", []),
        "all_permissions": all_permissions,
        "hardcoded_urls_ips": flags_dict.get("hardcoded_urls_ips", []),
        "targets_indian_banks": flags_dict.get("targets_indian_banks", False),
        "has_accessibility_abuse": flags_dict.get("has_accessibility_abuse", False),
        "has_sms_read_write": flags_dict.get("has_sms_read_write", False),
        "has_system_alert_window": flags_dict.get("has_system_alert_window", False),
        "obfuscation_score": flags_dict.get("obfuscation_score", 0.0),
        "has_reflection": flags_dict.get("has_reflection", False),
        "threat_correlation": correlation_raw,
        "dynamic_available": bool(
            dynamic_result
            and (
                dynamic_result.get("available")
                or dynamic_result.get("runtime_attempted")
            )
        ),
        "dynamic_result": dynamic_result,
        "fraud_workflow": dynamic_result.get("fraud_workflow") if dynamic_result else None,
        "manifest_findings": manifest_findings,
        "code_findings": code_findings,
        "dangerous_perms": dangerous_perms,
        "activities": activities,
        "services_list": services_list,
        "receivers": receivers,
        "certificate": certificate,
        "domains": domains,
        "hardcoded_secrets": hardcoded_secrets,
        "appsec_score": appsec_score,
        "mobsf_scan_hash": mobsf_scan_hash,
        "suspicious_strings": suspicious_strings,
        "intelligence_report": llm_response,
        "matched_rule": matched_rule,
        "vide": vide_result,
        # ── MobSF enrichment fields ────────────────────────────────────────────
        "providers": providers,
        "exported_activities": exported_activities,
        "exported_services": exported_services,
        "exported_receivers": exported_receivers,
        "binary_analysis": binary_analysis_data,
        "network_security": network_security_data,
        "trackers": trackers_data,
        "emails": emails_data,
        # ── Static enrichment results ──────────────────────────────────────────
        "investigation_manifest": manifest.model_dump() if manifest else None,
        "apktool_enrichment": {
            "available": apktool_result.available if apktool_result else False,
            "suspicious_resources": apktool_result.suspicious_resources if apktool_result and apktool_result.available else [],
            "obfuscated_resource_count": apktool_result.obfuscated_resource_count if apktool_result and apktool_result.available else 0,
            "decoded_manifest_available": bool(apktool_result and apktool_result.decoded_manifest_xml),
        } if apktool_result else None,
        "jadx_enrichment": {
            "available": jadx_result.available if jadx_result else False,
            "fraud_class_hits": jadx_result.fraud_class_hits if jadx_result and jadx_result.available else [],
            "dynamic_load_hits": jadx_result.dynamic_load_hits if jadx_result and jadx_result.available else [],
            "decompiled_class_count": jadx_result.decompiled_class_count if jadx_result and jadx_result.available else 0,
        } if jadx_result else None,
    }

    from datetime import datetime, timezone
    result["created_at"] = datetime.now(timezone.utc).isoformat()

    # ── Persist to DB ─────────────────────────────────────────────────────────
    timer.set_orchestrator_stage(OrchestratorStage.PERSISTING)
    timer.stage_started("PERSISTENCE")
    await save_case(sha256_hash, result, analyst_id=analyst_id)
    await record_run(result, sha256=sha256_hash, stage_name="local")

    # ── Cache for export endpoints ────────────────────────────────────────────
    report_cache_data = {
        "sha256": sha256_hash,
        "package_name": package_name,
        "family_classification": family_class,
        "final_risk_score": risk_result["final_risk_score"],
        "risk_band": risk_result["risk_band"],
        # Carried so the PDF renders the verdict the engine actually reached
        # rather than rebuilding the assertion matrix from dynamic_result.
        "verdict": risk_result.get("verdict", risk_result["risk_band"]),
        "execution_assertions": risk_result.get("execution_assertions"),
        "confidence": risk_result.get("confidence", 70.0),
        "has_accessibility_abuse": flags_dict.get("has_accessibility_abuse", False),
        "has_sms_read_write": flags_dict.get("has_sms_read_write", False),
        "has_system_alert_window": flags_dict.get("has_system_alert_window", False),
        "hardcoded_urls_ips": flags_dict.get("hardcoded_urls_ips", []),
        "targets_indian_banks": flags_dict.get("targets_indian_banks", False),
        "threat_correlation": correlation_raw,
        "intelligence_report": llm_response,
    }
    cache_report(sha256_hash, report_cache_data)

    # ── Build RAG investigation index for AI Assistant ────────────────────────
    try:
        build_investigation_index(sha256_hash, result)
        logger.info(f"[RAG] Investigation indexed for {sha256_hash}")
    except Exception as e:
        logger.warning(f"[RAG] Investigation indexing failed (non-critical): {e}")

    timer.stage_completed("PERSISTENCE")
    timer.set_orchestrator_stage(OrchestratorStage.COMPLETED)
    result["pipeline_timing"] = timer.to_dict()

    return result


def _to_str_list(val: Any) -> List[str]:
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    if isinstance(val, str) and val.strip():
        return [val.strip()]
    return []


# ─── Upload intake ────────────────────────────────────────────────────────────

# Real banking APKs top out around 150 MB. Mirrors MAX_UPLOAD_BYTES in the
# analysis engine - the engine enforced this on ITS upload endpoint, which the
# gateway never calls (it posts a path), so the limit did not apply to the path
# users actually hit.
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))
_UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024

# Every APK is a ZIP. An extension check alone accepts any content.
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


async def _receive_apk(file: UploadFile) -> tuple[str, str]:
    """
    Stream an uploaded APK to the shared volume and return (temp_path, sha256).

    Replaces two near-identical inline blocks that shared three defects:

      1. `file.filename.endswith(...)` raised AttributeError -> unhandled 500
         when a multipart part carried no filename. The engine guarded this
         (`if not filename or not ...`); the gateway did not.
      2. No size limit, so a single request could fill the volume that is the
         ONLY channel between the gateway and the engine - taking analysis down
         for everyone, not just the caller.
      3. No magic-byte check, so arbitrary content reached androguard, APKTool,
         JADX and zipfile.

    The partial file is always removed on rejection; previously a rejected
    upload could leave bytes on the volume.
    """
    filename = file.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .apk files are allowed.")

    hasher = hashlib.sha256()
    total = 0
    temp_path: Optional[str] = None

    try:
        # We first spool to a local temp file, then we will upload to ArtifactStorage
        # and remove the local spool file.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=_UPLOADS_DIR) as tmp:
            temp_path = tmp.name
            first = True
            while True:
                chunk = await file.read(_UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                if first:
                    # Validate before a single byte is committed to the volume.
                    if not chunk.startswith(_ZIP_MAGIC):
                        raise HTTPException(
                            status_code=400,
                            detail="File is not a valid APK (missing ZIP archive signature).",
                        )
                    first = False

                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"APK exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                    )

                hasher.update(chunk)
                # Blocking write - must not run on the event loop.
                await asyncio.to_thread(tmp.write, chunk)

            if first:
                raise HTTPException(status_code=400, detail="Empty upload.")

        sha256 = hasher.hexdigest()
        
        # Now upload the spooled file to the durable ArtifactStorage
        import sys
        if str(Path(__file__).resolve().parents[2]) not in sys.path:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        
        from sudarshan_core.storage.artifact_storage import get_storage
        storage = get_storage()
        object_key = f"apks/{sha256}.apk"
        await storage.put_file(temp_path, object_key, content_type="application/vnd.android.package-archive")

        from app.db.artifact_metadata import record_artifact
        await record_artifact(
            artifact_id=f"apk_{sha256}",
            artifact_type="original_apk",
            object_key=object_key,
            status="VERIFIED",
            size_bytes=total,
            sha256=sha256,
            content_type="application/vnd.android.package-archive"
        )
        
        # Remove the temporary spooled file since it is now in durable storage
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            
        return object_key, sha256

    except Exception:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise


def _build_response(result: Dict[str, Any], job_id: Optional[str] = None) -> AnalysisResponse:
    """Convert raw pipeline result dict into AnalysisResponse Pydantic model."""
    llm_response = result["intelligence_report"]

    executive_view = FraudCardExecutiveView(
        risk_badge=result["risk_band"],
        plain_english_narrative=llm_response.get("plain_english_narrative", "Analysis unavailable."),
        recommended_actions=_to_str_list(llm_response.get("recommended_actions")),
        customer_advisory_draft=llm_response.get("customer_advisory_draft", "No advisory available."),
    )

    critical_perms = [
        p for p in result["all_permissions"]
        if any(k in p for k in ("SMS", "ACCESSIBILITY", "SYSTEM_ALERT_WINDOW", "INSTALL_PACKAGES"))
    ]
    technical_view = FraudCardTechnicalView(
        permissions_fired=critical_perms or result["hardcoded_urls_ips"][:3],
        strings_fired=result["suspicious_strings"][:20],
        apis_fired=result.get("dangerous_apis_found_raw", []),
        matched_rule=result["matched_rule"],
        decoded_manifest_excerpts=[mf.title for mf in result["manifest_findings"][:5]],
    )

    intel_report = IntelligenceReport(
        plain_english_narrative=llm_response.get("plain_english_narrative", ""),
        fraud_objective=llm_response.get("fraud_objective"),
        affected_banking_apps=_to_str_list(llm_response.get("affected_banking_apps")),
        mitre_techniques_used=_to_str_list(llm_response.get("mitre_techniques_used")),
        banking_impact_assessment=llm_response.get("banking_impact_assessment"),
        cert_in_recommendations=_to_str_list(llm_response.get("cert_in_recommendations")),
        recommended_actions=_to_str_list(llm_response.get("recommended_actions")),
        customer_advisory_draft=llm_response.get("customer_advisory_draft", ""),
        confidence=llm_response.get("confidence", "Medium"),
        analysis_note=llm_response.get("analysis_note"),
    )

    # Build from the engine's own keys rather than re-listing them. The previous
    # explicit mapping dropped every field added later (axes_excluded,
    # concealed_payload, verdict_floored_for_visibility, dynamic_conclusive), so
    # the API reported null for provenance the engine had actually computed.
    # Unknown keys are ignored by pydantic, so this stays safe as the engine grows.
    frs_bd = result.get("frs_breakdown", {}) or {}
    known = set(FRSBreakdown.model_fields)
    frs_model = FRSBreakdown(**{k: v for k, v in frs_bd.items() if k in known})

    scenario_rows = [
        ThreatScenarioRow(**row)
        for row in result.get("threat_scenario_table", [])
    ]

    dynamic_result = result.get("dynamic_result")

    return AnalysisResponse(
        sha256=result["sha256"],
        package_name=result["package_name"],
        app_name=result.get("app_name"),
        version_name=result.get("version_name"),
        apk_size=result.get("apk_size"),
        created_at=result.get("created_at"),
        analysis_mode=result["analysis_mode"],
        job_id=job_id,
        family_classification=result["family_classification"],
        base_score=result["base_score"],
        ai_confidence_multiplier=result["ai_confidence_multiplier"],
        final_risk_score=result["final_risk_score"],
        risk_band=result["risk_band"],
        confidence=result.get("confidence", 70.0),
        recommended_action=result.get("recommended_action", ""),
        frs_breakdown=frs_model,
        risk_explanation=_build_risk_explanation(result.get("risk_explanation")),
        threat_scenario_table=scenario_rows,
        all_permissions=result["all_permissions"],
        hardcoded_urls_ips=result["hardcoded_urls_ips"],
        targets_indian_banks=result["targets_indian_banks"],
        has_accessibility_abuse=result["has_accessibility_abuse"],
        has_sms_read_write=result["has_sms_read_write"],
        has_system_alert_window=result["has_system_alert_window"],
        obfuscation_score=result.get("obfuscation_score", 0.0),
        has_reflection=result.get("has_reflection", False),
        threat_correlation=_build_correlation_model(result["threat_correlation"]),
        dynamic_analysis=_build_dynamic_analysis_model(dynamic_result),
        dynamic_available=result["dynamic_available"],
        manifest_findings=result["manifest_findings"],
        code_findings=result["code_findings"],
        dangerous_permissions=_coerce_dangerous_permissions(result.get("dangerous_perms")),
        activities=result["activities"],
        services=result["services_list"],
        receivers=result["receivers"],
        certificate=result["certificate"],
        domains=result["domains"],
        hardcoded_secrets=result["hardcoded_secrets"],
        appsec_score=result.get("appsec_score"),
        mobsf_scan_hash=result.get("mobsf_scan_hash"),
        apktool_enrichment=result.get("apktool_enrichment"),
        jadx_enrichment=result.get("jadx_enrichment"),
        # MobSF enrichment fields
        providers=result.get("providers", []),
        exported_activities=result.get("exported_activities", []),
        exported_services=result.get("exported_services", []),
        exported_receivers=result.get("exported_receivers", []),
        binary_analysis=result.get("binary_analysis", []),
        network_security=result.get("network_security", {}),
        trackers=result.get("trackers", []),
        emails=result.get("emails", []),
        intelligence_report=intel_report,
        fraud_workflow=_build_fraud_workflow(result.get("fraud_workflow")),
        vide=result.get("vide"),
        executive_view=executive_view,
        technical_view=technical_view,
    )


# ─── Sync Endpoint ────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalysisResponse)
@limiter.limit("10/minute")
async def analyze_upload(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(require_analyst),
):
    """
    Synchronous APK analysis - waits for full result before returning.
    Requires JWT Bearer token (any analyst role).
    """
    from app.db.database import count_pending_jobs, count_user_jobs_today
    
    max_queue = int(os.getenv("MAX_QUEUE_DEPTH", "1000"))
    user_quota = int(os.getenv("USER_QUOTA_PER_DAY", "1000"))
    
    import uuid
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    
    from app.db.database import reserve_job_slot_atomically
    reserve_res = await reserve_job_slot_atomically(
        job_id=job_id,
        analyst_id=user.get("id") or 0,
        user_quota=user_quota,
        max_queue=max_queue
    )
    if reserve_res == "QUEUE_FULL":
        raise HTTPException(status_code=429, detail="Analysis capacity is full. Please try again later.")
    elif reserve_res == "QUOTA_EXCEEDED":
        raise HTTPException(status_code=429, detail=f"Daily quota of {user_quota} analyses exceeded.")

    object_key, sha256_hash = await _receive_apk(file)
    
    from app.db.database import _connect
    async with _connect() as db:
        await db.execute("UPDATE analysis_jobs SET sha256 = ? WHERE job_id = ?", (sha256_hash, job_id))
        await db.commit()
    
    import tempfile
    import os
    from sudarshan_core.storage.artifact_storage import get_storage
    
    storage = get_storage()
    fd, temp_path = tempfile.mkstemp(suffix=".apk", prefix="sudarshan_sync_")
    os.close(fd)
    
    try:
        await storage.get_file(object_key, temp_path)
    except Exception as e:
        logger.exception(f"Failed to download payload from artifact storage: {e}")
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="Failed to retrieve uploaded file from storage.")

    try:
        result = await _run_analysis_pipeline(
            temp_path=temp_path,
            sha256_hash=sha256_hash,
            analyst_id=user.get("id"),
        )
        return _build_response(result)
    except Exception as e:
        logger.exception(f"Analysis pipeline failed: {e}")
        from app.db.database import _connect
        async with _connect() as db:
            await db.execute("UPDATE analysis_jobs SET status = 'FAILED', error = ? WHERE job_id = ?", (str(e), job_id))
            await db.commit()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        from app.db.database import _connect
        async with _connect() as db:
            await db.execute("UPDATE analysis_jobs SET status = 'COMPLETED' WHERE job_id = ? AND status != 'FAILED'", (job_id,))
            await db.commit()


# ─── Async Endpoint ───────────────────────────────────────────────────────────

from pydantic import BaseModel as _BM


class AsyncJobResponse(_BM):
    job_id: str
    status: str
    message: str


@router.post("/analyze/async", response_model=AsyncJobResponse, status_code=202)
@limiter.limit("10/minute")
async def analyze_upload_async(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(require_analyst),
):
    try:
        from app.db.database import reserve_job_slot_atomically
        
        max_queue = int(os.getenv("MAX_QUEUE_DEPTH", "1000"))
        user_quota = int(os.getenv("USER_QUOTA_PER_DAY", "1000"))
        
        import uuid
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        
        reserve_res = await reserve_job_slot_atomically(
            job_id=job_id,
            analyst_id=user.get("id") or 0,
            user_quota=user_quota,
            max_queue=max_queue
        )
        if reserve_res == "QUEUE_FULL":
            raise HTTPException(status_code=429, detail="Analysis queue is full. Please try again later.")
        elif reserve_res == "QUOTA_EXCEEDED":
            raise HTTPException(status_code=429, detail=f"Daily quota of {user_quota} analyses exceeded.")

        object_key, sha256_hash = await _receive_apk(file)
        # Use the job_id we atomically reserved
        await enqueue(job_id, object_key, file.filename, sha256_hash, analyst_id=user.get("id"))

        return AsyncJobResponse(
            job_id=job_id,
            status="queued",
            message="Analysis job queued. Poll /api/v1/status/{job_id} for result.",
        )
    except Exception as e:
        import traceback
        logger.error(f"Error in analyze_upload_async: {e}")
        logger.error(traceback.format_exc())
        raise


@router.get("/status/{job_id}")
async def job_status(job_id: str, user: dict = Depends(require_analyst)):
    """Poll the status of an async analysis job."""
    job = await get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    response: Dict[str, Any] = {
        "job_id": job_id,
        "status": job["status"],
        "queued_at": job.get("queued_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
    }

    if job["status"] == "done":
        response["result"] = job.get("result")
        response["progress_pct"] = 100
    elif job["status"] == "failed":
        response["error"] = job.get("error")
    else:
        response["progress_pct"] = job.get("progress_pct", 0)
        response["pipeline_stage"] = job.get("pipeline_stage")
        response["pipeline_substage"] = job.get("pipeline_substage")
        response["pipeline_message"] = job.get("pipeline_message")
        response["elapsed_ms"] = job.get("elapsed_ms")

    return response


@router.post("/analyze/cancel/{job_id}")
async def cancel_analysis_job(job_id: str, user: dict = Depends(require_analyst)):
    """Cancel an async analysis job in-flight or queued."""
    from app.workers.analysis_queue import cancel_job
    job = await get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    await cancel_job(job_id)
    return {
        "job_id": job_id,
        "status": "cancelled",
        "message": "Analysis cancelled.",
    }


# ─── Sandbox Status & Debug Endpoints ──────────────────────────────────────────

@router.get("/sandbox/status")
async def sandbox_status(user: dict = Depends(require_analyst)):
    """
    Returns the current status of the Frida dynamic analysis sandbox.
    Check this endpoint before running dynamic analysis.
    """
    return get_sandbox_status()


@router.get("/sandbox/debug/{case_id}")
async def sandbox_debug(case_id: str, user: dict = Depends(require_analyst)):
    """
    Returns live pipeline state machine diagnostics, telemetry, SLA budgets, and hook coverage.

    READ-ONLY. This previously called `get_tracker(case_id)`, which CREATES and
    stores a PipelineTracker when the key is absent - in a module-global dict
    whose eviction helper had no callers. So `GET /sandbox/debug/<random>` in a
    loop grew that dict by one tracker per request until the process OOMed,
    reachable with any analyst token. Look the tracker up; do not mint one.
    """
    from sudarshan_core.engines.pipeline_state import peek_tracker
    tracker = peek_tracker(case_id)
    if tracker is None:
        raise HTTPException(
            status_code=404,
            detail=f"No active analysis session for case '{case_id}'.",
        )
    return tracker.get_diagnostics()

