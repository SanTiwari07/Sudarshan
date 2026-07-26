# backend/app/routes/upload.py
"""
Sudarshan Upload & Analysis Pipeline
======================================
Full pipeline:
  APK → MobSF (or Androguard fallback) → Frida (if ready) → Threat Correlation → Risk Engine → RAG → Ollama → Response

Endpoints:
  POST /api/v1/analyze        — sync analysis (returns full result immediately)
  POST /api/v1/analyze/async  — async analysis (returns job_id; poll /status/{job_id})
  GET  /api/v1/status/{job_id}— poll async job
  GET  /api/v1/sandbox/status — Frida sandbox status
"""

import hashlib
import logging
import os
import tempfile
import asyncio
from pathlib import Path
import httpx
from typing import Any, Dict, Optional

UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.ai.ollama_client import analyze_with_llm
from app.analyzers.apk_analyzer import analyze_apk
from app.auth.auth import get_current_user, require_analyst
from app.db.database import save_case
from app.engines.classification_engine import classify_family
from app.engines.frida_sandbox import get_sandbox_status, run_frida_analysis
from app.engines.risk_engine import calculate_risk_score
from app.models.schemas import (
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
    StaticAnalysisFlags,
    ThreatCorrelationResult,
    ThreatScenarioRow,
    WorkflowStage,
)
from app.rag.knowledge_base import build_rag_context  # noqa: F401
from app.ai.gemini_rag import build_investigation_index
from app.routes.report import cache_report
from app.services.mobsf_client import MobSFAnalysisError, MobSFClient, MobSFNotAvailable
from app.services.threat_correlator import correlate
from app.workers.analysis_queue import create_job, enqueue, get_job
from app.models.manifest import build_manifest, InvestigationManifest
from app.engines.frida_sandbox import artifact_dir_for

logger = logging.getLogger(__name__)
router = APIRouter()

_mobsf = MobSFClient()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _flags_to_dict(flags: Any) -> Dict[str, Any]:
    """Convert StaticAnalysisFlags to plain dict."""
    return {
        "has_accessibility_abuse": flags.has_accessibility_abuse,
        "has_sms_read_write": flags.has_sms_read_write,
        "has_system_alert_window": flags.has_system_alert_window,
        "dangerous_apis_found": flags.dangerous_apis_found,
        "hardcoded_urls_ips": flags.hardcoded_urls_ips,
        "targets_indian_banks": flags.targets_indian_banks,
        "indian_bank_packages_found": getattr(flags, "indian_bank_packages_found", []),
        "obfuscation_score": getattr(flags, "obfuscation_score", 0.0),
        "has_reflection": getattr(flags, "has_reflection", False),
    }


def _build_correlation_model(raw: Dict) -> ThreatCorrelationResult:
    """Convert raw correlator dict → Pydantic model."""
    ioc_list = []
    for ioc in raw.get("ioc_reputation", []):
        try:
            ioc_list.append(IOCReputation(**ioc))
        except Exception:
            pass
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
    )


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


async def _call_analysis_engine(temp_path: str, sha256_hash: str) -> Optional[Dict[str, Any]]:
    """Call containerized analysis-engine microservice via REST over Docker network."""
    url = f"{ANALYSIS_ENGINE_URL}/api/v1/analyze"
    try:
        async with httpx.AsyncClient(timeout=310.0) as client:
            resp = await client.post(url, json={"file_path": temp_path, "sha256": sha256_hash})
            if resp.status_code == 200:
                logger.info(f"[Orchestrator] Analysis engine microservice returned 200 OK for {sha256_hash}")
                return resp.json()
            else:
                logger.warning(f"[Orchestrator] Analysis engine returned status {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.info(f"[Orchestrator] Containerized analysis engine unavailable ({e}); executing fallback pipeline locally.")
    return None


# ─── Core Analysis Logic (shared by sync + async) ────────────────────────────

async def _run_analysis_pipeline(
    temp_path: str,
    sha256_hash: str,
    analyst_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Full analysis pipeline. Returns a dict that can be serialised as AnalysisResponse.
    Delegates to analysis-engine microservice if available.
    """
    # 1. Attempt containerized microservice execution first
    engine_result = await _call_analysis_engine(temp_path, sha256_hash)
    if engine_result:
        return engine_result

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

    mobsf_available = await _mobsf.is_available()

    if mobsf_available:
        try:
            logger.info("MobSF available — using MobSF analysis engine")
            mobsf_report = await _mobsf.analyze(temp_path)
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

        except (MobSFAnalysisError, MobSFNotAvailable) as e:
            logger.warning(f"MobSF failed ({e}), falling back to Androguard")
            mobsf_available = False

    if not mobsf_available:
        logger.info("Using Androguard fallback")
        androguard_output = await asyncio.to_thread(analyze_apk, temp_path)
        package_name = androguard_output.package_name
        all_permissions = androguard_output.permissions or []
        flags_dict = _flags_to_dict(androguard_output.flags)
        suspicious_strings = androguard_output.suspicious_strings

    # ── STEP 1.5a: APKTool + JADX Enrichment (optional, gracefully skipped if not installed) ──
    apktool_result = None
    jadx_result = None
    try:
        from app.engines.apktool_engine import ApktoolEngine
        from app.engines.jadx_engine import JadxEngine
        _apktool = ApktoolEngine()
        _jadx = JadxEngine()
        if _apktool.is_available():
            apktool_result = await asyncio.to_thread(_apktool.analyze, temp_path)
            if apktool_result.available:
                # Enrich suspicious_strings with resource-level URL hits
                suspicious_strings = list(dict.fromkeys(
                    suspicious_strings + apktool_result.resource_strings
                ))[:100]
                logger.info(
                    f"[APKTool] Enrichment: {len(apktool_result.suspicious_resources)} suspicious resources, "
                    f"{apktool_result.obfuscated_resource_count} obfuscated names"
                )
        if _jadx.is_available():
            jadx_result = await asyncio.to_thread(_jadx.analyze, temp_path)
            if jadx_result.available:
                # Promote JADX-detected fraud patterns into flags_dict
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
                # Merge JADX-extracted URL strings
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
        logger.info(
            f"[Manifest] Generated: hook_profiles={manifest.hook_profiles}, "
            f"priorities={{A:{manifest.goal_priority_config.accessibility_priority},"
            f"S:{manifest.goal_priority_config.sms_priority},"
            f"O:{manifest.goal_priority_config.overlay_priority}}}"
        )
    except Exception as e:
        logger.warning(f"[Manifest] Manifest generation failed (non-critical): {e}")

    # ── STEP 1.5c: Frida Dynamic Analysis ────────────────────────────────────
    dynamic_result: Optional[Dict] = None
    frida_status = get_sandbox_status()

    if frida_status["ready"]:
        logger.info("Frida sandbox ready — running dynamic behavioral analysis")
        try:
            use_multistage = os.getenv("SUDARSHAN_MULTISTAGE", "false").lower() == "true"
            if use_multistage:
                from app.engines.multi_stage_engine import MultiStageEngine
                engine = MultiStageEngine(apk_path=temp_path, package_name=package_name)
                dynamic_result = await engine.run_all_stages()
            else:
                from app.engines.frida_sandbox import run_frida_analysis
                dynamic_result = await run_frida_analysis(temp_path, package_name=package_name)
            if dynamic_result.get("available"):
                logger.info(f"Frida BFCI={dynamic_result.get('bfci', 0):.1f}")
            else:
                logger.warning(f"Frida did not complete: {dynamic_result.get('error')}")
                dynamic_result = None
        except Exception as e:
            logger.warning(f"Frida analysis failed: {e}")
            dynamic_result = None
    else:
        logger.info(f"Frida sandbox not ready ({frida_status['message']})")

    # ── STEP 2: Classification ────────────────────────────────────────────────
    flags_model = StaticAnalysisFlags(**flags_dict)
    family_class, matched_rule = classify_family(flags_model)
    ai_confidence = 1.0 if family_class == "Unknown" else 1.2

    # ── STEP 3: Threat Correlation ────────────────────────────────────────────
    logger.info("Running threat correlation...")
    try:
        correlation_raw = await correlate(
            sha256=sha256_hash,
            urls=flags_dict.get("hardcoded_urls_ips", []),
            package_name=package_name,
        )
    except Exception as e:
        logger.warning(f"Threat correlation failed: {e}")
        correlation_raw = {"available": False}

    if correlation_raw.get("known_family") and family_class == "Unknown":
        family_class = correlation_raw["known_family"]
        ai_confidence = 1.15

    # ── STEP 4: Risk Scoring (5-axis STEI) ───────────────────────────────────
    risk_result = calculate_risk_score(
        flags=flags_dict,
        ai_confidence=ai_confidence,
        dynamic_result=dynamic_result,
        correlation_result=correlation_raw,
        family=family_class,
        all_permissions=all_permissions,
    )

    # ── STEP 5: RAG + Ollama Intelligence ────────────────────────────────────
    logger.info("Running RAG-grounded LLM analysis...")
    llm_response = await analyze_with_llm(
        flags=flags_dict,
        family=family_class,
        matched_rule=matched_rule,
        package_name=package_name,
        risk_result=risk_result,
        correlation=correlation_raw,
        dynamic=dynamic_result,
    )

    # ── Assemble result dict ──────────────────────────────────────────────────
    result = {
        "sha256": sha256_hash,
        "package_name": package_name,
        "dangerous_apis_found_raw": flags_dict.get("dangerous_apis_found", []),
        "app_name": mobsf_report.get("app_name") if mobsf_report else None,
        "analysis_mode": analysis_mode,
        "family_classification": family_class,
        "base_score": risk_result["base_score"],
        "ai_confidence_multiplier": risk_result["ai_confidence_multiplier"],
        "final_risk_score": risk_result["final_risk_score"],
        "risk_band": risk_result["risk_band"],
        "confidence": risk_result.get("confidence", 70.0),
        "recommended_action": risk_result.get("recommended_action", ""),
        "frs_breakdown": risk_result.get("frs_breakdown", {}),
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
        "dynamic_available": bool(dynamic_result and dynamic_result.get("available")),
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

    # ── Persist to DB ─────────────────────────────────────────────────────────
    await save_case(sha256_hash, result, analyst_id=analyst_id)

    # ── Cache for export endpoints ────────────────────────────────────────────
    report_cache_data = {
        "sha256": sha256_hash,
        "package_name": package_name,
        "family_classification": family_class,
        "final_risk_score": risk_result["final_risk_score"],
        "risk_band": risk_result["risk_band"],
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

    return result


def _build_response(result: Dict[str, Any], job_id: Optional[str] = None) -> AnalysisResponse:
    """Convert raw pipeline result dict into AnalysisResponse Pydantic model."""
    llm_response = result["intelligence_report"]

    executive_view = FraudCardExecutiveView(
        risk_badge=result["risk_band"],
        plain_english_narrative=llm_response.get("plain_english_narrative", "Analysis unavailable."),
        recommended_actions=llm_response.get("recommended_actions", []),
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
        affected_banking_apps=llm_response.get("affected_banking_apps", []),
        mitre_techniques_used=llm_response.get("mitre_techniques_used", []),
        banking_impact_assessment=llm_response.get("banking_impact_assessment"),
        cert_in_recommendations=llm_response.get("cert_in_recommendations", []),
        recommended_actions=llm_response.get("recommended_actions", []),
        customer_advisory_draft=llm_response.get("customer_advisory_draft", ""),
        confidence=llm_response.get("confidence", "Medium"),
        analysis_note=llm_response.get("analysis_note"),
    )

    frs_bd = result.get("frs_breakdown", {})
    frs_model = FRSBreakdown(
        stei=frs_bd.get("stei", 0.0),
        dynamic=frs_bd.get("dynamic", 0.0),
        correlation=frs_bd.get("correlation", 0.0),
        banking_impact=frs_bd.get("banking_impact", 0.0),
        formula_used=frs_bd.get("formula_used", "static_only_frs"),
        dynamic_available=frs_bd.get("dynamic_available", False),
        stei_axes=frs_bd.get("stei_axes", {}),
    )

    scenario_rows = [
        ThreatScenarioRow(**row)
        for row in result.get("threat_scenario_table", [])
    ]

    dynamic_result = result.get("dynamic_result")

    return AnalysisResponse(
        sha256=result["sha256"],
        package_name=result["package_name"],
        app_name=result.get("app_name"),
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
        dynamic_analysis=DynamicAnalysisResult(
            available=dynamic_result.get("available", False) if dynamic_result else False,
            activities_triggered=dynamic_result.get("activities_triggered", []) if dynamic_result else [],
            network_logs=dynamic_result.get("network_logs", []) if dynamic_result else [],
            api_calls=dynamic_result.get("api_calls", []) if dynamic_result else [],
            files_accessed=dynamic_result.get("files_accessed", []) if dynamic_result else [],
            screenshots=dynamic_result.get("screenshots", []) if dynamic_result else [],
            logcat=dynamic_result.get("logcat", "") if dynamic_result else "",
            multi_stage_summary=dynamic_result.get("multi_stage_summary", {}) if dynamic_result else {},
            coverage_metrics=dynamic_result.get("coverage_metrics", {}) if dynamic_result else {},
            attack_timeline=dynamic_result.get("attack_timeline", []) if dynamic_result else [],
            clicked_nodes=list(dynamic_result.get("clicked_nodes", [])) if dynamic_result else [],
            anti_analysis_events=dynamic_result.get("anti_analysis_events", []) if dynamic_result else [],
            yara_matches=dynamic_result.get("yara_matches", []) if dynamic_result else [],
        ) if dynamic_result else None,
        dynamic_available=result["dynamic_available"],
        manifest_findings=result["manifest_findings"],
        code_findings=result["code_findings"],
        dangerous_permissions=result["dangerous_perms"],
        activities=result["activities"],
        services=result["services_list"],
        receivers=result["receivers"],
        certificate=result["certificate"],
        domains=result["domains"],
        hardcoded_secrets=result["hardcoded_secrets"],
        appsec_score=result.get("appsec_score"),
        mobsf_scan_hash=result.get("mobsf_scan_hash"),
        intelligence_report=intel_report,
        fraud_workflow=_build_fraud_workflow(result.get("fraud_workflow")),
        executive_view=executive_view,
        technical_view=technical_view,
    )


# ─── Sync Endpoint ────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    user: dict = Depends(require_analyst),
):
    """
    Synchronous APK analysis — waits for full result before returning.
    Requires JWT Bearer token (any analyst role).
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .apk files are allowed.")

    hasher = hashlib.sha256()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=str(UPLOADS_DIR)) as tmp:
        while True:
            chunk = await file.read(1024 * 1024 * 8) # 8MB chunks
            if not chunk:
                break
            hasher.update(chunk)
            tmp.write(chunk)
        temp_path = tmp.name

    sha256_hash = hasher.hexdigest()

    try:
        result = await _run_analysis_pipeline(
            temp_path=temp_path,
            sha256_hash=sha256_hash,
            analyst_id=user.get("id"),
        )
        return _build_response(result)
    except Exception as e:
        logger.exception(f"Analysis pipeline failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass


# ─── Async Endpoint ───────────────────────────────────────────────────────────

from pydantic import BaseModel as _BM


class AsyncJobResponse(_BM):
    job_id: str
    status: str
    message: str


@router.post("/analyze/async", response_model=AsyncJobResponse, status_code=202)
async def analyze_upload_async(
    file: UploadFile = File(...),
    user: dict = Depends(require_analyst),
):
    """
    Asynchronous APK analysis — returns job_id immediately.
    Poll GET /api/v1/status/{job_id} to get result.
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .apk files are allowed.")

    hasher = hashlib.sha256()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=str(UPLOADS_DIR)) as tmp:
        while True:
            chunk = await file.read(1024 * 1024 * 8)
            if not chunk:
                break
            hasher.update(chunk)
            tmp.write(chunk)
        temp_path = tmp.name
        
    sha256_hash = hasher.hexdigest()

    job_id = create_job()
    await enqueue(job_id, temp_path, file.filename, sha256_hash, analyst_id=user.get("id"))

    return AsyncJobResponse(
        job_id=job_id,
        status="queued",
        message="Analysis job queued. Poll /api/v1/status/{job_id} for result.",
    )


@router.get("/status/{job_id}")
async def job_status(job_id: str, user: dict = Depends(require_analyst)):
    """Poll the status of an async analysis job."""
    job = get_job(job_id)
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
    elif job["status"] == "failed":
        response["error"] = job.get("error")

    return response


# ─── Sandbox Status Endpoint ──────────────────────────────────────────────────

@router.get("/sandbox/status")
async def sandbox_status():
    """
    Returns the current status of the Frida dynamic analysis sandbox.
    Check this endpoint before running dynamic analysis.
    """
    return get_sandbox_status()
