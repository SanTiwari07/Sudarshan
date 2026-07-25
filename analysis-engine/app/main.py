"""
SUDARSHAN — Standalone Analysis Engine Microservice
===================================================
FastAPI REST microservice responsible for executing all static & dynamic
APK analysis operations inside the containerized environment.

Port: 8001
Internal URL: http://analysis-engine:8001
"""

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
import uuid
from typing import Any, Dict, Optional
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile, BackgroundTasks, Query
from pydantic import BaseModel, Field

# Imports from app modules
from app.analyzers.apk_analyzer import analyze_apk
from app.engines.apktool_engine import ApktoolEngine
from app.engines.jadx_engine import JadxEngine
from app.engines.frida_sandbox import run_frida_analysis
from app.engines.network_capture import NetworkCapture
from app.engines.risk_engine import compute_fraud_risk_score
from app.models.manifest import build_manifest
from app.services.mobsf_client import mobsf_scan
from app.services.threat_correlator import correlate_threat_intel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("analysis-engine")

app = FastAPI(
    title="Sudarshan APK Analysis Engine Microservice",
    version="2.3.0",
    description="Containerized analysis engine executing APKTool, JADX, Androguard, Frida, and ADB."
)

DEFAULT_TIMEOUT_SECONDS = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "300"))
UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory thread-safe job store for async analysis jobs
JOBS: Dict[str, Dict[str, Any]] = {}


# ─── Data Contracts ───────────────────────────────────────────────────────────

class AnalyzePathRequest(BaseModel):
    file_path: str = Field(..., description="Absolute path to APK file in shared volume")
    sha256: Optional[str] = None
    timeout_seconds: Optional[int] = Field(default=DEFAULT_TIMEOUT_SECONDS, description="Per-request analysis timeout in seconds")


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress_pct: int = 0
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


# ─── Health & Status Endpoints ────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "analysis-engine"}


@app.get("/status")
def status():
    apktool = ApktoolEngine()
    jadx = JadxEngine()
    
    # Check ADB device status
    adb_connected = False
    try:
        import subprocess
        res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=3)
        adb_connected = "device" in res.stdout and "emulator" in res.stdout
    except Exception:
        pass

    return {
        "status": "ready",
        "tools": {
            "apktool": apktool.is_available(),
            "jadx": jadx.is_available(),
            "androguard": True,
            "adb_connected": adb_connected,
        },
        "uploads_dir": str(UPLOADS_DIR),
        "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    }


# ─── Core Analysis Pipeline Execution ────────────────────────────────────────

async def _execute_analysis_pipeline(
    apk_path: str,
    sha256_hash: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Execute the full static & dynamic analysis pipeline with hard timeout protection."""
    logger.info(f"[Engine] Executing analysis pipeline for SHA-256: {sha256_hash} (Timeout: {timeout_seconds}s)")

    async def _run():
        # 1. Primary Static Analysis via Androguard / MobSF
        flags = analyze_apk(apk_path)
        mobsf_res = await mobsf_scan(apk_path) if os.getenv("MOBSF_HOST") else None

        flags_dict = {
            "dangerous_permissions": flags.dangerous_permissions,
            "all_permissions": flags.all_permissions,
            "activities": flags.activities,
            "services_list": flags.services_list,
            "receivers": flags.receivers,
            "dangerous_apis_found": flags.dangerous_apis_found,
            "hardcoded_urls_ips": flags.hardcoded_urls_ips,
            "targets_indian_banks": flags.targets_indian_banks,
            "indian_bank_packages_found": getattr(flags, "indian_bank_packages_found", []),
            "obfuscation_score": getattr(flags, "obfuscation_score", 0.0),
            "has_reflection": getattr(flags, "has_reflection", False),
            "has_accessibility_abuse": getattr(flags, "has_accessibility_abuse", False),
            "has_sms_read_write": getattr(flags, "has_sms_read_write", False),
            "has_system_alert_window": getattr(flags, "has_system_alert_window", False),
        }

        # 2. Standalone Static Enrichment (APKTool + JADX)
        apktool = ApktoolEngine()
        jadx = JadxEngine()

        apktool_res = apktool.analyze(apk_path) if apktool.is_available() else None
        jadx_res = jadx.analyze(apk_path) if jadx.is_available() else None

        if apktool_res and apktool_res.decoded_manifest_xml:
            flags_dict["decoded_manifest_xml"] = apktool_res.decoded_manifest_xml
        if jadx_res and jadx_res.fraud_class_hits:
            flags_dict["jadx_fraud_hits"] = jadx_res.fraud_class_hits

        # 3. Investigation Manifest Generation
        manifest = build_manifest(
            sha256=sha256_hash,
            package_name=flags.package_name,
            flags_dict=flags_dict,
            analysis_mode="androguard",
        )

        manifest_dir = UPLOADS_DIR / sha256_hash
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest.to_file(manifest_dir / "manifest.json")

        # 4. Dynamic Sandbox Analysis via Frida & ADB
        duration = int(os.getenv("FRIDA_ANALYSIS_DURATION", "30"))
        dynamic_result = run_frida_analysis(
            apk_path=apk_path,
            package_name=flags.package_name,
            duration=duration,
        )

        # 5. mitmproxy HAR Net Ingest
        har_path = os.getenv("MITMPROXY_HAR_PATH")
        if har_path and os.path.exists(har_path):
            try:
                nc = NetworkCapture()
                added = nc.ingest_mitmproxy_har(har_path)
                if dynamic_result and isinstance(dynamic_result, dict):
                    dynamic_result["mitmproxy_flows_added"] = added
            except Exception as e:
                logger.warning(f"[Engine] mitmproxy HAR ingest notice: {e}")

        # 6. Threat Correlation & Risk Scoring
        threat_corr = correlate_threat_intel(
            sha256=sha256_hash,
            urls=flags.hardcoded_urls_ips,
            package_name=flags.package_name,
        )

        risk_output = compute_fraud_risk_score(
            flags=flags,
            dynamic_result=dynamic_result,
            threat_corr=threat_corr,
        )

        return {
            "sha256": sha256_hash,
            "package_name": flags.package_name,
            "app_name": getattr(flags, "app_name", None),
            "analysis_mode": "androguard",
            "family_classification": risk_output.get("family_classification", "Unknown"),
            "base_score": risk_output["base_score"],
            "ai_confidence_multiplier": risk_output["ai_confidence_multiplier"],
            "final_risk_score": risk_output["final_risk_score"],
            "risk_band": risk_output["risk_band"],
            "confidence": risk_output.get("confidence", 70.0),
            "recommended_action": risk_output.get("recommended_action", ""),
            "frs_breakdown": risk_output.get("frs_breakdown", {}),
            "threat_scenario_table": risk_output.get("threat_scenario_table", []),
            "all_permissions": flags.all_permissions,
            "dangerous_perms": flags.dangerous_permissions,
            "hardcoded_urls_ips": flags.hardcoded_urls_ips,
            "targets_indian_banks": flags.targets_indian_banks,
            "has_accessibility_abuse": getattr(flags, "has_accessibility_abuse", False),
            "has_sms_read_write": getattr(flags, "has_sms_read_write", False),
            "has_system_alert_window": getattr(flags, "has_system_alert_window", False),
            "obfuscation_score": getattr(flags, "obfuscation_score", 0.0),
            "has_reflection": getattr(flags, "has_reflection", False),
            "threat_correlation": threat_corr,
            "dynamic_result": dynamic_result,
            "dynamic_available": dynamic_result.get("available", False) if dynamic_result else False,
            "fraud_workflow": dynamic_result.get("fraud_workflow") if dynamic_result else None,
            "manifest_findings": [],
            "code_findings": [],
            "activities": flags.activities,
            "services_list": flags.services_list,
            "receivers": flags.receivers,
            "certificate": getattr(flags, "certificate", {}),
            "domains": getattr(flags, "domains", []),
            "hardcoded_secrets": getattr(flags, "hardcoded_secrets", []),
            "appsec_score": getattr(flags, "appsec_score", 50.0),
            "mobsf_scan_hash": mobsf_res.get("hash") if mobsf_res else None,
        }

    try:
        return await asyncio.wait_for(_run(), timeout=float(timeout_seconds))
    except asyncio.TimeoutError:
        logger.error(f"[Engine] Analysis hard timeout exceeded ({timeout_seconds}s) for {sha256_hash}")
        raise HTTPException(
            status_code=408,
            detail=f"Analysis engine timeout exceeded ({timeout_seconds}s). Execution killed to protect container resources."
        )


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.post("/api/v1/analyze")
async def analyze_path(req: AnalyzePathRequest):
    """
    Synchronous analysis endpoint — accepts shared volume file path and returns full JSON.
    """
    file_path = Path(req.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found in shared volume: {req.file_path}")

    sha256_hash = req.sha256
    if not sha256_hash:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        sha256_hash = hasher.hexdigest()

    return await _execute_analysis_pipeline(
        apk_path=str(file_path),
        sha256_hash=sha256_hash,
        timeout_seconds=req.timeout_seconds or DEFAULT_TIMEOUT_SECONDS,
    )


@app.post("/api/v1/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    """
    Direct file upload analysis endpoint.
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .apk files are allowed.")

    hasher = hashlib.sha256()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=UPLOADS_DIR) as tmp:
        while chunk := await file.read(1024 * 1024 * 8):
            hasher.update(chunk)
            tmp.write(chunk)
        temp_path = tmp.name

    sha256_hash = hasher.hexdigest()
    try:
        return await _execute_analysis_pipeline(
            apk_path=temp_path,
            sha256_hash=sha256_hash,
        )
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.post("/api/v1/analyze/async")
async def analyze_async(
    req: AnalyzePathRequest,
    background_tasks: BackgroundTasks,
):
    """
    Asynchronous job submission endpoint — returns job_id for polling.
    """
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        "job_id": job_id,
        "status": "QUEUED",
        "progress_pct": 10,
        "error": None,
        "result": None,
    }

    async def _async_task():
        JOBS[job_id]["status"] = "RUNNING"
        JOBS[job_id]["progress_pct"] = 30
        try:
            res = await _execute_analysis_pipeline(
                apk_path=req.file_path,
                sha256_hash=req.sha256 or "unknown",
                timeout_seconds=req.timeout_seconds or DEFAULT_TIMEOUT_SECONDS,
            )
            JOBS[job_id]["status"] = "COMPLETED"
            JOBS[job_id]["progress_pct"] = 100
            JOBS[job_id]["result"] = res
        except Exception as e:
            JOBS[job_id]["status"] = "FAILED"
            JOBS[job_id]["error"] = str(e)

    background_tasks.add_task(_async_task)
    return {"job_id": job_id, "status": "QUEUED"}


@app.get("/api/v1/status/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str):
    """Poll status of asynchronous analysis job."""
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job ID not found")
    return JOBS[job_id]
