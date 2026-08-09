"""
SUDARSHAN - Standalone Analysis Engine Microservice
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
import time
import uuid
from typing import Any, Dict, Optional
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from root .env file
_env_path = Path(__file__).resolve().parents[2] / ".env"
if not _env_path.exists():
    _env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)

from fastapi import FastAPI, File, HTTPException, UploadFile, BackgroundTasks, Query
from pydantic import BaseModel, Field

# Imports from app modules
from sudarshan_core.analyzers.apk_analyzer import analyze_apk
from sudarshan_core.engines.apktool_engine import ApktoolEngine
from sudarshan_core.engines.jadx_engine import JadxEngine
from sudarshan_core.engines.frida_sandbox import run_frida_analysis
from sudarshan_core.engines.network_capture import NetworkCapture
from sudarshan_core.engines.risk_engine import calculate_risk_score as compute_fraud_risk_score
from sudarshan_core.engines.vide import run_vide_analysis
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.models.manifest import build_manifest
from sudarshan_core.services.mobsf_client import MobSFAnalysisError, MobSFClient, MobSFNotAvailable
from sudarshan_core.services.threat_correlator import correlate, extract_dynamic_urls

# ─── Structured Logging Configuration ───────────────────────────────────────
# CRITICAL: Androguard at DEBUG level generates tens of thousands of log records
# per analysis (one per basic block per method per DEX). Each log record holds
# references to the call-site arguments, which keeps the entire DEX parse tree
# in memory indefinitely. On a 3.5 MB APK this alone can consume 2-3 GB.
# The container is capped at 4 GB; anything larger triggers Docker's OOM killer
# (exit 137) and takes the backend with it (dependency health-check fails).
#
# Androguard must run at WARNING in production. All Sudarshan subsystems use
# INFO so their operational logs are visible without the DEX-parser noise.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
# Silence heavy third-party loggers that produce noise without value
for _noisy in ("androguard", "androguard.core", "androguard.core.analysis",
               "androguard.core.bytecodes", "androguard.core.analysis.analysis",
               "androguard.core.axml"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

try:
    import loguru
    loguru.logger.disable("androguard")
except ImportError:
    pass

logger = logging.getLogger("analysis-engine")

# Per-subsystem structured loggers used throughout this module
_log_mobsf   = logging.getLogger("[MOBSF]")
_log_frida   = logging.getLogger("[FRIDA]")
_log_adb     = logging.getLogger("[ADB]")
_log_analysis = logging.getLogger("[ANALYSIS]")
_log_risk    = logging.getLogger("[RISK]")

app = FastAPI(
    title="Sudarshan APK Analysis Engine Microservice",
    version="2.3.0",
    description="Containerized analysis engine executing APKTool, JADX, Androguard, Frida, and ADB."
)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sudarshan_core.security.internal_auth import HEADER_NAME, internal_service_token


class _InternalServiceAuthMiddleware(BaseHTTPMiddleware):
    """Optional shared-secret gate for every route except health/status/docs."""

    _PUBLIC = frozenset({"/health", "/status", "/openapi.json", "/docs", "/redoc"})

    async def dispatch(self, request, call_next):
        if request.url.path in self._PUBLIC:
            return await call_next(request)
        expected = internal_service_token()
        if not expected:
            if os.getenv("SUDARSHAN_ENV", "").strip().lower() == "production":
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": (
                            "Analysis engine refuses unauthenticated requests in "
                            "production. Set ANALYSIS_ENGINE_INTERNAL_TOKEN."
                        )
                    },
                )
            return await call_next(request)
        if request.headers.get(HEADER_NAME) != expected:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        return await call_next(request)


app.add_middleware(_InternalServiceAuthMiddleware)


@app.on_event("startup")
async def _sandbox_containment_startup() -> None:
    """Fail closed in production when ADB/Frida targets bridge the host LAN."""
    from sudarshan_core.sandbox import load_sandbox_config
    from sudarshan_core.security.sandbox_containment import (
        audit_sandbox_connectivity,
        containment_strict_enabled,
        enforce_connectivity_policy,
    )

    cfg = load_sandbox_config()
    if containment_strict_enabled():
        enforce_connectivity_policy(cfg)
        return
    for finding in audit_sandbox_connectivity(cfg):
        log = logger.error if finding.severity == "error" else logger.warning
        log("[Containment] %s: %s", finding.code, finding.message)


DEFAULT_TIMEOUT_SECONDS = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "300"))
UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Tool wrappers are stateless; building them per request re-ran the availability
# probe (a subprocess) on every call, including on /status health polling.
_apktool = ApktoolEngine()
_jadx = JadxEngine()

# Bound how many analyses run at once. Each one occupies a worker thread and
# spawns APKTool/JADX subprocesses, and the container is capped at cpus: 2.0 - # without this, concurrent uploads oversubscribe the CPU and every analysis gets
# slower until they all breach the timeout together.
MAX_CONCURRENT_ANALYSES = int(os.getenv("MAX_CONCURRENT_ANALYSES", "2"))
_analysis_slots = asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)

# ─── Upload limits ────────────────────────────────────────────────────────────
# Uploads were previously unbounded: the read loop ran until the stream ended, so
# one request could fill the shared volume. Real banking APKs top out around
# 150 MB; 200 MB leaves headroom without making disk exhaustion cheap.
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))
UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024      # streaming write size
HASH_CHUNK_BYTES = 64 * 1024              # streaming hash read size

# Every APK is a ZIP archive. Extension checks alone let any file through.
#   PK\x03\x04 local header  ·  PK\x05\x06 empty  ·  PK\x07\x08 spanned
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

# Default when the risk engine returns no confidence of its own.
DEFAULT_CONFIDENCE = 70.0

# ─── Async job store ──────────────────────────────────────────────────────────
# In-process, so it does NOT survive a restart and is not shared across workers.
# entrypoint.sh therefore pins --workers 1; with 2 workers a job created in one
# process 404s from the other. Externalising this (SQLite/Redis) is the real fix
# and is still open - see audit/03_Backend_Audit.md §3.
#
# It also used to grow without bound, holding every completed job's full report
# for the process lifetime. Finished jobs now expire.
JOBS: Dict[str, Dict[str, Any]] = {}
JOB_RETENTION_SECONDS = int(os.getenv("JOB_RETENTION_SECONDS", "3600"))
MAX_RETAINED_JOBS = int(os.getenv("MAX_RETAINED_JOBS", "200"))


def _evict_finished_jobs() -> None:
    """Drop finished jobs past their TTL, then cap total retained jobs."""
    now = time.monotonic()
    for jid in [
        jid for jid, j in JOBS.items()
        if j.get("finished_at") and now - j["finished_at"] > JOB_RETENTION_SECONDS
    ]:
        JOBS.pop(jid, None)

    if len(JOBS) > MAX_RETAINED_JOBS:
        finished = sorted(
            (j for j in JOBS.values() if j.get("finished_at")),
            key=lambda j: j["finished_at"],
        )
        for j in finished[: len(JOBS) - MAX_RETAINED_JOBS]:
            JOBS.pop(j["job_id"], None)


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


def _adb_connected() -> bool:
    """Blocking ADB probe - always call via a worker thread."""
    try:
        from sudarshan_core.sandbox import get_sandbox_provider

        provider = get_sandbox_provider()
        adb = provider.find_adb()
        if not adb:
            return False
        ok, out = provider.adb("devices", timeout=5)
        if not ok:
            return False
        lines = [line.strip() for line in out.splitlines()[1:] if line.strip()]
        return any("device" in line for line in lines)
    except Exception as e:
        logger.warning(f"[Status] ADB check failed: {e}")
        return False


@app.get("/status")
async def status():
    # Every probe here shells out. Run them concurrently off the loop rather
    # than serially on it.
    adb_connected, apktool_ok, jadx_ok = await asyncio.gather(
        asyncio.to_thread(_adb_connected),
        asyncio.to_thread(_apktool.is_available),
        asyncio.to_thread(_jadx.is_available),
    )

    return {
        "status": "ready",
        "tools": {
            "apktool": apktool_ok,
            "jadx": jadx_ok,
            "androguard": True,
            "adb_connected": adb_connected,
        },
        "uploads_dir": str(UPLOADS_DIR),
        "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "max_concurrent_analyses": MAX_CONCURRENT_ANALYSES,
    }


# ─── Core Analysis Pipeline Execution ────────────────────────────────────────

async def _execute_analysis_pipeline(
    apk_path: str,
    sha256_hash: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Execute the full static & dynamic analysis pipeline with hard timeout protection."""
    from sudarshan_core.engines.pipeline_timing import PipelineTimer

    timer = PipelineTimer(job_id=sha256_hash[:12], case_id=sha256_hash)
    logger.info(f"[Engine] Executing analysis pipeline for SHA-256: {sha256_hash} (Timeout: {timeout_seconds}s)")

    async def _run():
        # 1. Primary Static Analysis - Androguard, MobSF, APKTool, JADX in parallel where safe
        async def _run_androguard():
            timer.stage_started("NATIVE_ANALYSIS")
            out = await asyncio.to_thread(analyze_apk, apk_path)
            timer.stage_completed("NATIVE_ANALYSIS")
            return out

        androguard_task = asyncio.create_task(_run_androguard())

        # MobSF is OPTIONAL enrichment. Unguarded, an unreachable MOBSF_HOST
        # raised MobSFAnalysisError straight out of the pipeline and the whole
        # request 500'd - so the gateway silently fell back to its own
        # (toolchain-less) local run. The backend has always guarded this
        # (routes/upload.py); the engine did not.
        mobsf_budget = int(os.getenv("MOBSF_MAX_SECONDS", "0") or "0")

        async def _run_mobsf() -> Optional[Dict[str, Any]]:
            timer.stage_started("MOBSF")
            try:
                client = MobSFClient()
                if mobsf_budget > 0:
                    res = await asyncio.wait_for(
                        client.analyze(apk_path),
                        timeout=float(mobsf_budget),
                    )
                else:
                    res = await client.analyze(apk_path)
                timer.stage_completed("MOBSF")
                return res
            except asyncio.TimeoutError:
                timer.stage_failed("MOBSF", "MOBSF_MAX_SECONDS exceeded")
                logger.warning(
                    "[Engine] MobSF exceeded MOBSF_MAX_SECONDS=%ss; continuing without MobSF",
                    mobsf_budget,
                )
                return None
            except (MobSFAnalysisError, MobSFNotAvailable) as e:
                timer.stage_failed("MOBSF", str(e))
                logger.warning("[Engine] MobSF unavailable, continuing without it: %s", e)
                return None
            except Exception as e:
                timer.stage_failed("MOBSF", str(e))
                logger.warning("[Engine] MobSF failed unexpectedly, continuing without it: %s", e)
                return None

        async def _run_apktool():
            if await asyncio.to_thread(_apktool.is_available):
                timer.stage_started("APKTOOL")
                res = await asyncio.to_thread(_apktool.analyze, apk_path)
                timer.stage_completed("APKTOOL")
                return res
            return None

        async def _run_jadx():
            if await asyncio.to_thread(_jadx.is_available):
                timer.stage_started("JADX")
                res = await asyncio.to_thread(_jadx.analyze, apk_path)
                timer.stage_completed("JADX")
                return res
            return None

        if os.getenv("MOBSF_HOST"):
            androguard_output, mobsf_res, apktool_res, jadx_res = await asyncio.gather(
                androguard_task,
                _run_mobsf(),
                _run_apktool(),
                _run_jadx(),
            )
        else:
            androguard_output, apktool_res, jadx_res = await asyncio.gather(
                androguard_task,
                _run_apktool(),
                _run_jadx(),
            )
            mobsf_res = None

        flags = androguard_output.flags
        package_name = androguard_output.package_name
        permissions = androguard_output.permissions or []

        flags_dict = {
            "dangerous_permissions": permissions,
            "all_permissions": permissions,
            "activities": [],
            "services_list": [],
            "receivers": [],
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

        if apktool_res and apktool_res.decoded_manifest_xml:
            flags_dict["decoded_manifest_xml"] = apktool_res.decoded_manifest_xml
        if jadx_res and jadx_res.fraud_class_hits:
            flags_dict["jadx_fraud_hits"] = jadx_res.fraud_class_hits

        # 3. Investigation Manifest Generation (blocking disk I/O)
        analysis_mode_str = "androguard+mobsf" if mobsf_res else "androguard"
        timer.stage_started("MANIFEST")
        manifest = await asyncio.to_thread(
            build_manifest,
            sha256=sha256_hash,
            package_name=package_name,
            flags_dict=flags_dict,
            analysis_mode=analysis_mode_str,
            all_permissions=permissions,
            dangerous_permissions=(mobsf_res or {}).get("dangerous_permissions", []),
            activities=(mobsf_res or {}).get("activities", []),
            services=(mobsf_res or {}).get("services", []),
            receivers=(mobsf_res or {}).get("receivers", []),
        )

        manifest_dir = UPLOADS_DIR / sha256_hash
        await asyncio.to_thread(manifest_dir.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(manifest.to_file, manifest_dir / "manifest.json")
        timer.stage_completed("MANIFEST")

        # 4. Dynamic Sandbox Analysis via Frida & ADB
        timer.stage_started("AGENTIC_EXPLORER")
        dynamic_result = await run_frida_analysis(
            apk_path=apk_path,
            package_name=package_name,
        )
        timer.stage_completed("AGENTIC_EXPLORER")

        # 5. mitmproxy HAR Net Ingest
        har_path = os.getenv("MITMPROXY_HAR_PATH")
        if har_path and await asyncio.to_thread(os.path.exists, har_path):
            try:
                nc = NetworkCapture()
                # Parses a HAR file off disk - size is attacker-influenced.
                added = await asyncio.to_thread(nc.ingest_mitmproxy_har, har_path)
                if dynamic_result and isinstance(dynamic_result, dict):
                    dynamic_result["mitmproxy_flows_added"] = added
            except Exception as e:
                logger.warning(f"[Engine] mitmproxy HAR ingest notice: {e}")

        # 6. Threat Correlation & Risk Scoring
        timer.stage_started("THREAT_CORRELATION")
        threat_corr = await correlate(
            sha256=sha256_hash,
            urls=flags.hardcoded_urls_ips,
            package_name=package_name,
            dynamic_urls=extract_dynamic_urls(dynamic_result),
        )
        timer.stage_completed("THREAT_CORRELATION")

        if dynamic_result and isinstance(dynamic_result, dict):
            dynamic_result["has_high_risk_capabilities"] = bool(
                getattr(flags, "has_accessibility_abuse", False)
                or getattr(flags, "has_system_alert_window", False)
                or getattr(flags, "has_sms_read_write", False)
            )

        suspect_ui = None
        if apktool_res and apktool_res.ui_profile:
            suspect_ui = UIProfile.from_dict(apktool_res.ui_profile)

        timer.stage_started("VIDE_DYNAMIC")
        vide_result = await asyncio.to_thread(
            safe_run_vide_analysis,
            suspect_profile=suspect_ui,
            dynamic_result=dynamic_result,
            package_name=package_name or "",
            certificate=(mobsf_res or {}).get("certificate", {}),
            apktool_available=bool(apktool_res and apktool_res.available),
        )
        timer.stage_completed("VIDE_DYNAMIC")

        timer.stage_started("RISK")
        risk_output = await asyncio.to_thread(
            compute_fraud_risk_score,
            flags=flags,
            dynamic_result=dynamic_result,
            correlation_result=threat_corr,
            # Without this the Permission Risk axis (10% of STEI) scored 0 for
            # every sample, because _axis_pr falls back to an empty list. The
            # backend already passed it (routes/upload.py); the engine did not.
            all_permissions=permissions,
            vide_result=vide_result,
        )
        timer.stage_completed("RISK")

        # MobSF is the only source for component inventory, certificate and
        # AppSec score. When it is not configured these stay empty/None - they
        # are NOT invented. Previously this block hardcoded eight fields,
        # including a fabricated "appsec_score": 50.0 that an analyst could not
        # distinguish from a computed score.
        mobsf = mobsf_res or {}
        analysis_mode = "androguard+mobsf" if mobsf_res else "androguard"

        return {
            "sha256": sha256_hash,
            "package_name": package_name,
            "app_name": getattr(androguard_output, "app_name", package_name),
            "analysis_mode": analysis_mode,
            "family_classification": risk_output.get("family_classification", "Unknown"),
            "base_score": risk_output["base_score"],
            "ai_confidence_multiplier": risk_output["ai_confidence_multiplier"],
            "final_risk_score": risk_output["final_risk_score"],
            "risk_band": risk_output["risk_band"],
            "confidence": risk_output.get("confidence", DEFAULT_CONFIDENCE),
            "recommended_action": risk_output.get("recommended_action", ""),
            "frs_breakdown": risk_output.get("frs_breakdown", {}),
            "threat_scenario_table": risk_output.get("threat_scenario_table", []),
            "all_permissions": permissions,
            "dangerous_perms": [p for p in permissions if "SMS" in p or "ACCESSIBILITY" in p or "ALERT" in p],
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
            # Androguard genuinely produces this; the engine used to drop it.
            "suspicious_strings": getattr(androguard_output, "suspicious_strings", []),

            # MobSF-derived. Empty/None when MobSF is not configured - never faked.
            "manifest_findings": mobsf.get("manifest_analysis", []),
            "code_findings": mobsf.get("code_analysis", {}).get("findings", []),
            "activities": mobsf.get("activities", [])[:20],
            "services_list": mobsf.get("services", [])[:10],
            "receivers": mobsf.get("receivers", [])[:10],
            "certificate": mobsf.get("certificate", {}),
            "domains": mobsf.get("domains", {}),
            "hardcoded_secrets": mobsf.get("hardcoded_secrets", []),
            "appsec_score": mobsf.get("appsec_score"),
            "mobsf_scan_hash": mobsf.get("scan_hash") or mobsf.get("hash"),

            # Lets a caller distinguish "nothing found" from "never computed" - # an evidentiary distinction a forensic report has to make.
            "analysis_completeness": {
                "static_androguard": True,
                "static_apktool": apktool_res is not None,
                "static_jadx": jadx_res is not None,
                "static_mobsf": mobsf_res is not None,
                "dynamic_frida": bool(dynamic_result and dynamic_result.get("available")),
                "threat_correlation": bool(threat_corr and threat_corr.get("available")),
                "vide_ui": bool(vide_result.get("visual_impersonation_detected")),
            },
            "vide": vide_result,
            "_pipeline": {"stage_timings": timer.snapshot()["stage_timings"]},
        }

    # The timeout only has teeth now that every blocking step is dispatched to a
    # worker thread: wait_for can only cancel at an await point, and previously
    # there were none between the blocking calls.
    #
    # Caveat, stated honestly: cancelling an asyncio.to_thread call does NOT kill
    # the thread. On timeout the caller gets a 408 immediately and the loop is
    # freed, but any in-flight step runs to completion in the background. That is
    # bounded in practice - APKTool and JADX enforce their own 120s/180s
    # subprocess timeouts, and the semaphore slot is not released until the step
    # returns, so a stuck analysis consumes a slot rather than the whole service.
    # Truly pre-emptive cancellation needs a process pool; see 03_Backend_Audit.
    async with _analysis_slots:
        try:
            return await asyncio.wait_for(_run(), timeout=float(timeout_seconds))
        except asyncio.TimeoutError:
            logger.error(f"[Engine] Analysis hard timeout exceeded ({timeout_seconds}s) for {sha256_hash}")
            raise HTTPException(
                status_code=408,
                detail=(
                    f"Analysis engine timeout exceeded ({timeout_seconds}s). "
                    "The request was abandoned; any in-flight tool invocation is "
                    "bounded by its own subprocess timeout."
                ),
            )


# ─── Input validation ─────────────────────────────────────────────────────────

def _resolve_upload_path(raw: str) -> Path:
    """
    Resolve a caller-supplied path and require it to live inside UPLOADS_DIR.

    The previous check was `Path(raw).exists()` and nothing else, so any readable
    path in the container could be fed to Androguard/APKTool/JADX and the 404
    body echoed the input back - a filesystem oracle. resolve() collapses
    '..' and symlinks before the containment test, so neither can escape.

    Errors are deliberately generic and never echo `raw`.
    """
    root = UPLOADS_DIR.resolve()
    try:
        candidate = Path(raw).resolve()
    except (OSError, RuntimeError):
        raise HTTPException(status_code=400, detail="Invalid file path.")

    if not candidate.is_relative_to(root):
        logger.warning("[Engine] Rejected out-of-tree analyze path: %r", raw)
        raise HTTPException(
            status_code=400,
            detail="file_path must reference a file inside the shared uploads volume.",
        )
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="File not found in shared uploads volume.")
    return candidate


def _reject_non_apk(head: bytes, filename: Optional[str]) -> None:
    """Extension plus ZIP magic. Extension alone accepts any content."""
    if not filename or not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .apk files are allowed.")
    if not head.startswith(_ZIP_MAGIC):
        raise HTTPException(
            status_code=400,
            detail="File is not a valid APK (missing ZIP archive signature).",
        )


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.post("/api/v1/analyze")
async def analyze_path(req: AnalyzePathRequest):
    """
    Synchronous analysis endpoint - accepts a shared-volume file path.
    The path must resolve inside UPLOADS_DIR; see _resolve_upload_path.
    """
    file_path = _resolve_upload_path(req.file_path)

    sha256_hash = req.sha256
    if not sha256_hash:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_BYTES):
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
    hasher = hashlib.sha256()
    total = 0
    temp_path: Optional[str] = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=UPLOADS_DIR) as tmp:
            temp_path = tmp.name
            first = True
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                if first:
                    # Validate before a single byte is committed to the volume.
                    _reject_non_apk(chunk[:4], file.filename)
                    first = False

                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"APK exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                    )

                hasher.update(chunk)
                await asyncio.to_thread(tmp.write, chunk)

            if first:
                raise HTTPException(status_code=400, detail="Empty upload.")

        return await _execute_analysis_pipeline(
            apk_path=temp_path,
            sha256_hash=hasher.hexdigest(),
        )
    finally:
        # Remove the sample AND the per-analysis manifest directory. The latter
        # was previously never cleaned, so the shared volume grew without bound.
        if temp_path and os.path.exists(temp_path):
            try:
                await asyncio.to_thread(os.remove, temp_path)
            except OSError as e:
                logger.warning("[Engine] Could not remove temp upload %s: %s", temp_path, e)


@app.post("/api/v1/analyze/async")
async def analyze_async(
    req: AnalyzePathRequest,
    background_tasks: BackgroundTasks,
):
    """
    Asynchronous job submission endpoint - returns job_id for polling.
    """
    # Validate the path up front so a bad request fails fast with 400 rather
    # than becoming a job that reports FAILED later. Same containment rule as
    # the synchronous endpoint - this path used req.file_path unchecked.
    apk_path = _resolve_upload_path(req.file_path)

    _evict_finished_jobs()

    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        "job_id": job_id,
        "status": "QUEUED",
        "progress_pct": 10,
        "error": None,
        "result": None,
        "created_at": time.monotonic(),
    }

    async def _async_task():
        JOBS[job_id]["status"] = "RUNNING"
        JOBS[job_id]["progress_pct"] = 30
        try:
            res = await _execute_analysis_pipeline(
                apk_path=str(apk_path),
                sha256_hash=req.sha256 or "unknown",
                timeout_seconds=req.timeout_seconds or DEFAULT_TIMEOUT_SECONDS,
            )
            JOBS[job_id]["status"] = "COMPLETED"
            JOBS[job_id]["progress_pct"] = 100
            JOBS[job_id]["result"] = res
        except Exception as e:
            logger.exception("[Engine] Job %s failed", job_id)
            JOBS[job_id]["status"] = "FAILED"
            JOBS[job_id]["error"] = str(e)
        finally:
            JOBS[job_id]["finished_at"] = time.monotonic()

    background_tasks.add_task(_async_task)
    return {"job_id": job_id, "status": "QUEUED"}


@app.get("/api/v1/status/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str):
    """Poll status of asynchronous analysis job."""
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job ID not found")
    return JOBS[job_id]
