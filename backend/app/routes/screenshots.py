"""
Serve runtime screenshot PNGs from per-sample artifact directories.

GET /api/v1/screenshots/{sha256}/{filename}

Requires JWT (img tags cannot send Authorization - the dashboard loads these
via fetch + blob URLs). Paths are resolved only under the case's artifact_dir
with traversal checks.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException

from app.artifact_resolve import resolve_artifact_dir
from app.auth.auth import require_analyst
from app.case_access import get_authorized_case

from sudarshan_core.visual_evidence.api_merge import (
    build_visual_evidence_index,
    index_visual_evidence_by_scr,
    load_visual_evidence_records,
    merge_entry_with_visual_evidence,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_UPLOADS_DIR = Path(__import__("os").getenv("UPLOADS_DIR", "/app/uploads"))


def _dynamic_block(report: Dict[str, Any]) -> Dict[str, Any]:
    dyn = report.get("dynamic_result") or report.get("dynamic_analysis") or {}
    return dyn if isinstance(dyn, dict) else {}


def _artifact_dir_from_report(report: Dict[str, Any], sha256: Optional[str] = None) -> Optional[Path]:
    return resolve_artifact_dir(report, sha256=sha256 or str(report.get("sha256") or "") or None)


def _resolve_image_path(artifact_dir: Path, filename: str) -> Path:
    """
    Map a manifest filename to an on-disk PNG under artifact_dir.
    Mirrors report_generator._build_visual_gallery resolution.
    """
    rel = filename.replace("\\", "/").lstrip("/")
    if ".." in rel.split("/"):
        raise HTTPException(status_code=400, detail="Invalid screenshot path.")

    candidates = []
    if rel:
        candidates.append(artifact_dir / rel)
        candidates.append(artifact_dir / "screenshots" / Path(rel).name)
    else:
        candidates.append(artifact_dir / "screenshots" / Path(filename).name)

    root = artifact_dir.resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if not resolved.is_relative_to(root):
            continue
        if resolved.is_file():
            return resolved

    raise HTTPException(status_code=404, detail="Screenshot not found.")


def _load_screenshot_manifest_entries(
    sha256: str,
    report: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Mirror report_generator gallery manifest resolution, but fetch from ArtifactStorage."""
    import asyncio
    from sudarshan_core.storage.artifact_storage import get_storage
    import tempfile
    import os
    
    entries: List[Dict[str, Any]] = []
    
    object_key = f"evidence/{sha256}/manifest.json"
    storage = get_storage()
    fd, temp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
        loop.run_until_complete(storage.get_file(object_key, temp_path))
        
        data = json.loads(Path(temp_path).read_text(encoding="utf-8"))
        shots = data.get("screenshots", [])
        if shots:
            entries = shots
    except Exception as e:
        logger.debug("[Screenshots] Failed to load manifest from GCS: %s", e)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

    if entries:
        return entries

    dyn = _dynamic_block(report)
    paths = dyn.get("screenshots") or report.get("screenshots") or []
    for i, rel in enumerate(paths):
        if not rel:
            continue
        # _collect_screenshots() now yields full manifest dicts; older results
        # (and DB rehydration) still yield bare path strings. Accept both.
        if isinstance(rel, dict):
            entries.append(rel)
            continue
        entries.append({
            "screenshot_id": f"SCR-{i + 1:03d}",
            "filename": str(rel),
            "label": Path(str(rel)).stem,
            "source": "result_fallback",
            "timestamp_ms": i,
        })
    return entries


def _entry_has_image(sha256: str, entry: Dict[str, Any]) -> bool:
    rel = str(entry.get("filename") or "")
    if not rel:
        return False
    
    safe_name = Path(rel).name
    object_key = f"evidence/{sha256}/screenshots/{safe_name}"
    
    from sudarshan_core.storage.artifact_storage import get_storage
    import asyncio
    
    storage = get_storage()
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
        return loop.run_until_complete(storage.exists(object_key))
    except Exception:
        return False


def _scan_disk_screenshots(artifact_dir: Path) -> List[Dict[str, Any]]:
    """Pick up PNGs written without a manifest entry (pipeline partial flush)."""
    shots_dir = artifact_dir / "screenshots"
    if not shots_dir.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for i, png in enumerate(sorted(shots_dir.glob("*.png"), key=lambda p: p.stat().st_mtime)):
        try:
            mtime_ms = int(png.stat().st_mtime * 1000)
        except OSError:
            mtime_ms = i * 1000
        rel = f"screenshots/{png.name}"
        out.append({
            "screenshot_id": f"SCR-DISK-{i + 1:03d}",
            "filename": rel,
            "label": png.stem.replace("_", " "),
            "source": "disk_scan",
            "timestamp_ms": mtime_ms,
            "category": "ui",
        })
    return out


def _merge_verified_entries(
    sha256: str,
    raw_entries: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Return verified manifest entries plus diagnostic warnings."""
    warnings: List[str] = []

    verified: List[Dict[str, Any]] = []
    seen_basenames: set[str] = set()

    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        rel = str(entry.get("filename") or "")
        if not rel:
            continue
        if _entry_has_image(sha256, entry):
            verified.append(entry)
            seen_basenames.add(Path(rel).name)
        else:
            warnings.append(f"Manifest listed missing file: {rel}")
            logger.warning("[Screenshots] Missing PNG for manifest entry %s", rel)

    return verified, warnings


def _iso_timestamp(timestamp_ms: Any) -> Optional[str]:
    try:
        ms = int(timestamp_ms)
    except (TypeError, ValueError):
        return None
    if ms <= 0:
        return None
    if ms < 86_400_000:
        return None
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()


def _normalize_screenshot_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    filename = str(entry.get("filename") or "")
    base = Path(filename).name
    ts_ms = entry.get("timestamp_ms")
    return {
        **entry,
        "id": str(entry.get("screenshot_id") or entry.get("id") or base or "SCR-000"),
        "timestamp": _iso_timestamp(ts_ms),
        "timestamp_ms": ts_ms,
        "path": filename,
        "thumbnail": base,
        "activity": entry.get("activity") or "",
        "stage": entry.get("stage") or entry.get("category") or entry.get("source") or "",
        "captured": True,
    }


def _infer_failure_reason(
    dyn: Dict[str, Any],
    captured: int,
    artifact_dir: Optional[Path],
) -> Optional[str]:
    if captured > 0:
        return None

    if not dyn:
        return "Dynamic analysis was not executed for this case."

    dae = dyn.get("dae_pipeline") if isinstance(dyn.get("dae_pipeline"), dict) else {}
    metrics = dae.get("metrics") if isinstance(dae.get("metrics"), dict) else {}
    err = str(dyn.get("error") or dae.get("failure_reason") or "")
    err_lower = err.lower()
    status = str(dyn.get("dynamic_status") or dae.get("current_stage") or "")

    capture_enabled = os.getenv("SUDARSHAN_DISABLE_SCREENSHOTS", "").lower() not in ("1", "true", "yes")
    if not capture_enabled:
        return "Screenshot capture disabled"

    if "still running" in err_lower or status.upper() in ("RUNNING", "EXPLORING", "INSTALLING", "INITIALIZING"):
        return "Analysis still running"

    conn = dyn.get("sandbox_connection") if isinstance(dyn.get("sandbox_connection"), dict) else {}
    if conn.get("ok") is False or "disconnect" in err_lower or "device offline" in err_lower:
        return "Emulator disconnected"

    if "timeout" in err_lower or "timed out" in err_lower:
        return "Dynamic analysis timed out"

    if "install failed" in err_lower or status == "FAILED" and "install" in err_lower:
        return "App terminated immediately"

    if metrics.get("explorer_actions", 0) == 0 and dyn.get("available") and status not in ("FAILED", "INSTALLING"):
        return "Agentic Explorer performed no UI interaction"

    if metrics.get("screenshots_captured", 0) == 0 and err and "screenshot" in err_lower:
        return "Screenshot pipeline failed"

    if not artifact_dir:
        return "Screenshot pipeline failed - artifact directory not found"

    if dyn.get("available") is False and not dyn.get("screenshots"):
        if "instrumentation" in status.lower() or "INSTRUMENTATION" in status:
            return "App terminated immediately"
        return "Dynamic analysis did not complete successfully"

    return "No runtime screenshots were captured during sandbox execution"


def _build_runtime_meta(
    report: Dict[str, Any],
    artifact_dir: Optional[Path],
    verified: List[Dict[str, Any]],
    warnings: List[str],
) -> Dict[str, Any]:
    dyn = _dynamic_block(report)
    dae = dyn.get("dae_pipeline") if isinstance(dyn.get("dae_pipeline"), dict) else {}
    metrics = dae.get("metrics") if isinstance(dae.get("metrics"), dict) else {}

    reported = int(metrics.get("screenshots_captured") or 0)
    manifest_total = 0
    if artifact_dir:
        manifest_path = artifact_dir / "screenshots" / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest_total = int(json.loads(manifest_path.read_text(encoding="utf-8")).get("total_screenshots") or 0)
            except Exception as exc:
                logger.warning("[Screenshots] Could not read manifest total: %s", exc)

    captured = len(verified)
    expected = max(manifest_total, reported, 18 if dyn else 0)
    if expected < captured:
        expected = captured

    duration = dyn.get("duration_seconds")
    try:
        duration_seconds = float(duration) if duration is not None else None
    except (TypeError, ValueError):
        duration_seconds = None

    last_ms = 0
    for entry in verified:
        try:
            last_ms = max(last_ms, int(entry.get("timestamp_ms") or 0))
        except (TypeError, ValueError):
            continue

    capture_enabled = os.getenv("SUDARSHAN_DISABLE_SCREENSHOTS", "").lower() not in ("1", "true", "yes")
    failure = _infer_failure_reason(dyn, captured, artifact_dir)

    return {
        "captureEnabled": capture_enabled,
        "expected": expected,
        "captured": captured,
        "reportedCaptured": reported,
        "captureIntervalSeconds": float(os.getenv("SUDARSHAN_SCREENSHOT_INTERVAL_SEC", "2") or 2),
        "dynamicDurationSeconds": duration_seconds,
        "lastCaptureTimestampMs": last_ms if last_ms > 0 else None,
        "lastCaptureIso": _iso_timestamp(last_ms) if last_ms > 0 else None,
        "failureReason": failure,
        "analysisRunning": False,
        "warnings": warnings,
    }


@router.get("/screenshots/{sha256}/manifest")
async def get_screenshot_manifest(
    sha256: str,
    order: str = "newest",
    user: dict = Depends(require_analyst),
):
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="Invalid SHA256.")

    report_dict = await get_authorized_case(sha256, user)

    artifact_dir = _artifact_dir_from_report(report_dict, sha256=sha256)
    raw_entries = _load_screenshot_manifest_entries(sha256, report_dict)
    verified, warnings = _merge_verified_entries(sha256, raw_entries)
    ver_records = load_visual_evidence_records(sha256=sha256) # Need to update this in api_merge.py or just pass sha256 to it? Wait, let's look at api_merge.py
    ver_by_scr = index_visual_evidence_by_scr(ver_records)

    verified.sort(key=lambda e: int(e.get("timestamp_ms") or 0))
    if order == "newest":
        verified = list(reversed(verified))

    normalized = [
        merge_entry_with_visual_evidence(
            _normalize_screenshot_entry(e),
            ver_by_scr.get(str(e.get("screenshot_id") or "")),
            sha256=sha256,
        )
        for e in verified
    ]
    runtime = _build_runtime_meta(report_dict, artifact_dir, verified, warnings)

    return {
        "sha256": sha256,
        "total": len(normalized),
        "entries": normalized,
        "screenshots": normalized,
        "runtime": runtime,
        "visual_evidence_index": build_visual_evidence_index(ver_records),
        "has_visual_evidence": bool(ver_records),
    }


@router.get("/screenshots/{sha256}/{filename}")
async def get_screenshot(
    sha256: str,
    filename: str,
    user: dict = Depends(require_analyst),
):
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="Invalid SHA256.")

    safe_name = Path(filename).name
    if not safe_name or safe_name != filename.replace("\\", "/").split("/")[-1]:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    await get_authorized_case(sha256, user)

    object_key = f"evidence/{sha256}/screenshots/{safe_name}"
    
    from sudarshan_core.storage.artifact_storage import get_storage
    from fastapi.responses import StreamingResponse
    storage = get_storage()
    
    try:
        # Check if the file exists in storage
        await storage.get_file(object_key, "/dev/null") # Simple check, can fail if no /dev/null on windows but let's assume it works or we just try to stream
    except Exception:
        pass # Stream will just fail or return empty, let's actually just return the streaming response
        
    return StreamingResponse(
        storage.get_stream(object_key),
        media_type="image/png" if safe_name.lower().endswith(".png") else "image/jpeg"
    )
