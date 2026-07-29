"""
SUDARSHAN — Runtime Telemetry API
====================================
Exposes live pipeline state, hook telemetry, event stream, and evidence
snapshots for the analyst dashboard and health monitoring.

Endpoints:
  GET /api/runtime/status   — overall pipeline health summary
  GET /api/runtime/hooks    — hook inventory, install counts, fire counts
  GET /api/runtime/events   — recent runtime events (last N)
  GET /api/runtime/pipeline — full pipeline state machine
  GET /api/runtime/metrics  — events/sec, dropped events, error rates
  GET /api/runtime/evidence — evidence store snapshot

These endpoints read from the in-process PipelineTracker registry and the
analysis job store. They require no special permissions beyond a valid JWT.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.auth import get_current_user
from sudarshan_core.engines.pipeline_state import _ACTIVE_TRACKERS, PipelineStage

logger = logging.getLogger(__name__)
router = APIRouter()

# ─── Shared state singletons (populated by analysis workers) ─────────────────
# These are module-level so they accumulate across requests in the same process.
# They are NOT persisted across container restarts.

_recent_events: List[Dict[str, Any]] = []       # ring buffer, max 500 events
_MAX_RECENT_EVENTS = 500
_hook_registry: Dict[str, Dict[str, Any]] = {}  # hook_name → {installed, fired, errors}
_pipeline_metrics: Dict[str, Any] = {
    "events_total": 0,
    "events_per_sec": 0.0,
    "dropped_events": 0,
    "hook_errors_total": 0,
    "active_sessions": 0,
    "last_event_ts": None,
    "_rate_window_start": time.time(),
    "_rate_window_count": 0,
}


def record_event(event: Dict[str, Any]) -> None:
    """Called by analysis workers to push events into the ring buffer."""
    global _recent_events, _pipeline_metrics
    _recent_events.append(event)
    if len(_recent_events) > _MAX_RECENT_EVENTS:
        _recent_events.pop(0)

    _pipeline_metrics["events_total"] += 1
    _pipeline_metrics["last_event_ts"] = time.time()

    # Rolling events/sec calculation (1-minute window)
    now = time.time()
    window_elapsed = now - _pipeline_metrics["_rate_window_start"]
    _pipeline_metrics["_rate_window_count"] += 1
    if window_elapsed >= 60.0:
        _pipeline_metrics["events_per_sec"] = round(
            _pipeline_metrics["_rate_window_count"] / window_elapsed, 2
        )
        _pipeline_metrics["_rate_window_start"] = now
        _pipeline_metrics["_rate_window_count"] = 0


def record_hook(name: str, fired: bool = False, error: bool = False) -> None:
    """Called by analysis workers to track hook telemetry."""
    if name not in _hook_registry:
        _hook_registry[name] = {"installed": True, "fired": 0, "errors": 0, "last_fired_ts": None}
    if fired:
        _hook_registry[name]["fired"] += 1
        _hook_registry[name]["last_fired_ts"] = time.time()
    if error:
        _hook_registry[name]["errors"] += 1
        _pipeline_metrics["hook_errors_total"] += 1


# ─── Helper: load evidence.json from artifact directory ──────────────────────

def _load_evidence_from_artifacts() -> List[Dict]:
    """Find the most recent evidence.json file in the sudarshan_artifacts tree."""
    artifact_roots = [
        Path("/app/uploads"),
        Path("sudarshan_artifacts"),
        Path("backend/sudarshan_artifacts"),
    ]
    best_path: Optional[Path] = None
    best_mtime: float = 0.0

    for root in artifact_roots:
        if not root.exists():
            continue
        for ev_file in root.rglob("evidence.json"):
            try:
                mtime = ev_file.stat().st_mtime
                if mtime > best_mtime:
                    best_mtime = mtime
                    best_path = ev_file
            except OSError:
                continue

    if best_path is None:
        return []

    try:
        with open(best_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return data.get("records", []) if isinstance(data, dict) else []
    except Exception as e:
        logger.warning(f"[RuntimeAPI] Could not read evidence.json: {e}")
        return []


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/runtime/health")
async def runtime_health():
    """
    Comprehensive diagnostics endpoint returning pipeline status across all stages.
    Returns: ADB, Device, Frida, Server, Hooks Installed, Events Received, Evidence Count, Risk Score, Subscribers, Errors.
    """
    from sudarshan_core.engines.frida_sandbox import get_sandbox_status

    sandbox = get_sandbox_status()
    emulators = sandbox.get("emulators_connected", [])
    evidence_records = _load_evidence_from_artifacts()

    # Aggregate hook stats from registry and active trackers
    active_trackers = list(_ACTIVE_TRACKERS.values())
    total_installed = sum(t.hook_coverage.total_installed for t in active_trackers) or len(_hook_registry)
    total_events = sum(t.event_counters.received for t in active_trackers) or _pipeline_metrics["events_total"]

    # Calculate latest risk score from evidence records
    latest_risk_score = 0.0
    if evidence_records:
        cats = set(r.get("category", "") for r in evidence_records)
        if "accessibility" in cats: latest_risk_score += 35.0
        if "sms" in cats: latest_risk_score += 25.0
        if "overlay" in cats: latest_risk_score += 20.0
        if "banking" in cats: latest_risk_score += 10.0
        if "network" in cats: latest_risk_score += 5.0
        if "persistence" in cats: latest_risk_score += 5.0

    errors_list = []
    for h_name, h_info in _hook_registry.items():
        if h_info.get("errors", 0) > 0:
            errors_list.append(f"{h_name}: {h_info['errors']} error(s)")

    return {
        "status": "PASS" if sandbox.get("ready") else "WARN",
        "timestamp": time.time(),
        "ADB": {
            "connected": len(emulators) > 0,
            "adb_path": sandbox.get("adb_path"),
            "mode": sandbox.get("mode"),
        },
        "Device": {
            "count": len(emulators),
            "serials": emulators,
            "active": len(emulators) > 0,
        },
        "Frida": {
            "available": sandbox.get("frida_available"),
            "version": sandbox.get("frida_version"),
        },
        "Server": {
            "running": sandbox.get("ready"),
            "hooks_script": sandbox.get("hooks_script_present"),
        },
        "Hooks Installed": total_installed,
        "Events Received": total_events,
        "Evidence Count": len(evidence_records),
        "Risk Score": round(latest_risk_score, 2),
        "Subscribers": len(active_trackers) + 1,
        "Errors": errors_list,
    }


@router.get("/runtime/status")
async def runtime_status(current_user: dict = Depends(get_current_user)):
    """
    Overall pipeline health summary.
    Reports Frida server status, ADB connectivity, hook counts, and event rates.
    """
    from sudarshan_core.engines.frida_sandbox import get_sandbox_status, _HOOKS_SCRIPT

    sandbox = get_sandbox_status()
    active_trackers = list(_ACTIVE_TRACKERS.values())
    active_count = len([t for t in active_trackers if t.current_stage not in (
        PipelineStage.FAILED, PipelineStage.REPORT_COMPLETE
    )])

    # Aggregate hook stats from all active trackers
    total_hooks_installed = sum(t.hook_coverage.total_installed for t in active_trackers)
    total_hooks_triggered = sum(t.hook_coverage.total_triggered for t in active_trackers)
    total_events = sum(t.event_counters.received for t in active_trackers)
    total_errors = sum(len(t.hook_exceptions) for t in active_trackers)

    # If no trackers yet, use the module-level registry
    if not active_trackers:
        total_hooks_installed = len(_hook_registry)
        total_hooks_triggered = sum(h["fired"] for h in _hook_registry.values())
        total_events = _pipeline_metrics["events_total"]
        total_errors = _pipeline_metrics["hook_errors_total"]

    return {
        "status": "ready" if sandbox.get("ready") else "not_ready",
        "timestamp": time.time(),
        "frida": {
            "available": sandbox.get("frida_available"),
            "version": sandbox.get("frida_version"),
            "server_running": sandbox.get("ready"),
        },
        "adb": {
            "connected": len(sandbox.get("emulators_connected", [])) > 0,
            "emulators": sandbox.get("emulators_connected", []),
            "mode": sandbox.get("mode"),
        },
        "hooks": {
            "script_present": sandbox.get("hooks_script_present"),
            "script_path": sandbox.get("hooks_script_path"),
            "hooks_installed": total_hooks_installed or len(_hook_registry),
            "hooks_active": total_hooks_triggered,
        },
        "pipeline": {
            "active_sessions": active_count,
            "events_total": total_events,
            "events_per_sec": _pipeline_metrics["events_per_sec"],
            "hook_errors": total_errors,
            "dropped_events": _pipeline_metrics["dropped_events"],
            "last_event_ts": _pipeline_metrics["last_event_ts"],
        },
        "connection_info": sandbox.get("connection_info"),
    }


@router.get("/runtime/hooks")
async def runtime_hooks(
    current_user: dict = Depends(get_current_user),
    case_id: Optional[str] = Query(None, description="Filter by case_id / package name"),
):
    """
    Hook inventory: installed hooks, fire counts, error counts.
    Returns both the in-process registry and any tracker-level data.
    """
    # Merge registry with tracker data
    hooks_out: Dict[str, Any] = {}

    # From module registry
    for name, info in _hook_registry.items():
        hooks_out[name] = {
            "installed": info["installed"],
            "fired": info["fired"],
            "errors": info["errors"],
            "last_fired_ts": info.get("last_fired_ts"),
        }

    # From active trackers (richer data)
    for tracker in _ACTIVE_TRACKERS.values():
        if case_id and tracker.case_id != case_id and tracker.package_name != case_id:
            continue
        for exc in tracker.hook_exceptions:
            hook = exc.get("hook", "unknown")
            if hook not in hooks_out:
                hooks_out[hook] = {"installed": True, "fired": 0, "errors": 0}
            hooks_out[hook]["errors"] += 1

    return {
        "timestamp": time.time(),
        "hooks_total": len(hooks_out),
        "hooks_installed": sum(1 for h in hooks_out.values() if h.get("installed")),
        "hooks_fired": sum(1 for h in hooks_out.values() if h.get("fired", 0) > 0),
        "hooks_with_errors": sum(1 for h in hooks_out.values() if h.get("errors", 0) > 0),
        "hooks": hooks_out,
    }


@router.get("/runtime/events")
async def runtime_events(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500, description="Max events to return"),
    category: Optional[str] = Query(None, description="Filter by event category"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW/MED/HIGH/CRITICAL)"),
):
    """
    Recent runtime events from the in-process ring buffer.
    Returns the most recent events captured across all sessions.
    """
    events = list(reversed(_recent_events))  # most recent first

    if category:
        events = [e for e in events if e.get("category") == category]
    if severity:
        events = [e for e in events if e.get("severity") == severity.upper()]

    events = events[:limit]

    return {
        "timestamp": time.time(),
        "total_in_buffer": len(_recent_events),
        "returned": len(events),
        "events": events,
    }


@router.get("/runtime/pipeline")
async def runtime_pipeline(
    current_user: dict = Depends(get_current_user),
    case_id: Optional[str] = Query(None, description="Filter by case_id"),
):
    """
    Full pipeline state machine for all active (or filtered) analysis sessions.
    """
    trackers = list(_ACTIVE_TRACKERS.values())
    if case_id:
        trackers = [t for t in trackers if t.case_id == case_id or t.package_name == case_id]

    pipeline_states = []
    for t in trackers:
        diag = t.get_diagnostics()
        diag["stage_history"] = [
            {
                "stage": rec.stage.value,
                "timestamp": rec.timestamp,
                "duration_ms": rec.duration_ms,
                "status": rec.status,
                "detail": rec.detail,
            }
            for rec in t.stage_history
        ]
        pipeline_states.append(diag)

    return {
        "timestamp": time.time(),
        "active_sessions": len(pipeline_states),
        "pipelines": pipeline_states,
    }


@router.get("/runtime/metrics")
async def runtime_metrics(current_user: dict = Depends(get_current_user)):
    """
    Aggregate runtime metrics: throughput, drop rates, error rates.
    """
    trackers = list(_ACTIVE_TRACKERS.values())
    total_generated = sum(t.event_counters.generated for t in trackers)
    total_received = sum(t.event_counters.received for t in trackers)
    total_stored = sum(t.event_counters.stored for t in trackers)

    return {
        "timestamp": time.time(),
        "events": {
            "generated": total_generated or _pipeline_metrics["events_total"],
            "received": total_received or _pipeline_metrics["events_total"],
            "stored": total_stored,
            "per_second": _pipeline_metrics["events_per_sec"],
            "dropped": _pipeline_metrics["dropped_events"],
            "buffer_size": len(_recent_events),
        },
        "hooks": {
            "total_registered": len(_hook_registry),
            "errors": _pipeline_metrics["hook_errors_total"],
        },
        "sessions": {
            "active": len([t for t in trackers if t.current_stage not in (
                PipelineStage.FAILED, PipelineStage.REPORT_COMPLETE
            )]),
            "total": len(trackers),
        },
        "last_event_ts": _pipeline_metrics["last_event_ts"],
    }


@router.get("/runtime/evidence")
async def runtime_evidence(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000, description="Max evidence records"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
):
    """
    Evidence store snapshot — reads from the most recent evidence.json artifact.
    Returns structured EvidenceRecord objects.
    """
    records = _load_evidence_from_artifacts()

    if severity:
        records = [r for r in records if r.get("severity") == severity.upper()]

    records = records[:limit]

    return {
        "timestamp": time.time(),
        "total_found": len(records),
        "returned": len(records),
        "evidence": records,
    }
