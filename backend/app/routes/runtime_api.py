"""
SUDARSHAN - Runtime Telemetry API
====================================
Exposes live pipeline state, hook telemetry, event stream, and evidence
snapshots for the analyst dashboard and health monitoring.

Endpoints:
  GET /api/runtime/status - overall pipeline health summary
  GET /api/runtime/hooks - hook inventory, install counts, fire counts
  GET /api/runtime/events - recent runtime events (last N)
  GET /api/runtime/pipeline - full pipeline state machine
  GET /api/runtime/metrics - events/sec, dropped events, error rates
  GET /api/runtime/evidence - evidence store snapshot

These endpoints read from the in-process PipelineTracker registry and the
analysis job store. They require no special permissions beyond a valid JWT.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
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

    # Hand a copy to the durable index. Appending to a list is atomic under the
    # GIL, so this is safe from the Frida worker threads that call us and it
    # never blocks them on I/O - the flusher task does the database work.
    if len(_persist_buffer) < _PERSIST_BUFFER_MAX:
        _persist_buffer.append(event)
    else:
        _pipeline_metrics["dropped_events"] += 1

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


# ─── Durable runtime-event index ─────────────────────────────────────────────
#
# The ring buffer above is a live view: 500 events, in memory, gone on restart.
# That was the whole record - so once the container restarted, nobody could
# review which hooks fired during a dynamic run.
#
# What goes to SQLite is metadata only: sha256, sequence, type, severity,
# timestamp, and a reference. The full payload of every event already lives in
# the per-session evidence store (evidence_store.py writes a WAL SQLite file per
# case under artifacts/evidence/), and copying those blobs into the gateway
# database would multiply its size to answer no question the index cannot.

_persist_buffer: List[Dict[str, Any]] = []
_PERSIST_BUFFER_MAX = int(os.getenv("RUNTIME_EVENT_BUFFER_MAX", "5000"))
_PERSIST_FLUSH_SECONDS = float(os.getenv("RUNTIME_EVENT_FLUSH_SECONDS", "5"))
_flush_task: Optional["asyncio.Task"] = None
_event_seq = 0


def _to_index_row(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Project a raw bus event onto the runtime_events columns."""
    global _event_seq
    sha = (
        event.get("sha256")
        or event.get("case_id")
        or (event.get("context") or {}).get("sha256")
    )
    if not sha:
        # Without a case to hang it on, an indexed event is unreachable.
        return None

    _event_seq += 1
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else event
    summary = (
        event.get("summary")
        or event.get("message")
        or event.get("api")
        or event.get("event_type")
        or ""
    )
    return {
        "sha256": sha,
        "job_id": event.get("job_id") or event.get("session_id"),
        "seq": event.get("seq") if isinstance(event.get("seq"), int) else _event_seq,
        "event_type": event.get("event_type") or event.get("type"),
        "severity": event.get("severity"),
        "ts": event.get("timestamp") or event.get("ts")
        or datetime.now(timezone.utc).isoformat(),
        "evidence_id": event.get("evidence_id") or event.get("id"),
        "payload_ref": event.get("payload_ref") or (payload or {}).get("evidence_db"),
        "summary": str(summary),
    }


async def flush_runtime_events() -> int:
    """Drain the buffer into runtime_events. Returns rows written."""
    if not _persist_buffer:
        return 0

    # Swap the whole buffer out in one slice assignment so producers can keep
    # appending to the fresh list while we write.
    batch, _persist_buffer[:] = list(_persist_buffer), []

    rows = [r for r in (_to_index_row(e) for e in batch) if r]
    if not rows:
        return 0

    from app.db.intel import record_runtime_events
    return await record_runtime_events(rows)


async def _flush_loop() -> None:
    while True:
        try:
            await asyncio.sleep(_PERSIST_FLUSH_SECONDS)
            written = await flush_runtime_events()
            if written:
                logger.debug("[Runtime] indexed %d event(s)", written)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            # Telemetry indexing must never take the app down; drop the batch
            # and keep going. The evidence store still has the payloads.
            logger.warning("[Runtime] event flush failed: %s", exc)

    # Final drain on shutdown, so a clean stop does not discard the tail.
    try:
        await flush_runtime_events()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[Runtime] final event flush failed: %s", exc)


async def start_runtime_event_flusher() -> None:
    global _flush_task
    if _flush_task is None or _flush_task.done():
        _flush_task = asyncio.create_task(_flush_loop())
        logger.info(
            "[Runtime] event indexer started (flush every %.0fs)", _PERSIST_FLUSH_SECONDS
        )


async def stop_runtime_event_flusher() -> None:
    global _flush_task
    if _flush_task and not _flush_task.done():
        _flush_task.cancel()
        try:
            await _flush_task
        except asyncio.CancelledError:
            pass
    _flush_task = None


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

_ARTIFACT_ROOTS = (
    Path("/app/uploads"),
    Path("sudarshan_artifacts"),
    Path("backend/sudarshan_artifacts"),
    Path(__file__).resolve().parents[2] / "sudarshan_artifacts",
    Path.cwd() / "sudarshan_artifacts",
)

# Cache the rglob result briefly. This walks the ENTIRE artifact tree and stats
# every hit, on the two endpoints a dashboard polls - and artifact directories
# are never removed, so the cost grows with every sample ever analysed.
_evidence_scan_cache: Dict[str, Any] = {"at": 0.0, "paths": []}
_EVIDENCE_SCAN_TTL = float(os.getenv("SUDARSHAN_EVIDENCE_SCAN_TTL", "10.0"))


def _scan_evidence_files() -> List[Path]:
    """Return every evidence.json under the artifact roots, newest first."""
    now = time.time()
    if now - _evidence_scan_cache["at"] < _EVIDENCE_SCAN_TTL:
        return _evidence_scan_cache["paths"]

    found: List[tuple] = []
    for root in _ARTIFACT_ROOTS:
        if not root.exists():
            continue
        for ev_file in root.rglob("evidence.json"):
            try:
                found.append((ev_file.stat().st_mtime, ev_file))
            except OSError:
                continue

    paths = [p for _, p in sorted(found, key=lambda t: t[0], reverse=True)]
    _evidence_scan_cache["at"] = now
    _evidence_scan_cache["paths"] = paths
    return paths


def _load_evidence_from_artifacts(case_id: Optional[str] = None) -> List[Dict]:
    """
    Load evidence records for a specific case, or the most recent one.

    `case_id` is matched against the artifact directory name, which
    frida_sandbox.artifact_dir_for builds as "<sample-stem>_<digest>".

    Without it this returned whichever sample finished LAST, globally - so an
    analyst looking at case A was shown case B's evidence whenever B completed
    more recently, and any authenticated caller could read evidence from cases
    they never submitted. The sibling routes already accept case_id; this one
    did not.
    """
    candidates = _scan_evidence_files()

    if case_id:
        needle = case_id.lower()
        candidates = [
            p for p in candidates
            if needle in p.parent.name.lower() or needle in str(p.parent).lower()
        ]

    best_path = candidates[0] if candidates else None
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
async def runtime_health(current_user: dict = Depends(get_current_user)):
    """
    Comprehensive diagnostics endpoint returning pipeline status across all stages.

    AUTHENTICATED. This was the only route in this module without a dependency,
    and it discloses the host ADB path, the connection mode, emulator serials,
    the exact Frida version, hook/event/evidence counts and per-hook error
    strings - host layout and analysis state, to anyone who could reach the
    gateway. The equivalent leak on /sandbox/status was closed previously; this
    endpoint reintroduced a subset of it.
    """
    from sudarshan_core.engines.frida_sandbox import get_sandbox_status

    sandbox = get_sandbox_status()
    emulators = sandbox.get("emulators_connected", [])
    evidence_records = _load_evidence_from_artifacts()

    # Aggregate hook stats from registry and active trackers
    active_trackers = list(_ACTIVE_TRACKERS.values())
    total_installed = sum(t.hook_coverage.total_installed for t in active_trackers) or len(_hook_registry)
    total_events = sum(t.event_counters.received for t in active_trackers) or _pipeline_metrics["events_total"]

    # Behaviour categories observed, NOT a score.
    #
    # This used to sum weights (35/25/20/10/5/5) over evidence categories and
    # report the total as "Risk Score" - a FOURTH scoring formula, matching
    # neither the FRS in risk_engine nor the BFCI in bfci_scorer, under a name
    # an analyst reads as the verdict. Two different numbers called the same
    # thing in one product is worse than one imperfect number.
    #
    # Scoring belongs to the risk engine. This endpoint reports what was
    # observed and leaves the verdict to the thing that owns it.
    observed_categories = sorted(
        {r.get("category", "") for r in evidence_records if r.get("category")}
    )

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
        # Deliberately NOT a score - see above. Risk is owned by risk_engine and
        # is served by /api/v1/cases/{sha256}.
        "Observed Categories": observed_categories,
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
    case_id: Optional[str] = Query(
        None, description="Scope to one case (artifact directory name / sample stem)"
    ),
):
    """
    Evidence store snapshot for a case.

    Pass `case_id` to scope the read. Without it this returns the most recently
    completed analysis, which is a convenience for a live dashboard and NOT a
    safe default when several analysts are working concurrently.
    """
    records = _load_evidence_from_artifacts(case_id)

    if severity:
        records = [r for r in records if r.get("severity") == severity.upper()]

    records = records[:limit]

    return {
        "timestamp": time.time(),
        "total_found": len(records),
        "returned": len(records),
        "evidence": records,
    }


@router.get("/runtime/diagnostics")
async def runtime_diagnostics(
    current_user: dict = Depends(get_current_user),
    case_id: Optional[str] = Query(None, description="Scope diagnostics to case ID / package"),
):
    """
    Comprehensive Runtime Analysis Diagnostics Mode.
    Answers all 15 operational pipeline health questions end-to-end.
    """
    from sudarshan_core.engines.frida_sandbox import get_sandbox_status, _find_adb, get_connected_emulators

    sandbox_status = get_sandbox_status()
    adb_path = _find_adb()
    emulators = get_connected_emulators() if adb_path else []

    evidence_records = _load_evidence_from_artifacts(case_id) if case_id else _load_evidence_from_artifacts()

    trackers = list(_ACTIVE_TRACKERS.values())
    active_tracker = None
    if case_id:
        for t in trackers:
            if case_id.lower() in t.package_name.lower():
                active_tracker = t
                break
    if not active_tracker and trackers:
        active_tracker = trackers[-1]

    registered_hooks_count = len(_hook_registry)
    triggered_hooks_count = sum(1 for h in _hook_registry.values() if h.get("fired", 0) > 0)

    raw_events_received = _pipeline_metrics.get("events_total", 0)
    evidence_stored_count = len(evidence_records)

    return {
        "timestamp": time.time(),
        "case_id_scoped": case_id,
        "diagnostics": {
            "emulator_connected": len(emulators) > 0,
            "connected_emulators": emulators,
            "adb_available": adb_path is not None,
            "adb_path": adb_path,
            "frida_available": sandbox_status.get("frida_available", False),
            "frida_version": sandbox_status.get("frida_version"),
            "frida_sandbox_ready": sandbox_status.get("ready", False),
            "hooks_bundle_present": sandbox_status.get("hooks_script_present", False),
            "hooks_registered_total": registered_hooks_count,
            "hooks_triggered_total": triggered_hooks_count,
            "raw_events_received": raw_events_received,
            "events_per_sec": _pipeline_metrics.get("events_per_sec", 0.0),
            "evidence_records_stored": evidence_stored_count,
            "active_sessions_count": len(trackers),
            "active_session_detail": active_tracker.to_dict() if active_tracker else None,
        },
        "pipeline_health_summary": {
            "status": "HEALTHY" if sandbox_status.get("ready") and raw_events_received > 0 else "READY_IDLE" if sandbox_status.get("ready") else "UNAVAILABLE",
            "message": "Full dynamic pipeline operational and ready to process APKs." if sandbox_status.get("ready") else sandbox_status.get("message", "Sandbox not ready"),
        }
    }

