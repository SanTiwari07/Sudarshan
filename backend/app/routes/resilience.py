"""Investigation resilience API.

Controls an analyst uses on a run that produced nothing, to make it produce
something:

    POST /api/v1/analysis/{session_id}/checkpoint/restore   resume after a crash
    POST /api/v1/analysis/{session_id}/time-warp            defeat dormancy timers
    POST /api/v1/analysis/{session_id}/seed-persona         defeat emptiness checks
    POST /api/v1/analysis/{session_id}/autonomous-anti-evasion  both, measured
    GET  /api/v1/analysis/{session_id}/suggestions          what to try next
    GET  /api/v1/analysis/{session_id}/assertions           execution matrix
    GET  /api/v1/analysis/personas                          persona catalogue
    WS   /api/v1/analysis/{session_id}/events               live event stream

All the mutating endpoints touch a live sandbox running hostile code, so they
are analyst-gated and every one of them reports what *actually* happened rather
than echoing the request - a time warp the device refused must not read as
applied.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.auth.auth import require_analyst
from app.services.resilience_events import (
    EVT_ANTI_EVASION_COMPLETE,
    EVT_ANTI_EVASION_STEP,
    EVT_CHECKPOINT_SAVED,
    EVT_EXECUTION_ASSERTION_UPDATED,
    EVT_PERSONA_SEEDED,
    EVT_SESSION_RECOVERED,
    EVT_TIME_WARP_APPLIED,
    hub,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analysis")

# A sandbox operation can take a while (dumpsys jobscheduler on a loaded
# emulator, 120 contact inserts). Run them off the event loop so one analyst's
# persona seed does not stall every other request.
_WORKER_TIMEOUT_SECONDS = 300


# ── Request models ─────────────────────────────────────────────────────────


class TimeWarpRequest(BaseModel):
    hours: float = Field(24.0, gt=0, le=2160, description="Hours to advance the clock.")
    force_jobs: bool = Field(True, description="Also force scheduled jobs and cycle Doze.")
    package_name: str = Field("", description="Package whose jobs should be forced.")
    device_serial: str = Field("", description="Target device; auto-selected when empty.")


class SeedPersonaRequest(BaseModel):
    persona_id: str = Field("default_retail_user")
    device_serial: str = Field("")
    include: Optional[List[str]] = Field(
        None, description="Subset of contacts/messages/calls/photos."
    )


class AntiEvasionRequest(BaseModel):
    package_name: str = Field(
        "", description="Target package; read from the stored case when empty."
    )
    device_serial: str = Field("")
    persona_id: str = Field("default_retail_user")
    contact_count: int = Field(12, ge=0, le=120)
    sms_count: int = Field(4, ge=0, le=50)
    call_count: int = Field(10, ge=0, le=100)
    photo_count: int = Field(3, ge=0, le=50)
    battery_level: int = Field(50, ge=1, le=100)
    observation_seconds: float = Field(
        3.0, ge=0.0, le=60.0, description="Hook-stream sampling window before the closing snapshot."
    )
    warp_schedule: Optional[List[float]] = Field(
        None, description="Cumulative clock offsets in hours; defaults to 6/12/24."
    )


class CheckpointRestoreRequest(BaseModel):
    package_name: str = Field("", description="Recorded on the session being resumed.")
    device_serial: str = Field("")


class SuggestionsRequest(BaseModel):
    execution_assertions: Optional[Dict[str, Any]] = None
    unfulfilled_goals: Optional[List[Dict[str, Any]]] = None
    target_bank_packages: Optional[List[Any]] = None


async def _run_blocking(func, *args, **kwargs):
    """Execute a blocking sandbox call without stalling the event loop."""
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, lambda: func(*args, **kwargs)),
        timeout=_WORKER_TIMEOUT_SECONDS,
    )


def _resolve_serial(requested: str) -> str:
    """Requested serial, or the provider's own selection. Never hardcoded."""
    if requested.strip():
        return requested.strip()
    try:
        from sudarshan_core.sandbox import get_sandbox_provider

        return get_sandbox_provider().select_device().serial
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=f"No Android sandbox is available: {exc}",
        ) from exc


# ── Personas ───────────────────────────────────────────────────────────────


@router.get("/personas")
async def list_available_personas(user: dict = Depends(require_analyst)) -> Dict[str, Any]:
    """Persona templates on disk, for the profile selector."""
    from sudarshan_core.engines.persona import list_personas

    personas = list_personas()
    return {"count": len(personas), "personas": personas}


# ── Execution assertions ───────────────────────────────────────────────────


@router.post("/{session_id}/assertions")
async def compute_assertions(
    session_id: str,
    body: Dict[str, Any],
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Derive the Execution Assertion Matrix from a dynamic result.

    Exposed so the UI can recompute the matrix for a stored case without
    re-running the whole risk engine.
    """
    from sudarshan_core.engines.execution_assertions import build_execution_assertions

    matrix = build_execution_assertions(
        body.get("dynamic_result") or {},
        target_bank_packages=body.get("target_bank_packages"),
    )
    payload = matrix.to_dict()
    await hub.publish(EVT_EXECUTION_ASSERTION_UPDATED, session_id, payload)
    return payload


# ── Suggestions ────────────────────────────────────────────────────────────


@router.get("/{session_id}/suggestions")
async def get_suggestions(
    session_id: str,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Remedial actions for a session, derived from its stored case record.

    Falls back to a generic unexercised-run list when the case has no stored
    dynamic result, so the panel is never empty when it is most needed.
    """
    from sudarshan_core.engines.agentic.remediation import (
        generate_remedial_suggestions,
        suggestions_to_dicts,
    )
    from sudarshan_core.engines.execution_assertions import build_execution_assertions

    dynamic_result: Dict[str, Any] = {}
    target_packages: List[Any] = []
    try:
        from app.db.database import get_case_by_sha256

        case = await get_case_by_sha256(session_id)
        if case:
            dynamic_result = case.get("dynamic_result") or {}
            flags = case.get("static_flags") or {}
            target_packages = flags.get("indian_bank_packages_found") or []
    except Exception as exc:  # noqa: BLE001
        logger.debug("[Resilience] no stored case for %s: %s", session_id, exc)

    matrix = build_execution_assertions(
        dynamic_result or {"available": True},
        target_bank_packages=target_packages,
    )
    suggestions = generate_remedial_suggestions(
        None,
        execution_assertions=matrix.to_dict(),
        target_bank_packages=target_packages,
    )
    return {
        "session_id": session_id,
        "execution_assertions": matrix.to_dict(),
        "suggestions": suggestions_to_dicts(suggestions),
    }


@router.post("/{session_id}/suggestions")
async def post_suggestions(
    session_id: str,
    body: SuggestionsRequest,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """Suggestions for a caller-supplied assertion matrix and goal audit."""
    from sudarshan_core.engines.agentic.remediation import (
        generate_remedial_suggestions,
        suggestions_to_dicts,
    )

    suggestions = generate_remedial_suggestions(
        body.unfulfilled_goals,
        execution_assertions=body.execution_assertions,
        target_bank_packages=body.target_bank_packages,
    )
    return {
        "session_id": session_id,
        "suggestions": suggestions_to_dicts(suggestions),
    }


# ── Time warp ──────────────────────────────────────────────────────────────


@router.post("/{session_id}/time-warp")
async def apply_time_warp(
    session_id: str,
    body: TimeWarpRequest,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """Advance the sandbox clock and release deferred background work."""
    from sudarshan_core.engines.time_warp import TimeWarpEngine

    serial = _resolve_serial(body.device_serial)
    engine = TimeWarpEngine(serial)
    try:
        result = await _run_blocking(
            engine.fast_forward_time,
            body.hours,
            body.force_jobs,
            package_name=body.package_name,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Time warp timed out on the device")
    except Exception as exc:  # noqa: BLE001
        logger.exception("[Resilience] time warp failed")
        raise HTTPException(status_code=500, detail=f"Time warp failed: {exc}") from exc

    payload = {"device_serial": serial, **result.to_dict()}
    await hub.publish(EVT_TIME_WARP_APPLIED, session_id, payload)
    logger.info(
        "[Resilience] %s warped %s by %.1fh (observed %.2fh, %d job(s) forced)",
        user.get("username", "?"),
        serial,
        body.hours,
        result.observed_shift_hours,
        len(result.jobs_forced),
    )
    return payload


# ── Persona seeding ────────────────────────────────────────────────────────


@router.post("/{session_id}/seed-persona")
async def seed_persona(
    session_id: str,
    body: SeedPersonaRequest,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """Write a persona's contacts, SMS, call log and photos to the sandbox."""
    from sudarshan_core.engines.device_state_simulator import DeviceStateSimulator

    serial = _resolve_serial(body.device_serial)
    simulator = DeviceStateSimulator(serial)
    try:
        result = await _run_blocking(
            simulator.seed_persona,
            body.persona_id,
            include=body.include,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Persona seeding timed out")
    except Exception as exc:  # noqa: BLE001
        logger.exception("[Resilience] persona seeding failed")
        raise HTTPException(status_code=500, detail=f"Persona seeding failed: {exc}") from exc

    if result.errors and not result.ok:
        # Surfaced as 422 rather than 500: the request was well-formed, the
        # device declined it, and the analyst needs to see why.
        payload = {"device_serial": serial, **result.to_dict()}
        await hub.publish(EVT_PERSONA_SEEDED, session_id, payload)
        raise HTTPException(status_code=422, detail=payload)

    payload = {"device_serial": serial, **result.to_dict()}
    await hub.publish(EVT_PERSONA_SEEDED, session_id, payload)
    return payload


# ── Autonomous anti-evasion ────────────────────────────────────────────────

#: One anti-evasion sequence per device at a time. Two overlapping runs would
#: interleave clock shifts and provider writes on the same sandbox, and neither
#: run's before/after delta would mean anything afterwards.
_anti_evasion_locks: Dict[str, asyncio.Lock] = {}


async def _resolve_package_name(session_id: str, requested: str) -> str:
    """Requested package, else the one recorded on the stored case."""
    if requested.strip():
        return requested.strip()
    try:
        from app.db.database import get_case_by_sha256

        case = await get_case_by_sha256(session_id)
        if case:
            return str(case.get("package_name") or "").strip()
    except Exception as exc:  # noqa: BLE001
        logger.debug("[Resilience] no stored package for %s: %s", session_id, exc)
    return ""


@router.post("/{session_id}/autonomous-anti-evasion")
async def run_autonomous_anti_evasion(
    session_id: str,
    body: AntiEvasionRequest,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Run the full time-warp + persona sequence and measure what it changed.

    The steps are driven from here, one at a time, so each one is published to
    the live event stream as it executes: a fifteen-second sequence against a
    live sandbox should not be a silent spinner. Blocking device work goes to
    the executor as everywhere else in this module; only the sampling window is
    an actual sleep, and it is awaited rather than occupying a worker thread.

    The response reports the *observed* delta between two behaviour snapshots.
    A metric the device would not surface comes back as null, and a run with no
    hook stream attached returns ``NO_RUNTIME_TELEMETRY`` rather than a clean
    bill of health - see :mod:`sudarshan_core.engines.anti_evasion`.
    """
    from app.routes.runtime_api import hook_telemetry_snapshot
    from sudarshan_core.engines.anti_evasion import (
        DEFAULT_WARP_SCHEDULE,
        AntiEvasionOrchestrator,
    )

    serial = _resolve_serial(body.device_serial)
    package_name = await _resolve_package_name(session_id, body.package_name)

    lock = _anti_evasion_locks.setdefault(serial, asyncio.Lock())
    if lock.locked():
        raise HTTPException(
            status_code=409,
            detail=f"An anti-evasion sequence is already running on {serial}.",
        )

    schedule = tuple(body.warp_schedule) if body.warp_schedule else DEFAULT_WARP_SCHEDULE
    orchestrator = AntiEvasionOrchestrator(
        serial,
        package_name,
        persona_id=body.persona_id,
        warp_schedule=schedule,
        contact_count=body.contact_count,
        sms_count=body.sms_count,
        call_count=body.call_count,
        photo_count=body.photo_count,
        battery_level=body.battery_level,
        telemetry_probe=lambda: hook_telemetry_snapshot(package_name),
    )

    async with lock:
        started_at = time.time()
        try:
            plan = orchestrator.steps()
            await hub.publish(
                EVT_ANTI_EVASION_STEP,
                session_id,
                {
                    "phase": "started",
                    "device_serial": serial,
                    "package_name": package_name,
                    "total_steps": len(plan) + 1,
                    "steps": [
                        {"key": s.key, "label": s.label, "description": s.description}
                        for s in plan
                    ],
                },
            )

            before = await _run_blocking(orchestrator.snapshot)
            results: List[Any] = []

            for index, step in enumerate(plan):
                await hub.publish(
                    EVT_ANTI_EVASION_STEP,
                    session_id,
                    {
                        "phase": "running",
                        "index": index,
                        "total_steps": len(plan) + 1,
                        "key": step.key,
                        "label": step.label,
                        "description": step.description,
                    },
                )
                step_start = time.perf_counter()
                outcome = await _run_blocking(step.run)
                outcome.duration_ms = (time.perf_counter() - step_start) * 1000.0
                results.append(outcome)
                await hub.publish(
                    EVT_ANTI_EVASION_STEP,
                    session_id,
                    {"phase": "finished", "index": index, **outcome.to_dict()},
                )

            # Sampling window: the manipulations have landed, and whatever the
            # sample does in response happens now.
            observe = orchestrator.observation_step(body.observation_seconds)
            await hub.publish(
                EVT_ANTI_EVASION_STEP,
                session_id,
                {
                    "phase": "running",
                    "index": len(plan),
                    "total_steps": len(plan) + 1,
                    "key": observe.key,
                    "label": observe.label,
                    "description": "Watch the instrumented process for new hook activity.",
                },
            )
            await asyncio.sleep(body.observation_seconds)
            results.append(observe)
            await hub.publish(
                EVT_ANTI_EVASION_STEP,
                session_id,
                {"phase": "finished", "index": len(plan), **observe.to_dict()},
            )

            after = await _run_blocking(orchestrator.snapshot)
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504, detail="The anti-evasion sequence timed out on the device"
            )
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[Resilience] anti-evasion sequence failed")
            raise HTTPException(
                status_code=500, detail=f"Anti-evasion sequence failed: {exc}"
            ) from exc

    result = orchestrator.summarise(
        before, after, results, session_id=session_id, started_at=started_at
    )
    payload = result.to_dict()
    await hub.publish(EVT_ANTI_EVASION_COMPLETE, session_id, payload)
    logger.info(
        "[Resilience] %s ran anti-evasion on %s (%s): %s%s",
        user.get("username", "?"),
        serial,
        package_name or "no package",
        result.verdict,
        f" [{', '.join(result.triggered_keys)}]" if result.triggered_keys else "",
    )
    return payload


# ── Checkpoints ────────────────────────────────────────────────────────────


@router.get("/{session_id}/checkpoint")
async def get_checkpoint(
    session_id: str,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """Whether a resumable checkpoint exists, and what it holds."""
    from sudarshan_core.engines.session_manager import DynamicAnalysisSession

    payload = DynamicAnalysisSession.load_checkpoint(session_id)
    if not payload:
        return {"session_id": session_id, "exists": False}

    snapshot = payload.get("snapshot") or {}
    return {
        "session_id": session_id,
        "exists": True,
        "saved_at": payload.get("saved_at"),
        "state": payload.get("state"),
        "package_name": payload.get("package_name"),
        "evidence_count": payload.get("evidence_count", 0),
        "snapshot_id": snapshot.get("snapshot_id", ""),
        "iteration": snapshot.get("iteration", 0),
        "satisfied_goals": snapshot.get("satisfied_goals", []),
        "screens_visited": len(snapshot.get("visited_screens") or []),
        "frida_events_captured": snapshot.get("frida_events_captured", 0),
    }


@router.post("/{session_id}/checkpoint/restore")
async def restore_checkpoint(
    session_id: str,
    body: CheckpointRestoreRequest,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Resume a crashed session from its last checkpoint.

    Rebuilds agent memory and the goal graph from the snapshot, and reloads
    evidence from the durable log, so the resumed run neither repeats completed
    goals nor re-counts the evidence they produced.
    """
    from sudarshan_core.engines.agentic.agent_memory import AgentMemory
    from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
    from sudarshan_core.engines.session_manager import DynamicAnalysisSession

    def _restore() -> Dict[str, Any]:
        memory = AgentMemory()
        tracker = GoalTracker()
        session = DynamicAnalysisSession(
            session_id,
            body.package_name,
            device_serial=body.device_serial,
        )
        snapshot = session.recover_from_checkpoint(memory=memory, goal_tracker=tracker)
        if snapshot is None:
            return {}
        recovered_evidence = session.evidence_store.recover_records()
        return {
            "state": session.state.value,
            "snapshot_id": session.last_snapshot_id,
            "recovery_attempts": session.recovery_attempts,
            "iteration": snapshot.get("iteration", 0),
            "satisfied_goals": snapshot.get("satisfied_goals", []),
            "screens_restored": len(memory.visited_screens),
            "evidence_recovered": recovered_evidence,
            "memory_summary": memory.get_summary(),
        }

    try:
        result = await _run_blocking(_restore)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[Resilience] checkpoint restore failed")
        raise HTTPException(status_code=500, detail=f"Restore failed: {exc}") from exc

    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"No recoverable checkpoint for session {session_id!r}",
        )

    payload = {"session_id": session_id, **result}
    await hub.publish(EVT_SESSION_RECOVERED, session_id, payload)
    logger.info(
        "[Resilience] %s restored %s from %s (%d goal(s) already satisfied)",
        user.get("username", "?"),
        session_id,
        result.get("snapshot_id") or "checkpoint",
        len(result.get("satisfied_goals") or []),
    )
    return payload


# ── Live event stream ──────────────────────────────────────────────────────


@router.get("/{session_id}/events")
async def recent_events(
    session_id: str,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Replay buffer for clients that cannot hold a WebSocket.

    Also the fallback path when a proxy in front of the backend does not
    upgrade connections - the panels stay correct, just less immediate.
    """
    return {"session_id": session_id, "events": hub.history(session_id)}


@router.websocket("/{session_id}/events/ws")
async def stream_events(websocket: WebSocket, session_id: str) -> None:
    """
    Live resilience event stream.

    Authenticated by a ``token`` query parameter rather than a header: the
    browser WebSocket API cannot set Authorization on the handshake, so the
    bearer token has to travel in the URL. It is validated with the same
    decoder as every REST route before the socket is accepted.
    """
    token = websocket.query_params.get("token", "")
    if not token:
        await websocket.close(code=4401, reason="Authentication required")
        return
    try:
        from app.auth.auth import _decode_token

        _decode_token(token)
    except Exception:  # noqa: BLE001
        await websocket.close(code=4401, reason="Invalid or expired token")
        return

    await websocket.accept()
    queue = await hub.subscribe()
    try:
        # Replay what this session already emitted so a panel opened mid-run
        # is not blank.
        for event in hub.history(session_id):
            await websocket.send_json(event)

        while True:
            event = await queue.get()
            if event.get("session_id") and event["session_id"] != session_id:
                continue
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("[Resilience] websocket closed: %s", exc)
    finally:
        await hub.unsubscribe(queue)
