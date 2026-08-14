"""
SUDARSHAN - Dynamic Analysis Session Manager
=============================================
Manages session lifecycle, sandbox process timeouts, and state transitions
(INITIALIZING -> RUNNING -> WAITING -> RECOVERING -> FINISHED / TIMEOUT / FAILED).

Orchestrates RuntimeEventBus, EvidenceStore, ScreenshotManager, BehaviorGraphBuilder,
ThreatCorrelatorListener, and ReportGenerator in a unified, evidence-driven pipeline.
"""

import asyncio
import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core import runtime_paths
from sudarshan_core.engines.behavior_graph import BehaviorGraphBuilder
from sudarshan_core.engines.event_bus import EventType, RuntimeEvent, RuntimeEventBus
from sudarshan_core.engines.evidence_store import EvidenceStore
from sudarshan_core.engines.screenshot_manager import ScreenshotManager
from sudarshan_core.services.threat_correlator import ThreatCorrelatorListener

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Explicit lifecycle states for a dynamic analysis session."""
    INITIALIZING = "INITIALIZING"
    RUNNING      = "RUNNING"
    WAITING      = "WAITING"
    RECOVERING   = "RECOVERING"
    FINISHED     = "FINISHED"
    TIMEOUT      = "TIMEOUT"
    FAILED       = "FAILED"
    FLUSHING     = "FLUSHING"
    # Re-hydrated from a checkpoint after a crash. Distinct from RECOVERING,
    # which is the attempt; this is the state a session is in once it has
    # successfully resumed and is running on restored state.
    RECOVERED    = "RECOVERED"


class DynamicAnalysisSession:
    """
    Supervises dynamic malware analysis sandbox runs.
    
    Acts as the master orchestrator initializing and controlling all dynamic analysis
    subsystems over the shared RuntimeEventBus.
    """

    def __init__(
        self,
        session_id: str,
        package_name: str,
        device_serial: str = "",
        output_dir: Optional[Path] = None,
        adb_path: str = "adb",
        timeout_seconds: int = 180,
    ) -> None:
        self.session_id = session_id
        self.package_name = package_name
        # Empty serial → resolve via SandboxProvider at first use if needed
        if not device_serial:
            try:
                from sudarshan_core.sandbox import get_sandbox_provider
                device_serial = get_sandbox_provider().select_device().serial
            except Exception:
                device_serial = ""
        self.device_serial = device_serial
        # `/tmp/sudarshan_<id>` used to be the default here. That is not a path
        # on Windows, so every artifact this session wrote - including its
        # checkpoints - landed somewhere unreadable on the platform most of
        # this project is developed on.
        self.output_dir = (
            Path(output_dir) if output_dir else runtime_paths.session_dir(session_id)
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path
        self.timeout_seconds = timeout_seconds

        self._state: SessionState = SessionState.INITIALIZING
        self._state_history: List[Dict[str, Any]] = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.failure_reason: str = ""

        # ── Checkpoint recovery ───────────────────────────────────────────────
        # Checkpoints live outside output_dir so a caller that wipes the
        # session directory between attempts does not destroy the thing needed
        # to resume. The location is env-overridable for containers.
        self.checkpoint_file_path: Path = (
            runtime_paths.checkpoint_dir()
            / f"{runtime_paths.safe_component(session_id)}.checkpoint.json"
        )
        self.last_snapshot_id: str = ""
        self.recovery_attempts: int = 0
        self.recovered_from_snapshot: bool = False

        # ── Instantiate Pipeline Backbone ─────────────────────────────────────
        self.event_bus = RuntimeEventBus()
        self.evidence_store = EvidenceStore(
            event_bus=self.event_bus,
            package_name=package_name,
        )
        self.screenshot_manager = ScreenshotManager(
            device_serial=device_serial,
            output_dir=self.output_dir,
            event_bus=self.event_bus,
            evidence_store=self.evidence_store,
            adb_path=adb_path,
            package_name=package_name,
        )
        self.behavior_graph = BehaviorGraphBuilder(event_bus=self.event_bus)
        self.threat_listener = ThreatCorrelatorListener(
            event_bus=self.event_bus,
            package_name=package_name,
        )

        # Record initial state
        self.set_state(SessionState.INITIALIZING, "Session created")

    @property
    def state(self) -> SessionState:
        return self._state

    def set_state(self, new_state: SessionState, reason: str = "") -> None:
        """Transition session to a new state and record timestamp."""
        old_state = self._state
        self._state = new_state
        entry = {
            "from_state": old_state.value if isinstance(old_state, SessionState) else str(old_state),
            "to_state": new_state.value,
            "timestamp": time.time(),
            "reason": reason,
        }
        self._state_history.append(entry)
        logger.info(
            "[SessionManager] [%s] State transition: %s -> %s (%s)",
            self.session_id, old_state.value, new_state.value, reason or "no reason"
        )

    def start(self) -> None:
        """Mark session execution as started and emit SESSION_STARTED event."""
        self.start_time = time.time()
        self.set_state(SessionState.RUNNING, "Sandbox launched")
        self.event_bus.publish(RuntimeEvent(
            event_type=EventType.SESSION_STARTED,
            timestamp=self.start_time,
            session_id=self.session_id,
            payload={"package_name": self.package_name, "device_serial": self.device_serial}
        ))

    def finish(self, reason: str = "Analysis complete", report_dict: Optional[Dict[str, Any]] = None) -> str:
        """
        Mark session execution as finished, flush evidence and behavior graph,
        and render the HTML report. Returns path to HTML report.
        """
        self.end_time = time.time()
        self.set_state(SessionState.FLUSHING, "Flushing telemetry artifacts")

        self.event_bus.publish(RuntimeEvent(
            event_type=EventType.SESSION_FINISHED,
            timestamp=self.end_time,
            session_id=self.session_id,
            payload={"duration_seconds": self.elapsed_seconds(), "reason": reason}
        ))

        # Flush evidence artifacts
        ev_file = self.output_dir / "evidence.json"
        self.evidence_store.flush(ev_file)

        bg_file = self.output_dir / "behavior_graph.json"
        self.behavior_graph.flush(bg_file)

        self.screenshot_manager.flush_manifest()

        # Render HTML Report
        report_file = self.output_dir / "report.html"
        if report_dict:
            try:
                from sudarshan_core.engines.report_generator import build_report
                build_report(report_dict, apk_dir=self.output_dir, output_path=report_file)
            except Exception as e:
                logger.error("[SessionManager] Report generation failed: %s", e)

        self.set_state(SessionState.FINISHED, reason)
        return str(report_file)

    def timeout(self, reason: str = "Execution budget exceeded") -> None:
        """Mark session as timed out."""
        self.end_time = time.time()
        self.set_state(SessionState.TIMEOUT, reason)

    def fail(self, reason: str) -> None:
        """Mark session as failed due to error."""
        self.end_time = time.time()
        self.failure_reason = reason
        self.set_state(SessionState.FAILED, reason)

    def elapsed_seconds(self) -> float:
        """Return elapsed execution duration in seconds."""
        if self.start_time == 0.0:
            return 0.0
        ref_end = self.end_time if self.end_time > 0.0 else time.time()
        return round(ref_end - self.start_time, 2)

    def is_active(self) -> bool:
        """Return True if session is currently running, waiting, or recovering."""
        return self._state in (SessionState.RUNNING, SessionState.WAITING, SessionState.RECOVERING)

    # ── Checkpoint recovery ────────────────────────────────────────────────────

    def save_checkpoint(self, snapshot_data: Dict[str, Any]) -> Optional[Path]:
        """
        Persist a resumable snapshot of this session.

        Written atomically - to a temporary file in the same directory, then
        renamed. A checkpoint is written *while* a sandbox is running hostile
        code; if the process dies mid-write, a half-flushed JSON file would be
        unparseable and the crash it was meant to survive would take the
        recovery path with it. ``os.replace`` is atomic on POSIX and Windows
        alike, so a reader sees either the previous checkpoint or the new one.

        Returns the checkpoint path, or None if it could not be written.
        """
        if not isinstance(snapshot_data, dict) or not snapshot_data:
            logger.warning("[SessionManager] Refusing to write an empty checkpoint")
            return None

        payload = {
            "session_id": self.session_id,
            "package_name": self.package_name,
            "device_serial": self.device_serial,
            "output_dir": str(self.output_dir),
            "state": self._state.value,
            "elapsed_seconds": self.elapsed_seconds(),
            "saved_at": time.time(),
            "evidence_count": self.evidence_store.count(),
            "snapshot": snapshot_data,
        }

        path = self.checkpoint_file_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
                newline="\n",
            )
            os.replace(tmp, path)
        except OSError as exc:
            logger.error("[SessionManager] Checkpoint write failed: %s", exc)
            return None

        self.last_snapshot_id = str(snapshot_data.get("snapshot_id") or "")
        logger.info(
            "[SessionManager] [%s] Checkpoint saved (%s) -> %s",
            self.session_id,
            self.last_snapshot_id or "unnamed",
            path,
        )
        self.event_bus.publish(RuntimeEvent(
            event_type=EventType.SESSION_STARTED,
            timestamp=time.time(),
            session_id=self.session_id,
            payload={
                "checkpoint_saved": True,
                "snapshot_id": self.last_snapshot_id,
                "path": str(path),
            },
        ))
        return path

    @staticmethod
    def load_checkpoint(
        session_id: str,
        checkpoint_path: Optional[Path] = None,
    ) -> Optional[Dict[str, Any]]:
        """Read a checkpoint payload without instantiating a session."""
        path = checkpoint_path or (
            runtime_paths.checkpoint_dir()
            / f"{runtime_paths.safe_component(session_id)}.checkpoint.json"
        )
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("[SessionManager] Checkpoint unreadable (%s): %s", path, exc)
            return None
        return data if isinstance(data, dict) else None

    def recover_from_checkpoint(
        self,
        checkpoint_path: Optional[Path] = None,
        *,
        memory: Optional[Any] = None,
        goal_tracker: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Re-hydrate this session from its last checkpoint.

        Restores agent memory and marks already-satisfied goals as COMPLETED so
        the resumed run does not re-execute them. That second part is the point:
        re-driving a completed goal would re-emit its evidence, and the verdict
        is computed from evidence counts - a crash-and-resume could otherwise
        inflate the score of a sample that did nothing new.

        Returns the snapshot dict on success, None when there is nothing to
        recover from.
        """
        self.recovery_attempts += 1
        self.set_state(SessionState.RECOVERING, "Restoring from checkpoint")

        payload = self.load_checkpoint(self.session_id, checkpoint_path or self.checkpoint_file_path)
        if not payload:
            self.set_state(SessionState.FAILED, "No checkpoint available to recover from")
            return None

        snapshot = payload.get("snapshot")
        if not isinstance(snapshot, dict) or not snapshot:
            self.set_state(SessionState.FAILED, "Checkpoint contained no snapshot")
            return None

        if memory is not None:
            try:
                memory.restore_snapshot(snapshot)
            except Exception as exc:  # noqa: BLE001
                logger.error("[SessionManager] Memory restore failed: %s", exc)

        satisfied = [str(g) for g in (snapshot.get("satisfied_goals") or [])]
        if goal_tracker is not None and satisfied:
            try:
                from sudarshan_core.engines.agentic.goal_tracker import GoalStatus

                for name in satisfied:
                    goal = goal_tracker.get_goal_by_name(name)
                    if goal is not None:
                        goal.status = GoalStatus.COMPLETED
            except Exception as exc:  # noqa: BLE001
                logger.error("[SessionManager] Goal restore failed: %s", exc)

        self.last_snapshot_id = str(snapshot.get("snapshot_id") or "")
        self.recovered_from_snapshot = True
        self.set_state(
            SessionState.RECOVERED,
            f"Resumed from {self.last_snapshot_id or 'checkpoint'} "
            f"({len(satisfied)} goal(s) already satisfied)",
        )
        logger.info(
            "[SessionManager] [%s] Recovered from checkpoint: iteration %s, "
            "%s goal(s) already satisfied, %s evidence record(s) at save time",
            self.session_id,
            snapshot.get("iteration", 0),
            len(satisfied),
            payload.get("evidence_count", 0),
        )
        return snapshot

    def discard_checkpoint(self) -> bool:
        """Remove the checkpoint once a session has finished cleanly."""
        try:
            if self.checkpoint_file_path.is_file():
                self.checkpoint_file_path.unlink()
                return True
        except OSError as exc:
            logger.warning("[SessionManager] Could not remove checkpoint: %s", exc)
        return False

    def get_status_summary(self) -> Dict[str, Any]:
        """Return JSON-serializable summary of session status."""
        return {
            "session_id": self.session_id,
            "package_name": self.package_name,
            "device_serial": self.device_serial,
            "current_state": self._state.value,
            "elapsed_seconds": self.elapsed_seconds(),
            "timeout_seconds": self.timeout_seconds,
            "failure_reason": self.failure_reason,
            "output_dir": str(self.output_dir),
            "evidence_count": self.evidence_store.count(),
            "behavior_nodes": len(self.behavior_graph.get_nodes()),
            "history": self._state_history,
            "checkpoint": {
                "path": str(self.checkpoint_file_path),
                "exists": self.checkpoint_file_path.is_file(),
                "last_snapshot_id": self.last_snapshot_id,
                "recovery_attempts": self.recovery_attempts,
                "recovered": self.recovered_from_snapshot,
            },
        }
