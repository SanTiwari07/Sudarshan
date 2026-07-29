"""
SUDARSHAN — Dynamic Analysis Session Manager
=============================================
Manages session lifecycle, sandbox process timeouts, and state transitions
(INITIALIZING -> RUNNING -> WAITING -> RECOVERING -> FINISHED / TIMEOUT / FAILED).

Orchestrates RuntimeEventBus, EvidenceStore, ScreenshotManager, BehaviorGraphBuilder,
ThreatCorrelatorListener, and ReportGenerator in a unified, evidence-driven pipeline.
"""

import asyncio
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        device_serial: str = "emulator-5554",
        output_dir: Optional[Path] = None,
        adb_path: str = "adb",
        timeout_seconds: int = 180,
    ) -> None:
        self.session_id = session_id
        self.package_name = package_name
        self.device_serial = device_serial
        self.output_dir = Path(output_dir) if output_dir else Path(f"/tmp/sudarshan_{session_id}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path
        self.timeout_seconds = timeout_seconds

        self._state: SessionState = SessionState.INITIALIZING
        self._state_history: List[Dict[str, Any]] = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.failure_reason: str = ""

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
        }
