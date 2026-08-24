"""
Runtime analysis lifecycle tracing.

Records explicit stage transitions for every dynamic analysis attempt so
failures cannot be mistaken for "runtime not requested".
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LifecycleEvent:
    event: str
    status: str
    component: str
    message: str
    timestamp: str
    case_id: str = ""
    analysis_id: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "event": self.event,
            "status": self.status,
            "component": self.component,
            "message": self.message,
            "timestamp": self.timestamp,
        }
        if self.case_id:
            out["case_id"] = self.case_id
        if self.analysis_id:
            out["analysis_id"] = self.analysis_id
        if self.error:
            out["error"] = self.error
        return out


class RuntimeLifecycleTracker:
    """Accumulates lifecycle events and summary counters for one analysis run."""

    def __init__(
        self,
        case_id: str = "",
        analysis_id: str = "",
    ) -> None:
        self.case_id = case_id
        self.analysis_id = analysis_id or case_id
        self.events: List[LifecycleEvent] = []
        self._started = time.monotonic()
        self.dynamic_requested: bool = False
        self.dynamic_status: str = "NOT_STARTED"
        self.emulator_status: str = "UNKNOWN"
        self.apk_install_status: str = "UNKNOWN"
        self.frida_status: str = "UNKNOWN"
        self.explorer_status: str = "UNKNOWN"
        self.persistence_status: str = "UNKNOWN"
        self.dashboard_inclusion_status: str = "UNKNOWN"
        self.actions_discovered: int = 0
        self.actions_executed: int = 0
        self.actions_verified: int = 0
        self.runtime_event_count: int = 0
        self.evidence_count: int = 0
        self.action_pipeline: List[Dict[str, Any]] = []

    def record(
        self,
        event: str,
        status: str,
        component: str,
        message: str = "",
        error: Optional[str] = None,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.events.append(
            LifecycleEvent(
                event=event,
                status=status,
                component=component,
                message=message,
                timestamp=ts,
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                error=error,
            )
        )
        logger.info(
            "[RuntimeLifecycle] %s %s/%s %s%s",
            event,
            status,
            component,
            message,
            f" error={error}" if error else "",
        )

    def mark_requested(self) -> None:
        self.dynamic_requested = True
        self.dynamic_status = "QUEUED"
        self.record(
            "runtime_requested",
            "QUEUED",
            "orchestrator",
            "Dynamic analysis requested for case",
        )

    def mark_dynamic_status(self, status: str) -> None:
        self.dynamic_status = status

    def merge_explorer_reports(self, reports: Dict[str, Any]) -> None:
        if not reports:
            return
        summary = reports.get("exploration_summary") or {}
        deep = reports.get("deep_exploration") or {}
        cov = deep.get("coverage") or summary
        self.actions_discovered = int(
            cov.get("actions_discovered") or summary.get("actions_discovered") or 0
        )
        self.actions_executed = int(
            cov.get("actions_explored") or summary.get("buttons_clicked") or 0
        )
        self.actions_verified = int(cov.get("actions_verified") or 0)
        pipeline = deep.get("action_traces") or reports.get("action_traces") or []
        if isinstance(pipeline, list):
            self.action_pipeline = pipeline

    def to_summary_dict(self) -> Dict[str, Any]:
        elapsed = round(time.monotonic() - self._started, 2)
        return {
            "case_id": self.case_id,
            "analysis_id": self.analysis_id,
            "dynamic_requested": self.dynamic_requested,
            "dynamic_status": self.dynamic_status,
            "emulator_status": self.emulator_status,
            "apk_install_status": self.apk_install_status,
            "frida_status": self.frida_status,
            "explorer_status": self.explorer_status,
            "persistence_status": self.persistence_status,
            "dashboard_inclusion_status": self.dashboard_inclusion_status,
            "actions_discovered": self.actions_discovered,
            "actions_executed": self.actions_executed,
            "actions_verified": self.actions_verified,
            "runtime_events": self.runtime_event_count,
            "evidence_moments": self.evidence_count,
            "action_pipeline": self.action_pipeline,
            "elapsed_seconds": elapsed,
            "events": [e.to_dict() for e in self.events],
        }

    def attach_to_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        result["runtime_lifecycle"] = self.to_summary_dict()
        result["runtime_requested"] = self.dynamic_requested
        if self.emulator_status == "READY":
            result["runtime_attempted"] = True
        return result

    def write_json(self, artifact_dir: Path) -> Optional[Path]:
        try:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            path = artifact_dir / "runtime_lifecycle.json"
            path.write_text(
                json.dumps(self.to_summary_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            return path
        except OSError as exc:
            logger.warning("[RuntimeLifecycle] Could not write runtime_lifecycle.json: %s", exc)
            return None


# Process-wide tracker for the active dynamic session (set by frida_sandbox).
_active_tracker: Optional[RuntimeLifecycleTracker] = None


def set_active_tracker(tracker: Optional[RuntimeLifecycleTracker]) -> None:
    global _active_tracker
    _active_tracker = tracker


def get_active_tracker() -> Optional[RuntimeLifecycleTracker]:
    return _active_tracker


def record_lifecycle_event(
    event: str,
    status: str,
    component: str,
    message: str = "",
    error: Optional[str] = None,
) -> None:
    tracker = get_active_tracker()
    if tracker is not None:
        tracker.record(event, status, component, message, error=error)
