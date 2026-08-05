"""
Sudarshan — Dynamic Analysis Engine (DAE) explicit pipeline state machine.

Every transition is logged and exposed for runtime telemetry. Failures must
carry a reason; states are never skipped silently.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DAEStage(str, Enum):
    INITIALIZING = "INITIALIZING"
    INSTALLING = "INSTALLING"
    VERIFY_INSTALL = "VERIFY_INSTALL"
    RESOLVE_ACTIVITY = "RESOLVE_ACTIVITY"
    LAUNCHING = "LAUNCHING"
    WAIT_FOR_PID = "WAIT_FOR_PID"
    WAIT_FOR_UI = "WAIT_FOR_UI"
    ATTACH_FRIDA = "ATTACH_FRIDA"
    VERIFY_HOOKS = "VERIFY_HOOKS"
    START_EXPLORER = "START_EXPLORER"
    CAPTURE_RUNTIME = "CAPTURE_RUNTIME"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    BUILD_WORKFLOW = "BUILD_WORKFLOW"
    GENERATE_REPORT = "GENERATE_REPORT"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


@dataclass
class DAETransition:
    from_stage: str
    to_stage: str
    timestamp: float
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


class DAEPipelineTracker:
    """Per-session DAE state machine with structured transition history."""

    def __init__(self, package_name: str = "", session_id: str = "") -> None:
        self.package_name = package_name
        self.session_id = session_id
        self._stage: DAEStage = DAEStage.INITIALIZING
        self._history: List[DAETransition] = []
        self.failure_reason: str = ""
        self.suggested_recovery: str = ""
        self.metrics: Dict[str, Any] = {
            "screenshots_captured": 0,
            "screenshots_skipped_duplicate": 0,
            "events_captured": 0,
            "hooks_installed": 0,
            "crashes_recovered": 0,
            "launch_retries": 0,
            "explorer_actions": 0,
            "current_activity": "",
            "current_fragment": "",
            "workflow_stage": "",
            "coverage_percent": 0.0,
        }

    @property
    def stage(self) -> DAEStage:
        return self._stage

    def transition(
        self,
        to_stage: DAEStage,
        reason: str = "",
        **detail: Any,
    ) -> None:
        if to_stage == self._stage and not reason:
            return
        entry = DAETransition(
            from_stage=self._stage.value,
            to_stage=to_stage.value,
            timestamp=time.time(),
            reason=reason,
            detail=dict(detail),
        )
        self._history.append(entry)
        self._stage = to_stage
        logger.info(
            "[DAE] %s → %s (%s)",
            entry.from_stage,
            entry.to_stage,
            reason or "ok",
        )

    def fail(self, reason: str, suggested_recovery: str = "") -> None:
        self.failure_reason = reason
        self.suggested_recovery = suggested_recovery
        self.transition(DAEStage.FAILED, reason=reason, recovery=suggested_recovery)

    def update_metrics(self, **kwargs: Any) -> None:
        self.metrics.update(kwargs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "package_name": self.package_name,
            "current_stage": self._stage.value,
            "failure_reason": self.failure_reason,
            "suggested_recovery": self.suggested_recovery,
            "metrics": dict(self.metrics),
            "transitions": [
                {
                    "from": t.from_stage,
                    "to": t.to_stage,
                    "timestamp": t.timestamp,
                    "reason": t.reason,
                    "detail": t.detail,
                }
                for t in self._history
            ],
        }
