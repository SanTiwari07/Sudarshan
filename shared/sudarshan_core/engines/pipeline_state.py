"""
SUDARSHAN — Pipeline State Machine, SLA Tracker & Diagnostic Telemetry
========================================================================
Manages explicit pipeline execution states, SLA performance budgets,
version metadata, event loss counters, and structured JSON telemetry.
"""

import enum
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ENGINE_VERSION = "2.3.1"
FRIDA_TARGET_VERSION = "17.16.4"
RISK_ENGINE_VERSION = "2.0"
DEFAULT_ANDROID_API = 35


class PipelineStage(str, enum.Enum):
    QUEUED = "QUEUED"
    AVD_BOOTING = "AVD_BOOTING"
    AVD_READY = "AVD_READY"
    APK_INSTALLING = "APK_INSTALLING"
    APK_INSTALLED = "APK_INSTALLED"
    FRIDA_STARTING = "FRIDA_STARTING"
    FRIDA_RUNNING = "FRIDA_RUNNING"
    PROCESS_SPAWNED = "PROCESS_SPAWNED"
    HOOKS_LOADING = "HOOKS_LOADING"
    HOOKS_READY = "HOOKS_READY"
    APP_RUNNING = "APP_RUNNING"
    EVENT_COLLECTION = "EVENT_COLLECTION"
    EVENT_CORRELATION = "EVENT_CORRELATION"
    BFCI_CALCULATED = "BFCI_CALCULATED"
    REPORT_COMPLETE = "REPORT_COMPLETE"
    FAILED = "FAILED"


class AnalysisOutcome(str, enum.Enum):
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    NO_RUNTIME_ACTIVITY = "NO_RUNTIME_ACTIVITY"
    FAILED = "FAILED"


# SLA Performance Budgets in seconds
STAGE_SLA_BUDGETS: Dict[PipelineStage, float] = {
    PipelineStage.QUEUED: 5.0,
    PipelineStage.AVD_BOOTING: 60.0,
    PipelineStage.AVD_READY: 5.0,
    PipelineStage.APK_INSTALLING: 15.0,
    PipelineStage.APK_INSTALLED: 5.0,
    PipelineStage.FRIDA_STARTING: 5.0,
    PipelineStage.FRIDA_RUNNING: 5.0,
    PipelineStage.PROCESS_SPAWNED: 10.0,
    PipelineStage.HOOKS_LOADING: 5.0,
    PipelineStage.HOOKS_READY: 3.0,
    PipelineStage.APP_RUNNING: 10.0,
    PipelineStage.EVENT_COLLECTION: 120.0,
    PipelineStage.EVENT_CORRELATION: 10.0,
    PipelineStage.BFCI_CALCULATED: 2.0,
    PipelineStage.REPORT_COMPLETE: 5.0,
}

TOTAL_PIPELINE_SLA_BUDGET: float = 300.0  # 5 minutes max overall budget


@dataclass
class EventCounters:
    generated: int = 0
    received: int = 0
    stored: int = 0
    scored: int = 0
    rendered: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "generated": self.generated,
            "received": self.received,
            "stored": self.stored,
            "scored": self.scored,
            "rendered": self.rendered,
        }


@dataclass
class HookCoverageMetrics:
    total_installed: int = 0
    total_triggered: int = 0
    category_installed: Dict[str, int] = field(default_factory=dict)
    category_triggered: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_installed": self.total_installed,
            "total_triggered": self.total_triggered,
            "coverage_ratio": (
                round(self.total_triggered / max(self.total_installed, 1), 3)
            ),
            "category_installed": self.category_installed,
            "category_triggered": self.category_triggered,
        }


@dataclass
class StageLogRecord:
    stage: PipelineStage
    timestamp: float
    duration_ms: float
    status: str
    detail: str = ""


class PipelineTracker:
    """Tracks state transitions, performance budgets, metrics, and structured logs per analysis case."""

    def __init__(self, case_id: str, package_name: str = "Unknown"):
        self.case_id = case_id
        self.package_name = package_name
        self.current_stage: PipelineStage = PipelineStage.QUEUED
        self.outcome: AnalysisOutcome = AnalysisOutcome.SUCCESS
        self.start_time: float = time.time()
        self.stage_start_time: float = time.time()
        self.stage_durations: Dict[str, float] = {}
        self.stage_history: List[StageLogRecord] = []
        self.event_counters: EventCounters = EventCounters()
        self.hook_coverage: HookCoverageMetrics = HookCoverageMetrics()
        self.hook_exceptions: List[Dict[str, Any]] = []
        self.failure_reason: Optional[str] = None
        self.bundle_hash: Optional[str] = None
        self.adb_ready: bool = False
        self.emulator_ready: bool = False
        self.apk_installed: bool = False
        self.frida_running: bool = False
        self.attached: bool = False
        self.hooks_loaded: bool = False

        self.transition_to(PipelineStage.QUEUED, "Analysis enqueued")

    def transition_to(self, stage: PipelineStage, detail: str = "") -> None:
        now = time.time()
        duration_ms = (now - self.stage_start_time) * 1000.0
        
        # Record history for previous stage
        if self.stage_history:
            self.stage_durations[self.current_stage.value] = round(duration_ms, 2)

        # Check SLA budget
        budget = STAGE_SLA_BUDGETS.get(stage, 30.0)
        sla_status = "OK"
        if (duration_ms / 1000.0) > budget:
            sla_status = "EXCEEDED_SLA"
            logger.warning(
                f"[Pipeline SLA] Case {self.case_id}: Stage {self.current_stage.value} "
                f"took {duration_ms/1000.0:.1f}s (budget: {budget:.1f}s)"
            )

        self.current_stage = stage
        self.stage_start_time = now

        log_rec = StageLogRecord(
            stage=stage,
            timestamp=now,
            duration_ms=round(duration_ms, 2),
            status=sla_status if stage != PipelineStage.FAILED else "FAILED",
            detail=detail,
        )
        self.stage_history.append(log_rec)

        # Emit structured JSON log line
        log_json = {
            "case_id": self.case_id,
            "package_name": self.package_name,
            "stage": stage.value,
            "duration_ms": round(duration_ms, 2),
            "total_elapsed_s": round(now - self.start_time, 2),
            "status": sla_status,
            "detail": detail,
        }
        logger.info(f"[PIPELINE_STATE] {json.dumps(log_json)}")

    def mark_failed(self, reason: str) -> None:
        self.failure_reason = reason
        self.outcome = AnalysisOutcome.FAILED
        self.transition_to(PipelineStage.FAILED, reason)

    def record_hook_exception(self, hook_name: str, error_msg: str) -> None:
        exc_record = {
            "timestamp": time.time(),
            "hook": hook_name,
            "error": error_msg,
        }
        self.hook_exceptions.append(exc_record)
        logger.warning(f"[HookException] Case {self.case_id}: {hook_name} failed: {error_msg}")

    def get_version_metadata(self) -> Dict[str, Any]:
        return {
            "analysis_version": ENGINE_VERSION,
            "frida_version": FRIDA_TARGET_VERSION,
            "risk_engine_version": RISK_ENGINE_VERSION,
            "android_api": DEFAULT_ANDROID_API,
            "bundle_hash": self.bundle_hash or "unknown",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def get_diagnostics(self) -> Dict[str, Any]:
        now = time.time()
        return {
            "case_id": self.case_id,
            "package_name": self.package_name,
            "pipeline_state": self.current_stage.value,
            "outcome": self.outcome.value,
            "failure_reason": self.failure_reason,
            "elapsed_seconds": round(now - self.start_time, 2),
            "adb_ready": self.adb_ready,
            "emulator_ready": self.emulator_ready,
            "apk_installed": self.apk_installed,
            "frida_running": self.frida_running,
            "attached": self.attached,
            "hooks_loaded": self.hooks_loaded,
            "event_counters": self.event_counters.to_dict(),
            "hook_coverage": self.hook_coverage.to_dict(),
            "hook_exceptions_count": len(self.hook_exceptions),
            "hook_exceptions": self.hook_exceptions[:10],
            "version_metadata": self.get_version_metadata(),
            "stage_durations": self.stage_durations,
        }


# Global registry for active pipeline trackers
_ACTIVE_TRACKERS: Dict[str, PipelineTracker] = {}


def get_tracker(case_id: str, package_name: str = "Unknown") -> PipelineTracker:
    if case_id not in _ACTIVE_TRACKERS:
        _ACTIVE_TRACKERS[case_id] = PipelineTracker(case_id, package_name)
    return _ACTIVE_TRACKERS[case_id]


def remove_tracker(case_id: str) -> None:
    _ACTIVE_TRACKERS.pop(case_id, None)
