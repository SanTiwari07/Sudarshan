"""
Structured pipeline stage timing and progress for Sudarshan investigations.

Emits stage_started / stage_completed / stage_failed events with duration_ms.
Used by the gateway orchestrator and analysis-engine microservice.
"""

from __future__ import annotations

import enum
import json
import logging
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

PIPELINE_TIMING_VERSION = "1"


class OrchestratorStage(str, enum.Enum):
    """High-level pipeline states exposed to the analyst UI."""

    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DYNAMIC_PREPARATION = "DYNAMIC_PREPARATION"
    DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
    EVIDENCE_PROCESSING = "EVIDENCE_PROCESSING"
    THREAT_CORRELATION = "THREAT_CORRELATION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    INTELLIGENCE_GENERATION = "INTELLIGENCE_GENERATION"
    REPORT_GENERATION = "REPORT_GENERATION"
    PERSISTING = "PERSISTING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    ANALYSIS_ENGINE = "ANALYSIS_ENGINE"


# Monotonic progress weights (sum to 100). Order reflects typical completion.
STAGE_PROGRESS_WEIGHTS: Dict[str, int] = {
    "UPLOAD": 3,
    "HASH": 2,
    "CASE_CREATION": 2,
    "STATIC": 8,
    "MOBSF": 12,
    "NATIVE_ANALYSIS": 5,
    "APKTOOL": 5,
    "JADX": 5,
    "MANIFEST": 3,
    "VIDE_STATIC": 2,
    "SANDBOX_PREP": 3,
    "INSTALL": 2,
    "LAUNCH": 2,
    "PID_RESOLVE": 1,
    "FRIDA_ATTACH": 2,
    "FRIDA_DEOPT": 1,
    "CANARY": 1,
    "HOOK_INSTALL": 2,
    "AGENTIC_EXPLORER": 10,
    "NETWORK_CAPTURE": 3,
    "EVIDENCE": 3,
    "WORKFLOW": 2,
    "BFCI": 2,
    "VIDE_DYNAMIC": 2,
    "THREAT_CORRELATION": 5,
    "RISK": 3,
    "RAG_INDEX": 2,
    "GEMINI": 5,
    "REPORT": 2,
    "PERSISTENCE": 2,
    "FINALIZATION": 2,
    "ENGINE_DELEGATION": 55,
}

ORCHESTRATOR_STAGE_PROGRESS: Dict[OrchestratorStage, int] = {
    OrchestratorStage.QUEUED: 2,
    OrchestratorStage.VALIDATING: 5,
    OrchestratorStage.STATIC_ANALYSIS: 25,
    OrchestratorStage.DYNAMIC_PREPARATION: 45,
    OrchestratorStage.DYNAMIC_ANALYSIS: 65,
    OrchestratorStage.EVIDENCE_PROCESSING: 72,
    OrchestratorStage.THREAT_CORRELATION: 78,
    OrchestratorStage.RISK_ASSESSMENT: 82,
    OrchestratorStage.INTELLIGENCE_GENERATION: 90,
    OrchestratorStage.REPORT_GENERATION: 95,
    OrchestratorStage.PERSISTING: 98,
    OrchestratorStage.ANALYSIS_ENGINE: 40,
    OrchestratorStage.COMPLETED: 100,
    OrchestratorStage.PARTIAL: 100,
    OrchestratorStage.FAILED: 100,
}

# Map fine-grained timing keys → orchestrator stage for UI truthfulness
FINE_STAGE_TO_ORCHESTRATOR: Dict[str, OrchestratorStage] = {
    "UPLOAD": OrchestratorStage.VALIDATING,
    "HASH": OrchestratorStage.VALIDATING,
    "CASE_CREATION": OrchestratorStage.VALIDATING,
    "STATIC": OrchestratorStage.STATIC_ANALYSIS,
    "MOBSF": OrchestratorStage.STATIC_ANALYSIS,
    "NATIVE_ANALYSIS": OrchestratorStage.STATIC_ANALYSIS,
    "APKTOOL": OrchestratorStage.STATIC_ANALYSIS,
    "JADX": OrchestratorStage.STATIC_ANALYSIS,
    "MANIFEST": OrchestratorStage.STATIC_ANALYSIS,
    "VIDE_STATIC": OrchestratorStage.STATIC_ANALYSIS,
    "SANDBOX_PREP": OrchestratorStage.DYNAMIC_PREPARATION,
    "INSTALL": OrchestratorStage.DYNAMIC_PREPARATION,
    "LAUNCH": OrchestratorStage.DYNAMIC_PREPARATION,
    "PID_RESOLVE": OrchestratorStage.DYNAMIC_ANALYSIS,
    "FRIDA_ATTACH": OrchestratorStage.DYNAMIC_ANALYSIS,
    "FRIDA_DEOPT": OrchestratorStage.DYNAMIC_ANALYSIS,
    "CANARY": OrchestratorStage.DYNAMIC_ANALYSIS,
    "HOOK_INSTALL": OrchestratorStage.DYNAMIC_ANALYSIS,
    "AGENTIC_EXPLORER": OrchestratorStage.DYNAMIC_ANALYSIS,
    "NETWORK_CAPTURE": OrchestratorStage.DYNAMIC_ANALYSIS,
    "EVIDENCE": OrchestratorStage.EVIDENCE_PROCESSING,
    "WORKFLOW": OrchestratorStage.EVIDENCE_PROCESSING,
    "BFCI": OrchestratorStage.EVIDENCE_PROCESSING,
    "VIDE_DYNAMIC": OrchestratorStage.EVIDENCE_PROCESSING,
    "THREAT_CORRELATION": OrchestratorStage.THREAT_CORRELATION,
    "RISK": OrchestratorStage.RISK_ASSESSMENT,
    "RAG_INDEX": OrchestratorStage.INTELLIGENCE_GENERATION,
    "GEMINI": OrchestratorStage.INTELLIGENCE_GENERATION,
    "REPORT": OrchestratorStage.REPORT_GENERATION,
    "PERSISTENCE": OrchestratorStage.PERSISTING,
    "FINALIZATION": OrchestratorStage.COMPLETED,
    "ENGINE_DELEGATION": OrchestratorStage.ANALYSIS_ENGINE,
}


@dataclass
class StageTimingRecord:
    stage: str
    started_at: str
    completed_at: Optional[str] = None
    duration_ms: Optional[float] = None
    status: str = "running"
    error: Optional[str] = None
    substage: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error": self.error,
            "substage": self.substage,
        }


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cumulative_progress(completed_stages: List[str]) -> int:
    total = sum(STAGE_PROGRESS_WEIGHTS.get(s, 1) for s in STAGE_PROGRESS_WEIGHTS)
    done = sum(STAGE_PROGRESS_WEIGHTS.get(s, 1) for s in completed_stages if s in STAGE_PROGRESS_WEIGHTS)
    if total <= 0:
        return 0
    return min(99, int(round(100 * done / total)))


class PipelineTimer:
  """Records per-stage timings and optional live progress callbacks."""

  def __init__(
      self,
      job_id: str,
      case_id: str,
      on_update: Optional[Callable[[Dict[str, Any]], None]] = None,
  ):
      self.job_id = job_id
      self.case_id = case_id
      self.on_update = on_update
      self._records: Dict[str, StageTimingRecord] = {}
      self._completed_order: List[str] = []
      self._orchestrator_stage: OrchestratorStage = OrchestratorStage.QUEUED
      self._started_monotonic = time.monotonic()
      self._stage_start_mono: Dict[str, float] = {}
      self._active_fine_stage: Optional[str] = None

  def set_orchestrator_stage(self, stage: OrchestratorStage, message: str = "") -> None:
      self._orchestrator_stage = stage
      self._emit(message=message)

  def stage_started(self, stage: str, substage: str = "") -> None:
      rec = StageTimingRecord(stage=stage, started_at=_iso_now(), substage=substage)
      self._records[stage] = rec
      self._stage_start_mono[stage] = time.monotonic()
      self._active_fine_stage = stage
      orch = FINE_STAGE_TO_ORCHESTRATOR.get(stage, self._orchestrator_stage)
      self._orchestrator_stage = orch
      payload = {
          "event": "stage_started",
          "job_id": self.job_id,
          "case_id": self.case_id,
          "stage": stage,
          "substage": substage,
          "started_at": rec.started_at,
          "orchestrator_stage": orch.value,
      }
      logger.info("[PIPELINE_TIMING] %s", json.dumps(payload))
      self._emit(message=substage or stage)

  def stage_completed(self, stage: str) -> None:
      rec = self._records.get(stage)
      now = _iso_now()
      if rec:
          rec.completed_at = now
          started_mono = self._stage_start_mono.get(stage, self._started_monotonic)
          rec.duration_ms = round((time.monotonic() - started_mono) * 1000, 2)
          rec.status = "completed"
      if stage not in self._completed_order:
          self._completed_order.append(stage)
      if self._active_fine_stage == stage:
          self._active_fine_stage = None
      payload = {
          "event": "stage_completed",
          "job_id": self.job_id,
          "case_id": self.case_id,
          "stage": stage,
          "completed_at": now,
          "duration_ms": rec.duration_ms if rec else None,
          "status": "completed",
          "error": None,
      }
      logger.info("[PIPELINE_TIMING] %s", json.dumps(payload))
      self._emit()

  def stage_failed(self, stage: str, error: str) -> None:
      rec = self._records.get(stage)
      now = _iso_now()
      if rec:
          rec.completed_at = now
          rec.status = "failed"
          rec.error = error
      payload = {
          "event": "stage_failed",
          "job_id": self.job_id,
          "case_id": self.case_id,
          "stage": stage,
          "completed_at": now,
          "status": "failed",
          "error": error,
      }
      logger.warning("[PIPELINE_TIMING] %s", json.dumps(payload))
      self._orchestrator_stage = OrchestratorStage.FAILED
      self._emit(message=error)

  def stage_timeout(self, stage: str, error: str = "stage timeout") -> None:
      self.stage_failed(stage, error)

  @contextmanager
  def stage(self, name: str, substage: str = ""):
      self.stage_started(name, substage)
      try:
          yield
          self.stage_completed(name)
      except Exception as e:
          self.stage_failed(name, str(e))
          raise

  @asynccontextmanager
  async def async_stage(self, name: str, substage: str = ""):
      self.stage_started(name, substage)
      try:
          yield
          self.stage_completed(name)
      except Exception as e:
          self.stage_failed(name, str(e))
          raise

  def progress_pct(self) -> int:
      if self._orchestrator_stage == OrchestratorStage.COMPLETED:
          return 100
      if self._orchestrator_stage == OrchestratorStage.FAILED:
          return min(99, _cumulative_progress(self._completed_order))
      orch_pct = ORCHESTRATOR_STAGE_PROGRESS.get(self._orchestrator_stage, 10)
      fine_pct = _cumulative_progress(self._completed_order)
      return min(99, max(orch_pct, fine_pct))

  def snapshot(self) -> Dict[str, Any]:
      elapsed_ms = round((time.monotonic() - self._started_monotonic) * 1000, 2)
      active = self._active_fine_stage
      rec = self._records.get(active) if active else None
      return {
          "job_id": self.job_id,
          "case_id": self.case_id,
          "progress_pct": self.progress_pct(),
          "orchestrator_stage": self._orchestrator_stage.value,
          "pipeline_stage": self._orchestrator_stage.value,
          "pipeline_substage": (rec.substage if rec and rec.substage else active) or "",
          "pipeline_message": self._message_for_stage(),
          "elapsed_ms": elapsed_ms,
          "active_fine_stage": active,
          "stage_timings": [r.to_dict() for r in self._records.values()],
          "timing_version": PIPELINE_TIMING_VERSION,
      }

  def _message_for_stage(self) -> str:
      messages = {
          OrchestratorStage.ANALYSIS_ENGINE: "Running static and dynamic analysis in analysis-engine…",
          OrchestratorStage.STATIC_ANALYSIS: "Static intelligence (MobSF, APKTool, JADX)…",
          OrchestratorStage.DYNAMIC_ANALYSIS: "Dynamic sandbox (Frida, Agentic Explorer)…",
          OrchestratorStage.THREAT_CORRELATION: "Correlating VirusTotal, OTX, AbuseIPDB…",
          OrchestratorStage.RISK_ASSESSMENT: "Calculating deterministic FRS…",
          OrchestratorStage.INTELLIGENCE_GENERATION: "RAG indexing and Gemini narrative…",
          OrchestratorStage.PERSISTING: "Saving case and investigation index…",
          OrchestratorStage.QUEUED: "Queued for analysis…",
      }
      return messages.get(self._orchestrator_stage, self._orchestrator_stage.value)

  def _emit(self, message: str = "") -> None:
      if not self.on_update:
          return
      snap = self.snapshot()
      if message:
          snap["pipeline_message"] = message
      try:
          self.on_update(snap)
      except Exception as e:
          logger.warning("[PipelineTimer] on_update failed: %s", e)

  def merge_engine_timings(self, engine_payload: Dict[str, Any]) -> None:
      """Import stage_timings returned by analysis-engine."""
      timings = engine_payload.get("stage_timings") or []
      for item in timings:
          stage = item.get("stage")
          if not stage:
              continue
          rec = StageTimingRecord(
              stage=stage,
              started_at=item.get("started_at", _iso_now()),
              completed_at=item.get("completed_at"),
              duration_ms=item.get("duration_ms"),
              status=item.get("status", "completed"),
              error=item.get("error"),
              substage=item.get("substage", ""),
          )
          self._records[stage] = rec
          if rec.status == "completed" and stage not in self._completed_order:
              self._completed_order.append(stage)

  def format_timing_table(self) -> str:
      lines = ["STAGE                  DURATION", "--------------------------------"]
      total = 0.0
      for stage in self._completed_order:
          rec = self._records.get(stage)
          ms = rec.duration_ms if rec and rec.duration_ms else 0.0
          total += ms
          lines.append(f"{stage:22} {ms:,.0f} ms")
      lines.append("--------------------------------")
      lines.append(f"{'TOTAL':22} {total:,.0f} ms")
      return "\n".join(lines)

  def to_dict(self) -> Dict[str, Any]:
      return {
          "timing_table": self.format_timing_table(),
          "snapshot": self.snapshot(),
      }
