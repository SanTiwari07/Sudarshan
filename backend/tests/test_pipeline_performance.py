"""Pipeline performance, progress truthfulness, and timing regression tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sudarshan_core.engines.pipeline_timing import (
    ORCHESTRATOR_STAGE_PROGRESS,
    OrchestratorStage,
    PipelineTimer,
    STAGE_PROGRESS_WEIGHTS,
)
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.services.mobsf_client import MobSFClient


def test_pipeline_timer_stage_lifecycle():
    events = []

    def on_update(snap):
        events.append(snap.get("orchestrator_stage"))

    timer = PipelineTimer("job-1", "case-abc", on_update=on_update)
    timer.set_orchestrator_stage(OrchestratorStage.RISK_ASSESSMENT)
    timer.stage_started("RISK", "FRS")
    timer.stage_completed("RISK")
    assert timer.progress_pct() >= ORCHESTRATOR_STAGE_PROGRESS[OrchestratorStage.RISK_ASSESSMENT] - 5
    assert "RISK_ASSESSMENT" in events


def test_no_stuck_risk_stage_when_gemini_running():
    timer = PipelineTimer("job-2", "case-xyz")
    timer.stage_completed("RISK")
    timer.set_orchestrator_stage(OrchestratorStage.INTELLIGENCE_GENERATION)
    timer.stage_started("GEMINI")
    snap = timer.snapshot()
    assert snap["orchestrator_stage"] == OrchestratorStage.INTELLIGENCE_GENERATION.value
    assert snap["pipeline_stage"] == OrchestratorStage.INTELLIGENCE_GENERATION.value


def test_risk_engine_remains_deterministic():
    flags = {
        "has_accessibility_abuse": True,
        "has_sms_read_write": False,
        "has_system_alert_window": False,
        "dangerous_apis_found": [],
        "hardcoded_urls_ips": [],
        "targets_indian_banks": True,
    }
    a = calculate_risk_score(flags=flags, ai_confidence=1.0, dynamic_result=None, correlation_result={"available": False})
    b = calculate_risk_score(flags=flags, ai_confidence=1.0, dynamic_result=None, correlation_result={"available": False})
    assert a["final_risk_score"] == b["final_risk_score"]
    assert a["risk_band"] == b["risk_band"]


def test_mobsf_cache_reuse(tmp_path, monkeypatch):
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path))
    monkeypatch.setenv("MOBSF_RESULT_CACHE", "true")
    client = MobSFClient()
    sha = "a" * 64
    report = {"available": True, "package_name": "com.test", "scan_hash": "abc"}
    client._store_cached_report(sha, report)
    loaded = client._load_cached_report(sha)
    assert loaded is not None
    assert loaded["package_name"] == "com.test"


@pytest.mark.asyncio
async def test_async_analysis_returns_immediately():
    """Async endpoint enqueues without blocking on the full pipeline."""
    from app.workers.analysis_queue import create_job, enqueue

    job_id = create_job(sha256_hash="c" * 64, analyst_id=1)
    assert job_id
    await enqueue(job_id, "/tmp/x.apk", "x.apk", "c" * 64, analyst_id=1)


def test_independent_static_tasks_parallel_pattern():
    """Documented expectation: native + MobSF weights exist for parallel static."""
    assert "NATIVE_ANALYSIS" in STAGE_PROGRESS_WEIGHTS
    assert "MOBSF" in STAGE_PROGRESS_WEIGHTS


def test_pipeline_stage_transitions():
    timer = PipelineTimer("j", "c")
    with timer.stage("STATIC"):
        pass
    with timer.stage("MOBSF"):
        pass
    assert "STATIC" in timer._completed_order
    assert "MOBSF" in timer._completed_order
