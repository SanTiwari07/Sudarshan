"""
What the analyst is told about a partial run.

The rule being pinned: a report must never claim more investigation happened
than actually did, and must never describe a run that collected evidence as one
that did not. Those are two different lies and the old copy could tell both -
"the sandbox executed but returned no conclusive telemetry" was written for a
run that had confirmed nine goals and captured 47 events, because the only
vocabulary available was conclusive / inconclusive / absent.
"""

from __future__ import annotations

import pytest

from sudarshan_core.engines.dynamic_coverage import (
    DynamicCoverageStatus,
    build_dynamic_coverage,
)
from sudarshan_core.engines.report_generator import _build_executive_conclusion
from sudarshan_core.engines.risk_engine import _dynamic_coverage_block


def _partial_run() -> dict:
    return build_dynamic_coverage(
        {
            "goals_total": 15,
            "goals_successful": 9,
            "goals_partial": 2,
            "goals_failed": 2,
            "goals_skipped": 1,
            "goals_not_reached": 1,
            "effective_goal_count": 10.0,
            "successful_goals": ["Launch Application"],
            "partial_goals": ["Login Flow"],
            "failed_goals": ["Overlay Detection"],
        },
        evidence_event_count=47,
        meaningful_transition_count=18,
        budget_seconds=1800,
        elapsed_seconds=842.4,
    )


def _report(coverage: dict) -> str:
    return _build_executive_conclusion(
        {
            "frs_breakdown": {
                "dynamic_ran": True,
                "dynamic_conclusive": True,
                "dynamic_coverage": _dynamic_coverage_block(
                    {"dynamic_coverage": coverage}
                ),
            },
            "dynamic_result": {"dynamic_coverage": coverage},
        }
    )


# ─── The report tells the truth about coverage ───────────────────────────────

def test_a_partial_run_is_reported_as_partial_with_its_numbers():
    html = _report(_partial_run())
    assert "partial goal coverage" in html
    assert "9 of 15" in html
    assert "66.7" in html


def test_a_partial_run_is_never_described_as_having_no_telemetry():
    """
    The exact regression: 47 captured events written up as "returned no
    conclusive telemetry" because the copy had no word for a partial run.
    """
    html = _report(_partial_run())
    assert "no conclusive telemetry" not in html


def test_a_partial_run_never_claims_all_stages_executed():
    html = _report(_partial_run())
    assert "all planned investigation goals" not in html


def test_the_limitations_are_stated_not_implied():
    html = _report(_partial_run())
    assert "Limitations:" in html
    assert "not fully exercised" in html


def test_a_complete_run_says_all_goals_completed():
    coverage = build_dynamic_coverage(
        {"goals_total": 15, "goals_successful": 15, "effective_goal_count": 15.0},
        evidence_event_count=60,
    )
    html = _report(coverage)
    assert "completed all planned investigation goals" in html


def test_a_silent_run_still_refuses_to_certify_the_sample():
    coverage = build_dynamic_coverage(
        {"goals_total": 15, "goals_successful": 0, "effective_goal_count": 0.0},
        evidence_event_count=0,
    )
    assert coverage["dynamic_status"] == DynamicCoverageStatus.NO_BEHAVIOR_OBSERVED
    html = _report(coverage)
    assert "No substantive runtime behaviour was observed" in html
    assert "not evidence of benignity" in html


def test_an_instrumentation_failure_is_not_written_up_as_a_quiet_sample():
    coverage = build_dynamic_coverage(
        None, sandbox_available=True, instrumentation_ok=False,
    )
    html = _report(coverage)
    assert "instrumentation could not be established" in html.lower()
    assert "No substantive runtime behaviour" not in html


# ─── The risk engine carries coverage with the score ─────────────────────────

def test_the_frs_breakdown_carries_coverage_metadata():
    block = _dynamic_coverage_block({"dynamic_coverage": _partial_run()})
    assert block["dynamic_status"] == DynamicCoverageStatus.PARTIAL
    assert block["dynamic_valid"] is True
    assert block["dynamic_complete"] is False
    assert block["dynamic_coverage_ratio"] == pytest.approx(0.6667, abs=1e-4)
    assert block["coverage_known"] is True


def test_a_stored_case_without_coverage_says_so_rather_than_reporting_zero():
    """
    An old record must not suddenly report 0% coverage - that would read as a
    regression in the sample rather than in the record.
    """
    block = _dynamic_coverage_block({"dynamic_status": "EVENTS_CAPTURED"})
    assert block["coverage_known"] is False
    assert block["dynamic_coverage_ratio"] == 0.0


def test_a_missing_dynamic_result_is_skipped_not_failed():
    block = _dynamic_coverage_block(None)
    assert block["dynamic_status"] == "SKIPPED"
    assert block["dynamic_valid"] is False


def test_coverage_metadata_survives_the_api_schema():
    """
    FastAPI's response_model silently drops undeclared keys, which is how
    computed values have gone missing from this API before.
    """
    from sudarshan_core.models.schemas import FRSBreakdown

    block = _dynamic_coverage_block({"dynamic_coverage": _partial_run()})
    model = FRSBreakdown(
        dynamic_status=block["dynamic_status"],
        dynamic_valid=block["dynamic_valid"],
        dynamic_complete=block["dynamic_complete"],
        dynamic_coverage=block,
    )
    dumped = model.model_dump()
    assert dumped["dynamic_status"] == DynamicCoverageStatus.PARTIAL
    assert dumped["dynamic_valid"] is True
    assert dumped["dynamic_coverage"]["goals_successful"] == 9
