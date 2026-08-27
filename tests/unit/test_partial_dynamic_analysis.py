"""
Dynamic analysis is evidence-accumulative, not all-or-nothing.

The defect class this file pins: a run in which nine of fifteen investigation
goals produced evidence used to be reportable only as "inconclusive", which
read to an analyst exactly like a run that never observed anything. Six failed
goals must not erase the evidence the other nine collected, and no arrangement
of goal states may make an observed event disappear.

Every test here is deterministic and needs no emulator: the goal graph is a
pure state machine, the coverage contract is a pure function, and the action
ladder is a pure payload builder. Anything that needed a device would not be a
regression test, it would be a hope.
"""

from __future__ import annotations

import time

import pytest

from sudarshan_core.engines.agentic.goal_tracker import (
    GoalStatus,
    GoalTracker,
    PARTIAL_GOAL_WEIGHT,
    TERMINAL_STATES,
)
from sudarshan_core.engines.dynamic_budget import (
    DYNAMIC_MAX_WALL_TIME_SECONDS,
    TIMEOUT_REASON,
    DynamicDeadline,
    clear_active_deadline,
    get_active_deadline,
    set_active_deadline,
)
from sudarshan_core.engines.dynamic_coverage import (
    DynamicCoverageStatus,
    build_dynamic_coverage,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _tracker_with(**counts: int) -> GoalTracker:
    """
    A tracker whose fifteen goals are forced into a requested distribution.

    States are assigned directly rather than driven through the agent loop: the
    point of these tests is the arithmetic and the reporting, and driving a
    real walk to produce "exactly two partial goals" would test the walk.
    """
    tracker = GoalTracker()
    goals = list(tracker.goals)
    index = 0
    for status_name, count in counts.items():
        status = getattr(GoalStatus, status_name)
        for _ in range(count):
            goals[index].status = status
            index += 1
    # Anything not named is left alone, then settled the way a real run would.
    return tracker


def _coverage(**counts: int) -> dict:
    tracker = _tracker_with(**counts)
    return tracker.coverage_report()


# ─── The forbidden global boolean ────────────────────────────────────────────

def test_no_global_all_goals_boolean_exists_anywhere():
    """
    `dynamic_valid` must never be `all(goals_successful)`.

    Asserted structurally rather than by reading source: a tracker in which one
    single goal failed and fourteen succeeded still reports fourteen
    successes, and the coverage contract still calls the run valid.
    """
    report = _coverage(COMPLETED=14, FAILED=1)
    result = build_dynamic_coverage(report, evidence_event_count=12)

    assert report["goals_successful"] == 14
    assert result["dynamic_valid"] is True
    assert result["dynamic_status"] == DynamicCoverageStatus.PARTIAL


# ─── CASE A-F from the specification ─────────────────────────────────────────

def test_case_a_all_goals_successful_is_complete_and_valid():
    result = build_dynamic_coverage(
        _coverage(COMPLETED=15), evidence_event_count=30,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.COMPLETE
    assert result["dynamic_valid"] is True
    assert result["dynamic_complete"] is True
    assert result["coverage_ratio"] == 1.0


def test_case_b_nine_of_fifteen_is_partial_and_valid():
    result = build_dynamic_coverage(
        _coverage(COMPLETED=9, FAILED=6), evidence_event_count=47,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.PARTIAL
    assert result["dynamic_valid"] is True
    assert result["dynamic_complete"] is False
    assert result["goals_successful"] == 9
    assert result["goals_failed"] == 6
    assert result["evidence_event_count"] == 47


def test_case_c_five_successful_goals_with_evidence_is_still_valid():
    result = build_dynamic_coverage(
        _coverage(COMPLETED=5, FAILED=10), evidence_event_count=8,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.PARTIAL
    assert result["dynamic_valid"] is True


def test_case_d_no_goals_and_no_events_is_no_behavior_not_partial():
    """
    A silent run must not read as a poorly-covered one.

    NO_BEHAVIOR_OBSERVED is the safety floor's anchor: reporting this as
    PARTIAL with 0% coverage would let an evasion-first sample look like a run
    that merely went badly, which is the opposite claim.
    """
    result = build_dynamic_coverage(
        _coverage(FAILED=15),
        instrumentation_ok=True,
        evidence_event_count=0,
        meaningful_transition_count=0,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.NO_BEHAVIOR_OBSERVED
    assert result["dynamic_valid"] is False
    assert "not evidence that the sample is benign" in result["limitations"][0]


def test_case_e_instrumentation_failure_is_distinct_from_partial():
    result = build_dynamic_coverage(
        None, sandbox_available=True, instrumentation_ok=False,
        evidence_event_count=0,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.INSTRUMENTATION_FAILED
    assert result["dynamic_valid"] is False
    assert result["dynamic_status"] != DynamicCoverageStatus.PARTIAL


def test_case_e_instrumentation_failure_keeps_events_it_did_collect():
    """
    A spawn-gated agent that got its hooks in and then watched the process die
    observed real behaviour. The status says the launch failed; the evidence
    still counts, so such a run is PARTIAL rather than a write-off.
    """
    result = build_dynamic_coverage(
        _coverage(COMPLETED=2, FAILED=13),
        instrumentation_ok=False,
        evidence_event_count=6,
    )
    assert result["dynamic_valid"] is True
    assert result["dynamic_status"] == DynamicCoverageStatus.PARTIAL


def test_case_f_no_sandbox_is_skipped():
    result = build_dynamic_coverage(None, sandbox_available=False)
    assert result["dynamic_status"] == DynamicCoverageStatus.SKIPPED
    assert result["dynamic_valid"] is False
    assert "No sandbox device was available" in result["limitations"][0]


# ─── Coverage arithmetic ─────────────────────────────────────────────────────

def test_the_specification_worked_example():
    """9 success, 2 partial, 2 failed, 1 skipped, 1 not reached -> 0.6667."""
    report = _coverage(
        COMPLETED=9, PARTIAL=2, FAILED=2, SKIPPED=1, NOT_REACHED=1,
    )
    result = build_dynamic_coverage(
        report, evidence_event_count=47, meaningful_transition_count=18,
        budget_seconds=1800, elapsed_seconds=842.4,
    )
    assert result["goals_total"] == 15
    assert result["goals_successful"] == 9
    assert result["goals_partial"] == 2
    assert result["goals_failed"] == 2
    assert result["goals_skipped"] == 1
    assert result["goals_not_reached"] == 1
    assert result["effective_goal_count"] == pytest.approx(10.0)
    assert result["coverage_ratio"] == pytest.approx(0.6667, abs=1e-4)
    assert result["dynamic_status"] == DynamicCoverageStatus.PARTIAL
    assert result["dynamic_valid"] is True
    assert result["timeout_reason"] is None
    assert any("6 of 15" in line for line in result["limitations"])


def test_partial_goals_count_half_toward_effective_coverage():
    report = _coverage(COMPLETED=4, PARTIAL=4, FAILED=7)
    assert report["effective_goal_count"] == pytest.approx(
        4 + 4 * PARTIAL_GOAL_WEIGHT
    )


def test_coverage_is_not_validity():
    """60% coverage is a valid partial run, not an invalid one."""
    result = build_dynamic_coverage(
        _coverage(COMPLETED=9, FAILED=6), evidence_event_count=20,
    )
    assert result["coverage_percent"] == pytest.approx(60.0)
    assert result["dynamic_valid"] is True


def test_a_run_with_no_goal_graph_but_real_events_is_still_valid():
    """
    Frida hooks fire from threads the UI walk never touched. A run whose goal
    graph produced nothing but whose agent recorded events has evidence in it.
    """
    result = build_dynamic_coverage(None, evidence_event_count=11)
    assert result["dynamic_valid"] is True
    assert result["dynamic_status"] == DynamicCoverageStatus.PARTIAL


# ─── Goal lifecycle ──────────────────────────────────────────────────────────

def test_a_goal_with_verified_progress_resolves_partial_not_failed():
    tracker = GoalTracker()
    tracker.mark_in_progress("Launch Application")
    tracker.record_progress_signal("Launch Application", "tap:screen_changed")

    status = tracker.resolve_goal("Launch Application", reason="max_attempts")

    assert status == GoalStatus.PARTIAL
    assert tracker.get_goal_by_name("Launch Application").failure_reason == "max_attempts"


def test_a_goal_with_nothing_observed_resolves_failed():
    tracker = GoalTracker()
    tracker.mark_in_progress("Launch Application")

    status = tracker.resolve_goal("Launch Application", reason="no_state_transition")

    assert status == GoalStatus.FAILED


def test_resolving_never_demotes_a_confirmed_goal():
    tracker = GoalTracker()
    goal = tracker.get_goal_by_name("Launch Application")
    goal.completion_evidence.append({"category": "foreground"})

    assert tracker.resolve_goal("Launch Application", reason="whatever") == (
        GoalStatus.COMPLETED
    )


def test_finalize_turns_unselected_goals_into_not_reached():
    tracker = GoalTracker()
    tracker.finalize()

    statuses = {g.name: g.status for g in tracker.goals}
    assert GoalStatus.PENDING not in statuses.values()
    assert any(s == GoalStatus.NOT_REACHED for s in statuses.values())


def test_finalize_under_timeout_marks_the_in_flight_goal_timeout():
    tracker = GoalTracker()
    tracker.mark_in_progress("Launch Application")

    tracker.finalize(timed_out=True)

    goal = tracker.get_goal_by_name("Launch Application")
    assert goal.status == GoalStatus.TIMEOUT
    assert goal.failure_reason == TIMEOUT_REASON


def test_finalize_is_idempotent():
    tracker = GoalTracker()
    tracker.finalize()
    first = tracker.completion_summary()
    tracker.finalize()
    assert tracker.completion_summary() == first


def test_a_timeout_does_not_retract_a_confirmed_observation():
    tracker = GoalTracker()
    goal = tracker.get_goal_by_name("Launch Application")
    goal.status = GoalStatus.IN_PROGRESS
    goal.completion_evidence.append({"category": "foreground"})

    tracker.mark_timed_out("Launch Application")

    assert goal.status == GoalStatus.COMPLETED


def test_partial_is_not_terminal_so_a_late_hook_can_still_confirm_it():
    """
    A goal that got part of the way can still be CONFIRMED by an event that
    arrives afterwards. Treating PARTIAL as terminal would refuse an
    observation to protect a bookkeeping state.
    """
    assert GoalStatus.PARTIAL not in TERMINAL_STATES

    tracker = GoalTracker()
    goal = tracker.get_goal_by_name("Network / C2 Communication")
    goal.status = GoalStatus.PARTIAL

    tracker.update_from_frida_events([
        {"category": "network", "data": {"hook": "OkHttp.RealCall.execute"}},
    ])

    assert goal.status == GoalStatus.COMPLETED


# ─── Evidence must survive other goals failing ───────────────────────────────

def test_one_failed_goal_does_not_erase_the_evidence_of_the_others():
    """
    Goal 1 accessibility, goal 2 overlay, goal 3 a failed click, goal 4 SMS,
    goal 5 network. The failure of goal 3 must leave 1, 2, 4 and 5 untouched.
    """
    tracker = GoalTracker()
    accessibility = tracker.get_goal_by_name("Accessibility Abuse")
    overlay = tracker.get_goal_by_name("Overlay Detection")
    sms = tracker.get_goal_by_name("SMS / OTP Interception")
    network = tracker.get_goal_by_name("Network / C2 Communication")

    tracker.update_from_frida_events([
        {"category": "accessibility",
         "data": {"hook": "AccessibilityNodeInfo.performAction"}},
        {"category": "overlay", "data": {"hook": "WindowManager.addView"}},
        {"category": "sms", "data": {"hook": "SmsMessage.getMessageBody"}},
        {"category": "network", "data": {"hook": "OkHttp.RealCall.execute"}},
    ])

    # The click on an unrelated goal fails, twice, and is given up on.
    tracker.mark_in_progress("Login Flow")
    tracker.mark_failed("Login Flow", reason="no_state_transition")

    for goal in (accessibility, overlay, sms, network):
        assert goal.status == GoalStatus.COMPLETED, goal.name
        assert goal.completion_evidence, goal.name

    report = tracker.coverage_report()
    assert report["goals_successful"] == 4
    result = build_dynamic_coverage(report, evidence_event_count=4)
    assert result["dynamic_valid"] is True


def test_evidence_survives_the_run_being_finalized_under_timeout():
    tracker = GoalTracker()
    tracker.update_from_frida_events([
        {"category": "sms", "data": {"hook": "SmsMessage.getMessageBody"}},
    ])
    sms = tracker.get_goal_by_name("SMS / OTP Interception")
    assert sms.status == GoalStatus.COMPLETED

    tracker.finalize(timed_out=True)

    assert sms.status == GoalStatus.COMPLETED
    assert len(sms.completion_evidence) == 1

    result = build_dynamic_coverage(
        tracker.coverage_report(), evidence_event_count=1, timed_out=True,
        budget_seconds=1800, elapsed_seconds=1800,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.TIME_BUDGET_EXHAUSTED
    assert result["dynamic_valid"] is True
    assert result["timeout_reason"] == TIMEOUT_REASON


def test_timeout_with_nothing_observed_is_no_behavior_not_a_valid_partial():
    result = build_dynamic_coverage(
        _coverage(FAILED=15), evidence_event_count=0, timed_out=True,
    )
    assert result["dynamic_status"] == DynamicCoverageStatus.NO_BEHAVIOR_OBSERVED
    assert result["dynamic_valid"] is False


# ─── The one wall clock ──────────────────────────────────────────────────────

def test_the_default_ceiling_is_thirty_minutes():
    assert DYNAMIC_MAX_WALL_TIME_SECONDS == 1800


def test_a_deadline_cannot_be_extended_by_anything():
    deadline = DynamicDeadline(total_seconds=100.0)
    before = deadline.total_seconds
    # Nothing on the public surface takes a budget and grants it.
    deadline.allows(10.0, stage="x")
    deadline.budget_for(10_000.0)
    deadline.note_expiry("x")
    assert deadline.total_seconds == before


def test_budget_for_clamps_a_child_to_the_parent():
    deadline = DynamicDeadline(total_seconds=60.0)
    assert deadline.budget_for(1800.0) <= 60.0
    assert deadline.budget_for(10.0) == pytest.approx(10.0, abs=0.5)


def test_an_expired_deadline_refuses_new_work_and_records_where():
    deadline = DynamicDeadline(
        total_seconds=1.0, started_monotonic=time.monotonic() - 10.0,
    )
    assert deadline.expired is True
    assert deadline.remaining() == 0.0
    assert deadline.allows(1.0, stage="planner") is False
    assert "planner" in deadline.refused_stages
    assert deadline.expired_at_stage == "planner"


def test_the_active_deadline_is_shared_and_clearable():
    try:
        assert get_active_deadline() is None
        deadline = DynamicDeadline(total_seconds=5.0)
        set_active_deadline(deadline)
        assert get_active_deadline() is deadline
    finally:
        clear_active_deadline()
    assert get_active_deadline() is None


def test_no_deadline_armed_means_unbounded_rather_than_zero():
    """
    A caller outside the dynamic pipeline - a unit test, a replay - must not be
    told it has no time. Returning 0 there would make every guard refuse.
    """
    from sudarshan_core.engines.dynamic_budget import remaining_seconds

    clear_active_deadline()
    assert remaining_seconds() == float("inf")
    assert remaining_seconds(default=30.0) == 30.0


# ─── Reporting ───────────────────────────────────────────────────────────────

def test_the_report_never_claims_all_stages_executed_for_a_partial_run():
    result = build_dynamic_coverage(
        _coverage(COMPLETED=9, PARTIAL=2, FAILED=4), evidence_event_count=47,
    )
    narrative = result["narrative"]
    assert "partial goal coverage" in narrative
    assert "9 of 15" in narrative
    assert "all planned investigation goals" not in narrative


def test_a_complete_run_says_so():
    result = build_dynamic_coverage(
        _coverage(COMPLETED=15), evidence_event_count=50,
    )
    assert result["narrative"] == (
        "Dynamic analysis completed all planned investigation goals."
    )


def test_a_silent_run_says_absence_of_observation_not_absence_of_behaviour():
    result = build_dynamic_coverage(_coverage(FAILED=15), evidence_event_count=0)
    assert "not evidence of benignity" in result["narrative"]


def test_every_status_is_a_declared_one():
    from sudarshan_core.engines.dynamic_coverage import DYNAMIC_STATUSES

    for report, kwargs in (
        (_coverage(COMPLETED=15), {"evidence_event_count": 5}),
        (_coverage(COMPLETED=9, FAILED=6), {"evidence_event_count": 5}),
        (_coverage(FAILED=15), {"evidence_event_count": 0}),
        (None, {"sandbox_available": False}),
        (None, {"instrumentation_ok": False}),
        (_coverage(COMPLETED=3), {"evidence_event_count": 5, "timed_out": True}),
    ):
        result = build_dynamic_coverage(report, **kwargs)
        assert result["dynamic_status"] in DYNAMIC_STATUSES


def test_the_json_payload_carries_the_contract_fields():
    result = build_dynamic_coverage(
        _coverage(COMPLETED=9, PARTIAL=2, FAILED=2, SKIPPED=1, NOT_REACHED=1),
        evidence_event_count=47, meaningful_transition_count=18,
        budget_seconds=1800, elapsed_seconds=842.4,
    )
    for key in (
        "dynamic_status", "dynamic_valid",
        "analysis_budget_seconds", "analysis_elapsed_seconds",
        "goals_total", "goals_successful", "goals_partial", "goals_failed",
        "goals_skipped", "goals_not_reached", "coverage_ratio",
        "evidence_event_count", "meaningful_transition_count",
        "successful_goals", "partial_goals", "failed_goals",
        "failure_reasons", "timeout_reason", "limitations",
    ):
        assert key in result, key
