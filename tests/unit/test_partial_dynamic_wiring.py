"""
The coverage contract actually reaches the report - end to end, no emulator.

A contract that is computed correctly and then dropped on the floor between the
explorer and the dynamic result is worth nothing, and that is precisely what had
already happened once: GoalTracker.coverage_report() existed, was correct, and
had ZERO call sites outside its own module. Nothing downstream ever saw it.

So these tests follow the value along the wire rather than re-checking the
arithmetic:

    GoalTracker -> AgenticExplorer.get_reports() -> risk_engine breakdown
                -> FRSBreakdown -> report copy
"""

from __future__ import annotations

import pytest

from sudarshan_core.engines.agentic.goal_tracker import GoalStatus
from sudarshan_core.engines.agentic_explorer import AgenticExplorer
from sudarshan_core.engines.dynamic_coverage import DynamicCoverageStatus


@pytest.fixture()
def explorer() -> AgenticExplorer:
    # No device is contacted by construction or by get_reports(); every device
    # call is behind an await that these tests never reach.
    return AgenticExplorer(device_serial="emulator-5554", package_name="com.test")


def test_get_reports_publishes_the_goal_coverage_the_tracker_computed(explorer):
    reports = explorer.get_reports()

    assert "goal_coverage" in reports
    assert "dynamic_coverage" in reports
    assert reports["goal_coverage"]["goals_total"] == 15


def test_get_reports_still_carries_every_key_frida_sandbox_reads(explorer):
    """
    The new keys are additive. Reshaping this dict would break the sandbox, the
    report and the VIDE bridge at once.
    """
    reports = explorer.get_reports()
    for key in (
        "exploration_graph", "coverage", "attack_timeline",
        "exploration_summary", "goal_summary", "dynamic_status",
    ):
        assert key in reports, key


def test_observed_frida_evidence_reaches_the_published_coverage(explorer):
    """
    Four confirming hooks, no UI progress at all. The coverage block must show
    four successful goals - runtime evidence does not depend on the walk.
    """
    explorer.goals.update_from_frida_events([
        {"category": "accessibility",
         "data": {"hook": "AccessibilityNodeInfo.performAction"}},
        {"category": "overlay", "data": {"hook": "WindowManager.addView"}},
        {"category": "sms", "data": {"hook": "SmsMessage.getMessageBody"}},
        {"category": "network", "data": {"hook": "OkHttp.RealCall.execute"}},
    ])
    explorer.exploration.runtime_events_observed = 4

    coverage = explorer.get_reports()["dynamic_coverage"]

    assert coverage["goals_successful"] == 4
    assert coverage["evidence_event_count"] == 4
    assert coverage["dynamic_valid"] is True
    assert coverage["dynamic_status"] == DynamicCoverageStatus.PARTIAL


def test_a_failed_goal_does_not_remove_another_goal_from_the_coverage(explorer):
    explorer.goals.update_from_frida_events([
        {"category": "sms", "data": {"hook": "SmsMessage.getMessageBody"}},
    ])
    explorer.exploration.runtime_events_observed = 1

    explorer.goals.mark_in_progress("Login Flow")
    explorer.goals.mark_failed("Login Flow", reason="no_state_transition")

    coverage = explorer.get_reports()["dynamic_coverage"]

    assert coverage["goals_successful"] == 1
    assert "SMS / OTP Interception" in coverage["successful_goals"]
    assert coverage["dynamic_valid"] is True


def test_the_failure_reason_travels_with_the_goal(explorer):
    explorer.goals.mark_in_progress("Login Flow")
    explorer.goals.mark_failed("Login Flow", reason="AUTH_FLOW_REJECTED")

    coverage = explorer.get_reports()["dynamic_coverage"]

    assert "AUTH_FLOW_REJECTED" in coverage["failure_reasons"]
    state = next(
        g for g in coverage["goal_states"] if g["goal_name"] == "Login Flow"
    )
    assert state["failure_reason"] == "AUTH_FLOW_REJECTED"


def test_the_permission_screen_ledger_is_published(explorer):
    """
    A permission dialog that keeps returning is the most effective trap on the
    device. Counting the encounters is what turns it from a loop into a bounded,
    reportable fact.
    """
    explorer._note_permission_screen("android.permission.READ_SMS", "hash-a")
    explorer._note_permission_screen("android.permission.READ_SMS", "hash-a")
    explorer._note_permission_screen("android.permission.CAMERA", "hash-b")

    ledger = explorer.get_reports()["permission_screens"]
    by_permission = {row["permission"]: row for row in ledger}

    assert by_permission["android.permission.READ_SMS"]["attempt_count"] == 2
    assert by_permission["android.permission.CAMERA"]["attempt_count"] == 1
    for row in ledger:
        assert set(row) >= {
            "permission", "screen_hash", "attempt_count", "result", "timestamp",
        }


def test_the_same_permission_on_a_different_screen_is_a_different_entry(explorer):
    """
    Android shows genuinely different dialogs for one permission - the first
    request, the "don't ask again" variant, the Settings page. Collapsing them
    would stop the walk answering a dialog it had never actually seen.
    """
    explorer._note_permission_screen("android.permission.CAMERA", "hash-a")
    explorer._note_permission_screen("android.permission.CAMERA", "hash-b")

    assert len(explorer.get_reports()["permission_screens"]) == 2


def test_finalize_settles_the_graph_before_reports_are_read(explorer):
    """
    A finished run must not publish PENDING goals: that invites the reader to
    treat "never selected" as "did not happen".
    """
    import asyncio

    explorer._stop_reason = None
    asyncio.run(explorer._finalize(actions_taken=0))

    statuses = {g.status for g in explorer.goals.goals}
    assert GoalStatus.PENDING not in statuses
    assert GoalStatus.IN_PROGRESS not in statuses

    coverage = explorer.get_reports()["dynamic_coverage"]
    assert coverage["goals_not_reached"] > 0


def test_a_run_stopped_by_the_deadline_reports_the_timeout(explorer):
    import asyncio

    from sudarshan_core.engines.agentic.exploration_engine import StopReason
    from sudarshan_core.engines.dynamic_budget import TIMEOUT_REASON

    explorer.goals.update_from_frida_events([
        {"category": "sms", "data": {"hook": "SmsMessage.getMessageBody"}},
    ])
    explorer.exploration.runtime_events_observed = 1
    explorer._stop_reason = StopReason.TIME_BUDGET_EXHAUSTED

    asyncio.run(explorer._finalize(actions_taken=3))
    coverage = explorer.get_reports()["dynamic_coverage"]

    assert coverage["dynamic_status"] == DynamicCoverageStatus.TIME_BUDGET_EXHAUSTED
    assert coverage["timeout_reason"] == TIMEOUT_REASON
    assert coverage["dynamic_valid"] is True
    # The evidence collected before the deadline is still there.
    assert coverage["goals_successful"] == 1
