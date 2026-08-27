"""
The Drinik regression: 50 events, BFCI 10.0, goal graph reporting zero.

Measured on a live emulator run before this was fixed:

    raw_event_counts   {"code_execution": 50, "harness_action": 1}
    bfci               10.0
    goals_successful   0
    goals_partial      0
    stage 10           NOT_REACHED

Three independent defects had to line up to produce that, and each one is
pinned separately below so a partial regression cannot pass:

1. The events were `ProcessBuilder.start` and `libc.execve`. Stage 10 declared
   `DexClassLoader.<init>` / `InMemoryDexClassLoader.<init>`. Both are code the
   process was not statically linked to run - the agent files both under
   `code_execution` and BFCI weights that one bucket - but the goal graph could
   only name the Dex half.

2. The tracker only saw events the explorer drained from the bus while walking.
   These fired on a background thread it never observed.

3. Even when replayed, only PENDING re-opened on new evidence, so an event
   arriving after finalize() landed on a NOT_REACHED goal and left it there.

The whole point is that fixing this by renaming a hook would have been wrong.
`test_the_fix_is_not_a_hook_rename` states that explicitly.
"""

from __future__ import annotations

import pytest

from sudarshan_core.engines.agentic.goal_tracker import GoalStatus, GoalTracker
from sudarshan_core.engines.behavior_taxonomy import Behavior, classify_events
from sudarshan_core.engines.runtime_event import (
    normalize_collected_events,
    normalize_events,
)


def _drinik_events(count_exec: int = 34, count_builder: int = 16) -> dict:
    """The shape of what the live run actually collected."""
    events = []
    for i in range(count_builder):
        events.append({
            "category": "code_execution", "severity": "HIGH",
            "timestamp": 1000 + i,
            "data": {"hook": "ProcessBuilder.start", "class_name": "ProcessBuilder",
                     "description": "app spawned a child process"},
        })
    for i in range(count_exec):
        events.append({
            "category": "code_execution", "severity": "CRITICAL",
            "timestamp": 2000 + i,
            "data": {"hook": "execve", "class_name": "libc",
                     "description": "native command execution"},
        })
    return {
        "code_execution": events,
        "harness_action": [{
            "category": "harness_action",
            "data": {"hook": "sandbox.build_fields_spoofed"},
        }],
    }


# ─── The regression itself ───────────────────────────────────────────────────

def test_command_execution_events_reach_a_goal():
    """
    THE regression. Before the fix this produced goals_successful == 0.
    """
    tracker = GoalTracker()
    tracker.reconcile(_drinik_events())
    tracker.finalize()

    report = tracker.coverage_report()
    assert report["goals_successful"] >= 1, (
        "50 command-execution events produced no successful goal - the graph "
        "is not reading the evidence the rest of the engine scores"
    )
    assert "Dynamic Code Loading" in report["successful_goals"]


def test_the_stage_is_confirmed_by_behaviour_not_by_a_renamed_hook():
    """
    The fix must NOT be "stage 10 now also lists ProcessBuilder.start".

    Stage 10's raw `frida_hooks` declaration is deliberately unchanged: it still
    names only the Dex constructors, because those are what it always meant.
    Confirmation comes from the behaviour layer instead.
    """
    goal = GoalTracker().get_goal(10)
    assert goal is not None
    assert "ProcessBuilder.start" not in goal.frida_hooks
    assert "execve" not in " ".join(goal.frida_hooks)
    assert Behavior.COMMAND_EXECUTION in goal.required_behaviors


def test_events_are_classified_as_command_execution_not_dex_loading():
    """
    Precision matters as much as recall. Reporting shell exec as dynamic Dex
    loading would be a false claim about what the sample did.
    """
    observed = classify_events(
        normalize_collected_events(_drinik_events())
    )
    assert Behavior.COMMAND_EXECUTION in observed
    assert Behavior.DYNAMIC_DEX_LOADING not in observed
    assert observed[Behavior.COMMAND_EXECUTION].count == 50


def test_the_harness_own_event_is_not_counted_as_sample_behaviour():
    observed = classify_events(normalize_collected_events(_drinik_events()))
    for obs in observed.values():
        for event in obs.events:
            assert not event.harness_attributed


# ─── Defect 2: events the walk never drained ─────────────────────────────────

def test_reconciliation_sees_events_the_explorer_never_drained():
    """
    The tracker is fed NOTHING during the walk, exactly as happens when a hook
    fires on a background thread. Reconciliation must still find it.
    """
    tracker = GoalTracker()
    assert tracker.coverage_report()["goals_successful"] == 0

    tracker.reconcile(_drinik_events())

    assert tracker.get_goal(10).status == GoalStatus.COMPLETED


# ─── Defect 3: evidence arriving after finalize() ────────────────────────────

def test_evidence_arriving_after_finalize_can_still_move_a_goal():
    """
    NOT_REACHED is assigned to goals the WALK never got to. It is not a claim
    about the sample, so an event arriving afterwards is new information.
    """
    tracker = GoalTracker()
    tracker.finalize()
    assert tracker.get_goal(10).status == GoalStatus.NOT_REACHED

    tracker.reconcile(_drinik_events())

    assert tracker.get_goal(10).status == GoalStatus.COMPLETED


def test_reconciliation_never_demotes_a_confirmed_goal():
    """It may only add what the walk missed; it cannot retract what it proved."""
    tracker = GoalTracker()
    goal = tracker.get_goal(6)          # SMS / OTP Interception
    goal.status = GoalStatus.COMPLETED
    goal.completion_evidence.append({"category": "sms"})

    tracker.reconcile(_drinik_events())

    assert goal.status == GoalStatus.COMPLETED


# ─── The other two live samples, by their real evidence shape ────────────────

def test_self_termination_is_reported_rather_than_scoring_nothing():
    """
    Cerberus: killProcess + System.exit, and nothing else. Refusing to be
    analysed is the most diagnostic thing that run produced, and the goal graph
    previously had no stage that could say it.
    """
    tracker = GoalTracker()
    tracker.reconcile({
        "anti_analysis": [
            {"category": "anti_analysis", "severity": "CRITICAL",
             "data": {"hook": "Process.killProcess"}},
            {"category": "anti_analysis", "severity": "CRITICAL",
             "data": {"hook": "System.exit"}},
        ],
    })
    tracker.finalize()

    report = tracker.coverage_report()
    assert "Anti-Analysis Resistance" in report["successful_goals"]


def test_a_device_admin_query_alone_stays_partial():
    """
    Also Cerberus. `isAdminActive` is a QUERY - it must support persistence and
    can never complete it, or every app that checks its own status would be
    reported as persisting.
    """
    tracker = GoalTracker()
    tracker.reconcile({
        "persistence": [
            {"category": "persistence",
             "data": {"hook": "DevicePolicyManager.isAdminActive"}},
        ],
    })
    tracker.finalize()

    goal = tracker.get_goal(9)
    assert goal.status == GoalStatus.PARTIAL
    assert "Persistence Mechanisms" not in tracker.coverage_report()["successful_goals"]


def test_lifecycle_callbacks_confirm_launch_but_nothing_else():
    """
    Anubis: the sample ran its own code, then handed the journey to a package
    it had installed. Lifecycle callbacks prove the launch - which foreground
    polling could not, because the foreground was no longer the target - and
    prove nothing about fraud.
    """
    tracker = GoalTracker()
    tracker.reconcile({
        "smoke": [
            {"category": "smoke", "data": {"hook": "Activity.onCreate"}}
            for _ in range(10)
        ],
    })
    tracker.finalize()

    report = tracker.coverage_report()
    assert "Launch Application" in report["successful_goals"]
    for fraud_goal in (
        "Accessibility Abuse", "Overlay Detection", "SMS / OTP Interception",
        "Network / C2 Communication",
    ):
        assert fraud_goal not in report["successful_goals"]


# ─── The safety property that must survive all of this ───────────────────────

def test_a_benign_chatty_app_completes_no_fraud_goal():
    """
    The failure mode in the other direction: an ordinary application whose
    lifecycle, file and keyboard chatter buys its way to a completed fraud
    goal. Volume must never become confidence.
    """
    tracker = GoalTracker()
    tracker.reconcile({
        "smoke": [{"category": "smoke", "data": {"hook": "Activity.onResume"}}
                  for _ in range(200)],
        "app_telemetry": [
            {"category": "app_telemetry",
             "data": {"hook": "InputMethodManager.showSoftInput"}}
            for _ in range(50)
        ],
        "files_accessed": [{"category": "files_accessed",
                            "data": {"hook": "File.<init>"}} for _ in range(80)],
    })
    tracker.finalize()

    report = tracker.coverage_report()
    # Launch is legitimately confirmed - the app did run.
    assert report["successful_goals"] == ["Launch Application"]
    for name in ("Accessibility Abuse", "Overlay Detection",
                 "SMS / OTP Interception", "Dynamic Code Loading",
                 "Persistence Mechanisms", "Anti-Analysis Resistance"):
        assert name not in report["successful_goals"], name


def test_an_empty_run_completes_nothing():
    tracker = GoalTracker()
    tracker.reconcile({})
    tracker.finalize()
    assert tracker.coverage_report()["goals_successful"] == 0
