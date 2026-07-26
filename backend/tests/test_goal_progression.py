"""
Regression tests for the goal dependency graph.

Root defect these cover: stage 1 ("Launch Application") had `frida_hooks=[]`
and `skip_if_missing=False`, and the only method that could complete it
(`mark_completed`) was never called in production. Because every other goal
declares `depends_on=[1, ...]`, the entire 15-stage graph was permanently
blocked — a live run produced `goals_completed: 0` with every action still on
stage 1.

Stage 1 now completes from observed foreground state, which is device truth
rather than an LLM assertion.
"""

import pytest

from sudarshan_core.engines.agentic.goal_tracker import (
    LAUNCH_CONFIRMATIONS_REQUIRED,
    LAUNCH_GOAL_NAME,
    MAX_GOAL_RETRIES,
    GoalStatus,
    GoalTracker,
)

TARGET = "com.target.bank"
OTHER = "com.android.launcher3"


@pytest.fixture
def tracker():
    return GoalTracker()


def _confirm_launch(tracker, package=TARGET, times=None):
    times = LAUNCH_CONFIRMATIONS_REQUIRED if times is None else times
    for _ in range(times):
        tracker.update_from_foreground(package, TARGET)


# ─── The deadlock itself ──────────────────────────────────────────────────────

def test_stage1_completes_from_foreground_observation(tracker):
    goal = tracker.get_goal_by_name(LAUNCH_GOAL_NAME)
    assert goal.status == GoalStatus.PENDING
    _confirm_launch(tracker)
    assert goal.status == GoalStatus.COMPLETED


def test_stage1_has_no_frida_hooks_so_needs_the_foreground_path(tracker):
    """Documents WHY the foreground path must exist — hooks can never do it."""
    goal = tracker.get_goal_by_name(LAUNCH_GOAL_NAME)
    assert goal.frida_hooks == []
    assert goal.skip_if_missing is False


def test_graph_advances_past_stage1(tracker):
    """The core regression: before the fix, next goal was stage 1 forever."""
    assert tracker.next_priority_goal().stage == 1
    _confirm_launch(tracker)
    assert tracker.next_priority_goal().stage == 2


def test_all_downstream_goals_become_reachable(tracker):
    """
    Every fraud category must be reachable, not just defined. Walk the graph
    driving each goal to COMPLETED via its own declared hooks.
    """
    _confirm_launch(tracker)
    seen = set()
    for _ in range(len(tracker.goals) * 3):
        goal = tracker.next_priority_goal()
        if goal is None:
            break
        seen.add(goal.name)
        if goal.frida_hooks:
            tracker.update_from_frida_events(
                [{"category": (goal.frida_categories or ["x"])[0],
                  "data": {"hook": goal.frida_hooks[0]}}]
            )
        else:
            goal.status = GoalStatus.SKIPPED

    for critical in (
        "Accessibility Abuse",
        "Overlay Detection",
        "SMS / OTP Interception",
        "Banking Application Detection",
        "Network / C2 Communication",
        "Persistence Mechanisms",
        "Dynamic Code Loading",
        "Runtime Reflection",
    ):
        assert critical in seen, f"{critical} was never reachable"


# ─── §4 matrix: foreground behaviours ─────────────────────────────────────────

def test_single_observation_is_not_enough(tracker):
    """One transient sample (splash/launcher hand-off) must not complete it."""
    tracker.update_from_foreground(TARGET, TARGET)
    goal = tracker.get_goal_by_name(LAUNCH_GOAL_NAME)
    if LAUNCH_CONFIRMATIONS_REQUIRED > 1:
        assert goal.status != GoalStatus.COMPLETED


def test_foreground_switches_away_resets_streak(tracker):
    tracker.update_from_foreground(TARGET, TARGET)
    tracker.update_from_foreground(OTHER, TARGET)       # user/app left
    tracker.update_from_foreground(TARGET, TARGET)      # back, streak restarts
    goal = tracker.get_goal_by_name(LAUNCH_GOAL_NAME)
    if LAUNCH_CONFIRMATIONS_REQUIRED > 1:
        assert goal.status != GoalStatus.COMPLETED
    _confirm_launch(tracker)
    assert goal.status == GoalStatus.COMPLETED


def test_intermittent_unreadable_foreground_resets_streak(tracker):
    """An unreadable reading is neither success nor failure — it breaks the run."""
    tracker.update_from_foreground(TARGET, TARGET)
    tracker.update_from_foreground("", TARGET)          # dumpsys unavailable
    goal = tracker.get_goal_by_name(LAUNCH_GOAL_NAME)
    if LAUNCH_CONFIRMATIONS_REQUIRED > 1:
        assert goal.status != GoalStatus.COMPLETED


def test_unknown_target_package_never_completes(tracker):
    for _ in range(10):
        tracker.update_from_foreground(TARGET, "")
    assert tracker.get_goal_by_name(LAUNCH_GOAL_NAME).status == GoalStatus.PENDING


def test_app_relaunch_after_completion_is_idempotent(tracker):
    _confirm_launch(tracker)
    goal = tracker.get_goal_by_name(LAUNCH_GOAL_NAME)
    evidence_count = len(goal.evidence_collected)
    _confirm_launch(tracker, times=5)                   # relaunch churn
    assert goal.status == GoalStatus.COMPLETED
    assert len(goal.evidence_collected) == evidence_count, "double-counted evidence"


def test_llm_cannot_mark_a_goal_complete(tracker):
    """The agent has no API to assert completion — device state decides."""
    assert not hasattr(tracker, "mark_completed")


# ─── §4 matrix: stage rollback / retry ────────────────────────────────────────

def test_failed_goal_is_retried_once(tracker):
    _confirm_launch(tracker)
    goal = tracker.next_priority_goal()
    tracker.mark_failed(goal.name)
    assert goal.status == GoalStatus.FAILED

    # Drain every other reachable goal so the FAILED one is the only candidate.
    for g in tracker.goals:
        if g.status in (GoalStatus.PENDING, GoalStatus.IN_PROGRESS) and g is not goal:
            g.status = GoalStatus.SKIPPED

    retried = tracker.next_priority_goal()
    assert retried is goal
    assert retried.status == GoalStatus.IN_PROGRESS
    assert retried.retries_used == MAX_GOAL_RETRIES


def test_failed_goal_is_given_up_after_max_retries(tracker):
    _confirm_launch(tracker)
    goal = tracker.next_priority_goal()
    for g in tracker.goals:
        if g is not goal:
            g.status = GoalStatus.SKIPPED

    for _ in range(MAX_GOAL_RETRIES + 1):
        tracker.mark_failed(goal.name)
        tracker.next_priority_goal()

    tracker.mark_failed(goal.name)
    assert tracker.next_priority_goal() is None
    assert tracker.all_done() is True
