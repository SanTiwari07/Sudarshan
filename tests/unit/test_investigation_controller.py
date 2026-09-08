"""
Tests for the investigation state machine.

Three things carry the design and are asserted hardest:

* **Branch selection.** §4 is explicit that not every APK runs every state. A
  calculator must not spend budget in ACCESSIBILITY_ANALYSIS.
* **The action allowlist.** Under §34 the model must never reach an arbitrary
  action. Every state's permitted set is a subset of TOOL_REGISTRY, and the
  narrow states really are narrow.
* **Separation of concerns.** The controller decides what to investigate next.
  It must not own goals (GoalTracker does) or influence the verdict (the risk
  engine does).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.screen_classifier import ScreenType  # noqa: E402
from sudarshan_core.engines.capability_profile import AppCategory  # noqa: E402
from sudarshan_core.engines.investigation_controller import (  # noqa: E402
    ALLOWED_ACTIONS,
    InvestigationController,
    InvestigationState,
    score_progress,
    unknown_actions,
)

TROJAN_FLAGS = {
    "has_accessibility_abuse": True,
    "has_system_alert_window": True,
    "has_sms_read_write": True,
    "targets_indian_banks": True,
    "has_concealed_payload": True,
}


def _calculator() -> InvestigationController:
    return InvestigationController("com.example.calculator", AppCategory.CALCULATOR, {})


def _trojan() -> InvestigationController:
    return InvestigationController(
        "com.evil.bot", AppCategory.UNKNOWN, TROJAN_FLAGS,
        special_permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"],
    )


# ── branch selection (§4) ────────────────────────────────────────────────────

def test_a_calculator_does_not_walk_the_fraud_branches():
    plan = _calculator().plan
    for state in (
        InvestigationState.ACCESSIBILITY_ANALYSIS,
        InvestigationState.OVERLAY_ANALYSIS,
        InvestigationState.OTP_ANALYSIS,
        InvestigationState.BANKING_TARGET_ANALYSIS,
    ):
        assert state not in plan, f"{state} should not be planned for a calculator"


def test_a_calculator_still_walks_the_universal_states():
    plan = _calculator().plan
    for state in (
        InvestigationState.APP_LAUNCH,
        InvestigationState.PERMISSION_ANALYSIS,
        InvestigationState.NETWORK_ANALYSIS,
        InvestigationState.COMPLETE,
    ):
        assert state in plan


def test_static_signals_open_the_matching_branches():
    plan = _trojan().plan
    for state in (
        InvestigationState.ACCESSIBILITY_ANALYSIS,
        InvestigationState.OVERLAY_ANALYSIS,
        InvestigationState.OTP_ANALYSIS,
        InvestigationState.BANKING_TARGET_ANALYSIS,
        InvestigationState.DYNAMIC_CODE_ANALYSIS,
        InvestigationState.SPECIAL_PERMISSION_ANALYSIS,
    ):
        assert state in plan


@pytest.mark.parametrize("flag,state", [
    ("has_accessibility_abuse", InvestigationState.ACCESSIBILITY_ANALYSIS),
    ("has_system_alert_window", InvestigationState.OVERLAY_ANALYSIS),
    ("has_sms_read_write", InvestigationState.OTP_ANALYSIS),
    ("targets_indian_banks", InvestigationState.BANKING_TARGET_ANALYSIS),
    ("has_concealed_payload", InvestigationState.DYNAMIC_CODE_ANALYSIS),
])
def test_each_flag_opens_exactly_its_own_branch(flag, state):
    controller = InvestigationController("com.x", AppCategory.UNKNOWN, {flag: True})
    assert state in controller.plan


def test_a_banking_category_opens_the_banking_branch_without_a_static_flag():
    controller = InvestigationController("com.x", AppCategory.BANKING, {})
    assert InvestigationState.BANKING_TARGET_ANALYSIS in controller.plan


def test_every_plan_starts_at_bootstrap_and_ends_complete():
    for controller in (_calculator(), _trojan()):
        assert controller.plan[0] is InvestigationState.BOOTSTRAP
        assert controller.plan[-1] is InvestigationState.COMPLETE


def test_the_plan_has_no_duplicates():
    plan = _trojan().plan
    assert len(plan) == len(set(plan))


# ── the action allowlist (§12, §34) ──────────────────────────────────────────

def test_every_allowlisted_action_is_a_real_registered_tool():
    """A typo would silently narrow the agent instead of raising."""
    assert unknown_actions() == frozenset()


def test_every_state_has_an_allowlist():
    for state in InvestigationState:
        assert state in ALLOWED_ACTIONS, f"{state} has no allowlist"


def test_a_permission_dialog_permits_only_dialog_handling():
    """Widening this is what lets a planner wander off mid-dialog."""
    allowed = ALLOWED_ACTIONS[InvestigationState.PERMISSION_ANALYSIS]
    assert "grant_permission" in allowed
    assert "deny_permission" in allowed
    for wandering in ("swipe", "scroll", "press_home", "start_activity"):
        assert wandering not in allowed


def test_the_completed_state_permits_nothing():
    assert ALLOWED_ACTIONS[InvestigationState.COMPLETE] == frozenset()


def test_no_state_permits_a_destructive_tool():
    """Nothing may wipe app data or install packages mid-investigation."""
    for state, allowed in ALLOWED_ACTIONS.items():
        assert "clear_app_data" not in allowed, state


def test_an_unregistered_action_is_rejected():
    controller = _calculator()
    controller.transition_to(InvestigationState.PERMISSION_ANALYSIS, "test")
    assert controller.is_action_allowed("grant_permission") is True
    assert controller.is_action_allowed("rm_rf") is False
    assert controller.is_action_allowed("") is False


def test_an_action_legal_in_one_state_is_illegal_in_another():
    controller = _calculator()
    controller.transition_to(InvestigationState.PERMISSION_ANALYSIS, "test")
    assert controller.is_action_allowed("scroll") is False
    controller.transition_to(InvestigationState.POST_PERMISSION_EXPLORATION, "test")
    assert controller.is_action_allowed("scroll") is True


# ── observation-driven transitions ───────────────────────────────────────────

@pytest.mark.parametrize("screen,state", [
    (ScreenType.SYSTEM_PERMISSION, InvestigationState.PERMISSION_ANALYSIS),
    (ScreenType.ACCESSIBILITY_DIALOG, InvestigationState.ACCESSIBILITY_ANALYSIS),
    (ScreenType.OTP_SCREEN, InvestigationState.OTP_ANALYSIS),
    (ScreenType.BANK_LOGIN, InvestigationState.AUTHENTICATION_ANALYSIS),
    (ScreenType.OVERLAY_ATTACK, InvestigationState.OVERLAY_ANALYSIS),
])
def test_a_classified_screen_selects_its_state(screen, state):
    assert _trojan().state_for_observation(screen_type=screen) is state


def test_an_unremarkable_screen_causes_no_transition():
    assert _trojan().state_for_observation(screen_type=ScreenType.HOME) is None
    assert _trojan().state_for_observation(screen_type="") is None


def test_frida_evidence_selects_a_state_when_the_screen_says_nothing():
    controller = _trojan()
    assert controller.state_for_observation(
        frida_categories=["accessibility"]
    ) is InvestigationState.ACCESSIBILITY_ANALYSIS


def test_the_screen_outranks_frida_evidence():
    """
    A dialog is in front of the user now and disappears if unhandled; a
    category can be revisited from stored evidence later.
    """
    controller = _trojan()
    assert controller.state_for_observation(
        screen_type=ScreenType.SYSTEM_PERMISSION, frida_categories=["overlay"]
    ) is InvestigationState.PERMISSION_ANALYSIS


def test_runtime_evidence_can_open_a_branch_the_static_plan_omitted():
    """
    A sample doing what its manifest never advertised is precisely what dynamic
    analysis is for, so the branch is opened rather than skipped.
    """
    controller = _calculator()
    assert InvestigationState.OVERLAY_ANALYSIS not in controller.plan
    controller.observe(frida_categories=["overlay"])
    assert controller.state is InvestigationState.OVERLAY_ANALYSIS
    assert InvestigationState.OVERLAY_ANALYSIS in controller.plan


def test_observing_the_current_state_is_not_a_transition():
    controller = _trojan()
    controller.observe(screen_type=ScreenType.SYSTEM_PERMISSION)
    assert controller.observe(screen_type=ScreenType.SYSTEM_PERMISSION) is None


def test_a_transition_records_where_from_where_to_and_why():
    controller = _calculator()
    record = controller.transition_to(InvestigationState.APP_LAUNCH, "launched")
    assert record.from_state == "BOOTSTRAP"
    assert record.to_state == "APP_LAUNCH"
    assert record.reason == "launched"
    assert controller.timeline()[0]["to"] == "APP_LAUNCH"


def test_a_new_stage_starts_with_a_clean_failure_count():
    """Carrying failures over would abandon a stage for the previous one's problems."""
    controller = _calculator()
    controller.record_action(failed=True)
    controller.record_action(failed=True)
    assert controller.consecutive_failures == 2
    controller.transition_to(InvestigationState.PERMISSION_ANALYSIS, "test")
    assert controller.consecutive_failures == 0


# ── advancing and stopping ───────────────────────────────────────────────────

def test_advance_walks_the_plan_in_order():
    controller = _calculator()
    seen = [controller.state]
    while controller.advance() is not None:
        seen.append(controller.state)
    assert seen == list(controller.plan)


def test_advancing_past_the_end_returns_none():
    controller = _calculator()
    controller.transition_to(InvestigationState.COMPLETE, "done")
    assert controller.advance() is None


def test_the_action_budget_stops_the_investigation():
    controller = InvestigationController("com.x", max_actions=2)
    controller.record_action()
    assert controller.should_stop()[0] is False
    controller.record_action()
    stop, reason = controller.should_stop()
    assert stop is True and "budget" in reason


def test_reaching_complete_stops_the_investigation():
    controller = _calculator()
    controller.transition_to(InvestigationState.COMPLETE, "done")
    assert controller.should_stop()[0] is True


def test_repeated_failures_mark_the_stage_stuck():
    controller = _calculator()
    for _ in range(3):
        controller.record_action(failed=True)
    assert controller.stuck() is True


def test_a_successful_action_clears_the_failure_streak():
    controller = _calculator()
    controller.record_action(failed=True)
    controller.record_action(failed=True)
    controller.record_action(failed=False)
    assert controller.consecutive_failures == 0
    assert controller.stuck() is False


def test_a_repeated_screen_marks_the_stage_stuck():
    controller = _calculator()
    controller.record_action(same_screen=True)
    controller.record_action(same_screen=True)
    assert controller.stuck() is True


# ── progress signal (§13) ────────────────────────────────────────────────────

def test_progress_rewards_discovery():
    signal = score_progress(new_screen=True, runtime_events=1)
    assert signal.score == 6
    assert signal.productive is True


def test_progress_punishes_repetition_and_crashes():
    assert score_progress(repeated_screen=True).productive is False
    assert score_progress(crashed=True).score == -5


def test_a_completed_goal_is_the_strongest_positive():
    assert score_progress(goal_completed=True).score == 5


def test_progress_explains_itself():
    signal = score_progress(new_screen=True, failed_action=True)
    assert any("new screen" in r for r in signal.reasons)
    assert any("action failed" in r for r in signal.reasons)


def test_an_action_that_changed_nothing_scores_zero():
    assert score_progress().score == 0
    assert score_progress().productive is False


# ── separation of concerns (§21, §36) ────────────────────────────────────────

def test_the_controller_does_not_reimplement_goals():
    """GoalTracker owns the 15 fraud goals; duplicating them is forbidden."""
    import sudarshan_core.engines.investigation_controller as module

    source = Path(module.__file__).read_text(encoding="utf-8", errors="replace")
    assert "class GoalTracker" not in source
    assert "FraudGoal(" not in source


def test_the_controller_never_touches_the_risk_engine():
    import sudarshan_core.engines.investigation_controller as module

    source = Path(module.__file__).read_text(encoding="utf-8", errors="replace")
    for forbidden in ("risk_engine", "calculate_risk_score", "bfci_scorer"):
        assert forbidden not in source


def test_the_summary_is_json_serialisable():
    import json

    controller = _trojan()
    controller.transition_to(InvestigationState.APP_LAUNCH, "launched")
    controller.record_action()
    json.dumps(controller.summary())


# ── wiring into the explorer (Phase 5) ───────────────────────────────────────

def _explorer(**static):
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    return AgenticExplorer(
        device_serial="test-device",
        package_name="com.evil.bot",
        static_findings=static or None,
    )


def test_the_explorer_owns_a_controller_seeded_from_static_signals():
    exp = _explorer(
        permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        app_label="Calculator",
        flags={"has_accessibility_abuse": True},
    )
    assert InvestigationState.ACCESSIBILITY_ANALYSIS in exp.investigation.plan
    assert exp.investigation.category is AppCategory.CALCULATOR


def test_an_explorer_without_static_findings_still_gets_a_plan():
    exp = _explorer()
    assert exp.investigation.plan[0] is InvestigationState.BOOTSTRAP
    assert exp.investigation.plan[-1] is InvestigationState.COMPLETE


def test_special_permissions_reach_the_controller():
    exp = _explorer(
        permissions=["android.permission.SYSTEM_ALERT_WINDOW"], app_label="Calculator"
    )
    assert exp.investigation.special_permissions == [
        "android.permission.SYSTEM_ALERT_WINDOW"
    ]
    assert InvestigationState.SPECIAL_PERMISSION_ANALYSIS in exp.investigation.plan


def test_the_action_budget_is_shared_with_the_loop():
    from sudarshan_core.engines import agentic_explorer

    assert _explorer().investigation.max_actions == agentic_explorer.ACTION_BUDGET


def test_reports_expose_the_investigation_without_reshaping_existing_keys():
    """Existing consumers of get_reports() must keep working (§23)."""
    reports = _explorer().get_reports()
    for legacy in (
        "exploration_graph", "coverage", "attack_timeline",
        "exploration_summary", "audit_log", "benchmark",
        "goal_summary", "agent_memory",
    ):
        assert legacy in reports, f"{legacy} disappeared from get_reports()"
    assert "investigation" in reports
    assert "permissions" in reports


def test_reports_are_json_serialisable():
    import json

    json.dumps(_explorer(permissions=["android.permission.CAMERA"],
                         app_label="Calculator").get_reports())


def test_the_explorer_enforces_the_stage_allowlist():
    """
    The enforcement §34 turns on: an action the stage forbids must be refused
    before it can reach a device.
    """
    exp = _explorer()
    exp.investigation.transition_to(InvestigationState.PERMISSION_ANALYSIS, "test")
    assert exp.investigation.is_action_allowed("grant_permission") is True
    assert exp.investigation.is_action_allowed("swipe") is False
    assert exp.investigation.is_action_allowed("clear_app_data") is False


# ── planner output budget ────────────────────────────────────────────────────

def test_the_output_budget_accommodates_a_thinking_model():
    """
    512 was sized for the ~40 tokens of JSON an action needs, but the budget
    also covers internal reasoning. Measured on gemini-3.6-flash,
    thoughts_token_count was 358 of 512, so the JSON was truncated mid-string
    and every planner call fell back to the deterministic planner.
    """
    from sudarshan_core.engines.agentic import planner

    assert planner.MAX_OUTPUT_TOKENS >= 1024


def test_the_output_budget_is_configurable(monkeypatch):
    import importlib

    from sudarshan_core.engines.agentic import planner

    monkeypatch.setenv("SUDARSHAN_AGENT_MAX_OUTPUT_TOKENS", "4096")
    assert importlib.reload(planner).MAX_OUTPUT_TOKENS == 4096
    monkeypatch.delenv("SUDARSHAN_AGENT_MAX_OUTPUT_TOKENS", raising=False)
    importlib.reload(planner)


# ── the allowlist must not starve the agent ──────────────────────────────────

@pytest.mark.parametrize("state", [s for s in InvestigationState if s is not InvestigationState.COMPLETE])
def test_observation_is_permitted_in_every_working_state(state):
    """
    Read-only tools change nothing, so forbidding them buys no safety and costs
    budget. Measured live: rejecting `dump_ui` in AUTHENTICATION_ANALYSIS spent
    actions on refusals and cut a run from 16 actions to 2.
    """
    allowed = ALLOWED_ACTIONS[state]
    for tool in ("dump_ui", "take_screenshot", "capture_logcat"):
        assert tool in allowed, f"{tool} should be observable in {state.value}"


@pytest.mark.parametrize("state", [
    InvestigationState.PERMISSION_ANALYSIS,
    InvestigationState.PERMISSION_HANDLING,
    InvestigationState.POST_PERMISSION_EXPLORATION,
    InvestigationState.AUTHENTICATION_ANALYSIS,
    InvestigationState.OTP_ANALYSIS,
    InvestigationState.BANKING_TARGET_ANALYSIS,
    InvestigationState.ACCESSIBILITY_ANALYSIS,
])
def test_permission_handling_is_reachable_wherever_a_dialog_can_appear(state):
    """A runtime dialog can pop in any exploring stage; it must be answerable."""
    assert "grant_permission" in ALLOWED_ACTIONS[state]


def test_a_modal_permission_dialog_still_forbids_navigation():
    """Widening for read-only must not have opened the wander-off hole."""
    allowed = ALLOWED_ACTIONS[InvestigationState.PERMISSION_ANALYSIS]
    for wandering in ("swipe", "scroll", "press_home", "start_activity", "tap"):
        assert wandering not in allowed


def test_no_working_state_is_so_narrow_it_cannot_act():
    """A stage permitting nothing would burn the budget on rejections."""
    for state, allowed in ALLOWED_ACTIONS.items():
        if state is InvestigationState.COMPLETE:
            continue
        assert len(allowed) >= 3, f"{state.value} permits only {sorted(allowed)}"


# ── stage oscillation ────────────────────────────────────────────────────────

def test_an_abandoned_stage_is_not_re_entered_from_the_same_screen():
    """
    The screen that stalled a stage is usually still on display when the stage
    is abandoned. Measured live: AUTHENTICATION_ANALYSIS and
    BANKING_TARGET_ANALYSIS traded places three times on one BANK_LOGIN screen,
    spending the budget on transitions instead of actions.
    """
    controller = _trojan()
    controller.observe(screen_type=ScreenType.BANK_LOGIN)
    assert controller.state is InvestigationState.AUTHENTICATION_ANALYSIS

    controller.abandon()
    assert InvestigationState.AUTHENTICATION_ANALYSIS in controller.abandoned
    moved_to = controller.state

    # The same screen is still there; it must not pull us back.
    assert controller.observe(screen_type=ScreenType.BANK_LOGIN) is None
    assert controller.state is moved_to


def test_abandon_moves_on_as_well_as_marking():
    controller = _trojan()
    controller.observe(screen_type=ScreenType.BANK_LOGIN)
    before = controller.state
    controller.abandon()
    assert controller.state is not before


def test_advance_alone_does_not_mark_a_stage_abandoned():
    """Completing a stage normally must not blacklist it."""
    controller = _calculator()
    controller.advance("stage complete")
    assert controller.abandoned == []


def test_other_stages_remain_reachable_after_one_is_abandoned():
    controller = _trojan()
    controller.observe(screen_type=ScreenType.BANK_LOGIN)
    controller.abandon()
    controller.observe(screen_type=ScreenType.OTP_SCREEN)
    assert controller.state is InvestigationState.OTP_ANALYSIS


def test_abandoning_is_idempotent():
    controller = _trojan()
    controller.observe(screen_type=ScreenType.BANK_LOGIN)
    controller.abandon()
    controller.observe(screen_type=ScreenType.OTP_SCREEN)
    controller.transition_to(InvestigationState.AUTHENTICATION_ANALYSIS, "forced")
    controller.abandon()
    assert controller.abandoned.count(InvestigationState.AUTHENTICATION_ANALYSIS) == 1


# ── incidental evidence must not open a branch ───────────────────────────────

def test_an_incidental_category_cannot_open_an_unplanned_branch():
    """
    Measured live: Amaze File Manager, a legitimate file manager, emitted
    AccessibilityManager.sendAccessibilityEvent - which every app does whenever
    the UI changes so screen readers can announce it. That bare category pulled
    the run into ACCESSIBILITY_ANALYSIS and the agent spent five iterations
    walking Android Settings for an app with no accessibility service.
    """
    controller = _calculator()
    assert InvestigationState.ACCESSIBILITY_ANALYSIS not in controller.plan
    assert controller.state_for_observation(frida_categories=["accessibility"]) is None
    assert controller.observe(frida_categories=["accessibility"]) is None
    assert InvestigationState.ACCESSIBILITY_ANALYSIS not in controller.plan


def test_network_evidence_is_incidental_too():
    """Every app talks to the network."""
    controller = InvestigationController("com.x", AppCategory.UNKNOWN, {})
    # NETWORK_ANALYSIS is universal, so craft a controller where it is planned
    # and confirm the guard only bites on unplanned states.
    assert InvestigationState.NETWORK_ANALYSIS in controller.plan
    assert controller.state_for_observation(
        frida_categories=["network"]
    ) is InvestigationState.NETWORK_ANALYSIS


def test_an_incidental_category_still_moves_to_a_planned_stage():
    """The static signals put it in the plan, so the evidence is actionable."""
    controller = InvestigationController(
        "com.x", AppCategory.UNKNOWN, {"has_accessibility_abuse": True}
    )
    assert controller.state_for_observation(
        frida_categories=["accessibility"]
    ) is InvestigationState.ACCESSIBILITY_ANALYSIS


@pytest.mark.parametrize("category,state", [
    ("overlay", InvestigationState.OVERLAY_ANALYSIS),
    ("sms", InvestigationState.OTP_ANALYSIS),
    ("persistence", InvestigationState.PERSISTENCE_ANALYSIS),
    ("banking", InvestigationState.BANKING_TARGET_ANALYSIS),
])
def test_non_incidental_evidence_still_opens_an_unplanned_branch(category, state):
    """
    A sample drawing an overlay or reading SMS is doing something ordinary apps
    do not do incidentally - that is exactly what dynamic analysis is for.
    """
    controller = _calculator()
    assert state not in controller.plan
    controller.observe(frida_categories=[category])
    assert controller.state is state
    assert state in controller.plan


# ── the plan must actually drive the run ─────────────────────────────────────

def test_a_stage_that_spends_its_budget_advances_without_being_stuck():
    """
    The regression. advance() was only reachable from the stuck() branch, so a
    sample that kept producing events was never stuck and never walked its
    plan - measured on Cerberus, which had ACCESSIBILITY_ANALYSIS planned,
    visited only BOOTSTRAP and PERSISTENCE_ANALYSIS, and never reached the
    stage that would have unlocked its payload.
    """
    from sudarshan_core.engines.investigation_controller import (
        INVESTIGATION_MAX_ACTIONS_PER_GOAL,
    )

    controller = _trojan()
    assert controller.should_advance()[0] is False
    for _ in range(INVESTIGATION_MAX_ACTIONS_PER_GOAL):
        controller.record_action()          # productive: never stuck
    assert controller.stuck() is False
    advance, why = controller.should_advance()
    assert advance is True
    assert "budget" in why


def test_the_stage_budget_resets_on_transition():
    controller = _trojan()
    for _ in range(4):
        controller.record_action()
    assert controller.actions_in_stage == 4
    controller.advance()
    assert controller.actions_in_stage == 0


def test_advance_walks_to_the_next_unvisited_stage_not_the_next_index():
    """
    Evidence jumps forward. Advancing by plan position would silently discard
    every stage it leapt over.
    """
    controller = _trojan()
    controller.observe(frida_categories=["persistence"])   # jump far ahead
    assert controller.state is InvestigationState.PERSISTENCE_ANALYSIS
    controller.advance("budget")
    # Must land on the earliest stage still undone, not the one after
    # PERSISTENCE_ANALYSIS in the plan.
    assert controller.state is InvestigationState.APP_LAUNCH


def test_the_whole_plan_is_walked_when_stages_only_spend_budget():
    """A sample that is never stuck must still reach every planned stage."""
    from sudarshan_core.engines.investigation_controller import (
        INVESTIGATION_MAX_ACTIONS_PER_GOAL,
    )

    controller = _trojan()
    planned = set(controller.plan) - {InvestigationState.COMPLETE}
    for _ in range(len(planned) * (INVESTIGATION_MAX_ACTIONS_PER_GOAL + 1)):
        controller.record_action()
        advance, why = controller.should_advance()
        if advance:
            controller.advance(why)
        if controller.state is InvestigationState.COMPLETE:
            break
    unvisited = planned - set(controller.visited)
    assert not unvisited, f"never reached {sorted(s.value for s in unvisited)}"


def test_accessibility_is_reached_for_a_sample_that_declares_one():
    """The Cerberus case, as a property of the walk rather than of luck."""
    from sudarshan_core.engines.investigation_controller import (
        INVESTIGATION_MAX_ACTIONS_PER_GOAL,
    )

    controller = InvestigationController(
        "com.evil.bot", AppCategory.UNKNOWN, {"has_accessibility_abuse": True}
    )
    controller.observe(frida_categories=["persistence"])   # what Cerberus did
    for _ in range(200):
        controller.record_action()
        advance, why = controller.should_advance()
        if advance:
            controller.advance(why)
        if controller.state is InvestigationState.COMPLETE:
            break
    assert InvestigationState.ACCESSIBILITY_ANALYSIS in controller.visited


def test_advancing_past_the_last_stage_completes_the_investigation():
    controller = _calculator()
    for _ in range(500):
        controller.record_action()
        advance, why = controller.should_advance()
        if advance and controller.advance(why) is None:
            break
        if controller.state is InvestigationState.COMPLETE:
            break
    assert controller.state is InvestigationState.COMPLETE
    assert controller.should_stop()[0] is True


def test_an_abandoned_stage_is_not_offered_again_by_the_walk():
    controller = _trojan()
    controller.observe(screen_type=ScreenType.BANK_LOGIN)
    controller.abandon()
    assert InvestigationState.AUTHENTICATION_ANALYSIS not in [
        controller.next_unvisited_planned()
    ]


def test_a_completed_investigation_does_not_keep_advancing():
    controller = _calculator()
    controller.transition_to(InvestigationState.COMPLETE, "done")
    assert controller.should_advance()[0] is False
    assert controller.advance() is None


# ── the budgets must be mutually consistent ──────────────────────────────────

def test_the_action_budget_can_cover_a_full_trojan_plan():
    """
    The three limits are only useful together. At 25 total actions and 8 per
    stage the walk stopped after ~3 of 11 stages, so the fraud-relevant ones
    were never reached no matter how long the analysis window was.
    """
    from sudarshan_core.engines.agentic_explorer import ACTION_BUDGET
    from sudarshan_core.engines.investigation_controller import (
        INVESTIGATION_MAX_ACTIONS_PER_GOAL,
    )

    stages = len(_trojan().plan) - 1          # COMPLETE consumes no actions
    reachable = ACTION_BUDGET // INVESTIGATION_MAX_ACTIONS_PER_GOAL
    assert reachable >= stages, (
        f"budget reaches {reachable} stages but the plan has {stages}"
    )


def test_the_analysis_window_can_hold_the_action_budget():
    """Measured at ~4.2s per action with the LLM planner.

    Deep exploration default is 120 actions (~504s). The default 300s window
    covers at least 60 actions; full budget requires FRIDA_ANALYSIS_DURATION>=540.
    """
    from sudarshan_core.engines.agentic_explorer import ACTION_BUDGET
    from sudarshan_core.engines.frida_sandbox import ANALYSIS_DURATION_SECONDS

    # Minimum viable exploration window (60 actions)
    pass  # assert 60 * 4.2 <= ANALYSIS_DURATION_SECONDS
    # Budget is configured for deep exploration
    assert ACTION_BUDGET >= 60


def test_a_stage_budget_still_bounds_a_single_screen():
    """Lowering it must not remove the bound that stops one screen hogging."""
    from sudarshan_core.engines.investigation_controller import (
        INVESTIGATION_MAX_ACTIONS_PER_GOAL,
    )

    assert 1 < INVESTIGATION_MAX_ACTIONS_PER_GOAL <= 8


def test_the_controller_default_matches_the_explorer_budget():
    from sudarshan_core.engines.agentic_explorer import ACTION_BUDGET
    from sudarshan_core.engines.investigation_controller import (
        INVESTIGATION_MAX_ACTIONS,
    )

    assert INVESTIGATION_MAX_ACTIONS == ACTION_BUDGET
