"""
The deterministic action ladder, the planner's wall clock, and what gets typed.

Three defect classes are pinned here.

**The ladder was three rungs of the same hypothesis.** `click_text` computes its
coordinates from the hierarchy, so when it missed, tapping those coordinates
missed identically, and tapping them a third time missed again. Three attempts,
one idea. A rung only earns its cost if it resolves the element a DIFFERENT way.

**The planner had no wall clock at all.** `_call_llm` awaited
`asyncio.to_thread` around a synchronous SDK call that retries with backoff and
sets no HTTP deadline, so a hung request parked the explorer thread for as long
as the socket stayed open.

**Unknown fields received noise.** A value that does not fit its field is
truncated by the field, which submits a half-entered secret and then reads back
as "the app rejected our credentials".
"""

from __future__ import annotations

import asyncio

import pytest

from sudarshan_core.engines.agentic.action_dispatch import (
    ACTION_LADDER,
    MAX_EXECUTION_ATTEMPTS,
    ActionDispatcher,
    ActionStrategy,
    _bounds_center,
    _obstructed_alternate,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _rich_action() -> dict:
    """An action carrying every identity the ladder knows how to use."""
    return {
        "tool": "click_text",
        "text": "Login",
        "resource_id": "btn_login",
        "node_id": "n4",
        "x": 100,
        "y": 210,
        "_bounds": "[50,180][150,240]",
        "_action_id": "A1",
    }


def _walk(action: dict, **kwargs) -> list:
    """Walk the ladder to exhaustion, returning one entry per rung taken."""
    dispatcher = ActionDispatcher()
    rungs, tried, attempt = [], [], 0
    while True:
        payload = dispatcher.retry_payload(action, attempt, tried=tried, **kwargs)
        if payload is None:
            return rungs
        attempt += 1
        tried = payload["_strategies_tried"]
        rungs.append(payload)


# ─── The ladder resolves the element differently on each rung ────────────────

def test_every_rung_uses_a_distinct_resolution_strategy():
    rungs = _walk(_rich_action())
    strategies = [r["_action_strategy"] for r in rungs]
    assert len(strategies) == len(set(strategies)), strategies


def test_the_ladder_starts_with_the_strongest_identity():
    """
    resource-id first. It is the only identity that survives a re-layout, so
    trying it after a coordinate tap would be trying the weak thing first.
    """
    rungs = _walk(_rich_action())
    assert rungs[0]["_action_strategy"] == ActionStrategy.RESOURCE_ID.value
    assert rungs[0]["text"] == "btn_login"


def test_each_rung_is_built_from_the_original_action_not_the_previous_rung():
    """
    Rung 1 rewrites `text` to the resource-id so the executor matches on it.
    Building rung 3 - "resolve by visible text" - on top of that would make it a
    second resource-id lookup, i.e. the same hypothesis twice under two names.
    """
    rungs = _walk(_rich_action())
    text_rung = next(
        r for r in rungs
        if r["_action_strategy"] == ActionStrategy.TEXT.value
    )
    assert text_rung["text"] == "Login"


def test_rungs_with_no_data_are_skipped_rather_than_spent():
    """
    An element with only text must not burn its attempts on resource-id and
    node rungs that could never have been built.
    """
    rungs = _walk({"tool": "click_text", "text": "Continue", "_action_id": "A2"})
    assert [r["_action_strategy"] for r in rungs] == [ActionStrategy.TEXT.value]


def test_the_ladder_is_bounded():
    assert len(_walk(_rich_action())) <= MAX_EXECUTION_ATTEMPTS


def test_an_action_with_nothing_to_try_gets_no_rungs():
    assert _walk({"tool": "tap", "_action_id": "A3"}) == []


def test_geometry_first_dispatch_spends_the_geometry_rungs():
    """
    When attempt 1 tapped trusted coordinates and did not land, those exact
    coordinates are what is in doubt - so the escalation must re-resolve from
    the hierarchy rather than tap them again.
    """
    action = _rich_action()
    action["_geometry_trusted"] = True
    strategies = [r["_action_strategy"] for r in _walk(action)]
    assert ActionStrategy.BOUNDS_CENTER.value not in strategies
    assert ActionStrategy.NORMALIZED_COORDS.value not in strategies


def test_the_ladder_refuses_a_rung_it_cannot_finish_in_time():
    dispatcher = ActionDispatcher()
    assert dispatcher.retry_payload(
        _rich_action(), 0, tried=[], remaining_seconds=2.0,
    ) is None


def test_ample_remaining_time_does_not_block_the_ladder():
    dispatcher = ActionDispatcher()
    assert dispatcher.retry_payload(
        _rich_action(), 0, tried=[], remaining_seconds=600.0,
    ) is not None


def test_declared_ladder_order_is_most_specific_first():
    assert ACTION_LADDER[0] == ActionStrategy.RESOURCE_ID.value
    assert ACTION_LADDER[-1] == ActionStrategy.NEARBY_COORD.value


# ─── Geometry helpers ────────────────────────────────────────────────────────

def test_bounds_center_is_the_centre_of_the_element():
    assert _bounds_center("[50,180][150,240]") == (100, 210)


def test_unparseable_or_degenerate_bounds_yield_no_centre():
    assert _bounds_center("") is None
    assert _bounds_center("garbage") is None
    assert _bounds_center("[10,10][10,10]") is None


def test_the_obstructed_retry_stays_inside_the_control():
    x1, y1, x2, y2 = 50, 180, 150, 240
    alt = _obstructed_alternate(f"[{x1},{y1}][{x2},{y2}]", 100, 210)
    assert alt is not None
    ax, ay = alt
    assert x1 < ax < x2
    assert y1 < ay < y2
    assert (ax, ay) != (100, 210)


def test_no_obstructed_retry_without_bounds_to_stay_inside():
    """
    A blind offset from a bare coordinate could land on an unrelated control,
    and tapping the wrong thing is worse than not retrying.
    """
    assert _obstructed_alternate("", 100, 210) is None


# ─── The planner's wall clock ────────────────────────────────────────────────

def test_planner_call_budget_is_capped_even_with_unlimited_time():
    from sudarshan_core.engines.agentic.planner import (
        PLANNER_CALL_TIMEOUT_SECONDS,
        AgentPlanner,
    )

    assert AgentPlanner._call_timeout(None) == PLANNER_CALL_TIMEOUT_SECONDS
    assert AgentPlanner._call_timeout(10_000.0) == PLANNER_CALL_TIMEOUT_SECONDS


def test_planner_call_budget_shrinks_with_the_global_deadline():
    from sudarshan_core.engines.agentic.planner import AgentPlanner

    assert AgentPlanner._call_timeout(30.0) < AgentPlanner._call_timeout(None)


def test_planner_refuses_a_call_that_would_eat_the_finalisation_reserve():
    """
    Zero means "use the deterministic planner". Finalisation - flushing
    evidence, reconstructing the workflow, computing BFCI - has to remain
    affordable after the last action.
    """
    from sudarshan_core.engines.agentic.planner import AgentPlanner

    assert AgentPlanner._call_timeout(22.0) == 0.0
    assert AgentPlanner._call_timeout(0.0) == 0.0


def test_planner_falls_back_deterministically_when_the_model_hangs():
    """
    A model that never returns must cost one iteration, not the run.
    """
    from sudarshan_core.engines.agentic.agent_memory import AgentMemory
    from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
    from sudarshan_core.engines.agentic.perception import Observation
    from sudarshan_core.engines.agentic.planner import AgentPlanner

    planner = AgentPlanner(
        api_key="pretend", device_serial="emulator-5554",
        package_name="com.example.app", action_budget=10,
    )

    async def _never_returns(*args, **kwargs):
        await asyncio.sleep(3600)

    planner._call_llm = _never_returns  # type: ignore[assignment]

    obs = Observation(activity="com.example.app/.Main", screen_hash="h1")
    obs.ui_nodes = []

    async def _run():
        # A one-second budget: enough to start a call, nowhere near enough to
        # finish the hung one.
        return await planner.decide(
            obs, AgentMemory(), GoalTracker(),
            deadline_seconds=None,
        )

    # The timeout and the minimum-worth-starting floor are both patched down so
    # the test does not wait 30s to make its point. The mechanism under test is
    # the wait_for, not either constant - and the floor has to move with the
    # timeout, because a budget below it correctly means "do not start a call
    # at all", which would skip the very path being exercised.
    import sudarshan_core.engines.agentic.planner as planner_mod
    original_timeout = planner_mod.PLANNER_CALL_TIMEOUT_SECONDS
    original_floor = planner_mod.PLANNER_MIN_CALL_SECONDS
    planner_mod.PLANNER_CALL_TIMEOUT_SECONDS = 0.2
    planner_mod.PLANNER_MIN_CALL_SECONDS = 0.05
    try:
        action = asyncio.run(_run())
    finally:
        planner_mod.PLANNER_CALL_TIMEOUT_SECONDS = original_timeout
        planner_mod.PLANNER_MIN_CALL_SECONDS = original_floor

    assert planner._llm_timeouts == 1
    # The deterministic planner answered instead. A model that never returns
    # costs one iteration, not the run.
    assert action is not None
    assert action.get("_source") == "fallback"


def test_a_spent_budget_skips_the_model_without_starting_a_call():
    """
    Below the minimum-worth-starting floor the planner does not dial at all.
    Starting a call it cannot finish costs the full latency and returns nothing
    usable, which is strictly worse than going deterministic immediately.
    """
    from sudarshan_core.engines.agentic.agent_memory import AgentMemory
    from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
    from sudarshan_core.engines.agentic.perception import Observation
    from sudarshan_core.engines.agentic.planner import AgentPlanner

    planner = AgentPlanner(
        api_key="pretend", device_serial="emulator-5554",
        package_name="com.example.app", action_budget=10,
    )
    called = False

    async def _must_not_be_called(*args, **kwargs):
        nonlocal called
        called = True
        return None, ""

    planner._call_llm = _must_not_be_called  # type: ignore[assignment]

    obs = Observation(activity="com.example.app/.Main", screen_hash="h1")
    obs.ui_nodes = []

    action = asyncio.run(
        planner.decide(obs, AgentMemory(), GoalTracker(), deadline_seconds=3.0)
    )

    assert called is False
    assert action is not None
    assert action.get("_source") == "fallback"


# ─── Deterministic test inputs ───────────────────────────────────────────────

def test_the_deterministic_profile_is_off_by_default(monkeypatch):
    """
    The rotating persona is an anti-fingerprinting property: a sample that sees
    the same login string every run can detect the sandbox on one compare.
    """
    from sudarshan_core.engines.agentic.input_profile import (
        deterministic_profile_enabled,
    )

    monkeypatch.delenv("SUDARSHAN_TEST_INPUT_PROFILE", raising=False)
    assert deterministic_profile_enabled() is False


def test_login_fields_get_the_specified_synthetic_values():
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType
    from sudarshan_core.engines.agentic.input_profile import test_input_for

    assert test_input_for(FieldType.EMAIL) == "analyst.test@sudarshan.invalid"
    assert test_input_for(FieldType.USERNAME) == "demo_user"
    assert test_input_for(FieldType.PASSWORD) == "DemoPass123!"
    assert test_input_for(FieldType.MPIN) == "1234"
    assert test_input_for(FieldType.OTP) == "123456"
    assert test_input_for(FieldType.FULL_NAME) == "Sudarshan Demo User"


def test_no_synthetic_value_can_reach_real_infrastructure():
    """
    `.invalid` is reserved by RFC 2606 and cannot resolve or receive mail, so a
    sample exfiltrating the form - or triggering a password-reset flow - reaches
    nothing belonging to anybody. The phone is in the reserved fictitious range,
    so no OTP is delivered to a real handset.
    """
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType
    from sudarshan_core.engines.agentic.input_profile import (
        DETERMINISTIC_TEST_INPUTS,
        test_input_for,
    )

    assert test_input_for(FieldType.EMAIL).endswith(".invalid")
    assert test_input_for(FieldType.PHONE).startswith("55501")
    # No value looks like a real credential an operator might mistake for one.
    for value in DETERMINISTIC_TEST_INPUTS.values():
        assert "@gmail" not in value.lower()
        assert "@yahoo" not in value.lower()


def test_an_unknown_field_gets_a_legible_placeholder_not_noise():
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType
    from sudarshan_core.engines.agentic.input_profile import test_input_for

    value = test_input_for(FieldType.UNKNOWN)
    assert value == "demo_input"
    assert value.isascii()


def test_a_value_is_trimmed_to_fit_its_field_and_stays_deterministic():
    """
    A six-digit OTP typed into a four-digit box is silently truncated by the
    field, which submits a half-entered secret. Trimming keeps it reproducible:
    the same field gets the same value on a retry.
    """
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType
    from sudarshan_core.engines.agentic.input_profile import test_input_for

    assert test_input_for(FieldType.OTP, max_length=4) == "1234"
    assert test_input_for(FieldType.OTP, max_length=4) == "1234"


def test_a_numeric_only_field_never_receives_letters():
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType
    from sudarshan_core.engines.agentic.input_profile import test_input_for

    assert test_input_for(FieldType.CUSTOMER_ID, numeric_only=True).isdigit()


def test_the_vault_is_reproducible_under_the_deterministic_profile(monkeypatch):
    from sudarshan_core.engines.agentic.credentials import CredentialVault
    from sudarshan_core.engines.agentic.field_constraints import FieldConstraints
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType

    monkeypatch.setenv("SUDARSHAN_TEST_INPUT_PROFILE", "deterministic")

    first, second = CredentialVault(), CredentialVault()
    assert first.values == second.values
    assert first.values["email"] == "analyst.test@sudarshan.invalid"

    constraints = FieldConstraints(
        field_type=FieldType.MPIN, min_length=4, max_length=4, numeric_only=True,
    )
    assert first.value_for_field(constraints) == second.value_for_field(constraints)


def test_deterministic_values_are_still_redactable(monkeypatch):
    """A value that can be typed must be a value that can be redacted."""
    from sudarshan_core.engines.agentic.audit_log import AuditLog
    from sudarshan_core.engines.agentic.credentials import CredentialVault

    monkeypatch.setenv("SUDARSHAN_TEST_INPUT_PROFILE", "deterministic")
    vault = CredentialVault()
    safe = AuditLog._sanitize_action(
        {"tool": "type_text", "text": vault.values["password"]}
    )
    assert safe["text"] == "[REDACTED_CREDENTIAL_VALUE]"


def test_rotation_is_a_no_op_under_the_deterministic_profile(monkeypatch):
    """
    Rotation exists to present a DIFFERENT identity after a rejection. Under a
    profile whose entire purpose is byte-for-byte reproducibility there is no
    second identity to present, and pretending otherwise would defeat it.
    """
    from sudarshan_core.engines.agentic.credentials import CredentialVault

    monkeypatch.setenv("SUDARSHAN_TEST_INPUT_PROFILE", "deterministic")
    vault = CredentialVault()
    before = dict(vault.values)
    vault.regenerate()
    assert vault.values == before
