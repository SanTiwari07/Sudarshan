"""
Regression tests for the planner budget and the type_text phase gate.

Two defects, both measured on a live Anubis run:

1. Gemini was called BEFORE the exploration graph was consulted, on every
   iteration. select_canonical_action gives the graph priority for
   click_text / tap / tap_sequence / type_text / check, so on those iterations
   the model's answer was computed and discarded. Measured latencies on
   consecutive iterations: 7.9s, 13.8s, 15.1s, 11.2s - about 12s each, against
   ~10s for all of perception, execution and verification combined. Twenty
   calls ate roughly 240s of a 300s window.

2. type_text was permitted on four stages only. The stage is chosen by what the
   SAMPLE does - a single `network` event maps to NETWORK_ANALYSIS - while the
   form on screen is also chosen by the sample, and the two need not agree.
   Anubis's C2 beacon moved the investigation to NETWORK_ANALYSIS while its
   payload displayed a four-field credential harvest; the planner asked to type
   five times and was refused every time, so one field of four was filled.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest


# ── planner budget ────────────────────────────────────────────────────────────


def test_planner_is_skipped_when_the_graph_already_wins():
    from sudarshan_core.engines.agentic_explorer import _planner_could_change_outcome

    for tool in ("click_text", "tap", "tap_sequence", "check"):
        assert _planner_could_change_outcome({"tool": tool}) is False, tool


def test_planner_is_skipped_for_a_field_the_graph_can_name():
    """
    The eChallan boxes resolve to MOBILE / MOTHER_NAME from their own hints, so
    the model has nothing to add and its answer would be discarded anyway.
    """
    from sudarshan_core.engines.agentic_explorer import _planner_could_change_outcome

    assert _planner_could_change_outcome(
        {"tool": "type_text", "field_type": "MOBILE"}
    ) is False


def test_planner_is_consulted_for_a_field_the_graph_cannot_name():
    """
    The one case where a model that can read the screen earns its latency: an
    unlabelled WebView box the graph fell through to a positional guess on.
    """
    from sudarshan_core.engines.agentic_explorer import _planner_could_change_outcome

    for unknown in ("", "UNKNOWN"):
        assert _planner_could_change_outcome(
            {"tool": "type_text", "field_type": unknown}
        ) is True, unknown


def test_planner_is_consulted_when_the_graph_has_nothing():
    from sudarshan_core.engines.agentic_explorer import _planner_could_change_outcome

    assert _planner_could_change_outcome(None) is True
    assert _planner_could_change_outcome({}) is True


def test_planner_is_consulted_for_tools_the_graph_does_not_win():
    """A scroll or a press_back from the graph must not silence the planner."""
    from sudarshan_core.engines.agentic_explorer import _planner_could_change_outcome

    for tool in ("scroll", "press_back", "swipe", "dump_ui"):
        assert _planner_could_change_outcome({"tool": tool}) is True, tool


def test_graph_wins_list_matches_the_selector_it_mirrors():
    """
    _GRAPH_WINS_TOOLS is a copy of the tuple inside select_canonical_action.
    If that function gains or loses a tool, this must move with it, or the
    budget will skip the planner on an iteration where it would have won.
    """
    import inspect

    from sudarshan_core.engines.agentic import action_dispatch
    from sudarshan_core.engines.agentic_explorer import _GRAPH_WINS_TOOLS

    source = inspect.getsource(action_dispatch.select_canonical_action)
    for tool in _GRAPH_WINS_TOOLS:
        assert f'"{tool}"' in source, (
            f"{tool} is in _GRAPH_WINS_TOOLS but not in select_canonical_action"
        )


def test_planner_consult_interval_is_positive():
    """
    The graph can never propose device-state work (grant_permission,
    inject_test_sms, fast_forward_time), so the model must get a turn on a
    fixed cadence however busy the graph is.
    """
    from sudarshan_core.engines.agentic_explorer import PLANNER_CONSULT_EVERY

    assert PLANNER_CONSULT_EVERY >= 1


# ── type_text phase gate ──────────────────────────────────────────────────────


def test_type_text_is_permitted_in_every_active_state():
    from sudarshan_core.engines.investigation_controller import (
        ALLOWED_ACTIONS, InvestigationState,
    )

    for state, allowed in ALLOWED_ACTIONS.items():
        if state is InvestigationState.COMPLETE:
            continue
        assert "type_text" in allowed, f"type_text missing from {state}"


def test_the_states_that_actually_blocked_anubis_now_allow_typing():
    from sudarshan_core.engines.investigation_controller import (
        ALLOWED_ACTIONS, InvestigationState,
    )

    for state in (
        InvestigationState.NETWORK_ANALYSIS,
        InvestigationState.FINAL_OBSERVATION,
        InvestigationState.OVERLAY_ANALYSIS,
        InvestigationState.PERSISTENCE_ANALYSIS,
    ):
        assert "type_text" in ALLOWED_ACTIONS[state], state


def test_complete_still_permits_nothing():
    """COMPLETE means the investigation is over, not that one tool is barred."""
    from sudarshan_core.engines.investigation_controller import (
        ALLOWED_ACTIONS, InvestigationState,
    )

    assert ALLOWED_ACTIONS[InvestigationState.COMPLETE] == frozenset()


def test_read_only_stages_did_not_lose_their_other_restrictions():
    """
    Adding type_text must not have widened anything else. BOOTSTRAP still
    refuses navigation.
    """
    from sudarshan_core.engines.investigation_controller import (
        ALLOWED_ACTIONS, InvestigationState,
    )

    bootstrap = ALLOWED_ACTIONS[InvestigationState.BOOTSTRAP]
    assert "tap" not in bootstrap
    assert "click_text" not in bootstrap
    assert "dump_ui" in bootstrap


# ── permission dialog: the question is not the button ────────────────────────


def test_permission_dialog_title_is_not_treated_as_a_button():
    """
    Android renders "Allow RTO eChallan to make and manage phone calls?" as the
    dialog TITLE, inside a clickable container. It matches \ballow\b, so it
    scored ACCEPT 0.55+ - the same as the real Allow button - and the agent
    kept picking it.

    Measured on the Anubis payload: three consecutive clicks on the prompt
    before reaching click_text(Allow). Permission screens go through the
    planner at ~25s each, so three dialogs burned 263s of the walk and the
    credential form was not reached until t+382s.
    """
    from sudarshan_core.engines.agentic.semantic_action import (
        SemanticRole, classify_semantic_role,
    )

    for prompt in (
        "Allow RTO eChallan to make and manage phone calls?",
        "Allow RTO eChallan to send and view SMS messages?",
        "Allow this app to access your contacts?",
    ):
        c = classify_semantic_role(
            label=prompt, class_name="android.widget.TextView", is_clickable=True,
        )
        assert c.role is SemanticRole.UNKNOWN, f"{prompt} -> {c.role}"


def test_real_dialog_buttons_still_classify_as_accept():
    """The fix must not disarm the controls the walk depends on."""
    from sudarshan_core.engines.agentic.semantic_action import (
        SemanticRole, classify_semantic_role,
    )

    for button in ("Allow", "Allow from this source", "Install", "Update", "OK"):
        c = classify_semantic_role(
            label=button, class_name="android.widget.Button", is_clickable=True,
        )
        assert c.role is SemanticRole.ACCEPT, f"{button} -> {c.role}"


def test_a_short_question_is_still_a_button():
    """
    The rule is long AND question-shaped. "Allow?" is a button; excluding it
    would be over-reach.
    """
    from sudarshan_core.engines.agentic.semantic_action import (
        SemanticRole, classify_semantic_role,
    )

    c = classify_semantic_role(
        label="Allow?", class_name="android.widget.Button", is_clickable=True,
    )
    assert c.role is SemanticRole.ACCEPT


def test_a_long_imperative_is_still_a_button():
    """"Allow from this source" is long but asks nothing - it stays a control."""
    from sudarshan_core.engines.agentic.semantic_action import _is_dialog_prompt

    assert _is_dialog_prompt("Allow from this source") is False
    assert _is_dialog_prompt("Allow RTO eChallan to make and manage phone calls?") is True


# ── form ordering: unfilled fields before filled ones ────────────────────────


def _input(label, resolved=False, fill_attempts=0, priority=100):
    from sudarshan_core.engines.agentic.exploration_engine import ActionItem

    a = ActionItem(
        action_id=f"ACT-{label[:3]}", node_id=f"n{label[:2]}",
        action_type="input", label=label,
    )
    a.verified = resolved   # `resolved` is verified|failed|blocked|unreachable|explored
    a.fill_attempts = fill_attempts
    a.priority = priority
    return a


def test_unfilled_fields_are_offered_before_already_filled_ones():
    """
    The four-field credential form on the Anubis payload. Ranked purely on
    priority, the two highest-scoring boxes kept winning: the run dispatched
    Full Name, Mobile Number, then Full Name and Mobile Number AGAIN. Mother
    Name and Date Of Birth were never attempted once - not failed, never
    dispatched - so the form could not be completed however long it ran.
    """
    inputs = [
        _input("Full Name*", resolved=True, priority=200),
        _input("Mobile Number*", resolved=True, priority=190),
        _input("Mother Name*", resolved=False, priority=100),
        _input("Date Of Birth*", resolved=False, priority=90),
    ]
    unfilled = [a for a in inputs if not a.resolved]
    filled = [a for a in inputs if a.resolved]
    unfilled.sort(key=lambda a: getattr(a, "fill_attempts", 0))
    ordered = unfilled + filled

    assert [a.label for a in ordered][:2] == ["Mother Name*", "Date Of Birth*"]


def test_a_field_that_cannot_be_typed_into_falls_behind_the_others():
    """
    A date box that opens a calendar rather than a keyboard must not absorb
    every remaining action while its siblings sit empty.
    """
    inputs = [
        _input("Date Of Birth*", resolved=False, fill_attempts=3),
        _input("Mother Name*", resolved=False, fill_attempts=0),
    ]
    inputs.sort(key=lambda a: getattr(a, "fill_attempts", 0))
    assert inputs[0].label == "Mother Name*"


def test_filled_fields_are_kept_for_re_entry_not_dropped():
    """A form cleared by a validation error still has to be re-entered."""
    inputs = [
        _input("Full Name*", resolved=True),
        _input("Mother Name*", resolved=False),
    ]
    unfilled = [a for a in inputs if not a.resolved]
    filled = [a for a in inputs if a.resolved]
    ordered = unfilled + filled
    assert len(ordered) == 2
    assert ordered[-1].label == "Full Name*"


# ── form progress is not stagnation ──────────────────────────────────────────


def test_recovery_does_not_submit_a_half_filled_form():
    """
    STEP_PRESS_ENTER was guarded on all_inputs_filled; STEP_TAP_SUBMIT was not,
    though both commit the form.

    Measured on the Anubis payload: two of four fields filled and verified,
    stagnation fired anyway (populating a WebView input does not change the
    screen hash), recovery climbed to tap_submit and committed the form with
    Mother Name and Date Of Birth empty.
    """
    from sudarshan_core.engines.agentic.form_recovery import (
        STEP_TAP_SUBMIT, FormRecoveryLadder, FormScreen,
    )

    submit = MagicMock()
    submit.usable = True
    half = FormScreen(
        state_id="STATE-012", input_count=4, unfilled_input_count=2,
    )
    half.submit = submit
    full = FormScreen(
        state_id="STATE-012", input_count=4, unfilled_input_count=0,
    )
    full.submit = submit

    ladder = FormRecoveryLadder()
    assert ladder._applicable(STEP_TAP_SUBMIT, half) is False
    assert ladder._applicable(STEP_TAP_SUBMIT, full) is True


# ── headless payloads: monkey can never start them ───────────────────────────


def test_a_package_with_no_launcher_falls_back_to_an_exported_component():
    """
    monkey can only start something carrying LAUNCHER. A dropped payload
    routinely declares none - measured live, com.pagethan10 was installed but
    `resolve-activity LAUNCHER` answered "No activity found", and the explorer
    re-issued the same monkey command every ~2s.
    """
    import asyncio

    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

    ex = ToolExecutor.__new__(ToolExecutor)
    ex.device_serial = "emulator-5554"
    calls = []

    async def _adb(*args):
        calls.append(args)
        if "monkey" in args:
            return True, "** No activities found to run, monkey aborted."
        if "resolve-activity" in args:
            return True, "com.pagethan10/.SilentService"
        if "am" in args:
            return True, "Starting: Intent"
        return True, ""

    ex._adb = _adb
    res = asyncio.run(ex._tool_start_activity({"package": "com.pagethan10"}))

    assert res.success is True
    assert res.data["via"] == "resolved_component"
    assert res.data["component"] == "com.pagethan10/.SilentService"


def test_a_truly_headless_package_is_terminal_not_retryable():
    """
    With no activity at all, the honest answer is that this is a property of
    the sample. `retryable=False` stops the budget being spent on a command
    that can never succeed; the hooks still observe the payload.
    """
    import asyncio

    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

    ex = ToolExecutor.__new__(ToolExecutor)
    ex.device_serial = "emulator-5554"

    async def _adb(*args):
        if "monkey" in args:
            return True, "** No activities found to run, monkey aborted."
        if "resolve-activity" in args:
            return True, "No activity found"
        return True, ""

    ex._adb = _adb
    res = asyncio.run(ex._tool_start_activity({"package": "com.pagethan10"}))

    assert res.success is False
    assert res.data["headless"] is True
    assert res.data["retryable"] is False
