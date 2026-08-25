"""
SUDARSHAN - Multi-field form entry.

The defect class these cover: the explorer could fill a login box but not a
registration / personal-details / KYC form. Several independent faults
reinforced each other, and each is pinned here by the behaviour that was wrong
rather than by the shape of the code that was wrong.

Grouped in one module because they are one bug from the user's point of view -
"the app asks for name, email and phone and the walk gives up" - and a
regression in any one of them brings the whole symptom back.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.tool_executor import ToolExecutor  # noqa: E402


# ─── Harness ─────────────────────────────────────────────────────────────────

def _executor(package: str = "com.example.form"):
    """A ToolExecutor whose ADB channel records every argv it is handed."""
    calls: list[tuple[str, ...]] = []

    async def _record(*args: str):
        calls.append(args)
        return True, ""

    ex = ToolExecutor(device_serial="fixture-5554", package_name=package)
    ex._adb = AsyncMock(side_effect=_record)
    return ex, calls


def _argv(calls) -> list[str]:
    return [" ".join(str(a) for a in c) for c in calls]


# ─── F1: clearing a field before typing into it ──────────────────────────────

def test_type_text_never_emits_an_invalid_keycode():
    """
    `KEYCODE_CTRL_A` is not an Android keycode.

    android.view.KeyEvent defines KEYCODE_CTRL_LEFT / KEYCODE_CTRL_RIGHT and no
    per-letter chord, so `input keyevent KEYCODE_CTRL_A` returns "Unknown
    keycode" and clears nothing. The result was discarded, so the failure was
    silent and every re-entry APPENDED to the field:
    `user4f2a` -> `user4f2auser9c1b` -> ... which no email or phone validator
    will ever accept.
    """
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    assert not any("KEYCODE_CTRL_A" in line for line in _argv(calls))


def test_type_text_clears_the_field_before_typing():
    """MOVE_END then backspaces, issued BEFORE the text goes in."""
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    lines = _argv(calls)

    clear_at = next(
        (i for i, line in enumerate(lines)
         if "KEYCODE_MOVE_END" in line and "KEYCODE_DEL" in line),
        None,
    )
    type_at = next(
        (i for i, line in enumerate(lines) if "input text" in line), None,
    )
    assert clear_at is not None, f"no clear sequence issued: {lines}"
    assert type_at is not None, f"nothing was typed: {lines}"
    assert clear_at < type_at, "the field must be cleared before typing"


def test_the_clear_is_a_single_round_trip():
    """
    One `input keyevent` carrying every keycode.

    `input` accepts a list, and a backspace per adb call would cost a round
    trip each - at ~50ms that is seconds per field on a form with several.
    """
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    del_calls = [line for line in _argv(calls) if "KEYCODE_DEL" in line]
    assert len(del_calls) == 1, f"expected one batched clear, got {del_calls}"
    assert del_calls[0].count("KEYCODE_DEL") > 1, "should batch several deletes"


def test_a_known_field_length_bounds_the_delete_count():
    """
    The caller can say how much is in the field, so we do not send 64
    backspaces to clear four digits.
    """
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "otp", "existing_length": 4,
        "x": 10, "y": 10,
    }))
    clear = next(line for line in _argv(calls) if "KEYCODE_DEL" in line)
    count = clear.count("KEYCODE_DEL")
    assert 4 <= count <= 24, f"delete count {count} not proportionate to 4 chars"


def test_a_failed_clear_is_surfaced_not_swallowed():
    """
    A clear that did not take means the next type APPENDS.

    It must be visible to the caller, because the field-population verifier is
    what turns that into a retry rather than a silently corrupted form.
    """
    calls: list[tuple[str, ...]] = []

    async def _clear_fails(*args: str):
        calls.append(args)
        if "keyevent" in args and "KEYCODE_DEL" in args:
            return False, "Error: Unknown keycode"
        return True, ""

    ex = ToolExecutor(device_serial="fixture-5554", package_name="com.example.form")
    ex._adb = AsyncMock(side_effect=_clear_fails)

    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    assert result.data.get("field_cleared") is False


def test_a_successful_clear_is_reported():
    ex, _ = _executor()
    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    assert result.data.get("field_cleared") is True


# ─── F2: the population verdict must decide whether a field is done ──────────

from sudarshan_core.engines.agentic.exploration_engine import (  # noqa: E402
    ExplorationBudget,
    ExplorationGraph,
)

TARGET = "com.example.form"

_FORM_XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.TextView" text="Full Name" clickable="false"
       bounds="[0,100][400,140]" />
 <node class="android.widget.EditText" resource-id="com.example.form:id/name"
       text="" password="false" enabled="true" bounds="[0,150][400,200]" />
 <node class="android.widget.TextView" text="Email" clickable="false"
       bounds="[0,220][400,260]" />
 <node class="android.widget.EditText" resource-id="com.example.form:id/email"
       text="" password="false" enabled="true" bounds="[0,270][400,320]" />
 <node class="android.widget.Button" text="SUBMIT" clickable="true"
       enabled="true" bounds="[0,350][400,400]" />
</hierarchy>"""


class _Obs:
    """Minimal observation the graph accepts."""

    def __init__(self, xml: str):
        from sudarshan_core.engines.agentic.perception import PerceptionPipeline

        pipeline = PerceptionPipeline.__new__(PerceptionPipeline)
        self.ui_nodes = pipeline._parse_ui_nodes(xml)
        self.activity = f"{TARGET}/.FormActivity"
        self.screen_hash = "h-form"
        self.is_webview = False
        self.ocr_text = ""
        self.logcat_tail = ""
        self.frida_events = []


def _form_state():
    g = ExplorationGraph(package_name=TARGET)
    st = g.observe(_Obs(_FORM_XML), semantic_type="UNKNOWN",
                   foreground_package=TARGET)
    return g, st


def _first_input(state):
    return next(a for a in state.actionable_elements if a.action_type == "input")


def _record(g, st, item, *, input_verified):
    return g.record_action(
        source_state_id=st.state_id,
        target_state_id=st.state_id,
        action_type="type_text",
        target_description=item.label,
        success=True,
        verified=False,
        ui_changed=False,
        ever_ui_changed=False,
        attempts=1,
        action_id=item.action_id,
        input_verified=input_verified,
    )


def test_an_unchecked_input_still_resolves():
    """
    Today's behaviour, preserved.

    Typing does not move the screen hash by design, so a caller that supplies
    no population verdict must still see the field resolved - otherwise every
    type_text would loop.
    """
    g, st = _form_state()
    item = _first_input(st)
    _record(g, st, item, input_verified=None)
    assert item.explored and item.verified
    assert item not in st.unexplored_actions()


def test_a_confirmed_population_resolves():
    g, st = _form_state()
    item = _first_input(st)
    _record(g, st, item, input_verified=True)
    assert item.explored and item.verified


def test_a_field_proven_empty_stays_unresolved_and_is_retried():
    """
    The defect: adb exited 0, so the field was marked explored and verified
    even when the verifier had just proven it empty. It left `pending_inputs`,
    which released the held submit control onto an unfilled form.
    """
    g, st = _form_state()
    item = _first_input(st)
    _record(g, st, item, input_verified=False)

    assert not item.explored, "a field proven empty must not read as explored"
    assert not item.verified
    assert item in st.unexplored_actions(), "it must be offered again"
    assert item in [a for a in st.unexplored_actions() if a.action_type == "input"]


def test_repeated_failures_resolve_as_failed_not_verified():
    """Bounded: a field that will not accept input must not loop forever."""
    g, st = _form_state()
    item = _first_input(st)

    for _ in range(ExplorationBudget.MAX_INPUT_FILL_ATTEMPTS):
        _record(g, st, item, input_verified=False)
        assert item.fill_attempts <= ExplorationBudget.MAX_INPUT_FILL_ATTEMPTS

    assert item.failed, "exhausted retries must resolve the action"
    assert not item.verified, "and must not claim it was verified"
    assert item not in st.unexplored_actions()


def test_the_retry_budget_is_not_pinned_by_execution_attempts():
    """
    `execution_attempts` is ASSIGNED from the caller's retry count, not
    incremented, so it sits at 1 across separate selections and cannot bound
    anything. Fill attempts are counted separately for exactly that reason.
    """
    g, st = _form_state()
    item = _first_input(st)
    _record(g, st, item, input_verified=False)
    _record(g, st, item, input_verified=False)
    assert item.fill_attempts == 2


# ─── F3 + F4: unlabeled fields must not all become the same junk ─────────────

from sudarshan_core.engines.agentic.field_classifier import (  # noqa: E402
    ClassificationSource,
    FieldClassification,
    classify_field,
    needs_escalation,
)
from sudarshan_core.engines.agentic.field_taxonomy import FieldType  # noqa: E402

#: Three EditTexts with no caption, no resource-id and no content-desc - the
#: shape a WebView registration form actually has.
_UNLABELLED_FORM_XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.webkit.WebView" text="app" clickable="true"
       bounds="[0,0][1080,2200]">
  <node class="android.widget.EditText" text="" password="false"
        enabled="true" bounds="[60,300][1020,400]" />
  <node class="android.widget.EditText" text="" password="false"
        enabled="true" bounds="[60,450][1020,550]" />
  <node class="android.widget.EditText" text="" password="false"
        enabled="true" bounds="[60,600][1020,700]" />
  <node class="android.widget.Button" text="SUBMIT" clickable="true"
        enabled="true" bounds="[60,800][1020,900]" />
 </node>
</hierarchy>"""


def test_unlabelled_fields_are_indistinguishable_to_the_deterministic_pass():
    """
    Establishes the premise. Not a bug in itself - there genuinely is no local
    signal - which is exactly why the escalation path has to exist.
    """
    obs = _Obs(_UNLABELLED_FORM_XML)
    inputs = [n for n in obs.ui_nodes if n.is_input]
    assert len(inputs) == 3
    types = [
        classify_field(
            field_label=n.field_label, resource_id=n.resource_id,
            content_desc=n.desc, class_name=n.class_name, text=n.text,
            is_password=n.is_password, index=i,
        ).field_type
        for i, n in enumerate(inputs)
    ]
    assert types[1] is FieldType.UNKNOWN and types[2] is FieldType.UNKNOWN


def test_a_positional_guess_escalates_from_any_screen_type():
    """
    The escalation POLICY was already right for a details form, and no
    screen-type rule is needed.

    A first-input guess scores 0.35 and the rest resolve to UNKNOWN at 0.10 -
    under the confidence threshold, and UNKNOWN is caught outright - so every
    unreadable field already qualifies wherever it appears. This is pinned
    because a rule keyed on UNKNOWN/WEBVIEW screens was added here and then
    removed as provably dead; it should not come back.
    """
    first = classify_field(index=0)
    rest = classify_field(index=1)
    assert first.source == ClassificationSource.POSITIONAL
    assert first.confidence < 0.55

    for screen in ("UNKNOWN", "WEBVIEW", "", "BANK_LOGIN"):
        assert needs_escalation(first, screen_type=screen), screen
        assert needs_escalation(rest, screen_type=screen), screen


def test_a_confidently_named_field_never_escalates():
    """The bar stays where it was: no model call for a field we can read."""
    named = classify_field(field_label="Email address")
    assert not needs_escalation(named, screen_type="UNKNOWN")
    assert not needs_escalation(named, screen_type="WEBVIEW")


def test_resolved_field_types_reach_the_action_inventory():
    """
    The wiring: what the escalation resolved must actually decide what gets
    typed, or the fields still all receive the same junk.
    """
    obs = _Obs(_UNLABELLED_FORM_XML)
    inputs = [n for n in obs.ui_nodes if n.is_input]
    overrides = {
        inputs[0].node_id: FieldClassification(
            field_type=FieldType.FULL_NAME, confidence=0.9,
            source=ClassificationSource.GEMINI),
        inputs[1].node_id: FieldClassification(
            field_type=FieldType.EMAIL, confidence=0.9,
            source=ClassificationSource.GEMINI),
        inputs[2].node_id: FieldClassification(
            field_type=FieldType.PHONE, confidence=0.9,
            source=ClassificationSource.GEMINI),
    }

    g = ExplorationGraph(package_name=TARGET)
    st = g.observe(obs, semantic_type="WEBVIEW", foreground_package=TARGET,
                   field_overrides=overrides)

    got = [a.field_type for a in st.actionable_elements if a.action_type == "input"]
    assert got == ["FULL_NAME", "EMAIL", "PHONE"]
    assert len(set(got)) == 3, "three fields must not share one type"


def test_without_overrides_the_inventory_is_unchanged():
    """The new argument is additive: omitting it changes nothing."""
    g = ExplorationGraph(package_name=TARGET)
    st = g.observe(_Obs(_FORM_XML), semantic_type="UNKNOWN",
                   foreground_package=TARGET)
    got = [a.field_type for a in st.actionable_elements if a.action_type == "input"]
    assert got == ["FULL_NAME", "EMAIL"]


def test_the_explorer_escalates_ambiguous_fields(monkeypatch):
    """
    End of the wiring: the async explorer must actually call the escalation
    and hand the answers to the synchronous graph.
    """
    from sudarshan_core.engines import agentic_explorer as ae

    resolved = {
        0: FieldType.FULL_NAME, 1: FieldType.EMAIL, 2: FieldType.PHONE,
    }
    seen: list = []

    async def _fake_gemini(deterministic, **ctx):
        idx = len(seen)
        seen.append(ctx)
        return FieldClassification(
            field_type=resolved[idx], confidence=0.95,
            source=ClassificationSource.GEMINI,
        )

    monkeypatch.setattr(ae, "classify_field_with_gemini", _fake_gemini)

    explorer = ae.AgenticExplorer.__new__(ae.AgenticExplorer)
    explorer.package_name = TARGET

    obs = _Obs(_UNLABELLED_FORM_XML)
    overrides = asyncio.run(
        explorer._resolve_ambiguous_fields(obs, screen_type="WEBVIEW")
    )

    assert len(seen) == 3, "all three ambiguous fields should be escalated"
    assert {c.field_type for c in overrides.values()} == {
        FieldType.FULL_NAME, FieldType.EMAIL, FieldType.PHONE,
    }


def test_escalation_is_skipped_on_an_unambiguous_form(monkeypatch):
    """No model call for a form the local patterns already read correctly."""
    from sudarshan_core.engines import agentic_explorer as ae

    called = []

    async def _fake_gemini(deterministic, **ctx):
        called.append(ctx)
        return deterministic

    monkeypatch.setattr(ae, "classify_field_with_gemini", _fake_gemini)

    explorer = ae.AgenticExplorer.__new__(ae.AgenticExplorer)
    explorer.package_name = TARGET
    asyncio.run(explorer._resolve_ambiguous_fields(_Obs(_FORM_XML),
                                                   screen_type="UNKNOWN"))
    assert called == [], "captioned fields must not cost a model round trip"


def test_a_planner_hint_can_correct_the_graphs_unknown_field():
    """
    `select_canonical_action` gave the graph's type_text unconditional
    priority, so the LLM had no way to correct a field_hint the graph had
    guessed wrong.
    """
    from sudarshan_core.engines.agentic.action_dispatch import (
        select_canonical_action,
    )

    graph_action = {
        "tool": "type_text", "field_hint": "text", "field_type": "UNKNOWN",
        "x": 100, "y": 200, "_action_id": "A-7",
    }
    planner_action = {
        "tool": "type_text", "field_hint": "email", "confidence": 0.9,
    }
    chosen, _ = select_canonical_action(graph_action, planner_action)

    assert chosen["field_hint"] == "email", "planner should correct the hint"
    assert chosen["_action_id"] == "A-7", "graph bookkeeping must survive"
    assert chosen["x"] == 100, "graph geometry must survive"


def test_a_planner_hint_does_not_override_a_confident_graph_field():
    from sudarshan_core.engines.agentic.action_dispatch import (
        select_canonical_action,
    )

    graph_action = {
        "tool": "type_text", "field_hint": "password", "field_type": "MPIN",
        "x": 1, "y": 2, "_action_id": "A-1",
    }
    planner_action = {"tool": "type_text", "field_hint": "email",
                      "confidence": 0.99}
    chosen, _ = select_canonical_action(graph_action, planner_action)
    assert chosen["field_hint"] == "password"
