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


# ─── F6: a validation error must not fork the screen ─────────────────────────

from sudarshan_core.engines.agentic.exploration_engine import (  # noqa: E402
    compute_composite_state_signature,
)


def _nodes(xml: str):
    from sudarshan_core.engines.agentic.perception import PerceptionPipeline

    return PerceptionPipeline.__new__(PerceptionPipeline)._parse_ui_nodes(xml)


def _sig(xml: str) -> str:
    return compute_composite_state_signature(
        f"{TARGET}/.FormActivity", TARGET, _nodes(xml),
    )[0]


#: A form row that is itself clickable - a Material card, a RecyclerView row.
#: This is the ONLY shape in which validation text reaches the state signature:
#: the parser emits a non-clickable TextView only when it can be recovered
#: through a clickable ancestor smaller than a full screen. A bare
#: `textinput_error` slot on a plain layout never enters `ui_nodes` at all and
#: could never have forked anything.
def _card_form(error: str = "") -> str:
    error_node = (
        f'<node class="android.widget.TextView" text="{error}"\n'
        f'        resource-id="com.example.form:id/textinput_error"\n'
        f'        clickable="false" bounds="[10,205][390,225]" />'
        if error else ""
    )
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.LinearLayout" clickable="true"
       bounds="[0,90][400,240]">
  <node class="android.widget.TextView" text="Email" clickable="false"
        bounds="[10,95][390,135]" />
  <node class="android.widget.EditText" resource-id="com.example.form:id/email"
        text="" password="false" enabled="true" bounds="[10,150][390,200]" />
  {error_node}
 </node>
</hierarchy>"""


def test_an_inline_validation_error_does_not_fork_the_state():
    """
    The ping-pong: inside a clickable row the error text IS recovered into the
    node list, so the screen hashed differently and the same form became two
    states, each holding its own unexplored copy of the same fields. Filling
    them cleared the error, the hash returned to the first state whose fields
    were also still unexplored, and the walk refilled until it gave up.
    """
    clean = _card_form()
    dirty = _card_form("Please enter a valid email")
    assert any(n.text == "Please enter a valid email" for n in _nodes(dirty)), (
        "fixture must actually put the error into the node list"
    )
    assert _sig(clean) == _sig(dirty)


@pytest.mark.parametrize("message", [
    "Please enter a valid email",
    "This field is required",
    "Mobile number cannot be empty",
    "Invalid phone number",
])
def test_common_validation_phrasings_are_all_treated_as_volatile(message):
    assert _sig(_card_form(message)) == _sig(_card_form()), message


def test_a_real_label_change_still_forks_the_state():
    """
    The rule must stay narrow. "Sign in" becoming "Welcome back" is a genuine
    transition and collapsing it would hide screens from the walk.
    """
    a = _card_form().replace("Email", "Sign in")
    b = _card_form().replace("Email", "Welcome back")
    assert _sig(a) != _sig(b)


def test_error_shaped_text_on_a_screen_with_no_inputs_still_counts():
    """
    Conservative by construction: validation feedback only exists next to a
    field, so a screen with nothing to fill keeps every node it has.
    """
    clean = _card_form().replace(
        '<node class="android.widget.EditText" '
        'resource-id="com.example.form:id/email"\n'
        '        text="" password="false" enabled="true" '
        'bounds="[10,150][390,200]" />', "")
    dirty = clean.replace(
        '</node>',
        '<node class="android.widget.TextView" text="This field is required"\n'
        '        clickable="false" bounds="[10,205][390,225]" /></node>')
    assert not any(n.is_input for n in _nodes(clean)), "fixture must have no inputs"
    assert _sig(clean) != _sig(dirty)


def test_the_signature_has_no_dead_parameter():
    """`visible_text` was accepted and never read. It is gone, not ignored."""
    import inspect

    params = inspect.signature(compute_composite_state_signature).parameters
    assert "visible_text" not in params


# ─── F8: fields before the button, whatever the button is called ─────────────

_SIGNUP_XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.TextView" text="Full Name" clickable="false"
       bounds="[0,100][400,140]" />
 <node class="android.widget.EditText" resource-id="com.example.form:id/name"
       text="" password="false" enabled="true" bounds="[0,150][400,200]" />
 <node class="android.widget.TextView" text="Email" clickable="false"
       bounds="[0,220][400,260]" />
 <node class="android.widget.EditText" resource-id="com.example.form:id/email"
       text="" password="false" enabled="true" bounds="[0,270][400,320]" />
 <node class="android.widget.TextView" text="Mobile Number" clickable="false"
       bounds="[0,340][400,380]" />
 <node class="android.widget.EditText" resource-id="com.example.form:id/phone"
       text="" password="false" enabled="true" bounds="[0,390][400,440]" />
 <node class="android.widget.Button" text="REGISTER" clickable="true"
       enabled="true" bounds="[0,470][400,530]" />
</hierarchy>"""


def _signup_graph():
    g = ExplorationGraph(package_name=TARGET)
    st = g.observe(_Obs(_SIGNUP_XML), semantic_type="UNKNOWN",
                   foreground_package=TARGET)
    return g, st


def test_inputs_rank_first_even_when_the_button_is_not_a_known_submit():
    """
    The reorder used to happen only when a submit control was RECOGNISED, and
    "REGISTER" is deliberately not one. So on a signup form no ordering was
    applied at all and the button - which outscores a plain field - went first,
    submitting an empty form.
    """
    g, st = _signup_graph()
    action = g.get_next_action(state_id=st.state_id)
    assert action["tool"] == "type_text", (
        f"expected a field first, got {action['tool']} '{action.get('text')}'"
    )


def test_the_commit_control_is_offered_once_the_fields_are_filled():
    g, st = _signup_graph()
    for item in [a for a in st.actionable_elements if a.action_type == "input"]:
        _record(g, st, item, input_verified=True)

    action = g.get_next_action(state_id=st.state_id)
    assert action["tool"] == "click_text"
    assert action["text"] == "REGISTER"


def test_register_is_held_behind_pending_inputs():
    """Ordering must treat it as a commit even though submit detection does not."""
    from sudarshan_core.engines.agentic.exploration_engine import (
        _is_form_commit_action,
    )

    g, st = _signup_graph()
    button = next(a for a in st.actionable_elements if a.action_type == "click")
    assert _is_form_commit_action(button)


@pytest.mark.parametrize("label", [
    "REGISTER", "Sign Up", "Create Account", "Sign up now", "Create an account",
])
def test_signup_captions_are_recognised_as_form_commits(label):
    from sudarshan_core.engines.agentic.exploration_engine import (
        ActionItem,
        _is_form_commit_action,
    )

    item = ActionItem(action_id="A-1", node_id="n1", action_type="click",
                      label=label)
    assert _is_form_commit_action(item), label


def test_register_is_still_not_a_credential_submit():
    """
    Preserved on purpose. On a login screen "Register" opens a different flow,
    and treating it as a submit made the walk spend its credential-retry budget
    on a navigation link. Ordering and login-outcome detection are separate
    questions and only the first one changed.
    """
    from sudarshan_core.engines.agentic.exploration_engine import (
        _is_submit_label,
    )

    assert not _is_submit_label("Register")
    assert not _is_submit_label("Sign Up")
    assert not _is_submit_label("Create Account")
    assert _is_submit_label("Login")
    assert _is_submit_label("Continue")


def test_a_question_is_never_a_form_commit():
    """"New user? Register" is a prompt, not a button that commits the form."""
    from sudarshan_core.engines.agentic.exploration_engine import (
        ActionItem,
        _is_form_commit_action,
    )

    item = ActionItem(action_id="A-1", node_id="n1", action_type="click",
                      label="New user? Register")
    assert not _is_form_commit_action(item)


# ─── F5: a data-entry form is a kind of screen ───────────────────────────────

from sudarshan_core.engines.agentic.screen_classifier import (  # noqa: E402
    ScreenType,
    classify_screen,
    is_explorable_screen_type,
    should_invoke_planner,
)


def _classify(xml: str, activity: str = f"{TARGET}/.RegisterActivity"):
    return classify_screen(activity, _nodes(xml), package_name=TARGET)


def test_a_multi_field_form_is_named_as_one():
    """
    A registration / KYC / personal-details screen used to fall through to
    UNKNOWN, so nothing downstream could model "a form that must be completed
    before it means anything".
    """
    result = _classify(_SIGNUP_XML)
    assert result.screen_type == ScreenType.DATA_ENTRY_FORM


def test_a_form_screen_is_explorable_and_worth_planning_for():
    assert is_explorable_screen_type(ScreenType.DATA_ENTRY_FORM)
    assert should_invoke_planner(ScreenType.DATA_ENTRY_FORM)


def test_a_login_screen_is_still_a_login_screen():
    """The new type must not steal the screens that already had a name."""
    login = _FORM_XML.replace("Full Name", "User ID").replace("Email", "Password")
    assert _classify(login, f"{TARGET}/.LoginActivity").screen_type == (
        ScreenType.BANK_LOGIN
    )


def test_an_otp_screen_is_still_an_otp_screen():
    """
    Signalled through the activity name, because plain TextView captions never
    reach classify_screen - the parser only emits interactive nodes, so a
    caption is consumed as a field label and is not in `ui_nodes` at all.
    """
    assert _classify(_SIGNUP_XML, f"{TARGET}/.OtpActivity").screen_type == (
        ScreenType.OTP_SCREEN
    )


def test_a_settings_screen_with_fields_is_still_settings():
    """Host and port boxes on a debug screen are not a registration form."""
    cfg = _FORM_XML.replace("Full Name", "Server IP").replace("Email", "Port")
    assert _classify(cfg, f"{TARGET}/.SettingsActivity").screen_type == (
        ScreenType.SETTINGS
    )


def test_a_single_field_screen_is_not_a_form():
    """One box is a search or a filter, not a form."""
    one = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.EditText" resource-id="com.example.form:id/q"
       text="" enabled="true" bounds="[0,10][400,60]" />
</hierarchy>"""
    assert _classify(one, f"{TARGET}/.SearchActivity").screen_type != (
        ScreenType.DATA_ENTRY_FORM
    )


def test_a_form_screen_does_not_become_an_authentication_state():
    """It is data entry, not auth. AuthState must stay where it was."""
    from sudarshan_core.engines.agentic.auth_state import (
        AuthState,
        AuthStateMachine,
    )

    m = AuthStateMachine()
    m.on_screen(screen_type=ScreenType.DATA_ENTRY_FORM,
                required_fields={"FULL_NAME", "EMAIL", "PHONE"})
    assert m.state is AuthState.UNKNOWN


def test_a_form_commit_is_held_until_the_form_is_complete():
    """
    The precondition, on the screen type that exists for it. Satisfied by the
    unconditional ordering from F8 rather than by a second rule keyed on the
    type - asserted here so the guarantee is pinned to DATA_ENTRY_FORM too.
    """
    g, st = _signup_graph()
    inputs = [a for a in st.actionable_elements if a.action_type == "input"]

    for remaining in range(len(inputs), 0, -1):
        action = g.get_next_action(state_id=st.state_id)
        assert action["tool"] == "type_text", (
            f"{remaining} field(s) unfilled but the walk chose "
            f"{action['tool']} '{action.get('text')}'"
        )
        item = next(a for a in inputs if a.action_id == action["_action_id"])
        _record(g, st, item, input_verified=True)

    assert g.get_next_action(state_id=st.state_id)["text"] == "REGISTER"
