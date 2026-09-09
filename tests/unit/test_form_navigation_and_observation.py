"""
SUDARSHAN - Getting off a login form, and saying what a screenshot shows.

Two symptoms, one run. On a login-gated banking sample the walk typed into the
password box, raised the soft keyboard, and then never moved again: every tap
aimed at "Login" landed on a keyboard key, the screen hash stopped changing, and
the session ended having captured three near-identical pictures of one form.
The report then described all three with the same lookup-table sentence, because
screenshot descriptions were keyed on WHY the shutter fired rather than on what
was in front of it.

Grouped in one module because they are one user-visible failure - "the analysis
never gets past the login screen and the evidence all reads the same" - and a
regression in either half brings it back.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.tool_executor import ToolExecutor  # noqa: E402


# ─── Harness ─────────────────────────────────────────────────────────────────

def _executor(keyboard: str = "unknown", package: str = "com.example.bank"):
    """
    A ToolExecutor whose ADB channel records argv and fakes an IME state.

    `keyboard` is "shown", "hidden" or "unknown" - the three answers the real
    `dumpsys input_method` probe can give, and the distinction the dismissal
    logic turns on.
    """
    calls: list[str] = []
    replies = {
        "shown": "mInputShown=true",
        "hidden": "mInputShown=false",
        "unknown": "",
    }

    async def _record(*args: str):
        line = " ".join(str(a) for a in args)
        calls.append(line)
        if "input_method" in line:
            return True, replies[keyboard]
        return True, ""

    ex = ToolExecutor(device_serial="fixture-5554", package_name=package)
    ex._adb = AsyncMock(side_effect=_record)
    return ex, calls


TARGET = "com.example.bank"

_LOGIN_XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.TextView" text="YONO SBI" clickable="false"
       bounds="[0,40][400,90]" />
 <node class="android.widget.TextView" text="Username" clickable="false"
       bounds="[0,100][400,140]" />
 <node class="android.widget.EditText" resource-id="com.example.bank:id/user"
       text="" password="false" enabled="true" bounds="[0,150][400,200]" />
 <node class="android.widget.TextView" text="Login Password" clickable="false"
       bounds="[0,220][400,260]" />
 <node class="android.widget.EditText" resource-id="com.example.bank:id/pass"
       text="" password="true" enabled="true" bounds="[0,270][400,320]" />
 <node class="android.widget.Button" text="Login" clickable="true"
       enabled="true" bounds="[0,470][400,530]" />
 <node class="android.widget.TextView" text="Forgot Password?" clickable="true"
       enabled="true" bounds="[0,560][400,600]" />
</hierarchy>"""


# ═══════════════════════════════════════════════════════════════════════════
# Part 1 - the keyboard must not be left standing in front of the form
# ═══════════════════════════════════════════════════════════════════════════

def test_typing_puts_a_visible_keyboard_away():
    """
    The IME covers the bottom of the screen, and that is where the submit
    button is. A field is not finished until the keyboard it raised is down.
    """
    ex, calls = _executor(keyboard="shown")
    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "password", "x": 10, "y": 300,
    }))
    assert result.success
    assert any("KEYCODE_BACK" in line for line in calls), (
        "a confirmed-visible keyboard must be dismissed after typing"
    )
    assert result.data["keyboard_was_visible"] is True


def test_the_dismissal_happens_after_the_text_lands():
    """Pressing BACK before the value is in would discard the value."""
    ex, calls = _executor(keyboard="shown")
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "username", "x": 10, "y": 170,
    }))
    typed_at = next(i for i, line in enumerate(calls) if "input text" in line)
    back_at = next(i for i, line in enumerate(calls) if "KEYCODE_BACK" in line)
    assert typed_at < back_at


def test_a_keyboard_that_is_already_down_is_not_pressed_back():
    """
    BACK with no IME up leaves the Activity, and on a login screen that means
    leaving the app. The dismissal is gated on the keyboard being there.
    """
    ex, calls = _executor(keyboard="hidden")
    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "username", "x": 10, "y": 170,
    }))
    assert not any("KEYCODE_BACK" in line for line in calls)
    assert result.data["keyboard_was_visible"] is False


def test_an_unreadable_ime_state_is_never_treated_as_hidden():
    """
    "Cannot tell" must mean "do not press", not "press and hope" - the failure
    mode of guessing wrong is navigating out of the app under analysis.
    """
    ex, calls = _executor(keyboard="unknown")
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "username", "x": 10, "y": 170,
    }))
    assert not any("KEYCODE_BACK" in line for line in calls)


def test_a_caller_can_opt_out_of_the_dismissal():
    ex, calls = _executor(keyboard="shown")
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "username", "x": 10, "y": 170,
        "dismiss_keyboard": False,
    }))
    assert not any("KEYCODE_BACK" in line for line in calls)
    assert not any("input_method" in line for line in calls), (
        "opting out must skip the probe too, not just the keypress"
    )


def test_the_ime_action_key_can_commit_the_form():
    ex, calls = _executor(keyboard="shown")
    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "password", "x": 10, "y": 300,
        "press_key": "enter",
    }))
    assert any("KEYCODE_ENTER" in line for line in calls)
    assert result.data["action_key"] == "KEYCODE_ENTER"


def test_next_advances_a_field_rather_than_committing():
    """
    On a multi-field form ENTER commits and TAB advances. Asking for the wrong
    one submits a half-filled form and reads back as the app refusing it.
    """
    ex, calls = _executor(keyboard="shown")
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "username", "x": 10, "y": 170,
        "press_key": "next",
    }))
    assert any("KEYCODE_TAB" in line for line in calls)
    assert not any("KEYCODE_ENTER" in line for line in calls)


def test_hide_keyboard_and_press_enter_are_real_dispatchable_tools():
    """
    `press_enter` was listed in NAVIGATIONAL_TOOLS but registered nowhere and
    implemented nowhere, so any planner that asked for it got
    "not registered in TOOL_REGISTRY".
    """
    from sudarshan_core.engines.agentic.tool_registry import TOOL_REGISTRY

    for name in ("hide_keyboard", "press_enter"):
        assert name in TOOL_REGISTRY, f"{name} missing from the registry"

    ex, calls = _executor(keyboard="shown")
    hide = asyncio.run(ex.execute({"tool": "hide_keyboard"}))
    assert hide.success and hide.error is None
    enter = asyncio.run(ex.execute({"tool": "press_enter"}))
    assert enter.success and enter.error is None
    assert any("KEYCODE_ENTER" in line for line in calls)


def test_hide_keyboard_reports_whether_it_actually_worked():
    """
    The caller needs to know whether its next tap is worth dispatching, so a
    keyboard still up after BACK is reported as such rather than as success.
    """
    ex, _ = _executor(keyboard="shown")   # the stub never stops showing it
    result = asyncio.run(ex.execute({"tool": "hide_keyboard"}))
    assert result.data["dismissed"] is False
    assert result.data["keyboard_state"] == "shown"


# ═══════════════════════════════════════════════════════════════════════════
# Part 1 - a filled form's only remaining job is to be submitted
# ═══════════════════════════════════════════════════════════════════════════

class _Obs:
    def __init__(self, xml: str, activity: str = f"{TARGET}/.LoginActivity"):
        self.ui_xml_raw = xml
        self.activity = activity
        self.screen_hash = str(abs(hash(xml)))
        self.ui_nodes = []
        self.frida_events = []


def _login_graph(semantic_type: str = "BANK_LOGIN"):
    from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
    from sudarshan_core.engines.agentic.perception import PerceptionPipeline

    pipeline = PerceptionPipeline.__new__(PerceptionPipeline)
    nodes = pipeline._parse_ui_nodes(_LOGIN_XML)

    obs = _Obs(_LOGIN_XML)
    obs.ui_nodes = nodes
    g = ExplorationGraph(package_name=TARGET)
    st = g.observe(obs, semantic_type=semantic_type, foreground_package=TARGET)
    return g, st


def _resolve(item) -> None:
    """Mark a field as filled the way record_action would."""
    item.explored = True
    item.verified = True


def test_a_login_screen_ranks_its_own_form_above_the_links_around_it():
    """
    "Forgot Password" scores comparably to a plain text box under the generic
    keyword table, so on a login screen the walk wandered off the only control
    that opens the app.
    """
    from sudarshan_core.engines.agentic.exploration_engine import (
        ActionPrioritizer,
        ApplicationProfile,
    )

    _, st = _login_graph()
    profile = ApplicationProfile()
    scores = {
        a.label: ActionPrioritizer.score_action(a, profile, "BANK_LOGIN")
        for a in st.actionable_elements
    }
    detour = next(v for k, v in scores.items() if "forgot" in k.lower())
    fields = [v for k, v in scores.items()
              if k.lower() in ("username", "login password")]
    assert fields, f"no fields found in {list(scores)}"
    assert min(fields) > detour, (
        f"a field must outrank a password-reset link: {scores}"
    )


def test_the_boost_is_confined_to_form_screens():
    """A settings list must not have its text boxes promoted over its menu."""
    from sudarshan_core.engines.agentic.exploration_engine import (
        ActionItem,
        ActionPrioritizer,
        ApplicationProfile,
    )

    field = ActionItem(action_id="A-1", node_id="n1", action_type="input",
                       label="Search")
    profile = ApplicationProfile()
    on_form = ActionPrioritizer.score_action(field, profile, "BANK_LOGIN")
    elsewhere = ActionPrioritizer.score_action(field, profile, "SETTINGS")
    assert on_form > elsewhere


def test_a_completed_form_offers_its_submit_control_next():
    """
    The half that was missing. Holding the button behind pending fields was
    already right; releasing it only returned it to plain priority order, where
    it competed with every link on the page.
    """
    g, st = _login_graph()
    for item in [a for a in st.actionable_elements if a.action_type == "input"]:
        _resolve(item)

    action = g.get_next_action(state_id=st.state_id)
    assert action is not None
    assert action["tool"] == "click_text"
    assert action["text"] == "Login", (
        f"expected the submit control, got '{action.get('text')}'"
    )


def test_the_fields_still_come_before_the_button():
    g, st = _login_graph()
    action = g.get_next_action(state_id=st.state_id)
    assert action["tool"] == "type_text"


def test_a_page_of_buttons_is_not_mistaken_for_a_completed_form():
    from sudarshan_core.engines.agentic.exploration_engine import _form_is_filled

    class _State:
        actionable_elements: list = []

    assert _form_is_filled(_State()) is False


def test_a_masked_field_counts_as_filled_once_it_has_been_typed_into():
    """
    A password box exposes neither its text nor its length, so demanding proof
    of population would hold the submit control back forever.
    """
    from sudarshan_core.engines.agentic.exploration_engine import _form_is_filled

    _, st = _login_graph()
    inputs = [a for a in st.actionable_elements if a.action_type == "input"]
    for item in inputs:
        item.explored = True          # typed into; never verified
    assert _form_is_filled(st) is True


# ═══════════════════════════════════════════════════════════════════════════
# Part 1 - the escalation ladder for a form that has stopped moving
# ═══════════════════════════════════════════════════════════════════════════

def _form(**kw):
    from sudarshan_core.engines.agentic.form_recovery import FormScreen, SubmitTarget

    base = dict(
        state_id="STATE-002",
        screen_type="BANK_LOGIN",
        input_count=2,
        unfilled_input_count=0,
        submit=SubmitTarget(label="Login", x=200, y=500, bounds="[0,470][400,530]"),
        keyboard_visible=True,
    )
    base.update(kw)
    return FormScreen(**base)


def test_the_keyboard_is_the_first_thing_tried():
    from sudarshan_core.engines.agentic.form_recovery import FormRecoveryLadder

    action = FormRecoveryLadder().plan(_form())
    assert action["tool"] == "hide_keyboard"


def test_each_rung_is_spent_once_so_a_stuck_form_cannot_absorb_the_budget():
    from sudarshan_core.engines.agentic.form_recovery import FormRecoveryLadder

    ladder = FormRecoveryLadder()
    form = _form()
    tools = []
    for _ in range(6):
        action = ladder.plan(form)
        if action is None:
            break
        tools.append(action["tool"])
    assert tools == ["hide_keyboard", "press_enter", "click_text", "scroll"]
    assert ladder.plan(form) is None, "an exhausted ladder must yield to normal selection"


def test_the_ladder_never_presses_back_at_an_unreadable_keyboard():
    from sudarshan_core.engines.agentic.form_recovery import FormRecoveryLadder

    action = FormRecoveryLadder().plan(_form(keyboard_visible=None))
    assert action["tool"] != "hide_keyboard"


def test_a_half_filled_form_is_never_committed_through_the_action_key():
    """Asking the app to validate incomplete input reads back as a refusal."""
    from sudarshan_core.engines.agentic.form_recovery import FormRecoveryLadder

    ladder = FormRecoveryLadder()
    form = _form(unfilled_input_count=1, keyboard_visible=False)
    tools = []
    while True:
        action = ladder.plan(form)
        if action is None:
            break
        tools.append(action["tool"])
    assert "press_enter" not in tools


def test_the_submit_tap_uses_the_coordinates_the_observation_gave_us():
    from sudarshan_core.engines.agentic.form_recovery import (
        FormRecoveryLadder,
        STEP_TAP_SUBMIT,
    )

    ladder = FormRecoveryLadder()
    form = _form(keyboard_visible=False, unfilled_input_count=0)
    ladder.plan(form) # consumes STEP_PRESS_ENTER
    action = ladder.plan(form)
    assert action["_recovery_step"] == STEP_TAP_SUBMIT
    assert (action["x"], action["y"]) == (200, 500)
    assert action["_geometry_trusted"] is True


def test_a_screen_with_no_fields_is_not_a_form_to_recover():
    from sudarshan_core.engines.agentic.form_recovery import FormRecoveryLadder

    assert FormRecoveryLadder().plan(_form(input_count=0)) is None


def test_a_screen_that_moved_gets_its_escapes_back():
    """
    A form revisited after a validation error is a fresh problem, not an
    already-solved one.
    """
    from sudarshan_core.engines.agentic.form_recovery import FormRecoveryLadder

    ladder = FormRecoveryLadder()
    form = _form()
    assert ladder.plan(form)["tool"] == "hide_keyboard"
    ladder.reset(form.state_id)
    assert ladder.plan(form)["tool"] == "hide_keyboard"


def test_the_submit_control_is_read_off_the_real_inventory():
    """
    Deliberately including a control already marked resolved: "tried it and
    nothing happened" is the symptom being treated, so refusing to re-offer it
    would make recovery a no-op exactly when it is needed.
    """
    from sudarshan_core.engines.agentic.form_recovery import describe_form_screen

    _, st = _login_graph()
    for item in st.actionable_elements:
        item.explored = True

    form = describe_form_screen(st, "BANK_LOGIN")
    assert form.input_count == 2
    assert form.all_inputs_filled
    assert form.submit is not None
    assert form.submit.label == "Login"


def _explorer():
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    return AgenticExplorer(
        device_serial="fixture-5554", package_name=TARGET,
        event_bus=None, screenshot_manager=None, static_findings={},
    )


class _Classification:
    def __init__(self, screen_type: str = "BANK_LOGIN"):
        self.screen_type = screen_type
        self.ownership = "TARGET_APP"


def test_the_explorer_does_nothing_until_the_screen_has_actually_stalled():
    """
    One unchanged screen is normal - typing into a field is SUPPOSED to leave
    the hash where it was. Firing the ladder on that would spend its rungs on
    every well-behaved form.
    """
    ex = _explorer()
    _, st = _login_graph()
    ex._unchanged_action_streak = 0
    assert asyncio.run(ex._form_recovery_action(st, _Classification())) is None


def test_a_stalled_form_gets_the_keyboard_taken_away():
    from sudarshan_core.engines.agentic.form_recovery import STAGNATION_THRESHOLD

    ex = _explorer()
    ex.executor.is_keyboard_visible = AsyncMock(return_value=True)
    _, st = _login_graph()
    ex._unchanged_action_streak = STAGNATION_THRESHOLD

    action = asyncio.run(ex._form_recovery_action(st, _Classification()))
    assert action is not None
    assert action["tool"] == "hide_keyboard"
    assert action["_source"] == "form_recovery"


def test_a_stalled_screen_with_no_form_is_left_to_the_normal_planners():
    """Recovery answers a form; a page of buttons has other escapes."""
    from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
    from sudarshan_core.engines.agentic.form_recovery import STAGNATION_THRESHOLD
    from sudarshan_core.engines.agentic.perception import PerceptionPipeline

    xml = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.Button" text="Accounts" clickable="true"
       bounds="[0,100][400,160]" />
</hierarchy>"""
    pipeline = PerceptionPipeline.__new__(PerceptionPipeline)
    obs = _Obs(xml)
    obs.ui_nodes = pipeline._parse_ui_nodes(xml)
    g = ExplorationGraph(package_name=TARGET)
    st = g.observe(obs, semantic_type="HOME", foreground_package=TARGET)

    ex = _explorer()
    ex.executor.is_keyboard_visible = AsyncMock(return_value=True)
    ex._unchanged_action_streak = STAGNATION_THRESHOLD
    assert asyncio.run(ex._form_recovery_action(st, _Classification("HOME"))) is None


def test_a_failing_ime_probe_costs_a_rung_not_the_run():
    from sudarshan_core.engines.agentic.form_recovery import STAGNATION_THRESHOLD

    ex = _explorer()
    ex.executor.is_keyboard_visible = AsyncMock(side_effect=RuntimeError("adb down"))
    _, st = _login_graph()
    ex._unchanged_action_streak = STAGNATION_THRESHOLD

    action = asyncio.run(ex._form_recovery_action(st, _Classification()))
    # Not hide_keyboard - an unreadable probe must never send BACK - but the
    # ladder still offers the next applicable escape.
    assert action is not None
    assert action["tool"] != "hide_keyboard"


def test_the_explorer_describes_the_screen_it_is_looking_at():
    ex = _explorer()
    obs = _Obs(_LOGIN_XML)
    result = ex._screen_observation(obs, _Classification())
    assert result is not None
    assert "Bank login screen" in result.visual_observation
    assert "Username" in result.visual_observation


def test_recovery_actions_are_allowed_past_the_stage_gate():
    """
    Gating recovery on the investigation stage would leave the walk stuck on
    exactly the form whose completion advances that stage.
    """
    import inspect

    from sudarshan_core.engines import agentic_explorer
    from sudarshan_core.engines.agentic.form_recovery import SOURCE

    source = inspect.getsource(agentic_explorer.AgenticExplorer.start)
    assert "FORM_RECOVERY_SOURCE" in source
    assert agentic_explorer.FORM_RECOVERY_SOURCE == SOURCE


# ═══════════════════════════════════════════════════════════════════════════
# Part 2 - a screenshot description must describe the screen
# ═══════════════════════════════════════════════════════════════════════════

def test_a_login_screen_is_described_by_what_is_on_it():
    from sudarshan_core.engines.agentic.ui_observation import describe_screen

    obs = describe_screen(
        activity=f"{TARGET}/com.example.bank.ui.LoginActivity",
        ui_xml=_LOGIN_XML,
        screen_type="BANK_LOGIN",
        keyboard_visible=True,
    )
    text = obs.visual_observation
    assert "Bank login screen" in text
    assert "LoginActivity" in text
    assert "Username" in text and "Login Password" in text
    assert "Login" in text
    assert "YONO SBI" in text
    assert "keyboard" in text.lower()
    assert obs.input_count == 2
    assert obs.password_input_count == 1


def test_the_description_is_not_the_capture_reason():
    """
    The defect: every frame in the appendix read "Lifecycle capture -
    01_app_opened" or "Application UI state observed immediately before session
    end", neither of which describes a picture.
    """
    from sudarshan_core.engines.agentic.ui_observation import describe_screen

    obs = describe_screen(
        activity=f"{TARGET}/.LoginActivity",
        ui_xml=_LOGIN_XML,
        screen_type="BANK_LOGIN",
    )
    for template in (
        "Lifecycle capture",
        "session end",
        "insufficient corroborating",
        "Initial application UI observed after launch",
    ):
        assert template.lower() not in obs.visual_observation.lower()


def test_two_different_screens_get_two_different_descriptions():
    from sudarshan_core.engines.agentic.ui_observation import describe_screen

    home_xml = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.TextView" text="Accounts" clickable="true"
       bounds="[0,100][400,160]" />
 <node class="android.widget.TextView" text="Transfer" clickable="true"
       bounds="[0,180][400,240]" />
</hierarchy>"""
    login = describe_screen(activity=f"{TARGET}/.LoginActivity",
                            ui_xml=_LOGIN_XML, screen_type="BANK_LOGIN")
    home = describe_screen(activity=f"{TARGET}/.HomeActivity",
                           ui_xml=home_xml, screen_type="HOME")
    assert login.visual_observation != home.visual_observation
    assert "Accounts" in home.visual_observation


def test_a_frame_with_no_hierarchy_says_so_rather_than_inventing_one():
    from sudarshan_core.engines.agentic.ui_observation import describe_screen

    obs = describe_screen(activity=f"{TARGET}/.MainActivity", screen_type="UNKNOWN")
    assert "MainActivity" in obs.visual_observation
    assert "not captured" in obs.visual_observation
    assert obs.input_count == 0


def test_a_malformed_dump_degrades_instead_of_raising():
    from sudarshan_core.engines.agentic.ui_observation import describe_screen

    obs = describe_screen(activity="a/b", ui_xml="<hierarchy><node", screen_type="")
    assert obs.visual_observation


def test_masked_contents_are_never_used_as_a_field_name():
    """`..........` is what was typed, not what the field is asking for."""
    from sudarshan_core.engines.agentic.ui_observation import describe_screen

    xml = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.widget.EditText" text="........." password="true"
       bounds="[0,270][400,320]" />
</hierarchy>"""
    obs = describe_screen(activity="a/b.C", ui_xml=xml, screen_type="BANK_LOGIN")
    assert "........." not in obs.visual_observation


def test_the_manager_records_what_the_caller_observed():
    from sudarshan_core.engines.agentic.ui_observation import describe_screen
    from sudarshan_core.engines.screenshot_manager import resolve_screen_observation

    observed = describe_screen(activity=f"{TARGET}/.LoginActivity",
                               ui_xml=_LOGIN_XML, screen_type="BANK_LOGIN")
    out = resolve_screen_observation(
        screen_observation=observed, reason="LIFECYCLE", label="01_app_opened",
    )
    assert out["visual_observation"] == observed.visual_observation
    assert out["observation_source"] == "ui_xml"


def test_the_manager_falls_back_to_the_raw_dump_then_to_metadata():
    from sudarshan_core.engines.screenshot_manager import resolve_screen_observation

    from_xml = resolve_screen_observation(
        ui_xml=_LOGIN_XML, activity=f"{TARGET}/.LoginActivity",
        semantic_type="BANK_LOGIN", reason="LIFECYCLE",
    )
    assert "Username" in from_xml["visual_observation"]

    from_meta = resolve_screen_observation(
        activity=f"{TARGET}/.LoginActivity", semantic_type="BANK_LOGIN",
        reason="LIFECYCLE", label="01_app_opened",
    )
    assert from_meta["observation_source"] == "metadata"
    assert "Bank login screen" in from_meta["visual_observation"]
    assert from_meta["visual_observation"], "metadata must still yield a sentence"


# ═══════════════════════════════════════════════════════════════════════════
# Part 2 - the linker must not make one sentence do two jobs
# ═══════════════════════════════════════════════════════════════════════════

def _artifact_with_shot(tmp_path: Path, **shot) -> Path:
    shots = tmp_path / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    png = shots / "001.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 32)
    entry = {
        "screenshot_id": "SCR-001",
        "filename": "screenshots/001.png",
        "timestamp_ms": 5_000,
        "label": "state_state-002_bank_login",
        "reason": "SUSPICIOUS_UI",
        "source": "explorer",
        "screen_hash": "h1",
        "activity": f"{TARGET}/.LoginActivity",
    }
    entry.update(shot)
    (shots / "manifest.json").write_text(
        json.dumps({"screenshots": [entry]}), encoding="utf-8",
    )
    (tmp_path / "evidence.json").write_text(
        json.dumps({"records": []}), encoding="utf-8",
    )
    return tmp_path


def test_the_recorded_observation_reaches_the_visual_evidence_record(tmp_path):
    from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker

    observation = (
        "Bank login screen (LoginActivity) showing 2 input fields "
        "(Username, Login Password) and 1 action control (Login)."
    )
    artifact = _artifact_with_shot(
        tmp_path, visual_observation=observation,
        screen_summary="Bank login screen (LoginActivity)",
    )
    rec = VisualEvidenceLinker(artifact).link()[0]
    assert rec.visual_observation == observation
    assert rec.screen_summary == "Bank login screen (LoginActivity)"


def test_an_uncorroborated_frame_still_describes_its_screen(tmp_path):
    """
    With no hook to correlate, the claim degrades to "insufficient
    corroborating runtime evidence...". That is a statement about the ANALYSIS.
    The observation must remain a statement about the SCREEN.
    """
    from sudarshan_core.visual_evidence.constants import CLAIM_INCONCLUSIVE_VISUAL
    from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker

    artifact = _artifact_with_shot(tmp_path, semantic_type="BANK_LOGIN")
    rec = VisualEvidenceLinker(artifact).link()[0]

    assert rec.claim_type == CLAIM_INCONCLUSIVE_VISUAL
    assert rec.visual_observation
    assert rec.visual_observation != rec.investigative_claim
    assert "insufficient corroborating" not in rec.visual_observation.lower()
    assert "Bank login screen" in rec.visual_observation


def test_the_corroboration_line_is_about_runtime_evidence_not_the_picture(tmp_path):
    """
    The modal printed `visual_observation` under "Why it matters" whenever
    corroboration was empty. Filling it with an honest statement about the
    absence of hooks removes the duplication at the source.
    """
    from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker

    artifact = _artifact_with_shot(tmp_path, semantic_type="BANK_LOGIN")
    rec = VisualEvidenceLinker(artifact).link()[0]

    assert rec.corroboration_summary
    assert rec.corroboration_summary != rec.visual_observation
    assert "no runtime hook" in rec.corroboration_summary.lower()


def test_a_lifecycle_frame_is_described_by_its_screen_not_its_label(tmp_path):
    from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker

    artifact = _artifact_with_shot(
        tmp_path, label="99_final_screen", reason="LIFECYCLE",
        semantic_type="BANK_LOGIN",
    )
    rec = VisualEvidenceLinker(artifact).link()[0]
    assert "Bank login screen" in rec.visual_observation
    assert rec.visual_observation != rec.investigative_claim


def test_the_record_round_trips_through_json(tmp_path):
    from sudarshan_core.visual_evidence.models import VisualEvidenceRecord

    rec = VisualEvidenceRecord(
        screenshot_id="SCR-001", filename="a.png", png_sha256="x",
        timestamp_ms=1, capture_trigger="LIFECYCLE", claim_type="c",
        investigative_claim="claim", quality="A", report_tier="t",
        correlation_status="unresolved",
        visual_observation="Bank login screen (LoginActivity)",
        screen_summary="Bank login screen (LoginActivity)",
    )
    back = VisualEvidenceRecord.from_dict(json.loads(json.dumps(rec.to_dict())))
    assert back.visual_observation == rec.visual_observation
    assert back.screen_summary == rec.screen_summary


def test_the_api_keeps_the_observation_and_the_claim_apart():
    from sudarshan_core.visual_evidence.api_merge import merge_entry_with_visual_evidence

    merged = merge_entry_with_visual_evidence(
        {"screenshot_id": "SCR-001", "filename": "screenshots/001.png",
         "reason": "SUSPICIOUS_UI"},
        {
            "screenshot_id": "SCR-001",
            "investigative_claim": "Visual capture completed but insufficient "
                                   "corroborating runtime evidence was available.",
            "visual_observation": "Bank login screen (LoginActivity) showing 2 "
                                  "input fields (Username, Login Password).",
            "screen_summary": "Bank login screen (LoginActivity)",
            "corroboration_summary": "No runtime hook fired while this screen "
                                     "was displayed.",
        },
        sha256="abc",
    )
    ve = merged["visual_evidence"]
    assert ve["visual_observation"] != ve["investigative_claim"]
    assert ve["corroboration_summary"] != ve["visual_observation"]
    assert merged["visual_observation"] == ve["visual_observation"]
    assert merged["screen_summary"] == "Bank login screen (LoginActivity)"


def test_a_manifest_row_without_a_visual_evidence_record_is_unchanged():
    from sudarshan_core.visual_evidence.api_merge import merge_entry_with_visual_evidence

    merged = merge_entry_with_visual_evidence(
        {"screenshot_id": "SCR-001", "filename": "screenshots/001.png"},
        None, sha256="abc",
    )
    assert merged["visual_evidence"] is None
