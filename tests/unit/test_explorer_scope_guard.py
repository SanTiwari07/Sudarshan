"""
Keeping the agent inside the app it is analysing.

The regression these cover: on InsecureBankv2 the agent tapped through to the
system Contacts app and spent 12 of its 16 actions there pressing back, so the
sample's own login screen was never exercised and the report's screenshots were
of AOSP rather than of the sample.

The guard has to let the agent leave for permission dialogs and Settings -
granting Accessibility is one of the fraud goals and lives in
com.android.settings - while pulling it back from anywhere else.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.perception import (  # noqa: E402
    INVESTIGATION_SCOPE_PACKAGES,
    in_investigation_scope,
    package_of,
)
from sudarshan_core.engines.agentic.tool_executor import NAVIGATIONAL_TOOLS  # noqa: E402

TARGET = "com.android.insecurebankv2"


# ── in_investigation_scope ────────────────────────────────────────────────────

def test_the_sample_itself_is_in_scope():
    assert in_investigation_scope(TARGET, TARGET) is True


@pytest.mark.parametrize("pkg", sorted(INVESTIGATION_SCOPE_PACKAGES))
def test_system_surfaces_the_investigation_needs_are_in_scope(pkg):
    """Permission dialogs, Settings and the installer are legitimate targets."""
    assert in_investigation_scope(pkg, TARGET) is True


def test_settings_stays_in_scope_so_the_accessibility_goal_is_reachable():
    """Bouncing off com.android.settings would make that fraud goal impossible."""
    assert in_investigation_scope("com.android.settings", TARGET) is True


@pytest.mark.parametrize("pkg", [
    "com.android.contacts",
    "com.google.android.contacts",
    "com.google.android.dialer",
    "com.android.chrome",
    "com.android.vending",
    "com.google.android.apps.nexuslauncher",
    "com.google.android.gm",
])
def test_unrelated_apps_are_out_of_scope(pkg):
    assert in_investigation_scope(pkg, TARGET) is False


def test_an_unreadable_foreground_is_not_treated_as_out_of_scope():
    """
    A malformed uiautomator dump mid-transition yields "". That is the absence
    of a reading, not evidence the agent wandered off - firing a recovery action
    on it would spend budget on noise.
    """
    assert in_investigation_scope("", TARGET) is True


def test_an_unknown_target_cannot_put_anything_out_of_scope():
    assert in_investigation_scope("com.android.contacts", "") is True


def test_a_package_that_merely_shares_a_prefix_is_out_of_scope():
    """Substring matching would wrongly admit look-alike package names."""
    assert in_investigation_scope("com.android.settings.evil", TARGET) is False
    assert in_investigation_scope(TARGET + ".attacker", TARGET) is False


def test_scope_check_composes_with_package_of():
    assert in_investigation_scope(
        package_of(f"{TARGET}/.LoginActivity"), TARGET
    ) is True
    assert in_investigation_scope(
        package_of("com.google.android.dialer/.DialtactsActivity"), TARGET
    ) is False


# ── the relaunch tool actually exists ─────────────────────────────────────────

def test_the_relaunch_tool_is_treated_as_navigational():
    """
    Recovery relaunches must wait for the window to settle.

    "am_start" was listed here but no such tool exists in TOOL_REGISTRY or on
    ToolExecutor, so every relaunch silently failed and never waited.
    """
    assert "start_activity" in NAVIGATIONAL_TOOLS
    assert "am_start" not in NAVIGATIONAL_TOOLS


def test_start_activity_is_a_real_registered_tool():
    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor
    from sudarshan_core.engines.agentic.tool_registry import get_tool

    assert get_tool("start_activity") is not None
    assert hasattr(ToolExecutor, "_tool_start_activity")
    # The name the recovery paths used to pass resolves to nothing.
    assert get_tool("am_start") is None


# ── _launch_component ─────────────────────────────────────────────────────────

def _explorer(package: str, main_activity):
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    return AgenticExplorer(
        device_serial="test-device",
        package_name=package,
        main_activity=main_activity,
    )


def test_bare_activity_class_is_qualified_with_the_package():
    """androguard returns a bare class name; `am start -n` needs a component."""
    exp = _explorer(TARGET, f"{TARGET}.LoginActivity")
    assert exp._launch_component() == f"{TARGET}/{TARGET}.LoginActivity"


def test_an_already_qualified_component_is_passed_through():
    """`cmd package resolve-activity` returns the full component already."""
    exp = _explorer(TARGET, f"{TARGET}/.LoginActivity")
    assert exp._launch_component() == f"{TARGET}/.LoginActivity"


@pytest.mark.parametrize("activity", [None, "", "   "])
def test_no_main_activity_yields_no_component(activity):
    """Callers fall back to press_home rather than `am start` with no target."""
    assert _explorer(TARGET, activity)._launch_component() == ""


def test_no_package_yields_no_component_for_a_bare_class():
    assert _explorer("", "SomeActivity")._launch_component() == ""


def test_main_activity_defaults_to_empty_rather_than_being_absent():
    """
    It used to be read but never assigned, so the crash-recovery path raised
    AttributeError into its own `except Exception` and did nothing.
    """
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    exp = AgenticExplorer(device_serial="test-device", package_name=TARGET)
    assert exp.main_activity == ""
    assert exp._launch_component() == ""


# ── remembering which control leads out of the app ────────────────────────────

def _memory_on_screen(screen_hash: str = "screen-a"):
    from sudarshan_core.engines.agentic.agent_memory import AgentMemory

    mem = AgentMemory()
    mem.current_screen_hash = screen_hash
    return mem


def test_an_escaping_action_is_remembered_for_the_screen_it_was_taken_from():
    mem = _memory_on_screen()
    assert mem.is_escaping_action("click_text", "Phone") is False
    mem.record_escaping_action("click_text", "Phone")
    assert mem.is_escaping_action("click_text", "Phone") is True


def test_the_same_control_on_a_different_screen_is_still_allowed():
    """A "Phone" button elsewhere in the app may do something different."""
    mem = _memory_on_screen("screen-a")
    mem.record_escaping_action("click_text", "Phone")
    mem.current_screen_hash = "screen-b"
    assert mem.is_escaping_action("click_text", "Phone") is False


def test_other_controls_on_the_same_screen_are_unaffected():
    mem = _memory_on_screen()
    mem.record_escaping_action("click_text", "Phone")
    assert mem.is_escaping_action("click_text", "Login") is False
    assert mem.is_escaping_action("tap", "Phone") is False


def test_recording_is_idempotent():
    mem = _memory_on_screen()
    mem.record_escaping_action("click_text", "Phone")
    mem.record_escaping_action("click_text", "Phone")
    assert len(mem._escaping_actions) == 1


def test_an_empty_tool_is_not_recorded():
    """Nothing was executed, so there is no control to blame."""
    mem = _memory_on_screen()
    mem.record_escaping_action("", "Phone")
    assert mem._escaping_actions == set()


def test_a_missing_target_is_normalised_rather_than_dropped():
    """A coordinate tap has no text; it still has to be recordable."""
    mem = _memory_on_screen()
    mem.record_escaping_action("tap", "")
    assert mem.is_escaping_action("tap", "") is True
    assert mem.is_escaping_action("tap", None) is True


def test_a_fresh_memory_blames_nothing():
    assert _memory_on_screen()._escaping_actions == set()


# ── self-hiding malware must not end the investigation ───────────────────────

def test_unrecoverable_navigation_does_not_break_the_loop():
    """
    Measured on Cerberus: it backgrounds itself and disables its launcher
    activity, so every relaunch returned "Activity class ... does not exist".
    Six failed recoveries then TERMINATED the run at 6 actions and 4 evidence
    records - while the trojan was still instrumented and still firing hooks.

    A backgrounded process is not a finished one, and self-hiding is the
    behaviour we are there to observe. The loop must stop navigating and keep
    observing.
    """
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    start = source.index("out_of_scope_streak > MAX_OUT_OF_SCOPE_RECOVERIES")
    branch = source[start:start + 3200]
    # The branch must continue the loop, not break out of it.
    assert "continue" in branch
    assert "navigation_abandoned" in branch


def test_the_abandonment_is_announced_as_a_finding():
    """Self-hiding is evidence, so the run must say so rather than go quiet."""
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    assert "self-hiding is itself a finding" in source
    assert "out_of_scope_unrecoverable" in source


# ── early self-hiding detection ──────────────────────────────────────────────

class _Result:
    def __init__(self, output="", error=None, success=True):
        self.output = output
        self.error = error
        self.success = success


def test_a_missing_launcher_component_is_recognised():
    """
    Cerberus disables its own launcher activity. `am` exits 0 and prints the
    failure to stdout, so the exit code cannot be trusted here.
    """
    from sudarshan_core.engines.agentic_explorer import _launcher_component_missing

    real = ("Error: Activity class {com.x/com.x.OzGUhRlf} does not exist.")
    assert _launcher_component_missing(_Result(output=real)) is True


@pytest.mark.parametrize("text", [
    "Error: Activity class {a/b} does not exist.",
    "Error type 3\nError: Unable to resolve Intent",
])
def test_every_missing_component_phrasing_is_matched(text):
    from sudarshan_core.engines.agentic_explorer import _launcher_component_missing

    assert _launcher_component_missing(_Result(output=text)) is True


def test_a_successful_relaunch_is_not_self_hiding():
    from sudarshan_core.engines.agentic_explorer import _launcher_component_missing

    assert _launcher_component_missing(
        _Result(output="Starting: Intent { cmp=com.x/.Main }")
    ) is False


def test_an_empty_or_absent_result_is_not_conclusive():
    """Silence is not evidence that the component is gone."""
    from sudarshan_core.engines.agentic_explorer import _launcher_component_missing

    assert _launcher_component_missing(None) is False
    assert _launcher_component_missing(_Result()) is False
    assert _launcher_component_missing(_Result(output="   ")) is False


def test_the_error_field_is_checked_as_well_as_output():
    from sudarshan_core.engines.agentic_explorer import _launcher_component_missing

    assert _launcher_component_missing(
        _Result(error="Activity class does not exist")
    ) is True


def test_detection_happens_on_the_first_conclusive_failure():
    """
    Six attempts at an activity Android says does not exist WERE the run:
    measured on Cerberus at 6 actions, 0 screens, 4 evidence records.
    """
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    assert "_launcher_component_missing(recovery_result)" in source
    assert "self_hiding_detected" in source


def test_the_plan_keeps_walking_once_navigation_is_abandoned():
    """
    A stage procedure such as the accessibility grant works through Settings and
    does not need the sample in the foreground, so a self-hiding app must not
    freeze the investigation in whatever stage it happened to reach.
    """
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    start = source.index("No recovery action - but the plan keeps moving")
    branch = source[start:start + 900]
    assert "should_advance()" in branch
    assert "_run_stage_procedure()" in branch


def test_abandoning_navigation_actually_stops_the_retries():
    """
    Detecting the missing component set `navigation_abandoned` but the guard
    still keyed off the streak counter alone, so it announced "cannot be
    relaunched" and then tried again anyway - once per iteration until the cap.
    """
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    start = source.index("if (\n                        navigation_abandoned")
    condition = source[start:start + 200]
    assert "navigation_abandoned" in condition
    assert "MAX_OUT_OF_SCOPE_RECOVERIES" in condition
