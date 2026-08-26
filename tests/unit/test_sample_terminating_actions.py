"""
The explorer must never tap a control that kills the app it is analysing.

Measured on a live e-challan run. The emulator ANR'd shortly after Frida
deoptimized the boot image, so Android put up its own dialog:

    RTO eChallan isn't responding
    [ Close app ]  [ Wait ]

"Close app" is a CANCEL, worth -20 in `ActionPrioritizer` - a penalty, not a
veto. The explorer tried "Wait" (INCONCLUSIVE), then the dialog's message text
(INCONCLUSIVE), and then "Close app" was simply the highest-ranked action left
on the screen, so it clicked it. The process under analysis died with the
four-field form half filled; the remaining budget was spent on a dead app and
every runtime hook went silent.

A score penalty only postpones that. This is a hard block.
"""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.semantic_action import (  # noqa: E402
    is_anr_wait_control,
    terminates_sample,
)


@pytest.mark.parametrize("label", [
    "Close app",
    "CLOSE APP",
    "close app",
    " Close app ",
    "Force stop",
    "Force Stop",
    "Force close",
    "Uninstall",
    "Clear data",
    "Clear storage",
    "Clear cache",
    "App info",
    "Quit",
])
def test_a_control_that_ends_the_sample_is_recognised(label):
    assert terminates_sample(label) is True


@pytest.mark.parametrize("label", [
    "Wait",
    "Get Details",
    "Login",
    "Submit",
    "Cancel",
    "Close",          # closing a dialog is not closing the app
    "Dismiss",
    "Back",
    "OK",
    "Continue",
    "",
])
def test_an_ordinary_control_is_not_treated_as_terminating(label):
    """
    The guard has to stay narrow. Blocking every "close"-ish label would strand
    the walk inside any dialog it opened - "Close" dismisses a sheet, and
    "Cancel" is a legitimate way forward when nothing else on a screen is
    actionable.
    """
    assert terminates_sample(label) is False


def test_the_anr_keep_alive_control_is_identifiable():
    assert is_anr_wait_control("Wait") is True
    assert is_anr_wait_control("Close app") is False


def test_the_exploration_graph_blocks_a_terminating_control():
    """
    The block lives on the path that actually selected it.

    `AgentPlanner` already refused these via its own `destructive_keywords`,
    but the live run selected "Close app" with `source=exploration_graph` -
    a different code path, which had no such guard.
    """
    from sudarshan_core.engines.agentic.exploration_engine import _terminates_sample

    assert _terminates_sample("Close app") is True
    assert _terminates_sample("Wait") is False


# ─── The dialog itself has to be recognised ──────────────────────────────────
#
# Blocking "Close app" is only half the fix. `resolve_screen_ownership` reads
# the ACTIVITY name and `CRASH_ACTIVITY_MARKERS` are activity names, but modern
# Android draws "<app> isn't responding" OVER the app's own activity - the
# foreground package is still the target and no marker matches. The dialog was
# therefore admitted as an ordinary explorable state, and with its one useful
# control blocked the walk span on it for 51 iterations, the whole remaining
# budget. Detection is on the framework's text.

class _Node:
    def __init__(self, text=""):
        self.text = text
        self.desc = ""
        self.content_desc = ""


def _classify(nodes, activity="com.tjmonh.android/.MainActivity",
              package="com.tjmonh.android"):
    from sudarshan_core.engines.agentic.screen_classifier import (
        classify_screen_with_ownership,
    )
    return classify_screen_with_ownership(
        activity, nodes, "", package, package,
    )


def test_an_anr_dialog_over_the_apps_own_activity_is_detected():
    from sudarshan_core.engines.agentic.screen_classifier import ScreenType

    result = _classify([
        _Node("RTO eChallan isn't responding"), _Node("Close app"), _Node("Wait"),
    ])
    assert result.screen_type == ScreenType.APP_NOT_RESPONDING


def test_a_keeps_stopping_dialog_is_detected_as_a_crash():
    from sudarshan_core.engines.agentic.screen_classifier import ScreenType

    result = _classify([
        _Node("Bank App keeps stopping"), _Node("Close app"), _Node("Open app again"),
    ])
    assert result.screen_type == ScreenType.CRASH_STATE


def test_an_apps_own_error_copy_is_not_mistaken_for_the_system_dialog():
    """
    The message alone is too weak a signal - apps write "not responding" in
    their own error text, and a form wrongly classified as a crash would end
    the branch that was about to produce the evidence.
    """
    from sudarshan_core.engines.agentic.screen_classifier import ScreenType

    result = _classify([
        _Node("The server is not responding, please try again"), _Node("Retry"),
    ])
    assert result.screen_type != ScreenType.APP_NOT_RESPONDING
    assert result.screen_type != ScreenType.CRASH_STATE


def test_a_bare_wait_button_is_not_a_crash_dialog():
    """"Wait" is an ordinary word; both halves are required."""
    from sudarshan_core.engines.agentic.screen_classifier import ScreenType

    result = _classify([_Node("Please wait"), _Node("Wait")])
    assert result.screen_type != ScreenType.APP_NOT_RESPONDING
