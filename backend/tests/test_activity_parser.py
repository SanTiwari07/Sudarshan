"""
Regression tests for foreground-activity parsing.

Before the fix, `topResumedActivity=([\\w./$]+)` matched the literal string
"ActivityRecord" (because real output is
`topResumedActivity=ActivityRecord{hash u0 com.pkg/.Activity t42}`), and the
`mResumedActivity` pattern captured the trailing task id "t42" instead of the
component. Both defects are covered below.
"""

import pytest
from pathlib import Path

from sudarshan_core.engines.agentic.perception import package_of, parse_foreground_activity


# ─── Captured dumpsys samples ─────────────────────────────────────────────────

PORTRAIT = """
  Display #0 (activities from top to bottom):
    Stack #1: type=standard mode=fullscreen
      mResumedActivity: ActivityRecord{6f3a1b2 u0 com.example.bank/.MainActivity t42}
      mLastPausedActivity: ActivityRecord{1a2b3c4 u0 com.android.launcher3/.Launcher t1}
"""

LANDSCAPE = """
  mDisplayId=0 rootTaskId=7
      topResumedActivity=ActivityRecord{9c8d7e6 u0 com.example.bank/com.example.bank.ui.LoginActivity t77}
      mOrientation=landscape
"""

FOLDABLE_MULTI_DISPLAY = """
  Display #0 (activities from top to bottom):
    Stack #3:
      mLastPausedActivity: ActivityRecord{aaa1111 u0 com.android.launcher3/.Launcher t1}
  Display #2 (activities from top to bottom):
    Stack #9:
      topResumedActivity=ActivityRecord{bbb2222 u0 com.example.wallet/.SplitActivity t99}
"""

FOCUS_ONLY = """
  mCurrentFocus=Window{4d5e6f7 u0 com.example.trojan/com.example.trojan.OverlayActivity}
  mFocusedApp=AppWindowToken{...}
"""

LAUNCHER = """
      mResumedActivity: ActivityRecord{0011223 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t1}
"""


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_portrait_resumed_activity():
    assert parse_foreground_activity(PORTRAIT) == "com.example.bank/.MainActivity"


def test_landscape_top_resumed_fully_qualified():
    assert (
        parse_foreground_activity(LANDSCAPE)
        == "com.example.bank/com.example.bank.ui.LoginActivity"
    )


def test_foldable_multi_display_prefers_resumed_over_paused():
    assert parse_foreground_activity(FOLDABLE_MULTI_DISPLAY) == "com.example.wallet/.SplitActivity"


def test_current_focus_fallback():
    assert (
        parse_foreground_activity(FOCUS_ONLY)
        == "com.example.trojan/com.example.trojan.OverlayActivity"
    )


def test_never_returns_the_literal_activityrecord():
    """The original defect: the regex captured the class name, not the component."""
    for sample in (PORTRAIT, LANDSCAPE, FOLDABLE_MULTI_DISPLAY, FOCUS_ONLY, LAUNCHER):
        assert parse_foreground_activity(sample) != "ActivityRecord"


def test_never_returns_the_task_id():
    """The original mResumedActivity regex captured the trailing task id."""
    result = parse_foreground_activity(PORTRAIT)
    assert not result.startswith("t")
    assert "/" in result


def test_empty_and_garbage_input():
    assert parse_foreground_activity("") == "unknown"
    assert parse_foreground_activity("no activities here") == "unknown"
    assert parse_foreground_activity(None or "") == "unknown"


def test_malformed_record_without_component():
    assert parse_foreground_activity("mResumedActivity: ActivityRecord{deadbeef u0 t9}") == "unknown"


ANDROID_13_NO_M_PREFIX = """
  ResumedActivity: ActivityRecord{12114874 u0 com.example.bank/.MainActivity t14}
"""


def test_android13_resumed_activity_without_m_prefix():
    """Android 13+ drops the 'm' prefix used by older releases."""
    assert parse_foreground_activity(ANDROID_13_NO_M_PREFIX) == "com.example.bank/.MainActivity"


def test_real_captured_android37_dumpsys():
    """Parsed against genuine output captured from the project's Pixel_6 AVD."""
    fixture = Path(__file__).parent / "fixtures" / "dumpsys_android37.txt"
    if not fixture.exists():
        pytest.skip("device capture fixture not present")
    raw = fixture.read_text(encoding="utf-8", errors="ignore")
    activity = parse_foreground_activity(raw)
    assert "/" in activity
    assert activity != "ActivityRecord"
    assert package_of(activity) == "ai.agribid.esurvey_farmer"


@pytest.mark.parametrize(
    "activity,expected",
    [
        ("com.example.bank/.MainActivity", "com.example.bank"),
        ("com.example.bank/com.example.bank.ui.Login", "com.example.bank"),
        ("unknown", ""),
        ("", ""),
        ("no-slash-here", ""),
    ],
)
def test_package_of(activity, expected):
    assert package_of(activity) == expected
