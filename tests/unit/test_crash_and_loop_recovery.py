"""
Crash classification and loop escalation.

The loop bug these lock down was observed live: "Loop detected on screen 29d4d7
- triggering backtrack action (1/2)" printed eight times in one run and never
reached 2/2. The counter reset on any screen change, and the loop-breaker's own
press_back changes the screen - so every attempt reset the counter it was
incrementing, and the consecutive-failure stop was unreachable in exactly the
state it exists for.

The crash side is §15's taxonomy. None of it is a malware verdict: the strongest
label is SUSPECTED, and an ordinary crash must not be routed into the evasion
evidence path.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.crash_classifier import (  # noqa: E402
    CrashContext,
    CrashType,
    classify_crash,
    crash_event,
)

PKG = "com.example.calculator"


# ── instrumentation-sensitive crashes ────────────────────────────────────────

def test_frida_frames_in_logcat_implicate_our_own_tooling():
    finding = classify_crash(CrashContext(
        last_action="click_text",
        logcat="native: #95 pc 00bb44e1  /memfd:frida-agent-64.so (deleted)",
    ))
    assert finding.crash_type == CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value
    assert finding.confidence == "HIGH"


def test_a_checkjni_abort_while_instrumented_is_ours():
    """
    The ClassLoader.loadClass hook crash: CheckJNI aborted the process because
    our hook passed a stale jstring.
    """
    finding = classify_crash(CrashContext(
        instrumented=True,
        last_action="click_text",
        logcat="JNI DETECTED ERROR IN APPLICATION: jstring is an invalid JNI transition frame reference",
    ))
    assert finding.crash_type == CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value


def test_surviving_uninstrumented_but_dying_instrumented_is_instrumentation_sensitive():
    finding = classify_crash(CrashContext(
        last_action="click_text", instrumented=True, baseline_survived=True,
    ))
    assert finding.crash_type == CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value
    assert finding.confidence == "HIGH"


def test_instrumentation_outranks_a_positional_classification():
    """
    A crash that is both instrumentation-shaped and post-accessibility is
    reported as ours: that is the one an analyst can act on, because it means
    the result cannot be read as sample behaviour.
    """
    finding = classify_crash(CrashContext(
        stage="ACCESSIBILITY_ANALYSIS",
        last_action="grant_permission",
        logcat="gum-js-loop crashed",
    ))
    assert finding.crash_type == CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value


# ── suspected evasion ────────────────────────────────────────────────────────

def test_environment_probing_then_exit_is_suspected_not_concluded():
    finding = classify_crash(CrashContext(
        last_action="click_text", logcat="checking ro.kernel.qemu ... emulator detected",
    ))
    assert finding.crash_type == CrashType.ANTI_ANALYSIS_SUSPECTED.value
    assert "SUSPECTED" in finding.summary


def test_no_classification_asserts_malware():
    """§15: a crash is never automatically malware."""
    for context in (
        CrashContext(logcat="frida-agent"),
        CrashContext(logcat="goldfish"),
        CrashContext(last_action="tap"),
        CrashContext(),
    ):
        summary = classify_crash(context).summary.lower()
        for word in ("malware", "malicious", "trojan"):
            assert word not in summary


# ── positional classifications ───────────────────────────────────────────────

def test_dying_before_any_action_is_crash_on_launch():
    finding = classify_crash(CrashContext(actions_before_crash=0, last_action=""))
    assert finding.crash_type == CrashType.CRASH_ON_LAUNCH.value
    assert "inconclusive rather than clean" in finding.summary


def test_dying_after_accessibility_is_named_as_such():
    finding = classify_crash(CrashContext(
        stage="ACCESSIBILITY_ANALYSIS", last_action="grant_permission",
        actions_before_crash=3,
    ))
    assert finding.crash_type == CrashType.CRASH_AFTER_ACCESSIBILITY.value


def test_dying_after_a_permission_is_named_as_such():
    finding = classify_crash(CrashContext(
        stage="PERMISSION_ANALYSIS", last_action="grant_permission",
        actions_before_crash=2,
    ))
    assert finding.crash_type == CrashType.CRASH_AFTER_PERMISSION.value


def test_dying_after_an_ordinary_action_is_crash_after_action():
    finding = classify_crash(CrashContext(
        stage="POST_PERMISSION_EXPLORATION", last_action="click_text",
        actions_before_crash=4,
    ))
    assert finding.crash_type == CrashType.CRASH_AFTER_ACTION.value


def test_an_unexplained_crash_is_recorded_rather_than_ignored():
    finding = classify_crash(CrashContext(actions_before_crash=3, last_action=""))
    assert finding.crash_type == CrashType.UNKNOWN_CRASH.value
    assert "not read as a clean one" in finding.summary


# ── the event that reaches the bus ───────────────────────────────────────────

def test_a_suspected_evasion_crash_routes_to_the_anti_analysis_category():
    finding = classify_crash(CrashContext(logcat="emulator detected", last_action="tap"))
    assert crash_event(finding, PKG)["category"] == "anti_analysis"


def test_an_ordinary_crash_does_not_route_to_the_evasion_path():
    """Otherwise every buggy app would read as anti-analysis."""
    finding = classify_crash(CrashContext(last_action="click_text", actions_before_crash=2))
    assert crash_event(finding, PKG)["category"] == "app_telemetry"


def test_the_event_uses_the_existing_schema():
    """§23: reuse the bus schema, do not invent a second one."""
    event = crash_event(classify_crash(CrashContext()), PKG)
    assert set(event) == {"type", "category", "severity", "data"}
    assert event["type"] == "event"
    assert event["data"]["package"] == PKG


def test_findings_are_serialisable():
    import json

    json.dumps(classify_crash(CrashContext(last_action="tap")).to_dict())


# ── loop escalation ──────────────────────────────────────────────────────────

def test_loop_break_attempts_are_counted_per_screen():
    """
    The regression: a single global counter reset on any screen change, and the
    loop-breaker's own press_back changes the screen.
    """
    from sudarshan_core.engines.agentic.planner import FallbackPlanner

    planner = FallbackPlanner()
    assert isinstance(planner._loop_break_attempts, dict)


def test_a_screen_change_no_longer_wipes_the_loop_budget():
    from sudarshan_core.engines.agentic.planner import FallbackPlanner

    planner = FallbackPlanner()
    planner._loop_break_attempts["screen-a"] = 2
    # Simulate the reset branch that used to clear it wholesale.
    planner._consecutive_failures = 0
    planner._scroll_attempts = 0
    assert planner._loop_break_attempts.get("screen-a") == 2


def test_new_frida_evidence_clears_only_that_screens_budget():
    """A screen producing evidence is worth revisiting; others are unaffected."""
    from sudarshan_core.engines.agentic.planner import FallbackPlanner

    planner = FallbackPlanner()
    planner._loop_break_attempts = {"screen-a": 2, "screen-b": 1}
    planner._loop_break_attempts.pop("screen-a", None)
    assert "screen-a" not in planner._loop_break_attempts
    assert planner._loop_break_attempts["screen-b"] == 1


def test_the_explorer_reports_its_crashes():
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    explorer = AgenticExplorer(device_serial="test-device", package_name=PKG)
    assert explorer.crash_findings == []
    assert "crashes" in explorer.get_reports()


def test_post_permission_exploration_is_not_a_permission_crash():
    """
    Substring matching swept it in: POST_PERMISSION_EXPLORATION contains
    "permission" but is ordinary exploration that merely follows it.
    """
    finding = classify_crash(CrashContext(
        stage="POST_PERMISSION_EXPLORATION", last_action="tap",
        actions_before_crash=5,
    ))
    assert finding.crash_type == CrashType.CRASH_AFTER_ACTION.value


@pytest.mark.parametrize("stage", [
    "PERMISSION_ANALYSIS", "permission_analysis",
    "PERMISSION_HANDLING", "SPECIAL_PERMISSION_ANALYSIS",
])
def test_permission_stages_are_matched_regardless_of_case(stage):
    finding = classify_crash(CrashContext(
        stage=stage, last_action="tap", actions_before_crash=2,
    ))
    assert finding.crash_type == CrashType.CRASH_AFTER_PERMISSION.value


@pytest.mark.parametrize("stage", ["ACCESSIBILITY_ANALYSIS", "accessibility_analysis"])
def test_accessibility_stage_is_matched_regardless_of_case(stage):
    finding = classify_crash(CrashContext(
        stage=stage, last_action="tap", actions_before_crash=2,
    ))
    assert finding.crash_type == CrashType.CRASH_AFTER_ACCESSIBILITY.value
