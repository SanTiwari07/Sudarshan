"""
Tests for deterministic action verification.

Two things matter most here and neither is "does SUCCESS work":

* a grant that reported success but did not take effect must come back FAILED -
  that is the defect this layer exists for, and it is live in the codebase
  today (`_tool_grant_permission("accessibility")` returns success=True even
  when it issued no command at all);

* an unreadable device must come back INCONCLUSIVE, never FAILED. Routing "we
  could not tell" into failure handling makes a broken probe look like a
  misbehaving sample.

No device: every parser is fed output captured from a real Android 17 emulator,
and the decision rules are pure functions of two snapshots.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.action_verifier import (  # noqa: E402
    DeviceStateProbe,
    StateSnapshot,
    VerificationOutcome,
    accessibility_enabled_for,
    parse_accessibility_components,
    parse_appop,
    parse_granted_permissions,
    verify_action,
)

P = "android.permission."
PKG = "com.example.calculator"

# Captured verbatim from `dumpsys package` on Android 17 / API 37.
DUMPSYS = """
    install permissions:
      android.permission.USE_CREDENTIALS: granted=true
      android.permission.INTERNET: granted=true
    runtime permissions:
      android.permission.POST_NOTIFICATIONS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED]
      android.permission.CAMERA: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED]
      android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ GRANTED_BY_DEFAULT]
"""


# ── parsers ──────────────────────────────────────────────────────────────────

def test_granted_permissions_are_parsed_from_real_dumpsys():
    granted = parse_granted_permissions(DUMPSYS)
    assert P + "ACCESS_FINE_LOCATION" in granted
    assert P + "CAMERA" not in granted
    assert P + "POST_NOTIFICATIONS" not in granted


def test_install_time_permissions_count_as_granted():
    """Only reading the runtime block would report INTERNET missing everywhere."""
    assert P + "INTERNET" in parse_granted_permissions(DUMPSYS)


def test_empty_dumpsys_yields_nothing():
    assert parse_granted_permissions("") == frozenset()


def test_accessibility_components_are_split_on_colon():
    value = "com.a/.SvcA:com.b/.SvcB"
    assert parse_accessibility_components(value) == {"com.a/.SvcA", "com.b/.SvcB"}


def test_the_literal_string_null_is_not_a_component():
    """
    Android returns "null" when unset. Treating it as a component name would
    make every accessibility verification pass.
    """
    assert parse_accessibility_components("null") == frozenset()
    assert parse_accessibility_components("  NULL  ") == frozenset()
    assert parse_accessibility_components("") == frozenset()


def test_appop_mode_is_parsed_from_real_output():
    line = "SYSTEM_ALERT_WINDOW: default; rejectTime=+8h9m39s350ms ago"
    assert parse_appop(line) == "default"
    assert parse_appop("SYSTEM_ALERT_WINDOW: allow") == "allow"
    assert parse_appop("") == ""


def test_accessibility_ownership_is_matched_by_package_not_substring():
    comps = frozenset({"com.example.calculator/.Svc"})
    assert accessibility_enabled_for(comps, PKG) is True
    assert accessibility_enabled_for(comps, "com.example.calc") is False
    assert accessibility_enabled_for(comps, "") is False


# ── permission grants ────────────────────────────────────────────────────────

def _snap(**kw) -> StateSnapshot:
    kw.setdefault("permissions_read", True)
    return StateSnapshot(**kw)


def test_a_grant_that_took_effect_is_success():
    after = _snap(granted_permissions=frozenset({P + "CAMERA"}))
    res = verify_action({"tool": "grant_permission", "permission": P + "CAMERA"},
                        _snap(), after, PKG)
    assert res.outcome == VerificationOutcome.SUCCESS.value
    assert res.observed == "GRANTED"


def test_a_grant_that_did_not_take_effect_is_failed():
    """
    `pm grant` for a permission the manifest never declared exits zero and
    grants nothing. ToolResult.success cannot see that; this can.
    """
    res = verify_action({"tool": "grant_permission", "permission": P + "CAMERA"},
                        _snap(), _snap(granted_permissions=frozenset()), PKG)
    assert res.outcome == VerificationOutcome.FAILED.value
    assert "not declared" in res.detail


def test_an_unreadable_permission_table_is_inconclusive_not_failed():
    after = StateSnapshot(permissions_read=False)
    res = verify_action({"tool": "grant_permission", "permission": P + "CAMERA"},
                        _snap(), after, PKG)
    assert res.outcome == VerificationOutcome.INCONCLUSIVE.value
    assert res.failed is False


def test_denial_is_verified_in_the_opposite_direction():
    ok = verify_action({"tool": "deny_permission", "permission": P + "CAMERA"},
                       _snap(), _snap(granted_permissions=frozenset()), PKG)
    assert ok.outcome == VerificationOutcome.SUCCESS.value

    bad = verify_action({"tool": "deny_permission", "permission": P + "CAMERA"},
                        _snap(), _snap(granted_permissions=frozenset({P + "CAMERA"})), PKG)
    assert bad.outcome == VerificationOutcome.FAILED.value


# ── accessibility, the case that lies today ──────────────────────────────────

def test_accessibility_enabled_is_success():
    after = StateSnapshot(
        accessibility_read=True,
        accessibility_components=frozenset({PKG + "/.Svc"}),
        accessibility_enabled=True,
    )
    res = verify_action({"tool": "grant_permission", "permission": "accessibility"},
                        StateSnapshot(), after, PKG)
    assert res.outcome == VerificationOutcome.SUCCESS.value


def test_accessibility_that_reported_success_but_did_nothing_is_failed():
    """
    The concrete defect: `_grant_accessibility` can return
    "SKIPPED: no accessibility_service_class set" while the tool still reports
    success=True. Device state says otherwise.
    """
    after = StateSnapshot(accessibility_read=True, accessibility_enabled=False)
    res = verify_action({"tool": "grant_permission", "permission": "accessibility"},
                        StateSnapshot(), after, PKG)
    assert res.outcome == VerificationOutcome.FAILED.value
    assert "without taking effect" in res.detail


def test_unreadable_accessibility_settings_are_inconclusive():
    res = verify_action({"tool": "grant_permission", "permission": "accessibility"},
                        StateSnapshot(), StateSnapshot(accessibility_read=False), PKG)
    assert res.outcome == VerificationOutcome.INCONCLUSIVE.value


def test_overlay_is_verified_through_appops():
    ok = verify_action({"tool": "grant_permission", "permission": "overlay"},
                       StateSnapshot(), StateSnapshot(appops={"SYSTEM_ALERT_WINDOW": "allow"}), PKG)
    assert ok.outcome == VerificationOutcome.SUCCESS.value

    bad = verify_action({"tool": "grant_permission", "permission": "overlay"},
                        StateSnapshot(), StateSnapshot(appops={"SYSTEM_ALERT_WINDOW": "default"}), PKG)
    assert bad.outcome == VerificationOutcome.FAILED.value

    unknown = verify_action({"tool": "grant_permission", "permission": "overlay"},
                            StateSnapshot(), StateSnapshot(appops={}), PKG)
    assert unknown.outcome == VerificationOutcome.INCONCLUSIVE.value


# ── relaunch ─────────────────────────────────────────────────────────────────

def test_a_relaunch_that_brought_the_app_forward_is_success():
    after = StateSnapshot(foreground_package=PKG, activity=f"{PKG}/.MainActivity")
    res = verify_action({"tool": "start_activity", "component": f"{PKG}/.MainActivity"},
                        StateSnapshot(), after, PKG)
    assert res.outcome == VerificationOutcome.SUCCESS.value


def test_a_relaunch_that_left_another_app_in_front_is_failed():
    after = StateSnapshot(
        foreground_package="com.google.android.apps.nexuslauncher",
        activity="com.google.android.apps.nexuslauncher/.NexusLauncherActivity",
    )
    res = verify_action({"tool": "start_activity", "component": f"{PKG}/.MainActivity"},
                        StateSnapshot(), after, PKG)
    assert res.outcome == VerificationOutcome.FAILED.value


def test_an_unreadable_foreground_makes_relaunch_inconclusive():
    res = verify_action({"tool": "start_activity", "component": f"{PKG}/.Main"},
                        StateSnapshot(), StateSnapshot(), PKG)
    assert res.outcome == VerificationOutcome.INCONCLUSIVE.value


# ── screen-changing actions ──────────────────────────────────────────────────

def test_a_click_that_changed_the_screen_is_success():
    res = verify_action({"tool": "click_text", "text": "Login"},
                        StateSnapshot(screen_hash="a"), StateSnapshot(screen_hash="b"))
    assert res.outcome == VerificationOutcome.SUCCESS.value


def test_a_click_that_changed_only_the_activity_still_counts():
    res = verify_action(
        {"tool": "click_text", "text": "Login"},
        StateSnapshot(screen_hash="a", activity=f"{PKG}/.A"),
        StateSnapshot(screen_hash="a", activity=f"{PKG}/.B"),
    )
    assert res.outcome == VerificationOutcome.SUCCESS.value


def test_an_unchanged_screen_is_inconclusive_not_failed():
    """
    Typing into a field, ticking a checkbox and dismissing a toast all leave
    the hash identical. Calling those failures would poison the loop's failure
    counters with actions that worked.
    """
    res = verify_action({"tool": "click_text", "text": "Login"},
                        StateSnapshot(screen_hash="a"), StateSnapshot(screen_hash="a"))
    assert res.outcome == VerificationOutcome.INCONCLUSIVE.value
    assert res.failed is False


def test_missing_screen_hashes_are_inconclusive():
    res = verify_action({"tool": "tap", "x": 1, "y": 2},
                        StateSnapshot(), StateSnapshot())
    assert res.outcome == VerificationOutcome.INCONCLUSIVE.value


# ── unmodelled actions ───────────────────────────────────────────────────────

@pytest.mark.parametrize("tool", ["dump_ui", "take_screenshot", "capture_logcat"])
def test_read_only_tools_are_unverified_rather_than_failed(tool):
    res = verify_action({"tool": tool}, StateSnapshot(), StateSnapshot())
    assert res.outcome == VerificationOutcome.UNVERIFIED.value
    assert res.failed is False


def test_only_a_positive_failure_counts_as_failed():
    for outcome in VerificationOutcome:
        res = verify_action({"tool": "dump_ui"}, StateSnapshot(), StateSnapshot())
        res.outcome = outcome.value
        assert res.failed is (outcome is VerificationOutcome.FAILED)


def test_result_serialises_and_logs_its_comparison():
    res = verify_action({"tool": "grant_permission", "permission": P + "CAMERA"},
                        _snap(), _snap(granted_permissions=frozenset({P + "CAMERA"})), PKG)
    data = res.to_dict()
    assert data["expected"] == "GRANTED" and data["observed"] == "GRANTED"
    line = res.log_line()
    assert "expected=GRANTED" in line and "observed=GRANTED" in line


# ── probe ────────────────────────────────────────────────────────────────────

def _probe_with(responses):
    """Fake adb: matches on a substring of the joined command."""
    async def fake_adb(*args):
        joined = " ".join(args)
        for needle, payload in responses.items():
            if needle in joined:
                return True, payload
        return False, ""
    return DeviceStateProbe(fake_adb, PKG)


def test_probe_builds_a_snapshot_from_device_output():
    probe = _probe_with({
        "dumpsys activity": "  mResumedActivity: ActivityRecord{x u0 " + PKG + "/.Main t1}",
        "dumpsys package": DUMPSYS,
        "enabled_accessibility_services": PKG + "/.Svc",
        "appops": "SYSTEM_ALERT_WINDOW: allow",
    })
    snap = asyncio.run(probe.snapshot(screen_hash="h1"))
    assert snap.foreground_package == PKG
    assert snap.permissions_read is True
    assert P + "INTERNET" in snap.granted_permissions
    assert snap.accessibility_enabled is True
    assert snap.appops["SYSTEM_ALERT_WINDOW"] == "allow"
    assert snap.screen_hash == "h1"


def test_probe_reports_not_read_rather_than_empty_when_adb_fails():
    """The distinction that keeps a dead probe from reading as a denied grant."""
    snap = asyncio.run(_probe_with({}).snapshot())
    assert snap.permissions_read is False
    assert snap.granted_permissions == frozenset()


def test_a_raising_adb_does_not_abort_the_snapshot():
    async def exploding(*args):
        raise RuntimeError("device gone")

    snap = asyncio.run(DeviceStateProbe(exploding, PKG).snapshot())
    assert snap.permissions_read is False
    assert snap.foreground_package == ""


# ── wiring into the explorer loop ────────────────────────────────────────────

def _explorer():
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    return AgenticExplorer(device_serial="test-device", package_name=PKG)


def test_the_explorer_owns_a_probe_bound_to_the_executor_channel():
    """
    The probe must reuse ToolExecutor._adb, which routes through the
    policy-enforcing SandboxProvider. Opening its own transport would sidestep
    the sandbox controls the rest of the engine depends on.
    """
    exp = _explorer()
    assert isinstance(exp._probe, DeviceStateProbe)
    assert exp._probe._adb == exp.executor._adb
    assert exp._probe.package_name == PKG


def test_only_device_state_actions_justify_a_probe():
    """A four-query probe per click would add ~100 ADB calls to a 25-action run."""
    exp = _explorer()
    assert exp._DEVICE_STATE_ACTIONS == {
        "grant_permission", "deny_permission", "start_activity"
    }


class _Obs:
    def __init__(self, screen_hash="", activity=""):
        self.screen_hash = screen_hash
        self.activity = activity


def test_screen_actions_are_deferred_rather_than_double_dumped():
    exp = _explorer()
    before = StateSnapshot(screen_hash="a")
    res = asyncio.run(exp._verify_action({"tool": "click_text", "text": "X"}, before, _Obs()))
    assert res.outcome == VerificationOutcome.UNVERIFIED.value
    assert exp._pending_verification is not None


def test_a_deferred_action_is_judged_by_the_next_observation():
    exp = _explorer()
    asyncio.run(exp._verify_action(
        {"tool": "click_text", "text": "X"}, StateSnapshot(screen_hash="a"), _Obs()
    ))
    result = exp._resolve_pending_verification(_Obs(screen_hash="b", activity=f"{PKG}/.B"))
    assert result.outcome == VerificationOutcome.SUCCESS.value
    assert exp._pending_verification is None


def test_resolving_with_nothing_pending_returns_none():
    assert _explorer()._resolve_pending_verification(_Obs()) is None


def test_a_snapshot_for_a_screen_action_costs_no_adb():
    """Built from perception data the loop already holds."""
    exp = _explorer()
    snap = asyncio.run(exp._verification_snapshot(
        {"tool": "click_text"}, _Obs(screen_hash="h", activity=f"{PKG}/.A")
    ))
    assert snap.screen_hash == "h"
    assert snap.foreground_package == PKG
    assert snap.permissions_read is False


def test_a_probe_failure_leaves_the_action_unverified_not_failed():
    """A dead probe must not be reported as a misbehaving sample."""
    exp = _explorer()

    async def exploding(*args):
        raise RuntimeError("device gone")

    exp._probe = DeviceStateProbe(exploding, PKG)
    res = asyncio.run(exp._verify_action(
        {"tool": "grant_permission", "permission": P + "CAMERA"}, StateSnapshot(), _Obs()
    ))
    assert res.failed is False
