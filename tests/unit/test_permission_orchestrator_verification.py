"""
Permission grants must be confirmed by the device, not asserted.

Three defects these lock down, all found by reading the orchestrator:

* `grant_accessibility` set ``success = True`` unconditionally, immediately
  after the settings write. Accessibility is the highest-weight fraud
  capability the sandbox can enable, so a false positive here misrepresents the
  whole investigation.

* `grant_overlay` computed ``"Error" not in out`` where `out` came from
  `_adb()`, which returns ``""`` when the command FAILS. ``"Error" not in ""``
  is True, so a failed grant reported success - worse than no check, because it
  looked like one.

* `grant_all_standard_permissions` returned a bare ``True`` after firing six
  fixed `pm grant` calls. A grant for a permission the manifest does not
  declare grants nothing, and every one of those was recorded as a success.

No device: the ADB channel is faked, and the parsers are fed output captured
from a real Android 17 emulator.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.permission_orchestrator import (  # noqa: E402
    PermissionOrchestrator,
)

P = "android.permission."
PKG = "com.example.calculator"

DUMPSYS_WITH_CAMERA = """
    install permissions:
      android.permission.INTERNET: granted=true
    runtime permissions:
      android.permission.CAMERA: granted=true, flags=[ USER_SENSITIVE_WHEN_GRANTED]
      android.permission.READ_SMS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED]
"""


def _orch(responses, ok=True):
    """Orchestrator whose ADB matches a substring of the joined command."""
    orch = PermissionOrchestrator(device_serial="test-device")
    calls = []

    def fake(*args):
        joined = " ".join(str(a) for a in args)
        calls.append(joined)
        for needle, payload in responses.items():
            if needle in joined:
                value = payload
                if isinstance(value, tuple):
                    return value
                return True, value
        return (ok, "")

    orch._adb2 = fake
    orch.calls = calls
    return orch


# ── the accessibility lie ────────────────────────────────────────────────────

def test_accessibility_is_reported_enabled_only_when_the_device_says_so():
    orch = _orch({
        "enabled_accessibility_services": f"{PKG}/.Svc",
        "accessibility_enabled": "1",
    })
    assert orch.verify_accessibility_enabled(PKG) is True


def test_a_settings_write_that_did_nothing_is_not_success():
    """The hardcoded `success = True` case."""
    orch = _orch({
        "enabled_accessibility_services": "null",
        "accessibility_enabled": "1",
    })
    assert orch.verify_accessibility_enabled(PKG) is False


def test_a_listed_component_with_the_master_switch_off_is_not_enabled():
    """A component listed while accessibility_enabled=0 receives no events."""
    orch = _orch({
        "enabled_accessibility_services": f"{PKG}/.Svc",
        "accessibility_enabled": "0",
    })
    assert orch.verify_accessibility_enabled(PKG) is False


def test_another_packages_service_does_not_count_as_ours():
    orch = _orch({
        "enabled_accessibility_services": "com.other.app/.Svc",
        "accessibility_enabled": "1",
    })
    assert orch.verify_accessibility_enabled(PKG) is False


def test_grant_accessibility_returns_false_when_the_write_had_no_effect():
    orch = _orch({
        "enabled_accessibility_services": "null",
        "accessibility_enabled": "1",
    })
    assert orch.grant_accessibility(PKG, "Calculator", service_class=".Svc") is False
    assert orch.actions_log[-1]["success"] is False


def test_grant_accessibility_still_refuses_without_a_service_class():
    """No manifest-parsed class means there is nothing real to enable."""
    orch = _orch({})
    assert orch.grant_accessibility(PKG, "Calculator", service_class=None) is False


# ── the overlay false positive ───────────────────────────────────────────────

def test_overlay_is_verified_through_appops():
    orch = _orch({"appops get": "SYSTEM_ALERT_WINDOW: allow"})
    assert orch.verify_overlay_granted(PKG) is True


def test_a_denied_overlay_is_not_success():
    orch = _orch({"appops get": "SYSTEM_ALERT_WINDOW: default; rejectTime=+8h ago"})
    assert orch.verify_overlay_granted(PKG) is False


def test_a_failed_adb_call_no_longer_reports_overlay_success():
    """
    The exact regression: `_adb()` returns "" on failure and the old check was
    `"Error" not in out`, which is True for "".
    """
    orch = _orch({"appops get": (False, "")})
    assert orch.verify_overlay_granted(PKG) is False
    assert orch.grant_overlay(PKG) is False


# ── device admin ─────────────────────────────────────────────────────────────

def test_device_admin_is_verified_against_policy_state():
    orch = _orch({"dpm list-owners": f"Owner: {PKG}/.Admin"})
    assert orch.verify_device_admin_active(PKG) is True


def test_dpm_saying_success_does_not_make_an_admin_active():
    """dpm prints Success in cases where the admin is not subsequently active."""
    orch = _orch({
        "set-active-admin": "Success: Active admin set",
        "dpm list-owners": "",
        "dumpsys device_policy": "",
    })
    assert orch.grant_device_admin(PKG, ".Admin") is False


# ── standard permissions ─────────────────────────────────────────────────────

def test_only_permissions_actually_held_are_returned():
    orch = _orch({"dumpsys package": DUMPSYS_WITH_CAMERA})
    granted = orch.grant_all_standard_permissions(
        PKG, [P + "CAMERA", P + "READ_SMS"]
    )
    assert granted == [P + "CAMERA"]


def test_an_undeclared_permission_is_logged_as_a_failure_not_a_success():
    orch = _orch({"dumpsys package": DUMPSYS_WITH_CAMERA})
    orch.grant_all_standard_permissions(PKG, [P + "READ_SMS"])
    assert orch.actions_log[-1]["success"] is False


def test_the_caller_chooses_which_permissions_to_grant():
    """Granting READ_SMS to an app that never asked for it reflects nothing."""
    orch = _orch({"dumpsys package": DUMPSYS_WITH_CAMERA})
    orch.grant_all_standard_permissions(PKG, [P + "CAMERA"])
    grants = [c for c in orch.calls if "pm grant" in c]
    assert len(grants) == 1
    assert "CAMERA" in grants[0]


def test_the_default_list_is_preserved_for_callers_that_pass_nothing():
    orch = _orch({"dumpsys package": DUMPSYS_WITH_CAMERA})
    orch.grant_all_standard_permissions(PKG)
    assert len([c for c in orch.calls if "pm grant" in c]) == 6


def test_an_unreadable_permission_table_grants_nothing_verified():
    orch = _orch({"dumpsys package": (False, "")})
    assert orch.grant_all_standard_permissions(PKG, [P + "CAMERA"]) == []


def test_a_single_permission_is_verified_individually():
    orch = _orch({"dumpsys package": DUMPSYS_WITH_CAMERA})
    assert orch.verify_permission_granted(PKG, P + "CAMERA") is True
    assert orch.verify_permission_granted(PKG, P + "READ_SMS") is False


# ── deterministic Settings navigation (§10) ──────────────────────────────────

def test_opening_accessibility_settings_uses_the_settings_action():
    orch = _orch({})
    assert orch.open_accessibility_settings() is True
    assert any("android.settings.ACCESSIBILITY_SETTINGS" in c for c in orch.calls)


def test_the_service_is_looked_for_by_package_or_app_name():
    orch = _orch({"uiautomator dump": f"<node text='Calculator' pkg='{PKG}'/>"})
    assert orch.find_accessibility_service(PKG) is True
    assert orch.find_accessibility_service("com.absent", "Calculator") is True
    assert orch.find_accessibility_service("com.absent", "Nothing") is False


def test_a_failed_ui_dump_is_not_a_found_service():
    orch = _orch({"uiautomator dump": (False, "")})
    assert orch.find_accessibility_service(PKG) is False


def test_returning_to_the_app_prefers_the_known_component():
    orch = _orch({})
    assert orch.return_to_app(PKG, ".MainActivity") is True
    assert any(f"{PKG}/.MainActivity" in c for c in orch.calls)


def test_returning_falls_back_to_the_launcher_without_a_component():
    orch = _orch({})
    orch.return_to_app(PKG)
    assert any("monkey" in c for c in orch.calls)


# ── the _adb failure distinction ─────────────────────────────────────────────

def test_adb_failure_is_distinguishable_from_empty_output():
    """
    Conflating the two is what made the overlay check wrong. `_adb2` keeps them
    apart; `_adb` is retained for existing callers.
    """
    orch = _orch({"cmd": (False, "")})
    assert orch._adb2("cmd") == (False, "")
    assert orch._adb("cmd") == ""


# ── the containment guard that blocked the whole flow ────────────────────────

def test_adb_own_listen_flag_is_still_forbidden():
    """The real exposure: adb listening on all interfaces."""
    from sudarshan_core.security.sandbox_containment import (
        ContainmentViolation,
        validate_adb_invocation,
    )

    for argv in (
        ["-a", "nodaemon", "server", "start"],
        ["-a", "-P", "5037", "server"],
    ):
        with pytest.raises(ContainmentViolation):
            validate_adb_invocation(argv)


def test_a_subcommands_own_dash_a_is_not_adbs():
    """
    `am start -a <ACTION>` is the engine's normal way to reach a Settings
    screen. A bare `"-a" in args` rejected it, so the accessibility flow could
    never have worked - measured live as
    "adb -a (listen on all interfaces) is forbidden".
    """
    from sudarshan_core.security.sandbox_containment import validate_adb_invocation

    validate_adb_invocation([
        "-s", "emulator-5554", "shell", "am", "start",
        "-a", "android.settings.ACCESSIBILITY_SETTINGS",
    ])


def test_dash_a_after_the_subcommand_is_allowed_generally():
    from sudarshan_core.security.sandbox_containment import validate_adb_invocation

    validate_adb_invocation(["-s", "dev", "shell", "ls", "-a"])
    validate_adb_invocation(["-s", "dev", "shell", "pm", "list", "packages", "-a"])


def test_blocked_subcommands_are_still_blocked():
    """Scoping the -a check must not have loosened anything else."""
    from sudarshan_core.security.sandbox_containment import (
        ContainmentViolation,
        validate_adb_invocation,
    )

    with pytest.raises(ContainmentViolation):
        validate_adb_invocation(["-s", "emulator-5554", "tcpip", "5555"])


# ── the device-admin false positive ──────────────────────────────────────────

DEVICE_POLICY_DUMP = """Current Device Policy Manager state:
  Enabled Device Admins (User 0, provisioningState: 0):
    admin=ComponentInfo{com.evil.bot/.AdminReceiver}
      Per-admin Policy:
  Registered Package list:
    12: com.android.chrome
    3: com.google.android.trichromelibrary
"""


def test_a_real_active_admin_is_detected():
    orch = _orch({"dpm list-owners": "", "dumpsys device_policy": DEVICE_POLICY_DUMP})
    assert orch.verify_device_admin_active("com.evil.bot") is True


def test_a_package_listed_elsewhere_in_the_dump_is_not_an_admin():
    """
    Measured live: com.android.chrome appears in an unrelated package list
    inside `dumpsys device_policy` and was reported as an active device admin.
    """
    orch = _orch({"dpm list-owners": "", "dumpsys device_policy": DEVICE_POLICY_DUMP})
    assert orch.verify_device_admin_active("com.android.chrome") is False


def test_admin_matching_is_on_the_package_half_not_a_substring():
    orch = _orch({"dpm list-owners": "", "dumpsys device_policy": DEVICE_POLICY_DUMP})
    assert orch.verify_device_admin_active("com.evil") is False
    assert orch.verify_device_admin_active("com.evil.bot.extra") is False


def test_an_empty_package_is_never_an_admin():
    assert _orch({}).verify_device_admin_active("") is False


def test_an_empty_dump_is_not_an_admin():
    orch = _orch({"dpm list-owners": "", "dumpsys device_policy": ""})
    assert orch.verify_device_admin_active("com.evil.bot") is False


# ── the component format bug verification exposed ────────────────────────────

def test_a_relative_class_is_flattened_to_a_component():
    """
    The bug: ".zWPzgfI" became "com.pkg.zWPzgfI" - a bare CLASS name with no
    "pkg/" prefix. `enabled_accessibility_services` is a colon-separated list of
    flattened components and silently ignores anything else, so the write did
    nothing. Invisible for as long as grant_accessibility returned a hardcoded
    True; the first verified run reported "grant did not take effect".
    """
    from sudarshan_core.engines.permission_orchestrator import _flatten_component

    assert _flatten_component(PKG, ".Svc") == f"{PKG}/.Svc"


def test_a_fully_qualified_class_keeps_its_package_half():
    from sudarshan_core.engines.permission_orchestrator import _flatten_component

    assert _flatten_component(PKG, f"{PKG}.Svc") == f"{PKG}/{PKG}.Svc"


def test_a_service_from_another_package_is_still_flattened_under_the_app():
    from sudarshan_core.engines.permission_orchestrator import _flatten_component

    assert _flatten_component(PKG, "com.other.Svc") == f"{PKG}/com.other.Svc"


def test_an_already_flattened_component_is_left_alone():
    from sudarshan_core.engines.permission_orchestrator import _flatten_component

    assert _flatten_component(PKG, f"{PKG}/.Svc") == f"{PKG}/.Svc"


@pytest.mark.parametrize("cls", ["", "   ", None])
def test_no_class_yields_no_component(cls):
    from sudarshan_core.engines.permission_orchestrator import _flatten_component

    assert _flatten_component(PKG, cls) == ""


def test_the_grant_writes_a_flattened_component():
    """End-to-end: what actually reaches `settings put secure`."""
    orch = _orch({
        "enabled_accessibility_services": f"{PKG}/.Svc",
        "accessibility_enabled": "1",
    })
    orch.grant_accessibility(PKG, "App", service_class=".Svc")
    writes = [c for c in orch.calls if "enabled_accessibility_services" in c and "put" in c]
    assert writes, "no settings write was issued"
    assert f"{PKG}/.Svc" in writes[0]
