"""
Pre-granting: keep it, but stop it being invisible.

Granting every declared permission before launch exists for a real reason - a
legacy-targetSdk app cold-starts into ReviewPermissionsActivity, which leaves
`pidof` empty and breaks the launch ladder. It is not a bug and it stays on by
default.

What was wrong is that it was silent. Android never shows a runtime permission
dialog for a permission already held, so:

  * the investigation cannot observe which permissions the sample would have
    asked for - and asking is a behaviour, whereas declaring is only an
    intention;
  * the dialog the report is meant to screenshot never appears;
  * the report shows a sample holding SMS access with no account of how it got
    it, because the answer is "we granted it ourselves".

So the fix is: make it switchable, return which permissions were granted rather
than a count, and record them as GRANTED_WITHOUT_REQUEST.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines import frida_sandbox  # noqa: E402
from sudarshan_core.engines.agentic_explorer import AgenticExplorer  # noqa: E402
from sudarshan_core.engines.permission_investigator import Classification  # noqa: E402

P = "android.permission."
PKG = "com.example.calculator"


# ── the switch ───────────────────────────────────────────────────────────────

def test_pregranting_is_on_by_default():
    """
    Turning it off wholesale trades a permission dialog for a failed launch on
    legacy-targetSdk apps, and would shift BFCI inputs without measurement.
    """
    assert frida_sandbox.PREGRANT_PERMISSIONS is True


def test_the_switch_is_read_from_the_environment(monkeypatch):
    import importlib

    for raw, expected in (("0", False), ("false", False), ("no", False),
                          ("1", True), ("", True)):
        monkeypatch.setenv("SUDARSHAN_PREGRANT_PERMISSIONS", raw)
        reloaded = importlib.reload(frida_sandbox)
        assert reloaded.PREGRANT_PERMISSIONS is expected, raw
    monkeypatch.delenv("SUDARSHAN_PREGRANT_PERMISSIONS", raising=False)
    importlib.reload(frida_sandbox)


def test_disabled_pregranting_grants_nothing_and_issues_no_adb(monkeypatch):
    """With the switch off the sample must be left to ask for itself."""
    calls = []
    monkeypatch.setattr(frida_sandbox, "PREGRANT_PERMISSIONS", False)
    monkeypatch.setattr(frida_sandbox, "_adb", lambda *a, **k: calls.append(a) or (True, ""))

    granted = frida_sandbox._grant_declared_runtime_permissions("dev", "x.apk", PKG)
    assert granted == []
    assert calls == []


# ── it returns what, not how many ────────────────────────────────────────────

def test_granted_permissions_are_returned_by_name(monkeypatch):
    """
    A count cannot tell the investigation which capabilities the sample holds
    without ever having asked for them.
    """
    monkeypatch.setattr(frida_sandbox, "PREGRANT_PERMISSIONS", True)
    monkeypatch.setattr(
        frida_sandbox, "_declared_runtime_permissions",
        lambda apk: [P + "CAMERA", P + "READ_SMS"],
    )
    monkeypatch.setattr(frida_sandbox, "_adb", lambda *a, **k: (True, ""))

    granted = frida_sandbox._grant_declared_runtime_permissions("dev", "x.apk", PKG)
    assert granted == [P + "CAMERA", P + "READ_SMS"]


def test_a_refused_grant_is_not_reported_as_granted(monkeypatch):
    monkeypatch.setattr(frida_sandbox, "PREGRANT_PERMISSIONS", True)
    monkeypatch.setattr(
        frida_sandbox, "_declared_runtime_permissions",
        lambda apk: [P + "CAMERA", P + "READ_SMS"],
    )

    def fake_adb(*args, **kwargs):
        return (False, "Operation not allowed") if "READ_SMS" in args[-1] else (True, "")

    monkeypatch.setattr(frida_sandbox, "_adb", fake_adb)
    granted = frida_sandbox._grant_declared_runtime_permissions("dev", "x.apk", PKG)
    assert granted == [P + "CAMERA"]


def test_non_android_permissions_are_skipped(monkeypatch):
    """Custom and vendor permissions are not `pm grant`-able."""
    monkeypatch.setattr(frida_sandbox, "PREGRANT_PERMISSIONS", True)
    monkeypatch.setattr(
        frida_sandbox, "_declared_runtime_permissions",
        lambda apk: ["com.example.CUSTOM", P + "CAMERA"],
    )
    monkeypatch.setattr(frida_sandbox, "_adb", lambda *a, **k: (True, ""))
    assert frida_sandbox._grant_declared_runtime_permissions("d", "x", PKG) == [P + "CAMERA"]


# ── the session carries it ───────────────────────────────────────────────────

def test_the_session_exposes_pregranted_permissions():
    session = frida_sandbox.FridaSession("test-device", PKG)
    assert session.pregranted_permissions == []


def test_the_explorer_construction_site_forwards_them():
    source = Path(frida_sandbox.__file__).read_text(encoding="utf-8", errors="replace")
    start = source.index("AgenticExplorer(")
    depth = 0
    for offset in range(start, len(source)):
        if source[offset] == "(":
            depth += 1
        elif source[offset] == ")":
            depth -= 1
            if depth == 0:
                break
    assert "pregranted_permissions=self.pregranted_permissions" in source[start:offset + 1]


# ── the classification that makes it visible ─────────────────────────────────

def _explorer(pregranted=None, declared=None, label="Calculator"):
    return AgenticExplorer(
        device_serial="test-device",
        package_name=PKG,
        static_findings={"permissions": declared or [], "app_label": label},
        pregranted_permissions=pregranted,
    )


def test_a_pregranted_permission_is_recorded_as_held():
    exp = _explorer(pregranted=[P + "CAMERA"], declared=[P + "CAMERA"])
    exp.permissions.classify_all()
    record = exp.permissions.records()[0]
    assert record.granted is True
    assert record.requested_at_runtime is False


def test_pregranting_an_expected_permission_reads_as_granted_without_request():
    """
    The honest label for our own doing. It is INFO because it is a finding about
    the harness, not about the sample.
    """
    exp = AgenticExplorer(
        device_serial="test-device",
        package_name="com.example.cam",
        static_findings={"permissions": [P + "CAMERA"], "app_label": "Camera"},
        pregranted_permissions=[P + "CAMERA"],
    )
    exp.permissions.classify_all()
    record = exp.permissions.records()[0]
    assert record.classification == Classification.GRANTED_WITHOUT_REQUEST.value
    assert record.severity == "INFO"


def test_an_unexpected_pregranted_permission_still_reports_as_unexpected():
    """Our pre-granting must not launder a permission the app should not have."""
    exp = _explorer(pregranted=[P + "READ_SMS"], declared=[P + "READ_SMS"])
    exp.permissions.classify_all()
    record = exp.permissions.records()[0]
    assert record.classification == Classification.UNEXPECTED_PERMISSION.value


def test_no_pregranting_leaves_permissions_unheld():
    exp = _explorer(pregranted=[], declared=[P + "CAMERA"])
    exp.permissions.classify_all()
    assert exp.permissions.records()[0].granted is False


def test_the_explorer_still_constructs_without_the_new_argument():
    """Existing call sites must keep working."""
    exp = AgenticExplorer(device_serial="test-device", package_name=PKG)
    assert exp.permissions.records() == []
