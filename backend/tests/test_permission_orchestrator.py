"""
Regression tests for Task 1:
  extract_accessibility_service_class() must return the manifest-declared class
  name (even when it is an obfuscated short name like '.zWPzgfI') rather than
  always assuming '.AccessibilityService'.

  grant_accessibility() must use the class received from
  extract_accessibility_service_class, not a hardcoded guess.

All tests use mocked Androguard objects so no real APK is needed.
"""
from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from sudarshan_core.engines.permission_orchestrator import (
    PermissionOrchestrator,
    extract_accessibility_service_class,
)

PACKAGE = "com.cerberus.rat"
REAL_SERVICE = ".zWPzgfI"  # obfuscated Cerberus class name


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_apk_mock(service_name: str, package: str, has_perm: bool = True, has_action: bool = True):
    """
    Build a minimal Androguard APK mock that:
      - returns [service_name] from get_services()
      - optionally returns BIND_ACCESSIBILITY_SERVICE from get_element()
      - optionally returns the accessibility action from get_intent_filters()
    """
    apk = MagicMock()
    apk.get_services.return_value = [service_name]

    if has_perm:
        apk.get_element.return_value = (
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        )
    else:
        apk.get_element.return_value = ""

    if has_action:
        apk.get_intent_filters.return_value = {
            "action": [
                "android.accessibilityservice.AccessibilityService"
            ]
        }
    else:
        apk.get_intent_filters.return_value = {"action": []}

    return apk


def _analyze_apk_factory(apk_mock):
    """Return an AnalyzeAPK that yields (apk_mock, None, None)."""
    def _fake_analyze(path):
        return apk_mock, None, None
    return _fake_analyze


# ── Test 1: real obfuscated class name is returned ────────────────────────────

def test_extracts_obfuscated_class_name(tmp_path):
    """
    extract_accessibility_service_class must return the manifest-declared class
    name '.zWPzgfI' when that is what the service element declares, not
    '.AccessibilityService'.
    """
    import sys
    apk_mock = _make_apk_mock(
        service_name=f"{PACKAGE}{REAL_SERVICE}",
        package=PACKAGE,
    )
    fake_apk_path = str(tmp_path / "cerberus.apk")

    mock_mod = MagicMock()
    mock_mod.AnalyzeAPK = _analyze_apk_factory(apk_mock)

    with patch.dict(sys.modules, {"androguard.misc": mock_mod, "androguard": MagicMock()}):
        result = extract_accessibility_service_class(fake_apk_path, PACKAGE)

    assert result == REAL_SERVICE, (
        f"Expected '{REAL_SERVICE}', got '{result}'. "
        "The hardcoded .AccessibilityService guess must NOT be used."
    )


# ── Test 2: returns None when no accessibility service is declared ────────────

def test_returns_none_when_no_service(tmp_path):
    """
    extract_accessibility_service_class must return None when the APK does not
    declare any accessibility service. It must NOT invent a class name.
    """
    import sys
    apk_mock = _make_apk_mock(
        service_name=f"{PACKAGE}.SomeOtherService",
        package=PACKAGE,
        has_perm=False,     # no BIND_ACCESSIBILITY_SERVICE
        has_action=False,   # no accessibility action
    )
    fake_apk_path = str(tmp_path / "clean.apk")

    mock_mod = MagicMock()
    mock_mod.AnalyzeAPK = _analyze_apk_factory(apk_mock)

    with patch.dict(sys.modules, {"androguard.misc": mock_mod, "androguard": MagicMock()}):
        result = extract_accessibility_service_class(fake_apk_path, PACKAGE)

    assert result is None, (
        "When no accessibility service is declared, the function must return "
        f"None, not '{result}'."
    )


# ── Test 3: grant_accessibility writes the correct component ──────────────────

def test_grant_accessibility_uses_real_class():
    """
    grant_accessibility(service_class='.zWPzgfI') must write
    'com.cerberus.rat.zWPzgfI' to settings, not the hardcoded guess
    'com.cerberus.rat/.AccessibilityService'.
    """
    calls: List[List[str]] = []

    def _fake_adb(*args):
        calls.append(list(args))
        return ""

    orchestrator = PermissionOrchestrator(
        device_serial="emulator-5554",
        adb_path="adb",
    )
    # Monkey-patch the ADB helper so no real device is needed
    orchestrator._adb = _fake_adb  # type: ignore[method-assign]

    orchestrator.grant_accessibility(
        package_name=PACKAGE,
        app_name="TestApp",
        service_class=REAL_SERVICE,
    )

    # Find the settings put secure enabled_accessibility_services call
    acc_calls = [c for c in calls if "enabled_accessibility_services" in c]
    assert acc_calls, "No 'settings put secure enabled_accessibility_services' call made"

    # The component written must be fully-qualified with the obfuscated name
    # The full call is:
    #   ["shell", "settings", "put", "secure",
    #    "enabled_accessibility_services", "<component>"]
    written_component = acc_calls[0][-1]
    expected = f"{PACKAGE}{REAL_SERVICE}"  # com.cerberus.rat.zWPzgfI
    assert written_component == expected, (
        f"Expected component '{expected}', got '{written_component}'. "
        "The hardcoded .AccessibilityService suffix must NOT appear."
    )


# ── Test 4: grant_accessibility skips when service_class is None ──────────────

def test_grant_accessibility_skips_when_no_class():
    """
    grant_accessibility(service_class=None) must not write anything to settings.
    Writing a non-existent component name silently fails on Android — skipping
    is the correct, honest behaviour.
    """
    calls: List[List[str]] = []

    def _fake_adb(*args):
        calls.append(list(args))
        return ""

    orchestrator = PermissionOrchestrator(
        device_serial="emulator-5554",
        adb_path="adb",
    )
    orchestrator._adb = _fake_adb  # type: ignore[method-assign]

    result = orchestrator.grant_accessibility(
        package_name=PACKAGE,
        app_name="TestApp",
        service_class=None,
    )

    acc_calls = [c for c in calls if "enabled_accessibility_services" in c]
    assert not acc_calls, (
        "grant_accessibility must NOT write to enabled_accessibility_services "
        "when service_class is None."
    )
    assert result is False, (
        "grant_accessibility must return False when service_class is None."
    )


# ── Test 5: ToolExecutor._grant_accessibility uses the stored class ────────────

def test_tool_executor_uses_stored_class():
    """
    ToolExecutor._grant_accessibility must use self.accessibility_service_class
    rather than the old hardcoded suffixes.
    """
    import asyncio
    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

    adb_calls: List[tuple] = []

    executor = ToolExecutor(
        device_serial="emulator-5554",
        package_name=PACKAGE,
        adb_path="adb",
        accessibility_service_class=REAL_SERVICE,
    )

    async def _fake_adb(*args):
        adb_calls.append(args)
        return True, ""

    executor._adb = _fake_adb  # type: ignore[method-assign]

    output = asyncio.run(executor._grant_accessibility())

    acc_calls = [
        c for c in adb_calls if "enabled_accessibility_services" in c
    ]
    assert acc_calls, "No settings put call was made"
    # The component value is the last arg
    component_arg = acc_calls[0][-1]
    expected = f"{PACKAGE}{REAL_SERVICE}"
    assert component_arg == expected, (
        f"Expected component '{expected}', got '{component_arg}'"
    )
    assert "SKIPPED" not in output


def test_tool_executor_skips_when_no_class():
    """
    ToolExecutor._grant_accessibility must skip (not write to settings)
    when accessibility_service_class is None.
    """
    import asyncio
    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

    adb_calls: List[tuple] = []

    executor = ToolExecutor(
        device_serial="emulator-5554",
        package_name=PACKAGE,
        adb_path="adb",
        accessibility_service_class=None,  # not known
    )

    async def _fake_adb(*args):
        adb_calls.append(args)
        return True, ""

    executor._adb = _fake_adb  # type: ignore[method-assign]

    output = asyncio.run(executor._grant_accessibility())

    acc_calls = [
        c for c in adb_calls if "enabled_accessibility_services" in c
    ]
    assert not acc_calls, (
        "ToolExecutor must NOT write to settings when accessibility_service_class is None"
    )
    assert "SKIPPED" in output
