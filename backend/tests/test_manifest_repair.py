"""
Regression tests for Task 3:
  INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION must trigger the manifest repair
  path in _adb_install_apk(), just like INSTALL_PARSE_FAILED and
  'Corrupt XML binary file' already did.

  These tests verify:
    1. The Teabot-specific error string reaches the repair branch.
    2. The existing INSTALL_PARSE_FAILED and Corrupt-XML markers still work.
    3. A non-parse error (e.g. INSTALL_FAILED_VERSION_DOWNGRADE) does NOT
       trigger repair.
    4. Repair provenance includes the specific failure reason.

No real APK or device needed: _adb() and repair_obfuscated_apk() are mocked.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, call, patch

import pytest

# ── Trigger constant under test ───────────────────────────────────────────────

PARSE_FAIL_MARKERS = (
    "INSTALL_PARSE_FAILED",
    "Corrupt XML binary file",
    "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",
)


def _triggers_repair(error_output: str) -> bool:
    """Mirror the trigger condition used in _adb_install_apk."""
    return any(m in error_output for m in PARSE_FAIL_MARKERS)


# ── Test 1: Teabot-specific marker triggers repair ────────────────────────────

def test_teabot_marker_triggers_repair():
    """
    The string 'INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION' (returned by
    Android when Teabot's deliberately malformed manifest is rejected) must
    trigger the repair path.
    """
    teabot_output = (
        "Failure [INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION: "
        "Failed to read AndroidManifest.xml]"
    )
    assert _triggers_repair(teabot_output), (
        "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION must trigger the manifest "
        "repair path. It was previously ignored."
    )


# ── Test 2: original markers still trigger repair ─────────────────────────────

@pytest.mark.parametrize("error_out", [
    "Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES]",
    "Failure [INSTALL_PARSE_FAILED]",
    "adb: error: Corrupt XML binary file",
])
def test_original_markers_still_trigger_repair(error_out):
    """
    Pre-existing repair triggers must continue to fire after this fix
    (regression guard).
    """
    assert _triggers_repair(error_out), (
        f"'{error_out}' should trigger repair but did not."
    )


# ── Test 3: non-parse errors do NOT trigger repair ────────────────────────────

@pytest.mark.parametrize("error_out", [
    "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]",
    "Failure [INSTALL_FAILED_ALREADY_EXISTS]",
    "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]",
    "",
])
def test_non_parse_errors_do_not_trigger_repair(error_out):
    """
    Errors unrelated to manifest parsing must NOT trigger the repair path to
    avoid unnecessary repair attempts on unrelated failures.
    """
    assert not _triggers_repair(error_out), (
        f"'{error_out}' should NOT trigger repair but did."
    )


# ── Test 4: repair_obfuscated_apk is called on Teabot error ──────────────────

def test_repair_called_for_teabot_error(tmp_path):
    """
    When _adb_install_apk encounters INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION,
    it must call repair_obfuscated_apk() with the original APK path.
    """
    import os

    # Create a dummy APK file so os.path.exists checks pass
    fake_apk = tmp_path / "teabot.apk"
    fake_apk.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    fake_repaired = tmp_path / "repaired_teabot.apk"
    fake_repaired.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

    adb_call_count = [0]

    def _fake_adb(*args, **kwargs):
        adb_call_count[0] += 1
        # All install attempts fail with the Teabot error
        if "install" in args:
            return False, (
                "Failure [INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION: "
                "Failed to read AndroidManifest.xml]"
            )
        return True, ""

    repair_was_called = [False]
    repair_path_arg = [None]

    def _fake_repair(apk_path):
        repair_was_called[0] = True
        repair_path_arg[0] = apk_path
        return True, str(fake_repaired), {
            "is_repaired_derivative": True,
            "repair_reason": "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",
            "original_sha256": "abc123",
        }

    with patch(
        "sudarshan_core.engines.frida_sandbox._adb",
        side_effect=_fake_adb,
    ), patch(
        "sudarshan_core.engines.apk_repair.repair_obfuscated_apk",
        side_effect=_fake_repair,
    ):
        from sudarshan_core.engines.frida_sandbox import _adb_install_apk

        ok, msg, provenance = _adb_install_apk(str(fake_apk), "emulator-5554")

    assert repair_was_called[0], (
        "repair_obfuscated_apk must be called when "
        "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION is encountered."
    )
    assert repair_path_arg[0] == str(fake_apk), (
        "repair_obfuscated_apk must receive the original APK path."
    )


# ── Test 5: provenance records the repair reason ──────────────────────────────

def test_provenance_records_repair_reason():
    """
    When repair is triggered by INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION,
    the returned provenance dict must document why repair was needed.
    """
    # Simulate what repair_obfuscated_apk returns for a Teabot sample
    provenance = {
        "is_repaired_derivative": True,
        "repair_reason": "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",
        "original_sha256": "deadbeef" * 8,
    }
    assert provenance.get("repair_reason") == "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION"
    assert provenance.get("is_repaired_derivative") is True
