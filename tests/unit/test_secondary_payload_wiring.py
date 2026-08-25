"""
The secondary-payload tracker must be REACHED, not merely importable.

The original defect was not a missing feature - `record_secondary_apk()`
already existed and was tested. It was that nothing in the production path ever
called it, so the whole capability was dead while looking covered.

Adding a second well-tested module would repeat that mistake exactly. These
tests assert the wiring itself: an event arriving on the bus reaches the
tracker, and the tracker's records reach the run's output.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.secondary_payload import (  # noqa: E402
    HOOK_APK_WRITE,
    HOOK_INSTALL_REQUEST,
    PayloadStatus,
)

APK = "/data/data/com.evil.app/files/dropped.apk"


def _explorer():
    """An explorer with no device attached - we only exercise event handling."""
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    return AgenticExplorer(
        device_serial="emulator-5554",
        adb_path="adb",
        package_name="com.evil.app",
    )


def _event(hook, **extra):
    base = {"id": "e1", "timestamp_ms": 1000, "category": "dangerous_apis",
            "hook": hook}
    base.update(extra)
    return base


# ── the wiring ───────────────────────────────────────────────────────────────

def test_an_apk_write_event_reaches_the_tracker():
    explorer = _explorer()
    explorer._on_frida_event(_event(HOOK_APK_WRITE, path=APK))

    assert len(explorer._payloads.payloads) == 1
    assert explorer._payloads.payloads[0].device_path == APK


def test_an_install_request_event_reaches_the_tracker():
    explorer = _explorer()
    explorer._on_frida_event(_event(HOOK_APK_WRITE, path=APK))
    explorer._on_frida_event(_event(HOOK_INSTALL_REQUEST, path=APK))

    payload = explorer._payloads.payloads[0]
    assert payload.status == PayloadStatus.INSTALL_REQUESTED.value
    assert payload.install_requested is True
    assert payload.install_confirmed is False


def test_the_tracker_is_fed_from_the_event_bus_subscription():
    """Publishing on the bus - not calling the handler directly - must work."""
    from sudarshan_core.engines.event_bus import RuntimeEventBus
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    bus = RuntimeEventBus()
    explorer = AgenticExplorer(
        device_serial="emulator-5554",
        adb_path="adb",
        package_name="com.evil.app",
        event_bus=bus,
    )
    bus.subscribe(explorer._on_frida_event)
    bus.publish(_event(HOOK_APK_WRITE, path=APK))

    # The bus dispatches on a background worker, so delivery is not immediate.
    deadline = time.time() + 3.0
    while time.time() < deadline and not explorer._payloads.payloads:
        time.sleep(0.01)

    assert len(explorer._payloads.payloads) == 1


def test_ordinary_events_do_not_create_payloads():
    explorer = _explorer()
    explorer._on_frida_event(_event("SmsMessage.getMessageBody"))
    explorer._on_frida_event(_event("URL.openConnection", url="http://x.test/a"))

    assert explorer._payloads.payloads == []


def test_a_malformed_event_never_breaks_event_delivery():
    """Event delivery is load-bearing; the tracker must not be able to stop it."""
    explorer = _explorer()
    explorer._on_frida_event({"hook": HOOK_APK_WRITE, "path": None})
    explorer._on_frida_event(_event(HOOK_APK_WRITE, path=APK))

    # The good event still landed.
    assert len(explorer._payloads.payloads) == 1
    # And both events are still buffered for the agent loop.
    assert len(explorer._pending_frida_events) == 2


# ── the output ───────────────────────────────────────────────────────────────

def test_detected_payloads_appear_in_the_run_output():
    explorer = _explorer()
    explorer._on_frida_event(_event(HOOK_APK_WRITE, path=APK))
    explorer._on_frida_event(_event(HOOK_INSTALL_REQUEST, path=APK))

    reports = explorer.get_reports()
    records = reports["secondary_apks"]

    assert len(records) == 1
    assert records[0]["device_path"] == APK
    assert records[0]["parent_package"] == "com.evil.app"
    assert records[0]["install_requested"] is True
    assert records[0]["install_confirmed"] is False
    assert reports["secondary_apk_summary"]["count"] == 1


def test_a_run_with_no_payloads_reports_an_empty_list():
    explorer = _explorer()
    reports = explorer.get_reports()
    assert reports["secondary_apks"] == []
    assert reports["secondary_apk_summary"]["count"] == 0


def test_preservation_without_a_sandbox_still_returns_records(tmp_path, monkeypatch):
    """
    No emulator attached must degrade to "detected but not preserved", not to
    a crash and not to silently dropping the finding.
    """
    explorer = _explorer()
    explorer._on_frida_event(_event(HOOK_APK_WRITE, path=APK))

    import sudarshan_core.sandbox as sandbox_mod

    def _boom():
        raise RuntimeError("no device")

    monkeypatch.setattr(sandbox_mod, "get_sandbox_provider", _boom)

    records = explorer.preserve_secondary_payloads(tmp_path)
    assert len(records) == 1
    assert records[0]["sha256"] == ""
    assert records[0]["status"] == PayloadStatus.DETECTED.value
